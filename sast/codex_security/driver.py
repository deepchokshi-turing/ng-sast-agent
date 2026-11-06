#!/usr/bin/env python3
"""Run a ``codex exec`` security review on a copy of the in-scope files.

Uploaded by ``CodexSecurityAgent`` and run inside the task sandbox with the
image's Python, as::

    python3 -I -B driver.py --request <request.json> --keyfile <key file> --out <result.json>

next to ``ccsr_driver.py`` (the Claude review's driver.py, uploaded under that
name), whose standard-library helpers it reuses: the scope copy, the file
reader and line counter, the CLI runner with its process-group kill, and the
scrubber.

1. A fresh private ``CODEX_HOME`` (mode 700) gets the agent's ``config.toml``
   (see request.py). ``HOME`` is a private folder too, and Codex gets only an
   allow-listed environment: no ``OPENAI_*``, ``CODEX_*`` or other host
   setting reaches it.
2. The API key is read from ``--keyfile`` and given to ``codex login
   --with-api-key`` on its stdin, which stores it in ``$CODEX_HOME/auth.json``
   (mode 600). It is never on a command line or in an environment.
3. The in-scope files and security_manifest.json are copied to the scope
   folder; Codex runs there (``-C``) and never sees /app/repo.
4. With ``sandbox`` "read-only" the config's permissions profile applies to
   every command the model runs: Codex's ``:read-only`` profile (no writes, no
   network) with ``deny`` entries for /app/repo, the key folder, CODEX_HOME and
   the agent's folders. ``codex sandbox -- true`` must work first: Codex's Linux
   sandbox needs bubblewrap and unprivileged user namespaces, which a default
   Docker container does not allow. If it cannot run, every command the model
   runs would fail, so the run stops with ``sandbox_unavailable`` instead of
   producing an empty review.
5. ``codex exec --json --output-schema ...`` runs with the prompt on stdin.
   Its JSONL events are read for the final answer, the token usage, the
   thread id, errors and every command the model ran (kept, scrubbed, cut;
   commands that name a private path are flagged).
6. The answer must be a JSON object with a findings list and an
   ``analysis_summary``. ``review_completed`` false, ``files_reviewed`` 0 or a
   finding that is not an object stop the run. Paths under the scope folder are
   made relative again.
7. ``CODEX_HOME`` (with auth.json, Codex's logs and its state databases) is
   deleted in a ``finally``.

Output: ``--out`` gets one JSON document, and the last stdout line is
``DRIVER_RESULT {json}``. Exit status 0 when the review can be trusted, 3 when
it cannot (``error`` says why), 4 on a crash. Every text written is scrubbed
of the key and of the masked forms of it that OpenAI's error messages carry.
Standard library only, Python 3.8+.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
try:
    import ccsr_driver  # the Claude review driver, uploaded next to this file
except ImportError:  # run from the repository (the tests)
    sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))
    from sast.claude_review import driver as ccsr_driver

DRIVER_FORMAT = 1
MANIFEST_FILE = ccsr_driver.MANIFEST_FILE
#: Seconds kept back at the end for writing the result.
RESERVE_SEC = 10
MIN_ATTEMPT_SEC = 60
NETWORK_CHECK_TIMEOUT_SEC = 20
LOGIN_TIMEOUT_SEC = 60
PROBE_TIMEOUT_SEC = 60
TAIL_CHARS = 4000
#: Command records kept; more are counted only.
MAX_COMMANDS = 2000
COMMAND_CHARS = 300

#: The only host variables Codex inherits (the Claude driver's list), plus HOME and CODEX_HOME.
ENV_ALLOW = ccsr_driver.CLI_ENV_ALLOW
ENV_ALLOW_PREFIXES = ccsr_driver.CLI_ENV_ALLOW_PREFIXES

#: OpenAI masks a key in its error messages as "sk-abc***wxyz" (Codex prints "sk-fake-***STKEY").
MASKED_KEY = re.compile(r"\b(?:sk|org|proj)-[A-Za-z0-9_-]{0,12}\*{3,}[A-Za-z0-9_-]{0,8}")

#: Error text -> code. The first match wins, so the specific ones come first.
ERROR_PATTERNS = (
    ("api_auth", ("401 unauthorized", "invalid_api_key", "incorrect api key", "invalid api key",
                  "403 forbidden", "permission denied for model", "not logged in")),
    ("quota", ("insufficient_quota", "exceeded your current quota", "billing")),
    ("model_unavailable", ("model_not_found", "does not exist or you do not have access", "unsupported model",
                           "model is not supported", "not supported when using codex with")),
    ("prompt_too_long", ("context_length_exceeded", "context window", "maximum context length")),
    ("rate_limited", ("429 too many requests", "rate limit")),
    ("network", ("error sending request", "dns error", "connection refused", "connection reset",
                 "failed to lookup address", "tcp connect error", "network is unreachable")),
)

#: Codes a retry cannot fix: stop at once.
FATAL_CODES = ("api_auth", "quota", "model_unavailable", "prompt_too_long", "network")

#: What a failed command's output says when Codex's sandbox cannot start (bubblewrap without user namespaces).
SANDBOX_FAILURE_MARKERS = ("bwrap: no permissions to create a new namespace", "bubblewrap is unavailable",
                           "filesystem-restricted execution requires bubblewrap")


class DriverError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code
        self.message = message


def scrub(text, secret):
    """``text`` without the key and without masked forms of a key."""
    return MASKED_KEY.sub("***", ccsr_driver.scrub(text or "", secret))


def tail(text, limit=TAIL_CHARS):
    return ccsr_driver.tail(text, limit)


def sha256_text(text):
    return ccsr_driver.sha256_text(text)


# ---------------------------------------------------------------- environment


def codex_environment(home, codex_home):
    """The allow-listed variables of this process, plus HOME and CODEX_HOME. No key."""
    env = {name: value for name, value in os.environ.items()
           if name in ENV_ALLOW or name.startswith(ENV_ALLOW_PREFIXES)}
    env["HOME"] = home
    env["CODEX_HOME"] = codex_home
    return env


def prepare_codex_home(codex_home, config_text):
    """A fresh CODEX_HOME (mode 700) holding only config.toml (mode 600)."""
    if os.path.lexists(codex_home):
        shutil.rmtree(codex_home)
    os.makedirs(codex_home)
    os.chmod(codex_home, 0o700)
    ccsr_driver.write_private(os.path.join(codex_home, "config.toml"), config_text)


def run_simple(argv, env, cwd, timeout, stdin_text=None):
    """(exit code or None on timeout, stdout, stderr)."""
    try:
        proc = subprocess.run(argv, input=(stdin_text or "").encode("utf-8"), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env, cwd=cwd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", ""
    except OSError as exc:
        return -1, "", "{}: {}".format(type(exc).__name__, exc)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def codex_version(codex, env, cwd):
    code, out, err = run_simple([codex, "--version"], env, cwd, 60)
    if code != 0:
        raise DriverError("cli_missing", "cannot run {} --version (exit {}): {}".format(codex, code, tail(err, 300)))
    return out.strip()


def login(codex, env, cwd, key, codex_home):
    """``codex login --with-api-key`` with the key on stdin; auth.json must then exist."""
    code, out, err = run_simple([codex, "login", "--with-api-key"], env, cwd, LOGIN_TIMEOUT_SEC, stdin_text=key)
    if code != 0:
        raise DriverError("login_failed", "codex login --with-api-key failed (exit {}): {}".format(
            code, tail(scrub(err or out, key), 400)))
    auth = os.path.join(codex_home, "auth.json")
    if not os.path.isfile(auth):
        raise DriverError("login_failed", "codex login wrote no {}".format(auth))
    os.chmod(auth, 0o600)
    code, out, err = run_simple([codex, "login", "status"], env, cwd, LOGIN_TIMEOUT_SEC)
    # The status line shows a masked key: only whether it says "API key" is kept.
    if code != 0 or "api key" not in (out + err).lower():
        raise DriverError("login_failed", "codex login status does not report an API key login (exit {})".format(code))
    return {"auth_file_mode": oct(os.stat(auth).st_mode & 0o777), "status": "api_key"}


def sandbox_probe(codex, env, cwd, key):
    """Whether Codex's own sandbox can run a command here (``codex sandbox -- true`` in ``cwd``; its ``-C``
    needs ``--permission-profile`` in 0.162.1, so the working directory is set by the process instead)."""
    code, out, err = run_simple([codex, "sandbox", "--", "true"], env, cwd, PROBE_TIMEOUT_SEC)
    text = scrub((err or "") + (out or ""), key)
    return {"ok": code == 0, "exit_code": code, "output": tail(text.strip(), 600)}


def network_check(url):
    """Any HTTP answer (401 without a key) means the API host can be reached. No key is sent."""
    try:
        with urllib.request.urlopen(url, timeout=NETWORK_CHECK_TIMEOUT_SEC) as response:
            return {"url": url, "status": response.status}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code}
    except Exception as exc:
        raise DriverError("network", "the sandbox cannot reach {} ({}: {}). This agent needs HTTPS egress to the "
                          "OpenAI API from the task container".format(url, type(exc).__name__, exc))


# ---------------------------------------------------------------- the review


def exec_argv(codex, model, schema_file, last_file, scope_dir, sandbox):
    """The ``codex exec`` command line (flags from ``codex exec --help`` of 0.162.1). The prompt goes on stdin."""
    argv = [codex, "exec", "--strict-config", "--json", "--skip-git-repo-check", "--ephemeral", "--ignore-rules",
            "--color", "never", "--output-schema", schema_file, "-o", last_file, "-C", scope_dir, "-m", model]
    if sandbox == "container":
        # Codex's own sandbox off: the task container is the only boundary (an explicit opt-in, see the docs).
        argv.append("--dangerously-bypass-approvals-and-sandbox")
    # read-only: no -s flag, so the config's permissions profile (read-only plus the deny list) applies.
    return argv + ["-"]


def parse_events(stdout):
    """What the ``--json`` event stream says. Lines that are not JSON objects are counted only."""
    out = {"thread_id": None, "usage": {}, "turns_completed": 0, "turn_failed": None, "errors": [], "final_text": None,
           "commands": [], "file_changes": [], "web_searches": 0, "mcp_tool_calls": 0, "item_types": {},
           "non_json_lines": 0}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if not isinstance(event, dict):
            out["non_json_lines"] += 1
            continue
        kind = event.get("type")
        if kind == "thread.started":
            out["thread_id"] = event.get("thread_id")
        elif kind == "turn.completed":
            out["turns_completed"] += 1
            for name, value in (event.get("usage") or {}).items():
                if isinstance(value, int) and not isinstance(value, bool):
                    out["usage"][name] = out["usage"].get(name, 0) + value
        elif kind == "turn.failed":
            out["turn_failed"] = str((event.get("error") or {}).get("message") or "turn failed")
        elif kind == "error":
            out["errors"].append(str(event.get("message") or ""))
        elif kind == "item.completed":
            item = event.get("item") if isinstance(event.get("item"), dict) else {}
            item_type = str(item.get("type") or "")
            out["item_types"][item_type] = out["item_types"].get(item_type, 0) + 1
            if item_type == "agent_message":
                out["final_text"] = item.get("text")
            elif item_type == "command_execution":
                out["commands"].append(item)
            elif item_type == "file_change":
                out["file_changes"].append([c.get("path") for c in item.get("changes") or [] if isinstance(c, dict)])
            elif item_type == "web_search":
                out["web_searches"] += 1
            elif item_type == "mcp_tool_call":
                out["mcp_tool_calls"] += 1
            elif item_type == "error":
                out["errors"].append(str(item.get("message") or ""))
    return out


def command_records(commands, private, secret, attempt):
    """(records, flagged, sandbox failures). A record keeps the command (scrubbed, cut), its exit code and status,
    never its output. A command naming a private path (the real repository, CODEX_HOME, the key or the request
    folder) is flagged."""
    records, flagged, sandbox_failures = [], [], 0
    for item in commands:
        command = scrub(str(item.get("command") or ""), secret)
        entry = {"attempt": attempt, "command": tail(command, COMMAND_CHARS), "exit_code": item.get("exit_code"),
                 "status": item.get("status")}
        named = [what for what, path in private if path and path.rstrip("/") in command]
        if named:
            entry["outside_scope"] = "names " + ", ".join(named)
            flagged.append(entry)
        output = str(item.get("aggregated_output") or "").lower()
        if item.get("status") == "failed" and any(m in output for m in SANDBOX_FAILURE_MARKERS):
            sandbox_failures += 1
            entry["sandbox_failure"] = True
        records.append(entry)
    return records, flagged, sandbox_failures


def classify(text):
    """The error code for a failure text, or None."""
    lowered = (text or "").lower()
    for code, markers in ERROR_PATTERNS:
        if any(m in lowered for m in markers):
            return code
    return None


def parse_answer(text):
    """The final answer as a dict with a findings list, else None."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        value = json.loads(text)
    except ValueError:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("findings"), list):
        return None
    return value


def judge(code, events, last_text):
    """(outcome, reason, answer). outcome: ok, timeout, fatal (with an error code as reason) or retry."""
    if code is None:
        return "timeout", "codex exec did not finish in its time", None
    answer = parse_answer(last_text) or parse_answer(events.get("final_text"))
    if answer is not None and not events.get("turn_failed"):
        return "ok", None, answer
    failure = events.get("turn_failed") or ("; ".join(events.get("errors") or [])[-1000:])
    error_code = classify(failure)
    if error_code in FATAL_CODES:
        return "fatal", error_code, failure
    if events.get("turn_failed"):
        return "retry", "the turn failed: {}".format(failure), None
    if code != 0:
        return "retry", "codex exec exited {} without a usable answer: {}".format(code, failure[-300:]), None
    return "retry", "the final answer is not a JSON object with a findings list", None


def check_review(answer, files_in_scope):
    summary = answer.get("analysis_summary")
    summary = summary if isinstance(summary, dict) else {}
    if summary.get("review_completed") is False:
        raise DriverError("review_incomplete", "the model reported review_completed false")
    reviewed = summary.get("files_reviewed")
    if files_in_scope and isinstance(reviewed, (int, float)) and not isinstance(reviewed, bool) and reviewed <= 0:
        raise DriverError("files_reviewed_zero", "the model reported files_reviewed {} while {} files are in "
                          "scope".format(reviewed, files_in_scope))
    bad = [i for i, f in enumerate(answer.get("findings") or []) if not isinstance(f, dict)]
    if bad:
        raise DriverError("bad_findings", "findings {} are not JSON objects".format(bad[:10]))
    return summary


def relativise(answer, base):
    """Finding and path step files under ``base`` (the scope copy) made relative to it. Returns the count."""
    changed = 0
    for finding in answer.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        location = finding.get("code_location")
        if isinstance(location, dict):
            new = ccsr_driver.relative_to(location.get("absolute_file_path"), base)
            if new != location.get("absolute_file_path"):
                location["absolute_file_path"] = new
                changed += 1
        for step in finding.get("path") if isinstance(finding.get("path"), list) else []:
            if isinstance(step, dict):
                new = ccsr_driver.relative_to(step.get("file"), base)
                if new != step.get("file"):
                    step["file"] = new
                    changed += 1
    return changed


def line_counts(repo, files):
    """{file: line count} of the in-scope text files, and the files that are not text."""
    counts, skipped = {}, []
    for path in files:
        kind, text = ccsr_driver.read_repo_file(repo, path)
        if kind == "text":
            counts[path] = len(ccsr_driver.text_lines(text))
        else:
            skipped.append([path, kind])
    return counts, skipped


def run_review(argv, prompt, cwd, env, attempts, deadline, key, private, record, last_file,
               min_attempt_sec=MIN_ATTEMPT_SEC):
    """Run codex exec until it gives a usable answer. Fills ``record`` as it goes. Returns the answer."""
    record.update({"attempts": [], "commands": [], "commands_count": 0, "commands_outside_scope": [],
                   "sandbox_failures": 0, "usage": {}, "file_changes": [], "web_searches": 0, "mcp_tool_calls": 0})
    failures = 0
    last_reason = "no attempt was started"
    last_kind = None
    while failures < attempts:
        left = deadline - time.monotonic()
        if left < min_attempt_sec:
            raise DriverError("deadline", "the review's time ran out before a usable answer ({} attempt(s), last: "
                              "{})".format(len(record["attempts"]), last_reason))
        if os.path.exists(last_file):
            os.remove(last_file)
        code, out, err, seconds, _init, _abort = ccsr_driver.run_cli_once(argv, prompt, cwd, env, left)
        out, err = scrub(out, key), scrub(err, key)
        events = parse_events(out)
        last_text = None
        if os.path.isfile(last_file):
            with open(last_file, encoding="utf-8", errors="replace") as f:
                last_text = scrub(f.read(), key)
        attempt = len(record["attempts"]) + 1
        records, flagged, sandbox_failures = command_records(events["commands"], private, key, attempt)
        record["commands_count"] += len(records)
        record["commands"] += records[:max(0, MAX_COMMANDS - len(record["commands"]))]
        record["commands_outside_scope"] += flagged
        record["sandbox_failures"] += sandbox_failures
        record["file_changes"] += events["file_changes"]
        record["web_searches"] += events["web_searches"]
        record["mcp_tool_calls"] += events["mcp_tool_calls"]
        for name, value in events["usage"].items():
            record["usage"][name] = record["usage"].get(name, 0) + value
        record["thread_id"] = events["thread_id"] or record.get("thread_id")
        outcome, reason, answer = judge(code, events, last_text)
        entry = {"exit_code": code, "seconds": seconds, "outcome": outcome, "thread_id": events["thread_id"],
                 "usage": events["usage"], "turns_completed": events["turns_completed"],
                 "item_types": events["item_types"], "errors": [tail(e, 300) for e in events["errors"][-5:]],
                 "stderr_tail": tail(err, 1500)}
        if outcome != "ok":
            entry["reason"] = tail(str(reason), 600)
            entry["stdout_tail"] = tail(out, 1500)
        record["attempts"].append(entry)
        if outcome == "ok":
            return answer
        if outcome == "timeout":
            raise DriverError("timeout", "codex exec did not finish within the review's time ({} s)".format(int(left)))
        if outcome == "fatal":
            raise DriverError(reason, tail(scrub(str(answer), key), 600))
        last_reason = reason
        last_kind = "turn_failed" if events.get("turn_failed") else ("crashed" if code != 0 else "no_answer")
        failures += 1
    # A service failure (the turn failed) is infrastructure; a crash or an answer that is not the schema's JSON is
    # the tool's outcome.
    error_code = {"turn_failed": "cli_failed", "crashed": "cli_crashed", "no_answer": "bad_answer"}.get(
        last_kind, "cli_failed")
    raise DriverError(error_code, "every codex exec attempt failed ({}), last: {}".format(attempts, last_reason))


def execute(request, key, keyfile, document, started, private_dirs=()):
    """The review itself. Fills ``document`` as it goes, raises DriverError."""
    deadline = started + float(request["budget_sec"]) - RESERVE_SEC
    repo = request["repo"]
    files = list(request.get("files") or [])
    scope_dir = request["scope_dir"]
    codex_home = request["codex_home"]
    home = request["home"]
    codex = request["codex"]
    sandbox = request.get("sandbox") or "read-only"
    if sandbox not in ("read-only", "container"):
        raise DriverError("bad_request", "unknown sandbox {!r}".format(sandbox))
    scope_abs, repo_abs = os.path.abspath(scope_dir), os.path.abspath(repo)
    if (not os.path.isabs(scope_dir) or scope_abs in ("/", repo_abs) or (repo_abs + os.sep).startswith(scope_abs + os.sep)
            or scope_abs.startswith(repo_abs + os.sep)):
        raise DriverError("bad_request", "scope_dir {!r} must be an absolute directory apart from the "
                          "repository".format(scope_dir))

    # 1. The scope copy and the line counts the agent checks locations against.
    document["scope_copy"] = ccsr_driver.make_scope_copy(repo, files, scope_dir)
    counts, not_text = line_counts(repo, files)
    document["line_counts"] = counts
    document["not_text"] = not_text[:200]
    if not counts:
        raise DriverError("nothing_to_review", "none of the {} in-scope files is a readable text file".format(len(files)))

    # 2. Codex's private home, config, schema and environment.
    os.makedirs(home, exist_ok=True)
    os.chmod(home, 0o700)
    prepare_codex_home(codex_home, request["config_toml"])
    private = os.path.join(os.path.dirname(codex_home), "codex-review-private")
    if os.path.lexists(private):
        shutil.rmtree(private)
    schema_file = os.path.join(private, "output_schema.json")
    ccsr_driver.write_private(schema_file, json.dumps(request["schema"], indent=1))
    last_file = os.path.join(private, "last_message.json")
    env = codex_environment(home, codex_home)
    document["codex_environment"] = sorted(env)   # names only
    document["config_sha256"] = sha256_text(request["config_toml"])
    document["schema_sha256"] = sha256_text(json.dumps(request["schema"], sort_keys=True))
    document["prompt_sha256"] = sha256_text(request["prompt"])
    document["prompt_bytes"] = len(request["prompt"].encode("utf-8"))
    document["codex_version"] = codex_version(codex, env, scope_dir)

    # 3. The network, the key, the sandbox.
    url = request.get("network_check_url")
    document["network"] = network_check(url) if url else "skipped"
    document["login"] = login(codex, env, scope_dir, key, codex_home)
    if sandbox == "read-only":
        probe = sandbox_probe(codex, env, scope_dir, key)
        document["sandbox_probe"] = probe
        if not probe["ok"]:
            raise DriverError("sandbox_unavailable", "Codex's read-only sandbox cannot run in this container ({}). It "
                              "needs bubblewrap with unprivileged user namespaces, which a default Docker container "
                              "does not allow".format(tail(probe["output"], 300)))
    else:
        document["sandbox_probe"] = "skipped: sandbox container"

    # 4. The review.
    argv = exec_argv(codex, request["model"], schema_file, last_file, scope_dir, sandbox)
    document["exec_argv"] = argv
    private_paths = [("the repository", repo_abs), ("CODEX_HOME", codex_home), ("the key folder", os.path.dirname(keyfile))]
    private_paths += [("an agent folder", d) for d in private_dirs]
    private_paths.append(("/proc", "/proc/"))
    record = document["exec"] = {}
    answer = run_review(argv, request["prompt"], scope_dir, env, int(request.get("attempts") or 2), deadline, key,
                        private_paths, record, last_file,
                        min_attempt_sec=float(request.get("min_attempt_sec") or MIN_ATTEMPT_SEC))
    if record["commands_count"] and record["sandbox_failures"] == record["commands_count"]:
        raise DriverError("sandbox_failed", "every command the model ran failed in Codex's sandbox ({}), so it read "
                          "no file".format(record["commands_count"]))
    document["paths_relativised"] = relativise(answer, scope_abs)
    document["review"] = answer
    document["review_summary"] = check_review(answer, len(counts))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--request", required=True)
    parser.add_argument("--keyfile", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    started = time.monotonic()
    document = {"driver_format": DRIVER_FORMAT, "status": "error"}
    key = ""
    code = 3
    codex_home = None
    try:
        with open(args.request) as f:
            request = json.load(f)
        codex_home = request.get("codex_home")
        document["request_options"] = {k: request.get(k) for k in (
            "mode", "model", "reasoning_effort", "sandbox", "attempts", "budget_sec")}
        try:
            with open(args.keyfile) as f:
                key = f.read().strip()
        except OSError as exc:
            raise DriverError("no_key", "cannot read the credential file: {}".format(exc))
        if not key:
            raise DriverError("no_key", "the credential file is empty")
        execute(request, key, args.keyfile, document, started,
                private_dirs=(os.path.dirname(os.path.abspath(args.request)),
                              os.path.dirname(os.path.abspath(args.out))))
        document["status"] = "ok"
        code = 0
    except DriverError as exc:
        document["error"] = {"code": exc.code, "message": scrub(exc.message, key)}
    except Exception as exc:
        document["error"] = {"code": "driver_crash", "message": scrub("{}: {}".format(type(exc).__name__, exc), key),
                             "traceback": tail(scrub(traceback.format_exc(), key), 3000)}
        code = 4
    finally:
        # auth.json holds the key: the whole private Codex home goes, also after a failure.
        if codex_home:
            shutil.rmtree(codex_home, ignore_errors=True)
            shutil.rmtree(os.path.join(os.path.dirname(codex_home), "codex-review-private"), ignore_errors=True)
            document["codex_home_removed"] = not os.path.lexists(codex_home)
    document["seconds"] = round(time.monotonic() - started, 1)
    text = scrub(json.dumps(document, indent=1, default=str), key)
    old = os.umask(0o077)
    try:
        with open(args.out, "w") as f:
            f.write(text)
    finally:
        os.umask(old)
    summary = {"status": document["status"], "error": (document.get("error") or {}).get("code"),
               "findings": len((document.get("review") or {}).get("findings") or []), "seconds": document["seconds"]}
    print("DRIVER_RESULT " + json.dumps(summary), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
