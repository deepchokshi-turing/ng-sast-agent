#!/usr/bin/env python3
"""Run anthropics/claude-code-security-review on /app/repo without GitHub.

Uploaded by ``ClaudeReviewAgent`` and run inside the task sandbox with the
Python of the claude-review venv (anthropic and requests pinned), as::

    python -I -B driver.py --request <request.json> --keyfile <key file> --out <result.json>

The upstream tool reviews a GitHub pull request. Its library parts have no
GitHub dependency, so this script calls them directly (see the study in the
agent's docs):

1. A pull request is synthesised: every in-scope file the agent listed is a new
   file added against an empty base, so the diff is the whole file. The upstream
   ``@generated`` rule is applied to it, and binary files are left out.
2. ``prompts.get_security_audit_prompt`` builds the prompt. In ``scoped`` mode
   the agent's custom scan instructions go through the upstream
   ``custom_scan_instructions`` argument.
3. The Claude Code CLI runs the review in /app/repo with the upstream command
   line plus ``-p`` and our own settings (see ``cli_argv`` and
   ``cli_settings``). The prompt goes on stdin.
4. ``findings_filter.FindingsFilter`` runs the upstream hard rules and the
   per-finding Claude API check, with the key passed in-process.

Where the upstream code would quietly turn a failure into "no findings" this
script stops with an error instead: no parseable result, ``is_error`` or a
non-success subtype, a result with no findings JSON, a model that says it did
not finish or reviewed no file, a filter whose API check failed, and any
per-finding filter call that failed (upstream keeps such a finding at
confidence 10). One deadline covers everything.

The credential is read from ``--keyfile`` (a mode 600 file in a mode 700
directory that the agent removes afterwards). It is never put on a command
line. The request's ``auth`` says what it is:

- ``api_key`` (an Anthropic API key): the CLI gets it through an
  ``apiKeyHelper`` in a private settings file (``cli_auth``
  "api_key_helper", the default) or, as a fallback, in the CLI process's own
  environment (``cli_auth`` "env"). The filter gets it as an argument.
- ``oauth`` (a Claude subscription token from ``claude setup-token``): the
  token works for Claude Code only. The CLI process alone gets it, as
  CLAUDE_CODE_OAUTH_TOKEN in its own environment, with no apiKeyHelper. The
  API preflight is skipped, the filter runs its regex rules only, and the
  anthropic SDK is replaced by a guard module that refuses to make a client,
  so no code in this process can send the token to the API.

Every text this script writes is scrubbed of the credential.

Output: ``--out`` gets one JSON document (see ``main``), and the last stdout
line is ``DRIVER_RESULT {json}``. Exit status 0 when the review can be
trusted, 3 when it cannot (the document says why in ``error``), 4 on a crash.

Standard library only at import time, and written for Python 3.8+. The
upstream package and anthropic are imported once the paths are set.
"""

import argparse
import hashlib
import json
import os
import queue
import shlex
import signal
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request

DRIVER_FORMAT = 1

#: The pull-request frame the upstream prompt needs. Neutral on purpose: it says
#: nothing about the task.
PR_NUMBER = 1
PR_TITLE = "Full repository security review"
PR_AUTHOR = "reviewer"
PR_CONTEXT = {"repo_name": "local", "pr_number": PR_NUMBER, "title": PR_TITLE, "description": ""}

#: Tools the review must not use. The upstream action relies on print mode
#: denying any tool that needs approval; this makes it explicit, and also
#: covers settings a repository might bring (project settings are not loaded).
DENIED_TOOLS = ("Bash", "WebFetch", "WebSearch", "Edit", "MultiEdit", "Write", "NotebookEdit")

#: Environment variables that would change how the CLI or the SDK authenticate
#: or where they connect. Removed from this process before anything runs.
SCRUBBED_ENV_PREFIXES = ("ANTHROPIC_", "CLAUDE_CODE_", "CLAUDECODE", "CLAUDE_CONFIG_DIR")
#: Claude Code's own switches for traffic other than the model API.
QUIET_ENV = {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_AUTOUPDATER": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
}

#: Seconds kept back at the end for writing the result.
RESERVE_SEC = 15
#: A CLI attempt with less time than this left is not started.
MIN_ATTEMPT_SEC = 60
#: A filter call with less time than this left is not started.
MIN_FILTER_CALL_SEC = 20
#: The upstream per-call limit of the filter (constants.DEFAULT_TIMEOUT_SECONDS).
FILTER_CALL_TIMEOUT_SEC = 180
NETWORK_CHECK_TIMEOUT_SEC = 20
PREFLIGHT_TIMEOUT_SEC = 60
PREFLIGHT_ATTEMPTS = 3
#: Characters of the CLI's own output kept per attempt.
TAIL_CHARS = 4000
#: Bytes read to decide whether a file is binary (as git does: a NUL byte).
BINARY_SNIFF_BYTES = 8000

#: What the CLI prints when it refuses a credential (Claude Code 2.1.296: "Invalid API key · Please run
#: /login", "OAuth token revoked · Please run /login", "Failed to authenticate. API Error: 401 ...",
#: "Login expired · Please run /login", "Not logged in"). Matched case-insensitively.
AUTH_FAILURE_MARKERS = ("invalid api key", "please run /login", "not logged in", "oauth token revoked",
                        "oauth token has expired", "login expired", "failed to authenticate", "authentication_error",
                        "api error: 401", "invalid bearer token")

#: CLI result subtypes that a retry cannot fix.
FATAL_SUBTYPES = ("error_max_turns", "error_max_budget_usd")


class DriverError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code
        self.message = message


def tail(text, limit=TAIL_CHARS):
    text = text or ""
    return text if len(text) <= limit else "[... {} characters cut ...]".format(len(text) - limit) + text[-limit:]


def sha256_text(text):
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- the pull request


def read_repo_file(repo, path):
    """(kind, text). kind is "text", "binary", "missing" or "unreadable"."""
    full = os.path.join(repo, path)
    if os.path.islink(full) or not os.path.isfile(full):
        return "missing", None
    try:
        with open(full, "rb") as f:
            data = f.read()
    except OSError:
        return "unreadable", None
    if b"\0" in data[:BINARY_SNIFF_BYTES]:
        return "binary", None
    return "text", data.decode("utf-8", "replace")


def file_section(path, text):
    """One file of a ``git diff`` against an empty base."""
    lines = text.splitlines()
    head = "diff --git a/{0} b/{0}\nnew file mode 100644\n--- /dev/null\n+++ b/{0}\n".format(path)
    if not lines:
        return head
    body = "".join("+" + line + "\n" for line in lines)
    if not text.endswith(("\n", "\r")):
        body += "\\ No newline at end of file\n"
    return head + "@@ -0,0 +1,{} @@\n".format(len(lines)) + body


def synthesise_pr(repo, files):
    """The pull request that adds every in-scope file: (pr_data, diff, record).

    ``files`` are repo-relative paths, already filtered by the task scope. The
    upstream rule drops a file whose diff section contains ``@generated``
    (github_action_audit.py:170-174), so that is done here too. Binary files are
    listed but have no diff, as in git. ``record["line_counts"]`` holds the line
    count of every text file, which the agent uses to check finding locations.
    """
    sections = []
    record = {"files": len(files), "in_diff": [], "skipped_generated": [], "skipped_binary": [], "missing": [],
              "line_counts": {}}
    additions = 0
    for path in files:
        kind, text = read_repo_file(repo, path)
        if kind != "text":
            record["skipped_binary" if kind == "binary" else "missing"].append(path)
            continue
        record["line_counts"][path] = len(text.splitlines())
        section = file_section(path, text)
        if "@generated" in section:
            record["skipped_generated"].append(path)
            continue
        sections.append(section)
        record["in_diff"].append(path)
        additions += record["line_counts"][path]
    listed = [p for p in files if p not in record["missing"]]
    pr_data = {
        "number": PR_NUMBER,
        "title": PR_TITLE,
        "user": PR_AUTHOR,
        "changed_files": len(listed),
        "additions": additions,
        "deletions": 0,
        "files": [{"filename": p} for p in listed],
    }
    diff = "".join(sections)
    record["diff_bytes"] = len(diff.encode("utf-8"))
    record["diff_sha256"] = sha256_text(diff)
    return pr_data, diff, record


# ---------------------------------------------------------------- the CLI


def cli_settings(keyfile, home, cli_auth):
    """The CLI's user settings. No secret in here: the helper only names the file.
    Only ``cli_auth`` "api_key_helper" gets a helper (never "oauth")."""
    deny = list(DENIED_TOOLS)
    # The key's folder and the CLI's own home are outside the repository, and
    # print mode denies reads there anyway. These rules say so explicitly.
    for folder in (os.path.dirname(keyfile), home):
        deny.append("Read(/{}/**)".format(folder.rstrip("/")))
    settings = {"permissions": {"deny": deny}}
    if cli_auth == "api_key_helper":
        settings["apiKeyHelper"] = "cat {}".format(shlex.quote(keyfile))
    return settings


def cli_argv(claude, model, settings_file, max_turns=None, max_budget_usd=None):
    """The upstream command (github_action_audit.py:224-229) plus our flags.

    Upstream: ``claude --output-format json --model <m> --disallowed-tools
    Bash(ps:*)``. Changed: ``--output-format stream-json --verbose``, whose last
    line is the same result object that ``json`` prints, and whose first line
    (the init message) says which model, credential source and tools the CLI
    really uses, so a wrong one is stopped before the review spends anything
    (see ``check_init``). Added: ``-p`` (upstream relies on stdout being a
    pipe), ``--settings`` with our settings and ``--setting-sources user`` so the
    repository's own .claude settings are not loaded, ``--strict-mcp-config`` so
    its .mcp.json is not either, ``--no-session-persistence``, and the optional
    limits.
    """
    argv = [claude, "--output-format", "stream-json", "--verbose", "--model", model, "--disallowed-tools",
            "Bash(ps:*)", "-p", "--settings", settings_file, "--setting-sources", "user", "--strict-mcp-config",
            "--no-session-persistence"]
    if max_turns:
        argv += ["--max-turns", str(int(max_turns))]
    if max_budget_usd:
        argv += ["--max-budget-usd", "{:g}".format(float(max_budget_usd))]
    return argv


#: The CLI's ``apiKeySource`` for each ``cli_auth``. With a subscription token
#: Claude Code 2.1.296 reports "none": ``apiKeySource`` names where an API key
#: came from, and its schema says "'none' (no API key in use - e.g. claude.ai
#: OAuth login, a bearer token, or a third-party cloud provider)". The token's
#: own source is a separate ``tokenSource`` that the init message does not carry.
#: The allow-listed environment rules out a bearer token and the other providers.
EXPECTED_KEY_SOURCE = {"api_key_helper": "apiKeyHelper", "env": "ANTHROPIC_API_KEY", "oauth": "none"}


def init_summary(init):
    keys = ("model", "apiKeySource", "permissionMode", "tools", "mcp_servers", "claude_code_version", "cwd")
    return {k: init.get(k) for k in keys if k in init}


def check_init(init, model, cli_auth):
    """None when the CLI's init message is what we asked for, else (code, reason).

    - The model must be the one requested. If Claude Code runs a model id as
      another model (an alias, a retired model, a setting from the
      environment), the review must not be reported under the requested one.
    - The credential must come from our key (``apiKeySource``), not from
      anything else the sandbox may offer. With a subscription token
      (``cli_auth`` "oauth") the source must be "none": an API key from
      anywhere (an apiKeyHelper, ANTHROPIC_API_KEY, a stored /login key) would
      bill another account.
    - No denied tool may be available.
    """
    used = init.get("model")
    if used != model:
        return ("model_remapped", "Claude Code would run the review on {!r}, not on the requested {!r}. Pass "
                "--ak model=<model id> (or set CLAUDE_REVIEW_MODEL) with a model your key can use, for example "
                "--ak model={}".format(used, model, used))
    source = init.get("apiKeySource")
    if source != EXPECTED_KEY_SOURCE.get(cli_auth):
        return ("cli_auth", "Claude Code takes its credential from {!r}, expected {!r}".format(
            source, EXPECTED_KEY_SOURCE.get(cli_auth)))
    tools = init.get("tools")
    if not isinstance(tools, list):
        return ("cli_settings", "the CLI's init message lists no tools, so the deny list cannot be checked")
    allowed = [t for t in tools if t in DENIED_TOOLS]
    if allowed:
        return ("cli_settings", "denied tools are still available to the review: {}".format(", ".join(allowed)))
    return None


#: The only variables the CLI inherits from this process: locale, temp dir,
#: CA bundles and proxies. Anything else, above all the ``ANTHROPIC_*``,
#: ``CLAUDE_*`` and ``CLAUDE_CODE_*`` settings a host or image may carry (for
#: example CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST, which lets the host pick the
#: model), never reaches it.
CLI_ENV_ALLOW = frozenset((
    "PATH", "LANG", "LANGUAGE", "TZ", "TMPDIR", "TERM", "USER", "LOGNAME",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
))
CLI_ENV_ALLOW_PREFIXES = ("LC_",)


def cli_environment(home, key, cli_auth, path_prefix):
    """The CLI's environment: the allow-listed variables of this process, plus
    HOME and the quiet switches. The key is in it only with ``cli_auth`` env
    (as ANTHROPIC_API_KEY), and a subscription token only with ``cli_auth``
    oauth (as CLAUDE_CODE_OAUTH_TOKEN, the one Claude setting added)."""
    env = {name: value for name, value in os.environ.items()
           if name in CLI_ENV_ALLOW or name.startswith(CLI_ENV_ALLOW_PREFIXES)}
    env.update(QUIET_ENV)
    env["HOME"] = home
    if path_prefix:
        env["PATH"] = path_prefix + os.pathsep + env.get("PATH", "/usr/bin:/bin")
    if cli_auth == "env":
        env["ANTHROPIC_API_KEY"] = key
    elif cli_auth == "oauth":
        env["CLAUDE_CODE_OAUTH_TOKEN"] = key
    return env


def auth_failure(stdout, stderr):
    """A short reason when the CLI's output says it refused the credential, else None."""
    text = "{}\n{}".format(stdout or "", stderr or "").lower()
    for marker in AUTH_FAILURE_MARKERS:
        if marker in text:
            return marker
    return None


def wrapper_summary(wrapper):
    keys = ("type", "subtype", "is_error", "num_turns", "total_cost_usd", "duration_ms", "duration_api_ms",
            "session_id", "usage", "modelUsage", "permission_denials", "stop_reason")
    return {k: wrapper.get(k) for k in keys if k in wrapper}


def run_cli_once(argv, prompt, cwd, env, timeout, check=None):
    """Run the CLI once: (exit code or None, stdout, stderr, seconds, init, abort).

    The prompt goes on stdin. stdout is read as it comes: the first JSON line
    of type ``system``/``init`` is passed to ``check``, and when that returns
    (code, reason) the whole process group is killed at once and ``abort`` is
    that pair. On timeout the group is killed and the exit code is None.
    """
    started = time.monotonic()
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=cwd, env=env, start_new_session=True)
    lines = queue.Queue()
    err_chunks = []

    def write():
        try:
            proc.stdin.write(prompt.encode("utf-8"))
        except OSError:
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def read_out():
        for raw in iter(proc.stdout.readline, b""):
            lines.put(raw.decode("utf-8", "replace"))
        lines.put(None)

    def read_err():
        err_chunks.append(proc.stderr.read().decode("utf-8", "replace"))

    threads = [threading.Thread(target=f, daemon=True) for f in (write, read_out, read_err)]
    for thread in threads:
        thread.start()

    def kill():
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()

    out = []
    init = None
    abort = None
    timed_out = False
    deadline = started + max(1.0, timeout)
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            timed_out = True
            kill()
            break
        try:
            line = lines.get(timeout=min(left, 5.0))
        except queue.Empty:
            continue
        if line is None:
            break
        out.append(line)
        if init is None and line.lstrip().startswith("{"):
            try:
                message = json.loads(line)
            except ValueError:
                message = None
            if isinstance(message, dict) and message.get("type") == "system" and message.get("subtype") == "init":
                init = message
                abort = check(init) if check else None
                if abort:
                    kill()
                    break
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        kill()
        proc.wait()
    for thread in threads:
        thread.join(timeout=5)
    code = None if timed_out else proc.returncode
    return code, "".join(out), "".join(err_chunks), round(time.monotonic() - started, 1), init, abort


def result_message(stdout, parse_json):
    """The CLI's result object: the last ``type: result`` line of stream-json,
    else the whole output parsed as one JSON value (``--output-format json``)."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if isinstance(message, dict) and message.get("type") == "result":
            return message
    ok, message = parse_json(stdout, "Claude Code output")
    if ok and isinstance(message, dict) and message.get("type") == "result":
        return message
    return None


def judge_attempt(code, stdout, parse_json):
    """What one CLI run gave: a dict with ``outcome`` and the parsed parts.

    outcome is "ok", "prompt_too_long", "fatal" (a retry cannot help) or
    "retry". ``parse_json`` is upstream ``json_parser.parse_json_with_fallbacks``.
    """
    if code is None:
        return {"outcome": "timeout", "reason": "the CLI did not finish in its time"}
    wrapper = result_message(stdout, parse_json)
    if wrapper is None:
        reason = "the CLI exited {} without a JSON result".format(code) if code else "the CLI output is not a JSON result"
        return {"outcome": "retry", "reason": reason}
    judged = {"wrapper": wrapper_summary(wrapper)}
    result_text = wrapper.get("result") if isinstance(wrapper.get("result"), str) else ""
    subtype = wrapper.get("subtype")
    if wrapper.get("is_error") and "prompt is too long" in result_text.lower():
        judged.update(outcome="prompt_too_long", reason="prompt is too long")
        return judged
    if subtype in FATAL_SUBTYPES:
        judged.update(outcome="fatal", reason="the CLI stopped with subtype {}".format(subtype))
        return judged
    if code != 0 or wrapper.get("is_error") or subtype != "success":
        judged.update(outcome="retry", reason="the CLI reported an error (exit {}, subtype {}, is_error {}): {}".format(
            code, subtype, wrapper.get("is_error"), tail(result_text, 300)))
        return judged
    ok, review = parse_json(result_text, "Claude result text")
    if not ok or not isinstance(review, dict) or not isinstance(review.get("findings"), list):
        judged.update(outcome="retry", reason="the model's reply holds no JSON with a findings list")
        return judged
    judged.update(outcome="ok", review=review)
    return judged


def run_review(argv, prompt_for, cwd, env, attempts, cli_deadline, parse_json, sleep=time.sleep,
               min_attempt_sec=MIN_ATTEMPT_SEC, check_init_for=None, record=None, refused=None):
    """Run the CLI until it gives a usable review. Returns (review, record).

    ``prompt_for(include_diff)`` builds the prompt. ``check_init_for(init)``
    vets the CLI's init message (see ``check_init``). ``refused`` is a
    (code, message) pair: a failed attempt whose output says the credential
    was refused raises it at once instead of retrying. Raises DriverError when
    no attempt gives a usable review. ``record`` (filled as it goes, so it is
    complete after a failure too) is returned with the review.
    """
    record = {} if record is None else record
    record.update({"attempts": [], "diff_omitted": False})
    include_diff = True
    prompt = prompt_for(True)
    record["prompt_sha256"] = sha256_text(prompt)
    record["prompt_bytes"] = len(prompt.encode("utf-8"))
    failures = 0
    last_reason = "no attempt was started"
    while failures < attempts:
        left = cli_deadline - time.monotonic()
        if left < min_attempt_sec:
            raise DriverError("deadline", "the review's time ran out before a usable CLI result ({} attempt(s), last: {})"
                              .format(len(record["attempts"]), last_reason))
        code, out, err, seconds, init, abort = run_cli_once(argv, prompt, cwd, env, left, check_init_for)
        if init is not None:
            record["init"] = init_summary(init)
        if abort:
            record["attempts"].append({"exit_code": code, "seconds": seconds, "outcome": "aborted",
                                       "reason": abort[1], "include_diff": include_diff})
            raise DriverError(abort[0], abort[1])
        judged = judge_attempt(code, out, parse_json)
        entry = {"exit_code": code, "seconds": seconds, "outcome": judged["outcome"],
                 "include_diff": include_diff, "stderr_tail": tail(err, 1500)}
        for key in ("reason", "wrapper"):
            if key in judged:
                entry[key] = judged[key]
        if judged["outcome"] != "ok":
            entry["stdout_tail"] = tail(out, 1500)
        record["attempts"].append(entry)
        if refused and judged["outcome"] in ("retry", "fatal"):
            marker = auth_failure(out, err)
            if marker:
                entry["auth_failure"] = marker
                raise DriverError(refused[0], "{} (the CLI said {!r})".format(refused[1], marker))
        if judged["outcome"] == "ok":
            record["cli"] = judged.get("wrapper")
            if init is None:
                raise DriverError("cli_init_missing", "the CLI printed no init message, so the model, credential "
                                  "and tools it used cannot be checked")
            used = sorted(((judged.get("wrapper") or {}).get("modelUsage") or {}).keys())
            requested = init.get("model")
            if used and requested not in used:
                raise DriverError("model_remapped", "the CLI reports usage for {} but not for the requested {!r}"
                                  .format(", ".join(used), requested))
            return judged["review"], record
        last_reason = judged.get("reason", judged["outcome"])
        if judged["outcome"] == "timeout":
            raise DriverError("timeout", "the CLI did not finish within the review's time ({} s)".format(int(left)))
        if judged["outcome"] == "fatal":
            raise DriverError("cli_limit", last_reason)
        if judged["outcome"] == "prompt_too_long":
            if not include_diff:
                raise DriverError("cli_failed", "the prompt is too long even without the diff")
            # Upstream's second pass: the file list only (github_action_audit.py:591-595).
            include_diff = False
            record["diff_omitted"] = True
            prompt = prompt_for(False)
            record["prompt_without_diff_sha256"] = sha256_text(prompt)
            continue
        failures += 1
        if failures < attempts:
            sleep(min(5 * failures, max(0.0, cli_deadline - time.monotonic() - min_attempt_sec)))
    raise DriverError("cli_failed", "every CLI attempt failed ({}), last: {}".format(attempts, last_reason))


def check_review(review, files_in_scope):
    """The review's own summary must say it finished and looked at something."""
    summary = review.get("analysis_summary")
    summary = summary if isinstance(summary, dict) else {}
    if summary.get("review_completed") is False:
        raise DriverError("review_incomplete", "the model reported review_completed false")
    reviewed = summary.get("files_reviewed")
    if files_in_scope and isinstance(reviewed, (int, float)) and not isinstance(reviewed, bool) and reviewed <= 0:
        raise DriverError("files_reviewed_zero",
                          "the model reported files_reviewed {} while {} files are in scope".format(
                              reviewed, files_in_scope))
    bad = [i for i, f in enumerate(review.get("findings") or []) if not isinstance(f, dict)]
    if bad:
        raise DriverError("bad_findings", "findings {} are not JSON objects".format(bad[:10]))
    return summary


# ---------------------------------------------------------------- the API


class Usage(object):
    """Token counts of the direct API calls (preflight and filter), per model."""

    FIELDS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")

    def __init__(self):
        self.by_model = {}
        self.calls = 0

    def add(self, model, usage):
        self.calls += 1
        row = self.by_model.setdefault(str(model), {k: 0 for k in self.FIELDS})
        for k in self.FIELDS:
            value = getattr(usage, k, None)
            if isinstance(value, int):
                row[k] += value


def wrap_create(client, usage):
    """Count tokens of every messages.create on an Anthropic client. Best effort."""
    try:
        messages = client.messages
        original = messages.create

        def create(*args, **kwargs):
            response = original(*args, **kwargs)
            usage.add(kwargs.get("model"), getattr(response, "usage", None))
            return response

        messages.create = create
    except Exception:  # counting is informational
        pass


def classify_api_error(anthropic, exc):
    """(code, message) for an exception from the SDK."""
    name = type(exc).__name__
    text = "{}: {}".format(name, exc)
    if isinstance(exc, getattr(anthropic, "AuthenticationError", ())) or \
            isinstance(exc, getattr(anthropic, "PermissionDeniedError", ())):
        return "api_auth", "the API refused the key ({}). Check ANTHROPIC_API_KEY on the host".format(text)
    if isinstance(exc, getattr(anthropic, "NotFoundError", ())):
        return "model_unavailable", text
    if isinstance(exc, getattr(anthropic, "APIConnectionError", ())):
        return "network", "cannot reach the Anthropic API from the sandbox ({})".format(text)
    return "api_error", text


def preflight(anthropic, key, models, usage, sleep=time.sleep):
    """One tiny request per model, so a bad key, a retired model or a blocked
    network fails in seconds instead of after the CLI's own long retries."""
    client = anthropic.Anthropic(api_key=key, max_retries=0)
    wrap_create(client, usage)
    checked = {}
    for model in models:
        if model in checked:
            continue
        last = None
        for attempt in range(PREFLIGHT_ATTEMPTS):
            try:
                client.messages.create(model=model, max_tokens=1, timeout=PREFLIGHT_TIMEOUT_SEC,
                                       messages=[{"role": "user", "content": "ping"}])
                last = None
                break
            except Exception as exc:
                code, message = classify_api_error(anthropic, exc)
                last = (code, message)
                if code in ("api_auth", "model_unavailable") or attempt == PREFLIGHT_ATTEMPTS - 1:
                    break
                sleep(2 * (attempt + 1))
        if last is not None:
            code, message = last
            if code == "model_unavailable":
                message = ("the model {!r} is not available to this key (retired, misspelt or not enabled): {}. "
                           "Choose another with --ak model=... or CLAUDE_REVIEW_MODEL".format(model, message))
            raise DriverError(code, message)
        checked[model] = "ok"
    return checked


def network_check(url):
    """Any HTTP answer from the API host means the sandbox can reach it."""
    try:
        with urllib.request.urlopen(url, timeout=NETWORK_CHECK_TIMEOUT_SEC) as response:
            return {"url": url, "status": response.status}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code}
    except Exception as exc:
        raise DriverError("network", "the sandbox cannot reach {} ({}: {}). This agent needs HTTPS egress to the "
                          "Anthropic API from the task container".format(url, type(exc).__name__, exc))


def make_api_client_class(base, usage, calls, deadline, check_model):
    """A ClaudeAPIClient that keeps the upstream prompts and retries but:

    - checks API access with ``check_model`` (the filter's own model) instead of
      the hard-coded claude-3-5-haiku-20241022, which may be retired;
    - never starts a call after the deadline, and shortens the per-call
      timeout to the time left;
    - records every finding analysis, so a failed one can be turned into an
      error (upstream keeps such a finding at confidence 10);
    - counts tokens.
    """

    class BenchClaudeAPIClient(base):
        def __init__(self, *args, **kwargs):
            base.__init__(self, *args, **kwargs)
            wrap_create(self.client, usage)

        def validate_api_access(self):
            try:
                self.client.messages.create(model=check_model, max_tokens=1, timeout=PREFLIGHT_TIMEOUT_SEC,
                                            messages=[{"role": "user", "content": "ping"}])
                calls.append({"kind": "validate", "ok": True, "model": check_model})
                return True, ""
            except Exception as exc:
                calls.append({"kind": "validate", "ok": False, "model": check_model,
                              "error": "{}: {}".format(type(exc).__name__, exc)})
                return False, "API validation failed: {}: {}".format(type(exc).__name__, exc)

        def analyze_single_finding(self, finding, pr_context=None, custom_filtering_instructions=None):
            left = deadline - time.monotonic()
            entry = {"kind": "finding", "file": finding.get("file"), "line": finding.get("line"),
                     "category": finding.get("category")}
            if left < MIN_FILTER_CALL_SEC:
                entry.update(ok=False, error="not started: the review's time ran out")
                calls.append(entry)
                return False, {}, entry["error"]
            self.timeout_seconds = int(min(FILTER_CALL_TIMEOUT_SEC, left - 5))
            started = time.monotonic()
            ok, result, error = base.analyze_single_finding(self, finding, pr_context, custom_filtering_instructions)
            entry.update(ok=bool(ok and result), seconds=round(time.monotonic() - started, 1))
            if entry["ok"]:
                entry.update(keep=result.get("keep_finding"), confidence=result.get("confidence_score"))
            else:
                entry["error"] = error or "no analysis"
            calls.append(entry)
            return ok, result, error

    return BenchClaudeAPIClient


def run_filter(findings_filter_module, client_module, filter_mode, key, model, instructions, findings, usage,
               deadline):
    """Upstream FindingsFilter, with failures made visible. Returns (kept, excluded, record)."""
    calls = []
    record = {"mode": filter_mode, "model": model if filter_mode == "claude" else None, "calls": calls}
    if filter_mode == "claude":
        cls = make_api_client_class(client_module.ClaudeAPIClient, usage, calls, deadline, model)
        # FindingsFilter builds its client from this module-level name.
        findings_filter_module.ClaudeAPIClient = cls
        ff = findings_filter_module.FindingsFilter(use_hard_exclusions=True, use_claude_filtering=True, api_key=key,
                                                   model=model, custom_filtering_instructions=instructions)
        if not ff.use_claude_filtering or ff.claude_client is None:
            reasons = [c.get("error") for c in calls if c.get("kind") == "validate" and not c.get("ok")]
            raise DriverError("filter_validation", "the false-positive filter could not use the API ({}), so "
                              "upstream would fall back to the hard rules only".format(
                                  reasons[-1] if reasons else "client not created"))
    else:
        ff = findings_filter_module.FindingsFilter(use_hard_exclusions=True, use_claude_filtering=False)
    ok, results, stats = ff.filter_findings(findings, PR_CONTEXT)
    if not ok:
        raise DriverError("filter_failed", "FindingsFilter reported failure")
    kept = list(results.get("filtered_findings") or [])
    excluded = list(results.get("excluded_findings") or [])
    record["summary"] = results.get("analysis_summary")
    failed = [c for c in calls if c.get("kind") == "finding" and not c.get("ok")]
    if filter_mode == "claude":
        silent = [f for f in kept if str((f.get("_filter_metadata") or {}).get("justification", ""))
                  .startswith("Claude API failed")]
        if failed or silent:
            first = failed[0].get("error") if failed else (silent[0].get("_filter_metadata") or {}).get("justification")
            raise DriverError("filter_call_failed", "{} of {} per-finding filter call(s) failed (upstream would keep "
                              "those findings at confidence 10). First: {}".format(
                                  max(len(failed), len(silent)), len(findings), tail(str(first), 400)))
    return kept, excluded, record


# ---------------------------------------------------------------- main


def scrub_environment(keep):
    removed = []
    for name in list(os.environ):
        if name.startswith(SCRUBBED_ENV_PREFIXES) and name not in keep:
            removed.append(name)
            del os.environ[name]
    return sorted(removed)


class SdkDisabled(RuntimeError):
    pass


def install_sdk_guard():
    """Put a stand-in for the anthropic package into ``sys.modules`` before the
    upstream code is imported. ``from anthropic import Anthropic`` still works,
    but making a client raises, so a subscription token can never reach the
    API from this process. The real SDK is not imported at all."""
    import types

    guard = types.ModuleType("anthropic")
    guard.__version__ = None
    guard.SDK_GUARD = True

    class Anthropic(object):
        def __init__(self, *args, **kwargs):
            raise SdkDisabled("the anthropic SDK is disabled with a subscription token (auth oauth)")

    guard.Anthropic = Anthropic
    sys.modules["anthropic"] = guard
    return guard


def versions(anthropic_module):
    out = {"python": sys.version.split()[0], "anthropic": getattr(anthropic_module, "__version__", None)}
    try:
        import requests  # noqa: F401  (upstream imports it; record which)
        out["requests"] = getattr(requests, "__version__", None)
    except Exception:
        out["requests"] = None
    return out


def claude_version(claude, env):
    try:
        proc = subprocess.run([claude, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                              timeout=60)
        return proc.stdout.decode("utf-8", "replace").strip()
    except Exception as exc:
        raise DriverError("cli_missing", "cannot run {} --version: {}".format(claude, exc))


def write_private(path, text):
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    os.chmod(folder, 0o700)
    old = os.umask(0o077)
    try:
        with open(path, "w") as f:
            f.write(text)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)


def execute(request, key, keyfile, document, started):
    """The review itself. Fills ``document`` as it goes, raises DriverError."""
    budget = float(request["budget_sec"])
    deadline = started + budget - RESERVE_SEC
    cli_deadline = started + budget * float(request.get("cli_share") or 0.6)
    repo = request["repo"]
    home = request["home"]
    model = request["model"]
    filter_model = request.get("filter_model") or model
    auth = request.get("auth") or "api_key"
    oauth = auth == "oauth"
    filter_mode = request.get("filter") or ("hard_rules" if oauth else "claude")
    cli_auth = "oauth" if oauth else (request.get("cli_auth") or "api_key_helper")
    files = list(request.get("files") or [])
    if auth not in ("api_key", "oauth"):
        raise DriverError("bad_request", "unknown auth {!r}".format(auth))
    if oauth and filter_mode != "hard_rules":
        raise DriverError("oauth_filter", "the {} filter needs an Anthropic API key, and this run has a subscription "
                          "token only".format(filter_mode))
    document["auth"] = auth
    document["filter_mode"] = filter_mode

    # Also removes a CLAUDE_CODE_OAUTH_TOKEN the process may have inherited: the token comes from the file.
    document["environment_removed"] = scrub_environment(keep=())
    # Upstream reads these at import time (constants.py, github_action_audit.py).
    os.environ["CLAUDE_MODEL"] = model
    os.environ["REPO_PATH"] = repo
    os.environ["ENABLE_CLAUDE_FILTERING"] = "true" if filter_mode == "claude" else "false"
    sys.path.insert(0, request["ccsr_dir"])
    if oauth:
        install_sdk_guard()
    try:
        import anthropic
        from claudecode import claude_api_client, findings_filter, json_parser, prompts
        from claudecode import constants as upstream_constants
    except Exception as exc:
        raise DriverError("import_failed", "cannot import the upstream review code: {}: {}".format(
            type(exc).__name__, exc))
    document["versions"] = versions(anthropic)
    document["upstream_default_model"] = upstream_constants.DEFAULT_CLAUDE_MODEL

    usage = Usage()
    document["api_usage"] = usage.by_model

    # 1. The API is reachable, takes the key and serves the models.
    # No credential goes with the network check. The preflight needs an API key, so a
    # subscription token skips it: a bad token or model shows up in the CLI's own run.
    document["network"] = network_check(request.get("network_check_url") or "https://api.anthropic.com/")
    if oauth:
        document["preflight"] = "skipped_oauth"
    else:
        models = [model] + ([filter_model] if filter_mode == "claude" else [])
        document["preflight"] = preflight(anthropic, key, models, usage)

    # 2. The pull request and the prompt.
    pr_data, diff, pr_record = synthesise_pr(repo, files)
    document["pr"] = pr_record
    if not pr_record["in_diff"] and not pr_data["files"]:
        raise DriverError("nothing_to_review", "none of the {} in-scope files could be read".format(len(files)))
    scan_instructions = request.get("scan_instructions")

    def prompt_for(include_diff):
        return prompts.get_security_audit_prompt(pr_data, diff, include_diff=include_diff,
                                                 custom_scan_instructions=scan_instructions)

    # 3. The CLI.
    settings = cli_settings(keyfile, home, cli_auth)
    settings_file = os.path.join(home, ".claude", "settings.json")
    write_private(settings_file, json.dumps(settings, indent=2))
    document["cli_settings"] = settings
    claude = request["claude"]
    env = cli_environment(home, key, cli_auth, os.path.dirname(claude))
    document["cli_environment"] = sorted(env)   # names only
    document["claude_code_version"] = claude_version(claude, env)
    argv = cli_argv(claude, model, settings_file, request.get("max_turns"), request.get("max_budget_usd"))
    document["cli_argv"] = argv
    cli_record = document["cli"] = {}
    review, _ = run_review(argv, prompt_for, repo, env, int(request.get("cli_attempts") or 3),
                                    min(cli_deadline, deadline), json_parser.parse_json_with_fallbacks,
                                    min_attempt_sec=float(request.get("min_attempt_sec") or MIN_ATTEMPT_SEC),
                                    check_init_for=lambda init: check_init(init, model, cli_auth),
                                    record=cli_record,
                                    refused=("cli_oauth_refused", "Claude Code refused the subscription token. Run "
                                             "`claude setup-token` again and set CLAUDE_CODE_OAUTH_TOKEN")
                                    if oauth else None)
    document["review"] = review
    document["review_summary"] = check_review(review, len(pr_data["files"]))

    # 4. The false-positive filter.
    findings = list(review.get("findings") or [])
    # A subscription token is never passed to the filter (it runs the regex rules only).
    kept, excluded, filter_record = run_filter(findings_filter, claude_api_client, filter_mode,
                                               None if oauth else key, filter_model,
                                               request.get("filter_instructions"), findings, usage, deadline)
    document["filter"] = filter_record
    document["kept"] = kept
    document["excluded"] = excluded
    document["api_calls"] = usage.calls


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
    try:
        with open(args.request) as f:
            request = json.load(f)
        document.update({k: request.get(k) for k in ("mode", "model", "filter", "filter_model", "auth", "cli_auth",
                                                     "max_turns", "max_budget_usd", "cli_attempts", "budget_sec",
                                                     "cli_share")})
        try:
            with open(args.keyfile) as f:
                key = f.read().strip()
        except OSError as exc:
            raise DriverError("no_key", "cannot read the credential file: {}".format(exc))
        if not key:
            raise DriverError("no_key", "the credential file is empty")
        execute(request, key, args.keyfile, document, started)
        document["status"] = "ok"
        code = 0
    except DriverError as exc:
        document["error"] = {"code": exc.code, "message": exc.message}
    except Exception as exc:
        document["error"] = {"code": "driver_crash", "message": "{}: {}".format(type(exc).__name__, exc),
                             "traceback": tail(traceback.format_exc(), 3000)}
        code = 4
    document["seconds"] = round(time.monotonic() - started, 1)
    text = json.dumps(document, indent=1, default=str)
    if key:
        text = text.replace(key, "***")
    old = os.umask(0o077)
    try:
        with open(args.out, "w") as f:
            f.write(text)
    finally:
        os.umask(old)
    summary = {"status": document["status"], "error": (document.get("error") or {}).get("code"),
               "raw": len((document.get("review") or {}).get("findings") or []),
               "kept": len(document.get("kept") or []), "seconds": document["seconds"]}
    print("DRIVER_RESULT " + json.dumps(summary), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
