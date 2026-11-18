#!/usr/bin/env python3
"""Run Cloudflare's security-audit skill in Claude Code on a copy of the in-scope files.

Uploaded by ``CloudflareAuditAgent`` and run inside the task sandbox with the
image's Python, as::

    python3 -I -B cf_driver.py --request <request.json> --keyfile <key file> --out <result.json>

next to ``ccsr_driver.py`` (the Claude review's driver.py, uploaded under that
name), whose standard-library helpers it reuses: the scope copy, the file
reader and line counter, the CLI runner with its process-group kill and init
check hook, the CLI environment, the credential-refusal markers, the result
message reader and the scrubber.

1. The in-scope files and security_manifest.json are copied to the scope
   folder (the audit's target). The skill's pinned files are copied to
   ``$HOME/.claude/skills/security-audit`` of a fresh private HOME, where
   Claude Code finds user skills, and their sha256 are checked again.
2. Claude Code runs in the scope folder, non-interactively (``-p``), with the
   request's prompt on stdin, ``--permission-mode dontAsk`` (anything not
   allowed below is denied, nothing is asked), only the agent's user settings
   (``--setting-sources user``, no MCP server), and these permissions:
   read the scope copy, the skill and the output folder; write and edit the
   output folder only; Bash only for the two validators under Node.js, a few
   read-only commands and ``mkdir`` in the output folder; sub-agents (``Task``)
   and the ``Skill`` tool as Claude Code offers them. Web access, notebooks,
   worktrees, cron and the like are denied, and so is reading the real
   repository, the key folder and ``/proc``.
3. The CLI's first message (init) must name the requested model, the expected
   credential source, permission mode ``dontAsk``, a sub-agent tool and, when
   it lists skills, ``security-audit``; otherwise the run stops at once.
4. After the run: ``run-metadata.json``, ``findings.json``,
   ``coverage-ledger.json`` and ``sast-annotations.json`` are read from the
   output folder, and the skill's two validators are run again by this script.
   ``run_status`` must be ``complete`` (the skill's own terminal state for a
   finished audit). Paths under the scope folder are made relative again.

The credential is read from ``--keyfile`` and reaches the CLI process only (a
subscription token as CLAUDE_CODE_OAUTH_TOKEN in its own environment, an API
key through an ``apiKeyHelper`` that reads the key file). Every text written is
scrubbed of it.

Output: ``--out`` gets one JSON document, and the last stdout line is
``DRIVER_RESULT {json}``. Exit status 0 when the audit can be trusted, 3 when
it cannot (``error`` says why), 4 on a crash. Standard library only, Python 3.8+.
"""

import argparse
import hashlib
import json
import os
import posixpath
import shlex
import shutil
import subprocess
import sys
import time
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
try:
    import ccsr_driver  # the Claude review driver, uploaded next to this file
except ImportError:  # run from the repository (the tests)
    sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))
    from sast.claude_review import driver as ccsr_driver

DRIVER_FORMAT = 1
DriverError = ccsr_driver.DriverError
MANIFEST_FILE = ccsr_driver.MANIFEST_FILE
SKILL_NAME = "security-audit"
ANNOTATIONS_FILE = "sast-annotations.json"
#: Seconds kept back at the end for reading the outputs and running the validators.
RESERVE_SEC = 45
MIN_ATTEMPT_SEC = 120
VALIDATOR_TIMEOUT_SEC = 60
TAIL_CHARS = 4000
#: Characters of REPORT.md kept in the result document.
REPORT_CHARS = 100000
#: Bytes of an output file read at most.
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
MAX_TOOL_USES = 5000
MAX_LISTED_FILES = 500

#: Tools the audit must not have (checked again in the init message).
DENIED_TOOLS = ("WebFetch", "WebSearch", "NotebookEdit", "CronCreate", "CronDelete", "CronList", "ScheduleWakeup",
                "EnterWorktree", "ExitWorktree", "DesignSync", "Workflow", "RemoteTrigger")
#: One of these must be there: the skill runs its hunters and verifiers as sub-agents.
SUBAGENT_TOOLS = ("Task", "Agent")
#: Read-only commands the audit may run (besides the validators and mkdir in the output folder).
READ_ONLY_COMMANDS = ("ls", "cat", "head", "tail", "wc", "grep", "rg", "find", "file", "stat", "cd", "pwd", "echo",
                      "printf", "sort", "uniq", "cut", "tr", "nl", "diff", "basename", "dirname", "realpath", "du",
                      "test", "true")
#: Bash command patterns denied even inside the allowed commands (deny wins over allow). The commands the CLI runs
#: inherit its environment, which holds a subscription token: CLAUDE_CODE_SUBPROCESS_ENV_SCRUB would strip it, but
#: in 2.1.296 it needs bubblewrap, which the task images lack (the CLI then exits at once), so commands that name the
#: credential variables, expand ${...} or read /proc are denied instead.
BASH_DENY_PATTERNS = ("*-exec*", "*-ok *", "*-delete*", "*-fprint*", "*--pre*", "*/proc/*", "*/proc", "*/proc *",
                      "*/app*", "*secret*", "*environ*", "*CLAUDE_CODE*", "*OAUTH*", "*ANTHROPIC*", "*${*")
#: Fields of a tool_use input that are kept (paths, patterns, the command, a sub-agent's type).
TOOL_FIELDS = ("file_path", "path", "pattern", "glob", "command", "subagent_type", "description", "skill")
TOOL_FS_FIELDS = ("file_path", "path")
#: Expected init permission mode.
PERMISSION_MODE = "dontAsk"


def scrub(text, secret):
    return ccsr_driver.scrub(text or "", secret)


def tail(text, limit=TAIL_CHARS):
    return ccsr_driver.tail(text, limit)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_json(text, what=None):
    """(ok, value): the ``parse_json`` shape ``ccsr_driver.result_message`` expects."""
    try:
        return True, json.loads(text)
    except (TypeError, ValueError):
        return False, None


# ---------------------------------------------------------------- set-up


def install_skill(source, home, expected):
    """A fresh copy of the pinned skill under ``home``/.claude/skills; every file's sha256 checked."""
    target = os.path.join(home, ".claude", "skills", SKILL_NAME)
    if os.path.lexists(target):
        shutil.rmtree(target)
    os.makedirs(target)
    for rel, sha in sorted(expected.items()):
        src = os.path.join(source, rel)
        if os.path.islink(src) or not os.path.isfile(src):
            raise DriverError("skill_missing", "skill file {} is missing".format(src))
        dst = os.path.join(target, rel)
        shutil.copyfile(src, dst)
        actual = sha256_file(dst)
        if actual != sha:
            raise DriverError("skill_missing", "skill file {} has sha256 {}, expected {}".format(rel, actual, sha))
    return target


def fresh_dir(path):
    if os.path.lexists(path):
        shutil.rmtree(path)
    os.makedirs(path)
    os.chmod(path, 0o700)


def rule_path(path):
    """A Claude Code permission rule path for an absolute directory: ``//abs/dir/**``."""
    return "/" + path.rstrip("/") + "/**"


def cli_settings(*, scope_dir, out_root, skill_dir, node, keyfile, repo, private_dirs, cli_auth):
    """The CLI's user settings: the permission rules. No secret in here."""
    allow = ["Read({})".format(rule_path(d)) for d in (scope_dir, out_root, skill_dir)]
    allow += ["Edit({})".format(rule_path(out_root)), "Write({})".format(rule_path(out_root))]
    for validator in ("validate-findings.cjs", "validate-coverage-ledger.cjs"):
        allow.append("Bash(node {}/{}:*)".format(skill_dir, validator))
        allow.append("Bash({} {}/{}:*)".format(node, skill_dir, validator))
    allow.append("Bash(mkdir -p {}/*)".format(out_root.rstrip("/")))
    allow += ["Bash({}:*)".format(c) for c in READ_ONLY_COMMANDS]
    deny = list(DENIED_TOOLS)
    for folder in (os.path.dirname(keyfile), repo) + tuple(private_dirs):
        deny.append("Read({})".format(rule_path(folder)))
    deny.append("Read(//proc/**)")
    deny += ["Bash({})".format(p) for p in BASH_DENY_PATTERNS]
    settings = {"permissions": {"allow": allow, "deny": deny, "defaultMode": PERMISSION_MODE}}
    if cli_auth == "api_key_helper":
        settings["apiKeyHelper"] = "cat {}".format(shlex.quote(keyfile))
    return settings


def cli_argv(claude, model, settings_file, add_dirs, max_turns=None, max_budget_usd=None, effort=None):
    argv = [claude, "--output-format", "stream-json", "--verbose", "--model", model, "-p",
            "--permission-mode", PERMISSION_MODE, "--settings", settings_file, "--setting-sources", "user",
            "--strict-mcp-config", "--no-session-persistence", "--add-dir"] + list(add_dirs)
    if max_turns:
        argv += ["--max-turns", str(int(max_turns))]
    if max_budget_usd:
        argv += ["--max-budget-usd", "{:g}".format(float(max_budget_usd))]
    if effort:
        argv += ["--effort", str(effort)]
    return argv


def check_init(init, model, cli_auth):
    """None when the init message is what was asked for, else (code, reason)."""
    if init.get("model") != model:
        return ("model_remapped", "Claude Code would run the audit on {!r}, not on the requested {!r}".format(
            init.get("model"), model))
    expected = ccsr_driver.EXPECTED_KEY_SOURCE.get(cli_auth)
    if init.get("apiKeySource") != expected:
        return ("cli_auth", "Claude Code takes its credential from {!r}, expected {!r}".format(
            init.get("apiKeySource"), expected))
    if init.get("permissionMode") != PERMISSION_MODE:
        return ("cli_settings", "Claude Code runs in permission mode {!r}, expected {!r}".format(
            init.get("permissionMode"), PERMISSION_MODE))
    tools = init.get("tools")
    if not isinstance(tools, list):
        return ("cli_settings", "the CLI's init message lists no tools, so the deny list cannot be checked")
    present = [t for t in tools if t in DENIED_TOOLS]
    if present:
        return ("cli_settings", "denied tools are still available: {}".format(", ".join(present)))
    if not any(t in tools for t in SUBAGENT_TOOLS):
        return ("no_subagents", "Claude Code offers no sub-agent tool ({}), which the skill needs".format(
            " or ".join(SUBAGENT_TOOLS)))
    skills = init.get("skills")
    if isinstance(skills, list) and SKILL_NAME not in skills:
        return ("skill_not_loaded", "Claude Code did not load the {} skill (skills: {})".format(
            SKILL_NAME, ", ".join(str(s) for s in skills[:20])))
    return None


def init_summary(init):
    keys = ("model", "apiKeySource", "permissionMode", "tools", "mcp_servers", "claude_code_version", "cwd", "skills",
            "agents")
    return {k: init.get(k) for k in keys if k in init}


# ---------------------------------------------------------------- the run


def _messages(stdout, kind):
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if isinstance(message, dict) and message.get("type") == kind and isinstance(message.get("message"), dict):
            content = message["message"].get("content")
            for block in content if isinstance(content, list) else []:
                if isinstance(block, dict):
                    yield block


def tool_uses(stdout):
    """(id, name, input) of every tool_use block of the stream-json, sub-agents' included, in order."""
    for block in _messages(stdout, "assistant"):
        if block.get("type") == "tool_use":
            yield (block.get("id"), str(block.get("name") or ""),
                   block.get("input") if isinstance(block.get("input"), dict) else {})


#: Words of a tool_result error that mean the permission rules refused the call.
REFUSAL_MARKERS = ("permission", "denied", "not allowed", "requires approval")


def refused_results(stdout):
    """{tool_use_id: text} of the tool results that are errors saying the call was refused."""
    out = {}
    for block in _messages(stdout, "user"):
        if block.get("type") != "tool_result" or not block.get("is_error"):
            continue
        content = block.get("content")
        if isinstance(content, list):
            content = " ".join(str(c.get("text") or "") for c in content if isinstance(c, dict))
        text = str(content or "")
        if any(marker in text.lower() for marker in REFUSAL_MARKERS):
            out[block.get("tool_use_id")] = text
    return out


def tool_use_records(stdout, roots, repo, secret, attempt):
    """(records, flagged): every tool_use with its path, pattern, command or sub-agent fields (scrubbed, cut to
    300 characters); flagged when a path is outside ``roots`` or a command names the real repository."""
    records, flagged = [], []
    refused = refused_results(stdout)
    for use_id, name, raw in tool_uses(stdout):
        entry = {"attempt": attempt, "tool": name}
        if use_id in refused:
            entry["refused"] = tail(scrub(refused[use_id], secret), 200)
        for field in TOOL_FIELDS:
            if field in raw and raw[field] is not None:
                entry[field] = tail(scrub(str(raw[field]), secret), 300)
        reasons = []
        for field in TOOL_FS_FIELDS:
            value = entry.get(field)
            if isinstance(value, str) and value.strip():
                full = posixpath.normpath(value if value.startswith("/") else posixpath.join(roots[0], value))
                if not any(full == r or full.startswith(r.rstrip("/") + "/") for r in roots):
                    reasons.append("{} outside the audit's folders".format(field))
        command = entry.get("command")
        if isinstance(command, str) and (repo.rstrip("/") in command or "/app/" in command or "/proc" in command):
            reasons.append("command names a denied path")
        if reasons:
            entry["outside_scope"] = "; ".join(reasons)
            flagged.append(entry)
        records.append(entry)
    return records, flagged


def judge(code, stdout):
    """What one CLI run gave: {"outcome": ok|timeout|prompt_too_long|fatal|retry, ...}."""
    if code is None:
        return {"outcome": "timeout", "reason": "the CLI did not finish in its time"}
    wrapper = ccsr_driver.result_message(stdout, parse_json)
    if wrapper is None:
        return {"outcome": "retry", "reason": "the CLI exited {} without a JSON result".format(code)}
    judged = {"wrapper": ccsr_driver.wrapper_summary(wrapper)}
    text = wrapper.get("result") if isinstance(wrapper.get("result"), str) else ""
    subtype = wrapper.get("subtype")
    if wrapper.get("is_error") and "prompt is too long" in text.lower():
        judged.update(outcome="prompt_too_long", reason="prompt is too long")
    elif subtype in ccsr_driver.FATAL_SUBTYPES:
        judged.update(outcome="fatal", reason="the CLI stopped with subtype {}".format(subtype))
    elif code != 0 or wrapper.get("is_error") or subtype != "success":
        judged.update(outcome="retry", reason="the CLI reported an error (exit {}, subtype {}, is_error {}): {}".format(
            code, subtype, wrapper.get("is_error"), tail(text, 300)))
    else:
        judged.update(outcome="ok", final_text=tail(text, 2000))
    return judged


def run_audit(argv, prompt, cwd, env, attempts, deadline, secret, roots, repo, out_dir, model, cli_auth, record,
              min_attempt_sec=MIN_ATTEMPT_SEC):
    """Run the CLI until the audit leaves its findings file. Fills ``record``; raises DriverError."""
    record.update({"attempts": [], "tool_uses": [], "tool_uses_count": 0, "tool_uses_outside_scope": []})
    record["prompt_sha256"] = ccsr_driver.sha256_text(prompt)
    record["prompt_bytes"] = len(prompt.encode("utf-8"))
    failures = 0
    last = "no attempt was started"
    oauth = cli_auth == "oauth"
    while failures < attempts:
        left = deadline - time.monotonic()
        if left < min_attempt_sec:
            raise DriverError("deadline", "the audit's time ran out ({} attempt(s), last: {})".format(
                len(record["attempts"]), last))
        if os.path.lexists(out_dir):
            shutil.rmtree(out_dir)
        code, out, err, seconds, init, abort = ccsr_driver.run_cli_once(
            argv, prompt, cwd, env, left, lambda i: check_init(i, model, cli_auth))
        out, err = scrub(out, secret), scrub(err, secret)
        uses, flagged = tool_use_records(out, roots, repo, secret, len(record["attempts"]) + 1)
        record["tool_uses_count"] += len(uses)
        record["tool_uses"] += uses[:max(0, MAX_TOOL_USES - len(record["tool_uses"]))]
        record["tool_uses_outside_scope"] += flagged
        if init is not None:
            record["init"] = init_summary(init)
        if abort:
            record["attempts"].append({"exit_code": code, "seconds": seconds, "outcome": "aborted", "reason": abort[1]})
            raise DriverError(abort[0], abort[1])
        judged = judge(code, out)
        entry = {"exit_code": code, "seconds": seconds, "outcome": judged["outcome"], "stderr_tail": tail(err, 1500)}
        for key in ("reason", "wrapper", "final_text"):
            if key in judged:
                entry[key] = judged[key]
        if judged["outcome"] != "ok":
            entry["stdout_tail"] = tail(out, 1500)
        record["attempts"].append(entry)
        if judged["outcome"] in ("retry", "fatal"):
            marker = ccsr_driver.auth_failure(out, err, parse_json)
            if marker:
                entry["auth_failure"] = marker
                raise DriverError("cli_oauth_refused" if oauth else "api_auth",
                                  "Claude Code refused the credential (the CLI said {!r})".format(marker))
        if judged["outcome"] == "ok":
            record["cli"] = judged.get("wrapper")
            if init is None:
                raise DriverError("cli_init_missing", "the CLI printed no init message, so the model, credential "
                                  "and tools it used cannot be checked")
            used = sorted(((judged.get("wrapper") or {}).get("modelUsage") or {}).keys())
            if used and model not in used:
                raise DriverError("model_remapped", "the CLI reports usage for {} but not for the requested {!r}"
                                  .format(", ".join(used), model))
            if os.path.isfile(os.path.join(out_dir, "findings.json")):
                return
            entry["outcome"] = "no_findings_file"
            last = "the CLI finished without writing {}/findings.json".format(out_dir)
            failures += 1
            if failures >= attempts:
                raise DriverError("no_findings_file", last)
            continue
        last = judged.get("reason", judged["outcome"])
        if judged["outcome"] == "timeout":
            raise DriverError("timeout", "the audit did not finish within its time ({} s)".format(int(left)))
        if judged["outcome"] == "fatal":
            raise DriverError("cli_limit", last)
        if judged["outcome"] == "prompt_too_long":
            raise DriverError("prompt_too_long", last)
        failures += 1
    raise DriverError("cli_failed", "every CLI attempt failed ({}), last: {}".format(attempts, last))


# ---------------------------------------------------------------- the outputs


def read_json(path, secret):
    """(status, value): status "missing", "too_large", "unparseable" or "ok"."""
    if os.path.islink(path) or not os.path.isfile(path):
        return "missing", None
    if os.path.getsize(path) > MAX_OUTPUT_BYTES:
        return "too_large", None
    with open(path, "rb") as f:
        text = scrub(f.read().decode("utf-8", "replace"), secret)
    ok, value = parse_json(text)
    return ("ok", value) if ok else ("unparseable", None)


def list_outputs(out_dir):
    files = []
    for folder, _, names in os.walk(out_dir):
        for name in sorted(names):
            full = os.path.join(folder, name)
            if not os.path.islink(full):
                files.append([os.path.relpath(full, out_dir).replace(os.sep, "/"), os.path.getsize(full)])
    files.sort()
    return {"count": len(files), "files": files[:MAX_LISTED_FILES]}


def run_validator(node, script, target, env, secret):
    if not os.path.isfile(target):
        return {"ran": False, "reason": "{} is missing".format(os.path.basename(target))}
    try:
        proc = subprocess.run([node, script, target], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                              timeout=VALIDATOR_TIMEOUT_SEC)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ran": False, "reason": "{}: {}".format(type(exc).__name__, exc)}
    return {"ran": True, "exit_code": proc.returncode, "passed": proc.returncode == 0,
            "output": tail(scrub(proc.stdout.decode("utf-8", "replace"), secret), 3000)}


def ledger_summary(ledger):
    """Units by status. The skill's ledger is a top-level array of units (validate-coverage-ledger.cjs)."""
    if isinstance(ledger, dict) and isinstance(ledger.get("units"), list):
        ledger = ledger["units"]
    if not isinstance(ledger, list):
        return None
    states = {}
    for unit in ledger:
        state = str(unit.get("status") or unit.get("state")) if isinstance(unit, dict) else "invalid"
        states[state] = states.get(state, 0) + 1
    return {"units": len(ledger), "by_state": states}


def relativise(findings, annotations, base):
    """trace, evidence and annotation location files under ``base`` made relative. Returns the count."""
    changed = 0
    items = []
    for record in findings if isinstance(findings, list) else []:
        if isinstance(record, dict):
            for key in ("trace", "evidence"):
                items += [s for s in (record.get(key) if isinstance(record.get(key), list) else [])
                          if isinstance(s, dict)]
    entries = (annotations or {}).get("findings") if isinstance(annotations, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("location"), dict):
            items.append(entry["location"])
    for item in items:
        new = ccsr_driver.relative_to(item.get("file"), base)
        if new != item.get("file"):
            item["file"] = new
            changed += 1
    return changed


def line_counts(repo, files):
    counts, not_text = {}, []
    for path in files:
        kind, text = ccsr_driver.read_repo_file(repo, path)
        if kind == "text":
            counts[path] = len(ccsr_driver.text_lines(text))
        else:
            not_text.append([path, kind])
    return counts, not_text


# ---------------------------------------------------------------- main


def execute(request, key, keyfile, document, started, private_dirs=()):
    budget = float(request["budget_sec"])
    deadline = started + budget - RESERVE_SEC
    repo = request["repo"]
    files = list(request.get("files") or [])
    auth = request.get("auth") or "oauth"
    if auth not in ("api_key", "oauth"):
        raise DriverError("bad_request", "unknown auth {!r}".format(auth))
    cli_auth = "oauth" if auth == "oauth" else "api_key_helper"
    model = request["model"]
    scope_dir, out_root, home = request["scope_dir"], request["out_root"], request["home"]
    out_dir = request["out_dir"]
    repo_abs = os.path.abspath(repo)
    for name, folder in (("scope_dir", scope_dir), ("out_root", out_root), ("home", home)):
        absolute = os.path.abspath(folder)
        if (not os.path.isabs(folder) or absolute in ("/", repo_abs) or absolute.startswith(repo_abs + os.sep)
                or (repo_abs + os.sep).startswith(absolute + os.sep)):
            raise DriverError("bad_request", "{} {!r} must be an absolute directory apart from the repository".format(
                name, folder))
    if not out_dir.startswith(out_root.rstrip("/") + "/"):
        raise DriverError("bad_request", "out_dir must be inside out_root")
    document["environment_removed"] = ccsr_driver.scrub_environment(keep=())

    # 1. The network, the target, the skill, the settings.
    document["network"] = ccsr_driver.network_check(request.get("network_check_url") or "https://api.anthropic.com/")
    counts, not_text = line_counts(repo, files)
    document["line_counts"] = counts
    document["not_text"] = not_text
    if not counts:
        raise DriverError("nothing_to_review", "none of the {} in-scope files could be read".format(len(files)))
    document["scope_copy"] = ccsr_driver.make_scope_copy(repo, files, scope_dir)
    fresh_dir(home)
    fresh_dir(out_root)
    skill_dir = install_skill(request["skill_src"], home, request["skill_files"])
    document["skill_dir"] = skill_dir
    claude, node = request["claude"], request["node"]
    settings = cli_settings(scope_dir=scope_dir, out_root=out_root, skill_dir=skill_dir, node=node, keyfile=keyfile,
                            repo=repo, private_dirs=private_dirs, cli_auth=cli_auth)
    settings_file = os.path.join(home, ".claude", "settings.json")
    ccsr_driver.write_private(settings_file, json.dumps(settings, indent=2))
    document["cli_settings"] = settings
    env = ccsr_driver.cli_environment(home, key, cli_auth,
                                      os.pathsep.join([os.path.dirname(claude), os.path.dirname(node)]))
    document["cli_environment"] = sorted(env)  # names only
    document["claude_code_version"] = ccsr_driver.claude_version(claude, env)
    prompt = request["prompt"]
    if "{out_dir}" in prompt or "{skill_dir}" in prompt:
        raise DriverError("bad_request", "the prompt still has placeholders")
    argv = cli_argv(claude, model, settings_file, [out_root, skill_dir], request.get("max_turns"),
                    request.get("max_budget_usd"), request.get("effort"))
    document["cli_argv"] = argv

    # 2. The audit.
    cli = document["cli"] = {}
    try:
        run_audit(argv, prompt, scope_dir, env, int(request.get("attempts") or 1), deadline, key,
                  [scope_dir, out_root, skill_dir], repo, out_dir, model, cli_auth, cli,
                  min_attempt_sec=float(request.get("min_attempt_sec") or MIN_ATTEMPT_SEC))
    finally:
        document["outputs"] = list_outputs(out_root) if os.path.isdir(out_root) else {"count": 0, "files": []}

    # 3. What it wrote.
    reads = {}
    for name in ("run-metadata.json", "findings.json", "coverage-ledger.json", ANNOTATIONS_FILE):
        reads[name] = read_json(os.path.join(out_dir, name), key)
    document["output_status"] = {name: status for name, (status, _) in reads.items()}
    metadata = reads["run-metadata.json"][1]
    findings = reads["findings.json"][1]
    annotations = reads[ANNOTATIONS_FILE][1]
    document["run_metadata"] = metadata if isinstance(metadata, dict) else None
    document["ledger"] = ledger_summary(reads["coverage-ledger.json"][1])
    report = os.path.join(out_dir, "REPORT.md")
    if os.path.isfile(report) and not os.path.islink(report):
        with open(report, "rb") as f:
            document["report_md"] = tail(scrub(f.read(MAX_OUTPUT_BYTES).decode("utf-8", "replace"), key), REPORT_CHARS)
    validator_env = {"PATH": os.path.dirname(node) + os.pathsep + "/usr/bin:/bin", "HOME": home}
    document["validators"] = {
        "findings": run_validator(node, os.path.join(skill_dir, "validate-findings.cjs"),
                                  os.path.join(out_dir, "findings.json"), validator_env, key),
        "coverage_ledger": run_validator(node, os.path.join(skill_dir, "validate-coverage-ledger.cjs"),
                                         os.path.join(out_dir, "coverage-ledger.json"), validator_env, key),
    }
    if not isinstance(findings, list):
        raise DriverError("bad_findings", "findings.json is {}, not a JSON list".format(
            reads["findings.json"][0] if reads["findings.json"][0] != "ok" else type(findings).__name__))
    bad = [i for i, f in enumerate(findings) if not isinstance(f, dict)]
    if bad:
        raise DriverError("bad_findings", "findings.json records {} are not JSON objects".format(bad[:10]))
    document["paths_relativised"] = relativise(findings, annotations, scope_dir)
    document["findings"] = findings
    document["annotations"] = annotations if isinstance(annotations, dict) else None
    status = (metadata or {}).get("run_status") if isinstance(metadata, dict) else None
    document["run_status"] = status
    if status != "complete":
        reason = (metadata or {}).get("incomplete_reason") if isinstance(metadata, dict) else None
        raise DriverError("review_incomplete", "the audit's run_status is {!r}{}".format(
            status, ", reason {!r}".format(reason) if reason else ""))


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
        document["request_options"] = {k: request.get(k) for k in (
            "mode", "model", "auth", "profile", "max_turns", "max_budget_usd", "effort", "attempts", "budget_sec")}
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
        document["error"] = {"code": exc.code, "message": exc.message}
    except Exception as exc:
        document["error"] = {"code": "driver_crash", "message": "{}: {}".format(type(exc).__name__, exc),
                             "traceback": tail(scrub(traceback.format_exc(), key), 3000)}
        code = 4
    document["seconds"] = round(time.monotonic() - started, 1)
    text = scrub(json.dumps(document, indent=1, default=str), key)
    old = os.umask(0o077)
    try:
        with open(args.out, "w") as f:
            f.write(text)
    finally:
        os.umask(old)
    summary = {"status": document["status"], "error": (document.get("error") or {}).get("code"),
               "records": len(document.get("findings") or []), "seconds": document["seconds"]}
    print("DRIVER_RESULT " + json.dumps(summary), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
