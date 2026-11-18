#!/usr/bin/env python3
"""Run ``promptfoo code-scans run`` on the in-scope files, inside the sandbox.

Uploaded by ``PromptfooCodeScanAgent`` next to install.py and run as
``python3 -I -B scan.py --request <json> --keyfile <file> --out <json>``.
Standard library only, written for any Python 3.6+.

Promptfoo Code Scanning reviews a change set: the files that differ between
two git refs. The task repositories have no history of their own (and no git),
so this script builds one that makes the whole scope the change:

1. ``scope_dir``, a fresh mode 700 directory outside /app/repo, gets a copy of
   each in-scope file (the task's scanner roots minus its excluded paths, as
   the agent listed them) and of security_manifest.json, at the same relative
   paths. Links and anything that is not a regular file are left out. Nothing
   else of /app/repo (the task's tests, solution or validation files, if any
   were there) is in it.
2. ``scope_dir`` becomes a git repository with the pinned git: branch ``main``
   with one empty commit, then branch ``scan`` with every copied file
   committed (``git add -A -f``, so a .gitignore in the copy hides nothing).
   System and global git config are ignored, and the dates are fixed.
3. promptfoo runs ``code-scans run <scope_dir> --base main --compare scan -f
   json`` (plus ``--guidance-file`` in scoped mode, and the options the agent
   passes). Its working directory is an empty private directory, because
   promptfoo loads ``.env`` from the working directory; its HOME and
   PROMPTFOO_CONFIG_DIR are private too; telemetry and update checks are off.
   The filesystem MCP server promptfoo starts to let the service read files is
   rooted at ``scope_dir`` (promptfoo's own default, "diffs + tracing into
   repo"), so it can read nothing outside the copy.

The API key is read from ``--keyfile`` and given to the promptfoo process only,
as PROMPTFOO_API_KEY in its own environment (the variable promptfoo's
``resolveBaseAuthCredentials`` reads), never on a command line. promptfoo's
private HOME (which may hold logs) and working directory are deleted at the
end, and the key is scrubbed from everything this script writes.

The result document (``--out``) has ``status`` "ok" or "error", ``error``
``{"code", "message"}``, promptfoo's JSON response (``response``: ``comments``
and ``review``), the scope copy record, the line count of every copied text
file (``line_counts``, to check reported lines against), the git record and
timings. Exit status 0 when the document was written.
"""

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time

MANIFEST_FILE = "security_manifest.json"
TAIL_CHARS = 4000
#: promptfoo's own limits (scanner-gevGsaKW.js, 0.124.1): larger blobs are skipped as "too large".
PROMPTFOO_MAX_BLOB_BYTES = 512000
#: promptfoo's DENYLIST_PATTERNS (0.124.1): files it leaves out of the change set. Recorded, not changed.
DENYLIST_DIRS = frozenset(("node_modules", "dist", "build", ".next", ".venv", "__pycache__"))
DENYLIST_NAMES = ("*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "poetry.lock",
                  "composer.lock", "Pipfile.lock", "*.min.js", "*.map", "*.bin", "*.exe", "*.dll", "*.so", "*.dylib",
                  "*.zip", "*.tar", "*.gz", "*.jpg", "*.jpeg", "*.png", "*.gif", "*.pdf", "*.mp4", "*.mov")
#: What promptfoo inherits from this process's environment.
ENV_ALLOW = frozenset((
    "LANG", "LANGUAGE", "TZ", "TMPDIR", "TERM", "SYSTEMROOT",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
))
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "sast-agent", "GIT_AUTHOR_EMAIL": "sast-agent@localhost",
    "GIT_COMMITTER_NAME": "sast-agent", "GIT_COMMITTER_EMAIL": "sast-agent@localhost",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}
#: Seconds kept for the copy, git and writing the result.
RESERVE_SEC = 30

#: promptfoo's failure text -> error code, first match wins (checked in this order).
#: Codes the agent turns into infrastructure errors: auth, network, service, git, mcp.
#: Any other failure is "tool_failed" (a tool outcome).
ERROR_PATTERNS = (
    ("auth", ("Authentication failed", "Authentication required", "Invalid API", "Unauthorized", "unauthorized",
              "Forbidden", "status code 401", "status code 403")),
    ("service", ("Server at capacity", "Scan cancelled by server", "status code 5")),
    ("network", ("Failed to connect to server", "Connection timeout", "Lost connection to server", "ENOTFOUND",
                 "ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "EAI_AGAIN", "getaddrinfo", "socket hang up",
                 "websocket error", "xhr poll error")),
    ("git", ("GitError", "Failed to process diff", "Failed to extract git metadata", "Failed to validate branch",
             "Not on a branch", "not a git repository")),
    ("mcp", ("Filesystem MCP", "filesystem MCP", "server-filesystem")),
)


class ScanError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code


def tail(text, limit=TAIL_CHARS):
    text = text or ""
    return text if len(text) <= limit else "[... {} characters cut ...]\n".format(len(text) - limit) + text[-limit:]


def scrub(text, secret):
    if not isinstance(text, str):
        return text
    return text.replace(secret, "***") if secret else text


def scrub_tree(value, secret):
    """``value`` (decoded JSON) with every string scrubbed of ``secret``."""
    if isinstance(value, str):
        return scrub(value, secret)
    if isinstance(value, list):
        return [scrub_tree(v, secret) for v in value]
    if isinstance(value, dict):
        return {scrub(k, secret): scrub_tree(v, secret) for k, v in value.items()}
    return value


def text_lines(text):
    """Lines as git and finding line numbers count them: split on "\\n" only, a
    final "\\n" ends the last line (as the Claude review driver counts)."""
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def classify(text):
    """The error code for promptfoo's failure ``text``."""
    for code, needles in ERROR_PATTERNS:
        if any(n in (text or "") for n in needles):
            return code
    return "tool_failed"


def in_promptfoo_denylist(path):
    """Whether promptfoo's own denylist drops ``path`` from the change set."""
    parts = path.split("/")
    return any(p in DENYLIST_DIRS for p in parts[:-1]) or any(fnmatch.fnmatchcase(parts[-1], n) for n in DENYLIST_NAMES)


def make_scope_copy(repo, files, scope_dir):
    """A fresh ``scope_dir`` with a copy of each in-scope file and of
    security_manifest.json. Returns (record, line counts of the copied text files)."""
    if os.path.lexists(scope_dir):
        shutil.rmtree(scope_dir)
    os.makedirs(scope_dir)
    os.chmod(scope_dir, 0o700)
    copied, skipped, line_counts, binary, large = [], [], {}, [], []
    wanted = list(files)
    if MANIFEST_FILE not in wanted:
        wanted.append(MANIFEST_FILE)
    for path in wanted:
        source = os.path.join(repo, path)
        target = os.path.normpath(os.path.join(scope_dir, path))
        if path.startswith("/") or ".." in path.split("/") or \
                not target.startswith(os.path.normpath(scope_dir) + os.sep) or path.split("/")[0] == ".git":
            skipped.append(path)
            continue
        if os.path.islink(source) or not os.path.isfile(source):
            if path != MANIFEST_FILE or os.path.lexists(source):
                skipped.append(path)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(source, target)
        copied.append(path)
        with open(target, "rb") as f:
            data = f.read()
        if len(data) > PROMPTFOO_MAX_BLOB_BYTES:
            large.append(path)
        if b"\0" in data:
            binary.append(path)
            continue
        line_counts[path] = len(text_lines(data.decode("utf-8", "replace")))
    record = {"dir": scope_dir, "files": len(copied), "manifest": MANIFEST_FILE in copied,
              "manifest_outside_roots": MANIFEST_FILE in copied and MANIFEST_FILE not in files,
              "skipped": skipped[:200], "binary": binary[:200],
              "over_promptfoo_size_limit": large[:200],
              "in_promptfoo_denylist": [p for p in copied if in_promptfoo_denylist(p)][:200]}
    return record, line_counts


def git_env(home, git):
    env = {name: value for name, value in os.environ.items() if name in ENV_ALLOW}
    env.update({"HOME": home, "PATH": os.path.dirname(git) + ":" + SYSTEM_PATH, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    env.update(GIT_IDENTITY)
    return env


def run_git(git, args, cwd, env):
    command = [git, "-c", "core.autocrlf=false", "-c", "core.safecrlf=false", "-c", "commit.gpgsign=false",
               "-c", "core.hooksPath=" + os.devnull] + args
    try:
        proc = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError("git", "git {} could not run: {}".format(" ".join(args), exc))
    output = proc.stdout.decode("utf-8", "replace")
    if proc.returncode != 0:
        raise ScanError("git", "git {} failed (exit {}): {}".format(" ".join(args), proc.returncode, tail(output, 600)))
    return output


def make_change_set(scope_dir, git, home):
    """``main`` (one empty commit) and ``scan`` (every file of the copy) in ``scope_dir``."""
    env = git_env(home, git)
    run_git(git, ["init", "-q", "--template=", "-b", "main", "."], scope_dir, env)
    run_git(git, ["commit", "-q", "--allow-empty", "--no-verify", "-m", "empty base"], scope_dir, env)
    run_git(git, ["checkout", "-q", "-b", "scan"], scope_dir, env)
    run_git(git, ["add", "-A", "-f", "."], scope_dir, env)
    run_git(git, ["commit", "-q", "--allow-empty", "--no-verify", "-m", "in-scope files"], scope_dir, env)
    changed = [p for p in run_git(git, ["diff", "--name-only", "-z", "main...scan"], scope_dir, env).split("\0") if p]
    return {"base": "main", "compare": "scan", "files_changed": len(changed),
            "head": run_git(git, ["rev-parse", "scan"], scope_dir, env).strip()}


def promptfoo_argv(request):
    argv = [request["node"], request["promptfoo"], "code-scans", "run", request["scope_dir"],
            "--base", "main", "--compare", "scan", "-f", "json"]
    if request.get("min_severity"):
        argv += ["--min-severity", request["min_severity"]]
    if request.get("diffs_only"):
        argv.append("--diffs-only")
    if request.get("guidance_file"):
        argv += ["--guidance-file", request["guidance_file"]]
    return argv


def promptfoo_env(request, key):
    env = {name: value for name, value in os.environ.items() if name in ENV_ALLOW}
    home = request["home"]
    env.update({
        "HOME": home,
        "PATH": "{}:{}:{}".format(os.path.dirname(request["git"]), os.path.dirname(request["node"]), SYSTEM_PATH),
        "PROMPTFOO_CONFIG_DIR": os.path.join(home, ".promptfoo"),
        "PROMPTFOO_DISABLE_TELEMETRY": "1",
        "PROMPTFOO_DISABLE_UPDATE": "1",
        "NO_COLOR": "1",
        "FORCE_COLOR": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "PROMPTFOO_API_KEY": key,
    })
    return env


def parse_response(stdout):
    """promptfoo's ``-f json`` response: the JSON object on stdout, else None."""
    decoder = json.JSONDecoder()
    index = stdout.find("{")
    while index >= 0:
        try:
            value, _end = decoder.raw_decode(stdout, index)
        except ValueError:
            index = stdout.find("{", index + 1)
            continue
        if isinstance(value, dict) and "comments" in value:
            return value
        index = stdout.find("{", index + 1)
    return None


def run_promptfoo(request, key, seconds):
    """(exit code, stdout, stderr, seconds, timed out)."""
    started = time.monotonic()
    proc = subprocess.Popen(promptfoo_argv(request), cwd=request["cwd"], env=promptfoo_env(request, key),
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=max(1, seconds))
    except subprocess.TimeoutExpired:
        timed_out = True
        for sig, wait in ((signal.SIGTERM, 10), (getattr(signal, "SIGKILL", signal.SIGTERM), 10)):
            try:
                if hasattr(os, "killpg"):
                    os.killpg(proc.pid, sig)
                else:  # not POSIX (only the tests run it there)
                    proc.kill()
            except OSError:
                pass
            try:
                out, err = proc.communicate(timeout=wait)
                break
            except subprocess.TimeoutExpired:
                out, err = b"", b""
    return (proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"),
            round(time.monotonic() - started, 1), timed_out)


def execute(request, key, document, started):
    deadline = started + float(request["budget_sec"])
    for name in ("home", "cwd"):
        if os.path.lexists(request[name]):
            shutil.rmtree(request[name])
        os.makedirs(request[name])
        os.chmod(request[name], 0o700)
    record, line_counts = make_scope_copy(request["repo"], request["files"], request["scope_dir"])
    document["scope_copy"] = record
    document["line_counts"] = line_counts
    if not record["files"]:
        raise ScanError("no_files", "none of the in-scope files could be copied")
    document["git"] = make_change_set(request["scope_dir"], request["git"], request["home"])
    document["argv"] = promptfoo_argv(request)
    document["env_names"] = sorted(promptfoo_env(request, "x"))
    seconds = deadline - time.monotonic() - RESERVE_SEC
    if seconds < 30:
        raise ScanError("deadline", "no time left to run promptfoo after preparing the scope")
    code, out, err, took, timed_out = run_promptfoo(request, key, seconds)
    document["promptfoo"] = {"exit_code": code, "seconds": took, "timed_out": timed_out,
                             "stderr_tail": tail(scrub(err, key)), "stdout_bytes": len(out)}
    if timed_out:
        raise ScanError("deadline", "promptfoo did not finish within {} s".format(int(seconds)))
    response = parse_response(out)
    if code != 0 or response is None:
        document["promptfoo"]["stdout_tail"] = tail(scrub(out, key))
    if code != 0:
        text = "\n".join(line for line in (err + "\n" + out).splitlines() if line.strip())
        message = next((line for line in text.splitlines() if "Scan failed" in line), tail(text, 600))
        raise ScanError(classify(text), "promptfoo exited {}: {}".format(code, message))
    if response is None:
        raise ScanError("bad_output", "promptfoo exited 0 without a JSON response on stdout")
    response = scrub_tree(response, key)
    document["response"] = response
    if response.get("success") is False or response.get("error"):
        message = str(response.get("error") or "the response says success: false")
        raise ScanError(classify(message), "promptfoo reported a failed scan: " + message[:600])
    if response.get("skipReason"):
        raise ScanError("skipped", "promptfoo skipped the scan: " + str(response.get("skipReason"))[:600])
    if not isinstance(response.get("comments"), list):
        raise ScanError("bad_output", "the response has no comments list")
    if not response["comments"] and str(response.get("review") or "").strip() == "No files to scan":
        raise ScanError("no_files", "promptfoo found no file to scan in the change set")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--keyfile", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    started = time.monotonic()
    with open(args.request) as f:
        request = json.load(f)
    document = {"scan_format": 1, "status": "error"}
    key = ""
    try:
        try:
            with open(args.keyfile) as f:
                key = f.read().strip()
        except OSError as exc:
            raise ScanError("no_key", "cannot read the key file: {}".format(exc))
        if not key:
            raise ScanError("no_key", "the key file is empty")
        document["request_sha256"] = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        execute(request, key, document, started)
        document["status"] = "ok"
    except ScanError as exc:
        document["error"] = {"code": exc.code, "message": scrub(str(exc), key)}
    except Exception as exc:  # a bug here: report it, never a traceback with the key
        document["error"] = {"code": "scan_script", "message": scrub("{}: {}".format(type(exc).__name__, exc), key)}
    finally:
        for name in ("home", "cwd"):
            if request.get(name):
                shutil.rmtree(request[name], ignore_errors=True)
    document["seconds"] = round(time.monotonic() - started, 1)
    text = scrub(json.dumps(document, indent=1), key)
    with open(args.out, "w") as f:
        f.write(text)
    print("SCAN_RESULT " + json.dumps({"status": document["status"],
                                       "error": (document.get("error") or {}).get("code")}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
