#!/usr/bin/env python3
"""Run datadog-saist once on a copy of the in-scope files (inside the task sandbox).

Uploaded by ``DatadogSaistAgent`` with the Claude review's driver (as
``ccsr_driver.py``, for its scope-copy and text helpers) and started as::

    python3 -I -B datadog_saist_driver.py --request <request.json> --keyfile <key file> --out <result.json>

The request holds everything but the key. The key is read from the mode 600
key file and given to the binary only in its own environment, under the
provider's variable name (``OPENAI_API_KEY``, ``ANTHROPIC_API_KEY`` or
``GOOGLE_API_KEY``, which the binary reads). It is never on a command line,
and every text kept in the result is scrubbed of it and of OpenAI's masked
form of a key.

What the driver does:

1. Copies the in-scope files (and security_manifest.json) to ``scope_dir``,
   outside /app/repo, and counts the lines of each text file.
2. Checks that the sandbox reaches the provider API and, unless the run uses
   the embedded rules, Datadog's public rule endpoint.
3. Runs ``datadog-saist --directory <scope copy> --output <private sarif>
   --detection-model M --validation-model M --debug ...`` with an allow-listed
   environment and a private HOME, bounded by the request's deadline.
4. Reads the SARIF and decides what the run was. datadog-saist exits 0 and
   writes a SARIF even when every model call failed (a refused key, for
   example): each failed (file, rule) scan is only tagged ``RULE_FAILURE`` on
   the SARIF artifact and logged with ``--debug``. So the driver counts the
   ``RULE_SUCCESS``/``RULE_FAILURE`` tags and classifies the logged errors.

The result document (``--out``) has ``status`` "ok" or "error" with an
``error`` {code, message}; ``DRIVER_RESULT {json}`` is the last stdout line.
Standard library only.
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
    import ccsr_driver  # the Claude review's driver, uploaded next to this file
except ImportError:  # run from the repository (the tests)
    sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))
    from sast.claude_review import driver as ccsr_driver

DRIVER_FORMAT = 1
RESERVE_SEC = 10
NETWORK_CHECK_TIMEOUT_SEC = 20
TAIL_CHARS = 6000
ENV_ALLOW = frozenset(("PATH", "LANG", "LANGUAGE", "TZ", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
                       "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"))
ENV_ALLOW_PREFIXES = ("LC_",)
#: OpenAI masks a key in its error messages as "sk-proj-****...ykcA".
MASKED_KEY = re.compile(r"\b(?:sk|org|proj)-[A-Za-z0-9_-]{0,12}\*{3,}[A-Za-z0-9_-]{0,8}")

#: Error text -> code. The first match wins, so the specific ones come first.
ERROR_PATTERNS = (
    ("api_auth", ("401 unauthorized", "invalid_api_key", "incorrect api key", "invalid api key",
                  "invalid x-api-key", "authentication_error", "api key not valid", "403 forbidden",
                  "permission_denied", "no openai authentication found", "no anthropic authentication found",
                  "no gemini authentication found")),
    ("quota", ("insufficient_quota", "exceeded your current quota", "credit balance is too low", "billing")),
    ("model_unavailable", ("model_not_found", "does not exist or you do not have access", "unsupported model",
                           "not_found_error")),
    ("prompt_too_long", ("context_length_exceeded", "maximum context length", "prompt is too long")),
    ("rate_limited", ("429 too many requests", "rate limit", "rate_limit")),
    ("network", ("no such host", "connection refused", "connection reset", "network is unreachable",
                 "i/o timeout", "tls handshake timeout")),
)
#: The rule download failed (internal/api/datadog_api.go and analysis/client.go).
RULES_FAILURE_MARKERS = ("failed to make request", "api request failed with status", "failed to decode response")
#: Codes that make the whole scan untrustworthy even when some scans succeeded.
FATAL_CODES = ("api_auth", "quota", "model_unavailable", "network")


class DriverError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code
        self.message = message


def scrub(text, secret):
    return MASKED_KEY.sub("***", ccsr_driver.scrub(text or "", secret))


def tail(text, limit=TAIL_CHARS):
    return ccsr_driver.tail(text, limit)


def classify(text):
    low = (text or "").lower()
    for code, needles in ERROR_PATTERNS:
        if any(n in low for n in needles):
            return code
    return None


def tool_environment(home, key_env, key):
    env = {name: value for name, value in os.environ.items()
           if name in ENV_ALLOW or name.startswith(ENV_ALLOW_PREFIXES)}
    env["HOME"] = home
    env[key_env] = key
    return env


def reach(url):
    """Any HTTP answer means the host can be reached; returns the status. No key is sent."""
    try:
        with urllib.request.urlopen(url, timeout=NETWORK_CHECK_TIMEOUT_SEC) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception as exc:
        raise DriverError("network", "the sandbox cannot reach {} ({}: {})".format(url, type(exc).__name__, exc))


def tool_argv(request, scope_dir, sarif_file):
    argv = [request["binary"], "--directory", scope_dir, "--output", sarif_file,
            "--detection-model", request["detection_model"], "--validation-model", request["validation_model"],
            "--request-timeout-sec", str(int(request["request_timeout_sec"])),
            "--file-concurrency", str(int(request["file_concurrency"])), "--debug"]
    if request.get("rules") == "embedded":
        argv.append("--local-prompts")
    if request.get("skip_indexing"):
        argv.append("--skip-indexing")
    return argv


def tags_of(properties):
    tags = (properties or {}).get("tags") if isinstance(properties, dict) else None
    return [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []


def tag_value(tags, name):
    for tag in tags:
        if tag.startswith(name + ":"):
            return tag[len(name) + 1:]
    return None


def scan_summary(sarif):
    """Files analysed, (file, rule) scans that succeeded and failed, tokens, from the tool's own SARIF tags."""
    runs = sarif.get("runs") if isinstance(sarif, dict) else None
    if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
        raise DriverError("bad_output", "the SARIF has no run")
    run = runs[0]
    succeeded, failed, failures = 0, 0, []
    artifacts = run.get("artifacts") if isinstance(run.get("artifacts"), list) else []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        uri = ((artifact.get("location") or {}).get("uri"))
        tags = tags_of(artifact.get("properties"))
        ok = [r for r in (tag_value(tags, "RULE_SUCCESS") or "").split(",") if r]
        bad = [r for r in (tag_value(tags, "RULE_FAILURE") or "").split(",") if r]
        succeeded += len(ok)
        failed += len(bad)
        failures += [[uri, r] for r in bad]
    run_tags = tags_of(run.get("properties"))

    def number(name):
        value = tag_value(run_tags, name)
        return int(value) if value and value.isdigit() else None

    results = run.get("results")
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules")
    return {"files_analysed": len(artifacts), "scans_succeeded": succeeded, "scans_failed": failed,
            "scan_failures": failures[:200],
            "input_tokens": number("DATADOG_SAIST_INPUT_TOKENS"), "output_tokens": number("DATADOG_SAIST_OUTPUT_TOKENS"),
            "results": len(results) if isinstance(results, list) else None,
            "rules": len(rules) if isinstance(rules, list) else None}


def execute(request, key, keyfile, document, started):
    deadline = started + float(request["budget_sec"]) - RESERVE_SEC
    repo = request["repo"]
    files = list(request.get("files") or [])
    scope_dir = request["scope_dir"]
    private = request["private_dir"]
    scope_abs, repo_abs = os.path.abspath(scope_dir), os.path.abspath(repo)
    if (not os.path.isabs(scope_dir) or scope_abs in ("/", repo_abs) or (repo_abs + os.sep).startswith(scope_abs + os.sep)
            or scope_abs.startswith(repo_abs + os.sep)):
        raise DriverError("bad_request", "scope_dir {!r} must be an absolute directory apart from the "
                          "repository".format(scope_dir))
    key_env = request["key_env"]
    if key_env not in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"):
        raise DriverError("bad_request", "unknown key variable {!r}".format(key_env))

    # 1. The scope copy and the line counts the agent checks locations against.
    document["scope_copy"] = ccsr_driver.make_scope_copy(repo, files, scope_dir)
    counts, not_text = {}, []
    for path in files:
        kind, text = ccsr_driver.read_repo_file(repo, path)
        if kind == "text":
            counts[path] = len(ccsr_driver.text_lines(text))
        else:
            not_text.append([path, kind])
    document["line_counts"] = counts
    document["not_text"] = not_text[:200]
    if not counts:
        raise DriverError("nothing_to_review", "none of the {} in-scope files is a readable text file".format(len(files)))

    # 2. The network.
    network = {}
    if request.get("provider_url"):
        network["provider"] = {"url": request["provider_url"], "status": reach(request["provider_url"])}
    if request.get("rules") != "embedded" and request.get("rules_url"):
        status = reach(request["rules_url"])
        network["rules"] = {"url": request["rules_url"], "status": status}
        if status != 200:
            raise DriverError("rules_unavailable", "Datadog's public rule endpoint answered HTTP {}".format(status))
    document["network"] = network

    # 3. The scan.
    if os.path.lexists(private):
        shutil.rmtree(private)
    os.makedirs(os.path.join(private, "home"))
    os.chmod(private, 0o700)
    sarif_file = os.path.join(private, "results.sarif")
    argv = tool_argv(request, scope_dir, sarif_file)
    document["argv"] = argv
    env = tool_environment(os.path.join(private, "home"), key_env, key)
    document["tool_environment"] = sorted(env)  # names only
    seconds = deadline - time.monotonic()
    if seconds < 30:
        raise DriverError("deadline", "no time left for the scan ({} s)".format(int(seconds)))
    begun = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=scope_dir, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=seconds)
    except subprocess.TimeoutExpired as exc:
        document["tool_seconds"] = round(time.monotonic() - begun, 1)
        out = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        document["stderr_tail"] = tail(scrub(out, key))
        raise DriverError("deadline", "datadog-saist did not finish within {} s".format(int(seconds)))
    document["tool_seconds"] = round(time.monotonic() - begun, 1)
    stdout = scrub(proc.stdout.decode("utf-8", "replace"), key)
    stderr = scrub(proc.stderr.decode("utf-8", "replace"), key)
    document["exit_code"] = proc.returncode
    document["stdout_tail"] = tail(stdout, 2000)
    document["stderr_tail"] = tail(stderr)
    document["warnings"] = sum(1 for line in stderr.splitlines() if "\tWARN\t" in line)
    if proc.returncode != 0:
        low = stderr.lower()
        if request.get("rules") != "embedded" and any(m in low for m in RULES_FAILURE_MARKERS):
            raise DriverError("rules_unavailable", "datadog-saist could not load its rules from Datadog's API: "
                              + tail(stderr.strip(), 400))
        code = classify(stderr)
        raise DriverError(code or "tool_crashed", "datadog-saist exited {}: {}".format(proc.returncode,
                                                                                    tail(stderr.strip(), 600)))

    # 4. The SARIF and what the run was.
    try:
        with open(sarif_file, encoding="utf-8") as f:
            text = scrub(f.read(), key)
        sarif = json.loads(text)
    except (OSError, ValueError) as exc:
        raise DriverError("bad_output", "datadog-saist exited 0 without a readable SARIF: {}".format(exc))
    summary = scan_summary(sarif)
    document["summary"] = summary
    document["sarif"] = sarif
    if summary["scans_failed"]:
        code = classify(stderr)
        document["failure_code"] = code
        if code in FATAL_CODES or summary["scans_succeeded"] == 0:
            raise DriverError(code or "llm_failed", "{} of {} (file, rule) scans failed{}".format(
                summary["scans_failed"], summary["scans_failed"] + summary["scans_succeeded"],
                " ({})".format(code) if code else ""))
    if summary["files_analysed"] == 0:
        raise DriverError("tool_saw_nothing", "datadog-saist analysed none of the {} in-scope files".format(len(counts)))


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
    private = None
    try:
        with open(args.request) as f:
            request = json.load(f)
        private = request.get("private_dir")
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
        document["error"] = {"code": exc.code, "message": scrub(exc.message, key)}
    except Exception as exc:
        document["error"] = {"code": "driver_crash", "message": scrub("{}: {}".format(type(exc).__name__, exc), key),
                             "traceback": tail(scrub(traceback.format_exc(), key), 3000)}
        code = 4
    finally:
        if private:
            shutil.rmtree(private, ignore_errors=True)
            document["private_dir_removed"] = not os.path.lexists(private)
    document["seconds"] = round(time.monotonic() - started, 1)
    text = scrub(json.dumps(document, indent=1, default=str), key)
    old = os.umask(0o077)
    try:
        with open(args.out, "w") as f:
            f.write(text)
    finally:
        os.umask(old)
    summary = {"status": document["status"], "error": (document.get("error") or {}).get("code"),
               "results": (document.get("summary") or {}).get("results"), "seconds": document["seconds"]}
    print("DRIVER_RESULT " + json.dumps(summary), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
