"""Fakes shared by the claude_review tests: a scripted ``claude`` CLI, a local
HTTP server for the network check, and helpers to run driver.py for real
against the vendored upstream code (tests/fixtures/ccsr_0c6a49f) and the fake
anthropic SDK (tests/fixtures/claude_review/fake_modules). Nothing here calls
a real API."""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from tests.conftest import FIXTURES, ROOT

CCSR_DIR = FIXTURES / "ccsr_0c6a49f"
FAKE_MODULES = FIXTURES / "claude_review" / "fake_modules"
FAKE_REQUESTS = FIXTURES / "claude_review" / "fake_requests"
DRIVER = ROOT / "sast" / "claude_review" / "driver.py"
KEY = "sk-ant-api03-TESTKEY-0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGH"
#: A made-up subscription token (the shape `claude setup-token` prints). Never a real one.
OAUTH_TOKEN = "sk-ant-oat01-TESTOAUTH-9876543210zyxwvutsrqponmlkjihgfedcba-QRSTUVWX"

#: The scripted CLI. It finds its files next to its own folder (the driver gives
#: the CLI an allow-listed environment, so no FAKE_* variable reaches it):
#: script.json is a JSON list, one entry per run:
#: {"exit": n, "stdout": "raw text"} or {"exit": n, "wrapper": {...}} where the
#: wrapper's "result" may be given as "review" (a dict, dumped to text). Output
#: is stream-json: an init message first (its fields can be overridden with
#: "init": {...}, or left out with "no_init": true), then the result. An entry
#: may also say "sleep": seconds (after the init), and "tool_uses": a list of
#: {"name": ..., "input": {...}} written as assistant tool_use messages before the
#: result. Runs past the end reuse the last entry.
#: Every run appends one JSON line to claude.log.
FAKE_CLAUDE = r'''#!{python}
import hashlib, json, os, subprocess, sys, time
if sys.argv[1:] == ["--version"]:
    print("2.1.296 (Claude Code)")
    sys.exit(0)
prompt = sys.stdin.read()
here = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
state = os.path.join(here, "claude.count")
count = int(open(state).read()) if os.path.exists(state) else 0
open(state, "w").write(str(count + 1))
script = json.load(open(os.path.join(here, "script.json")))
step = script[min(count, len(script) - 1)]
settings_file = sys.argv[sys.argv.index("--settings") + 1] if "--settings" in sys.argv else None
settings = json.load(open(settings_file)) if settings_file else None
helper_key = None
if settings and settings.get("apiKeyHelper"):
    helper_key = subprocess.run(["/bin/sh", "-c", settings["apiKeyHelper"]], stdout=subprocess.PIPE).stdout.decode().strip()
mode = oct(os.stat(settings_file).st_mode & 0o777) if settings_file else None
log = {"argv": sys.argv, "cwd": os.getcwd(), "home": os.environ.get("HOME"),
       "env_has_key": "ANTHROPIC_API_KEY" in os.environ, "env_key": os.environ.get("ANTHROPIC_API_KEY"),
       "env_oauth_token": os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"),
       "env_names": sorted(os.environ), "settings": settings, "settings_mode": mode, "helper_key": helper_key,
       "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(), "prompt_has_diff": "PR DIFF CONTENT:" in prompt,
       "prompt": prompt,
       "cwd_files": sorted(os.path.relpath(os.path.join(d, f), os.getcwd()) for d, _, fs in os.walk(os.getcwd())
                           for f in fs)}
with open(os.path.join(here, "claude.log"), "a") as f:
    f.write(json.dumps(log) + "\n")
if not step.get("no_init"):
    model = sys.argv[sys.argv.index("--model") + 1]
    source = "apiKeyHelper" if helper_key else ("ANTHROPIC_API_KEY" if "ANTHROPIC_API_KEY" in os.environ else "none")
    denied = (settings or {}).get("permissions", {}).get("deny", [])
    tools = [t for t in ["Task", "Bash", "Glob", "Grep", "Read", "Edit", "Write", "WebFetch", "WebSearch"]
             if t not in denied]
    init = {"type": "system", "subtype": "init", "cwd": os.getcwd(), "model": model, "apiKeySource": source,
            "tools": tools, "permissionMode": "default", "mcp_servers": [], "claude_code_version": "2.1.296"}
    init.update(step.get("init", {}))
    sys.stdout.write(json.dumps(init) + "\n")
    sys.stdout.flush()
time.sleep(step.get("sleep", 0))
for use in step.get("tool_uses", []):
    block = {"type": "tool_use", "id": "toolu_1", "name": use["name"], "input": use.get("input", {})}
    sys.stdout.write(json.dumps({"type": "assistant", "message": {"content": [block]}}) + "\n")
if "wrapper" in step:
    wrapper = dict(step["wrapper"])
    if "review" in wrapper:
        wrapper["result"] = json.dumps(wrapper.pop("review"))
    sys.stdout.write(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "..."}]}}) + "\n")
    sys.stdout.write(json.dumps(wrapper) + "\n")
else:
    sys.stdout.write(step.get("stdout", ""))
sys.exit(step.get("exit", 0))
'''


def wrapper(review: dict | None = None, *, subtype: str = "success", is_error: bool = False, result: str | None = None,
            cost: float = 0.42, turns: int = 7) -> dict:
    """A Claude Code ``--output-format json`` result."""
    out = {"type": "result", "subtype": subtype, "is_error": is_error, "duration_ms": 61000, "duration_api_ms": 58000,
           "num_turns": turns, "session_id": "11111111-2222-3333-4444-555555555555", "total_cost_usd": cost,
           "usage": {"input_tokens": 12000, "output_tokens": 900}, "modelUsage": {"claude-opus-4-1-20250805": {
               "inputTokens": 12000, "outputTokens": 900, "costUSD": cost}}, "permission_denials": []}
    if review is not None:
        out["review"] = review
    else:
        out["result"] = result or ""
    return out


def review(findings: list[dict], files_reviewed: int = 3, completed: bool = True) -> dict:
    return {"findings": findings, "analysis_summary": {
        "files_reviewed": files_reviewed, "high_severity": sum(f.get("severity") == "HIGH" for f in findings),
        "medium_severity": 0, "low_severity": 0, "review_completed": completed}}


def finding(file: str, line: int, category: str = "command_injection", severity: str = "HIGH", **extra) -> dict:
    out = {"file": file, "line": line, "severity": severity, "category": category,
           "description": f"{category} at {file}:{line}", "exploit_scenario": "an attacker controls the input",
           "recommendation": "validate the input", "confidence": 0.9}
    out.update(extra)
    return out


class NetCheckServer:
    """http://127.0.0.1:<port>/ answering 404, like api.anthropic.com/ does."""

    def __init__(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


class DriverRun:
    """One real driver.py process with the fakes, in ``tmp``."""

    def __init__(self, tmp: Path, repo: Path, files: list[str], *, script: list[dict], anthropic: dict | None = None,
                 net_url: str, secret: str = KEY, **request):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        claude = self.bin / "claude"
        claude.write_text(FAKE_CLAUDE.replace("{python}", sys.executable))
        claude.chmod(0o755)
        (tmp / "script.json").write_text(json.dumps(script))
        (tmp / "anthropic.json").write_text(json.dumps(anthropic or {}))
        secret_dir = tmp / "secret"
        secret_dir.mkdir(mode=0o700, exist_ok=True)
        self.keyfile = secret_dir / "anthropic-key"
        self.secret = secret
        self.keyfile.write_text(secret + "\n")
        self.keyfile.chmod(0o600)
        self.out = tmp / "out.json"
        self.request = {
            "repo": str(repo), "files": files, "mode": "stock", "model": "claude-opus-4-1-20250805",
            "filter_model": None, "filter": "claude", "cli_attempts": 3, "cli_auth": "api_key_helper",
            "cli_share": 0.6, "budget_sec": 200, "scan_instructions": None, "filter_instructions": None,
            "home": str(tmp / "home"), "ccsr_dir": str(CCSR_DIR), "claude": str(claude),
            "network_check_url": net_url,
        }
        self.request.update(request)
        (tmp / "request.json").write_text(json.dumps(self.request))

    def run(self, extra_env: dict | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
        paths = [str(FAKE_MODULES)]
        if importlib.util.find_spec("requests") is None:
            paths.append(str(FAKE_REQUESTS))
        env = {
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": os.pathsep.join(paths),
            "PYTHONDONTWRITEBYTECODE": "1",
            "FAKE_ANTHROPIC_CONFIG": str(self.tmp / "anthropic.json"),
            "FAKE_ANTHROPIC_LOG": str(self.tmp / "anthropic.log"),
            # The fake SDK touches this file when it is imported.
            "FAKE_ANTHROPIC_IMPORTED": str(self.tmp / "anthropic.imported"),
            # The driver must remove these before anything runs.
            "ANTHROPIC_BASE_URL": "http://should-be-removed.invalid",
            "CLAUDE_CODE_USE_BEDROCK": "1",
            # A host-managed container's switch that lets the host choose the model.
            "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST": "1",
        }
        env.update(extra_env or {})
        return subprocess.run([sys.executable, "-B", str(DRIVER), "--request", str(self.tmp / "request.json"),
                               "--keyfile", str(self.keyfile), "--out", str(self.out)],
                              capture_output=True, text=True, env=env, timeout=timeout)

    def document(self) -> dict:
        return json.loads(self.out.read_text())

    def claude_calls(self) -> list[dict]:
        log = self.tmp / "claude.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def sdk_imported(self) -> bool:
        return (self.tmp / "anthropic.imported").exists()

    def api_calls(self) -> list[dict]:
        log = self.tmp / "anthropic.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
