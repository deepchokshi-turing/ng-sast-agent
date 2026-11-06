"""Fakes shared by the codex_security tests: a scripted ``codex`` CLI and a
helper that runs sast/codex_security/driver.py for real against it. Nothing
here calls a real API, and the key is made up."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.conftest import ROOT

DRIVER = ROOT / "sast" / "codex_security" / "driver.py"
FIXTURES = ROOT / "tests" / "fixtures" / "codex_security"
#: A made-up key in the shape of an OpenAI project key. Never a real one.
KEY = "sk-proj-TESTKEY-0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGH"

#: The scripted CLI. It finds script.json next to its own folder. script.json:
#: {"sandbox_exit": n, "login_exit": n, "runs": [step, ...]} where a step is
#: {"exit": n, "final": {...} | "final_text": "...", "turn_failed": "...",
#:  "errors": [...], "commands": [{"command": ..., "exit_code": n, "status": ..., "output": ...}],
#:  "write_last": true, "sleep": s, "stdout": "raw"}.
#: Runs past the end reuse the last step. Every call appends a JSON line to codex.log.
FAKE_CODEX = r'''#!{python}
import json, os, sys, time
here = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
script = json.load(open(os.path.join(here, "script.json")))
args = sys.argv[1:]
stdin = "" if args in (["--version"], ["login", "status"]) or args[:1] == ["sandbox"] else sys.stdin.read()
codex_home = os.environ.get("CODEX_HOME", "")
auth = os.path.join(codex_home, "auth.json")
log = {"argv": sys.argv, "cwd": os.getcwd(), "env_names": sorted(os.environ), "env": dict(os.environ),
       "stdin": stdin, "codex_home": codex_home,
       "auth_key": json.load(open(auth)).get("OPENAI_API_KEY") if os.path.isfile(auth) else None,
       "config": open(os.path.join(codex_home, "config.toml")).read() if os.path.isfile(os.path.join(codex_home, "config.toml")) else None,
       "cwd_files": sorted(os.path.relpath(os.path.join(d, f), os.getcwd()) for d, _, fs in os.walk(os.getcwd()) for f in fs)}
with open(os.path.join(here, "codex.log"), "a") as f:
    f.write(json.dumps(log) + "\n")
if args == ["--version"]:
    print("codex-cli 0.162.1")
    sys.exit(0)
if args == ["login", "--with-api-key"]:
    if script.get("login_exit"):
        sys.exit(script["login_exit"])
    with open(auth, "w") as f:
        json.dump({"auth_mode": "apikey", "OPENAI_API_KEY": stdin.strip()}, f)
    print("Successfully logged in")
    sys.exit(0)
if args == ["login", "status"]:
    print("Logged in using an API key - sk-proj-***EFGH")
    sys.exit(0)
if args[:1] == ["sandbox"]:
    code = script.get("sandbox_exit", 0)
    if code:
        sys.stderr.write("bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces.\n")
    sys.exit(code)
assert args[0] == "exec", args
state = os.path.join(here, "codex.count")
count = int(open(state).read()) if os.path.exists(state) else 0
open(state, "w").write(str(count + 1))
runs = script.get("runs") or [{}]
step = runs[min(count, len(runs) - 1)]
last = args[args.index("-o") + 1]
time.sleep(step.get("sleep", 0))
if "stdout" in step:
    sys.stdout.write(step["stdout"])
    sys.exit(step.get("exit", 0))
out = [{"type": "thread.started", "thread_id": "thread-%d" % count}, {"type": "turn.started"}]
for message in step.get("errors", []):
    out.append({"type": "error", "message": message})
for i, c in enumerate(step.get("commands", [])):
    out.append({"type": "item.completed", "item": {"id": "c%d" % i, "type": "command_execution", "command": c["command"],
               "aggregated_output": c.get("output", ""), "exit_code": c.get("exit_code", 0), "status": c.get("status", "completed")}})
if step.get("turn_failed"):
    out.append({"type": "turn.failed", "error": {"message": step["turn_failed"]}})
else:
    text = step.get("final_text")
    if text is None and "final" in step:
        text = json.dumps(step["final"])
    if text is not None:
        out.append({"type": "item.completed", "item": {"id": "m", "type": "agent_message", "text": text}})
        if step.get("write_last", True):
            open(last, "w").write(text)
    out.append({"type": "turn.completed", "usage": {"input_tokens": 1200, "cached_input_tokens": 100,
                                                    "cache_write_input_tokens": 0, "output_tokens": 300,
                                                    "reasoning_output_tokens": 50}})
for event in out:
    sys.stdout.write(json.dumps(event) + "\n")
sys.exit(step.get("exit", 0))
'''


def answer(findings: list[dict], files_reviewed: int = 3, completed: bool = True) -> dict:
    return {"findings": findings, "analysis_summary": {"files_reviewed": files_reviewed,
                                                       "review_completed": completed}}


def finding(file: str, start: int, end: int | None = None, *, cwe=("CWE-78",), category: str = "command_injection",
            priority: int | None = 1, **extra) -> dict:
    """One finding in Codex's own review shape plus category and cwe (stock mode)."""
    out = {"title": f"[P{priority}] {category}", "body": f"{category} at {file}:{start}", "confidence_score": 0.8,
           "priority": priority, "category": category, "cwe": list(cwe),
           "code_location": {"absolute_file_path": file, "line_range": {"start": start,
                                                                        "end": start if end is None else end}}}
    out.update(extra)
    return out


class DriverRun:
    """One real driver.py process with the scripted codex, in ``tmp``."""

    def __init__(self, tmp: Path, repo: Path, files: list[str], *, script: dict, secret: str = KEY, **request):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        codex = self.bin / "codex"
        codex.write_text(FAKE_CODEX.replace("{python}", sys.executable))
        codex.chmod(0o755)
        (tmp / "script.json").write_text(json.dumps(script))
        secret_dir = tmp / "secret"
        secret_dir.mkdir(mode=0o700, exist_ok=True)
        self.keyfile = secret_dir / "openai-key"
        self.secret = secret
        self.keyfile.write_text(secret + "\n")
        self.keyfile.chmod(0o600)
        (tmp / "out").mkdir(exist_ok=True)
        self.out = tmp / "out" / "result.json"
        self.request = {
            "repo": str(repo), "files": files, "mode": "stock", "model": "gpt-5.6-sol", "reasoning_effort": None,
            "sandbox": "read-only", "attempts": 2, "budget_sec": 200, "prompt": "review the code",
            "schema": {"type": "object"}, "config_toml": 'model = "gpt-5.6-sol"\n',
            "home": str(tmp / "home"), "codex_home": str(tmp / "home" / "codex-home"),
            "scope_dir": str(tmp / "scope"), "codex": str(codex), "network_check_url": None,
            "min_attempt_sec": 1,
        }
        self.request.update(request)
        (tmp / "out" / "request.json").write_text(json.dumps(self.request))

    def run(self, extra_env: dict | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
        env = {
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            # The driver must not pass these on.
            "OPENAI_API_KEY": "sk-host-key-must-not-pass",
            "CODEX_API_KEY": "sk-host-key-must-not-pass-either",
            "CODEX_HOME": "/host/codex/home",
            "OPENAI_BASE_URL": "http://should-be-removed.invalid",
        }
        env.update(extra_env or {})
        return subprocess.run([sys.executable, "-B", str(DRIVER), "--request", str(self.tmp / "out" / "request.json"),
                               "--keyfile", str(self.keyfile), "--out", str(self.out)],
                              capture_output=True, text=True, env=env, timeout=timeout)

    def document(self) -> dict:
        return json.loads(self.out.read_text())

    def calls(self) -> list[dict]:
        log = self.tmp / "codex.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def exec_calls(self) -> list[dict]:
        return [c for c in self.calls() if c["argv"][1:2] == ["exec"]]


def files_under(path: Path) -> list[Path]:
    return [p for p in path.rglob("*") if p.is_file()] if path.exists() else []


def environ_without_keys() -> dict:
    return {k: v for k, v in os.environ.items() if k not in ("OPENAI_API_KEY", "CODEX_API_KEY")}
