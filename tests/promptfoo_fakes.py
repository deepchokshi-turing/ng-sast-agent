"""Fakes shared by the promptfoo tests: a scripted stand-in for the promptfoo
CLI, helpers to build its JSON comments with or without the scoped header, and
a runner for scan.py against them. Nothing here calls the Promptfoo service.

The stand-in is a Python script run as ``<python> fake_promptfoo.py code-scans
run ...`` (scan.py runs ``<node> <promptfoo entry> ...``, and the tests set
node to the test's Python and the entry to this script), so it works on any OS.
It finds ``script.json`` next to itself: a JSON list, one entry per run:
``{"exit": n, "response": {...}}`` (printed as JSON on stdout) or ``{"exit": n,
"stdout": "raw"}``, with optional ``"stderr"`` and ``"sleep"``. Runs past the end
reuse the last entry. Every run appends one JSON line to ``promptfoo.log``: its
argv, cwd, environment, the files in the scanned directory and whether the
working directory holds a .env file.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from tests.conftest import ROOT

SCAN = ROOT / "sast" / "promptfoo" / "scan.py"
#: A made-up key (never a real one).
KEY = "pf-test-KEY-0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGH"

FAKE_PROMPTFOO = r'''
import json, os, sys, time
here = os.path.dirname(os.path.abspath(__file__))
state = os.path.join(here, "promptfoo.count")
count = int(open(state).read()) if os.path.exists(state) else 0
open(state, "w").write(str(count + 1))
script = json.load(open(os.path.join(here, "script.json")))
step = script[min(count, len(script) - 1)]
repo = sys.argv[sys.argv.index("run") + 1]
files = sorted(os.path.relpath(os.path.join(d, f), repo).replace(os.sep, "/")
               for d, dirs, fs in os.walk(repo) for f in fs if ".git" not in os.path.relpath(d, repo).split(os.sep))
guidance = None
if "--guidance-file" in sys.argv:
    guidance = open(sys.argv[sys.argv.index("--guidance-file") + 1]).read()
log = {"argv": sys.argv, "cwd": os.getcwd(), "env": dict(os.environ), "files": files,
       "cwd_has_env_file": os.path.exists(os.path.join(os.getcwd(), ".env")), "guidance": guidance,
       "git_dir": os.path.isdir(os.path.join(repo, ".git"))}
with open(os.path.join(here, "promptfoo.log"), "a") as f:
    f.write(json.dumps(log) + "\n")
time.sleep(step.get("sleep", 0))
if "response" in step:
    sys.stdout.write(json.dumps(step["response"], indent=2) + "\n")
else:
    sys.stdout.write(step.get("stdout", ""))
sys.stderr.write(step.get("stderr", ""))
sys.exit(step.get("exit", 0))
'''


def header(rule: str = "LLM03.EA.FUNCTIONALITY", cwe: str = "CWE-95", control: str = "none", risk: str = "high",
           recs: str = "REC-NARROW-TYPED-TOOLS,REC-POLICY-GATE", path: list[str] | None = None) -> str:
    """The scoped header (guidance.HEADER_FORMAT) as the guidance asks for it."""
    lines = [f"RULE={rule}; CWE={cwe}; CONTROL={control}; RISK={risk}; RECS={recs}"]
    if path:
        lines += ["PATH:", *path]
    return "\n".join(lines)


def comment(file: str | None, line: int | None, text: str = "The tool evaluates model output.", *,
            start: int | None = None, severity: str = "high", head: str | None = None, fix: str = "Use a parser.") -> dict:
    """One comment of promptfoo's ``-f json`` response."""
    finding = f"{head}\n\n{text}" if head else text
    out = {"file": file, "line": line, "finding": finding, "fix": fix, "severity": severity,
           "aiAgentPrompt": "Fix the issue."}
    if start is not None:
        out["startLine"] = start
    return out


def response(comments: list[dict], review: str = "Reviewed the change.") -> dict:
    return {"success": True, "comments": comments, "review": review}


class ScanRun:
    """One real scan.py process with the stand-in, in ``tmp``."""

    def __init__(self, tmp: Path, repo: Path, files: list[str], *, script: list[dict], secret: str = KEY,
                 git: str | None = None, **request):
        self.tmp = tmp
        tool = tmp / "tool"
        tool.mkdir(parents=True, exist_ok=True)
        self.tool = tool
        (tool / "fake_promptfoo.py").write_text(FAKE_PROMPTFOO)
        (tool / "script.json").write_text(json.dumps(script))
        secret_dir = tmp / "secret"
        secret_dir.mkdir(exist_ok=True)
        self.keyfile = secret_dir / "promptfoo-key"
        self.keyfile.write_text(secret + "\n")
        self.out = tmp / "out.json"
        self.request = {
            "repo": str(repo), "files": files, "scope_dir": str(tmp / "scope"), "home": str(tmp / "home"),
            "cwd": str(tmp / "cwd"), "node": sys.executable, "git": git or shutil.which("git"),
            "promptfoo": str(tool / "fake_promptfoo.py"), "guidance_file": None, "min_severity": None,
            "diffs_only": False, "budget_sec": 200,
        }
        self.request.update(request)
        (tmp / "request.json").write_text(json.dumps(self.request))

    def run(self, timeout: float = 120) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-I", "-B", str(SCAN), "--request", str(self.tmp / "request.json"),
                               "--keyfile", str(self.keyfile), "--out", str(self.out)],
                              capture_output=True, text=True, timeout=timeout)

    def document(self) -> dict:
        return json.loads(self.out.read_text())

    def calls(self) -> list[dict]:
        log = self.tool / "promptfoo.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
