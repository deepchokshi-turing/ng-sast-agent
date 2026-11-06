"""Fakes shared by the cloudflare_audit tests: a scripted ``claude`` CLI that
plays the skill (it writes the audit's files into the output directory named in
the prompt), a fake ``node`` for the validators, record and annotation
builders, and a helper that runs sast/cloudflare_audit/driver.py for real
against them. Nothing here calls a real API, and the credentials are made up."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.claude_review_fakes import KEY, OAUTH_TOKEN, NetCheckServer  # noqa: F401  (re-exported)
from tests.conftest import ROOT

DRIVER = ROOT / "sast" / "cloudflare_audit" / "driver.py"
SKILL_FILES = {"SKILL.md": "---\nname: security-audit\n---\nfake skill\n",
               "validate-findings.cjs": "// fake\n", "validate-coverage-ledger.cjs": "// fake\n"}

#: The scripted CLI. script.json next to its folder is a list of runs (past the end the last is reused):
#: {"exit": n, "init": {...overrides}, "no_init": bool, "sleep": s, "tool_uses": [{"name", "input"}],
#:  "files": {"findings.json": <json value or "raw text">, ...} written into the prompt's output directory,
#:  "wrapper": {...} (the final result message; default a success), "stdout": "raw" (instead of a wrapper)}.
#: Every run appends one JSON line to claude.log.
FAKE_CLAUDE = r'''#!{python}
import json, os, re, sys, time
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
settings_file = sys.argv[sys.argv.index("--settings") + 1]
settings = json.load(open(settings_file))
out_dir = re.search(r"Output directory: (\S+)\. ", prompt).group(1)
log = {"argv": sys.argv, "cwd": os.getcwd(), "home": os.environ.get("HOME"), "env_names": sorted(os.environ),
       "env_oauth_token": os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"), "env_key": os.environ.get("ANTHROPIC_API_KEY"),
       "settings": settings, "settings_mode": oct(os.stat(settings_file).st_mode & 0o777), "prompt": prompt,
       "skills": sorted(os.listdir(os.path.join(os.environ["HOME"], ".claude", "skills", "security-audit"))),
       "cwd_files": sorted(os.path.relpath(os.path.join(d, f), os.getcwd()) for d, _, fs in os.walk(os.getcwd())
                           for f in fs)}
with open(os.path.join(here, "claude.log"), "a") as f:
    f.write(json.dumps(log) + "\n")
if not step.get("no_init"):
    model = sys.argv[sys.argv.index("--model") + 1]
    oauth = "CLAUDE_CODE_OAUTH_TOKEN" in os.environ
    denied = settings.get("permissions", {}).get("deny", [])
    tools = [t for t in ["Task", "Bash", "Edit", "Read", "Skill", "ToolSearch", "Write", "WebSearch", "Workflow"]
             if t not in denied]
    init = {"type": "system", "subtype": "init", "cwd": os.getcwd(), "model": model,
            "apiKeySource": "none" if oauth else "apiKeyHelper", "tools": tools,
            "permissionMode": sys.argv[sys.argv.index("--permission-mode") + 1], "mcp_servers": [],
            "claude_code_version": "2.1.296", "skills": ["security-audit", "debug"]}
    init.update(step.get("init", {}))
    sys.stdout.write(json.dumps(init) + "\n")
    sys.stdout.flush()
time.sleep(step.get("sleep", 0))
for use in step.get("tool_uses", []):
    block = {"type": "tool_use", "id": "toolu_1", "name": use["name"], "input": use.get("input", {})}
    sys.stdout.write(json.dumps({"type": "assistant", "message": {"content": [block]}}) + "\n")
files = step.get("files") or {}
if files:
    os.makedirs(out_dir, exist_ok=True)
for name, value in files.items():
    with open(os.path.join(out_dir, name), "w") as f:
        f.write(value if isinstance(value, str) else json.dumps(value))
if "stdout" in step:
    sys.stdout.write(step["stdout"])
else:
    wrapper = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 40, "total_cost_usd": 3.5,
               "duration_ms": 900000, "session_id": "s-1", "result": "Audit complete.",
               "usage": {"input_tokens": 1000, "output_tokens": 500},
               "modelUsage": {sys.argv[sys.argv.index("--model") + 1]: {"inputTokens": 1000, "outputTokens": 500,
                                                                         "cacheReadInputTokens": 20000}},
               "permission_denials": []}
    wrapper.update(step.get("wrapper", {}))
    sys.stdout.write(json.dumps(wrapper) + "\n")
sys.exit(step.get("exit", 0))
'''

#: A fake node: exits 0 for a file holding a JSON list or object, 1 otherwise, and logs its argv.
FAKE_NODE = r'''#!{python}
import json, os, sys
here = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
with open(os.path.join(here, "node.log"), "a") as f:
    f.write(json.dumps(sys.argv) + "\n")
try:
    json.load(open(sys.argv[2]))
except Exception as exc:
    print("invalid: %s" % exc)
    sys.exit(1)
print("ok")
'''


def step_record(kind, file, line):
    return {"kind": kind, "file": file, "line": line, "scope": "fn", "description": f"{kind} step"}


def confirmed(fingerprint="calc/eval", file="src/calc_agent/agent.py", trace=None, **extra):
    """A confirmed record in the skill's report-schema shape."""
    record = {
        "verdict": "confirmed", "fingerprint": fingerprint, "title": "Model output reaches eval",
        "description": "The calculator tool evals model-written text.", "root_cause": "eval on model output",
        "intended_behavior": "only arithmetic", "trace": trace if trace is not None else [
            step_record("entrypoint", file, 12), step_record("propagation", file, 10), step_record("sink", file, 8)],
        "evidence": [{"file": file, "line": 8, "description": "eval"}], "conditions": [],
        "execution": {"attacker_perspective": "a prompt asks for __import__('os')", "payloads": ["x"],
                      "instructions": ["call the tool"], "observed_result": "code runs"},
        "remediation": {"strategy": "Parse arithmetic with ast and allow only numeric nodes.",
                        "code_changes": [{"file_name": file, "fixed_code": "safe_eval(expr)"}]},
        "severity": {"likelihood": {"score": "high", "reason": "r"}, "impact": {"score": "high", "reason": "r"},
                     "overall_severity": "high"},
        "confidence": {"score": "high", "reason": "r"},
    }
    record.update(extra)
    return record


def needs_validation(fingerprint="calc/maint", file="src/calc_agent/maintenance.py", line=5):
    return {"verdict": "needs_validation", "fingerprint": fingerprint, "title": "Maintenance action without gate",
            "description": "d", "claimed_root_cause": "no approval", "trace": [step_record("sink", file, line)],
            "evidence": [{"file": file, "line": line, "description": "e"}], "blockers": ["needs a deployment fact"],
            "validation_plan": {"local": "run the tool with a dummy"}}


def rejected(fingerprint="calc/llm"):
    return {"verdict": "rejected", "fingerprint": fingerprint, "title": "t", "description": "d",
            "claimed_root_cause": "c", "trace": [step_record("sink", "src/calc_agent/llm.py", 2)],
            "evidence": [{"file": "src/calc_agent/llm.py", "line": 2, "description": "e"}], "reason": "disproved"}


def annotation(fingerprint="calc/eval", **fields):
    entry = {"fingerprint": fingerprint, "cwe": ["CWE-95"]}
    entry.update(fields)
    return entry


def audit_files(records, annotations=None, run_status="complete", **metadata):
    """The files the skill leaves in its output directory."""
    files = {"run-metadata.json": dict({"run_id": "run-1", "profile": "quick", "run_status": run_status}, **metadata),
             "findings.json": records,
             "coverage-ledger.json": [{"coverage_id": "a", "status": "covered"},
                                      {"coverage_id": "b", "status": "candidate"}],
             "REPORT.md": "# Report\n"}
    if annotations is not None:
        files["sast-annotations.json"] = {"findings": annotations}
    return files


class DriverRun:
    """One real driver.py process with the fakes, in ``tmp``."""

    def __init__(self, tmp: Path, repo: Path, files: list[str], *, script: list[dict], net_url: str,
                 secret: str = OAUTH_TOKEN, auth: str = "oauth", **request):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        claude = self.bin / "claude"
        claude.write_text(FAKE_CLAUDE.replace("{python}", sys.executable))
        claude.chmod(0o755)
        node_dir = tmp / "nodebin"
        node_dir.mkdir(exist_ok=True)
        node = node_dir / "node"
        node.write_text(FAKE_NODE.replace("{python}", sys.executable))
        node.chmod(0o755)
        skill = tmp / "skill-src"
        skill.mkdir(exist_ok=True)
        import hashlib
        hashes = {}
        for name, text in SKILL_FILES.items():
            (skill / name).write_text(text)
            hashes[name] = hashlib.sha256(text.encode()).hexdigest()
        (tmp / "script.json").write_text(json.dumps(script))
        secret_dir = tmp / "secret"
        secret_dir.mkdir(mode=0o700, exist_ok=True)
        self.keyfile = secret_dir / "claude-oauth-token"
        self.secret = secret
        self.keyfile.write_text(secret + "\n")
        self.keyfile.chmod(0o600)
        (tmp / "out").mkdir(exist_ok=True)
        self.out = tmp / "out" / "result.json"
        home = tmp / "home"
        self.out_root = tmp / "audit-out"
        self.out_dir = self.out_root / "run-1"
        skill_dir = home / ".claude" / "skills" / "security-audit"
        prompt = (f"Run a full security audit of the codebase at {tmp / 'scope'}.\n"
                  f"- Output directory: {self.out_dir}. It does not exist yet.\n"
                  f"- Skill directory: {skill_dir}.\n")
        self.request = {
            "repo": str(repo), "files": files, "mode": "scoped", "model": "claude-opus-5-5", "auth": auth,
            "profile": "quick", "attempts": 1, "budget_sec": 400, "min_attempt_sec": 5, "prompt": prompt,
            "scope_dir": str(tmp / "scope"), "out_root": str(self.out_root), "out_dir": str(self.out_dir),
            "home": str(home), "skill_src": str(skill), "skill_files": hashes, "claude": str(claude),
            "node": str(node), "network_check_url": net_url,
        }
        self.request.update(request)
        (tmp / "out" / "request.json").write_text(json.dumps(self.request))

    def run(self, timeout: float = 120) -> subprocess.CompletedProcess:
        env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
               # The driver must remove these before anything runs.
               "ANTHROPIC_BASE_URL": "http://should-be-removed.invalid", "CLAUDE_CODE_USE_BEDROCK": "1"}
        return subprocess.run([sys.executable, "-B", str(DRIVER), "--request", str(self.tmp / "out" / "request.json"),
                               "--keyfile", str(self.keyfile), "--out", str(self.out)],
                              capture_output=True, text=True, env=env, timeout=timeout)

    def document(self) -> dict:
        return json.loads(self.out.read_text())

    def claude_calls(self) -> list[dict]:
        log = self.tmp / "claude.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def node_calls(self) -> list[list[str]]:
        log = self.tmp / "node.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
