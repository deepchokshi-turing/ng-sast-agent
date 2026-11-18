"""Fakes shared by the datadog_saist tests: a scripted ``datadog-saist`` binary,
SARIF in the binary's own shape, and a helper that runs
sast/datadog_saist/driver.py for real against the fake. Nothing here calls a
real API, and the key is made up."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.conftest import ROOT

DRIVER = ROOT / "sast" / "datadog_saist" / "driver.py"
#: A made-up key in the shape of an OpenAI project key. Never a real one.
KEY = "sk-proj-DDTESTKEY-0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGH"

REMEDIATION = "- Grant agents only the minimum capabilities required\n- Prefer read-only tools"
RULES = {
    "datadog/python-excessiveagency": ("Potential excessive agency", "250",
                                       "In Python, Excessive Agency ...\n\n## How to remediate:\n" + REMEDIATION),
    "datadog/python-sensitiveinfodisclosure": ("Potential sensitive information disclosure", "200",
                                               "Sensitive data into messages=.\n\n## How to remediate:\n- Redact"),
    "datadog/python-xss": ("Potential cross-site scripting", "79", "XSS."),
    "datadog/python-improperoutputhandling": ("Potential improper output handling", "74", "LLM10:2026 output."),
}


def rule_descriptor(rule_id: str) -> dict:
    short, cwe, full = RULES.get(rule_id, ("Some new rule", "999", "New."))
    return {"id": rule_id, "shortDescription": {"text": short}, "fullDescription": {"text": full},
            "properties": {"tags": ["DATADOG_RULE_TYPE:datadog-ai-static-analyzer", f"CWE:{cwe}",
                                    "SEVERITY:WARNING", "CATEGORY:SECURITY"]}}


def result(rule_id: str, path: str, start: int, end: int | None = None, reason: str = "the model's reason") -> dict:
    """One result exactly as internal/sarif/sarif.go writes it."""
    cwe = RULES.get(rule_id, ("", "999", ""))[1]
    return {"ruleId": rule_id, "ruleIndex": 0, "level": "warning",
            "message": {"text": RULES.get(rule_id, ("Some new rule",))[0]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path},
                                                "region": {"startLine": start, "startColumn": 1,
                                                           "endLine": start if end is None else end,
                                                           "endColumn": 5}}}],
            "partialFingerprints": {"DATADOG_FINGERPRINT": "f" * 64},
            "properties": {"tags": [f"CWE:{cwe}", "DATADOG_CONFIDENCE:HIGH", f"DATADOG_CONFIDENCE_REASON:{reason}"]}}


def sarif(results: list[dict], artifacts: dict[str, tuple[list[str], list[str]]] | None = None,
          tokens: tuple[int, int] = (12000, 900), rules: list[str] | None = None) -> dict:
    """A whole SARIF in the binary's shape. ``artifacts``: {uri: (rules succeeded, rules failed)}."""
    if artifacts is None:
        artifacts = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: ([r["ruleId"]], [])
                     for r in results} or {"src/x.py": (["datadog/python-xss"], [])}
    arts = []
    for uri, (ok, bad) in artifacts.items():
        tags = ([f"RULE_SUCCESS:{','.join(ok)}"] if ok else []) + ([f"RULE_FAILURE:{','.join(bad)}"] if bad else [])
        arts.append({"location": {"uri": uri}, "length": 0, "properties": {"tags": tags} if tags else {}})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
            "runs": [{"tool": {"driver": {"name": "datadog-ai-static-analyzer", "version": "0.0.32",
                                          "rules": [rule_descriptor(r) for r in (rules or list(RULES))]}},
                      "artifacts": arts, "results": results,
                      "properties": {"tags": [f"DATADOG_SAIST_OUTPUT_TOKENS:{tokens[1]}",
                                              f"DATADOG_SAIST_INPUT_TOKENS:{tokens[0]}"]}}]}


#: The scripted binary. script.json next to its folder: {"exit": n, "sarif": {...} | null,
#: "stderr": "...", "sleep": s, "echo_key": bool}. Every call appends a JSON line to saist.log.
FAKE_SAIST = r'''#!{python}
import json, os, sys, time
here = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
script = json.load(open(os.path.join(here, "script.json")))
args = sys.argv[1:]
log = {"argv": sys.argv, "cwd": os.getcwd(), "env_names": sorted(os.environ), "env": dict(os.environ),
       "cwd_files": sorted(os.path.relpath(os.path.join(d, f), os.getcwd()) for d, _, fs in os.walk(os.getcwd()) for f in fs)}
with open(os.path.join(here, "saist.log"), "a") as f:
    f.write(json.dumps(log) + "\n")
time.sleep(script.get("sleep", 0))
err = script.get("stderr", "")
if script.get("echo_key"):
    err += "\nkey was " + os.environ.get("OPENAI_API_KEY", "")
sys.stderr.write(err)
if script.get("sarif") is not None:
    out = args[args.index("--output") + 1]
    open(out, "w").write(script["sarif"] if isinstance(script["sarif"], str) else json.dumps(script["sarif"]))
sys.exit(script.get("exit", 0))
'''


class DriverRun:
    """One real driver.py process with the scripted binary, in ``tmp``."""

    def __init__(self, tmp: Path, repo: Path, files: list[str], *, script: dict, secret: str = KEY, **request):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        binary = self.bin / "datadog-saist"
        binary.write_text(FAKE_SAIST.replace("{python}", sys.executable))
        binary.chmod(0o755)
        (tmp / "script.json").write_text(json.dumps(script))
        secret_dir = tmp / "secret"
        secret_dir.mkdir(mode=0o700, exist_ok=True)
        self.keyfile = secret_dir / "provider-key"
        self.keyfile.write_text(secret + "\n")
        self.keyfile.chmod(0o600)
        (tmp / "out").mkdir(exist_ok=True)
        self.out = tmp / "out" / "result.json"
        self.request = {
            "repo": str(repo), "files": files, "binary": str(binary), "detection_model": "openai-gpt5.2",
            "validation_model": "openai-gpt5.2", "key_env": "OPENAI_API_KEY", "rules": "api",
            "rules_url": None, "provider_url": None, "request_timeout_sec": 120, "file_concurrency": 20,
            "skip_indexing": False, "budget_sec": 200, "scope_dir": str(tmp / "scope"),
            "private_dir": str(tmp / "private"),
        }
        self.request.update(request)
        (tmp / "out" / "request.json").write_text(json.dumps(self.request))

    def run(self, timeout: float = 120) -> subprocess.CompletedProcess:
        env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
               # The driver must not pass these on.
               "OPENAI_API_KEY": "sk-host-key-must-not-pass", "ANTHROPIC_API_KEY": "sk-ant-host",
               "DD_API_KEY": "dd-host", "DD_SITE": "evil.example", "OPENAI_BASE_URL": "http://removed.invalid"}
        return subprocess.run([sys.executable, "-B", str(DRIVER), "--request", str(self.tmp / "out" / "request.json"),
                               "--keyfile", str(self.keyfile), "--out", str(self.out)],
                              capture_output=True, text=True, env=env, timeout=timeout)

    def document(self) -> dict:
        return json.loads(self.out.read_text())

    def calls(self) -> list[dict]:
        log = self.tmp / "saist.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
