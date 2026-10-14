"""PromptfooCodeScanAgent against a fake sandbox: options, the key, the scan
command, guidance, failures, the SARIF and its grade.

No service is called. The fake sandbox answers the scan.py command with a
result document in scan.py's format (its real behaviour is tested in
test_promptfoo_scan.py) and lists files from the sample task ``smoke_eval``.
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

import sast
from sast.claude_review.agent import KILL_AFTER_SEC
from sast.errors import ScannerError
from sast.promptfoo import guidance, pins
from sast.promptfoo.agent import PromptfooCodeScanAgent
from sast.promptfoo.normalise import TOOL_RULE_ID
from tests.conftest import ROOT, SAMPLE_TASKS
from tests.promptfoo_fakes import KEY, comment, header, response

WORK = "/opt/sast"
KEY_DIR = f"{WORK}/secret"
KEY_FILE = f"{KEY_DIR}/promptfoo-key"
OUT = f"{WORK}/out/promptfoo_scan.json"
GUIDANCE = f"{WORK}/out/promptfoo_guidance.txt"
SCOPE = f"{WORK}/scope-promptfoo"
TASK = "smoke_eval"
REPO = SAMPLE_TASKS / TASK / "environment" / "repo"
IN_SCOPE = ["src/calc_agent/__init__.py", "src/calc_agent/agent.py", "src/calc_agent/llm.py",
            "src/calc_agent/maintenance.py"]
INSTRUCTION = (SAMPLE_TASKS / TASK / "instruction.md").read_text()
PART = "/opt/sast/promptfoo-local"
INSTALL = {"node": f"{PART}/node/bin/node", "git": f"{PART}/git/bin/git",
           "promptfoo": f"{PART}/app/node_modules/promptfoo/dist/src/entrypoint.js",
           "python": "/usr/local/bin/python3", "source": "setup", "promptfoo_version_output": "0.124.1"}
#: The answer the smoke_eval truth expects, in the scoped header.
GOOD_HEADER = header(rule="LLM03.EA.FUNCTIONALITY", cwe="CWE-95,CWE-94", control="none", risk="high",
                     recs="REC-NARROW-TYPED-TOOLS,REC-POLICY-GATE",
                     path=["src/calc_agent/agent.py:12 model_decision", "src/calc_agent/agent.py:8 root_cause",
                           "src/calc_agent/agent.py:8 sink"])


def line_counts(files=IN_SCOPE):
    counts = {f: len((REPO / f).read_text().split("\n")) - (REPO / f).read_text().endswith("\n") for f in files}
    counts["security_manifest.json"] = 3
    return counts


def scan_document(comments=None, *, status="ok", error=None, review="Reviewed.", echo_key=False, secret=KEY):
    comments = [] if comments is None else comments
    doc = {
        "scan_format": 1, "status": status, "seconds": 95.0,
        "scope_copy": {"dir": SCOPE, "files": len(IN_SCOPE) + 1, "manifest": True, "manifest_outside_roots": True,
                       "skipped": [], "binary": [], "over_promptfoo_size_limit": []},
        "line_counts": line_counts(),
        "git": {"base": "main", "compare": "scan", "files_changed": len(IN_SCOPE) + 1, "head": "ab" * 20},
        "argv": [INSTALL["node"], INSTALL["promptfoo"], "code-scans", "run", SCOPE, "--base", "main", "--compare",
                 "scan", "-f", "json"],
        "env_names": ["HOME", "PATH", "PROMPTFOO_API_KEY", "PROMPTFOO_CONFIG_DIR", "PROMPTFOO_DISABLE_TELEMETRY",
                      "PROMPTFOO_DISABLE_UPDATE"],
        "promptfoo": {"exit_code": 0, "seconds": 90.0, "timed_out": False, "stderr_tail": "", "stdout_bytes": 900},
    }
    if status == "ok":
        doc["response"] = response(comments, review)
    if error:
        doc["error"] = error
    if echo_key:
        doc["note"] = f"the key was {secret}"
    return doc


class FakeSandbox:
    """Just enough of BaseEnvironment: a dict file system and scripted exec."""

    def __init__(self, document=None, scan_exit=0, scan_stdout=None, write_document=True, protect_exit=0,
                 install_result=None, secret=KEY):
        self.environment_dir = SAMPLE_TASKS / TASK / "environment"
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None, float | None]] = []
        self.events: list[tuple[str, str]] = []
        self.key_reads: list[tuple[str, bool]] = []
        self.document = scan_document() if document is None else document
        self.scan_exit = scan_exit
        self.scan_stdout = scan_stdout
        self.write_document = write_document
        self.protect_exit = protect_exit
        self.install_result = INSTALL if install_result is None else install_result
        self.request = None
        self.secret = secret

    def _remove_tree(self, path):
        for name in [n for n in self.files if n == path or n.startswith(path + "/")]:
            del self.files[name]

    def _find(self, command):
        args = shlex.split(command)
        roots = args[1:args.index("-name")]
        found = []
        for root in roots:
            base = REPO / root
            if base.is_file():
                found.append(root)
            elif base.is_dir():
                found += [p.relative_to(REPO).as_posix() for p in base.rglob("*") if p.is_file()]
        return ExecResult(stdout="\n".join(f"./{f}" if i % 2 else f for i, f in enumerate(found)) + "\n",
                          return_code=0)

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        self.commands.append((command, env, timeout_sec))
        self.events.append(("exec", command))
        if command.startswith("umask 077 && cat "):
            if self.protect_exit:
                return ExecResult(stdout="", stderr="Terminated", return_code=self.protect_exit)
            source, target = re.search(r"cat (\S+) > (\S+)", command).groups()
            self.files[target] = self.files.pop(source)
            return ExecResult(return_code=0)
        if re.fullmatch(r"rm -rf (\S+) && mkdir -p \S+ && chmod 700 \S+", command):
            self._remove_tree(command.split()[2])
            return ExecResult(return_code=0)
        if re.fullmatch(r"rm -rf (\S+)", command):
            self._remove_tree(command.split()[2])
            return ExecResult(return_code=0)
        if command.startswith("find "):
            return self._find(command)
        if "install.py" in command:
            return ExecResult(stdout="[install] ok\nINSTALL_RESULT " + json.dumps(self.install_result), return_code=0)
        if "scan.py" in command:
            args = shlex.split(command.split(" && exec ", 1)[1])
            keyfile = args[args.index("--keyfile") + 1]
            self.key_reads.append((keyfile, self.files.get(keyfile, b"").strip() == self.secret.encode()))
            self.request = json.loads(self.files[args[args.index("--request") + 1]])
            if self.write_document:
                self.files[args[args.index("--out") + 1]] = json.dumps(self.document).encode()
            stdout = self.scan_stdout if self.scan_stdout is not None else "SCAN_RESULT " + json.dumps(
                {"status": self.document.get("status")})
            return ExecResult(stdout=stdout, stderr="", return_code=self.scan_exit)
        if command.startswith("mkdir -p /opt/sast"):
            return ExecResult(stdout="writable\n", return_code=0)
        if command.startswith("if [ -e"):
            names = re.findall(r"if \[ -e (\S+) \]", command)
            return ExecResult(stdout="".join(f"OK {n}\n" for n in names if (REPO / n).exists()), return_code=0)
        if command.startswith("test -f") and " && cp " in command:
            source, target = re.match(r"test -f (\S+) && cp \S+ (\S+)", command).groups()
            if source not in self.files:
                return ExecResult(return_code=1)
            self.files[target] = self.files[source]
            return ExecResult(return_code=0)
        return ExecResult(stdout="", return_code=0)

    async def upload_file(self, source_path, target_path):
        self.events.append(("upload", str(target_path)))
        self.files[str(target_path)] = Path(source_path).read_bytes()

    async def download_file(self, source_path, target_path):
        if source_path not in self.files:
            raise FileNotFoundError(source_path)
        Path(target_path).write_bytes(self.files[source_path])

    def commands_with(self, needle):
        return [(c, env, t) for c, env, t in self.commands if needle in c]


CLEAN_ENV = ("PROMPTFOO_SCAN_MODE", "PROMPTFOO_SCAN_TIMEOUT_SEC", "PROMPTFOO_SCAN_MIN_SEVERITY",
             "PROMPTFOO_SCAN_DIFFS_ONLY")


@pytest.fixture
def api_key(monkeypatch):
    monkeypatch.setenv("PROMPTFOO_API_KEY", KEY)
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)


def run_agent(tmp_path, sandbox, instruction=INSTRUCTION, **options):
    options.setdefault("mode", "stock")  # these tests were written for stock; scoped is the default now
    agent = PromptfooCodeScanAgent(logs_dir=tmp_path, model_name="openai/gpt-5", **options)
    context = AgentContext()

    async def go():
        await agent.setup(sandbox)
        await agent.run(instruction, sandbox, context)

    return agent, context, go


def assert_key_nowhere(tmp_path, sandbox, context):
    """Not in any exec command or env, log, metadata, artifact or output, and the key file is gone."""
    for command, env, _ in sandbox.commands:
        assert KEY not in command
        assert "PROMPTFOO_API_KEY" not in (env or {})
        assert all(KEY not in value for value in (env or {}).values())
    assert KEY not in json.dumps(context.metadata, default=str)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert KEY not in path.read_text(errors="replace"), path
    for name, data in sandbox.files.items():
        assert KEY.encode() not in data, name
    assert not any(name.startswith(KEY_DIR) for name in sandbox.files)
    assert context.metadata["promptfoo_scan"]["key_file_removed"] is True


def sarif_of(sandbox):
    return json.loads(sandbox.files["/app/output/findings.sarif"])


# ---------------------------------------------------------------- scoped mode


def test_scoped_happy_path(tmp_path, api_key, grade_sarif):
    comments = [
        comment("src/calc_agent/agent.py", 8, "The calculator passes model output to eval().", head=GOOD_HEADER),
        # No header: listed, not emitted.
        comment("src/calc_agent/llm.py", 2, "Prompt is logged.", severity="medium"),
        # Excluded path: dropped as out of scope.
        comment("src/calc_agent/thirdparty/legacy.py", 1, head=GOOD_HEADER),
    ]
    sandbox = FakeSandbox(document=scan_document(comments))
    agent, context, go = run_agent(tmp_path, sandbox, mode="scoped")
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok", meta.get("error")
    assert meta["agent_version"] == f"{sast.__version__}+promptfoo-code-scan-0.124.1+node-24.21.0"
    assert meta["model"] is None and meta["harbor_model_name_ignored"] == "openai/gpt-5"
    assert meta["mode"] == "scoped" and meta["auth_source"] == "PROMPTFOO_API_KEY"
    assert agent.to_agent_info().model_info is None
    record = meta["promptfoo_scan"]
    assert record["guidance_source"] == "task_instruction" and record["contract"]["rule_ids"]
    assert record["review"] == "Reviewed." and record["comments"] == 3 and record["cost_usd"] is None
    assert meta["headers"] == {"valid": 1, "missing": 1, "malformed": 0}

    # The guidance went to the sandbox as a file outside the scope copy, and the request points at it.
    assert sandbox.request["guidance_file"] == GUIDANCE
    text = sandbox.files[GUIDANCE].decode()
    assert text == guidance.guidance_text(guidance.contract_for(INSTRUCTION)[0])
    assert "LLM03.EA.AUTONOMY" in text and "REC-POLICY-GATE" in text
    assert sandbox.request["files"] == IN_SCOPE and sandbox.request["scope_dir"] == SCOPE
    assert sandbox.request["node"] == INSTALL["node"] and sandbox.request["promptfoo"] == INSTALL["promptfoo"]

    doc = sarif_of(sandbox)
    (result,) = doc["runs"][0]["results"]
    assert result["ruleId"] == "LLM03.EA.FUNCTIONALITY" and result["level"] == "error"
    assert result["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": "src/calc_agent/agent.py"},
                                                          "region": {"startLine": 8, "endLine": 8}}
    assert result["message"]["text"] == "The calculator passes model output to eval()."
    props = result["properties"]
    assert props["cwe"] == ["CWE-95", "CWE-94"] and props["toolRuleIds"] == [TOOL_RULE_ID]
    assert props["controlStatus"] == "none" and props["residualRisk"] == "high"
    assert props["recommendations"] == ["REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE"]
    roles = [(s["location"]["physicalLocation"]["region"]["startLine"], s["properties"]["role"])
             for s in result["codeFlows"][0]["threadFlows"][0]["locations"]]
    assert roles == [(12, "model_decision"), (8, "root_cause"), (8, "sink")]
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "promptfoo-code-scan" and driver["version"] == "0.124.1+node-24.21.0"
    assert driver["properties"]["mode"] == "scoped" and driver["properties"]["headerFormat"] == guidance.HEADER_FORMAT
    run_props = doc["runs"][0]["properties"]["sastAgent"]
    assert run_props["dropped"]["noTaskRule"]["count"] == 1 and run_props["dropped"]["outOfScope"]["count"] == 1
    assert run_props["toolFindings"]["count"] == 3 and run_props["scorable"] is True
    assert run_props["promptfooReview"] == "Reviewed."

    reward = grade_sarif(TASK, doc)
    assert reward["reward"] > 0.9 and reward["controls"] == 1.0 and reward["recommendations"] == 1.0
    assert_key_nowhere(tmp_path, sandbox, context)
    assert set(meta["artifacts_saved"]) == {"metadata.json", "findings.sarif", "install.log", "promptfoo_scan.json",
                                            "promptfoo_guidance.txt"}


def test_the_key_travels_only_in_a_file_that_is_removed(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert sandbox.key_reads == [(KEY_FILE, True)]
    events = sandbox.events
    prepare = events.index(("exec", f"rm -rf {KEY_DIR} && mkdir -p {KEY_DIR} && chmod 700 {KEY_DIR}"))
    upload = events.index(("upload", f"{KEY_FILE}.upload"))
    protect = next(i for i, (kind, c) in enumerate(events) if kind == "exec" and "chmod 600" in c)
    scan_i = next(i for i, (kind, c) in enumerate(events) if kind == "exec" and "scan.py" in c)
    removed = events.index(("exec", f"rm -rf {KEY_DIR}"))
    assert prepare < upload < protect < scan_i < removed
    assert KEY not in json.dumps(sandbox.request)
    assert_key_nowhere(tmp_path, sandbox, context)


def test_scan_command_and_time_limit(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, timeout_sec=1800)
    asyncio.run(go())
    (command, env, exec_limit), = sandbox.commands_with("scan.py")
    args = shlex.split(command.split(" && exec ", 1)[1])
    assert args[:3] == ["timeout", "-k", str(KILL_AFTER_SEC)]
    seconds = int(args[3])
    assert args[4:] == [INSTALL["python"], "-I", "-B", f"{WORK}/scan.py", "--request",
                        f"{WORK}/out/promptfoo_request.json", "--keyfile", KEY_FILE, "--out", OUT]
    assert exec_limit == seconds + KILL_AFTER_SEC + 5
    assert seconds <= 1800 - 60 and sandbox.request["budget_sec"] == seconds
    assert env == {"HOME": f"{WORK}/home/promptfoo-runner", "PYTHONDONTWRITEBYTECODE": "1",
                   "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    record = context.metadata["promptfoo_scan"]
    assert record["harbor_limit_needed_sec"] == 1920 and "--agent-timeout-multiplier" in record["budget_note"]


# ---------------------------------------------------------------- stock mode


def test_stock_mode_sends_no_guidance_and_emits_nothing_scorable(tmp_path, api_key, grade_sarif):
    comments = [comment("src/calc_agent/agent.py", 8, "eval() of model output", head=GOOD_HEADER),
                comment("src/calc_agent/llm.py", 2, "prompt logged", severity="medium")]
    sandbox = FakeSandbox(document=scan_document(comments))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok" and meta["mode"] == "stock"
    assert sandbox.request["guidance_file"] is None and GUIDANCE not in sandbox.files
    assert meta["promptfoo_scan"]["guidance_source"] is None
    doc = sarif_of(sandbox)
    assert doc["runs"][0]["results"] == []
    agent_props = doc["runs"][0]["properties"]["sastAgent"]
    assert agent_props["scorable"] is False
    assert agent_props["dropped"]["noTaskRule"]["count"] == 2
    assert agent_props["toolFindings"]["items"][0][:4] == ["src/calc_agent/agent.py", 8, 8, "high"]
    assert meta["tool_findings_count"] == 2 and meta["results_emitted"] == 0
    assert set(meta["artifacts_saved"]) == {"metadata.json", "findings.sarif", "install.log", "promptfoo_scan.json"}
    assert meta["artifacts_failed"] == []


# ---------------------------------------------------------------- options


def test_options_from_kwargs_and_environment(tmp_path, api_key, monkeypatch):
    monkeypatch.setenv("PROMPTFOO_SCAN_MODE", "scoped")
    monkeypatch.setenv("PROMPTFOO_SCAN_MIN_SEVERITY", "LOW")
    agent = PromptfooCodeScanAgent(logs_dir=tmp_path)
    assert agent.options.mode == "scoped" and agent.options.min_severity == "low"
    agent = PromptfooCodeScanAgent(logs_dir=tmp_path, mode="stock", diffs_only="true", scan_roots="src/calc_agent",
                                   unknown_key="x")
    assert agent.options.mode == "stock" and agent.options.diffs_only is True
    assert agent.options.scan_roots == ["src/calc_agent"]

    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, min_severity="high", diffs_only="true",
                               scan_roots="src/calc_agent/agent.py", unknown_key="x")
    asyncio.run(go())
    assert sandbox.request["min_severity"] == "high" and sandbox.request["diffs_only"] is True
    assert sandbox.request["files"] == ["src/calc_agent/agent.py"]
    assert context.metadata["options_ignored"] == ["unknown_key"]


@pytest.mark.parametrize("bad", [{"mode": "fancy"}, {"min_severity": "none"}, {"timeout_sec": "30"},
                                 {"diffs_only": "maybe"}])
def test_bad_options_are_refused(tmp_path, bad):
    with pytest.raises(ValueError):
        PromptfooCodeScanAgent(logs_dir=tmp_path, **bad)


def test_preflight_needs_the_key_on_the_host(monkeypatch):
    monkeypatch.delenv("PROMPTFOO_API_KEY", raising=False)
    with pytest.raises(ValueError, match="PROMPTFOO_API_KEY is not set on the host"):
        PromptfooCodeScanAgent.preflight({}, {})
    # Never from Harbor's --ae env.
    with pytest.raises(ValueError):
        PromptfooCodeScanAgent.preflight({}, {"PROMPTFOO_API_KEY": KEY})
    monkeypatch.setenv("PROMPTFOO_API_KEY", KEY)
    PromptfooCodeScanAgent.preflight({"mode": "scoped"}, {})


def test_missing_key_fails_before_anything_runs(tmp_path, monkeypatch):
    monkeypatch.delenv("PROMPTFOO_API_KEY", raising=False)
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="PROMPTFOO_API_KEY is not set"):
        asyncio.run(go())
    assert context.metadata["status"] == "error" and not sandbox.commands_with("scan.py")


def test_run_without_setup_is_an_error(tmp_path, api_key):
    sandbox = FakeSandbox(install_result={"source": "setup"})
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="setup"):
        asyncio.run(go())


def test_install_files_and_command(tmp_path, api_key):
    agent = PromptfooCodeScanAgent(logs_dir=tmp_path)
    files = agent.install_files()
    assert set(files) == {"install.py", "scan.py", "pins.json", "package.json", "package-lock.json"}
    assert json.loads(files["pins.json"]) == pins.as_dict()
    assert all(KEY.encode() not in data for data in files.values())
    command = agent.install_command(WORK)
    assert KEY not in command and "install.py" in command and "pins.json" in command


# ---------------------------------------------------------------- failures


@pytest.mark.parametrize("code, words", [
    ("auth", "refused PROMPTFOO_API_KEY"),
    ("network", "cannot reach api.promptfoo.app"),
    ("service", "busy"),
    ("git", "git repository"),
    ("mcp", "MCP"),
    ("no_key", "key file"),
    ("scan_script", "runner failed"),
])
def test_infrastructure_failures_are_errors_and_remove_the_key(tmp_path, api_key, code, words):
    document = scan_document(status="error", error={"code": code, "message": f"something about {code}"})
    sandbox = FakeSandbox(document=document)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError) as raised:
        asyncio.run(go())
    assert words in str(raised.value) and type(raised.value) is ScannerError
    assert context.metadata["status"] == "error"
    assert_key_nowhere(tmp_path, sandbox, context)


@pytest.mark.parametrize("code, reason", [
    ("deadline", "deadline"), ("tool_failed", "tool_crashed"), ("bad_output", "bad_review_output"),
    ("no_files", "tool_saw_nothing"), ("skipped", "tool_saw_nothing"),
])
def test_tool_outcomes_are_scored_not_errors(tmp_path, api_key, code, reason):
    document = scan_document(status="error", error={"code": code, "message": "x"})
    sandbox = FakeSandbox(document=document)
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "tool_outcome" and meta["tool_outcome"]["reason"] == reason
    assert "/app/output/findings.sarif" not in sandbox.files
    assert_key_nowhere(tmp_path, sandbox, context)


def test_scan_killed_by_timeout_is_a_deadline(tmp_path, api_key):
    sandbox = FakeSandbox(scan_exit=124, write_document=False)
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert context.metadata["tool_outcome"]["reason"] == "deadline"
    assert context.metadata["promptfoo_scan"]["key_file_removed"] is True


def test_scan_without_output_is_an_error(tmp_path, api_key):
    sandbox = FakeSandbox(write_document=False, scan_stdout="Traceback ...")
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="without a readable result"):
        asyncio.run(go())


def test_ok_status_with_a_non_zero_exit_is_an_error(tmp_path, api_key):
    sandbox = FakeSandbox(scan_exit=1)
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError):
        asyncio.run(go())


def test_a_failure_while_protecting_the_key_leaves_nothing(tmp_path, api_key):
    sandbox = FakeSandbox(protect_exit=1)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="could not protect the key file"):
        asyncio.run(go())
    assert not sandbox.commands_with("scan.py")
    assert_key_nowhere(tmp_path, sandbox, context)


def test_key_echoed_by_the_runner_is_scrubbed_everywhere(tmp_path, api_key):
    sandbox = FakeSandbox(document=scan_document(echo_key=True), scan_stdout=f"SCAN_RESULT {{}}\nkey {KEY}\n")
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert context.metadata["status"] == "ok"
    assert_key_nowhere(tmp_path, sandbox, context)


# ---------------------------------------------------------------- the module's imports


def test_agent_imports_only_stdlib_and_harbor():
    from tests.test_imports import _closure

    code = ("import json, sys; import sast.promptfoo.agent; "
            "print(json.dumps(sorted({m.split('.')[0] for m in sys.modules})))")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True, capture_output=True, text=True)
    allowed = _closure("harbor")
    providers = metadata.packages_distributions()
    offenders = []
    for module in set(json.loads(out.stdout)) - set(sys.stdlib_module_names) - {
            "sast", "harbor", "sitecustomize", "usercustomize"}:
        if module.startswith("_"):
            continue
        dists = {d.lower().replace("_", "-") for d in providers.get(module, [])}
        if not dists & allowed:
            offenders.append((module, sorted(dists)))
    assert offenders == []


def test_scoped_is_the_default_mode(tmp_path):
    assert PromptfooCodeScanAgent(logs_dir=tmp_path).options.mode == "scoped"
