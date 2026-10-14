"""CodexSecurityAgent against a fake sandbox: options, model reporting, the key
file, the driver command, failures, normalisation, the SARIF and the grade.

No model is called. The fake sandbox answers the driver command with a result
document in driver.py's format (its real behaviour is tested in
test_codex_security_driver.py) and lists files from the sample task
``smoke_eval``.
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
from pathlib import Path

import pytest
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

import sast
from sast import cwe_map
from sast.claude_review.agent import KILL_AFTER_SEC
from sast.codex_security import pins
from sast.codex_security.agent import ENGINE, CodexSecurityAgent, choose_auth
from sast.codex_security.options import CodexSecurityOptions
from sast.errors import ScannerError
from tests.codex_security_fakes import KEY, answer, finding
from tests.conftest import FIXTURES, SAMPLE_TASKS

WORK = "/opt/sast"
KEY_DIR = f"{WORK}/secret-codex"
KEY_FILE = f"{KEY_DIR}/openai-key"
OUT = f"{WORK}/out/codex_security.json"
TASK = "smoke_eval"
REPO = SAMPLE_TASKS / TASK / "environment" / "repo"
MODEL = "gpt-5.6-sol"
IN_SCOPE = ["src/calc_agent/__init__.py", "src/calc_agent/agent.py", "src/calc_agent/llm.py",
            "src/calc_agent/maintenance.py"]
CONTRACT_TEXT = (FIXTURES / "claude_review" / "contract_instruction.md").read_text(encoding="utf-8")


def line_counts(files=IN_SCOPE):
    return {f: len((REPO / f).read_text().splitlines()) for f in files}


def driver_document(findings=None, *, status="ok", error=None, echo_key=False, files=IN_SCOPE, commands=None):
    findings = [] if findings is None else findings
    doc = {
        "driver_format": 1, "status": status, "seconds": 80.0,
        "codex_version": "codex-cli 0.162.1",
        "network": {"url": "https://api.openai.com/v1/models", "status": 401},
        "login": {"auth_file_mode": "0o600", "status": "api_key"},
        "sandbox_probe": {"ok": True, "exit_code": 0, "output": ""},
        "exec_argv": ["/opt/sast/codex-security/bin/codex", "exec", "--json"],
        "codex_environment": ["CODEX_HOME", "HOME", "PATH"],
        "codex_home_removed": True,
        "scope_copy": {"dir": f"{WORK}/codex-scope", "files": len(files), "manifest": True},
        "line_counts": line_counts(files),
        "not_text": [],
        "exec": {"attempts": [{"exit_code": 0, "seconds": 75.0, "outcome": "ok", "usage": {"input_tokens": 9000}}],
                 "commands": commands or [{"attempt": 1, "command": "/bin/bash -lc 'rg -n eval'", "exit_code": 0,
                                           "status": "completed"}],
                 "commands_count": len(commands or [1]), "commands_outside_scope": [], "sandbox_failures": 0,
                 "usage": {"input_tokens": 9000, "output_tokens": 700}, "thread_id": "thread-1",
                 "file_changes": [], "web_searches": 0, "mcp_tool_calls": 0},
        "review": answer(findings, files_reviewed=len(files)),
        "review_summary": {"files_reviewed": len(files), "review_completed": True},
        "paths_relativised": 0,
    }
    if error:
        doc["error"] = error
    if echo_key:
        doc["note"] = f"the key was {KEY}"
    return doc


class FakeSandbox:
    """Just enough of BaseEnvironment: a dict file system and scripted exec."""

    def __init__(self, document=None, driver_exit=0, driver_stdout=None, write_document=True, protect_exit=0,
                 install_ok=True):
        self.environment_dir = SAMPLE_TASKS / TASK / "environment"
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None, float | None]] = []
        self.events: list[tuple[str, str]] = []
        self.key_reads: list[tuple[str, bool]] = []
        self.document = driver_document() if document is None else document
        self.driver_exit = driver_exit
        self.driver_stdout = driver_stdout
        self.write_document = write_document
        self.protect_exit = protect_exit
        self.install_ok = install_ok
        self.request = None

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
                found += [str(p.relative_to(REPO)).replace("\\", "/") for p in base.rglob("*") if p.is_file()]
        return ExecResult(stdout="\n".join(found) + "\n", return_code=0)

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
        if "codex_install.py" in command:
            if not self.install_ok:
                return ExecResult(stdout="[install] ERROR: codex.tar.gz has sha256 00, expected 86", return_code=2)
            result = {"codex": "/opt/sast/codex-security-local/bin/codex", "source": "setup",
                      "codex_version_output": "codex-cli 0.162.1"}
            return ExecResult(stdout="INSTALL_RESULT " + json.dumps(result), return_code=0)
        if "codex_driver.py" in command:
            args = shlex.split(command.split(" && exec ", 1)[1])
            keyfile = args[args.index("--keyfile") + 1]
            self.key_reads.append((keyfile, self.files.get(keyfile, b"").strip() == KEY.encode()))
            self.request = json.loads(self.files[args[args.index("--request") + 1]])
            if self.write_document:
                self.files[args[args.index("--out") + 1]] = json.dumps(self.document).encode()
            stdout = self.driver_stdout if self.driver_stdout is not None else "DRIVER_RESULT " + json.dumps(
                {"status": self.document.get("status")})
            return ExecResult(stdout=stdout, stderr="", return_code=self.driver_exit)
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


CLEAN_ENV = ("CODEX_SECURITY_MODEL", "CODEX_SECURITY_MODE", "CODEX_SECURITY_AUTH", "CODEX_SECURITY_SANDBOX",
             "CODEX_SECURITY_TIMEOUT_SEC", "CODEX_SECURITY_REASONING_EFFORT", "CODEX_SECURITY_ATTEMPTS",
             "CODEX_API_KEY", "OPENAI_API_KEY")


@pytest.fixture
def api_key(monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", KEY)


def run_agent(tmp_path, box, instruction="instruction text", **options):
    options.setdefault("mode", "stock")  # these tests were written for stock; scoped is the default now
    agent = CodexSecurityAgent(logs_dir=tmp_path, model_name="anthropic/claude-x", **options)
    context = AgentContext()

    async def go():
        await agent.setup(box)
        await agent.run(instruction, box, context)

    return agent, context, go


def assert_key_nowhere(tmp_path, sandbox, context):
    """Not in any exec command or env, log, metadata, artifact or output, and the key file is gone."""
    for command, env, _ in sandbox.commands:
        assert KEY not in command
        assert not {"OPENAI_API_KEY", "CODEX_API_KEY"} & set(env or {})
        assert all(KEY not in value for value in (env or {}).values())
    assert KEY not in json.dumps(context.metadata, default=str)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert KEY not in path.read_text(errors="replace"), path
    for name, data in sandbox.files.items():
        assert KEY.encode() not in data, name
    assert not any(name.startswith(KEY_DIR) for name in sandbox.files)
    assert context.metadata["codex_security"]["key_file_removed"] is True


def sarif_of(sandbox):
    return json.loads(sandbox.files["/app/output/findings.sarif"])


def results_of(sandbox):
    return [(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
             r["locations"][0]["physicalLocation"]["region"]["startLine"],
             r["locations"][0]["physicalLocation"]["region"]["endLine"], r["level"])
            for r in sarif_of(sandbox)["runs"][0]["results"]]


# ---------------------------------------------------------------- options and credential


def test_options_from_kwargs_and_environment(monkeypatch, api_key):
    monkeypatch.setenv("CODEX_SECURITY_MODEL", "gpt-6.1-sol")
    monkeypatch.setenv("CODEX_SECURITY_MODE", "scoped")
    options = CodexSecurityAgent.parse_options({"model": "openai/gpt-5.5", "attempts": "3",
                                                "scan_roots": "src, config", "stray": "x"}, None)
    assert options.model == "gpt-5.5" and options.mode == "scoped" and options.attempts == 3
    assert options.scan_roots == ["src", "config"] and options.sandbox == "read-only" and options.auth == "auto"


@pytest.mark.parametrize("bad", [{"mode": "fast"}, {"sandbox": "none"}, {"attempts": "9"}, {"timeout_sec": "30"},
                                 {"model": "gpt 5"}, {"model": "-x"}, {"reasoning_effort": "a;b"},
                                 {"auth": "token"}])
def test_bad_options_are_refused(bad):
    with pytest.raises(Exception):
        CodexSecurityOptions(**bad)


def test_choose_auth_reads_names_only():
    assert choose_auth("auto", {"OPENAI_API_KEY": "k"})[0] == "OPENAI_API_KEY"
    assert choose_auth("auto", {"CODEX_API_KEY": "k"})[0] == "CODEX_API_KEY"
    assert choose_auth("auto", {"OPENAI_API_KEY": "a", "CODEX_API_KEY": "b"})[0] == "OPENAI_API_KEY"
    assert choose_auth("codex_api_key", {"OPENAI_API_KEY": "a", "CODEX_API_KEY": "b"})[0] == "CODEX_API_KEY"
    assert choose_auth("openai_api_key", {"CODEX_API_KEY": "b"})[0] is None
    name, note = choose_auth("auto", {"OPENAI_API_KEY": "  "})
    assert name is None and "OPENAI_API_KEY" in note


def test_preflight_needs_a_key_on_the_host(monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        CodexSecurityAgent.preflight({}, None)
    monkeypatch.setenv("CODEX_API_KEY", KEY)
    CodexSecurityAgent.preflight({}, None)


def test_missing_key_fails_before_anything_runs(tmp_path, monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="OPENAI_API_KEY"):
        asyncio.run(go())
    assert sandbox.commands_with("codex_driver.py") == [] and context.metadata["status"] == "error"


def test_install_failure_is_an_error(tmp_path, api_key):
    sandbox = FakeSandbox(install_ok=False)
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="sha256"):
        asyncio.run(go())


def test_install_files_and_command_carry_no_secret(tmp_path, api_key):
    agent = CodexSecurityAgent(logs_dir=tmp_path)
    files = agent.install_files()
    assert set(files) == {"codex_install.py", "codex_driver.py", "ccsr_driver.py", "codex_pins.json"}
    assert json.loads(files["codex_pins.json"]) == pins.as_dict()
    assert all(KEY.encode() not in data for data in files.values()) and KEY not in agent.install_command(WORK)


# ---------------------------------------------------------------- happy path


def test_happy_path_maps_findings_and_keeps_the_key_in_a_file(tmp_path, api_key):
    findings = [
        finding("src/calc_agent/agent.py", 8, cwe=["CWE-95"], category="eval_injection", priority=0),
        finding("src/calc_agent/maintenance.py", 6, 8, cwe=[], category="Command Injection", priority=2),
        # No CWE and a category the table does not know: unmapped, counted, not reported.
        finding("src/calc_agent/llm.py", 2, cwe=[], category="business_logic_flaw", priority=3),
    ]
    sandbox = FakeSandbox(document=driver_document(findings))
    agent, context, go = run_agent(tmp_path, sandbox, model=MODEL)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok", meta.get("error")
    assert meta["engine"] == ENGINE == "codex exec security review"
    assert meta["model"] == MODEL and meta["model_source"] == "option" and meta["mode"] == "stock"
    assert meta["auth_source"] == "OPENAI_API_KEY" and meta["sandbox"] == "read-only"
    assert meta["harbor_model_name_ignored"] == "anthropic/claude-x"
    info = agent.to_agent_info()
    assert info.model_info.name == MODEL and info.model_info.provider == "openai"
    assert meta["agent_version"] == f"{sast.__version__}+codex-exec-security-review-codex-cli-{pins.CODEX_VERSION}"

    review = meta["codex_security"]
    assert review["not_the_codex_security_product"] is True and review["codex_version"] == "codex-cli 0.162.1"
    assert review["usage"] == {"input_tokens": 9000, "output_tokens": 700} and review["cost_usd"] is None
    assert review["findings_raw"] == 3 and review["contract_source"] is None
    assert review["sandbox_deny"] == ["/app/repo", KEY_DIR, f"{WORK}/home/codex-security/codex-home",
                                      f"{WORK}/out", "/logs"]
    assert meta["cwe_source"] == {"model": 1, "none": 1, "table_fallback": 1}
    assert meta["unmapped_by_category"] == {"business_logic_flaw": 1}
    assert meta["findings_by_priority"] == {"P0": 1, "P2": 1, "P3": 1}

    assert results_of(sandbox) == [
        ("LLM03.EA.FUNCTIONALITY", "src/calc_agent/agent.py", 8, 8, "error"),
        ("LLM03.EA.FUNCTIONALITY", "src/calc_agent/maintenance.py", 6, 8, "warning"),
    ]
    first = sarif_of(sandbox)["runs"][0]["results"][0]
    assert first["properties"]["cwe"] == ["CWE-95"] and first["properties"]["toolRuleIds"] == ["codex/eval_injection"]
    assert first["properties"]["toolProperties"]["cweSource"] == "model"
    assert "codeFlows" not in first and "controlStatus" not in first["properties"]
    driver = sarif_of(sandbox)["runs"][0]["tool"]["driver"]
    assert driver["name"] == "codex-exec-security-review"
    assert driver["properties"]["engine"] == ENGINE and driver["properties"]["model"] == MODEL
    assert driver["properties"]["codexVersion"] == pins.CODEX_VERSION and driver["properties"]["cweMap"] == cwe_map.VERSION
    run_props = sarif_of(sandbox)["runs"][0]["properties"]["sastAgent"]
    assert run_props["engine"] == ENGINE and run_props["dropped"]["categoryNotInMap"]["count"] == 1

    # The request: the in-scope files, the stock prompt, no secret.
    request = sandbox.request
    assert request["files"] == IN_SCOPE and request["model"] == MODEL and request["mode"] == "stock"
    assert request["codex"] == "/opt/sast/codex-security-local/bin/codex"
    assert request["scope_dir"] == f"{WORK}/codex-scope" and request["network_check_url"].startswith("https://api.openai")
    assert "rule_id" not in json.dumps(request["schema"]) and KEY not in json.dumps(request)
    assert 'default_permissions = "sast-review"' in request["config_toml"]
    assert '"/app/repo" = "deny"' in request["config_toml"]

    # The key travels only in a file, which exists while the driver runs and is removed after.
    assert sandbox.key_reads == [(KEY_FILE, True)]
    events = sandbox.events
    prepare = events.index(("exec", f"rm -rf {KEY_DIR} && mkdir -p {KEY_DIR} && chmod 700 {KEY_DIR}"))
    upload = events.index(("upload", f"{KEY_FILE}.upload"))
    protect = next(i for i, (kind, c) in enumerate(events) if kind == "exec" and "chmod 600" in c)
    driver_i = next(i for i, (kind, c) in enumerate(events) if kind == "exec" and "codex_driver.py" in c)
    removed = events.index(("exec", f"rm -rf {KEY_DIR}"))
    assert prepare < upload < protect < driver_i < removed
    assert_key_nowhere(tmp_path, sandbox, context)
    assert set(meta["artifacts_saved"]) == {"metadata.json", "findings.sarif", "install.log", "codex_security.json"}


def test_driver_command_and_time_limit(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, timeout_sec=1800)
    asyncio.run(go())
    (command, env, exec_limit), = sandbox.commands_with("codex_driver.py")
    inner = command.split(" && exec ", 1)[1]
    args = shlex.split(inner)
    assert args[:3] == ["timeout", "-k", str(KILL_AFTER_SEC)]
    seconds = int(args[3])
    assert args[4:8] == ["$PY", "-I", "-B", f"{WORK}/codex_driver.py"]
    assert args[8:] == ["--request", f"{WORK}/out/codex_security_request.json", "--keyfile", KEY_FILE, "--out", OUT]
    assert exec_limit == seconds + KILL_AFTER_SEC + 5 and sandbox.request["budget_sec"] == seconds
    assert env == {"HOME": f"{WORK}/home/codex-security", "PYTHONDONTWRITEBYTECODE": "1",
                   "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    assert context.metadata["scan_budget_sec"] == 1800
    assert context.metadata["codex_security"]["harbor_limit_needed_sec"] == 1920


def test_default_model_and_container_sandbox_reach_the_driver(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, sandbox="container", reasoning_effort="xhigh")
    asyncio.run(go())
    assert sandbox.request["model"] == pins.DEFAULT_MODEL and context.metadata["model_source"] == "default"
    assert sandbox.request["sandbox"] == "container"
    config = sandbox.request["config_toml"]
    assert 'sandbox_mode = "danger-full-access"' in config and "permissions" not in config
    assert 'model_reasoning_effort = "xhigh"' in config
    assert context.metadata["codex_security"]["sandbox_deny"] == []


# ---------------------------------------------------------------- failures


@pytest.mark.parametrize("code, words", [
    ("api_auth", "refused the key"), ("network", "api.openai.com"), ("model_unavailable", "--ak model"),
    ("sandbox_unavailable", "sandbox=container"), ("cli_failed", "every attempt"), ("quota", "quota"),
    ("login_failed", "login"), ("no_key", "credential file"),
])
def test_driver_errors_become_scanner_errors_and_remove_the_key(tmp_path, api_key, code, words):
    doc = driver_document(status="error", error={"code": code, "message": "details"})
    sandbox = FakeSandbox(document=doc, driver_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError) as exc:
        asyncio.run(go())
    assert words in str(exc.value) and f"[{code}]" in str(exc.value)
    assert context.metadata["status"] == "error" and "tool_outcome" not in context.metadata
    assert_key_nowhere(tmp_path, sandbox, context)


@pytest.mark.parametrize("code, reason", [
    ("timeout", "deadline"), ("deadline", "deadline"), ("review_incomplete", "review_incomplete"),
    ("files_reviewed_zero", "files_reviewed_zero"), ("prompt_too_long", "prompt_too_long"),
    ("bad_answer", "bad_review_output"), ("bad_findings", "bad_review_output"), ("cli_crashed", "tool_crashed"),
])
def test_review_outcomes_are_scored_not_errors(tmp_path, api_key, code, reason):
    doc = driver_document(status="error", error={"code": code, "message": "details"})
    sandbox = FakeSandbox(document=doc, driver_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "tool_outcome" and meta["tool_outcome"]["reason"] == reason
    assert "/app/output/findings.sarif" not in sandbox.files
    assert_key_nowhere(tmp_path, sandbox, context)


def test_driver_without_output_is_an_error(tmp_path, api_key):
    sandbox = FakeSandbox(write_document=False, driver_exit=4)
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="without a readable result"):
        asyncio.run(go())


def test_ok_status_with_a_non_zero_exit_is_still_an_error(tmp_path, api_key):
    sandbox = FakeSandbox(driver_exit=1)
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError):
        asyncio.run(go())


def test_a_failure_while_protecting_the_key_leaves_nothing(tmp_path, api_key):
    sandbox = FakeSandbox(protect_exit=1)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="protect the key file"):
        asyncio.run(go())
    assert sandbox.commands_with("codex_driver.py") == []
    assert_key_nowhere(tmp_path, sandbox, context)


def test_key_echoed_by_the_driver_is_scrubbed_everywhere(tmp_path, api_key):
    doc = driver_document(echo_key=True)
    sandbox = FakeSandbox(document=doc, driver_stdout=f"leak {KEY} and sk-proj-***EFGH\nDRIVER_RESULT {{}}")
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert_key_nowhere(tmp_path, sandbox, context)
    log = (tmp_path / "command-1" / "stdout.txt").read_text()
    assert "leak *** and ***" in log and "EFGH" not in log


def test_run_without_setup_is_an_error(tmp_path, api_key):
    agent = CodexSecurityAgent(logs_dir=tmp_path)
    context = AgentContext()
    with pytest.raises(ScannerError, match="setup"):
        asyncio.run(agent.run("x", FakeSandbox(), context))


# ---------------------------------------------------------------- normalisation through the agent


def test_bad_locations_and_out_of_scope_findings_are_dropped_and_counted(tmp_path, api_key):
    findings = [
        finding("src/calc_agent/agent.py", 999),                       # past the end of the file
        finding("tests/test_agent.py", 1),                             # excluded path
        finding("src/calc_agent/agent.py", 0),                         # no such line
        finding("/etc/passwd", 1),                                     # outside the repository
        {"title": "no location"},
        "not an object",
        finding("src/calc_agent/agent.py", 8, 3, cwe=["CWE-95"]),      # end before start: start used
    ]
    sandbox = FakeSandbox(document=driver_document(findings))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert results_of(sandbox) == [("LLM03.EA.FUNCTIONALITY", "src/calc_agent/agent.py", 8, 8, "error")]
    # A missing location has no file, so it counts as out of scope, as /etc/passwd does.
    assert meta["dropped_bad_location_count"] == 3 and meta["dropped_out_of_scope_count"] == 3
    assert meta["end_line_replaced"] == 1
    dropped = sarif_of(sandbox)["runs"][0]["properties"]["sastAgent"]["dropped"]
    assert dropped["badLocation"]["count"] == 3 and dropped["outOfScope"]["count"] == 3


ASSESSED = {
    "rule_id": "LLM03.EA.FUNCTIONALITY",
    "path": [{"file": "src/calc_agent/agent.py", "line": 12, "role": "model_decision"},
             {"file": "src/calc_agent/agent.py", "line": 8, "role": "sink"}],
    "control_status": "none", "residual_risk": "high",
    "recommendation_ids": ["REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE", "REC-NARROW-TYPED-TOOLS"],
}


def test_scoped_mode_writes_the_models_path_controls_and_recommendations(tmp_path, api_key, grade_sarif):
    findings = [finding("src/calc_agent/agent.py", 8, cwe=["CWE-95"], category="eval_injection", **ASSESSED)]
    sandbox = FakeSandbox(document=driver_document(findings))
    _, context, go = run_agent(tmp_path, sandbox, instruction=CONTRACT_TEXT, mode="scoped")
    asyncio.run(go())
    (result,) = sarif_of(sandbox)["runs"][0]["results"]
    steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [(s["location"]["physicalLocation"]["region"]["startLine"], s["properties"]["role"]) for s in steps] == [
        (12, "model_decision"), (8, "sink")]
    props = result["properties"]
    assert props["controlStatus"] == "none" and props["residualRisk"] == "high"
    assert props["recommendations"] == ["REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE"]
    review = context.metadata["codex_security"]
    assert review["contract_source"] == "task_instruction" and review["contract"]["rule_ids"][0].startswith("LLM")
    assert all(not v for v in review["contract_ids_not_accepted"].values())
    # The task's contract reaches the model as prompt text and as schema enums.
    assert "security_manifest.json" in sandbox.request["prompt"]
    assert "REC-POLICY-GATE" in json.dumps(sandbox.request["schema"])
    reward = grade_sarif(TASK, sarif_of(sandbox))
    assert reward["reward"] > 0 and reward["controls"] == 1.0 and reward["recommendations"] == 1.0


def test_scoped_mode_drops_bad_steps_values_and_rule_ids(tmp_path, api_key):
    findings = [
        finding("src/calc_agent/agent.py", 8, cwe=["CWE-95", "not-a-cwe"], rule_id="LLM09.MADE.UP",
                path=[{"file": "src/calc_agent/agent.py", "line": 999, "role": "sink"},
                      {"file": "tests/test_x.py", "line": 1, "role": "source"},
                      {"file": "src/calc_agent/agent.py", "line": 8, "role": "sink"}],
                control_status="mostly", residual_risk="severe", recommendation_ids=["REC-NOT-REAL"]),
        # Autonomy: no CWE maps to it, only the model's rule_id can report it.
        finding("src/calc_agent/maintenance.py", 5, cwe=["CWE-862"], rule_id="llm03.ea.autonomy"),
    ]
    sandbox = FakeSandbox(document=driver_document(findings))
    _, context, go = run_agent(tmp_path, sandbox, instruction=CONTRACT_TEXT, mode="scoped")
    asyncio.run(go())
    rules = {r[1:3]: r[0] for r in results_of(sandbox)}
    assert rules == {("src/calc_agent/agent.py", 8): "LLM03.EA.FUNCTIONALITY",
                     ("src/calc_agent/maintenance.py", 5): "LLM03.EA.AUTONOMY"}
    meta = context.metadata
    assert meta["rule_ids_rejected"] == ["LLM09.MADE.UP"] and meta["rule_source"] == {"cwe_table": 1, "model": 1}
    assert meta["path_steps_dropped_count"] == 2 and meta["assessed_values_rejected"] == ["mostly", "severe"]
    assert meta["recommendations_rejected"] == ["REC-NOT-REAL"] and meta["cwes_rejected"] == ["not-a-cwe"]


def test_stock_mode_ignores_the_assessed_fields(tmp_path, api_key):
    findings = [finding("src/calc_agent/agent.py", 8, cwe=["CWE-95"], **{**ASSESSED, "rule_id": "LLM03.EA.AUTONOMY"})]
    sandbox = FakeSandbox(document=driver_document(findings))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    (result,) = sarif_of(sandbox)["runs"][0]["results"]
    assert result["ruleId"] == "LLM03.EA.FUNCTIONALITY" and "codeFlows" not in result
    assert not {"controlStatus", "residualRisk", "recommendations"} & set(result["properties"])
    assert context.metadata["rule_source"] == {"cwe_table": 1}


def test_scoped_mode_without_a_contract_uses_the_harness_constants(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, instruction="no contract here", mode="scoped")
    asyncio.run(go())
    assert context.metadata["codex_security"]["contract_source"] == "harness_constants"
    assert "LLM03.EA.AUTONOMY" in json.dumps(sandbox.request["schema"])


def test_the_stock_sarif_grades_like_any_scanner(tmp_path, api_key, grade_sarif):
    findings = [finding("src/calc_agent/agent.py", 8, cwe=["CWE-95"], category="eval_injection")]
    sandbox = FakeSandbox(document=driver_document(findings))
    _, _, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert grade_sarif(TASK, sarif_of(sandbox))["reward"] > 0


def test_an_empty_review_writes_an_empty_sarif(tmp_path, api_key, grade_sarif):
    sandbox = FakeSandbox(document=driver_document([]))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert context.metadata["status"] == "ok" and sarif_of(sandbox)["runs"][0]["results"] == []


def test_commands_outside_the_scope_reach_the_metadata_and_the_sarif(tmp_path, api_key):
    doc = driver_document()
    doc["exec"]["commands_outside_scope"] = [{"attempt": 1, "command": "cat /app/repo/tests/x.py",
                                              "outside_scope": "names the repository"}]
    sandbox = FakeSandbox(document=doc)
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert context.metadata["codex_security"]["commands_outside_scope_count"] == 1
    flagged = sarif_of(sandbox)["runs"][0]["properties"]["sastAgent"]["commandsOutsideScope"]
    assert flagged == {"count": 1, "items": ["cat /app/repo/tests/x.py"]}


def test_agent_imports_only_stdlib_and_harbor():
    import subprocess
    import sys
    from importlib import metadata

    from tests.conftest import ROOT
    from tests.test_imports import _closure

    code = ("import json, sys; import sast.codex_security.agent; "
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
    assert CodexSecurityAgent(logs_dir=tmp_path).options.mode == "scoped"
