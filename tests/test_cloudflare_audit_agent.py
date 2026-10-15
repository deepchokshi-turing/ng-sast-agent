"""CloudflareAuditAgent against a fake sandbox: options, model reporting, the
credential file, the driver command, the request, failures, normalisation, the
SARIF and the grade.

No model is called. The fake sandbox answers the driver command with a result
document in driver.py's format (its real behaviour is tested in
test_cloudflare_audit_driver.py) and lists files from the sample task
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
from sast.cloudflare_audit import pins, request as request_module
from sast.cloudflare_audit.agent import CloudflareAuditAgent
from sast.cloudflare_audit.options import CloudflareAuditOptions
from sast.errors import ScannerError
from tests.cloudflare_audit_fakes import KEY, OAUTH_TOKEN, annotation, confirmed, needs_validation, rejected
from tests.conftest import FIXTURES, SAMPLE_TASKS

WORK = "/opt/sast"
KEY_DIR = f"{WORK}/secret-cloudflare"
OUT = f"{WORK}/out/cloudflare_audit.json"
TASK = "smoke_eval"
REPO = SAMPLE_TASKS / TASK / "environment" / "repo"
MODEL = "claude-opus-5-5"
IN_SCOPE = ["src/calc_agent/__init__.py", "src/calc_agent/agent.py", "src/calc_agent/llm.py",
            "src/calc_agent/maintenance.py"]
CONTRACT_TEXT = (FIXTURES / "claude_review" / "contract_instruction.md").read_text(encoding="utf-8")
ASSESSED = {"rule_id": "LLM03.EA.FUNCTIONALITY", "location": {"file": "src/calc_agent/agent.py", "start_line": 8,
                                                             "end_line": 8},
            "trace_roles": ["model_decision", None, "sink"], "control_status": "none", "residual_risk": "high",
            "recommendation_ids": ["REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE"]}


def line_counts(files=IN_SCOPE):
    return {f: len((REPO / f).read_text().splitlines()) for f in files}


def driver_document(records=None, annotations=None, *, status="ok", error=None, echo_key=None, run_status="complete"):
    records = [] if records is None else records
    doc = {
        "driver_format": 1, "status": status, "seconds": 900.0, "claude_code_version": "2.1.296 (Claude Code)",
        "network": {"url": "https://api.anthropic.com/", "status": 404},
        "cli_argv": ["/opt/sast/cloudflare-audit/bin/claude", "-p"], "cli_settings": {"permissions": {}},
        "cli_environment": ["CLAUDE_CODE_OAUTH_TOKEN", "HOME", "PATH"],
        "scope_copy": {"files": 5, "manifest": True}, "line_counts": line_counts(), "not_text": [],
        "cli": {"init": {"model": MODEL, "apiKeySource": "none", "permissionMode": "dontAsk",
                         "skills": ["security-audit"], "tools": ["Task", "Read"]},
                "attempts": [{"exit_code": 0, "seconds": 880.0, "outcome": "ok",
                              "wrapper": {"total_cost_usd": 4.25}}],
                "cli": {"total_cost_usd": 4.25, "num_turns": 60, "modelUsage": {MODEL: {
                    "inputTokens": 1000, "outputTokens": 400, "cacheReadInputTokens": 9000,
                    "cacheCreationInputTokens": 500}}, "permission_denials": [{"tool_name": "Bash"}]},
                "tool_uses_count": 3,
                "tool_uses": [{"tool": "Skill", "skill": "security-audit"}, {"tool": "Task", "subagent_type": "general"},
                              {"tool": "Read", "file_path": "/opt/sast/cloudflare-scope/src/calc_agent/agent.py"}],
                "tool_uses_outside_scope": []},
        "outputs": {"count": 6, "files": [["findings.json", 100]]},
        "output_status": {"findings.json": "ok"},
        "validators": {"findings": {"ran": True, "exit_code": 0, "passed": True, "output": "ok"}},
        "run_metadata": {"run_status": run_status, "profile": "quick"}, "run_status": run_status,
        "ledger": {"units": 4, "by_state": {"covered": 3, "candidate": 1}},
        "findings": records, "annotations": {"findings": annotations} if annotations is not None else None,
        "paths_relativised": 0,
    }
    if error:
        doc["error"] = error
    if echo_key:
        doc["note"] = f"the token was {echo_key}"
    return doc


class FakeSandbox:
    """Just enough of BaseEnvironment: a dict file system and scripted exec."""

    def __init__(self, document=None, driver_exit=0, write_document=True, install_ok=True):
        self.environment_dir = SAMPLE_TASKS / TASK / "environment"
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None, float | None]] = []
        self.key_reads: list[tuple[str, bool]] = []
        self.document = driver_document() if document is None else document
        self.driver_exit = driver_exit
        self.write_document = write_document
        self.install_ok = install_ok
        self.request = None

    def _remove_tree(self, path):
        for name in [n for n in self.files if n == path or n.startswith(path + "/")]:
            del self.files[name]

    def _find(self, command):
        args = shlex.split(command)
        found = []
        for root in args[1:args.index("-name")]:
            base = REPO / root
            if base.is_file():
                found.append(root)
            elif base.is_dir():
                found += [str(p.relative_to(REPO)).replace("\\", "/") for p in base.rglob("*") if p.is_file()]
        return ExecResult(stdout="\n".join(found) + "\n", return_code=0)

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        self.commands.append((command, env, timeout_sec))
        if command.startswith("umask 077 && cat "):
            source, target = re.search(r"cat (\S+) > (\S+)", command).groups()
            self.files[target] = self.files.pop(source)
            return ExecResult(return_code=0)
        if re.fullmatch(r"rm -rf (\S+) && mkdir -p \S+ && chmod 700 \S+", command) or re.fullmatch(r"rm -rf (\S+)",
                                                                                                    command):
            self._remove_tree(command.split()[2])
            return ExecResult(return_code=0)
        if command.startswith("find "):
            return self._find(command)
        if "cf_install.py" in command:
            if not self.install_ok:
                return ExecResult(stdout="[install] ERROR: SKILL.md has sha256 00, expected 5e", return_code=2)
            result = {"claude": "/opt/sast/cloudflare-audit/bin/claude", "node": "/opt/sast/cloudflare-audit/node/bin/node",
                      "skill_dir": "/opt/sast/cloudflare-audit/skill/security-audit", "source": "setup"}
            return ExecResult(stdout="INSTALL_RESULT " + json.dumps(result), return_code=0)
        if "cf_driver.py" in command:
            args = shlex.split(command.split(" && exec ", 1)[1])
            keyfile = args[args.index("--keyfile") + 1]
            self.key_reads.append((keyfile, self.files.get(keyfile, b"").strip()))
            self.request = json.loads(self.files[args[args.index("--request") + 1]])
            if self.write_document:
                self.files[args[args.index("--out") + 1]] = json.dumps(self.document).encode()
            return ExecResult(stdout="DRIVER_RESULT " + json.dumps({"status": self.document.get("status")}),
                              stderr="", return_code=self.driver_exit)
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
        self.files[str(target_path)] = Path(source_path).read_bytes()

    async def download_file(self, source_path, target_path):
        if source_path not in self.files:
            raise FileNotFoundError(source_path)
        Path(target_path).write_bytes(self.files[source_path])

    def commands_with(self, needle):
        return [(c, env, t) for c, env, t in self.commands if needle in c]


CLEAN_ENV = tuple(f"CLOUDFLARE_AUDIT_{k.upper()}" for k in CloudflareAuditOptions.model_fields) + (
    "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN")


@pytest.fixture
def token(monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", OAUTH_TOKEN)


def run_agent(tmp_path, box, instruction=CONTRACT_TEXT, **options):
    agent = CloudflareAuditAgent(logs_dir=tmp_path, model_name="openai/gpt-x", **options)
    context = AgentContext()

    async def go():
        await agent.setup(box)
        await agent.run(instruction, box, context)

    return agent, context, go


def assert_secret_nowhere(tmp_path, sandbox, context, secret=OAUTH_TOKEN):
    for command, env, _ in sandbox.commands:
        assert secret not in command
        assert not {"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"} & set(env or {})
        assert all(secret not in value for value in (env or {}).values())
    assert secret not in json.dumps(context.metadata, default=str)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret not in path.read_text(errors="replace"), path
    for name, data in sandbox.files.items():
        assert secret.encode() not in data, name
    assert not any(name.startswith(KEY_DIR) for name in sandbox.files)
    assert context.metadata["cloudflare_audit"]["key_file_removed"] is True


def sarif_of(sandbox):
    return json.loads(sandbox.files["/app/output/findings.sarif"])


# ---------------------------------------------------------------- options and credential


def test_options_from_kwargs_and_environment(monkeypatch, token):
    monkeypatch.setenv("CLOUDFLARE_AUDIT_PROFILE", "standard")
    monkeypatch.setenv("CLOUDFLARE_AUDIT_MODEL", "claude-x-1")
    options = CloudflareAuditAgent.parse_options({"model": "anthropic/claude-opus-5-5", "agent_budget": "30",
                                                  "include_needs_validation": "false", "scan_roots": "src, config",
                                                  "stray": "x"}, None)
    assert options.model == "claude-opus-5-5" and options.profile == "standard" and options.agent_budget == 30
    assert options.include_needs_validation is False and options.mode == "scoped" and options.auth == "auto"
    assert options.scan_roots == ["src", "config"] and options.attempts == 1


@pytest.mark.parametrize("bad", [{"mode": "fast"}, {"profile": "huge"}, {"attempts": "3"}, {"timeout_sec": "60"},
                                 {"model": "claude x"}, {"model": "-x"}, {"auth": "token"}, {"agent_budget": "2"},
                                 {"reasoning_effort": "ultra"}])
def test_bad_options_are_refused(bad):
    with pytest.raises(Exception):
        CloudflareAuditOptions(**bad)


def test_preflight_needs_a_credential_on_the_host(monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="Cloudflare security-audit agent"):
        CloudflareAuditAgent.preflight({}, None)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", OAUTH_TOKEN)
    CloudflareAuditAgent.preflight({}, None)


def test_missing_credential_fails_before_anything_runs(tmp_path, monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="CLAUDE_CODE_OAUTH_TOKEN"):
        asyncio.run(go())
    assert sandbox.commands_with("cf_driver.py") == [] and context.metadata["status"] == "error"


def test_install_failure_is_an_error(tmp_path, token):
    _, _, go = run_agent(tmp_path, FakeSandbox(install_ok=False))
    with pytest.raises(ScannerError, match="sha256"):
        asyncio.run(go())


def test_install_files_and_command_carry_no_secret(tmp_path, token):
    agent = CloudflareAuditAgent(logs_dir=tmp_path)
    files = agent.install_files()
    assert set(files) == {"cf_install.py", "cf_driver.py", "ccsr_install.py", "ccsr_driver.py", "cf_pins.json"}
    assert json.loads(files["cf_pins.json"]) == pins.as_dict()
    assert all(OAUTH_TOKEN.encode() not in data for data in files.values())
    assert OAUTH_TOKEN not in agent.install_command(WORK)


# ---------------------------------------------------------------- happy path


def test_scoped_run_maps_the_audit_and_keeps_the_token_in_a_file(tmp_path, token, grade_sarif):
    records = [confirmed(), needs_validation(), rejected()]
    annotations = [annotation(**ASSESSED), annotation("calc/maint", cwe=["CWE-862"], rule_id="LLM03.EA.AUTONOMY")]
    sandbox = FakeSandbox(document=driver_document(records, annotations, echo_key=OAUTH_TOKEN))
    agent, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok", meta.get("error")
    assert meta["model"] == MODEL and meta["model_source"] == "default" and meta["mode"] == "scoped"
    assert meta["auth"] == "oauth" and meta["auth_source"] == "CLAUDE_CODE_OAUTH_TOKEN"
    assert meta["harbor_model_name"] == "openai/gpt-x" and meta["harbor_model_name_used"] is False
    assert agent.to_agent_info().model_info.name == MODEL
    assert meta["agent_version"] == f"{sast.__version__}+cloudflare-security-audit-skill-{pins.SKILL_COMMIT[:7]}" \
                                    f"+claude-code-{pins.CLAUDE_CODE_VERSION}"
    audit = meta["cloudflare_audit"]
    assert audit["run_status"] == "complete" and audit["records_by_verdict"] == {
        "confirmed": 1, "needs_validation": 1, "rejected": 1}
    assert audit["skill_loaded"] is True and audit["subagent_calls"] == 1
    assert audit["contract_source"] == "task_instruction"
    assert all(not v for v in audit["contract_ids_not_accepted"].values())
    usage = meta["usage_summary"]
    assert usage["cost_usd"] == 4.25 and usage["n_input_tokens"] == 10500 and usage["n_output_tokens"] == 400
    assert context.cost_usd == 4.25

    # The credential: only in the key file, read by the driver, then removed.
    assert sandbox.key_reads == [(f"{KEY_DIR}/claude-oauth-token", OAUTH_TOKEN.encode())]
    assert_secret_nowhere(tmp_path, sandbox, context)

    # The request: the scope, the contract guidance, the paths.
    request = sandbox.request
    assert request["files"] == IN_SCOPE + ["security_manifest.json"] or set(IN_SCOPE) <= set(request["files"])
    assert not any(f.startswith("tests/") for f in request["files"])
    assert request["auth"] == "oauth" and request["model"] == MODEL and request["profile"] == "quick"
    assert request["out_dir"] == f"{WORK}/cloudflare-audit-out/run-1" and request["scope_dir"] == f"{WORK}/cloudflare-scope"
    assert "security_manifest.json" in request["prompt"] and "REC-POLICY-GATE" in request["prompt"]
    assert request_module.ANNOTATIONS_FILE in request["prompt"] and "Profile: quick." in request["prompt"]
    assert request["skill_files"] == pins.SKILL_FILES

    results = sarif_of(sandbox)["runs"][0]["results"]
    assert [(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
             r["locations"][0]["physicalLocation"]["region"]["startLine"]) for r in results] == [
        ("LLM03.EA.FUNCTIONALITY", "src/calc_agent/agent.py", 8),
        ("LLM03.EA.AUTONOMY", "src/calc_agent/maintenance.py", 5)]
    first = results[0]
    steps = first["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [(s["location"]["physicalLocation"]["region"]["startLine"], s.get("properties", {}).get("role"))
            for s in steps] == [(12, "source"), (10, None), (8, "sink")]
    props = first["properties"]
    assert props["controlStatus"] == "none" and props["residualRisk"] == "high"
    assert props["recommendations"] == ["REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE"]
    assert props["toolProperties"]["recommendation"] == "Parse arithmetic with ast and allow only numeric nodes."
    run_props = sarif_of(sandbox)["runs"][0]["properties"]["sastAgent"]
    assert run_props["dropped"]["notReported"]["count"] == 1 and run_props["runStatus"] == "complete"
    driver = sarif_of(sandbox)["runs"][0]["tool"]["driver"]
    assert driver["name"] == "cloudflare-security-audit-skill" and driver["properties"]["skillCommit"] == pins.SKILL_COMMIT

    reward = grade_sarif(TASK, sarif_of(sandbox))
    assert reward["reward"] > 0 and reward["controls"] == 1.0 and reward["recommendations"] == 1.0


def test_stock_mode_needs_the_cwe_side_file_to_map(tmp_path, token, grade_sarif):
    sandbox = FakeSandbox(document=driver_document([confirmed()], [annotation(**ASSESSED)]))
    _, context, go = run_agent(tmp_path, sandbox, mode="stock")
    asyncio.run(go())
    (result,) = sarif_of(sandbox)["runs"][0]["results"]
    assert result["ruleId"] == "LLM03.EA.FUNCTIONALITY" and "controlStatus" not in result["properties"]
    assert "rule_id" not in sandbox.request["prompt"] and '"cwe"' in sandbox.request["prompt"]
    assert grade_sarif(TASK, sarif_of(sandbox))["reward"] > 0
    assert context.metadata["cloudflare_audit"]["contract_source"] is None


def test_harbor_model_is_used_when_it_names_an_anthropic_model(tmp_path, token):
    agent = CloudflareAuditAgent(logs_dir=tmp_path, model_name="anthropic/claude-sonnet-5-5")
    assert agent.audit_model() == "claude-sonnet-5-5" and agent.model_source() == "harbor_model_name"


def test_an_empty_audit_writes_an_empty_sarif(tmp_path, token):
    sandbox = FakeSandbox(document=driver_document([], []))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert context.metadata["status"] == "ok" and sarif_of(sandbox)["runs"][0]["results"] == []


# ---------------------------------------------------------------- failures


@pytest.mark.parametrize("code,reason", [("review_incomplete", "review_incomplete"), ("deadline", "deadline"),
                                         ("timeout", "deadline"), ("no_findings_file", "bad_review_output"),
                                         ("bad_findings", "bad_review_output"), ("cli_limit", "cli_limit"),
                                         ("prompt_too_long", "prompt_too_long")])
def test_tool_outcomes_write_no_sarif(tmp_path, token, code, reason):
    doc = driver_document(status="error", error={"code": code, "message": f"m {OAUTH_TOKEN}"})
    sandbox = FakeSandbox(document=doc, driver_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "tool_outcome" and meta["tool_outcome"]["reason"] == reason
    assert "/app/output/findings.sarif" not in sandbox.files
    assert_secret_nowhere(tmp_path, sandbox, context)


@pytest.mark.parametrize("code", ["cli_oauth_refused", "model_remapped", "network", "cli_settings", "no_subagents",
                                  "skill_not_loaded", "cli_failed", "driver_crash"])
def test_infrastructure_failures_raise(tmp_path, token, code):
    doc = driver_document(status="error", error={"code": code, "message": "m"})
    sandbox = FakeSandbox(document=doc, driver_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError):
        asyncio.run(go())
    assert context.metadata["status"] == "error"
    assert not any(name.startswith(KEY_DIR) for name in sandbox.files)


def test_no_driver_result_is_an_error(tmp_path, token):
    sandbox = FakeSandbox(write_document=False, driver_exit=1)
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="without a readable result"):
        asyncio.run(go())
    assert not any(name.startswith(KEY_DIR) for name in sandbox.files)


def test_api_key_auth_uses_its_own_file(tmp_path, monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", OAUTH_TOKEN)
    sandbox = FakeSandbox(document=driver_document([], []))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert sandbox.key_reads == [(f"{KEY_DIR}/anthropic-key", KEY.encode())]
    assert sandbox.request["auth"] == "api_key"
    assert_secret_nowhere(tmp_path, sandbox, context, secret=KEY)


def test_scoped_mode_without_a_contract_falls_back_to_the_harness_constants(tmp_path, token):
    agent = CloudflareAuditAgent(logs_dir=tmp_path)
    built = agent.audit_request("placeholder instruction with no contract")
    assert built["contract_source"] == "harness_constants" and "LLM03.EA.AUTONOMY" in built["prompt"]
    stock = CloudflareAuditAgent(logs_dir=tmp_path, mode="stock").audit_request(CONTRACT_TEXT)
    assert stock["contract_source"] is None and "LLM02" not in stock["prompt"] and "full audit mode" in stock["prompt"]


def test_budget_and_profile_reach_the_prompt(tmp_path, token):
    prompt = CloudflareAuditAgent(logs_dir=tmp_path, profile="deep", agent_budget=40).audit_request(CONTRACT_TEXT)["prompt"]
    assert "Profile: deep." in prompt and "Budget: 40 agent invocations." in prompt
