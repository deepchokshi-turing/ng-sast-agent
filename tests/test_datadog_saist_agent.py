"""DatadogSaistAgent against a fake sandbox: options, models, the key file, the
driver command, failures, normalisation, the SARIF and the grade.

No model is called. The fake sandbox answers the driver command with a result
document in driver.py's format (its real behaviour is tested in
test_datadog_saist_driver.py) and lists files from the sample task
``smoke_eval``.
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex

import pytest
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

import sast
from sast.datadog_saist import pins, rule_map
from sast.datadog_saist.agent import DatadogSaistAgent
from sast.datadog_saist.normalise import normalise, remediation
from sast.datadog_saist.options import DatadogSaistOptions
from sast.errors import ScannerError
from tests.conftest import FIXTURES, SAMPLE_TASKS
from tests.datadog_saist_fakes import KEY, REMEDIATION, result, sarif

WORK = "/opt/sast"
KEY_DIR = f"{WORK}/secret-datadog-saist"
KEY_FILE = f"{KEY_DIR}/provider-key"
OUT = f"{WORK}/out/datadog_saist.json"
TASK = "smoke_eval"
REPO = SAMPLE_TASKS / TASK / "environment" / "repo"
IN_SCOPE = ["src/calc_agent/__init__.py", "src/calc_agent/agent.py", "src/calc_agent/llm.py",
            "src/calc_agent/maintenance.py"]
CONTRACT_TEXT = (FIXTURES / "claude_review" / "contract_instruction.md").read_text(encoding="utf-8")


def line_counts(files=IN_SCOPE):
    return {f: len((REPO / f).read_text().splitlines()) for f in files}


def driver_document(results=None, *, status="ok", error=None, echo_key=False, doc=None):
    document = {
        "driver_format": 1, "status": status, "seconds": 40.0, "tool_seconds": 35.0, "exit_code": 0,
        "network": {"provider": {"url": "https://api.openai.com/v1/models", "status": 401},
                    "rules": {"url": pins.RULES_URL, "status": 200}},
        "argv": ["/opt/sast/datadog-saist/bin/datadog-saist", "--directory", f"{WORK}/datadog-saist-scope"],
        "tool_environment": ["HOME", "OPENAI_API_KEY", "PATH"],
        "scope_copy": {"dir": f"{WORK}/datadog-saist-scope", "files": len(IN_SCOPE), "manifest": True},
        "line_counts": line_counts(), "not_text": [],
        "summary": {"files_analysed": 4, "scans_succeeded": 6, "scans_failed": 0, "scan_failures": [],
                    "input_tokens": 12000, "output_tokens": 900, "results": len(results or []), "rules": 4},
        "sarif": doc if doc is not None else sarif(results or []),
        "private_dir_removed": True,
    }
    if error:
        document["error"] = error
    if echo_key:
        document["note"] = f"the key was {KEY}"
    return document


class FakeSandbox:
    """Just enough of BaseEnvironment: a dict file system and scripted exec."""

    def __init__(self, document=None, driver_exit=0, install_ok=True, protect_exit=0):
        self.environment_dir = SAMPLE_TASKS / TASK / "environment"
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None, float | None]] = []
        self.events: list[tuple[str, str]] = []
        self.key_reads: list[tuple[str, bool]] = []
        self.document = driver_document() if document is None else document
        self.driver_exit = driver_exit
        self.install_ok = install_ok
        self.protect_exit = protect_exit
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
        if re.fullmatch(r"rm -rf (\S+) && mkdir -p \S+ && chmod 700 \S+", command) or \
                re.fullmatch(r"rm -rf (\S+)", command):
            self._remove_tree(command.split()[2])
            return ExecResult(return_code=0)
        if command.startswith("find "):
            return self._find(command)
        if "datadog_saist_install.py" in command:
            if not self.install_ok:
                return ExecResult(stdout="[install] ERROR: zip has sha256 00, expected 6e", return_code=2)
            res = {"binary": "/opt/sast/datadog-saist/bin/datadog-saist", "binary_sha256": "883d", "source": "setup"}
            return ExecResult(stdout="INSTALL_RESULT " + json.dumps(res), return_code=0)
        if "datadog_saist_driver.py" in command:
            args = shlex.split(command.split(" && exec ", 1)[1])
            keyfile = args[args.index("--keyfile") + 1]
            self.key_reads.append((keyfile, self.files.get(keyfile, b"").strip() == KEY.encode()))
            self.request = json.loads(self.files[args[args.index("--request") + 1]])
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
        self.events.append(("upload", str(target_path)))
        self.files[str(target_path)] = __import__("pathlib").Path(source_path).read_bytes()

    async def download_file(self, source_path, target_path):
        if source_path not in self.files:
            raise FileNotFoundError(source_path)
        __import__("pathlib").Path(target_path).write_bytes(self.files[source_path])


CLEAN_ENV = ("DATADOG_SAIST_MODEL", "DATADOG_SAIST_VALIDATION_MODEL", "DATADOG_SAIST_MODE", "DATADOG_SAIST_RULES",
             "DATADOG_SAIST_TIMEOUT_SEC", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY")


@pytest.fixture
def api_key(monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", KEY)


def run_agent(tmp_path, box, instruction="instruction text", model_name="anthropic/claude-x", **options):
    agent = DatadogSaistAgent(logs_dir=tmp_path, model_name=model_name, **options)
    context = AgentContext()

    async def go():
        await agent.setup(box)
        await agent.run(instruction, box, context)

    return agent, context, go


def sarif_of(sandbox):
    return json.loads(sandbox.files["/app/output/findings.sarif"])


def results_of(sandbox):
    return [(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
             r["locations"][0]["physicalLocation"]["region"]["startLine"],
             r["locations"][0]["physicalLocation"]["region"]["endLine"])
            for r in sarif_of(sandbox)["runs"][0]["results"]]


def assert_key_nowhere(tmp_path, sandbox, context):
    for command, env, _ in sandbox.commands:
        assert KEY not in command
        assert not set(pins.KEY_ENVS.values()) & set(env or {})
    assert KEY not in json.dumps(context.metadata, default=str)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert KEY not in path.read_text(errors="replace"), path
    for name, data in sandbox.files.items():
        assert KEY.encode() not in data, name
    assert not any(name.startswith(KEY_DIR) for name in sandbox.files)
    assert context.metadata["datadog_saist"]["key_file_removed"] is True


# ---------------------------------------------------------------- options and models


def test_options_defaults_and_model_names(monkeypatch, api_key):
    o = DatadogSaistOptions()
    assert o.mode == "stock" and o.rules == "api" and o.request_timeout_sec == 120 and o.model is None
    assert DatadogSaistOptions(model="gpt-5.2").model == "openai-gpt5.2"
    assert DatadogSaistOptions(model="openai/gpt-5-mini").model == "openai-gpt5-mini"
    assert DatadogSaistOptions(model="claude-4.5-sonnet").model == "claude-4.5-sonnet"
    monkeypatch.setenv("DATADOG_SAIST_MODEL", "openai-gpt5.2-codex")
    monkeypatch.setenv("DATADOG_SAIST_RULES", "embedded")
    options = DatadogSaistAgent.parse_options({"scan_roots": "src, config", "stray": "x"}, None)
    assert options.model == "openai-gpt5.2-codex" and options.rules == "embedded"
    assert options.scan_roots == ["src", "config"]
    assert DatadogSaistAgent.parse_options({"model": "gpt-5-mini"}, None).model == "openai-gpt5-mini"


@pytest.mark.parametrize("bad", [{"model": "gpt-4o"}, {"model": "gpt-5.2", "validation_model": "claude-4.5-haiku"},
                                 {"mode": "fancy"}, {"rules": "local"}, {"request_timeout_sec": 1}])
def test_bad_options_are_refused(bad):
    with pytest.raises(Exception):
        DatadogSaistOptions(**bad)


def test_model_choice_and_harbor_m(tmp_path, api_key):
    assert DatadogSaistAgent(logs_dir=tmp_path).detection_model() == pins.DEFAULT_MODEL
    agent = DatadogSaistAgent(logs_dir=tmp_path, model_name="openai/gpt-5-mini")
    assert agent.detection_model() == "openai-gpt5-mini" and agent.model_source() == "harbor_model_name"
    assert agent.validation_model() == "openai-gpt5-mini"
    other = DatadogSaistAgent(logs_dir=tmp_path, model_name="anthropic/claude-sonnet-4-5")
    assert other.detection_model() == pins.DEFAULT_MODEL and other.model_source() == "default"
    explicit = DatadogSaistAgent(logs_dir=tmp_path, model_name="openai/gpt-5-mini", model="gpt-5.2")
    assert explicit.detection_model() == "openai-gpt5.2" and explicit.model_source() == "option"
    info = explicit.to_agent_info()
    assert info.model_info.name == "gpt-5.2" and info.model_info.provider == "openai"


def test_preflight_needs_the_providers_key(monkeypatch, tmp_path):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        DatadogSaistAgent.preflight({}, {})
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    DatadogSaistAgent.preflight({}, {})
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        DatadogSaistAgent.preflight({"model": "claude-4.5-haiku"}, {})


def test_install_files_and_command_carry_no_secret(tmp_path, api_key):
    agent = DatadogSaistAgent(logs_dir=tmp_path)
    files = agent.install_files()
    assert set(files) == {"datadog_saist_install.py", "datadog_saist_driver.py", "ccsr_driver.py",
                          "datadog_saist_pins.json"}
    pinned = json.loads(files["datadog_saist_pins.json"])
    assert pinned["version"] == "0.0.32" and pinned["commit"] == pins.COMMIT
    assert pinned["assets"]["x86_64"]["sha256"] == "6e1c17d4a831f05cad50a95648a594c50c98a82226cc60456cea69aa5e463038"
    assert all(KEY.encode() not in data for data in files.values()) and KEY not in agent.install_command(WORK)


def test_install_failure_is_an_error(tmp_path, api_key):
    _, _, go = run_agent(tmp_path, FakeSandbox(install_ok=False))
    with pytest.raises(ScannerError, match="installing datadog-saist failed"):
        asyncio.run(go())


def test_missing_key_fails_before_anything_runs(tmp_path, monkeypatch):
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    sandbox = FakeSandbox()
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="OPENAI_API_KEY"):
        asyncio.run(go())
    assert not any("datadog_saist_driver.py" in c for c, _, _ in sandbox.commands)


# ---------------------------------------------------------------- the run


def test_happy_path_maps_rules_and_keeps_the_key_in_a_file(tmp_path, api_key):
    results = [
        result("datadog/python-excessiveagency", "src/calc_agent/agent.py", 8, reason="eval of model output"),
        result("datadog/python-sensitiveinfodisclosure", "src/calc_agent/llm.py", 2, 3),
        # Outside the five ruleIds: counted, not reported.
        result("datadog/python-xss", "src/calc_agent/agent.py", 13),
        # A kind the table does not know (a rule Datadog adds later): counted, not reported.
        result("datadog/python-brandnewrule", "src/calc_agent/agent.py", 12),
    ]
    sandbox = FakeSandbox(document=driver_document(results))
    agent, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok", meta.get("error")
    assert meta["model"] == "openai-gpt5.2" and meta["model_source"] == "default" and meta["mode"] == "stock"
    assert meta["auth_source"] == "OPENAI_API_KEY" and meta["harbor_model_name_used"] is False
    assert meta["agent_version"] == f"{sast.__version__}+datadog-saist-{pins.VERSION}"
    assert meta["rule_not_reported"] == {"datadog/python-xss": 1}
    assert meta["rule_not_in_map"] == {"datadog/python-brandnewrule": 1}
    assert results_of(sandbox) == [
        ("LLM03.EA.FUNCTIONALITY", "src/calc_agent/agent.py", 8, 8),
        ("LLM02.SID.MEDIUM", "src/calc_agent/llm.py", 2, 3),
    ]
    first = sarif_of(sandbox)["runs"][0]["results"][0]
    props = first["properties"]
    assert props["cwe"] == ["CWE-250"] and props["toolRuleIds"] == ["datadog/python-excessiveagency"]
    assert props["toolProperties"]["reason"] == "eval of model output"
    assert props["toolProperties"]["ruleRemediation"] == REMEDIATION
    assert first["message"]["text"] == "eval of model output"
    assert "codeFlows" not in first and not {"controlStatus", "residualRisk", "recommendations"} & set(props)
    run = sarif_of(sandbox)["runs"][0]
    assert run["tool"]["driver"]["properties"]["ruleMap"] == rule_map.VERSION
    agent_props = run["properties"]["sastAgent"]
    assert agent_props["dropped"]["ruleOutsideTaskRules"]["count"] == 1
    assert agent_props["dropped"]["ruleNotInMap"]["count"] == 1
    assert agent_props["rulesSha256"] == meta["datadog_saist"]["rules_sha256"] and meta["datadog_saist"]["rules_count"] == 4

    # Usage: tokens and a priced estimate.
    usage = meta["usage_summary"]
    assert usage["n_input_tokens"] == 12000 and usage["n_output_tokens"] == 900
    assert usage["cost_usd"] == pytest.approx((12000 * 1.75 + 900 * 14.0) / 1e6)
    assert context.n_input_tokens == 12000

    # The request: in-scope files, models, no secret.
    request = sandbox.request
    assert request["files"] == IN_SCOPE and request["detection_model"] == "openai-gpt5.2"
    assert request["key_env"] == "OPENAI_API_KEY" and request["scope_dir"] == f"{WORK}/datadog-saist-scope"
    assert KEY not in json.dumps(request)

    assert sandbox.key_reads == [(KEY_FILE, True)]
    events = sandbox.events
    upload = events.index(("upload", f"{KEY_FILE}.upload"))
    driver_i = next(i for i, (kind, c) in enumerate(events) if kind == "exec" and "datadog_saist_driver.py" in c)
    removed = events.index(("exec", f"rm -rf {KEY_DIR}"))
    assert upload < driver_i < removed
    assert_key_nowhere(tmp_path, sandbox, context)
    assert set(meta["artifacts_saved"]) == {"metadata.json", "findings.sarif", "install.log", "datadog_saist.json"}


def test_scoped_mode_runs_as_stock_and_records_the_contract(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, instruction=CONTRACT_TEXT, mode="scoped")
    asyncio.run(go())
    scan = context.metadata["datadog_saist"]
    assert context.metadata["mode"] == "scoped" and context.metadata["mode_effective"] == "stock"
    assert scan["contract_passed_to_tool"] is False and scan["contract"]["rule_ids"]
    assert scan["rule_map_targets_not_in_contract"] == []
    assert "contract" not in json.dumps(sandbox.request)


@pytest.mark.parametrize("code, words", [
    ("api_auth", "refused the key"), ("rules_unavailable", "public endpoint"), ("network", "egress"),
    ("llm_failed", "every model call"), ("quota", "quota")])
def test_driver_errors_become_scanner_errors_and_remove_the_key(tmp_path, api_key, code, words):
    sandbox = FakeSandbox(document=driver_document(status="error", error={"code": code, "message": f"m {KEY}"}),
                          driver_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=words) as info:
        asyncio.run(go())
    assert KEY not in str(info.value)
    assert context.metadata["status"] == "error"
    assert_key_nowhere(tmp_path, sandbox, context)


@pytest.mark.parametrize("code, reason", [("deadline", "deadline"), ("tool_crashed", "tool_crashed"),
                                          ("bad_output", "bad_review_output"), ("tool_saw_nothing", "tool_saw_nothing")])
def test_tool_outcomes_are_scored_not_errors(tmp_path, api_key, code, reason):
    sandbox = FakeSandbox(document=driver_document(status="error", error={"code": code, "message": "x"}),
                          driver_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert context.metadata["status"] == "tool_outcome" and context.metadata["tool_outcome"]["reason"] == reason
    assert "/app/output/findings.sarif" not in sandbox.files


def test_key_echoed_by_the_driver_is_scrubbed_everywhere(tmp_path, api_key):
    sandbox = FakeSandbox(document=driver_document(echo_key=True))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert_key_nowhere(tmp_path, sandbox, context)


def test_the_sarif_grades_on_the_sample_task(tmp_path, api_key, grade_sarif):
    sandbox = FakeSandbox(document=driver_document([result("datadog/python-excessiveagency",
                                                           "src/calc_agent/agent.py", 8)]))
    _, _, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert grade_sarif(TASK, sarif_of(sandbox))["reward"] > 0


def test_an_empty_scan_writes_an_empty_sarif(tmp_path, api_key):
    sandbox = FakeSandbox(document=driver_document([]))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert context.metadata["status"] == "ok" and sarif_of(sandbox)["runs"][0]["results"] == []


# ---------------------------------------------------------------- normalisation


def test_bad_locations_and_out_of_scope_results_are_dropped_and_counted():
    doc = sarif([
        result("datadog/python-excessiveagency", "tests/test_smoke.py", 3),          # excluded path
        result("datadog/python-excessiveagency", "src/calc_agent/agent.py", 999),     # past the end
        result("datadog/python-excessiveagency", "src/calc_agent/nothere.py", 1),    # not a counted file
        result("datadog/python-excessiveagency", "src/calc_agent/agent.py", 8, 2),   # end before start
        {"ruleId": "datadog/python-excessiveagency"},                                 # no location
        "not an object",
    ], artifacts={"src/calc_agent/agent.py": (["datadog/python-excessiveagency"], [])})
    findings, counts = normalise(doc, line_counts=line_counts(), roots=["src"], excludes=["tests"])
    assert [(f.file, f.start_line, f.end_line) for f in findings] == [("src/calc_agent/agent.py", 8, 8)]
    assert counts["dropped_out_of_scope_count"] == 1 and counts["dropped_bad_location_count"] == 4
    assert counts["end_line_replaced"] == 1


def test_the_real_sarif_of_the_fit_trial_normalises_to_nothing():
    doc = json.loads((FIXTURES / "datadog_saist" / "real_401_run.sarif").read_text(encoding="utf-8"))
    findings, counts = normalise(doc, line_counts={}, roots=["src"], excludes=[])
    assert findings == [] and counts["findings_reported"] == 0


def test_every_python_rule_of_the_real_run_is_in_the_frozen_table():
    doc = json.loads((FIXTURES / "datadog_saist" / "real_401_run.sarif").read_text(encoding="utf-8"))
    ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids) == 29
    assert all(rule_map.lookup(i)[2] for i in ids)
    # No Datadog rule describes a tool credential's scope, so PERMISSIONS is never reported.
    assert {rule_map.lookup(i)[1] for i in ids} - {None} == {
        "LLM02.SID.MEDIUM", "LLM02.SID.HIGH", "LLM03.EA.FUNCTIONALITY", "LLM03.EA.AUTONOMY"}


def test_rule_map_is_frozen():
    assert rule_map.VERSION == "datadog-map-1"
    assert rule_map.lookup("datadog/python-excessiveagency")[1] == "LLM03.EA.FUNCTIONALITY"
    assert rule_map.lookup("datadog/java-sensitiveinfodisclosure")[1] == "LLM02.SID.MEDIUM"
    assert rule_map.lookup("datadog/python-systempromptleakage")[1] == "LLM02.SID.HIGH"
    assert rule_map.lookup("datadog/python-improperoutputhandling")[1] == "LLM03.EA.AUTONOMY"
    assert rule_map.lookup("datadog/python-promptinjection")[1] is None
    assert rule_map.lookup("semgrep/x") == ("", None, False)
    for task_rule, _cwe, _why in rule_map.RULE_MAP.values():
        assert task_rule is None or task_rule in sast.cwe_map.TASK_RULES


def test_remediation_is_cut_at_the_next_heading():
    assert remediation("Desc\n\n## How to remediate:\n- a\n- b\n\n## Example\nx") == "- a\n- b"
    assert remediation("no section") is None


def test_agent_imports_only_stdlib_and_harbor():
    import subprocess
    import sys
    from importlib import metadata

    from tests.conftest import ROOT
    from tests.test_imports import _closure

    code = ("import json, sys; import sast.datadog_saist.agent; "
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
