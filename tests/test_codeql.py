"""CodeQLAgent: normalising real CodeQL 2.27.1 SARIF, scope, grading, lifecycle and errors."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

import pytest
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

from sast import sarif
from sast.codeql import pins
from sast.codeql.agent import CodeQLAgent, codescanning_config, languages_present
from sast.codeql.normalise import cwes_of, normalise
from sast.errors import ScannerError
from tests.conftest import FIXTURES, SAMPLE_TASKS

#: Recorded with `codeql database analyze` (bundle 2.27.1, python-security-extended)
#: on tests/fixtures/tasks/smoke_web_eval/environment/repo.
WEB_EVAL = FIXTURES / "codeql_2.27.1_smoke_web_eval.sarif"
#: The same, on tests/fixtures/tasks/smoke_eval (model output -> eval): no result.
MODEL_EVAL = FIXTURES / "codeql_2.27.1_smoke_eval.sarif"


def load(path: Path) -> dict:
    return json.loads(path.read_text())


# ---- normalise ----------------------------------------------------------------

def test_code_injection_from_real_codeql_output():
    findings, counts = normalise(load(WEB_EVAL))
    assert len(findings) == 1
    f = findings[0]
    assert f.tool_rule_id == "py/code-injection"
    assert f.cwes[0] == "CWE-94"  # the query's own first CWE tag
    assert (f.file, f.start_line) == ("src/calc_service/server.py", 8)
    # The tool's own path: from the HTTP request (do_GET, line 12) to the eval (line 8).
    assert len(f.flow) >= 2
    assert f.flow[0][1] == 12 and f.flow[-1][1] == 8
    assert counts["findings_with_tool_flow"] == 1 and counts["results_raw"] == 1


def test_model_output_is_not_a_codeql_source():
    findings, counts = normalise(load(MODEL_EVAL))
    assert findings == [] and counts["results_raw"] == 0


@pytest.mark.parametrize("task, raw, rule, cwe", [
    # The v3 dataset tasks, recorded under each task's own limits (see tests/fixtures/README.md).
    ("sample_task_7f3a91", 0, None, None),
    ("task_bd9abf_positive", 0, None, None),
    ("task_bd9abf_negative", 0, None, None),
    ("task_dc4b7a_positive", 1, "py/incomplete-url-substring-sanitization", "CWE-20"),
    ("task_dc4b7a_negative", 1, "py/incomplete-url-substring-sanitization", "CWE-20"),
    ("task_4da5ab_positive", 1, "py/insecure-protocol", "CWE-327"),
])
def test_real_dataset_tasks(task, raw, rule, cwe):
    findings, counts = normalise(load(FIXTURES / f"codeql_2.27.1_{task}.sarif"))
    assert counts["results_raw"] == raw
    assert [f.tool_rule_id for f in findings] == ([rule] if rule else [])
    if cwe:
        assert findings[0].cwes[0] == cwe
    # CWE-20 and CWE-327 are outside the five OWASP rule ids: nothing is reported.
    doc, stats = sarif.build(findings, tool_name="codeql", tool_version=pins.CODEQL_VERSION)
    assert doc["runs"][0]["results"] == []
    assert stats["findings_unmapped"] == raw


def test_dataset_twins_get_identical_codeql_results():
    # dc4b7a's only result sits in code the fix did not touch, the same in both twins.
    pos, _ = normalise(load(FIXTURES / "codeql_2.27.1_task_dc4b7a_positive.sarif"))
    neg, _ = normalise(load(FIXTURES / "codeql_2.27.1_task_dc4b7a_negative.sarif"))
    assert [(f.tool_rule_id, f.file, f.start_line) for f in pos] == [(f.tool_rule_id, f.file, f.start_line) for f in neg]


def test_cwe_tags_are_read_in_order():
    rule = {"properties": {"tags": ["security", "external/cwe/cwe-094", "external/cwe/cwe-095", "x/cwe-1"]}}
    assert cwes_of(rule) == ("CWE-94", "CWE-95")


def test_non_security_queries_and_missing_runs():
    doc = copy.deepcopy(load(WEB_EVAL))
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        rule.setdefault("properties", {})["tags"] = ["maintainability"]
    findings, counts = normalise(doc)
    assert findings == [] and counts["results_non_security"] == 1
    with pytest.raises(ValueError):
        normalise({"version": "2.1.0"})


# ---- SARIF and the grader --------------------------------------------------------

def test_sarif_carries_the_tools_own_path():
    findings, _ = normalise(load(WEB_EVAL))
    doc, stats = sarif.build(findings, tool_name="codeql", tool_version=pins.CODEQL_VERSION)
    (result,) = doc["runs"][0]["results"]
    steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert steps[0]["properties"] == {"role": "source"} and steps[-1]["properties"] == {"role": "sink"}
    assert all("properties" not in s for s in steps[1:-1])  # the tool does not name the middle steps
    assert stats["results_with_tool_flow"] == 1
    # Judgment fields stay unscored, as for Semgrep.
    assert "controlStatus" not in result["properties"] and "heuristics" in result["properties"]


def test_grader_gives_path_credit_only_for_a_real_path(grade_sarif):
    findings, _ = normalise(load(WEB_EVAL))
    doc, _ = sarif.build(findings, tool_name="codeql", tool_version=pins.CODEQL_VERSION)
    score = grade_sarif("smoke_web_eval", doc)
    assert (score["tp"], score["fp"], score["fn"]) == (1, 0, 0)
    assert score["path"] == 1.0
    assert score["reward"] == 0.7  # detection 0.35 + classification 0.05 + path 0.30; no controls or recommendations

    # The same result without its path: no path credit.
    for r in doc["runs"][0]["results"]:
        r.pop("codeFlows")
    assert grade_sarif("smoke_web_eval", doc)["reward"] == 0.4


# ---- scope -----------------------------------------------------------------------

def test_codescanning_config_anchors_paths_at_the_repo_root():
    config = codescanning_config(["src", "lib/core"], ["tests", "src/x/thirdparty"])
    assert config["paths"] == ["src", "lib/core"]
    assert config["paths-ignore"] == ["**/tests", "src/x/thirdparty", "**/__pycache__", "**/*.pyc", "**/*.pyo"]
    assert "paths" not in codescanning_config(["."], [])


def test_codescanning_config_never_lists_a_file_in_paths():
    # CodeQL's Python extractor fails on a file in `paths` (NotADirectoryError),
    # and the real tasks list security_manifest.json and pyproject.toml as roots.
    roots = ["src", "config", "fixtures", "security_manifest.json", "pyproject.toml"]
    config = codescanning_config(roots, ["tests"], {"src", "config", "fixtures"})
    assert config["paths"] == ["src", "config", "fixtures"]
    # A root that is itself source code: extract everything, filter findings afterwards.
    assert "paths" not in codescanning_config(["src", "app.py"], [], {"src"})


def test_languages_present_respects_the_scope():
    files = ["src/a.py", "tests/test_a.py", "src/__pycache__/a.pyc", "web/app.ts", "src/ui/w.tsx"]
    assert languages_present(files, ["src"], ["tests"]) == {"python": 1, "javascript-typescript": 1}
    assert languages_present(files, ["web"], []) == {"javascript-typescript": 1}
    assert languages_present(["README.md"], ["."], []) == {}


# ---- lifecycle -------------------------------------------------------------------

class FakeSandbox:
    """Just enough of BaseEnvironment for the CodeQL agent: a dict file system and scripted exec."""

    def __init__(self, task: str, sarif_path: Path | None = WEB_EVAL, files=("src/calc_service/server.py",),
                 create_exit: int = 0, analyze_exit: int = 0, install_exit: int = 0):
        self.environment_dir = SAMPLE_TASKS / task / "environment"
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None]] = []
        self.sarif = sarif_path.read_bytes() if sarif_path else None
        self.listed = files
        self.create_exit, self.analyze_exit, self.install_exit = create_exit, analyze_exit, install_exit

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        self.commands.append((command, env))
        if "codeql_install.py" in command:
            if self.install_exit:
                return ExecResult(stdout="[codeql-install] ERROR: sha256 mismatch", return_code=self.install_exit)
            return ExecResult(stdout='INSTALL_RESULT {"codeql_version": "2.27.1"}', return_code=0)
        if command.startswith("mkdir -p /opt/sast"):
            return ExecResult(stdout="writable\n", return_code=0)
        if command.startswith("if [ -e"):
            return ExecResult(stdout="OK src\n", return_code=0)
        if command.startswith("if [ -d"):
            return ExecResult(stdout="DIR src\n", return_code=0)
        if command.startswith("find "):
            return ExecResult(stdout="\n".join(self.listed), return_code=0)
        if command.startswith("nproc"):
            return ExecResult(stdout="1\n", return_code=0)
        if " database create " in command:
            return ExecResult(stdout="", stderr="A fatal error occurred" if self.create_exit else "",
                              return_code=self.create_exit)
        if " database analyze " in command:
            if self.sarif is not None and not self.analyze_exit:
                out = command.split("--output ")[1].split(" ")[0]
                self.files[out] = self.sarif
            return ExecResult(stdout="", stderr="Query evaluation ran out of memory" if self.analyze_exit else "",
                              return_code=self.analyze_exit)
        return ExecResult(stdout="", return_code=0)

    async def upload_file(self, source_path, target_path):
        self.files[str(target_path)] = Path(source_path).read_bytes()

    async def download_file(self, source_path, target_path):
        if source_path not in self.files:
            raise FileNotFoundError(source_path)
        Path(target_path).write_bytes(self.files[source_path])


def run_agent(tmp_path, sandbox, **options):
    agent = CodeQLAgent(logs_dir=tmp_path, model_name="openai/gpt-5", **options)
    context = AgentContext()

    async def go():
        await agent.setup(sandbox)
        await agent.run("instruction text", sandbox, context)

    return agent, context, go


def test_happy_path(tmp_path):
    sandbox = FakeSandbox("smoke_web_eval")
    agent, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())

    out = json.loads(sandbox.files["/app/output/findings.sarif"])
    (result,) = out["runs"][0]["results"]
    assert result["ruleId"] == "LLM03.EA.FUNCTIONALITY" and "codeFlows" in result

    create = next(c for c, _ in sandbox.commands if " database create " in c)
    assert "--build-mode=none" in create and "--language=python" in create and "--db-cluster" in create
    assert "--codescanning-config /opt/sast/out/codeql-config.yml" in create
    assert "--threads 1" in create and "--ram 1536" in create
    analyze = next(c for c, _ in sandbox.commands if " database analyze " in c)
    assert pins.SUITES["python"] in analyze and "--format=sarif-latest" in analyze
    config = json.loads(sandbox.files["/opt/sast/out/codeql-config.yml"])
    assert config == {"paths-ignore": ["**/tests", "**/__pycache__", "**/*.pyc", "**/*.pyo"], "paths": ["src"]}

    meta = context.metadata
    assert meta["status"] == "ok" and meta["tool"] == "codeql" and meta["languages"] == {"python": 1}
    assert meta["per_language"]["python"]["lines_of_code"] > 0
    assert meta["results_with_tool_flow"] == 1
    assert {"codeql-python.sarif", "codeql-logs.tar.gz", "findings.sarif", "metadata.json"} <= set(meta["artifacts_saved"])
    assert meta["codeql_logs_packed"] is True
    assert any("tar czf codeql-logs.tar.gz" in c for c, _ in sandbox.commands)
    assert (tmp_path / "command-1" / "stdout.txt").exists() and (tmp_path / "command-2" / "stdout.txt").exists()
    assert agent.to_agent_info().model_info is None


def test_javascript_uses_codeqls_database_folder_name(tmp_path):
    # --language=javascript-typescript creates the database folder "javascript"
    # (seen in a real Harbor run, where pointing analyze at the language name failed).
    sandbox = FakeSandbox("smoke_web_eval", files=("src/agent.js",))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    analyze = next(c for c, _ in sandbox.commands if " database analyze " in c)
    assert "/opt/sast/out/codeql-db/javascript " in analyze
    assert pins.SUITES["javascript-typescript"] in analyze
    assert context.metadata["languages"] == {"javascript-typescript": 1}


def test_every_language_has_a_database_folder():
    assert set(pins.DATABASE_DIRS) == set(pins.SUITES) == set(pins.LANGUAGE_EXTENSIONS)


@pytest.mark.parametrize("kwargs, message", [
    ({"files": ("README.md",)}, "no Python or JavaScript"),
    ({"create_exit": 32}, "creating the CodeQL database failed"),
    ({"analyze_exit": 2}, "python analysis failed"),
    ({"analyze_exit": 137}, "was killed"),
    ({"sarif_path": None}, "could not read"),
])
def test_untrustworthy_scans_are_errors(tmp_path, kwargs, message):
    sandbox = FakeSandbox("smoke_web_eval", **kwargs)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=message):
        asyncio.run(go())
    assert context.metadata["status"] == "error"
    assert "/app/output/findings.sarif" not in sandbox.files


def test_no_extracted_code_is_an_error(tmp_path):
    doc = load(WEB_EVAL)
    for metric in doc["runs"][0]["properties"]["metricResults"]:
        if str(metric.get("ruleId", "")).endswith("/summary/lines-of-code"):
            metric["value"] = 0
    path = tmp_path / "empty.sarif"
    path.write_text(json.dumps(doc))
    _, _, go = run_agent(tmp_path / "logs", FakeSandbox("smoke_web_eval", sarif_path=path))
    with pytest.raises(ScannerError, match="extracted no python code"):
        asyncio.run(go())


def test_install_failure_is_an_error(tmp_path):
    _, _, go = run_agent(tmp_path, FakeSandbox("smoke_web_eval", install_exit=2))
    with pytest.raises(ScannerError, match="installing codeql failed .*sha256 mismatch"):
        asyncio.run(go())


def test_install_files_have_their_own_names(tmp_path):
    files = CodeQLAgent(logs_dir=tmp_path).install_files()
    assert set(files) == {"codeql_install.py", "codeql-pins.json"}  # never overwrite the Semgrep installer
    pinned = json.loads(files["codeql-pins.json"])
    assert pinned["codeql_version"] == "2.27.1" and set(pinned["bundles"]) == {"x86_64", "aarch64"}
    assert pinned["query_packs"] == {"codeql/python-queries": "1.8.11", "codeql/javascript-queries": "2.4.6"}


def test_logs_are_packed_even_when_a_step_fails(tmp_path):
    sandbox = FakeSandbox("smoke_web_eval", analyze_exit=2)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError):
        asyncio.run(go())
    assert any("tar czf codeql-logs.tar.gz" in c for c, _ in sandbox.commands)
    assert "codeql-logs.tar.gz" in context.metadata["artifacts_saved"]


# ---- the installer's checks, against a fake codeql CLI --------------------------

def _fake_bundle(tmp_path: Path, version: str = "2.27.1", packs: dict | None = None):
    import importlib.util
    spec = importlib.util.spec_from_file_location("codeql_install", Path(__file__).resolve().parents[1]
                                                  / "sast" / "codeql" / "install.py")
    install = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(install)
    home = tmp_path / "codeql"
    for pack, pv in (packs if packs is not None else pins.QUERY_PACKS).items():
        (home / "qlpacks" / pack / pv).mkdir(parents=True)
    cli = home / "codeql"
    # Like the real CLI: JSON on stdout, progress on stderr.
    cli.write_text("#!/bin/sh\necho 'Recording pack reference' >&2\n"
                   f"case \"$1\" in version) echo '{{\"version\": \"{version}\"}}';; "
                   "resolve) echo '[\"/q/a.ql\", \"/q/b.ql\"]';; esac\n")
    cli.chmod(0o755)
    install.CODEQL_HOME, install.CLI = str(home), str(cli)
    return install


def test_installer_reports_version_packs_and_suites(tmp_path):
    install = _fake_bundle(tmp_path)
    info = install.describe(pins.as_dict())
    assert info["codeql_version"] == "2.27.1"
    assert info["query_packs"] == pins.QUERY_PACKS
    assert info["suite_query_counts"] == {"javascript-typescript": 2, "python": 2}


@pytest.mark.parametrize("version, packs", [
    ("2.27.2", None),                                   # a different CLI
    ("2.27.1", {"codeql/python-queries": "1.9.0", "codeql/javascript-queries": "2.4.6"}),  # a different pack
])
def test_installer_refuses_a_different_bundle(tmp_path, version, packs):
    install = _fake_bundle(tmp_path, version, packs)
    with pytest.raises(SystemExit):
        install.describe(pins.as_dict())
