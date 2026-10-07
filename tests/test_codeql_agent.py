"""CodeQLAgent.setup/run against a fake sandbox: commands, scope, logs, metadata, errors.

The scan output the fake sandbox hands back is recorded CodeQL 2.27.1 SARIF
(see tests/test_codeql_normalise.py for which task produced each file).
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

from sast.codeql import pins
from sast.codeql.agent import (CodeQLAgent, codeql_config, extraction_report, extractor_paths, failure_reason,
                               lines_of_code, ram_mb)
from sast.errors import ScannerError
from tests.conftest import FIXTURES, SAMPLE_TASKS

SARIF_4DA5AB = FIXTURES / "codeql_2.27.1_task_4da5ab_positive.json"
SARIF_7F3A91 = FIXTURES / "codeql_2.27.1_task_7f3a91.json"
#: Real CodeQL output on two small crafted repositories (see tests/fixtures/README.md).
SARIF_UNPARSEABLE = FIXTURES / "codeql_2.27.1_crafted_unparseable_files.json"
SARIF_NO_PYTHON = FIXTURES / "codeql_2.27.1_crafted_no_python.json"
CREATE_FAILURE = FIXTURES / "codeql_2.27.1_create_failure_file_in_paths.txt"


class FakeSandbox:
    """Just enough of BaseEnvironment: a dict file system and scripted exec."""

    def __init__(self, environment_dir: Path, sarif: bytes | None, create_exit: int = 0, analyze_exit: int = 0,
                 install_exit: int = 0, kinds: dict[str, str] | None = None,
                 python_files: tuple[str, ...] = ("src/support_copilot/agent.py", "tests/test_smoke.py"),
                 tar: str = "ok"):
        self.environment_dir = environment_dir
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None]] = []
        self.sarif = sarif
        self.create_exit = create_exit
        self.analyze_exit = analyze_exit
        self.install_exit = install_exit
        self.python_files = python_files
        self.tar = tar
        self.kinds = kinds if kinds is not None else {"src": "DIR", "config": "DIR", "fixtures": "DIR",
                               "security_manifest.json": "FILE", "pyproject.toml": "FILE"}

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        self.commands.append((command, env))
        if "codeql_install.py" in command:
            if self.install_exit:
                return ExecResult(stdout="[install] ERROR: CodeQL is not installed at /opt/sast/codeql/codeql",
                                  return_code=self.install_exit)
            return ExecResult(stdout='[install] ok\nINSTALL_RESULT {"codeql_version": "2.27.1"}', return_code=0)
        if "database create" in command:
            return ExecResult(stdout="", stderr="A fatal error occurred: boom" if self.create_exit else "",
                              return_code=self.create_exit)
        if "database analyze" in command:
            if self.sarif is not None:
                self.files["/opt/sast/out/codeql.sarif"] = self.sarif
            return ExecResult(stdout="", stderr="", return_code=self.analyze_exit)
        if command.startswith("mkdir -p /opt/sast"):
            return ExecResult(stdout="writable\n", return_code=0)
        if command.startswith("if [ -d"):
            lines = []
            for part in command.split("; if ")[0:]:
                path = part.split("echo DIR ", 1)[1].split(";", 1)[0].strip().strip("'")
                kind = self.kinds.get(path)
                lines.append(f"{kind} {path}" if kind else f"MISSING {path}")
            return ExecResult(stdout="\n".join(lines), return_code=0)
        if command.startswith("nproc"):
            return ExecResult(stdout="2\n", return_code=0)
        if command.startswith("find "):
            prefix = "./" if command.startswith("find . ") else ""
            return ExecResult(stdout="".join(f"{prefix}{f}\n" for f in self.python_files), return_code=0)
        if "codeql-logs.tar.gz" in command and "tar -czf" in command:
            if self.tar == "raise":
                raise RuntimeError("sandbox connection lost")
            return ExecResult(stdout="", return_code=0 if self.tar == "ok" else 2)
        return ExecResult(stdout="", return_code=0)

    async def upload_file(self, source_path, target_path):
        self.files[str(target_path)] = Path(source_path).read_bytes()

    async def download_file(self, source_path, target_path):
        if source_path not in self.files:
            raise FileNotFoundError(source_path)
        Path(target_path).write_bytes(self.files[source_path])


def run_agent(tmp_path, sandbox, **options):
    agent = CodeQLAgent(logs_dir=tmp_path / "logs", model_name="openai/gpt-5", **options)
    context = AgentContext()

    async def go():
        await agent.setup(sandbox)
        await agent.run("instruction text", sandbox, context)

    return agent, context, go


def sample_env(task="task_7f3a91"):
    return SAMPLE_TASKS / task / "environment"


def task_with(tmp_path, toml: str) -> Path:
    """A task folder whose task.toml is ``toml``: only the scan settings are read."""
    (tmp_path / "task" / "environment").mkdir(parents=True)
    (tmp_path / "task" / "task.toml").write_text(toml)
    return tmp_path / "task" / "environment"


def test_happy_path_commands_logs_and_metadata(tmp_path):
    sandbox = FakeSandbox(sample_env(), SARIF_7F3A91.read_bytes())
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())

    create = (tmp_path / "logs" / "command-1" / "stdout.txt").read_text()
    analyze = (tmp_path / "logs" / "command-2" / "stdout.txt").read_text()
    assert ("/opt/sast/codeql/codeql database create /opt/sast/codeql-db --language=python --build-mode=none "
            "--source-root=/app/repo --codescanning-config=/opt/sast/codeql-config.json --threads=1 --ram=1536") in create
    assert (f"/opt/sast/codeql/codeql database analyze /opt/sast/codeql-db /opt/sast/codeql/{pins.SUITE_PATH} "
            "--format=sarif-latest --output=/opt/sast/out/codeql.sarif --threads=1 --ram=1536") in analyze
    assert "python-security-extended.qls" in analyze

    # The scope file: folders only (CodeQL's extractor crashes on a file in paths).
    config = json.loads(sandbox.files["/opt/sast/codeql-config.json"])
    assert config == {"name": "sast-agents task scope", "paths": ["src", "config", "fixtures"],
                      "paths-ignore": ["tests", "**/tests"]}

    meta = context.metadata
    assert meta["status"] == "ok"
    assert meta["agent"] == "codeql-sast"
    assert meta["agent_version"] == "0.4.0+codeql-2.27.1"
    assert meta["tool"] == "codeql" and meta["tool_version"] == "2.27.1"
    assert meta["scan"]["threads"] == 1 and meta["scan"]["ram_mb"] == 1536
    assert meta["scan"]["file_roots"] == ["pyproject.toml", "security_manifest.json"]
    assert meta["results_raw"] == 0 and meta["codeql_rules_run"] == 50
    assert meta["results_emitted"] == 0

    sarif = json.loads(sandbox.files["/app/output/findings.sarif"])
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "codeql"
    assert sarif["runs"][0]["results"] == []

    assert meta["lines_of_code"] == 166 and meta["python_files_in_scope"] == 1
    assert meta["codeql_extraction"]["error_count"] == 0 and meta["codeql_extraction"]["warning_count"] == 0
    assert meta["codeql_logs_packed"] is True
    assert set(meta["artifacts_saved"]) == {"metadata.json", "findings.sarif", "install.log", "codeql.sarif",
                                            "codeql-logs.tar.gz", "codeql-config.json"}
    commands = [c for c, _ in sandbox.commands]
    assert any("cp /opt/sast/out/codeql.sarif /logs/artifacts/sast/codeql.sarif" in c for c in commands)
    assert any("cp /opt/sast/codeql-config.json /logs/artifacts/sast/codeql-config.json" in c for c in commands)
    tar = [c for c in commands if "tar -czf" in c]
    assert len(tar) == 1 and "cd /opt/sast/codeql-db" in tar[0] and "for d in log diagnostic" in tar[0]
    scan_env = [env for c, env in sandbox.commands if "database create" in c][0]
    assert scan_env["HOME"] == "/opt/sast/home"


def test_findings_from_the_recorded_output_reach_the_metadata(tmp_path):
    sandbox = FakeSandbox(sample_env(), SARIF_4DA5AB.read_bytes())
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["findings_security"] == 1
    # py/insecure-protocol is CWE-327, which the shared table does not map.
    assert meta["unmapped_by_cwe"] == {"CWE-327": 1}
    assert meta["findings_compact"] == [
        ["py/insecure-protocol", ["CWE-327"], "src/pydantic_ai_mini/_compat/httpx2.py", 146, 146, None]]


def test_results_outside_the_task_scope_are_dropped(tmp_path):
    env_dir = task_with(tmp_path, '[metadata]\nscanner_roots = ["src"]\n'
                                  'excluded_paths = ["src/pydantic_ai_mini/_compat"]\n')
    sandbox = FakeSandbox(env_dir, SARIF_4DA5AB.read_bytes())
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["results_raw"] == 1 and meta["findings_out_of_scope"] == 1 and meta["findings_security"] == 0
    config = json.loads(sandbox.files["/opt/sast/codeql-config.json"])
    assert config["paths-ignore"] == ["src/pydantic_ai_mini/_compat"]


@pytest.mark.parametrize("memory, cpus, threads, ram", [(8192, 4, 4, 7680), (1024, 2, 2, 1024), (1400, 1, 1, 1024)])
def test_threads_and_ram_come_from_the_sandbox_config(tmp_path, memory, cpus, threads, ram):
    class Config:
        pass

    Config.cpus, Config.memory_mb = cpus, memory
    sandbox = FakeSandbox(sample_env(), SARIF_7F3A91.read_bytes())
    sandbox.task_env_config = Config()
    _, _, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    for log in ("command-1", "command-2"):
        text = (tmp_path / "logs" / log / "stdout.txt").read_text()
        assert f"--threads={threads} --ram={ram}" in text


def test_no_task_toml_scans_the_whole_repo_with_nproc_threads(tmp_path):
    (tmp_path / "bare" / "environment").mkdir(parents=True)
    sandbox = FakeSandbox(tmp_path / "bare" / "environment", SARIF_7F3A91.read_bytes())
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert json.loads(sandbox.files["/opt/sast/codeql-config.json"]) == {"name": "sast-agents task scope"}
    create = (tmp_path / "logs" / "command-1" / "stdout.txt").read_text()
    assert "--threads=2" in create and "--ram" not in create
    assert context.metadata["scan"]["ram_mb"] is None


def test_install_failure_is_an_error_not_a_zero(tmp_path):
    sandbox = FakeSandbox(sample_env(), None, install_exit=2)
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="installing codeql failed .*not installed at /opt/sast/codeql/codeql"):
        asyncio.run(go())
    assert "/app/output/findings.sarif" not in sandbox.files


@pytest.mark.parametrize("sarif, create_exit, analyze_exit, message", [
    (None, 0, 0, "could not read"),
    (b"{not json", 0, 0, "unreadable"),
    (b'{"runs": []}', 0, 0, "no runs"),
    (b'{"runs": [{"tool": {}}]}', 0, 0, "no results list"),
    (b'{"runs": [{"results": [], "invocations": [{"executionSuccessful": false}]}]}', 0, 0, "did not complete"),
    (None, 32, 0, "database create exited 32: A fatal error occurred: boom"),
    (SARIF_NO_PYTHON.read_bytes(), 0, 0, "extracted no Python code"),
    (SARIF_7F3A91.read_bytes(), 0, 2, "database analyze exited 2"),
    (SARIF_7F3A91.read_bytes(), 0, 124, "ran out of time"),
    (SARIF_7F3A91.read_bytes(), 137, 0, "was killed"),
])
def test_untrustworthy_scans_are_errors(tmp_path, sarif, create_exit, analyze_exit, message):
    sandbox = FakeSandbox(sample_env(), sarif, create_exit=create_exit, analyze_exit=analyze_exit)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=message):
        asyncio.run(go())
    assert context.metadata["status"] == "error"
    assert "/app/output/findings.sarif" not in sandbox.files
    assert "/logs/artifacts/sast/metadata.json" in sandbox.files
    # The config, CodeQL's own output and its logs are kept after a failure too.
    commands = [c for c, _ in sandbox.commands]
    assert any("cp /opt/sast/codeql-config.json /logs/artifacts/sast/codeql-config.json" in c for c in commands)
    assert any("cp /opt/sast/out/codeql.sarif /logs/artifacts/sast/codeql.sarif" in c for c in commands)
    assert any("tar -czf" in c for c in commands)
    assert context.metadata["codeql_logs_packed"] is True


def test_a_failed_create_never_runs_analyze(tmp_path):
    sandbox = FakeSandbox(sample_env(), SARIF_7F3A91.read_bytes(), create_exit=1)
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError):
        asyncio.run(go())
    assert not any("database analyze" in c for c, _ in sandbox.commands)


def test_missing_roots_are_noted_and_all_missing_is_an_error(tmp_path):
    sandbox = FakeSandbox(sample_env(), SARIF_7F3A91.read_bytes(), kinds={"src": "DIR"})
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert context.metadata["scan_roots_missing"] == ["config", "fixtures", "security_manifest.json",
                                                      "pyproject.toml"]
    assert json.loads(sandbox.files["/opt/sast/codeql-config.json"])["paths"] == ["src"]

    sandbox = FakeSandbox(sample_env(), SARIF_7F3A91.read_bytes(), kinds={})
    _, _, go = run_agent(tmp_path / "second", sandbox)
    with pytest.raises(ScannerError, match="none of the scan roots exist"):
        asyncio.run(go())


def test_no_python_in_scope_is_an_error_before_codeql_runs(tmp_path):
    # Only the excluded tests/ folder has Python: nothing in scope.
    sandbox = FakeSandbox(sample_env(), SARIF_7F3A91.read_bytes(), python_files=("tests/test_smoke.py",))
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="no Python source in the scan scope"):
        asyncio.run(go())
    assert not any("database create" in c for c, _ in sandbox.commands)
    assert context.metadata["python_files_in_scope"] == 0


def test_a_whole_repo_scan_lists_python_from_the_root(tmp_path):
    (tmp_path / "bare" / "environment").mkdir(parents=True)
    sandbox = FakeSandbox(tmp_path / "bare" / "environment", SARIF_7F3A91.read_bytes(),
                          python_files=("app.py", "pkg/__pycache__/x.pyc.py"))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    find = [c for c, _ in sandbox.commands if c.startswith("find ")]
    assert find == ["find . -type f \\( -name '*.py' -o -name '*.pyi' \\) 2>/dev/null | head -n 20000"]
    assert context.metadata["python_files_in_scope"] == 1  # bytecode folders are never in scope


def test_zero_lines_of_code_is_an_error(tmp_path):
    """Real output: CodeQL on a repo whose scope holds no Python exits 0 with lines-of-code 0."""
    assert lines_of_code(json.loads(SARIF_NO_PYTHON.read_bytes())) == 0
    sandbox = FakeSandbox(sample_env(), SARIF_NO_PYTHON.read_bytes())
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="lines of code 0"):
        asyncio.run(go())
    assert context.metadata["lines_of_code"] == 0


def test_a_missing_lines_of_code_metric_is_an_error(tmp_path):
    document = json.loads(SARIF_7F3A91.read_bytes())
    document["runs"][0]["properties"]["metricResults"] = []
    sandbox = FakeSandbox(sample_env(), json.dumps(document).encode())
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="no py/summary/lines-of-code metric"):
        asyncio.run(go())
    assert context.metadata["lines_of_code"] is None


def test_unparseable_files_are_recorded_not_fatal(tmp_path):
    """Real output: a file with a syntax error and a file that is not UTF-8. CodeQL
    2.27.1 reports both at warning level (no "level" key) and analyses the rest."""
    env_dir = task_with(tmp_path, '[metadata]\nscanner_roots = ["src"]\nexcluded_paths = ["tests"]\n')
    sandbox = FakeSandbox(env_dir, SARIF_UNPARSEABLE.read_bytes(), kinds={"src": "DIR"},
                          python_files=("src/pkg/ok.py",))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok" and meta["lines_of_code"] == 10
    report = meta["codeql_extraction"]
    assert report["error_count"] == 0 and report["warning_count"] == 5
    assert report["files_not_extracted"] == ["src/pkg/bad_enc.py", "src/pkg/bad_syntax.py"]
    assert {w["id"] for w in report["warnings"]} == {"py/diagnostics/syntax-error",
                                                      "py/diagnostics/extraction-warnings"}
    # The one result, py/code-injection in ok.py, still comes through.
    assert meta["findings_security"] == 1


def _as_error_level(document: dict, file: str) -> dict:
    for note in document["runs"][0]["invocations"][0]["toolExecutionNotifications"]:
        if (note.get("descriptor") or {}).get("id") == "py/diagnostics/extraction-warnings" and \
                file in json.dumps(note.get("locations")):
            note["level"] = "error"
    return document


def test_an_error_level_extraction_failure_in_scope_is_an_error(tmp_path):
    env_dir = task_with(tmp_path, '[metadata]\nscanner_roots = ["src"]\n')
    document = _as_error_level(json.loads(SARIF_UNPARSEABLE.read_bytes()), "src/pkg/bad_syntax.py")
    sandbox = FakeSandbox(env_dir, json.dumps(document).encode(), kinds={"src": "DIR"},
                          python_files=("src/pkg/ok.py",))
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="error-level extraction problem.*src/pkg/bad_syntax.py"):
        asyncio.run(go())
    assert context.metadata["codeql_extraction"]["error_count"] == 1


def test_an_error_level_notification_outside_the_scope_is_only_recorded(tmp_path):
    env_dir = task_with(tmp_path, '[metadata]\nscanner_roots = ["src"]\nexcluded_paths = ["src/pkg/bad_syntax.py"]\n')
    document = _as_error_level(json.loads(SARIF_UNPARSEABLE.read_bytes()), "src/pkg/bad_syntax.py")
    sandbox = FakeSandbox(env_dir, json.dumps(document).encode(), kinds={"src": "DIR"},
                          python_files=("src/pkg/ok.py",))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    report = context.metadata["codeql_extraction"]
    assert report["error_count"] == 1 and report["errors"][0]["in_scope"] is False
    assert report["errors_in_scope"] == []


@pytest.mark.parametrize("tar", ["fail", "raise"])
def test_packing_the_logs_never_fails_a_good_scan(tmp_path, tar):
    sandbox = FakeSandbox(sample_env(), SARIF_7F3A91.read_bytes(), tar=tar)
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok" and "/app/output/findings.sarif" in sandbox.files
    assert meta["codeql_logs_packed"] is False if tar == "fail" else "sandbox connection lost" in meta["codeql_logs_packed"]


def test_run_without_setup_is_an_error(tmp_path):
    agent = CodeQLAgent(logs_dir=tmp_path)
    with pytest.raises(ScannerError, match="setup"):
        asyncio.run(agent.run("x", FakeSandbox(sample_env(), None), AgentContext()))


def test_the_ignored_model_is_not_credited_and_stray_options_are_accepted(tmp_path):
    agent = CodeQLAgent(logs_dir=tmp_path, model_name="openai/gpt-5-mini", reasoning_effort="high", foo="bar")
    info = agent.to_agent_info()
    assert info.model_info is None and info.name == "codeql-sast"


def test_install_files_carry_the_pins(tmp_path):
    files = CodeQLAgent(logs_dir=tmp_path).install_files()
    assert set(files) == {"codeql_install.py", "codeql_pins.json"}
    assert json.loads(files["codeql_pins.json"]) == pins.as_dict()


# ---- pure helpers --------------------------------------------------------------

@pytest.mark.parametrize("memory, expected", [(2048, 1536), (1536, 1024), (1000, 1024), (None, None), (0, None)])
def test_ram_budget(memory, expected):
    assert ram_mb(memory) == expected


def test_extractor_paths_keep_folders_and_python_file_parents():
    files = {"pyproject.toml", "security_manifest.json", "tools/run.py", "main.py"}
    assert extractor_paths(["src", "pyproject.toml", "security_manifest.json"], files) == ["src"]
    assert extractor_paths(["src", "tools/run.py"], files) == ["src", "tools"]
    assert extractor_paths(["src", "main.py"], files) is None  # a top-level file: the whole repository
    assert extractor_paths(["."], set()) is None


def test_config_keeps_one_meaning_of_a_plain_exclude():
    assert codeql_config(["."], ["tests", "src/vendor"]) == {
        "name": "sast-agents task scope", "paths-ignore": ["tests", "**/tests", "src/vendor"]}


# ---- failure reasons from real CodeQL output ----------------------------------------

def test_failure_reason_uses_real_error_lines():
    # Real output of database create with a file in `paths` (CodeQL 2.27.1).
    reason = failure_reason(CREATE_FAILURE.read_text())
    assert reason.startswith("A fatal error occurred: Exit status 1 from command:")
    assert reason.endswith("NotADirectoryError: [Errno 20] Not a directory: 'p.toml'")


@pytest.mark.parametrize("output, expected", [
    ("Picked up JAVA_TOOL_OPTIONS: -Dx=error\nInitializing database.\n"
     "A fatal error occurred: Invalid source root: /app/nothere.\n", "A fatal error occurred: Invalid source root: /app/nothere."),
    ("Compiling queries: 0 errors\nRunning 50 queries\n[ERROR] out of disk space\nShutting down 0 errors\n",
     "[ERROR] out of disk space"),
    ("[2026-10-08 01:10:47] [ERROR] Spawned process exited abnormally (code 1)\n",
     "[ERROR] Spawned process exited abnormally (code 1)"),
])
def test_failure_reason_examples(output, expected):
    assert failure_reason(output) == expected


def test_failure_reason_ignores_lines_that_only_mention_errors():
    output = "Picked up JAVA_TOOL_OPTIONS: -Dhttp.error=1\nFinished with 0 errors and 0 warnings\nexit"
    assert failure_reason(output) == "Finished with 0 errors and 0 warnings\nexit"


def test_extraction_report_on_a_clean_dataset_task():
    report = extraction_report(json.loads(SARIF_4DA5AB.read_bytes()), ["src"], ["tests"])
    assert report == {"error_count": 0, "warning_count": 0, "errors": [], "warnings": [],
                      "errors_in_scope": [], "files_not_extracted": []}


# ---- the real bundle ---------------------------------------------------------------

def test_real_bundle_layout_matches_the_pins(codeql_bundle):
    """The pinned suite path exists in the real 2.27.1 bundle."""
    assert (codeql_bundle / pins.SUITE_PATH).is_file()


def test_a_fresh_real_run_matches_the_recorded_fixture(tmp_path, codeql_bundle):
    """The agent's own commands with the real CLI on smoke_web_eval give the recorded results."""
    import subprocess

    from sast.codeql.agent import analyze_command, create_command
    from sast.codeql.normalise import normalise

    repo = tmp_path / "repo"
    shutil.copytree(SAMPLE_TASKS / "smoke_web_eval" / "environment" / "repo", repo)
    config = tmp_path / "codeql-config.json"
    config.write_text(json.dumps(codeql_config(["src"], ["tests"])))
    cli = str(codeql_bundle / "codeql")
    db, out = str(tmp_path / "db"), str(tmp_path / "codeql.sarif")
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    subprocess.run(create_command(db, str(config), 1, 1536, source_root=str(repo), codeql=cli),
                   check=True, capture_output=True, timeout=600, env=env)
    subprocess.run(analyze_command(db, out, 1, 1536, suite=str(codeql_bundle / pins.SUITE_PATH), codeql=cli),
                   check=True, capture_output=True, timeout=600, env=env)
    fresh = json.loads(Path(out).read_text())
    recorded = json.loads((FIXTURES / "codeql_2.27.1_smoke_web_eval.json").read_text())
    key = lambda doc: [(f.tool_rule_id, f.file, f.start_line, f.trace) for f in normalise(doc)[0]]  # noqa: E731
    assert key(fresh) == key(recorded)
    assert lines_of_code(fresh) == lines_of_code(recorded) == 14
