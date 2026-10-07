"""SemgrepAgent.setup/run against a fake sandbox: orchestration, logs, metadata, errors."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

from sast.errors import ScannerError
from sast.semgrep.agent import SemgrepAgent
from tests.conftest import DEV_TASKS, FIXTURES


class FakeSandbox:
    """Just enough of BaseEnvironment: a dict file system and scripted exec."""

    def __init__(self, task: str, semgrep_output: bytes | None, scan_exit: int = 0, install_exit: int = 0):
        self.environment_dir = DEV_TASKS / task / "environment"
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None]] = []
        self.semgrep_output = semgrep_output
        self.scan_exit = scan_exit
        self.install_exit = install_exit

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        self.commands.append((command, env))
        if "install.py" in command:
            if self.install_exit:
                return ExecResult(stdout="[install] ERROR: no network", return_code=self.install_exit)
            return ExecResult(stdout='[install] ok\nINSTALL_RESULT {"semgrep_version": "1.179.0"}', return_code=0)
        if "semgrep scan" in command or "/venv/bin/semgrep" in command:
            if self.semgrep_output is not None:
                self.files["/opt/sast/out/semgrep.json"] = self.semgrep_output
            return ExecResult(stdout="", stderr="", return_code=self.scan_exit)
        if command.startswith("mkdir -p /opt/sast"):
            return ExecResult(stdout="writable\n", return_code=0)
        if command.startswith("test -f"):
            return ExecResult(stdout="default\n", return_code=0)
        if command.startswith("if [ -e"):
            lines = [f"OK {p}" for p in ("src", "config", "fixtures", "security_manifest.json", "pyproject.toml",
                                         "package.json")]
            return ExecResult(stdout="\n".join(lines), return_code=0)
        if command.startswith("nproc"):
            return ExecResult(stdout="2\n", return_code=0)
        return ExecResult(stdout="", return_code=0)

    async def upload_file(self, source_path, target_path):
        self.files[str(target_path)] = Path(source_path).read_bytes()

    async def download_file(self, source_path, target_path):
        if source_path not in self.files:
            raise FileNotFoundError(source_path)
        Path(target_path).write_bytes(self.files[source_path])


def run_agent(tmp_path, sandbox, **options):
    agent = SemgrepAgent(logs_dir=tmp_path, model_name="openai/gpt-5", **options)
    context = AgentContext()

    async def go():
        await agent.setup(sandbox)
        await agent.run("instruction text", sandbox, context)

    return agent, context, go


def test_happy_path_writes_sarif_logs_and_metadata(tmp_path):
    sandbox = FakeSandbox("smoke_eval", (FIXTURES / "semgrep_1.179.0_smoke_eval.json").read_bytes())
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())

    sarif = json.loads(sandbox.files["/app/output/findings.sarif"])
    assert [r["ruleId"] for r in sarif["runs"][0]["results"]] == ["LLM03.EA.FUNCTIONALITY"] * 2
    assert (tmp_path / "findings.sarif").exists()
    assert "INSTALL_RESULT" in (tmp_path / "setup" / "stdout.txt").read_text()
    scan_log = (tmp_path / "command-1" / "stdout.txt").read_text()
    assert "--exclude tests" in scan_log and "--include /src" in scan_log and "--jobs 1" in scan_log
    assert "--max-memory 1536" in scan_log
    assert "--no-rewrite-rule-ids" in scan_log and "/opt/sast/rules-merged/generic_secrets.yaml" in scan_log

    meta = context.metadata
    assert meta["status"] == "ok"
    assert meta["model_ignored"] == "openai/gpt-5"
    assert meta["cwe_map"] == "cwe-map-2"
    assert meta["scan_budget_sec"] == 780
    assert meta["results_emitted"] == 2  # the eval() and the merged shell=True pair
    assert meta["findings_compact"][0][-1] == "LLM03.EA.FUNCTIONALITY"
    assert meta["findings_out_of_scope"] == 0
    assert meta["semgrepignore"] == "default"

    scan_env = [env for cmd, env in sandbox.commands if "/venv/bin/semgrep" in cmd][0]
    assert scan_env["HOME"] == "/opt/sast/home"
    assert scan_env["PATH"].startswith("/opt/sast/venv/bin:")

    # Raw output, SARIF, metadata and install log are kept as trial artifacts.
    assert set(meta["artifacts_saved"]) == {"metadata.json", "findings.sarif", "install.log", "semgrep.json"}
    assert "/logs/artifacts/sast/findings.sarif" in sandbox.files
    assert any("cp /opt/sast/out/semgrep.json /logs/artifacts/sast/semgrep.json" in c for c, _ in sandbox.commands)


def test_install_failure_is_an_error_not_a_zero(tmp_path):
    sandbox = FakeSandbox("smoke_eval", None, install_exit=2)
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="installing semgrep failed"):
        asyncio.run(go())
    assert "/app/output/findings.sarif" not in sandbox.files


@pytest.mark.parametrize("output, exit_code, message", [
    (None, 0, "could not read"),
    (b"{not json", 0, "unreadable"),
    (b'{"errors": []}', 0, "no results list"),
    (b'{"results": []}', 124, "ran out of time"),
    (b'{"results": []}', 137, "was killed"),
    # Semgrep writes "results": [] even when it fails: never a clean scan.
    (b'{"results": [], "errors": [{"type": "SemgrepError", "message": "invalid configuration"}]}', 7,
     "exited 7: invalid configuration"),
    (b'{"results": [], "errors": []}', 2, "exited 2: no error details"),
    (None, 2, "exited 2: no readable output"),
])
def test_untrustworthy_scans_are_errors(tmp_path, output, exit_code, message):
    sandbox = FakeSandbox("smoke_eval", output, scan_exit=exit_code)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=message):
        asyncio.run(go())
    assert context.metadata["status"] == "error"
    assert "/app/output/findings.sarif" not in sandbox.files
    # The diagnosis is still kept.
    assert "/logs/artifacts/sast/metadata.json" in sandbox.files


def test_resources_come_from_the_sandbox_config(tmp_path):
    class Config:
        cpus, memory_mb = 4, 8192

    sandbox = FakeSandbox("smoke_eval", (FIXTURES / "semgrep_1.179.0_smoke_eval.json").read_bytes())
    sandbox.task_env_config = Config()
    _, _, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    scan_log = (tmp_path / "command-1" / "stdout.txt").read_text()
    # 4 jobs; --max-memory is per job: (8192 - 512) // 4
    assert "--jobs 4" in scan_log and "--max-memory 1920" in scan_log


def test_install_error_line_leads_the_message(tmp_path):
    sandbox = FakeSandbox("smoke_eval", None, install_exit=2)
    _, _, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=r"failed \(exit 2\): \[install\] ERROR: no network"):
        asyncio.run(go())


def test_the_ignored_model_is_not_credited(tmp_path):
    info = SemgrepAgent(logs_dir=tmp_path, model_name="openai/gpt-5-mini").to_agent_info()
    assert info.model_info is None and info.name == "semgrep-sast"


def test_options_override_the_task(tmp_path):
    sandbox = FakeSandbox("smoke_eval", (FIXTURES / "semgrep_1.179.0_smoke_eval.json").read_bytes())
    _, _, go = run_agent(tmp_path, sandbox, exclude="vendor", jobs=3)
    asyncio.run(go())
    scan_log = (tmp_path / "command-1" / "stdout.txt").read_text()
    assert "--exclude vendor" in scan_log and "--exclude tests" not in scan_log and "--jobs 3" in scan_log


def test_run_without_setup_is_an_error(tmp_path):
    sandbox = FakeSandbox("smoke_eval", None)
    agent = SemgrepAgent(logs_dir=tmp_path)
    with pytest.raises(ScannerError, match="setup"):
        asyncio.run(agent.run("x", sandbox, AgentContext()))


def test_install_script_is_shipped_with_the_pins(tmp_path):
    files = SemgrepAgent(logs_dir=tmp_path).install_files()
    assert set(files) == {"install.py", "merge_rules.py", "pins.json"}
    pins = json.loads(files["pins.json"])
    assert pins["semgrep_version"] == "1.179.0" and pins["rules_file_count"] == 898


# ---- scan scope: Semgrep anchors include/exclude patterns to the scan target ----

from sast.semgrep.agent import in_scope, scope_args  # noqa: E402


def test_scope_is_anchored_at_the_repository_root():
    assert scope_args(["src", "config/agent.json"], ["tests", "src/calc_agent/thirdparty"]) == [
        "--include", "/src", "--include", "/config/agent.json",
        "--exclude", "tests", "--exclude", "/src/calc_agent/thirdparty",
        "--exclude", "__pycache__", "--exclude", "*.pyc", "--exclude", "*.pyo",
    ]
    assert scope_args(["."], []) == ["--exclude", "__pycache__", "--exclude", "*.pyc", "--exclude", "*.pyo"]


def test_in_scope():
    roots, excludes = ["src", "pyproject.toml"], ["tests", "src/calc_agent/thirdparty"]
    assert in_scope("src/calc_agent/agent.py", roots, excludes)
    assert in_scope("pyproject.toml", roots, excludes)
    assert not in_scope("src/calc_agent/thirdparty/legacy.py", roots, excludes)
    assert not in_scope("src/pkg/tests/test_x.py", roots, excludes)
    assert not in_scope("srcfoo/a.py", roots, excludes)
    assert not in_scope("lib/a.py", roots, excludes)
    assert in_scope("lib/a.py", ["."], [])
    assert not in_scope("src/calc_agent/__pycache__/agent.cpython-311.pyc", roots, excludes)
    assert not in_scope("src/old.pyc", ["."], [])
