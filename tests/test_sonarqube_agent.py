"""SonarQubeAgent against a fake sandbox: configuration, token handling, arguments, failures.

No SonarQube server is involved. The fake sandbox answers fetch.py and
sonar-scanner with fixed exit codes and an empty result, or with a response
recorded from a real SonarQube 26.9 run (tests/fixtures/sonarqube_26.9_*.json,
see test_sonarqube_normalise.py).
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

import sast
from sast.errors import ScannerError
from sast.sonarqube import pins
from sast.sonarqube.agent import SonarQubeAgent, exclusion_globs, scanner_properties
from tests.conftest import FIXTURES, ROOT, SAMPLE_TASKS

TOKEN = "squ_0123456789abcdef0123456789abcdef01234567"
HOST = "http://host.docker.internal:9000"
TOKEN_DIR = "/opt/sast/secret"
TOKEN_FILE = f"{TOKEN_DIR}/sonar-token"


def empty_document(project_key: str, deleted: bool = True, error: str | None = None, status: str = "SUCCESS"):
    """What fetch.py writes for a project with no results (the shape only, no findings)."""
    return {
        "fetch_format": 1,
        "server": {"host_url": HOST},
        "project_key": project_key,
        "ce_task": {"id": "task-1", "status": status, "errorMessage": None if status == "SUCCESS" else "boom"},
        "issues_pages": [{"issues": [], "paging": {"pageIndex": 1, "pageSize": 500, "total": 0}}],
        "hotspots_pages": [{"hotspots": [], "paging": {"pageIndex": 1, "pageSize": 500, "total": 0}}],
        "rules": {},
        "quality_profiles": {"profiles": [{"name": "Sonar way", "key": "py-profile", "language": "py",
                                           "isDefault": True}]},
        "deleted": deleted,
        "delete_error": None,
        "kept": False,
        "error": error,
    }


class FakeSandbox:
    """Just enough of BaseEnvironment: a dict file system and scripted exec."""

    def __init__(self, task="smoke_eval", check_exit=0, scanner_exit=0, scanner_stdout="INFO: EXECUTION SUCCESS",
                 collect_exit=0, collect_status="SUCCESS", recorded=None):
        self.environment_dir = SAMPLE_TASKS / task / "environment"
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None, float | None]] = []
        #: ("exec", command) and ("upload", path) in order.
        self.events: list[tuple[str, str]] = []
        #: (step, the path it reads the token from, whether that file then held the token).
        self.token_reads: list[tuple[str, str | None, bool]] = []
        self.recorded = recorded
        self.check_exit = check_exit
        self.scanner_exit = scanner_exit
        self.scanner_stdout = scanner_stdout
        self.collect_exit = collect_exit
        self.collect_status = collect_status

    def _holds_token(self, path):
        return self.files.get(path, b"").strip() == TOKEN.encode()

    def _remove_tree(self, path):
        for name in [n for n in self.files if n == path or n.startswith(path + "/")]:
            del self.files[name]

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        self.commands.append((command, env, timeout_sec))
        self.events.append(("exec", command))
        if "fetch.py" in command:
            path = (env or {}).get("SONAR_TOKEN_FILE")
            self.token_reads.append((command.split("fetch.py ")[1].split()[0], path, self._holds_token(path)))
        scanner_token = re.search(r'SONAR_TOKEN="\$\(cat (\S+)\)" exec ', command)
        if scanner_token:
            path = scanner_token.group(1)
            self.token_reads.append(("sonar-scanner", path, self._holds_token(path)))
        if command.startswith("umask 077 && cat "):
            source, target = re.search(r"cat (\S+) > (\S+)", command).groups()
            self.files[target] = self.files.pop(source)
            return ExecResult(return_code=0)
        if re.fullmatch(r"rm -rf (\S+)", command) or re.fullmatch(r"rm -rf (\S+) && mkdir -p \S+ && chmod 700 \S+",
                                                                   command):
            self._remove_tree(command.split()[2])
            return ExecResult(return_code=0)
        if "install.py" in command:
            result = {"scanner_home": pins.INSTALL_DIR, "scanner_version": pins.SONAR_SCANNER_VERSION,
                      "python": "/opt/sast/venv/bin/python"}
            return ExecResult(stdout="INSTALL_RESULT " + json.dumps(result), return_code=0)
        if "fetch.py check" in command:
            if self.check_exit:
                return ExecResult(stdout="[fetch] ERROR: GET api/authentication/validate failed: the server did "
                                         "not accept SONAR_TOKEN", return_code=self.check_exit)
            check = {"status": "UP", "server_version": "26.9.test", "edition": "community",
                     "default_python_profile": {"name": "Sonar way", "key": "py-profile"}}
            return ExecResult(stdout="CHECK_RESULT " + json.dumps(check), return_code=0)
        if "/bin/sonar-scanner" in command:
            return ExecResult(stdout=self.scanner_stdout, stderr="", return_code=self.scanner_exit)
        if "fetch.py collect" in command:
            args = shlex.split(command)
            key, out = args[args.index("--project") + 1], args[args.index("--out") + 1]
            failed = self.collect_status != "SUCCESS"
            document = empty_document(key, status=self.collect_status, error="boom" if failed else None)
            if self.recorded is not None:
                document = json.loads((FIXTURES / f"sonarqube_26.9_{self.recorded}.json").read_text())
            self.files[out] = json.dumps(document).encode()
            if self.collect_exit:
                return ExecResult(stdout=f"[fetch] ERROR: the background task task-1 ended {self.collect_status}: "
                                         "boom", return_code=self.collect_exit)
            return ExecResult(stdout='COLLECT_RESULT {"issues": 0}', return_code=0)
        if "fetch.py delete" in command:
            return ExecResult(stdout='DELETE_RESULT {"deleted": true}', return_code=0)
        if command.startswith("mkdir -p /opt/sast"):
            return ExecResult(stdout="writable\n", return_code=0)
        if command.startswith("if [ -e"):
            return ExecResult(stdout="OK src\n", return_code=0)
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


@pytest.fixture
def server_env(monkeypatch):
    monkeypatch.setenv("SONAR_HOST_URL", HOST)
    monkeypatch.setenv("SONAR_TOKEN", TOKEN)


def run_agent(tmp_path, sandbox, **options):
    agent = SonarQubeAgent(logs_dir=tmp_path, model_name="openai/gpt-5", **options)
    context = AgentContext()

    async def go():
        await agent.setup(sandbox)
        await agent.run("instruction text", sandbox, context)

    return agent, context, go


def assert_token_nowhere(tmp_path, sandbox, context):
    """Not in any exec command or exec env, log, metadata or artifact, and the token file is gone."""
    for command, env, _ in sandbox.commands:
        assert TOKEN not in command
        assert "SONAR_TOKEN" not in (env or {})
        assert all(TOKEN not in value for value in (env or {}).values())
    assert TOKEN not in json.dumps(context.metadata, default=str)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert TOKEN not in path.read_text(errors="replace"), path
    # Every file left in the sandbox, artifacts and output included.
    for name, data in sandbox.files.items():
        assert TOKEN.encode() not in data, name
    assert not any(name.startswith(TOKEN_DIR) for name in sandbox.files)
    assert context.metadata["sonarqube"]["token_file_removed"] is True


# ---------------------------------------------------------------- happy path


def test_happy_path_token_only_in_a_file(tmp_path, server_env):
    sandbox = FakeSandbox()
    agent, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())

    meta = context.metadata
    assert meta["status"] == "ok"
    assert meta["agent_version"] == f"{sast.__version__}+sonarqube-{pins.SONAR_SCANNER_VERSION}"
    sonar = meta["sonarqube"]
    assert re.fullmatch(r"sast-[0-9a-f]{12}", sonar["project_key"])
    assert sonar["server_version"] == "26.9.test" and sonar["edition"] == "community"
    assert sonar["quality_profile"] == [{"name": "Sonar way", "key": "py-profile", "language": "py",
                                         "isDefault": True}]
    assert sonar["deleted"] is True and sonar["host_url"] == HOST
    assert sonar["findings_by_sonar_type"] == {"VULNERABILITY": 0, "SECURITY_HOTSPOT": 0}
    assert meta["results_by_sonar_type"] == {"VULNERABILITY": 0, "SECURITY_HOTSPOT": 0}

    # The token travels only in a file, which every step that needs it reads.
    for needle in ("fetch.py check", "/bin/sonar-scanner", "fetch.py collect"):
        (command, env, _), = sandbox.commands_with(needle)
        assert env["SONAR_TOKEN_FILE"] == TOKEN_FILE and env["SONAR_HOST_URL"] == HOST
        assert command.startswith("/opt/sast/venv/bin/python") or needle == "/bin/sonar-scanner"
    assert sandbox.token_reads == [("check", TOKEN_FILE, True), ("sonar-scanner", TOKEN_FILE, True),
                                   ("collect", TOKEN_FILE, True)]
    (scanner, _, _), = sandbox.commands_with("/bin/sonar-scanner")
    assert f'SONAR_TOKEN="$(cat {TOKEN_FILE})" exec /opt/sast/sonar-scanner/bin/sonar-scanner -D' in scanner

    # The directory is private before the upload, the file is private after it, and it is removed last.
    events = sandbox.events
    prepare = events.index(("exec", f"rm -rf {TOKEN_DIR} && mkdir -p {TOKEN_DIR} && chmod 700 {TOKEN_DIR}"))
    upload = events.index(("upload", f"{TOKEN_FILE}.upload"))
    protect = next(i for i, (kind, c) in enumerate(events) if kind == "exec" and "chmod 600" in c)
    removed = events.index(("exec", f"rm -rf {TOKEN_DIR}"))
    assert prepare < upload < protect < removed
    assert "umask 077" in events[protect][1] and f"rm -f {TOKEN_FILE}.upload" in events[protect][1]
    assert removed > max(i for i, (_, c) in enumerate(events) if "fetch.py collect" in c)
    assert meta["sonarqube"]["token_file"] == TOKEN_FILE
    assert_token_nowhere(tmp_path, sandbox, context)

    sarif = json.loads(sandbox.files["/app/output/findings.sarif"])
    assert sarif["runs"][0]["results"] == [] and sarif["runs"][0]["tool"]["driver"]["name"] == "sonarqube"
    assert set(meta["artifacts_saved"]) == {"metadata.json", "findings.sarif", "install.log", "sonarqube.json",
                                            "sonar-scanner.log"}


def test_scanner_arguments(tmp_path, server_env):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    (command, _, _), = sandbox.commands_with("/bin/sonar-scanner")
    args = shlex.split(command.split(" && ")[-1])
    assert args[:2] == [f"SONAR_TOKEN=$(cat {TOKEN_FILE})", "exec"]
    args = args[2:]
    assert args[0] == "/opt/sast/sonar-scanner/bin/sonar-scanner"
    props = dict(a[2:].split("=", 1) for a in args[1:])
    key = context.metadata["sonarqube"]["project_key"]
    assert props == {
        "sonar.projectKey": key,
        "sonar.projectName": key,
        "sonar.projectBaseDir": "/app/repo",
        "sonar.sources": "src",
        "sonar.exclusions": "**/tests,**/tests/**,src/calc_agent/thirdparty,src/calc_agent/thirdparty/**,"
                            "**/__pycache__/**,**/*.pyc,**/*.pyo",
        "sonar.python.version": "3",
        "sonar.sourceEncoding": "UTF-8",
        "sonar.scm.disabled": "true",
        "sonar.working.directory": "/opt/sast/out/sonar/scannerwork",
        "sonar.scanner.metadataFilePath": "/opt/sast/out/sonar/report-task.txt",
        "sonar.qualitygate.wait": "false",
    }
    assert "sonar.host.url" not in command and "sonar.token" not in command and "sonar.login" not in command
    (collect, _, _), = sandbox.commands_with("fetch.py collect")
    assert "--report /opt/sast/out/sonar/report-task.txt" in collect and f"--project {key}" in collect
    assert "--keep" not in collect


def test_project_keys_are_unique(tmp_path, server_env):
    keys = set()
    for i in range(3):
        sandbox = FakeSandbox()
        _, context, go = run_agent(tmp_path / str(i), sandbox)
        asyncio.run(go())
        keys.add(context.metadata["sonarqube"]["project_key"])
    assert len(keys) == 3


def test_keep_project_option(tmp_path, server_env):
    sandbox = FakeSandbox()
    _, _, go = run_agent(tmp_path, sandbox, keep_project=True)
    asyncio.run(go())
    (collect, _, _), = sandbox.commands_with("fetch.py collect")
    assert collect.endswith(" --keep")


def test_budget_covers_scanner_and_collect(tmp_path, server_env):
    sandbox = FakeSandbox()
    _, _, go = run_agent(tmp_path, sandbox, scan_budget_sec=600)
    asyncio.run(go())
    (_, _, scanner_timeout), = sandbox.commands_with("/bin/sonar-scanner")
    (collect, _, collect_timeout), = sandbox.commands_with("fetch.py collect")
    deadline = int(re.search(r"--deadline (\d+)", collect).group(1))
    assert scanner_timeout <= 600 - 120
    assert collect_timeout <= 600 and deadline <= collect_timeout - 60


def test_too_small_a_budget_fails_before_the_scanner(tmp_path, server_env):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, scan_budget_sec=100)
    with pytest.raises(ScannerError, match="budget"):
        asyncio.run(go())
    assert not sandbox.commands_with("/bin/sonar-scanner")


# ---------------------------------------------------------------- token handling


def test_token_echoed_by_a_tool_is_scrubbed(tmp_path, server_env):
    sandbox = FakeSandbox(scanner_stdout=f"INFO: token {TOKEN} in a debug line\nINFO: EXECUTION SUCCESS")
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert_token_nowhere(tmp_path, sandbox, context)
    log = sandbox.files["/logs/artifacts/sast/sonar-scanner.log"].decode()
    assert "INFO: token *** in a debug line" in log
    assert "token *** in a debug line" in (tmp_path / "command-2" / "stdout.txt").read_text()


def test_token_in_a_failure_message_is_scrubbed(tmp_path, server_env):
    sandbox = FakeSandbox(scanner_exit=1, scanner_stdout=f"ERROR: Not authorized with {TOKEN}")
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError) as info:
        asyncio.run(go())
    assert TOKEN not in str(info.value) and "Not authorized with ***" in str(info.value)
    assert_token_nowhere(tmp_path, sandbox, context)


# ---------------------------------------------------------------- configuration


@pytest.mark.parametrize("unset, message", [
    (("SONAR_HOST_URL",), "SONAR_HOST_URL not set"),
    (("SONAR_TOKEN",), "SONAR_TOKEN not set"),
    (("SONAR_HOST_URL", "SONAR_TOKEN"), "SONAR_HOST_URL and SONAR_TOKEN not set"),
])
def test_missing_configuration_fails_before_anything_runs(tmp_path, monkeypatch, unset, message):
    monkeypatch.setenv("SONAR_HOST_URL", HOST)
    monkeypatch.setenv("SONAR_TOKEN", TOKEN)
    for name in unset:
        monkeypatch.delenv(name)
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=message):
        asyncio.run(go())
    assert context.metadata["status"] == "error"
    assert not sandbox.commands_with("fetch.py") and not sandbox.commands_with("sonar-scanner -D")
    assert "/app/output/findings.sarif" not in sandbox.files


def test_empty_values_count_as_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("SONAR_HOST_URL", "  ")
    monkeypatch.setenv("SONAR_TOKEN", TOKEN)
    _, _, go = run_agent(tmp_path, FakeSandbox())
    with pytest.raises(ScannerError, match="SONAR_HOST_URL not set"):
        asyncio.run(go())


def test_host_url_needs_a_scheme(tmp_path, monkeypatch):
    monkeypatch.setenv("SONAR_HOST_URL", "host.docker.internal:9000")
    monkeypatch.setenv("SONAR_TOKEN", TOKEN)
    _, _, go = run_agent(tmp_path, FakeSandbox())
    with pytest.raises(ScannerError, match="must start with http"):
        asyncio.run(go())


def test_run_without_setup_is_an_error(tmp_path, server_env):
    agent = SonarQubeAgent(logs_dir=tmp_path)
    with pytest.raises(ScannerError, match="setup"):
        asyncio.run(agent.run("x", FakeSandbox(), AgentContext()))


# ---------------------------------------------------------------- failures are errors


def test_server_check_failure_is_an_error(tmp_path, server_env):
    sandbox = FakeSandbox(check_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="server check failed.*did not accept SONAR_TOKEN"):
        asyncio.run(go())
    assert not sandbox.commands_with("/bin/sonar-scanner")
    assert "/logs/artifacts/sast/metadata.json" in sandbox.files


def test_scanner_failure_is_an_error_and_cleans_up(tmp_path, server_env):
    sandbox = FakeSandbox(scanner_exit=2, scanner_stdout="ERROR: You're not authorized to analyze this project")
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="sonar-scanner exited 2: ERROR: You're not authorized"):
        asyncio.run(go())
    key = context.metadata["sonarqube"]["project_key"]
    (delete, env, _), = sandbox.commands_with("fetch.py delete")
    assert f"--project {key}" in delete and env["SONAR_TOKEN_FILE"] == TOKEN_FILE
    assert ("delete", TOKEN_FILE, True) in sandbox.token_reads
    assert_token_nowhere(tmp_path, sandbox, context)
    assert not sandbox.commands_with("fetch.py collect")
    assert "/app/output/findings.sarif" not in sandbox.files
    assert "/logs/artifacts/sast/sonar-scanner.log" in sandbox.files


@pytest.mark.parametrize("status, exit_code", [("FAILED", 4), ("CANCELED", 4), ("PENDING", 5)])
def test_background_task_not_success_is_an_error(tmp_path, server_env, status, exit_code):
    sandbox = FakeSandbox(collect_exit=exit_code, collect_status=status)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=f"collecting the SonarQube results failed \\(exit {exit_code}\\).*{status}"):
        asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "error"
    assert meta["sonarqube"]["ce_task"]["status"] == status and meta["sonarqube"]["deleted"] is True
    assert "/app/output/findings.sarif" not in sandbox.files
    # The raw responses are kept for diagnosis.
    assert "/logs/artifacts/sast/sonarqube.json" in sandbox.files


def test_scanner_timeout_is_an_error_and_cleans_up(tmp_path, server_env):
    sandbox = FakeSandbox(scanner_exit=124, scanner_stdout="INFO: still indexing")
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="ran out of time"):
        asyncio.run(go())
    assert sandbox.commands_with("fetch.py delete")
    # The delete after a timeout is recorded in the metadata, not in a throwaway dict.
    assert context.metadata["sonarqube"]["deleted"] is True
    assert_token_nowhere(tmp_path, sandbox, context)


def test_token_file_removed_after_a_failed_check(tmp_path, server_env):
    sandbox = FakeSandbox(check_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError):
        asyncio.run(go())
    assert_token_nowhere(tmp_path, sandbox, context)


def test_recorded_response_through_the_agent(tmp_path, server_env):
    """A real 26.9 response (old fetch format, no CWE): one vulnerability, counted, nothing reported."""
    sandbox = FakeSandbox(recorded="task_dc4b7a_positive")
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok"
    assert meta["results_by_sonar_type"] == {"VULNERABILITY": 1, "SECURITY_HOTSPOT": 0}
    assert meta["sonarqube"]["findings_by_sonar_type"] == {"VULNERABILITY": 1, "SECURITY_HOTSPOT": 0}
    assert meta["results_by_cwe_decision"] == {"none": 1, "unmapped": 0, "mapped": 0, "ambiguous": 0}
    assert meta["rules_without_cwe"] == ["python:S5332"] and meta["flows_raw"] == 0
    assert meta["results_emitted"] == 0 and meta["findings_unmapped"] == 1
    assert json.loads(sandbox.files["/app/output/findings.sarif"])["runs"][0]["results"] == []
    assert_token_nowhere(tmp_path, sandbox, context)


# ---------------------------------------------------------------- pure parts


def test_exclusion_globs_follow_the_semgrep_agent_meaning():
    assert exclusion_globs(["tests", "src/vendor/", "docs/readme.md"]) == [
        "**/tests", "**/tests/**", "src/vendor", "src/vendor/**", "docs/readme.md", "docs/readme.md/**",
        "**/__pycache__/**", "**/*.pyc", "**/*.pyo",
    ]
    assert exclusion_globs([]) == ["**/__pycache__/**", "**/*.pyc", "**/*.pyo"]
    with pytest.raises(ScannerError, match="comma"):
        exclusion_globs(["a,b"])


def test_scanner_properties_refuse_commas_in_roots():
    with pytest.raises(ScannerError, match="comma"):
        scanner_properties(project_key="sast-0", roots=["a,b"], excludes=[], sonar_dir="/w")


def test_install_files_and_command_carry_no_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("SONAR_TOKEN", TOKEN)
    agent = SonarQubeAgent(logs_dir=tmp_path)
    files = agent.install_files()
    assert set(files) == {"install.py", "fetch.py", "pins.json"}
    assert all(TOKEN.encode() not in data for data in files.values())
    assert json.loads(files["pins.json"])["install_dir"] == "/opt/sast/sonar-scanner"
    assert TOKEN not in agent.install_command("/opt/sast")


def test_agent_imports_only_stdlib_and_harbor():
    from importlib import metadata

    from tests.test_imports import _closure

    code = ("import json, sys; import sast.sonarqube.agent; "
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
