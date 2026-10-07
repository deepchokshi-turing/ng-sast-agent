"""SonarQubeAgent against a fake sandbox: configuration, token handling, arguments, time limits, failures.

No SonarQube server is involved. The fake sandbox answers ``fetch.py
collect`` with a document recorded from a real SonarQube 26.9 run
(tests/fixtures/sonarqube_26.9-f2_<task>.json, fetch_format 2, see
test_sonarqube_normalise.py) and ``fetch.py check`` with that run's server
version and default Python profile. Two parts are not recorded, because the
recordings predate the calls, and are written here in the documented API
shape: the ``api/measures/component`` answer (``measures_response``) and the
edition in the check result ("community", which the 26.9 Community Build
reports). Tests of error paths that no recording can show (a FAILED
background task, a failed upload, a timeout, an analysis of nothing) say so in
their docstrings.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
import shlex
import subprocess
import sys
import types
from pathlib import Path

import pytest
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

import sast
import sast.sonarqube.agent as agent_module
from sast.errors import ScannerError
from sast.sonarqube import pins
from sast.sonarqube.agent import (
    CLEANUP_SLICE_SEC,
    KILL_AFTER_SEC,
    SonarQubeAgent,
    analysis_check,
    exclusion_globs,
    language_distribution,
    parse_failures,
    scanner_properties,
)
from tests.conftest import FIXTURES, ROOT, SAMPLE_TASKS

TOKEN = "squ_0123456789abcdef0123456789abcdef01234567"
HOST = "http://host.docker.internal:9000"
TOKEN_DIR = "/opt/sast/secret"
TOKEN_FILE = f"{TOKEN_DIR}/sonar-token"


def recorded_f2(task: str) -> dict:
    return json.loads((FIXTURES / f"sonarqube_26.9-f2_{task}.json").read_text())


def measures_response(project_key: str, files: int = 34, ncloc: int = 1500, distribution: str = "py=1500") -> dict:
    """api/measures/component in its documented shape. Not recorded: the recordings predate this call."""
    measures = [{"metric": "files", "value": str(files)}, {"metric": "ncloc", "value": str(ncloc)}]
    if distribution is not None:
        measures.append({"metric": "ncloc_language_distribution", "value": distribution})
    return {"component": {"key": project_key, "name": project_key, "qualifier": "TRK", "measures": measures}}


def check_result(document: dict) -> dict:
    """What fetch.py check prints, from the recorded run's server version and default Python profile."""
    profile = document["quality_profiles"]["profiles"][0]
    return {"status": "UP", "server_version": document["server"]["version"], "server_id": None,
            "edition": "community", "default_python_profile": {"name": profile["name"], "key": profile["key"]}}


class FakeSandbox:
    """Just enough of BaseEnvironment: a dict file system and scripted exec.

    ``recorded`` names the f2 recording ``fetch.py collect`` returns.
    ``edit_document`` may change a copy of it, for error paths no recording shows.
    """

    def __init__(self, task="smoke_eval", recorded="task_4da5ab_negative", check_exit=0, scanner_exit=0,
                 scanner_stdout="INFO  EXECUTION SUCCESS", collect_exit=0, collect_stdout=None, measures=None,
                 edit_document=None, prepare_exit=0, fail_upload=False, protect_exit=0, clock=None,
                 scanner_seconds=0.0):
        self.environment_dir = SAMPLE_TASKS / task / "environment"
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None, float | None]] = []
        #: ("exec", command) and ("upload", path) in order.
        self.events: list[tuple[str, str]] = []
        #: (step, the path it reads the token from, whether that file then held the token).
        self.token_reads: list[tuple[str, str | None, bool]] = []
        self.document = recorded_f2(recorded)
        self.document["measures"] = measures_response(self.document["project_key"]) if measures is None else measures
        self.check = check_result(self.document)
        if edit_document is not None:
            edit_document(self.document)
        self.check_exit = check_exit
        self.scanner_exit = scanner_exit
        self.scanner_stdout = scanner_stdout
        self.collect_exit = collect_exit
        self.collect_stdout = collect_stdout
        self.prepare_exit = prepare_exit
        self.fail_upload = fail_upload
        self.protect_exit = protect_exit
        self.clock = clock
        self.scanner_seconds = scanner_seconds

    def _holds_token(self, path):
        return self.files.get(path, b"").strip() == TOKEN.encode()

    def _remove_tree(self, path):
        for name in [n for n in self.files if n == path or n.startswith(path + "/")]:
            del self.files[name]

    def _find(self, command):
        """``find <roots> -type f -name '*.py'`` over the task's real repository."""
        repo = self.environment_dir / "repo"
        roots = shlex.split(command)[1:shlex.split(command).index("-type")]
        found = []
        for root in roots:
            base = repo / root
            if base.is_file() and base.suffix == ".py":
                found.append(root)
            elif base.is_dir():
                found += [str(p.relative_to(repo)) for p in base.rglob("*.py")]
        return ExecResult(stdout="\n".join(found) + "\n", return_code=0)

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
            if self.protect_exit:
                return ExecResult(stdout="", stderr="Terminated", return_code=self.protect_exit)
            source, target = re.search(r"cat (\S+) > (\S+)", command).groups()
            self.files[target] = self.files.pop(source)
            return ExecResult(return_code=0)
        if re.fullmatch(r"rm -rf (\S+) && mkdir -p \S+ && chmod 700 \S+", command):
            self._remove_tree(command.split()[2])
            return ExecResult(return_code=self.prepare_exit)
        if re.fullmatch(r"rm -rf (\S+)", command):
            self._remove_tree(command.split()[2])
            return ExecResult(return_code=0)
        if command.startswith("find "):
            return self._find(command)
        if "install.py" in command:
            result = {"scanner_home": pins.INSTALL_DIR, "scanner_version": pins.SONAR_SCANNER_VERSION,
                      "python": "/opt/sast/venv/bin/python"}
            return ExecResult(stdout="INSTALL_RESULT " + json.dumps(result), return_code=0)
        if "fetch.py check" in command:
            if self.check_exit:
                return ExecResult(stdout="[fetch] ERROR: GET api/authentication/validate failed: the server did "
                                         "not accept SONAR_TOKEN", return_code=self.check_exit)
            return ExecResult(stdout="CHECK_RESULT " + json.dumps(self.check), return_code=0)
        if "/bin/sonar-scanner" in command:
            if self.clock is not None:
                self.clock.now += self.scanner_seconds
            return ExecResult(stdout=self.scanner_stdout, stderr="", return_code=self.scanner_exit)
        if "fetch.py collect" in command:
            args = shlex.split(command)
            out = args[args.index("--out") + 1]
            self.files[out] = json.dumps(self.document).encode()
            if self.collect_exit:
                return ExecResult(stdout=self.collect_stdout or "[fetch] ERROR: failed", return_code=self.collect_exit)
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
        if self.fail_upload and str(target_path).endswith(".upload"):
            # The copy arrived, then the call failed (a docker cp that timed out, say).
            raise RuntimeError("docker cp: context deadline exceeded")

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


def bounded_seconds(command):
    """The seconds of the first ``timeout -k 10 <seconds>`` in a command."""
    return int(re.search(rf"timeout -k {KILL_AFTER_SEC} (\d+) ", command).group(1))


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
    assert sonar["server_version"] == "26.9.0.129388" and sonar["edition"] == "community"
    profile = sandbox.document["quality_profiles"]["profiles"][0]
    assert sonar["quality_profile"] == [{"name": "Sonar way", "key": profile["key"], "language": "py",
                                         "isDefault": True, "activeRuleCount": 398}]
    assert sonar["deleted"] is True and sonar["host_url"] == HOST
    assert sonar["ce_task"]["status"] == "SUCCESS" and sonar["ce_task"]["warnings"] == []
    assert sonar["ce_task"]["warningCount"] == 0
    # smoke_eval's src/ minus its excludes holds four Python files.
    assert sonar["python_files_in_scope"] == 4
    assert sonar["analysis"] == {"files": 34, "ncloc": 1500, "ncloc_by_language": {"py": 1500},
                                 "python_files_in_scope": 4, "active_python_rules": 398,
                                 "python_profile": {"name": "Sonar way", "key": profile["key"], "isDefault": True}}
    assert sonar["files_not_parsed"] == []
    # The recorded S4423 result: CWE-295, 326, 327, none mapped, so nothing is reported.
    assert meta["results_by_sonar_type"] == {"VULNERABILITY": 1, "SECURITY_HOTSPOT": 0}
    assert meta["results_by_cwe_decision"] == {"none": 0, "unmapped": 1, "mapped": 0, "ambiguous": 0}

    # The token travels only in a file, which every step that needs it reads.
    for needle in ("fetch.py check", "/bin/sonar-scanner", "fetch.py collect"):
        (command, env, _), = sandbox.commands_with(needle)
        assert env["SONAR_TOKEN_FILE"] == TOKEN_FILE and env["SONAR_HOST_URL"] == HOST
    assert sandbox.token_reads == [("check", TOKEN_FILE, True), ("sonar-scanner", TOKEN_FILE, True),
                                   ("collect", TOKEN_FILE, True)]
    (scanner, _, _), = sandbox.commands_with("/bin/sonar-scanner")
    assert re.search(rf'SONAR_TOKEN="\$\(cat {TOKEN_FILE}\)" exec timeout -k 10 \d+ '
                     r"/opt/sast/sonar-scanner/bin/sonar-scanner -D", scanner)

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


def test_recorded_mapped_result_reaches_the_sarif(tmp_path, server_env):
    """The real dc4b7a negative run: two python:S5332 issues (CWE-200, 319) become LLM02.SID.HIGH under cwe-map-4."""
    sandbox = FakeSandbox(recorded="task_dc4b7a_negative")
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok" and meta["cwe_map"] == "cwe-map-4"
    assert meta["results_by_cwe_decision"] == {"none": 0, "unmapped": 0, "mapped": 2, "ambiguous": 0}
    results = json.loads(sandbox.files["/app/output/findings.sarif"])["runs"][0]["results"]
    assert [(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
             r["locations"][0]["physicalLocation"]["region"]["startLine"]) for r in results] == [
        ("LLM02.SID.HIGH", "src/crewai_rag_web_mini/_compat/requests.py", 115),
        ("LLM02.SID.HIGH", "src/crewai_rag_web_mini/security/safe_requests.py", 77),
    ]
    assert all(r["properties"]["cwe"] == ["CWE-200", "CWE-319"] and "codeFlows" not in r for r in results)
    assert meta["sonarqube"]["findings_by_sonar_type"] == {"VULNERABILITY": 2, "SECURITY_HOTSPOT": 0}
    assert_token_nowhere(tmp_path, sandbox, context)


def test_scanner_arguments(tmp_path, server_env):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    (command, _, _), = sandbox.commands_with("/bin/sonar-scanner")
    args = shlex.split(command.split(" && ")[-1])
    assert args[:2] == [f"SONAR_TOKEN=$(cat {TOKEN_FILE})", "exec"]
    assert args[2:4] == ["timeout", "-k"] and args[4] == "10" and args[5].isdigit()
    args = args[6:]
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


# ---------------------------------------------------------------- one deadline, enforced in the sandbox


def test_every_tool_step_runs_under_timeout_within_one_budget(tmp_path, server_env):
    sandbox = FakeSandbox()
    _, _, go = run_agent(tmp_path, sandbox, scan_budget_sec=600)
    asyncio.run(go())
    (check, _, check_exec), = sandbox.commands_with("fetch.py check")
    (scanner, _, scanner_exec), = sandbox.commands_with("/bin/sonar-scanner")
    (collect, _, collect_exec), = sandbox.commands_with("fetch.py collect")
    assert check.startswith("timeout -k 10 ") and collect.startswith("timeout -k 10 ")
    for command, exec_limit in ((check, check_exec), (scanner, scanner_exec), (collect, collect_exec)):
        # The exec waits a little longer than the in-sandbox timeout, so the sandbox stops the tool first.
        assert exec_limit == bounded_seconds(command) + KILL_AFTER_SEC + 5
    assert bounded_seconds(check) <= 120
    assert bounded_seconds(scanner) <= 600 - 120
    assert collect_exec <= 600
    # fetch.py's own deadline (task wait, measures, paging, rule lookups) leaves time to delete the project.
    deadline = int(re.search(r"--deadline (\d+)", collect).group(1))
    assert deadline <= bounded_seconds(collect) - 30


def test_too_small_a_budget_fails_before_the_scanner(tmp_path, server_env):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, scan_budget_sec=100)
    with pytest.raises(ScannerError, match="budget"):
        asyncio.run(go())
    assert not sandbox.commands_with("/bin/sonar-scanner")
    assert not sandbox.commands_with("fetch.py delete")  # no project was created


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


def test_budget_spent_by_the_scanner_still_deletes_the_project(tmp_path, server_env, monkeypatch):
    """No recording: the scanner used up the budget, so collect is not started, and the project is deleted anyway."""
    clock = Clock()
    monkeypatch.setattr(agent_module, "time", types.SimpleNamespace(monotonic=clock.monotonic))
    sandbox = FakeSandbox(clock=clock, scanner_seconds=590)
    _, context, go = run_agent(tmp_path, sandbox, scan_budget_sec=600)
    with pytest.raises(ScannerError, match="ran out before collecting the results"):
        asyncio.run(go())
    assert not sandbox.commands_with("fetch.py collect")
    (delete, _, delete_exec), = sandbox.commands_with("fetch.py delete")
    # Cleanup gets its fixed slice although no budget is left.
    assert bounded_seconds(delete) == CLEANUP_SLICE_SEC and delete_exec == CLEANUP_SLICE_SEC + KILL_AFTER_SEC + 5
    assert context.metadata["sonarqube"]["deleted"] is True
    assert_token_nowhere(tmp_path, sandbox, context)


def test_collect_timeout_deletes_the_project(tmp_path, server_env):
    """No recording: fetch.py collect stopped by ``timeout`` (exit 124)."""
    sandbox = FakeSandbox(collect_exit=124, collect_stdout="[fetch] still waiting")
    _, context, go = run_agent(tmp_path, sandbox)
    sandbox.document["deleted"] = False  # killed before its own delete ran
    with pytest.raises(ScannerError, match="collecting the SonarQube results ran out of time"):
        asyncio.run(go())
    assert sandbox.commands_with("fetch.py delete")
    assert context.metadata["sonarqube"]["deleted"] is True
    assert_token_nowhere(tmp_path, sandbox, context)


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


@pytest.mark.parametrize("failure, message", [
    ({"fail_upload": True}, "could not upload /opt/sast/secret/sonar-token.upload"),
    ({"protect_exit": 124}, "protecting the token file ran out of time"),
    ({"protect_exit": 1}, "could not protect the token file"),
    ({"prepare_exit": 1}, "could not prepare the token directory"),
])
def test_a_failure_while_writing_the_token_leaves_nothing(tmp_path, server_env, failure, message):
    """The teammate's reproduction: the upload or the protect step fails after the upload arrived.

    No recording can show this. Before the fix the upload stayed in the sandbox,
    where the verifier (root, same sandbox) could read it.
    """
    sandbox = FakeSandbox(**failure)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=message):
        asyncio.run(go())
    assert [name for name in sandbox.files if name.startswith(TOKEN_DIR)] == []
    assert not sandbox.commands_with("fetch.py")
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


def test_host_url_with_user_info_is_refused_without_echoing_it(tmp_path, monkeypatch):
    monkeypatch.setenv("SONAR_HOST_URL", "http://admin:hunter2@host.docker.internal:9000")
    monkeypatch.setenv("SONAR_TOKEN", TOKEN)
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="must not contain a user name or password") as info:
        asyncio.run(go())
    assert "hunter2" not in str(info.value) and "hunter2" not in json.dumps(context.metadata, default=str)
    assert not sandbox.commands_with("fetch.py")


def test_run_without_setup_is_an_error(tmp_path, server_env):
    agent = SonarQubeAgent(logs_dir=tmp_path)
    with pytest.raises(ScannerError, match="setup"):
        asyncio.run(agent.run("x", FakeSandbox(), AgentContext()))


# ---------------------------------------------------------------- failures are errors


def test_server_check_failure_is_an_error(tmp_path, server_env):
    """No recording: a refused token (the 401 itself is tested on fetch.py)."""
    sandbox = FakeSandbox(check_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="server check failed.*did not accept SONAR_TOKEN"):
        asyncio.run(go())
    assert not sandbox.commands_with("/bin/sonar-scanner")
    assert "/logs/artifacts/sast/metadata.json" in sandbox.files
    assert_token_nowhere(tmp_path, sandbox, context)


def test_scanner_failure_is_an_error_and_cleans_up(tmp_path, server_env):
    """No recording: the scanner refused by the server."""
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


def _failed_task(status):
    def edit(document):
        document["ce_task"].update({"status": status, "errorMessage": "boom"})
        document["error"] = f"the background task ended {status}: boom"
        document["issues_pages"], document["hotspots_pages"] = [], []
    return edit


@pytest.mark.parametrize("status, exit_code", [("FAILED", 4), ("CANCELED", 4), ("PENDING", 5)])
def test_background_task_not_success_is_an_error(tmp_path, server_env, status, exit_code):
    """No recording of a failed task: the recorded document with its task status changed."""
    sandbox = FakeSandbox(collect_exit=exit_code, collect_stdout=f"[fetch] ERROR: the background task ended {status}",
                          edit_document=_failed_task(status))
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=f"collecting the SonarQube results failed \\(exit {exit_code}\\).*{status}"):
        asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "error"
    assert meta["sonarqube"]["ce_task"]["status"] == status and meta["sonarqube"]["deleted"] is True
    assert not sandbox.commands_with("fetch.py delete")  # fetch.py already deleted it
    assert "/app/output/findings.sarif" not in sandbox.files
    # The raw responses are kept for diagnosis.
    assert "/logs/artifacts/sast/sonarqube.json" in sandbox.files


def test_scanner_timeout_is_an_error_and_cleans_up(tmp_path, server_env):
    """No recording: sonar-scanner stopped by ``timeout`` (exit 124)."""
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


# ---------------------------------------------------------------- a scan that analysed nothing


def _no_active_rules(document):
    document["quality_profiles"]["profiles"][0]["activeRuleCount"] = 0


@pytest.mark.parametrize("sandbox_args, message", [
    ({"measures": None, "edit_document": lambda d: d.update(measures=measures_response(d["project_key"], 0, 0, ""))},
     "analysed 0 files"),
    ({"edit_document": lambda d: d.update(measures=measures_response(d["project_key"], 3, 40, "xml=40"))},
     "holds 4 Python files but SonarQube analysed no Python"),
    ({"edit_document": lambda d: d.update(measures=None)}, "measures .* were not read"),
    ({"edit_document": _no_active_rules}, "'Sonar way' has no active rules"),
    ({"edit_document": lambda d: d.update(quality_profiles={"profiles": []})}, "no Python quality profile"),
])
def test_a_scan_that_analysed_nothing_is_an_error(tmp_path, server_env, sandbox_args, message):
    """No recording analysed nothing: the recorded document with its measures or profile changed."""
    sandbox = FakeSandbox(**sandbox_args)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="SonarQube did not analyse the code: .*" + message):
        asyncio.run(go())
    assert "/app/output/findings.sarif" not in sandbox.files
    assert context.metadata["sonarqube"]["deleted"] is True
    assert_token_nowhere(tmp_path, sandbox, context)


def test_parse_failures_and_task_warnings_reach_the_metadata(tmp_path, server_env):
    warnings = ["1 file could not be parsed"]
    sandbox = FakeSandbox(
        scanner_stdout="INFO  40 files indexed (done)\nERROR Unable to parse file: src/calc_agent/llm.py\n"
                       "INFO  EXECUTION SUCCESS",
        edit_document=lambda d: d["ce_task"].update(warnings=warnings, warningCount=1))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    sonar = context.metadata["sonarqube"]
    assert sonar["files_not_parsed"] == ["ERROR Unable to parse file: src/calc_agent/llm.py"]
    assert sonar["ce_task"]["warnings"] == warnings and sonar["ce_task"]["warningCount"] == 1


def test_an_old_format_document_is_refused(tmp_path, server_env):
    """A fetch_format 1 document (the real 2026-10-07 recording) would report nothing silently."""
    sandbox = FakeSandbox()
    old = json.loads((FIXTURES / "sonarqube_26.9_task_dc4b7a_positive.json").read_text())
    old["measures"] = sandbox.document["measures"]
    sandbox.document = old
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="fetch_format 1"):
        asyncio.run(go())


# ---------------------------------------------------------------- analysis check, pure


def test_analysis_check_on_a_recorded_document():
    document = recorded_f2("task_dc4b7a_positive")
    document["measures"] = measures_response(document["project_key"], 34, 1200, "py=1180;xml=20")
    summary, problems = analysis_check(document, 34)
    assert problems == [] and summary["ncloc_by_language"] == {"py": 1180, "xml": 20}
    assert summary["active_python_rules"] == 398


def test_analysis_check_uses_the_default_profile_when_the_project_has_none():
    document = recorded_f2("task_dc4b7a_positive")
    document["measures"] = measures_response(document["project_key"])
    document["default_quality_profiles"] = document["quality_profiles"]
    document["quality_profiles"] = {"profiles": []}
    summary, problems = analysis_check(document, 1)
    assert problems == [] and summary["python_profile"]["name"] == "Sonar way"


def test_no_python_in_scope_needs_no_python_analysis():
    document = recorded_f2("task_dc4b7a_positive")
    document["measures"] = measures_response(document["project_key"], 2, 30, "js=30")
    assert analysis_check(document, 0)[1] == []


def test_language_distribution_and_parse_failures():
    assert language_distribution("py=120;xml=4") == {"py": 120, "xml": 4}
    assert language_distribution(None) == {} and language_distribution("") == {}
    assert parse_failures("INFO ok\nERROR Unable to parse file: a.py\nWARN Parse error at line 3") == [
        "ERROR Unable to parse file: a.py", "WARN Parse error at line 3"]


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
