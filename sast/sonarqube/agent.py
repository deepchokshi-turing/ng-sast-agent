"""``sast.sonarqube.agent:SonarQubeAgent``: SonarQube as a Harbor agent, no LLM.

SonarQube is a server the user hosts. The agent reads where it is and a token
from the host's environment, runs sonar-scanner (from the tools image) inside
the task sandbox against it, collects the VULNERABILITY issues and Security
Hotspots through the web API from inside the sandbox (``fetch.py``), deletes
the throwaway project, and writes /app/output/findings.sarif.

Configuration, read on the host when the scan starts:

- ``SONAR_HOST_URL``: the server as the sandbox sees it, for example
  ``http://host.docker.internal:9000`` for a local Docker server.
- ``SONAR_TOKEN``: a user token that may create, analyse, browse and delete
  projects.

Harbor turns an exec call's ``env`` into command-line arguments (``docker
compose exec -e NAME=value``, ``env NAME=value`` on Daytona), where any process
listing shows them. So the token never goes through ``env`` or a command line.
It is uploaded as a file in a mode 700 directory under the work dir, made mode
600, read by fetch.py (``SONAR_TOKEN_FILE``) and put into sonar-scanner's own
environment by the sandbox shell (``SONAR_TOKEN="$(cat <file>)" exec ...``).
The file is deleted when the scan ends, also after a failure (writing it is
inside the same try/finally). The token is
never in a log, an artifact or the metadata, and the command output that is
kept is scrubbed of it in case a tool echoes it.

Local use::

    export SONAR_HOST_URL=http://host.docker.internal:9000 SONAR_TOKEN=<token>
    PYTHONPATH=<this repo> harbor run -p <task> -a sast.sonarqube.agent:SonarQubeAgent
"""

from __future__ import annotations

import json
import os
import secrets
import shlex
import time
import urllib.parse
from pathlib import Path
from typing import Any, ClassVar

from harbor.environments.base import BaseEnvironment, ExecResult

from ..base import REPO_DIR, ScannerAgent
from ..errors import ScannerError, ToolOutcome
from ..findings import Finding
from ..scope import in_scope, repo_path, task_scope
from ..task_config import TaskSettings
from . import pins
from .normalise import normalise, sonar_types
from .options import SonarQubeOptions

_HERE = Path(__file__).parent

#: fetch.py exit codes (fetch.py EXIT_TASK, EXIT_TIMEOUT) that are tool outcomes:
#: the server's analysis of this repository failed, or the scan budget ran out.
FETCH_EXIT_OUTCOME = {4: "tool_crashed", 5: "deadline"}
#: sonar-scanner output that points at the server or the network, not at the code:
#: a non-zero exit with one of these is an infrastructure failure (lowercase).
SCANNER_INFRA_MARKERS = ("not authorized", "unauthorized", "insufficient privileges", "http 401", "http 403",
                         "failed to query server", "connection refused", "unknownhostexception", "connectexception",
                         "sockettimeoutexception", "sslhandshakeexception", "unable to reach")

#: Always excluded, like the Semgrep agent: compiled bytecode is a build output.
ALWAYS_EXCLUDE_GLOBS = ("**/__pycache__/**", "**/*.pyc", "**/*.pyo")

#: One deadline (the scan budget) covers the server check, sonar-scanner, the
#: background task, the measures, the paging and the rule lookups. sonar-scanner
#: and fetch.py run under ``timeout -k KILL_AFTER_SEC <seconds>`` inside the
#: sandbox, so they stop there even when Harbor only kills its exec client.

#: Seconds of the budget kept back for collecting results after sonar-scanner.
COLLECT_RESERVE_SEC = 120
#: fetch.py's own deadline ends this long before its ``timeout``, so it can
#: still delete the project (fetch.DELETE_SLICE_SEC) and write its JSON.
FETCH_DELETE_RESERVE_SEC = 30
#: A step with less time than this left is not started.
MIN_STEP_SEC = 30
CHECK_TIMEOUT_SEC = 120
#: ``timeout -k``: seconds between SIGTERM and SIGKILL.
KILL_AFTER_SEC = 10
#: How much longer the exec call waits than the in-sandbox ``timeout``.
EXEC_SLACK_SEC = 5
#: Cleanup (deleting the project, removing the token file) always gets this
#: much, also after the deadline. The budget leaves Harbor's 120 s margin for it.
CLEANUP_SLICE_SEC = 30
#: Lines of sonar-scanner output kept that say a file could not be parsed.
MAX_PARSE_LINES = 100

#: The token file, relative to the work dir, in a directory only its owner can enter.
TOKEN_DIR = "secret"
TOKEN_FILE = "sonar-token"

SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def exclusion_globs(excludes: list[str]) -> list[str]:
    """sonar.exclusions patterns, relative to the project base dir (/app/repo).

    The same meaning as the Semgrep agent's excludes: a path with a slash is
    anchored at the repository root (``src/vendor`` is that folder or file
    only), a plain name (``tests``) is that name at any depth.
    """
    globs: list[str] = []
    for raw in excludes:
        path = raw.strip("/")
        if "," in path:
            raise ScannerError(f"excluded path {raw!r} contains a comma, which sonar.exclusions cannot express")
        if path in ("", "."):
            continue
        prefix = "" if "/" in path else "**/"
        globs += [f"{prefix}{path}", f"{prefix}{path}/**"]
    return _unique([*globs, *ALWAYS_EXCLUDE_GLOBS])


def _unique(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def scanner_properties(
    *, project_key: str, roots: list[str], excludes: list[str], sonar_dir: str
) -> list[str]:
    """The -D arguments for sonar-scanner. Host and token come from its environment."""
    for root in roots:
        if "," in root:
            raise ScannerError(f"scan root {root!r} contains a comma, which sonar.sources cannot express")
    properties = {
        "sonar.projectKey": project_key,
        "sonar.projectName": project_key,
        "sonar.projectBaseDir": REPO_DIR,
        "sonar.sources": ",".join(roots),
        "sonar.exclusions": ",".join(exclusion_globs(excludes)),
        "sonar.python.version": "3",
        "sonar.sourceEncoding": "UTF-8",
        "sonar.scm.disabled": "true",
        # The repository may be read-only: the scanner's files go to the work dir.
        "sonar.working.directory": f"{sonar_dir}/scannerwork",
        "sonar.scanner.metadataFilePath": f"{sonar_dir}/report-task.txt",
        "sonar.qualitygate.wait": "false",
    }
    return [f"-D{key}={value}" for key, value in properties.items()]


def bounded(command: str, seconds: float) -> str:
    """``command`` under coreutils ``timeout`` inside the sandbox."""
    return f"timeout -k {KILL_AFTER_SEC} {max(1, int(seconds))} {command}"


def exec_timeout(seconds: float) -> float:
    """The exec call's own limit for a command bounded to ``seconds``."""
    return max(1, int(seconds)) + KILL_AFTER_SEC + EXEC_SLACK_SEC


def _measures(document: dict[str, Any]) -> dict[str, str] | None:
    component = (document.get("measures") or {}).get("component")
    if not isinstance(component, dict):
        return None
    return {str(m.get("metric")): str(m.get("value") or "") for m in component.get("measures") or []
            if isinstance(m, dict)}


def _int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def language_distribution(value: str | None) -> dict[str, int]:
    """``ncloc_language_distribution`` ("py=120;xml=4") as {language: ncloc}."""
    result: dict[str, int] = {}
    for part in (value or "").split(";"):
        if "=" in part:
            language, count = part.split("=", 1)
            result[language.strip()] = _int(count)
    return result


def python_profile(document: dict[str, Any]) -> dict[str, Any] | None:
    """The project's Python quality profile, else the server's default one."""
    for key in ("quality_profiles", "default_quality_profiles"):
        profiles = [p for p in ((document.get(key) or {}).get("profiles") or [])
                    if isinstance(p, dict) and p.get("language", "py") == "py"]
        if profiles:
            return profiles[0]
    return None


def analysis_check(document: dict[str, Any], python_files_in_scope: int) -> tuple[dict[str, Any], list[str]]:
    """(what was analysed, problems). Any problem means the scan cannot be trusted.

    A scan that indexed no file, analysed no Python although the scope holds
    Python files, or ran a Python profile with no active rule finds nothing
    because it looked at nothing, which must not be graded as a clean scan.
    """
    measures = _measures(document)
    profile = python_profile(document)
    by_language = language_distribution((measures or {}).get("ncloc_language_distribution"))
    summary = {
        "files": _int((measures or {}).get("files")) if measures is not None else None,
        "ncloc": _int((measures or {}).get("ncloc")) if measures is not None else None,
        "ncloc_by_language": by_language,
        "python_files_in_scope": python_files_in_scope,
        "python_profile": {k: (profile or {}).get(k) for k in ("name", "key", "isDefault")} if profile else None,
        "active_python_rules": _int(profile.get("activeRuleCount")) if profile else None,
    }
    problems = []
    if measures is None:
        problems.append("the analysis measures (api/measures/component) were not read")
    elif summary["files"] == 0:
        problems.append("SonarQube analysed 0 files (wrong scan roots or exclusions?)")
    elif python_files_in_scope > 0 and by_language.get("py", 0) == 0:
        problems.append(f"the scope holds {python_files_in_scope} Python files but SonarQube analysed no Python "
                        f"(ncloc_language_distribution {measures.get('ncloc_language_distribution')!r})")
    if profile is None:
        problems.append("no Python quality profile was found for the project")
    elif summary["active_python_rules"] == 0:
        problems.append(f"the Python quality profile {profile.get('name')!r} has no active rules")
    return summary, problems


def parse_failures(output: str) -> list[str]:
    """sonar-scanner lines that say a file could not be parsed."""
    lines = [line.strip() for line in output.splitlines()
             if "Unable to parse" in line or "Parse error" in line or "parsing error" in line.lower()]
    return lines[:MAX_PARSE_LINES]


def _scrub(text: str | None, token: str) -> str:
    text = text or ""
    return text.replace(token, "***") if token else text


def _last_error(output: str, default: str) -> str:
    errors = [line.strip() for line in output.splitlines() if "ERROR" in line]
    return errors[-1][:600] if errors else default


def _result_line(output: str, prefix: str) -> dict[str, Any] | None:
    for line in reversed(output.splitlines()):
        if line.startswith(prefix + " "):
            try:
                return json.loads(line[len(prefix) + 1:])
            except ValueError:
                return None
    return None


class SonarQubeAgent(ScannerAgent):
    options_model: ClassVar[type[SonarQubeOptions]] = SonarQubeOptions
    tool_name: ClassVar[str] = "sonarqube"

    @staticmethod
    def name() -> str:
        return "sonarqube-sast"

    def tool_version(self) -> str:
        """The sonar-scanner version. The server's version is in the metadata."""
        return pins.SONAR_SCANNER_VERSION

    # ------------------------------------------------------------ install

    def install_files(self) -> dict[str, bytes]:
        return {
            "install.py": (_HERE / "install.py").read_bytes(),
            "fetch.py": (_HERE / "fetch.py").read_bytes(),
            "pins.json": json.dumps(pins.as_dict(), indent=2).encode("utf-8"),
        }

    def install_command(self, work_dir: str) -> str:
        # The Python that /opt/sast brings (from the tools image), else the image's.
        return (
            "PY=python3; [ -x /opt/sast/venv/bin/python ] && PY=/opt/sast/venv/bin/python; "
            f'SAST_ROOT={shlex.quote(work_dir)} "$PY" {shlex.quote(work_dir + "/install.py")} '
            f"{shlex.quote(work_dir + '/pins.json')}"
        )

    # ------------------------------------------------------------ scan

    @staticmethod
    def _server_config() -> tuple[str, str]:
        host = os.environ.get("SONAR_HOST_URL", "").strip()
        token = os.environ.get("SONAR_TOKEN", "").strip()
        missing = [name for name, value in (("SONAR_HOST_URL", host), ("SONAR_TOKEN", token)) if not value]
        if missing:
            raise ScannerError(
                f"{' and '.join(missing)} not set on the host: the SonarQube agent needs the server URL as the "
                "sandbox sees it (e.g. http://host.docker.internal:9000) and a user token (see README.md)"
            )
        if "@" in urllib.parse.urlsplit(host).netloc:
            # Not echoed: it holds a credential, and the URL goes into the exec env and the metadata.
            raise ScannerError("SONAR_HOST_URL must not contain a user name or password (user:pass@host): "
                               "the agent authenticates with SONAR_TOKEN only")
        if not host.startswith(("http://", "https://")):
            raise ScannerError(f"SONAR_HOST_URL must start with http:// or https://, got {host!r}")
        return host, token

    async def scan(
        self,
        environment: BaseEnvironment,
        settings: TaskSettings,
        budget_sec: float,
        meta: dict[str, Any],
    ) -> list[Finding]:
        host, token = self._server_config()
        work = getattr(self, "_work_dir", None)
        if work is None:
            raise ScannerError("setup() did not run: sonar-scanner was not checked")
        deadline = time.monotonic() + budget_sec
        options: SonarQubeOptions = self.options  # type: ignore[assignment]
        python = (getattr(self, "_install", None) or {}).get("python") or "python3"
        scanner_home = (getattr(self, "_install", None) or {}).get("scanner_home") or pins.INSTALL_DIR
        fetch = f"{shlex.quote(python)} {shlex.quote(work + '/fetch.py')}"
        sonar_dir = f"{work}/out/sonar"
        json_out = f"{work}/out/sonarqube.json"
        token_dir = f"{work}/{TOKEN_DIR}"
        token_file = f"{token_dir}/{TOKEN_FILE}"
        # No secret in here: Harbor puts these on the exec command line.
        env = {
            "SONAR_HOST_URL": host,
            "SONAR_TOKEN_FILE": token_file,
            "SONAR_USER_HOME": f"{work}/home/.sonar",
            "HOME": f"{work}/home",
            "PATH": f"{scanner_home}/bin:{SYSTEM_PATH}",
        }
        sonar: dict[str, Any] = {"host_url": host, "keep_project": bool(options.keep_project)}
        meta["sonarqube"] = sonar

        try:
            # Inside the try: a failed upload or protect step must still remove the file.
            await self._write_token(environment, token_dir, token_file, token, sonar)
            return await self._scan_with_token(environment, settings, budget_sec, meta, sonar, token, env,
                                               fetch=fetch, work=work, sonar_dir=sonar_dir, json_out=json_out,
                                               token_file=token_file, scanner_home=scanner_home,
                                               deadline=deadline)
        finally:
            await self._remove_token(environment, token_dir, sonar)

    async def _scan_with_token(
        self,
        environment: BaseEnvironment,
        settings: TaskSettings,
        budget_sec: float,
        meta: dict[str, Any],
        sonar: dict[str, Any],
        token: str,
        env: dict[str, str],
        *,
        fetch: str,
        work: str,
        sonar_dir: str,
        json_out: str,
        token_file: str,
        scanner_home: str,
        deadline: float,
    ) -> list[Finding]:
        options: SonarQubeOptions = self.options  # type: ignore[assignment]

        def left() -> float:
            return deadline - time.monotonic()

        def need(seconds: float, what: str) -> None:
            if left() < seconds:
                raise ToolOutcome("deadline", f"the scan budget ({int(budget_sec)} s) ran out before {what}")

        # 1. The server is up and takes the token.
        need(MIN_STEP_SEC, "checking the SonarQube server")
        seconds = min(CHECK_TIMEOUT_SEC, left() - KILL_AFTER_SEC - EXEC_SLACK_SEC)
        result = await self._run_logged(environment, "command-1", bounded(f"{fetch} check", seconds), token,
                                        env=env, timeout_sec=exec_timeout(seconds),
                                        what="the SonarQube server check")
        check = _result_line(result.stdout or "", "CHECK_RESULT")
        if result.return_code != 0 or check is None:
            raise ScannerError("SonarQube server check failed (exit {}): {}".format(
                result.return_code, _last_error(result.stdout or result.stderr or "", "no output")))
        sonar.update({
            "server_version": check.get("server_version"),
            "server_id": check.get("server_id"),
            "edition": check.get("edition"),
            "default_python_profile": check.get("default_python_profile"),
        })

        # 2. The scope, and how many Python files it holds.
        roots, excludes = task_scope(options.scan_roots or settings.scanner_roots,
                                     options.exclude or settings.excluded_paths, "scan_roots", "exclude")
        need(MIN_STEP_SEC, "checking the scan roots")
        roots = await self._existing_roots(environment, roots, meta)
        meta["scan"] = {"roots": roots, "excludes": excludes, "exclusions": exclusion_globs(excludes)}
        python_files = await self._python_files_in_scope(environment, roots, excludes, min(60.0, left()))
        sonar["python_files_in_scope"] = python_files

        # 3. sonar-scanner, with a throwaway project. From here on the project
        # may exist, so every exit path deletes it.
        project_key = f"sast-{secrets.token_hex(6)}"
        sonar["project_key"] = project_key
        sonar["deleted"] = False
        arguments = scanner_properties(project_key=project_key, roots=roots, excludes=excludes, sonar_dir=sonar_dir)
        need(COLLECT_RESERVE_SEC + MIN_STEP_SEC, "running sonar-scanner")
        scanner_started = False
        try:
            seconds = left() - COLLECT_RESERVE_SEC
            command = (
                f"rm -rf {shlex.quote(sonar_dir)} {shlex.quote(json_out)} && mkdir -p {shlex.quote(sonar_dir)} && "
                # The sandbox shell reads the token into the scanner's environment only.
                + f'SONAR_TOKEN="$(cat {shlex.quote(token_file)})" exec '
                + bounded(" ".join(shlex.quote(part) for part in [f"{scanner_home}/bin/sonar-scanner", *arguments]),
                          seconds)
            )
            scanner_started = True
            result = await self._run_logged(environment, "command-2", command, token, env=env, cwd=REPO_DIR,
                                            timeout_sec=exec_timeout(seconds), what="sonar-scanner", tool_step=True)
            await self._keep_scanner_log(environment, result, f"{work}/out/sonar-scanner.log")
            sonar["scanner_exit_code"] = result.return_code
            sonar["files_not_parsed"] = parse_failures(f"{result.stdout}\n{result.stderr}")
            if result.return_code != 0:
                output = f"{result.stdout}\n{result.stderr}"
                message = "sonar-scanner exited {}: {} (full log: agent/command-2/stdout.txt)".format(
                    result.return_code, _last_error(output, "no ERROR line in its output"))
                if any(marker in output.lower() for marker in SCANNER_INFRA_MARKERS):
                    raise ScannerError(message)
                raise ToolOutcome("tool_crashed", message)

            # 4. Wait for the server, read what it analysed and found, delete the project.
            need(FETCH_DELETE_RESERVE_SEC + MIN_STEP_SEC + KILL_AFTER_SEC + EXEC_SLACK_SEC, "collecting the results")
            seconds = left() - KILL_AFTER_SEC - EXEC_SLACK_SEC
            command = (
                f"{fetch} collect --report {shlex.quote(sonar_dir + '/report-task.txt')} "
                f"--project {project_key} --out {shlex.quote(json_out)} "
                f"--deadline {int(seconds - FETCH_DELETE_RESERVE_SEC)}"
                + (" --keep" if options.keep_project else "")
            )
            result = await self._run_logged(environment, "command-3", bounded(command, seconds), token, env=env,
                                            timeout_sec=exec_timeout(seconds),
                                            what="collecting the SonarQube results", tool_step=True)
            document = await self._read_document(environment, json_out)
            if document is not None:
                sonar["deleted"] = bool(document.get("deleted"))
                sonar["delete_error"] = document.get("delete_error")
                task = document.get("ce_task") or {}
                sonar["ce_task"] = {k: task.get(k) for k in ("id", "status", "executionTimeMs", "errorMessage",
                                                             "warningCount", "warnings")}
                profiles = (document.get("quality_profiles") or {}).get("profiles") or []
                sonar["quality_profile"] = [{k: p.get(k) for k in ("name", "key", "language", "isDefault",
                                                                   "activeRuleCount")} for p in profiles]
                # Security Hotspot rules on the server and active in that profile.
                # Both are 0 on Community Build 26.9, so no hotspot can appear there.
                for key in ("hotspot_rules_total", "hotspot_rules_active", "hotspot_rules_qprofile",
                            "hotspot_rules_error"):
                    sonar[key] = document.get(key)
            if result.return_code != 0:
                message = "collecting the SonarQube results failed (exit {}): {}".format(
                    result.return_code, _last_error(result.stdout or result.stderr or "", "no output"))
                if result.return_code in FETCH_EXIT_OUTCOME:
                    raise ToolOutcome(FETCH_EXIT_OUTCOME[result.return_code], message)
                raise ScannerError(message)
            if document is None:
                raise ScannerError(f"{json_out} is missing or unreadable after a successful collect")

            # 5. A scan that looked at nothing is an error, not a clean result.
            summary, problems = analysis_check(document, python_files)
            sonar["analysis"] = summary
            if problems:
                message = "SonarQube did not analyse the code: " + "; ".join(problems)
                # A missing profile or unread measures is the server's setup; analysing
                # no file or no Python of a scope that has some is the tool on this code.
                if any("quality profile" in p or "were not read" in p for p in problems):
                    raise ScannerError(message)
                raise ToolOutcome("tool_saw_nothing", message)
        except BaseException:
            if scanner_started and not sonar.get("deleted"):
                await self._delete_project(environment, fetch, project_key, env, sonar)
            raise

        try:
            findings, counts = normalise(document)
        except ValueError as exc:
            raise ScannerError(str(exc)) from exc
        meta.update(counts)
        kept = self._keep_in_scope(findings, roots, excludes, meta)
        sonar["findings_by_sonar_type"] = sonar_types(kept)
        return kept

    def artifact_files(self) -> dict[str, str]:
        work = getattr(self, "_work_dir", None)
        if not work:
            return {}
        return {"sonarqube.json": f"{work}/out/sonarqube.json", "sonar-scanner.log": f"{work}/out/sonar-scanner.log"}

    # ------------------------------------------------------------ helpers

    async def _run_logged(
        self,
        environment: BaseEnvironment,
        log_name: str,
        command: str,
        token: str,
        *,
        env: dict[str, str],
        timeout_sec: float,
        what: str,
        cwd: str | None = None,
        tool_step: bool = False,
    ) -> ExecResult:
        """One exec, logged with the token scrubbed. The token is in neither the command nor the env."""
        if token in command or any(token in value for value in env.values()):  # a programming error
            raise ScannerError("refusing to run a command whose command line or env contains SONAR_TOKEN")
        started = time.monotonic()
        try:
            result = await self._exec(environment, command, timeout_sec=timeout_sec, what=what, cwd=cwd, env=env,
                                      tool_step=tool_step)
        except ToolOutcome as exc:
            raise exc.with_message(_scrub(str(exc), token)) from None
        except ScannerError as exc:
            raise ScannerError(_scrub(str(exc), token)) from None
        clean = ExecResult(stdout=_scrub(result.stdout, token), stderr=_scrub(result.stderr, token),
                           return_code=result.return_code)
        self._write_log(log_name, command, clean, round(time.monotonic() - started, 1))
        return clean

    async def _python_files_in_scope(
        self, environment: BaseEnvironment, roots: list[str], excludes: list[str], timeout_sec: float
    ) -> int:
        """How many .py files the scope holds, so a scan that analysed no Python can be told apart."""
        paths = " ".join(shlex.quote(r) for r in roots)
        result = await self._exec(environment, f"find {paths} -type f -name '*.py' 2>/dev/null",
                                  timeout_sec=max(1.0, timeout_sec), what="counting Python files", cwd=REPO_DIR)
        files = {repo_path(line.strip()) for line in (result.stdout or "").splitlines() if line.strip()}
        return sum(1 for f in files if in_scope(f, roots, excludes))

    async def _write_token(
        self, environment: BaseEnvironment, token_dir: str, token_file: str, token: str, sonar: dict[str, Any]
    ) -> None:
        """The token as a mode 600 file in a mode 700 directory. No command here holds the token.

        The upload may arrive owned by another user (``docker cp`` writes as
        root), so the sandbox user copies it into a file of its own, created
        under umask 077, and removes the upload. The caller removes the whole
        directory in a ``finally``, so a failure in any step here leaves nothing.
        """
        quoted_dir, quoted_file = shlex.quote(token_dir), shlex.quote(token_file)
        upload = f"{token_dir}/{TOKEN_FILE}.upload"
        quoted_upload = shlex.quote(upload)
        result = await self._exec(environment,
                                  f"rm -rf {quoted_dir} && mkdir -p {quoted_dir} && chmod 700 {quoted_dir}",
                                  timeout_sec=60, what="preparing the token directory")
        if result.return_code != 0:
            raise ScannerError(f"could not prepare the token directory {token_dir} (exit {result.return_code})")
        await self._upload_bytes(environment, token.encode("utf-8"), upload)
        result = await self._exec(
            environment,
            f"umask 077 && cat {quoted_upload} > {quoted_file} && rm -f {quoted_upload} && "
            f"chmod 600 {quoted_file} && test -s {quoted_file}",
            timeout_sec=60, what="protecting the token file")
        if result.return_code != 0:
            raise ScannerError(f"could not protect the token file {token_file} (exit {result.return_code})")
        sonar["token_file"] = token_file

    async def _remove_token(self, environment: BaseEnvironment, token_dir: str, sonar: dict[str, Any]) -> None:
        """Delete the token file and its directory. Best effort, recorded in the metadata."""
        try:
            result = await self._exec(environment, f"rm -rf {shlex.quote(token_dir)}", timeout_sec=CLEANUP_SLICE_SEC,
                                      what="removing the token file")
            sonar["token_file_removed"] = result.return_code == 0
        except ScannerError:
            sonar["token_file_removed"] = False

    async def _keep_scanner_log(self, environment: BaseEnvironment, result: ExecResult, path: str) -> None:
        """The scrubbed scanner output, as an artifact. Best effort."""
        text = f"exit code: {result.return_code}\n\n--- stdout ---\n{result.stdout}\n\n--- stderr ---\n{result.stderr}\n"
        try:
            await self._upload_bytes(environment, text.encode("utf-8"), path)
        except ScannerError:
            pass

    async def _read_document(self, environment: BaseEnvironment, path: str) -> dict[str, Any] | None:
        try:
            document = json.loads(await self._download_bytes(environment, path))
        except (ScannerError, ValueError):
            return None
        return document if isinstance(document, dict) else None

    async def _delete_project(
        self, environment: BaseEnvironment, fetch: str, project_key: str, env: dict[str, str], sonar: dict[str, Any]
    ) -> None:
        """Best-effort cleanup after a failure, in a fixed time slice even past the deadline. The run fails anyway."""
        if getattr(self.options, "keep_project", False):
            return
        try:
            result = await self._exec(environment, bounded(f"{fetch} delete --project {project_key}",
                                                           CLEANUP_SLICE_SEC),
                                      timeout_sec=exec_timeout(CLEANUP_SLICE_SEC),
                                      what="deleting the SonarQube project", env=env)
            outcome = _result_line(result.stdout or "", "DELETE_RESULT") or {}
            sonar["deleted"] = bool(outcome.get("deleted"))
        except ScannerError:
            sonar["deleted"] = False
