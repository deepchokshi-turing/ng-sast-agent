"""What every scanner agent shares: install in the sandbox, scan, write the SARIF.

A scanner agent has no model. It installs its tool inside the task sandbox
(never on the worker, which has only Harbor), scans ``/app/repo``, and writes
``/app/output/findings.sarif`` for the task's verifier. Subclasses supply the
install files and the scan; this class owns the lifecycle, the time limits, the
logs the platform keeps, and the run metadata.

Failure policy: anything that makes the result untrustworthy (install failed,
scan crashed or ran out of time, unreadable output) raises ``ScannerError``, so
the trial is recorded as errored and can be re-run instead of being graded as
"found nothing".
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shlex
import tempfile
import time
from abc import abstractmethod
from dataclasses import replace
from pathlib import Path
from typing import Any, ClassVar

from harbor.agents.base import BaseAgent
from harbor.agents.capabilities import AgentCapabilities
from harbor.environments.base import BaseEnvironment, ExecResult
from harbor.models.agent.context import AgentContext
from harbor.models.trial.result import AgentInfo

from . import __version__, cwe_map, heuristics, sarif, task_config
from .errors import ScannerError
from .findings import Finding
from .task_config import TaskSettings

REPO_DIR = "/app/repo"
OUTPUT_DIR = "/app/output"
OUTPUT_FILE = f"{OUTPUT_DIR}/findings.sarif"
#: Harbor copies the sandbox's /logs/artifacts into the trial's artifacts/ folder,
#: and the platform archives the whole trial: the raw tool output lives here.
ARTIFACTS_DIR = "/logs/artifacts/sast"

#: Where the tool is installed. /opt is used when the agent's user can write it,
#: otherwise /tmp (an image that runs the agent as a non-root user).
WORK_DIR_CANDIDATES = ("/opt/sast", "/tmp/sast")

#: Harbor gives setup() 360 s in total and the platform cannot raise it.
SETUP_TIMEOUT_SEC = 300
#: The scan stops this long before Harbor's agent timeout. Harbor grades a trial
#: whose agent hit its timeout (the missing SARIF scores 0), so the agent must
#: stop first and report the trial as errored instead.
TIMEOUT_MARGIN_SEC = 120
MIN_SCAN_BUDGET_SEC = 60
#: When the task sets no agent timeout, Harbor imposes none; cap the scan anyway.
DEFAULT_SCAN_BUDGET_SEC = 3600
#: Rows of the compact finding list kept in the run metadata.
MAX_COMPACT_FINDINGS = 5000
#: How much of a command's output goes into the logs the platform keeps.
LOG_TAIL_CHARS = 20000


def _tail(text: str | None, limit: int = LOG_TAIL_CHARS) -> str:
    text = text or ""
    return text if len(text) <= limit else f"[... {len(text) - limit} characters cut ...]\n" + text[-limit:]


class ScannerAgent(BaseAgent):
    capabilities = AgentCapabilities()

    #: The tool's name, as written in the SARIF driver.
    tool_name: ClassVar[str]

    # ------------------------------------------------------------ subclass API

    @abstractmethod
    def install_files(self) -> dict[str, bytes]:
        """Files to upload into the work directory before installing."""

    @abstractmethod
    def install_command(self, work_dir: str) -> str:
        """The shell command that installs the tool. Must print a last line
        ``INSTALL_RESULT {json}`` on success."""

    @abstractmethod
    def tool_version(self) -> str:
        """The tool version written into the SARIF driver."""

    @abstractmethod
    async def scan(
        self,
        environment: BaseEnvironment,
        settings: TaskSettings,
        budget_sec: float,
        meta: dict[str, Any],
    ) -> list[Finding]:
        """Scan /app/repo and return its security findings. Adds what it learns
        to ``meta``; raises ScannerError when the scan cannot be trusted."""

    # ------------------------------------------------------------ Harbor API

    def version(self) -> str | None:
        return f"{__version__}+{self.tool_name}-{self.tool_version()}"

    def to_agent_info(self) -> AgentInfo:
        """No model: the platform makes every run name one, but it is never
        called, so the trial must not credit it with the scanner's results."""
        return AgentInfo(name=self.name(), version=self.version() or "unknown", model_info=None)

    async def setup(self, environment: BaseEnvironment) -> None:
        self._work_dir = await self._choose_work_dir(environment)
        for name, data in self.install_files().items():
            await self._upload_bytes(environment, data, f"{self._work_dir}/{name}")

        command = self.install_command(self._work_dir)
        started = time.monotonic()
        result = await self._exec(environment, command, timeout_sec=SETUP_TIMEOUT_SEC, what="install")
        seconds = round(time.monotonic() - started, 1)
        self._write_log("setup", command, result, seconds)

        install = None
        for line in reversed((result.stdout or "").splitlines()):
            if line.startswith("INSTALL_RESULT "):
                install = json.loads(line[len("INSTALL_RESULT "):])
                break
        if result.return_code != 0 or install is None:
            output = f"{result.stdout or ''}\n{result.stderr or ''}"
            errors = [line.strip() for line in output.splitlines() if "ERROR" in line]
            reason = errors[-1] if errors else _tail(output.strip(), 400)
            raise ScannerError(
                f"installing {self.tool_name} failed (exit {result.return_code}): {reason} "
                "(full log: agent/setup/stdout.txt)"
            )
        self._install = {**install, "work_dir": self._work_dir, "setup_seconds": seconds}

    async def run(self, instruction: str, environment: BaseEnvironment, context: AgentContext) -> None:
        meta: dict[str, Any] = {
            "agent": self.name(),
            "agent_version": self.version(),
            "tool": self.tool_name,
            "tool_version": self.tool_version(),
            "cwe_map": cwe_map.VERSION,
            "heuristics": heuristics.VERSION,
            "install": getattr(self, "_install", None),
            "model_ignored": self.model_name,
            "options_ignored": sorted((getattr(self.options, "model_extra", None) or {}).keys()),
            "instruction_sha256": hashlib.sha256(instruction.encode("utf-8")).hexdigest(),
        }
        # Set now and again at the end: Harbor keeps what is here even if the run fails.
        context.metadata = meta
        document = None
        try:
            settings = self._effective_settings(environment)
            meta["task"] = settings.describe()
            budget = self._scan_budget(settings)
            meta["scan_budget_sec"] = budget

            started = time.monotonic()
            findings = await self.scan(environment, settings, budget, meta)
            meta["scan_seconds"] = round(time.monotonic() - started, 1)

            built, stats = sarif.build(findings, tool_name=self.tool_name, tool_version=self.tool_version())
            meta.update(stats)
            meta["findings_security"] = len(findings)
            rows = [f.compact(rule) for f, rule in zip(findings, sarif.emitted_rules(findings))]
            meta["findings_compact_columns"] = ["tool_rule_id", "cwes", "file", "start_line", "end_line", "rule_id"]
            meta["findings_compact"] = rows[:MAX_COMPACT_FINDINGS]
            meta["findings_compact_truncated"] = len(rows) > MAX_COMPACT_FINDINGS

            await self._write_output(environment, built)
            document = built
            meta["status"] = "ok"
        except ScannerError as exc:
            meta["status"] = "error"
            meta["error"] = str(exc)
            raise
        except Exception as exc:
            meta["status"] = "error"
            meta["error"] = f"{type(exc).__name__}: {exc}"
            raise ScannerError(f"{self.tool_name} agent failed: {type(exc).__name__}: {exc}") from exc
        finally:
            context.metadata = meta
            await self._save_artifacts(environment, meta, document)

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _effective_settings(environment: BaseEnvironment) -> TaskSettings:
        """task.toml's scan settings, with the CPUs and memory the sandbox really
        has: Harbor writes any job-level override into ``task_env_config``."""
        settings = task_config.load(getattr(environment, "environment_dir", None))
        env_config = getattr(environment, "task_env_config", None)
        cpus = getattr(env_config, "cpus", None)
        memory = getattr(env_config, "memory_mb", None)
        return replace(
            settings,
            cpus=int(cpus) if cpus else settings.cpus,
            memory_mb=int(memory) if memory else settings.memory_mb,
        )

    def artifact_files(self) -> dict[str, str]:
        """Sandbox files to keep as trial artifacts: {artifact name: sandbox path}."""
        return {}

    async def _save_artifacts(
        self, environment: BaseEnvironment, meta: dict[str, Any], document: dict[str, Any] | None
    ) -> None:
        """Best effort, also after a failure: these are for people reading the
        trial, and a missing copy must not turn a good scan into an error."""
        saved, failed = [], []
        try:
            await environment.exec(f"mkdir -p {ARTIFACTS_DIR}", timeout_sec=60)
            uploads: dict[str, bytes] = {
                "metadata.json": json.dumps(meta, indent=2, default=str).encode("utf-8"),
            }
            if document is not None:
                uploads["findings.sarif"] = json.dumps(document, indent=2).encode("utf-8")
            setup_log = self.logs_dir / "setup" / "stdout.txt"
            if setup_log.is_file():
                uploads["install.log"] = setup_log.read_bytes()
            for name, data in uploads.items():
                try:
                    await self._upload_bytes(environment, data, f"{ARTIFACTS_DIR}/{name}")
                    saved.append(name)
                except Exception:
                    failed.append(name)
            for name, path in self.artifact_files().items():
                copied = await environment.exec(
                    f"test -f {path} && cp {path} {ARTIFACTS_DIR}/{name}", timeout_sec=120
                )
                (saved if copied.return_code == 0 else failed).append(name)
        except Exception as exc:
            failed.append(f"artifacts: {type(exc).__name__}: {exc}")
        meta["artifacts_saved"] = saved
        meta["artifacts_failed"] = failed

    def _scan_budget(self, settings: TaskSettings) -> float:
        override = getattr(self.options, "scan_budget_sec", None)
        if override:
            return float(override)
        if settings.agent_timeout_sec is None:
            return float(DEFAULT_SCAN_BUDGET_SEC)
        return max(float(MIN_SCAN_BUDGET_SEC), settings.agent_timeout_sec - TIMEOUT_MARGIN_SEC)

    async def _exec(
        self,
        environment: BaseEnvironment,
        command: str,
        *,
        timeout_sec: float,
        what: str,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        """environment.exec with our own time limit, failing as ScannerError.

        The environment enforces ``timeout_sec`` itself (Daytona wraps the command
        in ``timeout``); the outer wait is a backstop in case it does not.
        """
        try:
            result = await asyncio.wait_for(
                environment.exec(command, cwd=cwd, env=env, timeout_sec=int(timeout_sec)),
                timeout=timeout_sec + 30,
            )
        except asyncio.TimeoutError as exc:
            raise ScannerError(f"{what} did not finish within {int(timeout_sec)} s") from exc
        except ScannerError:
            raise
        except Exception as exc:
            if "timeout" in type(exc).__name__.lower() or "timed out" in str(exc).lower():
                raise ScannerError(f"{what} did not finish within {int(timeout_sec)} s: {exc}") from exc
            raise ScannerError(f"{what} could not run in the sandbox: {type(exc).__name__}: {exc}") from exc
        if result.return_code in (124, 137, 143):
            reason = "ran out of time" if result.return_code == 124 else "was killed (out of memory?)"
            raise ScannerError(
                f"{what} {reason} (exit {result.return_code}). Last output: {_tail(result.stdout or result.stderr, 600)}"
            )
        return result

    async def _existing_roots(self, environment: BaseEnvironment, roots: list[str], meta: dict[str, Any]) -> list[str]:
        """The scan roots that exist in /app/repo; missing ones are recorded, none is an error."""
        if roots == ["."]:
            return roots
        checks = "; ".join(
            f"if [ -e {shlex.quote(p)} ]; then echo OK {shlex.quote(p)}; else echo MISSING {shlex.quote(p)}; fi"
            for p in roots
        )
        result = await self._exec(environment, checks, timeout_sec=60, what="checking scan roots", cwd=REPO_DIR)
        present = [line[3:] for line in (result.stdout or "").splitlines() if line.startswith("OK ")]
        missing = [p for p in roots if p not in present]
        meta["scan_roots_missing"] = missing
        if not present:
            raise ScannerError(f"none of the scan roots exist in {REPO_DIR}: {', '.join(roots)}")
        return [p for p in roots if p in present]

    async def _nproc(self, environment: BaseEnvironment) -> int:
        result = await self._exec(environment, "nproc 2>/dev/null || echo 1", timeout_sec=60, what="counting CPUs")
        try:
            return max(1, int((result.stdout or "1").strip().splitlines()[0]))
        except (ValueError, IndexError):
            return 1

    async def _choose_work_dir(self, environment: BaseEnvironment) -> str:
        for candidate in WORK_DIR_CANDIDATES:
            probe = await self._exec(
                environment,
                f"mkdir -p {candidate}/out {candidate}/home && test -w {candidate} && echo writable",
                timeout_sec=60,
                what="preparing the work directory",
            )
            if probe.return_code == 0 and "writable" in (probe.stdout or ""):
                return candidate
        raise ScannerError(f"none of {', '.join(WORK_DIR_CANDIDATES)} is writable in the sandbox")

    async def _upload_bytes(self, environment: BaseEnvironment, data: bytes, target: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / Path(target).name
            local.write_bytes(data)
            try:
                await environment.upload_file(local, target)
            except Exception as exc:
                raise ScannerError(f"could not upload {target}: {exc}") from exc

    async def _download_bytes(self, environment: BaseEnvironment, source: str) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / Path(source).name
            try:
                await environment.download_file(source, local)
                return local.read_bytes()
            except Exception as exc:
                raise ScannerError(f"could not read {source} from the sandbox: {exc}") from exc

    async def _write_output(self, environment: BaseEnvironment, document: dict[str, Any]) -> None:
        data = json.dumps(document, indent=2).encode("utf-8")
        (self.logs_dir / "findings.sarif").write_bytes(data)
        await self._exec(environment, f"mkdir -p {OUTPUT_DIR}", timeout_sec=60, what="preparing /app/output")
        await self._upload_bytes(environment, data, OUTPUT_FILE)

    def _write_log(self, name: str, command: str, result: ExecResult, seconds: float) -> None:
        """agent/<name>/stdout.txt: one of the few trial files the platform keeps."""
        folder = self.logs_dir / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "stdout.txt").write_text(
            f"$ {command}\n"
            f"exit code: {result.return_code}   seconds: {seconds}\n\n"
            f"--- stdout ---\n{_tail(result.stdout)}\n\n"
            f"--- stderr ---\n{_tail(result.stderr)}\n",
            encoding="utf-8",
        )
