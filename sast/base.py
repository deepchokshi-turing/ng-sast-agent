"""What every scanner agent shares: install in the sandbox, scan, write the SARIF.

A scanner agent has no model. It installs its tool inside the task sandbox
(never on the worker, which has only Harbor), scans ``/app/repo``, and writes
``/app/output/findings.sarif`` for the task's verifier. Subclasses supply the
install files and the scan; this class owns the lifecycle, the time limits, the
logs the platform keeps, and the run metadata. The one model-backed agent
(``sast.claude_review``) also overrides ``model_metadata`` and ``to_agent_info``
so the run names the model it really called.

Failure policy (``sast.errors``): an infrastructure failure (install failed,
sandbox or Harbor trouble, a missing or refused credential, an unreachable API
or server, unreadable output) raises ``ScannerError``, so the trial is recorded
as errored and can be re-run instead of being graded as "found nothing". A tool
outcome (the scan budget ran out, the tool crashed on the code or analysed
none of it, the review said it was incomplete) is a ``ToolOutcome``: ``run``
records it as ``tool_outcome`` in the metadata, writes no SARIF and returns
normally, so Harbor runs the verifier and the grader scores the trial 0 on a
positive and on a negative task alike.
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
from typing import Any, Callable, ClassVar

from harbor.agents.base import BaseAgent
from harbor.agents.capabilities import AgentCapabilities
from harbor.environments.base import BaseEnvironment, ExecResult
from harbor.models.agent.context import AgentContext
from harbor.models.trial.result import AgentInfo

from . import __version__, cwe_map, heuristics, sarif, task_config
from .errors import ScannerError, ToolOutcome
from .findings import Finding
from .scope import in_scope
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
#: The scan stops this long before Harbor's agent timeout, so that the agent, not
#: Harbor, ends the run: it records why (``tool_outcome`` "deadline") and saves
#: its logs and artifacts, then returns without a SARIF. The verifier still runs
#: and scores the trial 0, exactly as it would after Harbor's own timeout.
TIMEOUT_MARGIN_SEC = 120
MIN_SCAN_BUDGET_SEC = 60
#: When the task sets no agent timeout, Harbor imposes none; cap the scan anyway.
DEFAULT_SCAN_BUDGET_SEC = 3600
#: The tools image manifest reader (sast/manifest.py). Uploaded next to every
#: installer as sast_manifest.py, which imports it (audit L6).
MANIFEST_READER = Path(__file__).with_name("manifest.py")
MANIFEST_READER_NAME = "sast_manifest.py"
#: Rows of the compact finding list kept in the run metadata.
MAX_COMPACT_FINDINGS = 5000
#: How much of a command's output goes into the logs the platform keeps.
LOG_TAIL_CHARS = 20000
#: Rows of each list in the SARIF's ``runs[0].properties`` (the full lists are in the metadata).
RUN_PROPERTY_ROWS = 20


def _count(value: Any) -> int:
    """A metadata count that may be an int, a list or a {kind: count} dict."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        return sum(v for v in value.values() if isinstance(v, int) and not isinstance(v, bool))
    if isinstance(value, list):
        return len(value)
    return 0


def run_entry(rows: Any, count: int | None = None) -> dict[str, Any]:
    """One entry of the SARIF's ``runs[0].properties``: a count and the first rows."""
    rows = list(rows or [])
    return {"count": len(rows) if count is None else count, "items": rows[:RUN_PROPERTY_ROWS]}


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
        files = {MANIFEST_READER_NAME: MANIFEST_READER.read_bytes(), **self.install_files()}
        for name, data in files.items():
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
            # MANIFEST.json of the tools image as the installer saw it: manifest
            # and tree digests, and whether this tool's files were rehashed.
            "image_manifest": (getattr(self, "_install", None) or {}).get("image_manifest"),
            **self.model_metadata(),
            "options_ignored": sorted((getattr(self.options, "model_extra", None) or {}).keys()),
            "instruction_sha256": hashlib.sha256(instruction.encode("utf-8")).hexdigest(),
        }
        # The task's instruction (its output contract), for an agent that builds its request from it.
        self._instruction = instruction
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

            built, stats = sarif.build(findings, tool_name=self.tool_name, tool_version=self.tool_version(),
                                       run_properties=self.sarif_run_properties(meta, findings))
            extra_driver = self.sarif_driver_properties()
            if extra_driver:
                built["runs"][0]["tool"]["driver"].setdefault("properties", {}).update(extra_driver)
            meta.update(stats)
            meta["findings_security"] = len(findings)
            rows = [f.compact(rule) for f, rule in zip(findings, sarif.emitted_rules(findings))]
            meta["findings_compact_columns"] = ["tool_rule_id", "cwes", "file", "start_line", "end_line", "rule_id"]
            meta["findings_compact"] = rows[:MAX_COMPACT_FINDINGS]
            meta["findings_compact_truncated"] = len(rows) > MAX_COMPACT_FINDINGS

            await self._write_output(environment, built)
            document = built
            meta["status"] = "ok"
        except ToolOutcome as exc:
            # Scored, not re-run: no SARIF, a normal return, and the verifier scores the trial 0.
            meta["status"] = "tool_outcome"
            meta["tool_outcome"] = {"reason": exc.reason, "message": str(exc)}
            meta["sarif_written"] = False
        except ScannerError as exc:
            meta["status"] = "error"
            meta["error"] = str(exc)
            raise
        except Exception as exc:
            meta["status"] = "error"
            meta["error"] = f"{type(exc).__name__}: {exc}"
            raise ScannerError(f"{self.tool_name} agent failed: {type(exc).__name__}: {exc}") from exc
        finally:
            self._report_usage(context, meta)
            context.metadata = meta
            await self._save_artifacts(environment, meta, document)

    def harbor_model(self, provider: str, bare_prefixes: tuple[str, ...]) -> str | None:
        """Harbor's ``-m`` as a model id this tool can call, else None.

        ``<provider>/<model>`` gives ``<model>`` when the provider is this tool's;
        a bare name is used when it starts with one of ``bare_prefixes``. Any
        other value (the platform names a model on every run, often another
        provider's) is ignored and recorded by the agent, never passed on."""
        name = (getattr(self, "model_name", None) or "").strip()
        if not name:
            return None
        if "/" in name:
            prefix, _, model = name.partition("/")
            if prefix.strip().lower() != provider:
                return None
            return model.strip() or None
        return name if name.startswith(bare_prefixes) else None

    def usage_summary(self, meta: dict[str, Any]) -> dict[str, Any] | None:
        """Tokens and cost of a model-backed scan, for Harbor's result fields:
        {n_input_tokens (cache included), n_cache_tokens, n_output_tokens,
        cost_usd, cost_source}. None for tools that call no model (the default)."""
        return None

    def _report_usage(self, context: AgentContext, meta: dict[str, Any]) -> None:
        """Copy usage_summary into the AgentContext (Harbor's agent_result) and the metadata."""
        try:
            usage = self.usage_summary(meta)
        except Exception as exc:  # reporting never fails a run
            meta["usage_summary_error"] = f"{type(exc).__name__}: {exc}"
            return
        if not usage:
            return
        meta["usage_summary"] = usage
        for field in ("n_input_tokens", "n_cache_tokens", "n_output_tokens", "cost_usd"):
            if usage.get(field) is not None:
                setattr(context, field, usage[field])

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

    def model_metadata(self) -> dict[str, Any]:
        """What the run metadata says about a model. A scanner calls none, so
        Harbor's ``-m`` is recorded as ignored. A model-backed agent overrides
        this (and ``to_agent_info``) to name the model it really used."""
        return {"model_ignored": self.model_name}

    def sarif_driver_properties(self) -> dict[str, Any]:
        """Extra ``tool.driver.properties`` for the SARIF (for example the model
        and mode of a model-backed agent). Never read by the grader."""
        return {}

    def artifact_files(self) -> dict[str, str]:
        """Sandbox files to keep as trial artifacts: {artifact name: sandbox path}."""
        return {}

    def sarif_run_properties(self, meta: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
        """``runs[0].properties`` of the SARIF: what was dropped or re-mapped between
        the tool's output and the results, as counts and the first
        ``RUN_PROPERTY_ROWS`` rows of each list (the full lists are in the run
        metadata). Never scored, and it does not change which results are written.

        ``unmappedCwe`` are the findings the SARIF writer leaves out because no
        CWE maps to a task ruleId; the rest comes from the normaliser's counts in
        ``meta``. A subclass adds its own (the Claude review adds the category
        map's re-mapping and the upstream filter's exclusions).
        """
        unmapped = sarif.unmapped_findings(findings)
        dropped: dict[str, Any] = {
            # No CWE of the finding maps to one of the task's ruleIds (cwe_map).
            "unmappedCwe": run_entry(sarif.unmapped_rows(unmapped)),
            # The CWEs point to more than one ruleId family.
            "ambiguousCwe": run_entry(meta.get("results_cwe_ambiguous")),
            # Reported outside the task's scanner roots, or under an excluded path.
            "outOfScope": run_entry(meta.get("findings_out_of_scope_items"),
                                    _count(meta.get("findings_out_of_scope"))),
            # No usable location (outside the repository, no line).
            "badLocation": run_entry([], _count(meta.get("results_outside_repo"))
                                     + _count(meta.get("results_without_line"))),
        }
        return {"sastAgent": {"agent": self.name(), "cweMap": cwe_map.VERSION, "dropped": dropped}}

    @staticmethod
    def _keep_in_scope(findings: list[Finding], roots: list[str], excludes: list[str],
                       meta: dict[str, Any]) -> list[Finding]:
        """The findings inside the task scope; the others are counted and listed in ``meta``."""
        kept = [f for f in findings if in_scope(f.file, roots, excludes)]
        out = [[f.tool_rule_id, list(f.cwes), f.file, f.start_line] for f in findings
               if not in_scope(f.file, roots, excludes)]
        meta["findings_out_of_scope"] = len(out)
        meta["findings_out_of_scope_items"] = out[:200]
        return kept

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
        scrub: Callable[[str], str] | None = None,
        tool_step: bool = False,
    ) -> ExecResult:
        """environment.exec with our own time limit, failing as ScannerError.

        ``tool_step`` marks the command that runs the tool on the repository
        (the scan itself, not a helper command): running out of time there is
        the tool not finishing within the scan budget, and being killed is the
        tool failing on the code, so both are a ``ToolOutcome`` ("deadline",
        "tool_killed") instead of an infrastructure error.

        The environment enforces ``timeout_sec`` itself (Daytona wraps the command
        in ``timeout``); the outer wait is a backstop in case it does not.
        ``scrub`` (a secret remover) is applied to the whole output before the
        error message keeps its tail: a secret cut in two at the cut point would
        no longer match afterwards.
        """
        try:
            result = await asyncio.wait_for(
                environment.exec(command, cwd=cwd, env=env, timeout_sec=int(timeout_sec)),
                timeout=timeout_sec + 30,
            )
        except asyncio.TimeoutError as exc:
            message = f"{what} did not finish within {int(timeout_sec)} s"
            raise (ToolOutcome("deadline", message) if tool_step else ScannerError(message)) from exc
        except ScannerError:
            raise
        except Exception as exc:
            if "timeout" in type(exc).__name__.lower() or "timed out" in str(exc).lower():
                message = f"{what} did not finish within {int(timeout_sec)} s: {exc}"
                raise (ToolOutcome("deadline", message) if tool_step else ScannerError(message)) from exc
            raise ScannerError(f"{what} could not run in the sandbox: {type(exc).__name__}: {exc}") from exc
        if result.return_code in (124, 137, 143):
            reason = "ran out of time" if result.return_code == 124 else "was killed (out of memory?)"
            output = result.stdout or result.stderr
            if scrub is not None:
                output = scrub(output or "")
            message = f"{what} {reason} (exit {result.return_code}). Last output: {_tail(output, 600)}"
            if tool_step:
                raise ToolOutcome("deadline" if result.return_code == 124 else "tool_killed", message)
            raise ScannerError(message)
        return result

    async def _existing_roots(self, environment: BaseEnvironment, roots: list[str], meta: dict[str, Any]) -> list[str]:
        """The scan roots that exist in /app/repo. Missing ones are recorded in
        ``meta["scan_roots_missing"]``, and none at all is a ScannerError."""
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
        """The sandbox's CPU count, 1 when it cannot be read."""
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
