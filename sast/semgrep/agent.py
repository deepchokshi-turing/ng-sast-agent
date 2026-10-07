"""``sast.semgrep.agent:SemgrepAgent``: Semgrep OSS as a Harbor agent, no LLM.

Installs Semgrep 1.179.0 and the pinned semgrep-rules folders inside the task
sandbox, scans /app/repo, keeps the security findings, maps each to a task ruleId
by its CWE (``sast.cwe_map``), and writes /app/output/findings.sarif for the
task's verifier.

Local use::

    PYTHONPATH=<this repo> harbor run -p <task> -a sast.semgrep.agent:SemgrepAgent

On the eval platform, register ``sast.semgrep.agent:SemgrepAgent`` with this
repository's git source; see README.md. The platform requires a model on every
run; it is accepted and never called.
"""

from __future__ import annotations

import json
import shlex
import time
from pathlib import Path
from typing import Any, ClassVar

from harbor.environments.base import BaseEnvironment

from ..base import REPO_DIR, ScannerAgent
from ..errors import ScannerError
from ..findings import Finding
from ..scope import ALWAYS_EXCLUDE, in_scope, task_scope
from ..task_config import TaskSettings
from . import pins
from .normalise import normalise
from .options import SemgrepOptions

_INSTALL_SCRIPT = Path(__file__).with_name("install.py")
_MERGE_SCRIPT = Path(__file__).with_name("merge_rules.py")


#: ``in_scope`` and ``ALWAYS_EXCLUDE`` live in ``sast.scope`` now. They stay
#: importable from here for older imports (``from sast.semgrep.agent import in_scope``).
__all__ = ["ALWAYS_EXCLUDE", "SemgrepAgent", "in_scope", "scope_args"]


def scope_args(roots: list[str], excludes: list[str]) -> list[str]:
    """--include/--exclude for a scan of "." (the repository root).

    Semgrep matches these like .gitignore, relative to each scan target: a
    pattern with a slash is anchored to the target. So the scan target is always
    the repository root and every path is anchored with a leading "/", which
    makes ``src/vendor`` mean exactly /app/repo/src/vendor. A plain name without
    a slash (``tests``) keeps gitignore's meaning: that name at any depth.
    """
    args: list[str] = []
    if roots != ["."]:
        for root in roots:
            args += ["--include", "/" + root.strip("/")]
    for path in [*excludes, *ALWAYS_EXCLUDE]:
        args += ["--exclude", ("/" + path.strip("/")) if "/" in path.strip("/") else path]
    return args


class SemgrepAgent(ScannerAgent):
    options_model: ClassVar[type[SemgrepOptions]] = SemgrepOptions
    tool_name: ClassVar[str] = "semgrep"

    @staticmethod
    def name() -> str:
        return "semgrep-sast"

    def tool_version(self) -> str:
        return pins.SEMGREP_VERSION

    # ------------------------------------------------------------ install

    def install_files(self) -> dict[str, bytes]:
        return {
            "install.py": _INSTALL_SCRIPT.read_bytes(),
            "merge_rules.py": _MERGE_SCRIPT.read_bytes(),
            "pins.json": json.dumps(pins.as_dict(), indent=2).encode("utf-8"),
        }

    def install_command(self, work_dir: str) -> str:
        return (
            f"SAST_ROOT={shlex.quote(work_dir)} python3 {shlex.quote(work_dir + '/install.py')} "
            f"{shlex.quote(work_dir + '/pins.json')}"
        )

    # ------------------------------------------------------------ scan

    async def scan(
        self,
        environment: BaseEnvironment,
        settings: TaskSettings,
        budget_sec: float,
        meta: dict[str, Any],
    ) -> list[Finding]:
        work = getattr(self, "_work_dir", None)
        if work is None:
            raise ScannerError("setup() did not run: Semgrep is not installed")
        options: SemgrepOptions = self.options  # type: ignore[assignment]

        roots, excludes = task_scope(options.scan_roots or settings.scanner_roots,
                                     options.exclude or settings.excluded_paths, "scan_roots", "exclude")
        roots = await self._existing_roots(environment, roots, meta)

        jobs = options.jobs or settings.cpus or await self._nproc(environment)
        # --max-memory limits each job's semgrep-core, not the whole scan.
        max_memory = options.max_memory_mb
        if max_memory is None and settings.memory_mb and settings.memory_mb >= 1024:
            max_memory = max(256, (settings.memory_mb - 512) // jobs)

        ignore = await self._exec(
            environment, f"test -f {REPO_DIR}/.semgrepignore && echo repo || echo default",
            timeout_sec=60, what="checking .semgrepignore",
        )
        meta["semgrepignore"] = (ignore.stdout or "").strip() or "unknown"

        output_file = f"{work}/out/semgrep.json"
        command = [
            f"{work}/venv/bin/semgrep", "scan",
            "--metrics=off", "--disable-version-check", "--no-git-ignore", "--json", "--quiet",
            # No --dataflow-traces: Semgrep OSS 1.179.0 puts no trace in its JSON
            # without a login, so there is nothing to read (see normalise.py).
            # Merged per folder at install; ids already carry their original path.
            "--no-rewrite-rule-ids",
            *[arg for d in pins.RULES_DIRS for arg in ("--config", f"{work}/rules-merged/{d.replace('/', '_')}.yaml")],
            "--timeout", str(options.per_file_timeout_sec),
            "--jobs", str(jobs),
            *(["--max-memory", str(max_memory)] if max_memory else []),
            *scope_args(roots, excludes),
            "--output", output_file,
            ".",
        ]
        shell = f"rm -f {shlex.quote(output_file)} && " + " ".join(shlex.quote(part) for part in command)
        env = {
            "HOME": f"{work}/home",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_SEND_METRICS": "off",
            # Semgrep finds semgrep-core through PATH: ours first, never the image's.
            "PATH": f"{work}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
        meta["scan"] = {
            "roots": roots,
            "excludes": excludes,
            "jobs": jobs,
            "max_memory_mb": max_memory,
            "per_file_timeout_sec": options.per_file_timeout_sec,
        }

        started = time.monotonic()
        result = await self._exec(
            environment, shell, timeout_sec=budget_sec, what="the Semgrep scan", cwd=REPO_DIR, env=env
        )
        seconds = round(time.monotonic() - started, 1)
        self._write_log("command-1", shell, result, seconds)
        meta["scan"]["exit_code"] = result.return_code

        if result.return_code != 0:
            # Without --error, findings exit 0; any other code is a failed scan
            # (2 missing target, 7 bad config, ...), even though Semgrep still
            # writes a JSON with "results": [] that would read as a clean scan.
            raise ScannerError(
                f"Semgrep exited {result.return_code}: {await self._semgrep_errors(environment, output_file)}"
            )
        raw = await self._download_bytes(environment, output_file)
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise ScannerError(f"Semgrep's JSON output is unreadable: {exc}") from exc

        try:
            findings, counts = normalise(document)
        except ValueError as exc:
            raise ScannerError(str(exc)) from exc
        meta.update(counts)
        # Belt and braces: Semgrep's include/exclude matching is gitignore-like;
        # anything it still reported outside the task's scope is dropped and counted.
        kept = [f for f in findings if in_scope(f.file, roots, excludes)]
        meta["findings_out_of_scope"] = len(findings) - len(kept)
        return kept

    def artifact_files(self) -> dict[str, str]:
        work = getattr(self, "_work_dir", None)
        return {"semgrep.json": f"{work}/out/semgrep.json"} if work else {}

    async def _semgrep_errors(self, environment: BaseEnvironment, output_file: str) -> str:
        """Semgrep's own error messages, for the trial's error text."""
        try:
            document = json.loads(await self._download_bytes(environment, output_file))
        except (ScannerError, ValueError):
            return "no readable output (see agent/command-1/stdout.txt)"
        messages = [" ".join(str(e.get("message") or e.get("type") or "").split())[:300]
                    for e in document.get("errors") or [] if isinstance(e, dict)]
        return "; ".join(messages[:3]) or "no error details in its output"
