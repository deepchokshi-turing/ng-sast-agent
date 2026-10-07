"""``sast.codeql.agent:CodeQLAgent``: CodeQL as a Harbor agent, no LLM.

Uses the pinned CodeQL bundle (``pins.py``), normally pre-installed in the
``sast-tools`` image, else installed at setup. For each language present in the
scan scope it builds a database with ``--build-mode=none`` (Python and
JavaScript/TypeScript need no build), runs the bundled ``security-extended``
suite, keeps the security results, maps each to a task ruleId by its CWE tags
(``sast.cwe_map``), and writes /app/output/findings.sarif. Path queries report
the dataflow path they found; it is passed through as ``codeFlows``. Nothing
else is added.

No custom queries and no extra source models: CodeQL tracks data from the
sources its libraries know (HTTP requests, files, environment, ...). Model
output is not one of them, so a flow that starts at an LLM reply is outside what
the stock tool sees. That is part of what this baseline measures.

Local use::

    PYTHONPATH=<this repo> harbor run -p <task> -a sast.codeql.agent:CodeQLAgent
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
from ..scope import ALWAYS_EXCLUDE, in_scope
from ..task_config import TaskSettings, repo_relative
from . import pins
from .normalise import normalise
from .options import CodeQLOptions

_INSTALL_SCRIPT = Path(__file__).with_name("install.py")
#: Files listed per language when deciding which languages are present.
MAX_LISTED_FILES = 50000


def codescanning_config(roots: list[str], excludes: list[str], directories: set[str] | None = None) -> dict[str, Any]:
    """CodeQL's ``paths``/``paths-ignore`` for the task's scope (see ``sast.scope``).

    CodeQL patterns are relative to the source root (/app/repo), so a path with
    "/" already means exactly that path. A bare name (``tests``) means that name
    at any depth, which CodeQL spells ``**/tests``.

    ``paths`` may only name directories: CodeQL's Python extractor walks each
    entry and fails on a file (NotADirectoryError). ``directories`` says which
    roots are directories (None: all are). File roots that are not source code
    (``pyproject.toml``, ``security_manifest.json``) hold nothing to analyse and
    are left out. If a file root *is* source code, ``paths`` is omitted (the whole
    repository is extracted) and the scope is enforced on the findings instead.
    """
    def pattern(path: str) -> str:
        path = path.strip("/")
        return path if "/" in path else f"**/{path}"

    config: dict[str, Any] = {"paths-ignore": [pattern(p) for p in [*excludes, *ALWAYS_EXCLUDE]]}
    if roots == ["."]:
        return config
    dirs = [r.strip("/") for r in roots if directories is None or r in directories]
    files = [r for r in roots if directories is not None and r not in directories]
    source_exts = tuple(ext for exts in pins.LANGUAGE_EXTENSIONS.values() for ext in exts)
    if any(f.endswith(source_exts) for f in files) or not dirs:
        return config  # whole repository; findings are filtered to the scope afterwards
    config["paths"] = dirs
    return config


def languages_present(files: list[str], roots: list[str], excludes: list[str]) -> dict[str, int]:
    """Supported languages with at least one source file in scope, and their file counts."""
    counts: dict[str, int] = {}
    for file in files:
        if not in_scope(file, roots, excludes):
            continue
        for language, extensions in pins.LANGUAGE_EXTENSIONS.items():
            if file.endswith(extensions):
                counts[language] = counts.get(language, 0) + 1
    return {lang: counts[lang] for lang in pins.SUITES if lang in counts}


class CodeQLAgent(ScannerAgent):
    options_model: ClassVar[type[CodeQLOptions]] = CodeQLOptions
    tool_name: ClassVar[str] = "codeql"

    @staticmethod
    def name() -> str:
        return "codeql-sast"

    def tool_version(self) -> str:
        return pins.CODEQL_VERSION

    # ------------------------------------------------------------ install

    def install_files(self) -> dict[str, bytes]:
        # Own file names: the work directory is shared with the Semgrep install.
        return {
            "codeql_install.py": _INSTALL_SCRIPT.read_bytes(),
            "codeql-pins.json": json.dumps(pins.as_dict(), indent=2).encode("utf-8"),
        }

    def install_command(self, work_dir: str) -> str:
        return (
            f"SAST_ROOT={shlex.quote(work_dir)} python3 {shlex.quote(work_dir + '/codeql_install.py')} "
            f"{shlex.quote(work_dir + '/codeql-pins.json')}"
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
            raise ScannerError("setup() did not run: CodeQL is not installed")
        options: CodeQLOptions = self.options  # type: ignore[assignment]
        deadline = time.monotonic() + budget_sec

        roots = [repo_relative(p, "scan_roots") for p in (options.scan_roots or settings.scanner_roots)] or ["."]
        excludes = [repo_relative(p, "exclude") for p in (options.exclude or settings.excluded_paths)]
        roots = await self._existing_roots(environment, roots, meta)

        languages = languages_present(await self._source_files(environment, roots), roots, excludes)
        meta["languages"] = languages
        if not languages:
            raise ScannerError(
                "no Python or JavaScript/TypeScript source in the scan scope "
                f"(roots {roots}, excludes {excludes}); CodeQL has nothing to analyse"
            )

        threads = options.threads or settings.cpus or await self._nproc(environment)
        ram = options.ram_mb
        if ram is None and settings.memory_mb and settings.memory_mb >= 1024:
            ram = settings.memory_mb - 512

        out = f"{work}/out"
        db = f"{out}/codeql-db"
        config_file = f"{out}/codeql-config.yml"
        config = codescanning_config(roots, excludes, await self._directories(environment, roots))
        # JSON is valid YAML, and CodeQL reads the file as YAML.
        await self._upload_bytes(environment, json.dumps(config, indent=2).encode("utf-8"), config_file)
        env = {"HOME": f"{work}/home"}
        tuning = ["--threads", str(threads), *(["--ram", str(ram)] if ram else [])]
        cli = f"{work}/codeql/codeql"
        meta["scan"] = {"roots": roots, "excludes": excludes, "config": config, "threads": threads, "ram_mb": ram}

        create = [
            cli, "database", "create", db, "--db-cluster", "--language=" + ",".join(languages),
            "--build-mode=none", "--source-root", REPO_DIR, "--codescanning-config", config_file,
            "--overwrite", *tuning,
        ]
        try:
            return await self._create_and_analyze(environment, create, languages, cli, db, out, tuning,
                                                  roots, excludes, deadline, env, meta)
        finally:
            await self._pack_logs(environment, out, meta)

    async def _create_and_analyze(
        self, environment: BaseEnvironment, create: list[str], languages: dict[str, int], cli: str, db: str,
        out: str, tuning: list[str], roots: list[str], excludes: list[str], deadline: float,
        env: dict[str, str], meta: dict[str, Any],
    ) -> list[Finding]:
        await self._step(environment, "command-1", "creating the CodeQL database", create, deadline, env, meta)

        findings: list[Finding] = []
        counts: dict[str, Any] = {}
        self._sarif_files = {}
        for n, language in enumerate(languages, start=2):
            sarif_file = f"{out}/codeql-{language}.sarif"
            analyze = [
                cli, "database", "analyze", f"{db}/{pins.DATABASE_DIRS[language]}", pins.SUITES[language],
                "--format=sarif-latest", "--output", sarif_file, f"--sarif-category={language}", *tuning,
            ]
            await self._step(environment, f"command-{n}", f"the CodeQL {language} analysis", analyze, deadline,
                             env, meta)
            self._sarif_files[f"codeql-{language}.sarif"] = sarif_file
            try:
                document = json.loads(await self._download_bytes(environment, sarif_file))
                found, c = normalise(document)
            except ValueError as exc:
                raise ScannerError(f"CodeQL's {language} SARIF is unreadable: {exc}") from exc
            loc = _lines_of_code(document)
            if loc == 0:
                raise ScannerError(f"CodeQL extracted no {language} code (lines of code 0); the scan saw nothing")
            counts[language] = {**c, "lines_of_code": loc}
            findings += found
        meta["per_language"] = counts
        meta["results_raw"] = sum(c["results_raw"] for c in counts.values())
        meta["findings_with_tool_flow"] = sum(c["findings_with_tool_flow"] for c in counts.values())

        # CodeQL applied the same scope through paths/paths-ignore; anything it
        # still reported outside it is dropped and counted.
        kept = [f for f in findings if in_scope(f.file, roots, excludes)]
        meta["findings_out_of_scope"] = len(findings) - len(kept)
        return kept

    def artifact_files(self) -> dict[str, str]:
        work = getattr(self, "_work_dir", None)
        files = dict(getattr(self, "_sarif_files", {}) or {})
        if work:
            files["codeql-config.yml"] = f"{work}/out/codeql-config.yml"
            files["codeql-logs.tar.gz"] = f"{work}/out/codeql-logs.tar.gz"
        return files

    async def _pack_logs(self, environment: BaseEnvironment, out: str, meta: dict[str, Any]) -> None:
        """CodeQL's own log folders (database create and analyze), packed for the
        artifacts. Best effort, also after a failure, when they matter most."""
        command = (
            f"cd {shlex.quote(out)} && rm -f codeql-logs.tar.gz && "
            "logs=$(find codeql-db -type d -name log 2>/dev/null) && "
            '[ -n "$logs" ] && tar czf codeql-logs.tar.gz $logs'
        )
        try:
            result = await environment.exec(command, timeout_sec=120)
            meta["codeql_logs_packed"] = result.return_code == 0
        except Exception as exc:  # artifacts must never turn a good scan into an error
            meta["codeql_logs_packed"] = f"{type(exc).__name__}: {exc}"

    async def _step(
        self,
        environment: BaseEnvironment,
        log_name: str,
        what: str,
        command: list[str],
        deadline: float,
        env: dict[str, str],
        meta: dict[str, Any],
    ) -> None:
        remaining = deadline - time.monotonic()
        if remaining < 10:
            raise ScannerError(f"no time left in the scan budget for {what}")
        shell = " ".join(shlex.quote(part) for part in command)
        started = time.monotonic()
        result = await self._exec(environment, shell, timeout_sec=remaining, what=what, cwd=REPO_DIR, env=env)
        seconds = round(time.monotonic() - started, 1)
        self._write_log(log_name, shell, result, seconds)
        meta.setdefault("steps", {})[log_name] = {"what": what, "exit_code": result.return_code, "seconds": seconds}
        if result.return_code != 0:
            tail = (result.stderr or result.stdout or "").strip().splitlines()[-5:]
            raise ScannerError(f"{what} failed (exit {result.return_code}): {' | '.join(tail)[:600]}")

    async def _directories(self, environment: BaseEnvironment, roots: list[str]) -> set[str]:
        """The scan roots that are directories (CodeQL ``paths`` accepts only those)."""
        checks = "; ".join(f"if [ -d {shlex.quote(p)} ]; then echo DIR {shlex.quote(p)}; fi" for p in roots)
        result = await self._exec(environment, checks, timeout_sec=60, what="checking scan roots", cwd=REPO_DIR)
        return {line[4:] for line in (result.stdout or "").splitlines() if line.startswith("DIR ")}

    async def _source_files(self, environment: BaseEnvironment, roots: list[str]) -> list[str]:
        """Repo-relative files with a supported extension under the roots (scope is applied by the caller)."""
        names = " -o ".join(f"-name {shlex.quote('*' + ext)}"
                            for exts in pins.LANGUAGE_EXTENSIONS.values() for ext in exts)
        targets = " ".join(shlex.quote(r) for r in roots)
        command = f"find {targets} -type f \\( {names} \\) 2>/dev/null | head -n {MAX_LISTED_FILES}"
        result = await self._exec(environment, command, timeout_sec=120, what="listing source files", cwd=REPO_DIR)
        files = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            while line.startswith("./"):
                line = line[2:]
            if line:
                files.append(line)
        return files


def _lines_of_code(document: dict[str, Any]) -> int | None:
    """CodeQL's own count of extracted lines of code, when the SARIF has it."""
    for run in document.get("runs") or []:
        for metric in (run.get("properties") or {}).get("metricResults") or []:
            rule = str(metric.get("ruleId") or "")
            if rule.endswith("/summary/lines-of-code") and isinstance(metric.get("value"), int):
                return metric["value"]
    return None
