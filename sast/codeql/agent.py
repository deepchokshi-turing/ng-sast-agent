"""``sast.codeql.agent:CodeQLAgent``: CodeQL as a Harbor agent, no LLM.

Uses the CodeQL 2.27.1 bundle baked into the tools image at /opt/sast/codeql,
builds a Python database of /app/repo without a build (``--build-mode=none``),
runs the bundle's ``python-security-extended`` suite, maps each result to a task
ruleId by its CWE (``sast.cwe_map``) and writes /app/output/findings.sarif for
the task's verifier. CodeQL path queries report a real dataflow path, and that
path becomes the result's ``codeFlows``.

A scan that cannot be trusted is a ScannerError: no Python in scope, a failed
step, unusable SARIF, a lines-of-code metric that is 0 or missing, or an
error-level extraction notification on an in-scope file. Warnings, such as a
file CodeQL could not parse, are recorded in the metadata. The README's
"Failure policy" gives the evidence for that line.

Local use::

    PYTHONPATH=<this repo> harbor run -p <task> -a sast.codeql.agent:CodeQLAgent

CodeQL is used for research and experimentation only (see README.md).
"""

from __future__ import annotations

import json
import re
import shlex
import time
from pathlib import Path
from typing import Any, ClassVar

from harbor.environments.base import BaseEnvironment

from ..base import REPO_DIR, ScannerAgent
from ..errors import ScannerError
from ..findings import Finding
from ..scope import in_scope, task_scope
from ..task_config import TaskSettings
from . import pins
from .normalise import base_uris, normalise, repo_path
from .options import CodeQLOptions

_INSTALL_SCRIPT = Path(__file__).with_name("install.py")

CODEQL = f"{pins.INSTALL_DIR}/codeql"
SUITE = f"{pins.INSTALL_DIR}/{pins.SUITE_PATH}"
#: Left for the OS and the agent out of the sandbox memory.
RAM_RESERVE_MB = 512
RAM_FLOOR_MB = 1024
#: What the Python extractor reads. A scope without one of these is an error.
PYTHON_EXTENSIONS = (".py", ".pyi")
#: Enough to know the scope holds Python, without listing a huge repository.
MAX_LISTED_FILES = 20000
#: The metric query in python-security-extended that counts extracted lines.
LINES_OF_CODE_RULE = "py/summary/lines-of-code"
#: Notifications kept in the metadata, per level.
MAX_NOTIFICATIONS_KEPT = 50
#: Notification ids that mean CodeQL could not analyse the file they name (seen
#: with 2.27.1 on a file with a syntax error and on a file that is not UTF-8).
NOT_EXTRACTED_IDS = ("py/diagnostics/syntax-error", "py/diagnostics/extraction-warnings")


def ram_mb(memory_mb: int | None) -> int | None:
    """CodeQL's --ram: the sandbox memory minus 512 MB, never below 1024 MB.
    None when the task gives no memory size (CodeQL then sizes itself)."""
    if not memory_mb:
        return None
    return max(RAM_FLOOR_MB, int(memory_mb) - RAM_RESERVE_MB)


def extractor_paths(roots: list[str], files: set[str] | frozenset[str] = frozenset()) -> list[str] | None:
    """The ``paths`` CodeQL extracts, from the task's scanner roots.

    CodeQL 2.27.1's Python extractor walks every ``paths`` entry as a folder and
    crashes on a file (``NotADirectoryError`` on ``pyproject.toml``), so file
    roots are not written as such. A Python file root brings in its folder (the
    results outside the scope are dropped after the scan). Other files are not
    Python source and are left out. None means the whole repository.
    """
    if roots == ["."]:
        return None
    paths: list[str] = []
    for root in roots:
        root = root.strip("/")
        if root in files:
            if not root.endswith((".py", ".pyi")):
                continue
            root = root.rsplit("/", 1)[0] if "/" in root else "."
        if root in (".", ""):
            return None
        if root not in paths:
            paths.append(root)
    return paths


def codeql_config(roots: list[str], excludes: list[str], files: set[str] | frozenset[str] = frozenset()) -> dict[str, Any]:
    """The --codescanning-config document for the task scope.

    CodeQL anchors ``paths``/``paths-ignore`` at the source root. A plain name
    without a slash (``tests``) means that name at any depth in the Semgrep agent,
    so it is also written as ``**/<name>`` here to keep one meaning of the scope.
    ``files`` are the roots that are files, not folders (see ``extractor_paths``).
    """
    config: dict[str, Any] = {"name": "sast-agents task scope"}
    paths = extractor_paths(roots, files)
    if paths:
        config["paths"] = paths
    ignore: list[str] = []
    for path in excludes:
        path = path.strip("/")
        ignore.append(path)
        if "/" not in path:
            ignore.append(f"**/{path}")
    if ignore:
        config["paths-ignore"] = ignore
    return config


def create_command(db: str, config_file: str, threads: int, ram: int | None,
                   source_root: str = REPO_DIR, codeql: str = CODEQL) -> list[str]:
    return [
        codeql, "database", "create", db,
        "--language=python", "--build-mode=none",
        f"--source-root={source_root}",
        f"--codescanning-config={config_file}",
        f"--threads={threads}",
        *([f"--ram={ram}"] if ram else []),
        "--overwrite",
    ]


def analyze_command(db: str, output: str, threads: int, ram: int | None,
                    suite: str = SUITE, codeql: str = CODEQL) -> list[str]:
    return [
        codeql, "database", "analyze", db, suite,
        "--format=sarif-latest", f"--output={output}",
        f"--threads={threads}",
        *([f"--ram={ram}"] if ram else []),
    ]


def lines_of_code(document: dict[str, Any]) -> int | None:
    """CodeQL's own count of extracted Python lines (``py/summary/lines-of-code``),
    None when the SARIF does not carry the metric."""
    runs = document.get("runs") if isinstance(document, dict) else None
    for run in runs or []:
        for metric in ((run or {}).get("properties") or {}).get("metricResults") or []:
            rule = (metric or {}).get("ruleId") or ((metric or {}).get("rule") or {}).get("id")
            if rule == LINES_OF_CODE_RULE and isinstance(metric.get("value"), int):
                return metric["value"]
    return None


def extraction_report(document: dict[str, Any], roots: list[str], excludes: list[str]) -> dict[str, Any]:
    """What CodeQL said about extracting the code, from the run's toolExecutionNotifications.

    SARIF gives a notification without a ``level`` the level "warning", and that
    is how CodeQL 2.27.1 writes ``py/diagnostics/syntax-error`` and
    ``py/diagnostics/extraction-warnings``. Notes and "none" (telemetry, file
    lists, platform) are not kept. Each kept notification is placed in the repo
    and marked in or out of the task scope.

    Returns ``errors_in_scope`` (error level, naming a file in scope), ``errors``
    and ``warnings`` (all of that level, capped), and ``files_not_extracted``
    (in-scope files a ``NOT_EXTRACTED_IDS`` notification names).
    """
    errors_in_scope: list[dict[str, Any]] = []
    kept: dict[str, list[dict[str, Any]]] = {"error": [], "warning": []}
    counts = {"error": 0, "warning": 0}
    not_extracted: set[str] = set()
    for run in (document.get("runs") or [])[:1]:
        bases = base_uris(run or {})
        for invocation in (run or {}).get("invocations") or []:
            for note in (invocation or {}).get("toolExecutionNotifications") or []:
                if not isinstance(note, dict):
                    continue
                level = str(note.get("level") or "warning").lower()
                if level not in kept:
                    continue
                rule = str((note.get("descriptor") or {}).get("id") or "")
                files = []
                for location in note.get("locations") or []:
                    artifact = ((location or {}).get("physicalLocation") or {}).get("artifactLocation") or {}
                    file = repo_path(artifact, bases)
                    if file and file not in files:
                        files.append(file)
                scoped = [f for f in files if in_scope(f, roots, excludes)]
                row = {
                    "id": rule,
                    "files": files,
                    "in_scope": bool(scoped),
                    "message": " ".join(str((note.get("message") or {}).get("text") or "").split())[:300],
                }
                counts[level] += 1
                if len(kept[level]) < MAX_NOTIFICATIONS_KEPT:
                    kept[level].append(row)
                if level == "error" and scoped:
                    errors_in_scope.append(row)
                if rule in NOT_EXTRACTED_IDS:
                    not_extracted.update(scoped)
    return {
        "error_count": counts["error"],
        "warning_count": counts["warning"],
        "errors": kept["error"],
        "warnings": kept["warning"],
        "errors_in_scope": errors_in_scope,
        "files_not_extracted": sorted(not_extracted),
    }


_FATAL = re.compile(r"A fatal error occurred: .*")
_TIMESTAMP = re.compile(r"^\[\d{4}-\d\d-\d\d [\d:.]+\] (\[build-std(?:out|err)\] )?")
_TAGGED = re.compile(r"^(\[ERROR\]|ERROR:|Error:|FATAL:?)\s")
_EXCEPTION = re.compile(r"^[A-Za-z_][\w.]*(Error|Exception): \S")


def failure_reason(output: str) -> str:
    """The lines of a failed CodeQL step that say why it failed.

    Only real error lines count: CodeQL's "A fatal error occurred:" line, a line
    tagged ``[ERROR]``/``ERROR:``, and a Python exception line from the
    extractor (``NotADirectoryError: ...``). A line that merely contains the word
    (``0 errors``, a JAVA_TOOL_OPTIONS echo) is not one. The fatal line comes
    first, the last exception second as its cause. Without any of them, the
    output's last 400 characters are used.
    """
    fatal: list[str] = []
    tagged: list[str] = []
    exceptions: list[str] = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        match = _FATAL.search(line)
        if match:
            fatal.append(match.group(0))
            continue
        body = _TIMESTAMP.sub("", line)
        if _TAGGED.match(body):
            tagged.append(body)
        elif _EXCEPTION.match(body):
            exceptions.append(body)
    primary = fatal[-1] if fatal else (tagged[-1] if tagged else None)
    cause = exceptions[-1] if exceptions else None
    parts = [p[:300] for p in (primary, cause) if p]
    if parts:
        return "; ".join(parts)
    rest = "\n".join(line for line in (output or "").splitlines() if "JAVA_TOOL_OPTIONS" not in line).strip()
    return rest[-400:] or "no output"


def _shell(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


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
        return {
            "codeql_install.py": _INSTALL_SCRIPT.read_bytes(),
            "codeql_pins.json": json.dumps(pins.as_dict(), indent=2).encode("utf-8"),
        }

    def install_command(self, work_dir: str) -> str:
        return f"python3 {shlex.quote(work_dir + '/codeql_install.py')} {shlex.quote(work_dir + '/codeql_pins.json')}"

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
            raise ScannerError("setup() did not run: CodeQL was not checked")

        roots, excludes = task_scope(settings.scanner_roots, settings.excluded_paths)
        roots, files = await self._classify_roots(environment, roots, meta)
        python_files = await self._python_files(environment, roots, excludes, meta)
        if not python_files:
            raise ScannerError(
                f"no Python source in the scan scope (roots {roots}, excludes {excludes}): "
                "CodeQL would have nothing to analyse"
            )
        threads = settings.cpus or await self._nproc(environment)
        ram = ram_mb(settings.memory_mb)

        db = f"{work}/codeql-db"
        out = f"{work}/out"
        config_file = f"{work}/codeql-config.json"
        sarif_file = f"{out}/codeql.sarif"
        config = codeql_config(roots, excludes, files)
        await self._upload_bytes(environment, json.dumps(config, indent=2).encode("utf-8"), config_file)
        meta["scan"] = {
            "roots": roots,
            "excludes": excludes,
            "file_roots": sorted(files),
            "codeql_config": config,
            "threads": threads,
            "ram_mb": ram,
            "suite": pins.SUITE_PATH,
        }
        env = {"HOME": f"{work}/home"}

        deadline = time.monotonic() + budget_sec
        try:
            create = f"rm -f {shlex.quote(sarif_file)} && " + _shell(create_command(db, config_file, threads, ram))
            await self._run_step(environment, "command-1", create, "CodeQL database create", deadline, env, meta)
            analyze = _shell(analyze_command(db, sarif_file, threads, ram))
            await self._run_step(environment, "command-2", analyze, "CodeQL database analyze", deadline, env, meta)
            return await self._read_results(environment, sarif_file, roots, excludes, meta)
        finally:
            # Also after a failure, when CodeQL's own logs matter most.
            await self._pack_logs(environment, db, out, meta)

    async def _read_results(self, environment: BaseEnvironment, sarif_file: str, roots: list[str],
                            excludes: list[str], meta: dict[str, Any]) -> list[Finding]:
        raw = await self._download_bytes(environment, sarif_file)
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise ScannerError(f"CodeQL's SARIF output is unreadable: {exc}") from exc
        try:
            findings, counts = normalise(document)
        except ValueError as exc:
            raise ScannerError(str(exc)) from exc
        meta.update(counts)

        loc = lines_of_code(document)
        meta["lines_of_code"] = loc
        if loc is None:
            raise ScannerError(
                f"CodeQL's SARIF has no {LINES_OF_CODE_RULE} metric, so there is no telling whether any "
                "code was extracted (is the suite python-security-extended?)"
            )
        if loc == 0:
            raise ScannerError(
                f"CodeQL extracted no Python code (lines of code 0) although the scope has "
                f"{meta.get('python_files_in_scope')} Python files: the scan saw nothing"
            )

        report = extraction_report(document, roots, excludes)
        meta["codeql_extraction"] = report
        if report["errors_in_scope"]:
            first = report["errors_in_scope"][0]
            raise ScannerError(
                f"CodeQL reported {len(report['errors_in_scope'])} error-level extraction problem(s) in "
                f"in-scope files, so they were not analysed: {first['id']} on {', '.join(first['files'][:3])}: "
                f"{first['message']}"
            )

        kept = [f for f in findings if in_scope(f.file, roots, excludes)]
        meta["findings_out_of_scope"] = len(findings) - len(kept)
        return kept

    def artifact_files(self) -> dict[str, str]:
        work = getattr(self, "_work_dir", None)
        if not work:
            return {}
        return {
            "codeql-config.json": f"{work}/codeql-config.json",
            "codeql.sarif": f"{work}/out/codeql.sarif",
            "codeql-logs.tar.gz": f"{work}/out/codeql-logs.tar.gz",
        }

    async def _pack_logs(self, environment: BaseEnvironment, db: str, out: str, meta: dict[str, Any]) -> None:
        """The database's ``log`` and ``diagnostic`` folders, packed for the
        artifacts. Best effort: whatever happens here is recorded in
        ``meta["codeql_logs_packed"]`` and never fails the scan."""
        tar = shlex.quote(f"{out}/codeql-logs.tar.gz")
        command = (
            f"rm -f {tar}; cd {shlex.quote(db)} 2>/dev/null || exit 3; "
            'set --; for d in log diagnostic; do [ -d "$d" ] && set -- "$@" "$d"; done; '
            f'[ $# -gt 0 ] || exit 4; tar -czf {tar} "$@"'
        )
        try:
            result = await environment.exec(command, timeout_sec=120)
            meta["codeql_logs_packed"] = result.return_code == 0
        except Exception as exc:  # noqa: BLE001  artifacts never turn a scan into an error
            meta["codeql_logs_packed"] = f"{type(exc).__name__}: {exc}"

    async def _run_step(self, environment: BaseEnvironment, log_name: str, command: str, what: str,
                        deadline: float, env: dict[str, str], meta: dict[str, Any]) -> None:
        remaining = deadline - time.monotonic()
        if remaining < 1:
            raise ScannerError(f"no time left for {what}")
        started = time.monotonic()
        result = await self._exec(environment, command, timeout_sec=remaining, what=what, cwd=REPO_DIR, env=env)
        seconds = round(time.monotonic() - started, 1)
        self._write_log(log_name, command, result, seconds)
        meta["scan"][f"{log_name}_exit_code"] = result.return_code
        meta["scan"][f"{log_name}_seconds"] = seconds
        if result.return_code != 0:
            reason = failure_reason(f"{result.stdout or ''}\n{result.stderr or ''}")
            raise ScannerError(f"{what} exited {result.return_code}: {reason} (full log: agent/{log_name}/stdout.txt)")

    async def _classify_roots(
        self, environment: BaseEnvironment, roots: list[str], meta: dict[str, Any]
    ) -> tuple[list[str], set[str]]:
        """(roots that exist, the ones among them that are files). CodeQL needs
        to know which are files (see ``extractor_paths``), so this is a variant
        of ``ScannerAgent._existing_roots`` with the same failure rule."""
        if roots == ["."]:
            return roots, set()
        checks = "; ".join(
            f"if [ -d {shlex.quote(p)} ]; then echo DIR {shlex.quote(p)}; "
            f"elif [ -e {shlex.quote(p)} ]; then echo FILE {shlex.quote(p)}; else echo MISSING {shlex.quote(p)}; fi"
            for p in roots
        )
        result = await self._exec(environment, checks, timeout_sec=60, what="checking scan roots", cwd=REPO_DIR)
        kinds = {}
        for line in (result.stdout or "").splitlines():
            kind, _, path = line.partition(" ")
            if kind in ("DIR", "FILE"):
                kinds[path] = kind
        missing = [p for p in roots if p not in kinds]
        meta["scan_roots_missing"] = missing
        if len(missing) == len(roots):
            raise ScannerError(f"none of the scan roots exist in {REPO_DIR}: {', '.join(roots)}")
        present = [p for p in roots if p in kinds]
        return present, {p for p in present if kinds[p] == "FILE"}

    async def _python_files(self, environment: BaseEnvironment, roots: list[str], excludes: list[str],
                            meta: dict[str, Any]) -> list[str]:
        """Repo-relative Python files under the roots and inside the scope
        (at most MAX_LISTED_FILES are listed)."""
        names = " -o ".join(f"-name {shlex.quote('*' + ext)}" for ext in PYTHON_EXTENSIONS)
        targets = " ".join(shlex.quote(r) for r in roots)
        command = f"find {targets} -type f \\( {names} \\) 2>/dev/null | head -n {MAX_LISTED_FILES}"
        result = await self._exec(environment, command, timeout_sec=120, what="listing Python files", cwd=REPO_DIR)
        listed = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            while line.startswith("./"):
                line = line[2:]
            if line:
                listed.append(line)
        files = [f for f in listed if in_scope(f, roots, excludes)]
        meta["python_files_in_scope"] = len(files)
        meta["python_files_listing_capped"] = len(listed) >= MAX_LISTED_FILES
        return files
