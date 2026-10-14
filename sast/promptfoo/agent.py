"""``sast.promptfoo.agent:PromptfooCodeScanAgent``: Promptfoo Code Scanning
(``promptfoo code-scans run``) as a Harbor agent.

Promptfoo Code Scanning is a hosted service: the CLI (open source, pinned in
``pins.py`` and installed in the sandbox at setup) sends a git change set to
https://api.promptfoo.app, whose model reviews it and may read further files
through a filesystem MCP server the CLI runs locally. It reviews changes, not
repositories, so the sandbox runner (``scan.py``) copies the in-scope files to
a fresh directory outside /app/repo, makes them the whole change of a
two-commit git repository, and runs the CLI on that (``--base main --compare
scan -f json``). Nothing outside the copy is reachable by the service.

Configuration, read on the host:

- ``PROMPTFOO_API_KEY``: the Promptfoo API key (the variable promptfoo itself
  reads). Missing, the trial fails before anything runs.
- Options (``--ak key=value``, or ``PROMPTFOO_SCAN_<KEY>`` in the environment):
  ``mode`` (stock or scoped), ``timeout_sec``, ``min_severity``,
  ``diffs_only``, ``scan_roots``, ``exclude``. See options.py.

Scoped mode gives the task's output contract (the instruction Harbor passes to
``run``) to the service through ``--guidance-file``, with a fixed preamble that
asks for a parseable header at the start of every finding (``guidance.py``);
only that header is read (``normalise.py``). Stock mode passes no guidance, and
since promptfoo's findings carry no task ruleId, none of them can be scored:
they are recorded in the SARIF run properties and the metadata only.

A scan that did not finish (deadline), promptfoo failing on the code, an
unreadable response or a scan that saw no file is a tool outcome
(``sast.errors.ToolOutcome``): no SARIF, a normal return, scored 0. A missing
or refused key, an unreachable or busy service, or a broken git/MCP set-up is
an infrastructure failure (``ScannerError``).

The key is handled like the Claude review's: uploaded as a file into a mode
700 directory under the work dir, copied under umask 077 into a mode 600 file,
read by scan.py and handed to the promptfoo process only, as PROMPTFOO_API_KEY
in that child's own environment, and deleted when the scan ends, also after a
failure. It is never on a command line, in the exec env, in the metadata, a log
or an artifact, and all output that is kept is scrubbed of it.
"""

from __future__ import annotations

import json
import os
import shlex
import time
from pathlib import Path
from typing import Any, ClassVar

from harbor.environments.base import BaseEnvironment, ExecResult

from ..base import REPO_DIR, TIMEOUT_MARGIN_SEC, ScannerAgent, run_entry
from ..claude_review.agent import (
    EXEC_SLACK_SEC,
    KILL_AFTER_SEC,
    ClaudeReviewAgent,
    _result_line,
    _scrub,
    _sha256,
    bounded,
    budget_note,
    exec_timeout,
)
from ..errors import ScannerError, ToolOutcome
from ..findings import Finding
from ..scope import task_scope
from ..task_config import TaskSettings
from . import guidance, pins
from .normalise import normalise
from .options import PromptfooOptions

_HERE = Path(__file__).parent

#: The host variable with the API key, and the one promptfoo reads (``resolveBaseAuthCredentials``).
KEY_ENV = "PROMPTFOO_API_KEY"
KEY_DIR = "secret"
KEY_FILE = "promptfoo-key"
#: Under the work dir.
SCOPE_DIR = "scope-promptfoo"
TOOL_HOME = "home/promptfoo"
TOOL_CWD = "home/promptfoo-cwd"
RUNNER_HOME = "home/promptfoo-runner"
SCAN_OUT = "out/promptfoo_scan.json"
REQUEST_FILE = "out/promptfoo_request.json"
GUIDANCE_FILE = "out/promptfoo_guidance.txt"

#: Seconds of the budget kept for listing files and writing the key first.
PREPARE_RESERVE_SEC = 60
MIN_SCAN_SEC = 120
CLEANUP_SLICE_SEC = 30
#: More files than this in scope is refused.
MAX_FILES = 5000
#: Characters of promptfoo's review summary kept in the metadata and the run properties.
REVIEW_CHARS = 2000

SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

#: scan.py error code -> what it means for the person reading the trial.
ERROR_HINTS = {
    "no_key": "the key file could not be read in the sandbox",
    "auth": "the Promptfoo service refused PROMPTFOO_API_KEY",
    "network": "the sandbox cannot reach api.promptfoo.app. This agent needs HTTPS (websocket) egress from the "
               "task container",
    "service": "the Promptfoo service is busy or cancelled the scan",
    "git": "the scope's git repository could not be built or read",
    "mcp": "promptfoo could not start its filesystem MCP server",
    "scan_script": "the sandbox runner failed",
    "deadline": "the scan ran out of time",
    "tool_failed": "promptfoo failed on this repository",
    "bad_output": "promptfoo's response could not be read",
    "no_files": "promptfoo found no file to scan",
    "skipped": "promptfoo skipped the scan",
}

#: scan.py error code -> the tool outcome it is (``sast.errors``). Every other
#: code is an infrastructure failure and stays a ScannerError.
OUTCOME_CODES = {
    "deadline": "deadline",
    "tool_failed": "tool_crashed",
    "bad_output": "bad_review_output",
    "no_files": "tool_saw_nothing",
    "skipped": "tool_saw_nothing",
}


def key_problem(environ: Any = None) -> str | None:
    """Why the host's credential is unusable, else None. Only the name is looked at."""
    environ = os.environ if environ is None else environ
    if str(environ.get(KEY_ENV, "") or "").strip():
        return None
    return (f"{KEY_ENV} is not set on the host: the Promptfoo Code Scanning agent needs a Promptfoo API key "
            "(see README.md)")


class PromptfooCodeScanAgent(ScannerAgent):
    options_model: ClassVar[type[PromptfooOptions]] = PromptfooOptions
    tool_name: ClassVar[str] = "promptfoo-code-scan"

    # The Claude review agent's key-file, output and file-listing steps, reused as they are.
    _write_key = ClaudeReviewAgent._write_key
    _remove_key = ClaudeReviewAgent._remove_key
    _read_output = ClaudeReviewAgent._read_output
    _files_in_scope = ClaudeReviewAgent._files_in_scope

    @staticmethod
    def name() -> str:
        return "promptfoo-code-scan"

    @classmethod
    def preflight(cls, kwargs=None, env=None) -> None:
        """Before any trial is queued: valid options and a key on the host (never from --ae)."""
        super().preflight(kwargs, env)
        cls.parse_options(kwargs, env)
        problem = key_problem()
        if problem:
            raise ValueError(problem)

    def tool_version(self) -> str:
        return f"{pins.PROMPTFOO_VERSION}+node-{pins.NODE_VERSION}"

    @property
    def scan_options(self) -> PromptfooOptions:
        return self.options  # type: ignore[return-value]

    def model_metadata(self) -> dict[str, Any]:
        options = self.scan_options
        return {
            # The service picks the model; neither the CLI nor its response names it.
            "model": None,
            "model_source": "chosen by the Promptfoo Code Scanning service, not reported",
            "mode": options.mode,
            "auth_source": KEY_ENV,
            "harbor_model_name_ignored": self.model_name,
        }

    def sarif_driver_properties(self) -> dict[str, Any]:
        options = self.scan_options
        return {"mode": options.mode, "promptfooVersion": pins.PROMPTFOO_VERSION, "nodeVersion": pins.NODE_VERSION,
                "gitVersion": pins.GIT_VERSION, "minSeverity": options.min_severity or "promptfoo default (medium)",
                "diffsOnly": options.diffs_only, "headerFormat": guidance.HEADER_FORMAT,
                "scorable": options.mode == "scoped"}

    def guidance_for(self, instruction: str | None = None) -> tuple[str | None, str | None, Any]:
        """(guidance text, its source, the contract) in scoped mode; (None, None, None) in stock mode."""
        if self.scan_options.mode != "scoped":
            return None, None, None
        if instruction is None:
            instruction = getattr(self, "_instruction", None)
        parsed, source = guidance.contract_for(instruction)
        return guidance.guidance_text(parsed), source, parsed

    # ------------------------------------------------------------ install

    def install_files(self) -> dict[str, bytes]:
        return {
            "install.py": (_HERE / "install.py").read_bytes(),
            "scan.py": (_HERE / "scan.py").read_bytes(),
            "pins.json": json.dumps(pins.as_dict(), indent=2).encode("utf-8"),
            pins.PACKAGE_JSON: (_HERE / pins.NPM_DIR / pins.PACKAGE_JSON).read_bytes(),
            pins.PACKAGE_LOCK: (_HERE / pins.NPM_DIR / pins.PACKAGE_LOCK).read_bytes(),
        }

    def install_command(self, work_dir: str) -> str:
        return (
            "PY=python3; [ -x /opt/sast/venv/bin/python ] && PY=/opt/sast/venv/bin/python; "
            f'SAST_ROOT={shlex.quote(work_dir)} "$PY" {shlex.quote(work_dir + "/install.py")} '
            f"{shlex.quote(work_dir + '/pins.json')}"
        )

    # ------------------------------------------------------------ scan

    def _scan_budget(self, settings: TaskSettings) -> float:
        options = self.scan_options
        explicit = options.timeout_sec or options.scan_budget_sec
        return float(explicit) if explicit else super()._scan_budget(settings)

    def _credential(self) -> str:
        problem = key_problem()
        if problem:
            raise ScannerError(problem)
        return os.environ[KEY_ENV].strip()

    async def scan(
        self,
        environment: BaseEnvironment,
        settings: TaskSettings,
        budget_sec: float,
        meta: dict[str, Any],
    ) -> list[Finding]:
        key = self._credential()
        work = getattr(self, "_work_dir", None)
        install = getattr(self, "_install", None) or {}
        if work is None or not (install.get("node") and install.get("git") and install.get("promptfoo")):
            raise ScannerError("setup() did not run: promptfoo was not installed and checked")
        deadline = time.monotonic() + budget_sec
        options = self.scan_options
        record: dict[str, Any] = {
            "mode": options.mode,
            "promptfoo_version": pins.PROMPTFOO_VERSION,
            "node_version": pins.NODE_VERSION,
            "git_version": pins.GIT_DEB_VERSION,
            "min_severity": options.min_severity,
            "diffs_only": options.diffs_only,
            "auth_source": KEY_ENV,
            "api_host": "https://api.promptfoo.app (promptfoo default)",
            "header_format": guidance.HEADER_FORMAT,
            # Promptfoo's response reports no cost, token count or model.
            "cost_usd": None,
        }
        meta["promptfoo_scan"] = record
        note = budget_note(budget_sec, bool(options.timeout_sec or options.scan_budget_sec), settings.agent_timeout_sec)
        if note:
            record["harbor_limit_needed_sec"] = int(budget_sec) + TIMEOUT_MARGIN_SEC
            record["budget_note"] = note

        # 1. The scope: the files the service may see.
        roots, excludes = task_scope(options.scan_roots or settings.scanner_roots,
                                     options.exclude or settings.excluded_paths, "scan_roots", "exclude")
        roots = await self._existing_roots(environment, roots, meta)
        files = await self._files_in_scope(environment, roots, excludes)
        meta["scan"] = {"roots": roots, "excludes": excludes, "files_in_scope": len(files)}
        if not files:
            raise ScannerError("no file is in scope: nothing to scan")
        if len(files) > MAX_FILES:
            raise ToolOutcome("too_many_files",
                              f"{len(files)} files are in scope, more than the {MAX_FILES} this agent scans")

        # 2. The request: everything but the key.
        text, source, parsed = self.guidance_for()
        record["guidance_source"] = source
        record["guidance_sha256"] = _sha256(text) if text else None
        record["contract"] = parsed.describe() if parsed is not None else None
        rule_ids = tuple(r for r, _ in parsed.rules) if parsed is not None else None
        guidance_path = None
        if text:
            guidance_path = f"{work}/{GUIDANCE_FILE}"
            await self._upload_bytes(environment, text.encode("utf-8"), guidance_path)
        key_dir = f"{work}/{KEY_DIR}"
        key_file = f"{key_dir}/{KEY_FILE}"
        out_file = f"{work}/{SCAN_OUT}"
        left = deadline - time.monotonic() - PREPARE_RESERVE_SEC
        scan_seconds = left - KILL_AFTER_SEC - EXEC_SLACK_SEC
        if scan_seconds < MIN_SCAN_SEC:
            raise ScannerError(f"the scan budget ({int(budget_sec)} s) leaves {int(scan_seconds)} s for the scan")
        request = {
            "repo": REPO_DIR,
            "files": files,
            "scope_dir": f"{work}/{SCOPE_DIR}",
            "home": f"{work}/{TOOL_HOME}",
            "cwd": f"{work}/{TOOL_CWD}",
            "node": install["node"],
            "git": install["git"],
            "promptfoo": install["promptfoo"],
            "guidance_file": guidance_path,
            "min_severity": options.min_severity,
            "diffs_only": options.diffs_only,
            "budget_sec": int(scan_seconds),
        }
        request_bytes = json.dumps(request, indent=1).encode("utf-8")
        if key.encode() in request_bytes:  # a programming error
            raise ScannerError(f"refusing to upload a request that contains {KEY_ENV}")
        record["request_sha256"] = _sha256(request_bytes)
        request_file = f"{work}/{REQUEST_FILE}"
        await self._upload_bytes(environment, request_bytes, request_file)

        try:
            # Inside the try: a failed upload or protect step must still remove the file.
            await self._write_key(environment, key_dir, key_file, key, record)
            document = await self._run_scan(environment, key, install, request_file, key_file, out_file,
                                            scan_seconds, record)
        finally:
            await self._remove_key(environment, key_dir, record)

        response = document.get("response") or {}
        line_counts = {str(k): int(v) for k, v in (document.get("line_counts") or {}).items() if isinstance(v, int)}
        findings, counts = normalise(response.get("comments") or [], mode=options.mode, line_counts=line_counts,
                                     roots=roots, excludes=excludes, scope_dir=request["scope_dir"],
                                     **({"rule_ids": rule_ids} if rule_ids else {}))
        meta.update(counts)
        return findings

    async def _run_scan(
        self,
        environment: BaseEnvironment,
        key: str,
        install: dict[str, Any],
        request_file: str,
        key_file: str,
        out_file: str,
        seconds: float,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        work = self._work_dir
        python = install.get("python") or "python3"
        # No secret here: Harbor puts the env on the exec command line.
        env = {"HOME": f"{work}/{RUNNER_HOME}", "PATH": SYSTEM_PATH, "PYTHONDONTWRITEBYTECODE": "1"}
        command = (
            f"rm -f {shlex.quote(out_file)} && mkdir -p {shlex.quote(work + '/' + RUNNER_HOME)} && exec "
            + bounded(" ".join(shlex.quote(p) for p in [python, "-I", "-B", f"{work}/scan.py", "--request",
                                                         request_file, "--keyfile", key_file, "--out", out_file]),
                      seconds)
        )
        result = await self._run_logged(environment, "command-1", command, key, env=env,
                                        timeout_sec=exec_timeout(seconds), what="the Promptfoo code scan",
                                        cwd=REPO_DIR)
        record["scan_exit_code"] = result.return_code
        record["scan_result"] = _result_line(result.stdout or "", "SCAN_RESULT")
        document = await self._read_output(environment, out_file, key)
        if document is None:
            raise ScannerError("the scan runner exited {} without a readable result (full log: "
                               "agent/command-1/stdout.txt): {}".format(
                                   result.return_code, _scrub((result.stderr or result.stdout or "")[-400:], key)))
        self._record(document, record)
        error = document.get("error")
        if result.return_code != 0 or document.get("status") != "ok" or error:
            code = (error or {}).get("code") if isinstance(error, dict) else None
            message = (error or {}).get("message") if isinstance(error, dict) else str(error)
            hint = ERROR_HINTS.get(code or "", "the scan failed")
            text = _scrub(f"Promptfoo code scan: {hint} [{code or 'exit ' + str(result.return_code)}]: {message}", key)
            if code in OUTCOME_CODES:
                raise ToolOutcome(OUTCOME_CODES[code], text)
            raise ScannerError(text)
        return document

    @staticmethod
    def _record(document: dict[str, Any], record: dict[str, Any]) -> None:
        """What the run metadata keeps from the runner's result (findings are counted by the normaliser)."""
        response = document.get("response") if isinstance(document.get("response"), dict) else {}
        comments = response.get("comments") if isinstance(response.get("comments"), list) else []
        record.update({
            "scan_status": document.get("status"),
            "scan_error": document.get("error"),
            "scan_seconds": document.get("seconds"),
            "scope_copy": document.get("scope_copy"),
            "git": document.get("git"),
            "argv": document.get("argv"),
            "env_names": document.get("env_names"),
            "promptfoo": document.get("promptfoo"),
            "review": str(response.get("review") or "")[:REVIEW_CHARS] or None,
            "comments": len(comments),
            "batch_count": response.get("batchCount"),
            "success": response.get("success"),
        })

    def sarif_run_properties(self, meta: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
        """The base account, plus what the promptfoo normaliser dropped: findings
        with no valid task ruleId (all of them in stock mode), outside the scope or
        at a bad location, and the header fields it rejected."""
        props = super().sarif_run_properties(meta, findings)
        agent = props["sastAgent"]
        dropped = agent["dropped"]
        dropped["outOfScope"] = run_entry(meta.get("dropped_out_of_scope"), meta.get("dropped_out_of_scope_count"))
        dropped["badLocation"] = run_entry(meta.get("dropped_bad_location"), meta.get("dropped_bad_location_count"))
        dropped["noTaskRule"] = run_entry(meta.get("dropped_no_task_rule"), meta.get("dropped_no_task_rule_count"))
        dropped["pathSteps"] = run_entry(meta.get("path_steps_dropped"), meta.get("path_steps_dropped_count"))
        dropped["headerValues"] = run_entry(
            [*(f"RULE={v}" for v in meta.get("rule_ids_rejected") or []),
             *(f"CWE={v}" for v in meta.get("cwes_rejected") or []),
             *(meta.get("assessed_values_rejected") or []),
             *(f"RECS={v}" for v in meta.get("recommendations_rejected") or []),
             *(f"ROLE={v}" for v in meta.get("path_roles_rejected") or [])])
        record = meta.get("promptfoo_scan") or {}
        agent.update({
            "mode": self.scan_options.mode,
            "scorable": self.scan_options.mode == "scoped",
            "headerFormat": guidance.HEADER_FORMAT,
            "headers": meta.get("headers"),
            "guidanceSource": record.get("guidance_source"),
            "allClearComments": meta.get("comments_all_clear", 0),
            # Every comment promptfoo reported, emitted or not: [file, startLine, line, severity, text].
            "toolFindings": run_entry(meta.get("tool_findings"), meta.get("tool_findings_count")),
            "promptfooReview": (record.get("review") or "")[:1000] or None,
        })
        return props

    def artifact_files(self) -> dict[str, str]:
        work = getattr(self, "_work_dir", None)
        if not work:
            return {}
        files = {"promptfoo_scan.json": f"{work}/{SCAN_OUT}"}
        if self.scan_options.mode == "scoped":
            files["promptfoo_guidance.txt"] = f"{work}/{GUIDANCE_FILE}"
        return files

    # ------------------------------------------------------------ helpers

    async def _run_logged(
        self,
        environment: BaseEnvironment,
        log_name: str,
        command: str,
        key: str,
        *,
        env: dict[str, str],
        timeout_sec: float,
        what: str,
        cwd: str | None = None,
    ) -> ExecResult:
        """The scan exec (a tool step), logged with the key scrubbed. It is in neither the command nor the env."""
        if key in command or any(key in value for value in env.values()) or KEY_ENV in env:  # a programming error
            raise ScannerError(f"refusing to run a command whose command line or env contains {KEY_ENV}")
        started = time.monotonic()
        try:
            result = await self._exec(environment, command, timeout_sec=timeout_sec, what=what, cwd=cwd, env=env,
                                      scrub=lambda text: _scrub(text, key), tool_step=True)
        except ToolOutcome as exc:
            raise exc.with_message(_scrub(str(exc), key)) from None
        except ScannerError as exc:
            raise ScannerError(_scrub(str(exc), key)) from None
        clean = ExecResult(stdout=_scrub(result.stdout, key), stderr=_scrub(result.stderr, key),
                           return_code=result.return_code)
        self._write_log(log_name, command, clean, round(time.monotonic() - started, 1))
        return clean
