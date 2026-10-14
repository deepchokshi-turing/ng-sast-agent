"""``sast.codex_security.agent:CodexSecurityAgent``: an OpenAI Codex security
review as a Harbor agent ("codex exec security review").

OpenAI's dedicated product, the Codex Security CLI (``@openai/codex-security``,
formerly Aardvark), is not what runs here: its scans need Codex Security access
on the OpenAI account, which a plain API key may not have (see
docs/codex-security-agent.md). This agent runs the open-source Codex CLI
(openai/codex, pinned in pins.py) non-interactively, ``codex exec``, with a
fixed security review prompt, a JSON output schema, Codex's read-only sandbox
and no approvals, on a copy of the in-scope files. The metadata and the SARIF
name the engine ``codex exec security review`` so its results are never read
as the Codex Security product's.

Configuration, read on the host:

- The credential: ``OPENAI_API_KEY`` or ``CODEX_API_KEY`` (option ``auth``).
  No credential fails the trial before anything runs.
- Options (``--ak key=value``, or ``CODEX_SECURITY_<KEY>``): ``model``,
  ``reasoning_effort``, ``mode`` (stock or scoped), ``auth``, ``sandbox``,
  ``timeout_sec``, ``attempts``, ``scan_roots``, ``exclude``. See options.py.

The key is handled like the Claude review's: uploaded as a file into a mode 700
directory under the work dir, copied under umask 077 into a mode 600 file,
read by the driver, which hands it to ``codex login --with-api-key`` on stdin
(Codex stores it in the private CODEX_HOME's auth.json, which the driver
deletes), and the key file is removed when the review ends, also after a
failure. The key is never on a command line, in the exec env, in the metadata,
a log or an artifact, and all output that is kept is scrubbed of it.

A review that did not deliver (the deadline, ``review_completed`` false, no
file reviewed, an answer that is not the schema's JSON, a prompt too long, codex
crashing) is a tool outcome (``ToolOutcome``: no SARIF, scored 0). A missing or
refused key, no quota, an unknown model, a closed network, a sandbox that
cannot run or repeated service errors are infrastructure failures
(``ScannerError``).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from pathlib import Path
from typing import Any, ClassVar

from harbor.environments.base import BaseEnvironment, ExecResult
from harbor.models.trial.result import AgentInfo, ModelInfo

from .. import pricing, sarif
from ..base import REPO_DIR, TIMEOUT_MARGIN_SEC, ScannerAgent, run_entry
from ..claude_review import contract
from ..claude_review.agent import (
    EXEC_SLACK_SEC,
    KILL_AFTER_SEC,
    ClaudeReviewAgent,
    _result_line,
    _sha256,
    bounded,
    budget_note,
    exec_timeout,
)
from ..errors import ScannerError, ToolOutcome
from ..findings import Finding
from ..scope import task_scope
from ..task_config import TaskSettings
from . import normalise as normalise_module
from . import pins, request as request_module
from .normalise import normalise
from .options import CodexSecurityOptions

_HERE = Path(__file__).parent

#: How the engine is named in the metadata and the SARIF.
ENGINE = "codex exec security review"
#: The host variables that may hold the key, by ``auth`` option.
KEY_ENVS = {"openai_api_key": "OPENAI_API_KEY", "codex_api_key": "CODEX_API_KEY"}
KEY_DIR = "secret-codex"
KEY_FILE = "openai-key"
SCOPE_DIR = "codex-scope"
#: Codex's HOME and CODEX_HOME, under the work dir (not under /tmp: Codex refuses to put its helpers there).
CLI_HOME = "home/codex-security"
DRIVER_OUT = "out/codex_security.json"
NETWORK_CHECK_URL = "https://api.openai.com/v1/models"

#: Seconds of the budget kept for listing files and writing the key first.
PREPARE_RESERVE_SEC = 60
MIN_DRIVER_SEC = 120
MAX_FILES = 5000
MAX_COMMANDS_META = 500
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#: OpenAI's masked form of a key in error messages (as the driver's MASKED_KEY).
MASKED_KEY = re.compile(r"\b(?:sk|org|proj)-[A-Za-z0-9_-]{0,12}\*{3,}[A-Za-z0-9_-]{0,8}")

#: driver error code -> what it means for the person reading the trial.
ERROR_HINTS = {
    "no_key": "the credential file could not be read in the sandbox",
    "network": "the sandbox cannot reach api.openai.com. This agent needs HTTPS egress from the task container",
    "api_auth": "the OpenAI API refused the key",
    "quota": "the OpenAI account has no quota or billing for this key",
    "rate_limited": "the OpenAI API kept rate-limiting the review",
    "model_unavailable": "the model is not available to this key (retired, misspelt or not enabled). Choose another "
                         "with --ak model=<model id>",
    "login_failed": "codex login --with-api-key did not store the key",
    "cli_missing": "the Codex CLI cannot run",
    "sandbox_unavailable": "Codex's read-only sandbox cannot run in this container. Under Harbor's Docker "
                           "environment add --extra-docker-compose harbor/codex-sandbox.compose.yaml, run where "
                           "unprivileged user namespaces are allowed, or opt in to --ak sandbox=container (see "
                           "docs/codex-security-agent.md)",
    "sandbox_failed": "every command the model ran failed in Codex's sandbox",
    "cli_failed": "codex exec failed on every attempt",
    "cli_crashed": "codex exec exited with an error and no answer",
    "bad_answer": "the model's final answer is not the schema's JSON",
    "timeout": "the review ran out of time",
    "deadline": "the review ran out of time",
    "review_incomplete": "the model said the review is incomplete",
    "files_reviewed_zero": "the model said it reviewed no file",
    "prompt_too_long": "the review does not fit the model's context window",
    "bad_findings": "the model's findings are not JSON objects",
    "nothing_to_review": "none of the in-scope files could be read",
}

#: driver error code -> the tool outcome it is. Every other code stays a ScannerError.
OUTCOME_CODES = {
    "deadline": "deadline",
    "timeout": "deadline",
    "review_incomplete": "review_incomplete",
    "files_reviewed_zero": "files_reviewed_zero",
    "prompt_too_long": "prompt_too_long",
    "bad_findings": "bad_review_output",
    "bad_answer": "bad_review_output",
    "cli_crashed": "tool_crashed",
}


def choose_auth(requested: str, environ: Any = None) -> tuple[str | None, str]:
    """(host variable name, how it was chosen). The name is None when the key is missing.
    Only the variable names are looked at here: no value is returned or recorded."""
    environ = os.environ if environ is None else environ

    def present(name: str) -> bool:
        return bool(str(environ.get(name, "") or "").strip())

    if requested in KEY_ENVS:
        name = KEY_ENVS[requested]
        return (name, f"auth={requested}") if present(name) else (
            None, f"auth={requested} needs {name}, which is not set on the host")
    if present("OPENAI_API_KEY"):
        return "OPENAI_API_KEY", "auth=auto: OPENAI_API_KEY is set"
    if present("CODEX_API_KEY"):
        return "CODEX_API_KEY", "auth=auto: CODEX_API_KEY is set, OPENAI_API_KEY is not"
    return None, ("neither OPENAI_API_KEY nor CODEX_API_KEY is set on the host: the Codex security review agent "
                  "needs an OpenAI API key (see docs/codex-security-agent.md)")


def scrub(text: str | None, key: str) -> str:
    text = text or ""
    if key:
        text = text.replace(key, "***")
    return MASKED_KEY.sub("***", text)


class CodexSecurityAgent(ScannerAgent):
    options_model: ClassVar[type[CodexSecurityOptions]] = CodexSecurityOptions
    tool_name: ClassVar[str] = "codex-exec-security-review"

    # The Claude review's sandbox helpers, reused as they are: the key file
    # (mode 600 in a mode 700 folder, removed in a finally), the file listing,
    # and reading the driver's result with a scrub backstop.
    _write_key = ClaudeReviewAgent._write_key
    _remove_key = ClaudeReviewAgent._remove_key
    _files_in_scope = ClaudeReviewAgent._files_in_scope
    _read_output = ClaudeReviewAgent._read_output
    _contract_gaps = staticmethod(ClaudeReviewAgent._contract_gaps)

    @staticmethod
    def name() -> str:
        return "codex-security-review"

    @classmethod
    def preflight(cls, kwargs=None, env=None) -> None:
        """Before any trial is queued: valid options and a key on the host (never from --ae)."""
        super().preflight(kwargs, env)
        options = cls.parse_options(kwargs, env)
        source, note = choose_auth(options.auth)
        if source is None:
            raise ValueError(note)

    def tool_version(self) -> str:
        return f"codex-cli-{pins.CODEX_VERSION}"

    # ------------------------------------------------------------ the model

    @property
    def review_options(self) -> CodexSecurityOptions:
        return self.options  # type: ignore[return-value]

    def review_model(self) -> str:
        """--ak model, else Harbor's -m when it names an OpenAI model, else Codex Security's default."""
        return self.review_options.model or self.harbor_model("openai", ("gpt-", "codex-")) or pins.DEFAULT_MODEL

    def model_source(self) -> str:
        if self.review_options.model:
            return "option"
        return "harbor_model_name" if self.harbor_model("openai", ("gpt-", "codex-")) else "default"

    def to_agent_info(self) -> AgentInfo:
        """The model this agent really calls, not Harbor's ``-m``."""
        return AgentInfo(name=self.name(), version=self.version() or "unknown",
                         model_info=ModelInfo(name=self.review_model(), provider="openai"))

    def model_metadata(self) -> dict[str, Any]:
        options = self.review_options
        return {
            "engine": ENGINE,
            "model": self.review_model(),
            "model_source": self.model_source(),
            "reasoning_effort": options.reasoning_effort,
            "mode": options.mode,
            "sandbox": options.sandbox,
            "auth_source": choose_auth(options.auth)[0],
            "harbor_model_name": self.model_name,
            "harbor_model_name_used": self.model_source() == "harbor_model_name",
        }

    def usage_summary(self, meta: dict[str, Any]) -> dict[str, Any] | None:
        """Codex reports tokens, not money: every attempt's usage, priced from the list table."""
        review = meta.get("codex_security") if isinstance(meta.get("codex_security"), dict) else None
        if not review:
            return None
        usages = [a.get("usage") for a in review.get("attempt_outcomes") or []
                  if isinstance(a, dict) and isinstance(a.get("usage"), dict)]
        if not usages and isinstance(review.get("usage"), dict):
            usages = [review["usage"]]
        if not usages:
            return None
        model = review.get("model") or self.review_model()
        tokens = {"input": 0, "cache_read": 0, "cache_write": 0, "output": 0}
        cost: float | None = 0.0
        for usage in usages:
            part, c = pricing.openai_usage_cost(model, usage)
            for k in tokens:
                tokens[k] += part[k]
            if any(part.values()):
                cost = None if c is None or cost is None else cost + c
        return {
            "n_input_tokens": tokens["input"],
            "n_cache_tokens": tokens["cache_read"],
            "n_output_tokens": tokens["output"],
            "cost_usd": round(cost, 6) if cost is not None else None,
            "cost_source": "estimate: Codex token usage (all attempts) x {} list price as of {}{}".format(
                model, pricing.PRICES_AS_OF, "" if cost is not None else " (model not in the price table)"),
        }

    def sarif_driver_properties(self) -> dict[str, Any]:
        options = self.review_options
        return {"engine": ENGINE, "model": self.review_model(), "reasoningEffort": options.reasoning_effort,
                "mode": options.mode, "sandbox": options.sandbox, "codexVersion": pins.CODEX_VERSION}

    def deny_paths(self, work: str) -> list[str]:
        """What the model's commands may not read in the read-only sandbox: the real repository, the key folder,
        Codex's own home (auth.json), the agent's request and result folder, and Harbor's /logs."""
        return [REPO_DIR, f"{work}/{KEY_DIR}", f"{work}/{CLI_HOME}/codex-home", f"{work}/out", "/logs"]

    def review_request(self, task_instruction: str | None = None, work: str = "/opt/sast") -> dict[str, Any]:
        """The prompt, schema and config for this run, and where the scoped text came from."""
        options = self.review_options
        if task_instruction is None:
            task_instruction = getattr(self, "_instruction", None)
        parsed = source = None
        if options.mode == "scoped":
            parsed = contract.parse(task_instruction)
            source = "task_instruction"
            if parsed is None:
                parsed, source = request_module.fallback_contract(), "harness_constants"
            prompt = request_module.scoped_prompt(parsed)
        else:
            prompt = request_module.stock_prompt()
        return {"prompt": prompt, "schema": request_module.output_schema(options.mode, parsed),
                "config_toml": request_module.config_toml(self.review_model(), options.sandbox,
                                                          options.reasoning_effort, deny=self.deny_paths(work)),
                "contract": parsed, "contract_source": source}

    # ------------------------------------------------------------ install

    def install_files(self) -> dict[str, bytes]:
        return {
            "codex_install.py": (_HERE / "install.py").read_bytes(),
            "codex_driver.py": (_HERE / "driver.py").read_bytes(),
            # The Claude review's driver: the Codex driver imports its standard-library helpers.
            "ccsr_driver.py": (_HERE.parent / "claude_review" / "driver.py").read_bytes(),
            "codex_pins.json": json.dumps(pins.as_dict(), indent=2).encode("utf-8"),
        }

    def install_command(self, work_dir: str) -> str:
        return (
            "PY=python3; [ -x /opt/sast/venv/bin/python ] && PY=/opt/sast/venv/bin/python; "
            f'SAST_ROOT={shlex.quote(work_dir)} "$PY" {shlex.quote(work_dir + "/codex_install.py")} '
            f"{shlex.quote(work_dir + '/codex_pins.json')}"
        )

    # ------------------------------------------------------------ scan

    def _scan_budget(self, settings: TaskSettings) -> float:
        options = self.review_options
        explicit = options.timeout_sec or options.scan_budget_sec
        return float(explicit) if explicit else super()._scan_budget(settings)

    def _credential(self) -> tuple[str, str, str]:
        """(host variable name, how it was chosen, the key). The key goes nowhere but the key file."""
        name, note = choose_auth(self.review_options.auth)
        if name is None:
            raise ScannerError(note)
        key = os.environ.get(name, "").strip()
        if not key:
            raise ScannerError(f"{name} is not set on the host")
        return name, note, key

    async def scan(
        self,
        environment: BaseEnvironment,
        settings: TaskSettings,
        budget_sec: float,
        meta: dict[str, Any],
    ) -> list[Finding]:
        auth_source, auth_note, key = self._credential()
        work = getattr(self, "_work_dir", None)
        install = getattr(self, "_install", None) or {}
        if work is None or not install.get("codex"):
            raise ScannerError("setup() did not run: the Codex CLI was not checked")
        deadline = time.monotonic() + budget_sec
        options = self.review_options
        review: dict[str, Any] = {
            "engine": ENGINE,
            "not_the_codex_security_product": True,
            "mode": options.mode,
            "model": self.review_model(),
            "reasoning_effort": options.reasoning_effort,
            "sandbox": options.sandbox,
            "auth_source": auth_source,
            "auth_choice": auth_note,
            "codex_version_pinned": pins.CODEX_VERSION,
            "attempts_allowed": options.attempts,
            "normaliser": normalise_module.VERSION,
            # Codex reports tokens, not money, and has no cost or turn cap: only the time limit bounds a run.
            # The estimate from the tokens is in usage_summary (and Harbor's cost_usd).
            "cost_usd": None,
        }
        meta["codex_security"] = review
        note = budget_note(budget_sec, bool(options.timeout_sec or options.scan_budget_sec), settings.agent_timeout_sec)
        if note:
            review["harbor_limit_needed_sec"] = int(budget_sec) + TIMEOUT_MARGIN_SEC
            review["budget_note"] = note

        # 1. The scope: the files the review is given.
        roots, excludes = task_scope(options.scan_roots or settings.scanner_roots,
                                     options.exclude or settings.excluded_paths, "scan_roots", "exclude")
        roots = await self._existing_roots(environment, roots, meta)
        files = await self._files_in_scope(environment, roots, excludes)
        meta["scan"] = {"roots": roots, "excludes": excludes, "files_in_scope": len(files)}
        if not files:
            raise ScannerError("no file is in scope: nothing to review")
        if len(files) > MAX_FILES:
            raise ToolOutcome("too_many_files",
                              f"{len(files)} files are in scope, more than the {MAX_FILES} this agent reviews")

        # 2. The request: everything but the key.
        built = self.review_request(work=work)
        parsed = built["contract"]
        review.update({
            "prompt_sha256": _sha256(built["prompt"]),
            "schema_sha256": _sha256(json.dumps(built["schema"], sort_keys=True)),
            "config_sha256": _sha256(built["config_toml"]),
            "contract_source": built["contract_source"],
            "sandbox_deny": self.deny_paths(work) if options.sandbox == "read-only" else [],
            "contract": parsed.describe() if parsed else None,
            "contract_ids_not_accepted": self._contract_gaps(parsed) if built["contract_source"] == "task_instruction"
            else {},
        })
        key_dir = f"{work}/{KEY_DIR}"
        key_file = f"{key_dir}/{KEY_FILE}"
        out_file = f"{work}/{DRIVER_OUT}"
        left = deadline - time.monotonic() - PREPARE_RESERVE_SEC
        driver_seconds = left - KILL_AFTER_SEC - EXEC_SLACK_SEC
        if driver_seconds < MIN_DRIVER_SEC:
            raise ScannerError(f"the scan budget ({int(budget_sec)} s) leaves {int(driver_seconds)} s for the review")
        home = f"{work}/{CLI_HOME}"
        request = {
            "repo": REPO_DIR,
            "files": files,
            "mode": options.mode,
            "model": self.review_model(),
            "reasoning_effort": options.reasoning_effort,
            "sandbox": options.sandbox,
            "attempts": options.attempts,
            "budget_sec": int(driver_seconds),
            "prompt": built["prompt"],
            "schema": built["schema"],
            "config_toml": built["config_toml"],
            "home": home,
            "codex_home": f"{work}/{CLI_HOME}/codex-home",
            "scope_dir": f"{work}/{SCOPE_DIR}",
            "codex": install["codex"],
            "network_check_url": NETWORK_CHECK_URL,
        }
        request_bytes = json.dumps(request, indent=1).encode("utf-8")
        if key.encode() in request_bytes:  # a programming error
            raise ScannerError(f"refusing to upload a request that contains {auth_source}")
        review["request_sha256"] = _sha256(request_bytes)
        request_file = f"{work}/out/codex_security_request.json"
        await self._upload_bytes(environment, request_bytes, request_file)

        try:
            await self._write_key(environment, key_dir, key_file, key, review)
            document = await self._run_driver(environment, key, request_file, key_file, out_file, driver_seconds,
                                              review, auth_source)
        finally:
            await self._remove_key(environment, key_dir, review)

        line_counts = {str(k): int(v) for k, v in (document.get("line_counts") or {}).items() if isinstance(v, int)}
        findings, counts = normalise((document.get("review") or {}).get("findings") or [], mode=options.mode,
                                     line_counts=line_counts, roots=roots, excludes=excludes)
        meta.update(counts)
        return findings

    async def _run_driver(self, environment: BaseEnvironment, key: str, request_file: str, key_file: str,
                          out_file: str, seconds: float, review: dict[str, Any], secret_name: str) -> dict[str, Any]:
        work = self._work_dir
        # No secret here: Harbor puts the env on the exec command line.
        env = {"PATH": SYSTEM_PATH, "PYTHONDONTWRITEBYTECODE": "1", "HOME": f"{work}/{CLI_HOME}"}
        command = (
            "PY=python3; [ -x /opt/sast/venv/bin/python ] && PY=/opt/sast/venv/bin/python; "
            f"rm -f {shlex.quote(out_file)} && mkdir -p {shlex.quote(work + '/' + CLI_HOME)} {shlex.quote(work + '/out')}"
            " && exec "
            + bounded('"$PY" ' + " ".join(shlex.quote(p) for p in ["-I", "-B", f"{work}/codex_driver.py", "--request",
                                                                   request_file, "--keyfile", key_file,
                                                                   "--out", out_file]), seconds)
        )
        if key in command or any(key in v for v in env.values()) or any(n in KEY_ENVS.values() for n in env):
            raise ScannerError(f"refusing to run a command whose command line or env contains {secret_name}")
        started = time.monotonic()
        try:
            result = await self._exec(environment, command, timeout_sec=exec_timeout(seconds),
                                      what="the Codex security review", cwd=REPO_DIR, env=env,
                                      scrub=lambda text: scrub(text, key), tool_step=True)
        except ToolOutcome as exc:
            raise exc.with_message(scrub(str(exc), key)) from None
        except ScannerError as exc:
            raise ScannerError(scrub(str(exc), key)) from None
        result = ExecResult(stdout=scrub(result.stdout, key), stderr=scrub(result.stderr, key),
                            return_code=result.return_code)
        self._write_log("command-1", command, result, round(time.monotonic() - started, 1))
        review["driver_exit_code"] = result.return_code
        review["driver_result"] = _result_line(result.stdout or "", "DRIVER_RESULT")
        document = await self._read_output(environment, out_file, key)
        if document is None:
            raise ScannerError("the review driver exited {} without a readable result (full log: "
                               "agent/command-1/stdout.txt): {}".format(
                                   result.return_code, scrub((result.stderr or result.stdout or "")[-400:], key)))
        self._record(document, review)
        error = document.get("error")
        if result.return_code != 0 or document.get("status") != "ok" or error:
            code = (error or {}).get("code") if isinstance(error, dict) else None
            message = (error or {}).get("message") if isinstance(error, dict) else str(error)
            hint = ERROR_HINTS.get(code or "", "the review failed")
            text = scrub(f"Codex security review: {hint} [{code or 'exit ' + str(result.return_code)}]: {message}", key)
            if code in OUTCOME_CODES:
                raise ToolOutcome(OUTCOME_CODES[code], text)
            raise ScannerError(text)
        return document

    @staticmethod
    def _record(document: dict[str, Any], review: dict[str, Any]) -> None:
        """What the run metadata keeps from the driver's result (no finding text, no command output)."""
        record = document.get("exec") if isinstance(document.get("exec"), dict) else {}
        answer = document.get("review") if isinstance(document.get("review"), dict) else {}
        review.update({
            "driver_status": document.get("status"),
            "driver_error": document.get("error"),
            "driver_seconds": document.get("seconds"),
            "codex_version": document.get("codex_version"),
            "network": document.get("network"),
            "login": document.get("login"),
            "sandbox_probe": document.get("sandbox_probe"),
            "exec_argv": document.get("exec_argv"),
            "codex_environment": document.get("codex_environment"),
            "codex_home_removed": document.get("codex_home_removed"),
            "scope_copy": document.get("scope_copy"),
            "not_text": document.get("not_text"),
            "paths_relativised": document.get("paths_relativised"),
            "thread_id": record.get("thread_id"),
            "usage": record.get("usage"),
            "attempts": len(record.get("attempts") or []),
            "attempt_outcomes": [{k: a.get(k) for k in ("exit_code", "seconds", "outcome", "reason", "usage")}
                                 for a in record.get("attempts") or [] if isinstance(a, dict)],
            "commands_count": record.get("commands_count"),
            "commands": (record.get("commands") or [])[:MAX_COMMANDS_META],
            "commands_outside_scope": record.get("commands_outside_scope") or [],
            "commands_outside_scope_count": len(record.get("commands_outside_scope") or []),
            "sandbox_failures": record.get("sandbox_failures"),
            "file_changes": record.get("file_changes"),
            "web_searches": record.get("web_searches"),
            "mcp_tool_calls": record.get("mcp_tool_calls"),
            "review_summary": document.get("review_summary"),
            "findings_raw": len(answer.get("findings") or []) if isinstance(answer.get("findings"), list) else 0,
        })

    def sarif_run_properties(self, meta: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
        """The base account with this agent's own drops and re-mapping (as the Claude review's)."""
        props = super().sarif_run_properties(meta, findings)
        agent = props["sastAgent"]
        dropped = agent["dropped"]
        dropped["outOfScope"] = run_entry(meta.get("dropped_out_of_scope"), meta.get("dropped_out_of_scope_count"))
        dropped["badLocation"] = run_entry(meta.get("dropped_bad_location"), meta.get("dropped_bad_location_count"))
        by_category = meta.get("unmapped_by_category") or {}
        dropped["categoryNotInMap"] = run_entry([[k, v] for k, v in by_category.items()],
                                                sum(v for v in by_category.values() if isinstance(v, int)))
        remapped = []
        for f, rule in zip(findings, sarif.emitted_rules(findings)):
            if rule and not f.task_rule:
                extra = dict(f.extra)
                remapped.append({"category": extra.get("category"), "cwe": list(f.cwes),
                                 "cweSource": extra.get("cweSource"), "ruleId": rule,
                                 "location": f"{f.file}:{f.start_line}"})
        agent["remapped"] = run_entry(remapped)
        review = meta.get("codex_security") or {}
        agent["commandsOutsideScope"] = run_entry([c.get("command") for c in review.get("commands_outside_scope") or []
                                                   if isinstance(c, dict)])
        agent.update({"engine": ENGINE, "mode": self.review_options.mode, "sandbox": self.review_options.sandbox,
                      "contractSource": review.get("contract_source"), "endLineReplaced": meta.get("end_line_replaced")})
        return props

    def artifact_files(self) -> dict[str, str]:
        work = getattr(self, "_work_dir", None)
        if not work:
            return {}
        return {"codex_security.json": f"{work}/{DRIVER_OUT}"}
