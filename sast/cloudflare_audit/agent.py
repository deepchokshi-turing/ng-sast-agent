"""``sast.cloudflare_audit.agent:CloudflareAuditAgent``: Cloudflare's
security-audit agent skill (cloudflare/security-audit-skill), run in Claude
Code, as a Harbor agent.

The skill is a set of Markdown instructions, a findings JSON schema and two
Node.js validators that turn a coding agent into an auditor: reconnaissance, a
coverage ledger, hunter sub-agents, independent verifier sub-agents, a
``findings.json`` of ``confirmed``, ``needs_validation`` and ``rejected``
records with ``entrypoint -> propagation -> sink`` traces and, for confirmed
records, a remediation, and a Markdown report. It is agent-neutral (any
harness with a Task-like sub-agent tool); this agent runs it in the Claude Code
CLI, pinned as for the Claude review, with the skill installed as a user skill.
See docs/cloudflare-audit-agent.md.

Configuration, read on the host:

- The credential: ``CLAUDE_CODE_OAUTH_TOKEN`` (a subscription token from
  ``claude setup-token``) or ``ANTHROPIC_API_KEY`` (option ``auth``, ``auto``
  by default: the API key when it is set, else the token). No credential fails
  the trial before anything runs.
- Options (``--ak key=value``, or ``CLOUDFLARE_AUDIT_<KEY>``): ``model``,
  ``mode`` (stock or scoped), ``auth``, ``profile``, ``agent_budget``,
  ``include_needs_validation``, ``max_turns``, ``max_budget_usd``,
  ``reasoning_effort``, ``timeout_sec``, ``attempts``, ``scan_roots``,
  ``exclude``. See options.py.

The credential is handled as in the Claude review: uploaded as a file into a
mode 700 directory under the work dir, copied under umask 077 into a mode 600
file, read by the driver and handed to the CLI process only (a token in its own
environment, an API key through an apiKeyHelper that reads the file), and
deleted when the audit ends, also after a failure. It is never on a command
line, in the exec env, in the metadata, a log or an artifact, and all output
that is kept is scrubbed of it.

An audit that did not deliver (the deadline, ``run_status`` other than
``complete``, no ``findings.json``, an unusable findings file, the CLI's turn or
budget limit, a prompt too long) is a tool outcome (``ToolOutcome``: no SARIF,
scored 0). A missing or refused credential, a wrong model, a closed network, a
CLI that would not take the agent's settings or offers no sub-agents are
infrastructure failures (``ScannerError``).
"""

from __future__ import annotations

import json
import os
import shlex
import time
from pathlib import Path
from typing import Any, ClassVar

from harbor.environments.base import BaseEnvironment, ExecResult
from harbor.models.trial.result import AgentInfo, ModelInfo

from .. import sarif
from ..base import REPO_DIR, TIMEOUT_MARGIN_SEC, ScannerAgent, run_entry
from ..claude_review import contract
from ..claude_review.agent import (
    CREDENTIAL_ENV,
    EXEC_SLACK_SEC,
    KILL_AFTER_SEC,
    ClaudeReviewAgent,
    _result_line,
    _scrub,
    _sha256,
    bounded,
    budget_note,
    choose_auth,
    exec_timeout,
)
from ..errors import ScannerError, ToolOutcome
from ..findings import Finding
from ..scope import task_scope
from ..task_config import TaskSettings
from . import normalise as normalise_module
from . import pins, request as request_module
from .normalise import normalise
from .options import CloudflareAuditOptions

_HERE = Path(__file__).parent

KEY_DIR = "secret-cloudflare"
#: auth mode -> the credential's file name in KEY_DIR.
CREDENTIAL_FILE = {"api_key": "anthropic-key", "oauth": "claude-oauth-token"}
SCOPE_DIR = "cloudflare-scope"
#: The skill's output root (outside the target); the audit writes into its run-1.
AUDIT_ROOT = "cloudflare-audit-out"
AUDIT_RUN = "run-1"
CLI_HOME = "home/cloudflare-audit"
DRIVER_OUT = "out/cloudflare_audit.json"
NETWORK_CHECK_URL = "https://api.anthropic.com/"

PREPARE_RESERVE_SEC = 60
MIN_DRIVER_SEC = 240
MAX_FILES = 5000
MAX_TOOL_USES_META = 500
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

#: driver error code -> what it means for the person reading the trial.
ERROR_HINTS = {
    "no_key": "the credential file could not be read in the sandbox",
    "network": "the sandbox cannot reach api.anthropic.com. This agent needs HTTPS egress from the task container",
    "api_auth": "Claude Code refused ANTHROPIC_API_KEY",
    "cli_oauth_refused": "the subscription token was refused. Run `claude setup-token` again and set the new token "
                         "in CLAUDE_CODE_OAUTH_TOKEN",
    "model_remapped": "Claude Code would run the audit on another model than the one requested. Choose the model "
                      "with --ak model=<model id>",
    "cli_auth": "Claude Code would not use the credential the agent gave it",
    "cli_settings": "Claude Code did not apply the agent's permission settings",
    "cli_init_missing": "Claude Code did not say which model and tools it used",
    "no_subagents": "Claude Code offers no sub-agent tool, which the skill needs",
    "skill_not_loaded": "Claude Code did not load the security-audit skill",
    "skill_missing": "the installed skill files do not match their pins",
    "cli_missing": "the Claude Code CLI cannot run",
    "cli_failed": "Claude Code failed on every attempt",
    "cli_limit": "Claude Code stopped at --max-turns or --max-budget-usd",
    "timeout": "the audit ran out of time",
    "deadline": "the audit ran out of time",
    "review_incomplete": "the skill did not record a complete audit (run_status)",
    "no_findings_file": "the audit ended without writing findings.json",
    "bad_findings": "findings.json is not a list of JSON objects",
    "prompt_too_long": "the audit does not fit the model's context window",
    "nothing_to_review": "none of the in-scope files could be read",
}

#: driver error code -> the tool outcome it is. Every other code stays a ScannerError.
OUTCOME_CODES = {
    "deadline": "deadline",
    "timeout": "deadline",
    "review_incomplete": "review_incomplete",
    "no_findings_file": "bad_review_output",
    "bad_findings": "bad_review_output",
    "cli_limit": "cli_limit",
    "prompt_too_long": "prompt_too_long",
}


class CloudflareAuditAgent(ScannerAgent):
    options_model: ClassVar[type[CloudflareAuditOptions]] = CloudflareAuditOptions
    tool_name: ClassVar[str] = "cloudflare-security-audit-skill"

    # The Claude review's sandbox helpers, reused as they are: the key file (mode 600 in a mode 700 folder, removed
    # in a finally), the file listing, reading the driver's result with a scrub backstop, the logged exec.
    _write_key = ClaudeReviewAgent._write_key
    _remove_key = ClaudeReviewAgent._remove_key
    _files_in_scope = ClaudeReviewAgent._files_in_scope
    _read_output = ClaudeReviewAgent._read_output
    _run_logged = ClaudeReviewAgent._run_logged
    _contract_gaps = staticmethod(ClaudeReviewAgent._contract_gaps)

    @staticmethod
    def name() -> str:
        return "cloudflare-security-audit"

    @classmethod
    def preflight(cls, kwargs=None, env=None) -> None:
        """Before any trial is queued: valid options and a credential on the host (never from --ae)."""
        super().preflight(kwargs, env)
        options = cls.parse_options(kwargs, env)
        auth, note = choose_auth(options.auth)
        if auth is None:
            raise ValueError(note.replace("Claude Code security review agent", "Cloudflare security-audit agent"))

    def tool_version(self) -> str:
        return f"{pins.SKILL_COMMIT[:7]}+claude-code-{pins.CLAUDE_CODE_VERSION}"

    # ------------------------------------------------------------ the model

    @property
    def audit_options(self) -> CloudflareAuditOptions:
        return self.options  # type: ignore[return-value]

    def audit_model(self) -> str:
        """--ak model, else Harbor's -m when it names an Anthropic model, else the default."""
        return self.audit_options.model or self.harbor_model("anthropic", ("claude-",)) or pins.DEFAULT_MODEL

    def model_source(self) -> str:
        if self.audit_options.model:
            return "option"
        return "harbor_model_name" if self.harbor_model("anthropic", ("claude-",)) else "default"

    def auth_mode(self) -> str | None:
        return choose_auth(self.audit_options.auth)[0]

    def to_agent_info(self) -> AgentInfo:
        return AgentInfo(name=self.name(), version=self.version() or "unknown",
                         model_info=ModelInfo(name=self.audit_model(), provider="anthropic"))

    def model_metadata(self) -> dict[str, Any]:
        options = self.audit_options
        return {
            "model": self.audit_model(),
            "model_source": self.model_source(),
            "mode": options.mode,
            "profile": options.profile,
            "agent_budget": options.agent_budget,
            "include_needs_validation": options.include_needs_validation,
            "auth": self.auth_mode(),
            "auth_source": CREDENTIAL_ENV.get(self.auth_mode() or ""),
            "reasoning_effort": options.reasoning_effort,
            "harbor_model_name": self.model_name,
            "harbor_model_name_used": self.model_source() == "harbor_model_name",
        }

    def usage_summary(self, meta: dict[str, Any]) -> dict[str, Any] | None:
        """The CLI's own reported cost (every attempt) and tokens (all models, sub-agents included)."""
        audit = meta.get("cloudflare_audit") if isinstance(meta.get("cloudflare_audit"), dict) else None
        if not audit:
            return None
        costs = [c for c in audit.get("attempt_cost_usd") or [] if isinstance(c, (int, float))]
        tokens = {"input": 0, "cache_read": 0, "cache_write": 0, "output": 0}
        for row in (audit.get("model_usage") or {}).values():
            if isinstance(row, dict):
                tokens["input"] += int(row.get("inputTokens") or 0)
                tokens["cache_read"] += int(row.get("cacheReadInputTokens") or 0)
                tokens["cache_write"] += int(row.get("cacheCreationInputTokens") or 0)
                tokens["output"] += int(row.get("outputTokens") or 0)
        if not costs and not any(tokens.values()):
            return None
        return {
            "n_input_tokens": tokens["input"] + tokens["cache_read"] + tokens["cache_write"],
            "n_cache_tokens": tokens["cache_read"],
            "n_output_tokens": tokens["output"],
            "cost_usd": round(sum(costs), 6) if costs else None,
            "cost_source": "Claude Code CLI reported cost (all attempts; with a subscription token this is the CLI's "
                           "list-price figure, not a charge); tokens: final CLI attempt, every model",
        }

    def sarif_driver_properties(self) -> dict[str, Any]:
        options = self.audit_options
        return {"model": self.audit_model(), "mode": options.mode, "profile": options.profile,
                "auth": self.auth_mode(), "reasoningEffort": options.reasoning_effort,
                "skillRepo": pins.SKILL_REPO, "skillCommit": pins.SKILL_COMMIT,
                "claudeCodeVersion": pins.CLAUDE_CODE_VERSION, "includeNeedsValidation":
                    options.include_needs_validation}

    def paths(self, work: str) -> dict[str, str]:
        root = f"{work}/{AUDIT_ROOT}"
        home = f"{work}/{CLI_HOME}"
        return {"scope_dir": f"{work}/{SCOPE_DIR}", "out_root": root, "out_dir": f"{root}/{AUDIT_RUN}",
                "home": home, "skill_dir": f"{home}/.claude/skills/{pins.SKILL_NAME}"}

    def audit_request(self, task_instruction: str | None = None, work: str = "/opt/sast") -> dict[str, Any]:
        """The prompt for this run, and where the scoped text came from."""
        options = self.audit_options
        if task_instruction is None:
            task_instruction = getattr(self, "_instruction", None)
        parsed = source = None
        if options.mode == "scoped":
            parsed = contract.parse(task_instruction)
            source = "task_instruction" if parsed is not None else "harness_constants"
        where = self.paths(work)
        prompt = request_module.build_prompt(options.mode, parsed, target=where["scope_dir"],
                                             out_dir=where["out_dir"], skill_dir=where["skill_dir"],
                                             profile=options.profile, budget=options.agent_budget)
        return {"prompt": prompt, "contract": parsed, "contract_source": source}

    # ------------------------------------------------------------ install

    def install_files(self) -> dict[str, bytes]:
        return {
            "cf_install.py": (_HERE / "install.py").read_bytes(),
            "cf_driver.py": (_HERE / "driver.py").read_bytes(),
            # The Claude review's installer and driver: these import their standard-library helpers.
            "ccsr_install.py": (_HERE.parent / "claude_review" / "install.py").read_bytes(),
            "ccsr_driver.py": (_HERE.parent / "claude_review" / "driver.py").read_bytes(),
            "cf_pins.json": json.dumps(pins.as_dict(), indent=2).encode("utf-8"),
        }

    def install_command(self, work_dir: str) -> str:
        return (
            "PY=python3; [ -x /opt/sast/venv/bin/python ] && PY=/opt/sast/venv/bin/python; "
            f'SAST_ROOT={shlex.quote(work_dir)} "$PY" {shlex.quote(work_dir + "/cf_install.py")} '
            f"{shlex.quote(work_dir + '/cf_pins.json')}"
        )

    # ------------------------------------------------------------ scan

    def _scan_budget(self, settings: TaskSettings) -> float:
        options = self.audit_options
        explicit = options.timeout_sec or options.scan_budget_sec
        return float(explicit) if explicit else super()._scan_budget(settings)

    def _credential(self) -> tuple[str, str, str]:
        """(auth mode, how it was chosen, the secret). The secret goes nowhere but the credential file."""
        auth, note = choose_auth(self.audit_options.auth)
        if auth is None:
            raise ScannerError(note.replace("Claude Code security review agent", "Cloudflare security-audit agent"))
        secret = os.environ.get(CREDENTIAL_ENV[auth], "").strip()
        if not secret:
            raise ScannerError(f"{CREDENTIAL_ENV[auth]} is not set on the host")
        return auth, note, secret

    async def scan(
        self,
        environment: BaseEnvironment,
        settings: TaskSettings,
        budget_sec: float,
        meta: dict[str, Any],
    ) -> list[Finding]:
        auth, auth_note, key = self._credential()
        work = getattr(self, "_work_dir", None)
        install = getattr(self, "_install", None) or {}
        if work is None or not install.get("claude") or not install.get("node") or not install.get("skill_dir"):
            raise ScannerError("setup() did not run: the audit tools were not checked")
        deadline = time.monotonic() + budget_sec
        options = self.audit_options
        audit: dict[str, Any] = {
            "mode": options.mode,
            "model": self.audit_model(),
            "profile": options.profile,
            "agent_budget": options.agent_budget,
            "include_needs_validation": options.include_needs_validation,
            "auth": auth,
            "auth_source": CREDENTIAL_ENV[auth],
            "auth_choice": auth_note,
            "skill_repo": pins.SKILL_REPO,
            "skill_commit": pins.SKILL_COMMIT,
            "claude_code_version_pinned": pins.CLAUDE_CODE_VERSION,
            "node_version_pinned": pins.NODE_VERSION,
            "attempts_allowed": options.attempts,
            "max_turns": options.max_turns,
            "max_budget_usd": options.max_budget_usd,
            "normaliser": normalise_module.VERSION,
        }
        meta["cloudflare_audit"] = audit
        note = budget_note(budget_sec, bool(options.timeout_sec or options.scan_budget_sec), settings.agent_timeout_sec)
        if note:
            audit["harbor_limit_needed_sec"] = int(budget_sec) + TIMEOUT_MARGIN_SEC
            audit["budget_note"] = note

        # 1. The scope: the files the audit is given.
        roots, excludes = task_scope(options.scan_roots or settings.scanner_roots,
                                     options.exclude or settings.excluded_paths, "scan_roots", "exclude")
        roots = await self._existing_roots(environment, roots, meta)
        files = await self._files_in_scope(environment, roots, excludes)
        meta["scan"] = {"roots": roots, "excludes": excludes, "files_in_scope": len(files)}
        if not files:
            raise ScannerError("no file is in scope: nothing to review")
        if len(files) > MAX_FILES:
            raise ToolOutcome("too_many_files",
                              f"{len(files)} files are in scope, more than the {MAX_FILES} this agent audits")

        # 2. The request: everything but the credential.
        built = self.audit_request(work=work)
        parsed = built["contract"]
        audit.update({
            "prompt_sha256": _sha256(built["prompt"]),
            "contract_source": built["contract_source"],
            "contract": parsed.describe() if parsed else None,
            "contract_ids_not_accepted": self._contract_gaps(parsed) if parsed else {},
        })
        key_dir = f"{work}/{KEY_DIR}"
        key_file = f"{key_dir}/{CREDENTIAL_FILE[auth]}"
        out_file = f"{work}/{DRIVER_OUT}"
        left = deadline - time.monotonic() - PREPARE_RESERVE_SEC
        driver_seconds = left - KILL_AFTER_SEC - EXEC_SLACK_SEC
        if driver_seconds < MIN_DRIVER_SEC:
            raise ScannerError(f"the scan budget ({int(budget_sec)} s) leaves {int(driver_seconds)} s for the audit")
        where = self.paths(work)
        request = {
            "repo": REPO_DIR,
            "files": files,
            "mode": options.mode,
            "model": self.audit_model(),
            "auth": auth,
            "profile": options.profile,
            "effort": options.reasoning_effort,
            "max_turns": options.max_turns,
            "max_budget_usd": options.max_budget_usd,
            "attempts": options.attempts,
            "budget_sec": int(driver_seconds),
            "prompt": built["prompt"],
            "scope_dir": where["scope_dir"],
            "out_root": where["out_root"],
            "out_dir": where["out_dir"],
            "home": where["home"],
            "skill_src": install["skill_dir"],
            "skill_files": dict(pins.SKILL_FILES),
            "claude": install["claude"],
            "node": install["node"],
            "network_check_url": NETWORK_CHECK_URL,
        }
        request_bytes = json.dumps(request, indent=1).encode("utf-8")
        if key.encode() in request_bytes:  # a programming error
            raise ScannerError(f"refusing to upload a request that contains {CREDENTIAL_ENV[auth]}")
        audit["request_sha256"] = _sha256(request_bytes)
        request_file = f"{work}/out/cloudflare_audit_request.json"
        await self._upload_bytes(environment, request_bytes, request_file)

        try:
            await self._write_key(environment, key_dir, key_file, key, audit)
            document = await self._run_driver(environment, key, install, request_file, key_file, out_file,
                                              driver_seconds, audit, CREDENTIAL_ENV[auth])
        finally:
            await self._remove_key(environment, key_dir, audit)

        line_counts = {str(k): int(v) for k, v in (document.get("line_counts") or {}).items() if isinstance(v, int)}
        findings, counts = normalise(document.get("findings") or [], document.get("annotations"), mode=options.mode,
                                     include_needs_validation=options.include_needs_validation,
                                     line_counts=line_counts, roots=roots, excludes=excludes)
        meta.update(counts)
        return findings

    async def _run_driver(self, environment: BaseEnvironment, key: str, install: dict[str, Any], request_file: str,
                          key_file: str, out_file: str, seconds: float, audit: dict[str, Any],
                          secret_name: str) -> dict[str, Any]:
        work = self._work_dir
        # No secret here: Harbor puts the env on the exec command line.
        env = {"PATH": SYSTEM_PATH, "PYTHONDONTWRITEBYTECODE": "1", "HOME": f"{work}/{CLI_HOME}"}
        command = (
            "PY=python3; [ -x /opt/sast/venv/bin/python ] && PY=/opt/sast/venv/bin/python; "
            f"rm -f {shlex.quote(out_file)} && mkdir -p {shlex.quote(work + '/out')}"
            " && exec "
            + bounded('"$PY" ' + " ".join(shlex.quote(p) for p in ["-I", "-B", f"{work}/cf_driver.py", "--request",
                                                                   request_file, "--keyfile", key_file,
                                                                   "--out", out_file]), seconds)
        )
        result = await self._run_logged(environment, "command-1", command, key, env=env,
                                        timeout_sec=exec_timeout(seconds), what="the Cloudflare security audit",
                                        cwd=REPO_DIR, secret_name=secret_name, tool_step=True)
        audit["driver_exit_code"] = result.return_code
        audit["driver_result"] = _result_line(result.stdout or "", "DRIVER_RESULT")
        document = await self._read_output(environment, out_file, key)
        if document is None:
            raise ScannerError("the audit driver exited {} without a readable result (full log: "
                               "agent/command-1/stdout.txt): {}".format(
                                   result.return_code, _scrub((result.stderr or result.stdout or "")[-400:], key)))
        self._record(document, audit)
        error = document.get("error")
        if result.return_code != 0 or document.get("status") != "ok" or error:
            code = (error or {}).get("code") if isinstance(error, dict) else None
            message = (error or {}).get("message") if isinstance(error, dict) else str(error)
            hint = ERROR_HINTS.get(code or "", "the audit failed")
            text = _scrub(f"Cloudflare security audit: {hint} [{code or 'exit ' + str(result.return_code)}]: "
                          f"{message}", key)
            if code in OUTCOME_CODES:
                raise ToolOutcome(OUTCOME_CODES[code], text)
            raise ScannerError(text)
        return document

    @staticmethod
    def _record(document: dict[str, Any], audit: dict[str, Any]) -> None:
        """What the run metadata keeps from the driver's result (no finding text)."""
        cli = document.get("cli") if isinstance(document.get("cli"), dict) else {}
        wrapper = cli.get("cli") if isinstance(cli.get("cli"), dict) else {}
        attempts = [a for a in (cli.get("attempts") or []) if isinstance(a, dict)]
        init = cli.get("init") if isinstance(cli.get("init"), dict) else {}
        findings = document.get("findings") if isinstance(document.get("findings"), list) else []
        verdicts: dict[str, int] = {}
        for record in findings:
            if isinstance(record, dict):
                verdicts[str(record.get("verdict"))] = verdicts.get(str(record.get("verdict")), 0) + 1
        metadata = document.get("run_metadata") if isinstance(document.get("run_metadata"), dict) else {}
        audit.update({
            "driver_status": document.get("status"),
            "driver_error": document.get("error"),
            "driver_seconds": document.get("seconds"),
            "claude_code_version": document.get("claude_code_version"),
            "network": document.get("network"),
            "cli_argv": document.get("cli_argv"),
            "cli_settings": document.get("cli_settings"),
            "cli_environment": document.get("cli_environment"),
            "environment_removed": document.get("environment_removed"),
            "cli_init": init,
            "cli_credential_source": init.get("apiKeySource"),
            "skill_loaded": (pins.SKILL_NAME in init["skills"]) if isinstance(init.get("skills"), list) else None,
            "prompt_bytes": cli.get("prompt_bytes"),
            "attempts": len(attempts),
            "attempt_outcomes": [{k: a.get(k) for k in ("exit_code", "seconds", "outcome", "reason")}
                                 for a in attempts],
            "attempt_cost_usd": [((a.get("wrapper") or {}).get("total_cost_usd")) for a in attempts],
            "total_cost_usd": wrapper.get("total_cost_usd"),
            "num_turns": wrapper.get("num_turns"),
            "duration_ms": wrapper.get("duration_ms"),
            "usage": wrapper.get("usage"),
            "model_usage": wrapper.get("modelUsage"),
            "session_id": wrapper.get("session_id"),
            "permission_denials_count": len(wrapper.get("permission_denials") or []),
            "permission_denials": (wrapper.get("permission_denials") or [])[:50],
            "scope_copy": document.get("scope_copy"),
            "not_text": document.get("not_text"),
            "paths_relativised": document.get("paths_relativised"),
            "tool_uses_count": cli.get("tool_uses_count"),
            "tool_uses_by_tool": _by_tool(cli.get("tool_uses") or []),
            "subagent_calls": sum(1 for t in cli.get("tool_uses") or [] if isinstance(t, dict)
                                  and t.get("tool") in ("Task", "Agent")),
            "tool_uses_refused": [t for t in cli.get("tool_uses") or [] if isinstance(t, dict) and t.get("refused")][:100],
            "tool_uses_refused_count": sum(1 for t in cli.get("tool_uses") or [] if isinstance(t, dict)
                                           and t.get("refused")),
            "tool_uses": (cli.get("tool_uses") or [])[:MAX_TOOL_USES_META],
            "tool_uses_outside_scope": cli.get("tool_uses_outside_scope") or [],
            "tool_uses_outside_scope_count": len(cli.get("tool_uses_outside_scope") or []),
            "outputs": document.get("outputs"),
            "output_status": document.get("output_status"),
            "validators": {k: {f: v.get(f) for f in ("ran", "exit_code", "passed", "reason")}
                           for k, v in (document.get("validators") or {}).items() if isinstance(v, dict)},
            "run_status": document.get("run_status"),
            "run_profile": metadata.get("profile"),
            "incomplete_reason": metadata.get("incomplete_reason"),
            "ledger": document.get("ledger"),
            "records_by_verdict": verdicts,
            "annotations_present": isinstance(document.get("annotations"), dict),
        })

    def sarif_run_properties(self, meta: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
        """The base account with this agent's own drops and re-mapping."""
        props = super().sarif_run_properties(meta, findings)
        agent = props["sastAgent"]
        dropped = agent["dropped"]
        dropped["outOfScope"] = run_entry(meta.get("dropped_out_of_scope"), meta.get("dropped_out_of_scope_count"))
        dropped["badLocation"] = run_entry(meta.get("dropped_bad_location"), meta.get("dropped_bad_location_count"))
        dropped["badRecord"] = run_entry(meta.get("dropped_records"), meta.get("dropped_records_count"))
        dropped["notReported"] = run_entry([[k, v] for k, v in (meta.get("records_skipped") or {}).items()],
                                           sum((meta.get("records_skipped") or {}).values()))
        dropped["traceDropped"] = run_entry(meta.get("traces_dropped"), meta.get("traces_dropped_count"))
        dropped["noAnnotation"] = run_entry(meta.get("records_without_annotation"),
                                            meta.get("records_without_annotation_count"))
        remapped = []
        for f, rule in zip(findings, sarif.emitted_rules(findings)):
            if rule and not f.task_rule:
                remapped.append({"fingerprint": dict(f.extra).get("fingerprint"), "cwe": list(f.cwes),
                                 "ruleId": rule, "location": f"{f.file}:{f.start_line}"})
        agent["remapped"] = run_entry(remapped)
        audit = meta.get("cloudflare_audit") or {}
        agent["toolUsesOutsideScope"] = run_entry([{k: t.get(k) for k in ("tool", "file_path", "path", "command")
                                                    if t.get(k)} for t in audit.get("tool_uses_outside_scope") or []
                                                   if isinstance(t, dict)])
        agent.update({"mode": self.audit_options.mode, "profile": self.audit_options.profile,
                      "contractSource": audit.get("contract_source"), "runStatus": audit.get("run_status"),
                      "recordsByVerdict": audit.get("records_by_verdict"), "validators": audit.get("validators"),
                      "endLineReplaced": meta.get("end_line_replaced")})
        return props

    def artifact_files(self) -> dict[str, str]:
        work = getattr(self, "_work_dir", None)
        if not work:
            return {}
        return {"cloudflare_audit.json": f"{work}/{DRIVER_OUT}"}


def _by_tool(uses: list[Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for use in uses:
        if isinstance(use, dict):
            out[str(use.get("tool"))] = out.get(str(use.get("tool")), 0) + 1
    return dict(sorted(out.items()))
