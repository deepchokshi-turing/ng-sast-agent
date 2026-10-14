"""``sast.claude_review.agent:ClaudeReviewAgent``: Anthropic's open-source
Claude Code security review (anthropics/claude-code-security-review) as a
Harbor agent.

Unlike the other agents this one calls a model, through the Claude Code CLI
for the review and (with an API key) the Anthropic API for the upstream
false-positive filter. It
runs the upstream library code from its own driver (``driver.py``) inside the
task sandbox, with no GitHub involved: the in-scope files of /app/repo are
reviewed as one pull request that adds them all. See README.md for setup.

Configuration, read on the host:

- The credential, one of:
  ``ANTHROPIC_API_KEY``, an API key for both stages, or
  ``CLAUDE_CODE_OAUTH_TOKEN``, a Claude subscription token made with
  ``claude setup-token``. That token works for Claude Code only, so with it
  the filter runs its regex rules only and the driver's API preflight is
  skipped. The ``auth`` option picks one (``auto`` by default: the API key
  when it is set, else the token). No credential fails the trial before
  anything runs.
- Options (``--ak key=value``, or ``CLAUDE_REVIEW_<KEY>`` in the environment):
  ``model``, ``filter_model``, ``mode`` (stock or scoped), ``auth``,
  ``filter``, ``max_turns``, ``max_budget_usd``, ``timeout_sec``,
  ``cli_share``, ``cli_attempts``, ``cli_auth``, ``scan_roots``, ``exclude``.
  See options.py.

Scoped mode builds its custom scan instructions from the task's own output
contract, the instruction text Harbor passes to ``run`` (``contract.py``), and
falls back to the bundled ``scoped_scan_instructions.txt`` only when the
instruction carries no contract. The review runs in a copy of the in-scope
files (``driver.make_scope_copy``), and every tool call of the CLI is kept.

A review that did not finish (deadline, ``review_completed`` false, no file
reviewed, the CLI's turn or budget limit, a prompt too long) is a tool outcome
(``sast.errors.ToolOutcome``): no SARIF, a normal return, scored 0. A missing or
refused credential, an unreachable API or a CLI that would not use the agent's
settings is an infrastructure failure (``ScannerError``).

The credential is handled like SonarQube's token: it is uploaded as a file into
a mode 700 directory under the work dir, copied under umask 077 into a mode 600
file, read by the driver and deleted when the review ends, also after a
failure. The driver hands an API key to the CLI through an apiKeyHelper in a
private settings file and to the filter in-process, and a subscription token
to the CLI process's own environment as CLAUDE_CODE_OAUTH_TOKEN, nowhere else.
The credential is never on a command line, in the exec env, in the metadata, a
log or an artifact, and all output that is kept is scrubbed of it.
"""

from __future__ import annotations

import hashlib
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
from ..errors import ScannerError, ToolOutcome
from ..findings import Finding
from ..scope import in_scope, repo_path, task_scope
from ..task_config import TaskSettings
from . import category_map, contract, pins
from .normalise import normalise
from .options import ClaudeReviewOptions

_HERE = Path(__file__).parent

#: The scoped mode's texts. The scan instructions are built at run time from the
#: task's instruction (``contract.py``); this bundled copy, written from the same
#: contract, is the fallback for an instruction that carries none. The filter
#: text is the upstream default minus two hard exclusions (FILTER_EXCLUSIONS_DROPPED).
SCAN_INSTRUCTIONS_FILE = _HERE / "scoped_scan_instructions.txt"
FILTER_INSTRUCTIONS_FILE = _HERE / "scoped_filter_instructions.txt"
#: The upstream filter's hard exclusions (claude_api_client.py, numbered as there)
#: that the scoped filter text leaves out, so scoped runs keep findings the stock
#: filter would drop. They are in the Claude API filter's prompt only, so they
#: matter only when that filter runs (filter mode "claude").
FILTER_EXCLUSIONS_DROPPED = (
    {"upstream_number": 7, "text": "A lack of hardening measures. Code is not expected to implement all security "
                                   "best practices, just avoid obvious vulnerabilities."},
    {"upstream_number": 14, "text": "Including user-controlled content in AI system prompts is not a "
                                    "vulnerability. In general, the inclusion of user input in an AI prompt is "
                                    "not a vulnerability."},
)
#: The CLI runs in this copy of the in-scope files, under the work dir.
SCOPE_DIR = "scope"
#: Tool call records kept in the run metadata (all of them are in claude_review.json).
MAX_TOOL_USES_META = 500

KEY_ENV = "ANTHROPIC_API_KEY"
OAUTH_ENV = "CLAUDE_CODE_OAUTH_TOKEN"
#: auth mode -> the host variable that holds its credential.
CREDENTIAL_ENV = {"api_key": KEY_ENV, "oauth": OAUTH_ENV}
KEY_DIR = "secret"
KEY_FILE = "anthropic-key"
OAUTH_FILE = "claude-oauth-token"
#: auth mode -> the credential's file name in KEY_DIR.
CREDENTIAL_FILE = {"api_key": KEY_FILE, "oauth": OAUTH_FILE}
#: The CLI's HOME (its settings.json, auto-memory), under the work dir.
CLI_HOME = "home/claude-review"
DRIVER_OUT = "out/claude_review.json"

#: ``timeout -k``: seconds between SIGTERM and SIGKILL.
KILL_AFTER_SEC = 10
EXEC_SLACK_SEC = 5
#: Seconds of the budget kept for listing files and writing the key first.
PREPARE_RESERVE_SEC = 60
MIN_DRIVER_SEC = 120
CLEANUP_SLICE_SEC = 30
#: More files than this in scope is refused (the prompt would be meaningless).
MAX_FILES = 5000

SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

#: driver error code -> what it means for the person reading the trial.
ERROR_HINTS = {
    "no_key": "the credential file could not be read in the sandbox",
    "network": "the sandbox cannot reach api.anthropic.com. This agent needs HTTPS egress from the task container",
    "api_auth": "the API refused ANTHROPIC_API_KEY",
    "model_unavailable": "the model is not available (retired or misspelt?)",
    "cli_failed": "Claude Code did not produce a usable review",
    "cli_limit": "Claude Code stopped at --max-turns or --max-budget-usd",
    "timeout": "the review ran out of time",
    "deadline": "the review ran out of time",
    "review_incomplete": "the model said the review is incomplete",
    "files_reviewed_zero": "the model said it reviewed no file",
    "filter_validation": "the false-positive filter could not reach the API",
    "filter_call_failed": "a per-finding filter call failed",
    "model_remapped": "Claude Code would run the review on another model than the one requested. Choose the "
                      "model with --ak model=<model id> (or CLAUDE_REVIEW_MODEL=<model id>) and run again",
    "cli_auth": "Claude Code would not use the credential the agent gave it",
    "cli_oauth_refused": "the subscription token was refused. Run `claude setup-token` again and set the new "
                         "token in CLAUDE_CODE_OAUTH_TOKEN",
    "oauth_filter": "the Claude filter needs an API key, and this run has a subscription token only",
    "cli_settings": "Claude Code did not apply the agent's tool restrictions",
    "cli_init_missing": "Claude Code did not say which model and tools it used",
    "prompt_too_long": "the review prompt is too long even without the diff",
    "bad_findings": "the model's findings are not JSON objects",
}

#: driver error code -> the tool outcome it is (``sast.errors``). Every other code
#: is an infrastructure failure and stays a ScannerError.
OUTCOME_CODES = {
    "deadline": "deadline",
    "timeout": "deadline",
    "review_incomplete": "review_incomplete",
    "files_reviewed_zero": "files_reviewed_zero",
    "cli_limit": "cli_limit",
    "prompt_too_long": "prompt_too_long",
    "bad_findings": "bad_review_output",
}


def budget_note(budget_sec: float, explicit: bool, task_timeout_sec: float | None) -> str | None:
    """A note when an explicit review time needs a longer Harbor limit than task.toml gives, else None.

    Harbor applies --agent-timeout-multiplier (and --agent-timeout) to task.toml's
    agent timeout but does not tell the agent the result (0.23 and 0.24 pass it
    only to the oracle agent), so the effective limit cannot be checked here. The
    budget the agent derives itself always fits task.toml, so only an explicit
    ``timeout_sec`` above it gets the note. The note is a reminder, not an error.
    """
    if not explicit or task_timeout_sec is None or budget_sec + TIMEOUT_MARGIN_SEC <= task_timeout_sec:
        return None
    return (f"timeout_sec={int(budget_sec)} is more than task.toml's agent timeout of {int(task_timeout_sec)} s "
            f"allows. Harbor's own limit (task.toml times --agent-timeout-multiplier) must be at least "
            f"{int(budget_sec) + TIMEOUT_MARGIN_SEC} s, or Harbor stops the review first. The agent cannot "
            "see that limit, so it is not checked")


def choose_auth(requested: str, environ: Any = None) -> tuple[str | None, str]:
    """(auth mode, how it was chosen). The mode is None when the credential it
    needs is missing on the host, and the second value then says what is missing.

    Only the variable names are looked at here: no value is returned or recorded.
    """
    environ = os.environ if environ is None else environ
    has_key = bool(str(environ.get(KEY_ENV, "") or "").strip())
    has_token = bool(str(environ.get(OAUTH_ENV, "") or "").strip())
    if requested == "api_key":
        return ("api_key", "auth=api_key") if has_key else (
            None, f"auth=api_key needs {KEY_ENV}, which is not set on the host")
    if requested == "oauth":
        return ("oauth", "auth=oauth") if has_token else (
            None, f"auth=oauth needs {OAUTH_ENV} (a token from `claude setup-token`), which is not set on the host")
    if has_key and has_token:
        return "api_key", f"auth=auto: both {KEY_ENV} and {OAUTH_ENV} are set, {KEY_ENV} is used"
    if has_key:
        return "api_key", f"auth=auto: {KEY_ENV} is set"
    if has_token:
        return "oauth", f"auth=auto: {OAUTH_ENV} is set, {KEY_ENV} is not"
    return None, (f"neither {KEY_ENV} nor {OAUTH_ENV} is set on the host: the Claude Code security review agent "
                  f"needs an Anthropic API key or a Claude subscription token from `claude setup-token` "
                  "(see README.md)")


def filter_conflict(auth: str | None, requested_filter: str | None) -> str | None:
    """The reason a filter cannot run with this credential, else None."""
    if auth == "oauth" and requested_filter == "claude":
        return (f"filter=claude needs an Anthropic API key, and this run uses {OAUTH_ENV}. The subscription token "
                "works for Claude Code only, not for the API the filter calls. Drop filter=claude (the filter then "
                f"runs its regex rules only) or set {KEY_ENV} and use auth=api_key")
    return None


def bounded(command: str, seconds: float) -> str:
    return f"timeout -k {KILL_AFTER_SEC} {max(1, int(seconds))} {command}"


def exec_timeout(seconds: float) -> float:
    return max(1, int(seconds)) + KILL_AFTER_SEC + EXEC_SLACK_SEC


def _scrub(text: str | None, key: str) -> str:
    text = text or ""
    return text.replace(key, "***") if key else text


def _sha256(data: bytes | str) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def _result_line(output: str, prefix: str) -> dict[str, Any] | None:
    for line in reversed(output.splitlines()):
        if line.startswith(prefix + " "):
            try:
                value = json.loads(line[len(prefix) + 1:])
            except ValueError:
                return None
            return value if isinstance(value, dict) else None
    return None


class ClaudeReviewAgent(ScannerAgent):
    options_model: ClassVar[type[ClaudeReviewOptions]] = ClaudeReviewOptions
    tool_name: ClassVar[str] = "claude-code-security-review"

    @staticmethod
    def name() -> str:
        return "claude-security-review"

    @classmethod
    def preflight(cls, kwargs=None, env=None) -> None:
        """Before any trial is queued: valid options, a credential on the host and
        a filter that the credential can run."""
        super().preflight(kwargs, env)
        options = cls.parse_options(kwargs, env)
        # No model is refused here. Whether a model id is served as itself is only known at run time:
        # the driver reads the CLI's init message and stops the review at once on any other model.
        # The credential is read from the host's own environment only, never from --ae (Harbor writes
        # agent env values into the job config).
        auth, note = choose_auth(options.auth)
        if auth is None:
            raise ValueError(note)
        conflict = filter_conflict(auth, options.filter)
        if conflict:
            raise ValueError(conflict)

    def tool_version(self) -> str:
        return f"{pins.CCSR_COMMIT[:7]}+claude-code-{pins.CLAUDE_CODE_VERSION}"

    # ------------------------------------------------------------ the model

    @property
    def review_options(self) -> ClaudeReviewOptions:
        return self.options  # type: ignore[return-value]

    def review_model(self) -> str:
        return self.review_options.model or pins.UPSTREAM_DEFAULT_MODEL

    def filter_model(self) -> str:
        return self.review_options.filter_model or self.review_model()

    def auth_mode(self) -> str | None:
        """api_key or oauth, from the option and the host's variables. None when the credential is missing."""
        return choose_auth(self.review_options.auth)[0]

    def filter_mode(self) -> str:
        """The filter that runs: the option, else claude with an API key and hard_rules with a subscription token."""
        chosen = self.review_options.filter
        if chosen:
            return chosen
        return "hard_rules" if self.auth_mode() == "oauth" else "claude"

    def results_label(self) -> str:
        """How results of this configuration should be labelled in a report."""
        return "{} CLI + {} filter".format(self.review_options.mode,
                                           "Claude" if self.filter_mode() == "claude" else "hard-rule")

    def to_agent_info(self) -> AgentInfo:
        """The model this agent really calls, not Harbor's ``-m``."""
        return AgentInfo(name=self.name(), version=self.version() or "unknown",
                         model_info=ModelInfo(name=self.review_model(), provider="anthropic"))

    def model_metadata(self) -> dict[str, Any]:
        options = self.review_options
        return {
            "model": self.review_model(),
            "model_source": "option" if options.model else "upstream_default",
            "filter_model": self.filter_model() if self.filter_mode() == "claude" else None,
            "mode": options.mode,
            "filter_mode": self.filter_mode(),
            "auth": self.auth_mode(),
            # Harbor's -m: recorded, never used (the platform makes every run name one).
            "harbor_model_name_ignored": self.model_name,
            # None: the CLI's own default, as upstream; a value is passed as --effort (a deviation).
            "reasoning_effort": options.reasoning_effort,
        }

    def sarif_driver_properties(self) -> dict[str, Any]:
        options = self.review_options
        return {"model": self.review_model(), "mode": options.mode, "filterMode": self.filter_mode(),
                "auth": self.auth_mode(), "reasoningEffort": options.reasoning_effort,
                "upstreamCommit": pins.CCSR_COMMIT, "claudeCodeVersion": pins.CLAUDE_CODE_VERSION,
                "categoryMap": category_map.VERSION}

    def instructions(self, task_instruction: str | None = None) -> tuple[str | None, str | None]:
        """(scan instructions, filter instructions) for the mode. None in stock mode.
        ``task_instruction`` defaults to the instruction ``run`` was given."""
        if self.review_options.mode != "scoped":
            return None, None
        text, _source, _contract = self.scan_instructions_for(task_instruction)
        return text, FILTER_INSTRUCTIONS_FILE.read_text(encoding="utf-8")

    def scan_instructions_for(
        self, task_instruction: str | None = None
    ) -> tuple[str, str, contract.Contract | None]:
        """(scoped scan instructions, their source, the contract). The source is
        "task_instruction" when the instruction carries the output contract, else
        "bundled" (``scoped_scan_instructions.txt``)."""
        if task_instruction is None:
            task_instruction = getattr(self, "_instruction", None)
        parsed = contract.parse(task_instruction)
        if parsed is not None:
            return contract.scan_instructions(parsed), "task_instruction", parsed
        return SCAN_INSTRUCTIONS_FILE.read_text(encoding="utf-8"), "bundled", None

    # ------------------------------------------------------------ install

    def install_files(self) -> dict[str, bytes]:
        return {
            "install.py": (_HERE / "install.py").read_bytes(),
            "driver.py": (_HERE / "driver.py").read_bytes(),
            "pins.json": json.dumps(pins.as_dict(), indent=2).encode("utf-8"),
            pins.REQUIREMENTS_FILE: (_HERE / pins.REQUIREMENTS_FILE).read_bytes(),
        }

    def install_command(self, work_dir: str) -> str:
        return (
            "PY=python3; [ -x /opt/sast/venv/bin/python ] && PY=/opt/sast/venv/bin/python; "
            f'SAST_ROOT={shlex.quote(work_dir)} "$PY" {shlex.quote(work_dir + "/install.py")} '
            f"{shlex.quote(work_dir + '/pins.json')}"
        )

    # ------------------------------------------------------------ scan

    def _scan_budget(self, settings: TaskSettings) -> float:
        options = self.review_options
        explicit = options.timeout_sec or options.scan_budget_sec
        return float(explicit) if explicit else super()._scan_budget(settings)

    def _credential(self) -> tuple[str, str, str]:
        """(auth mode, how it was chosen, the secret). The secret goes nowhere but the credential file."""
        auth, note = choose_auth(self.review_options.auth)
        if auth is None:
            raise ScannerError(note)
        conflict = filter_conflict(auth, self.review_options.filter)
        if conflict:
            raise ScannerError(conflict)
        secret = os.environ.get(CREDENTIAL_ENV[auth], "").strip()
        if not secret:  # changed since choose_auth looked: treat as missing
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
        if work is None or not install.get("venv_python"):
            raise ScannerError("setup() did not run: the review tools were not checked")
        deadline = time.monotonic() + budget_sec
        options = self.review_options
        filter_mode = self.filter_mode()
        review: dict[str, Any] = {
            "mode": options.mode,
            "model": self.review_model(),
            "filter_model": self.filter_model() if filter_mode == "claude" else None,
            "filter_mode": filter_mode,
            "filter_mode_source": "option" if options.filter else "default_for_" + auth,
            "auth": auth,
            "auth_choice": auth_note,
            "results_label": self.results_label(),
            "upstream_repo": pins.CCSR_REPO,
            "upstream_commit": pins.CCSR_COMMIT,
            "claude_code_version_pinned": pins.CLAUDE_CODE_VERSION,
            "category_map": category_map.VERSION,
            "cli_auth": options.cli_auth if auth == "api_key" else "oauth_env",
            "cli_attempts": options.cli_attempts,
            "max_turns": options.max_turns,
            "max_budget_usd": options.max_budget_usd,
        }
        meta["claude_review"] = review
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

        # 2. The request: everything but the credential.
        scan_text, filter_text = self.instructions()
        review["scan_instructions_sha256"] = _sha256(scan_text) if scan_text else None
        review["filter_instructions_sha256"] = _sha256(filter_text) if filter_text else None
        review["scan_instructions_source"] = None
        review["filter_exclusions_dropped"] = []
        if options.mode == "scoped":
            _, source, parsed = self.scan_instructions_for()
            review["scan_instructions_source"] = source
            review["contract"] = parsed.describe() if parsed else None
            review["contract_ids_not_accepted"] = self._contract_gaps(parsed)
            review["filter_exclusions_dropped"] = [dict(e) for e in FILTER_EXCLUSIONS_DROPPED]
            # The dropped exclusions are in the Claude filter's prompt; the hard-rule filter never reads it.
            review["filter_exclusions_dropped_apply"] = filter_mode == "claude"
        key_dir = f"{work}/{KEY_DIR}"
        key_file = f"{key_dir}/{CREDENTIAL_FILE[auth]}"
        out_file = f"{work}/{DRIVER_OUT}"
        left = deadline - time.monotonic() - PREPARE_RESERVE_SEC
        driver_seconds = left - KILL_AFTER_SEC - EXEC_SLACK_SEC
        if driver_seconds < MIN_DRIVER_SEC:
            raise ScannerError(f"the scan budget ({int(budget_sec)} s) leaves {int(driver_seconds)} s for the review")
        request = {
            "repo": REPO_DIR,
            "files": files,
            "mode": options.mode,
            "model": self.review_model(),
            "filter_model": self.filter_model(),
            "filter": filter_mode,
            "auth": auth,
            "max_turns": options.max_turns,
            "max_budget_usd": options.max_budget_usd,
            "effort": options.reasoning_effort,
            "cli_attempts": options.cli_attempts,
            "cli_auth": options.cli_auth,
            "cli_share": options.cli_share,
            "budget_sec": int(driver_seconds),
            "scan_instructions": scan_text,
            "filter_instructions": filter_text,
            "home": f"{work}/{CLI_HOME}",
            "scope_dir": f"{work}/{SCOPE_DIR}",
            "ccsr_dir": install.get("ccsr_dir") or f"{pins.INSTALL_DIR}/ccsr",
            "claude": install.get("claude") or f"{pins.INSTALL_DIR}/bin/claude",
        }
        request_bytes = json.dumps(request, indent=1).encode("utf-8")
        if key.encode() in request_bytes:  # a programming error
            raise ScannerError(f"refusing to upload a request that contains {CREDENTIAL_ENV[auth]}")
        review["request_sha256"] = _sha256(request_bytes)
        request_file = f"{work}/out/claude_review_request.json"
        await self._upload_bytes(environment, request_bytes, request_file)

        try:
            # Inside the try: a failed upload or protect step must still remove the file.
            await self._write_key(environment, key_dir, key_file, key, review)
            document = await self._run_driver(environment, key, install, request_file, key_file, out_file,
                                               driver_seconds, review, secret_name=CREDENTIAL_ENV[auth])
        finally:
            await self._remove_key(environment, key_dir, review)

        line_counts = {str(k): int(v) for k, v in ((document.get("pr") or {}).get("line_counts") or {}).items()
                       if isinstance(v, int)}
        findings, counts = normalise(document.get("kept") or [], mode=options.mode, line_counts=line_counts,
                                     roots=roots, excludes=excludes)
        meta.update(counts)
        return findings

    @staticmethod
    def _contract_gaps(parsed: contract.Contract | None) -> dict[str, list[str]]:
        """Ids and values the contract names that the normaliser does not accept
        (empty lists when the two agree, as they should)."""
        if parsed is None:
            return {}
        from .. import cwe_map, heuristics
        from ..findings import CONTROL_STATUSES, PATH_ROLES, RISK_LEVELS
        return {
            "rule_ids": [r for r, _ in parsed.rules if r not in cwe_map.TASK_RULES],
            "recommendation_ids": [r for r, _ in parsed.recommendations if r not in heuristics.CATALOGUE],
            "roles": [r for r in parsed.roles if r not in PATH_ROLES],
            "control_statuses": [v for v in parsed.control_statuses if v not in CONTROL_STATUSES],
            "residual_risks": [v for v in parsed.residual_risks if v not in RISK_LEVELS],
        }

    def sarif_run_properties(self, meta: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
        """The base account, with the Claude review's own drops and re-mapping:
        findings outside the scope or at a bad location, categories the category
        map does not know, findings whose ruleId the harness derived from the
        category or CWE (not the model's own rule_id), and the upstream filter's
        exclusions (stage, reason, file:line)."""
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
        review = meta.get("claude_review") or {}
        excluded = [{"stage": e.get("stage"), "reason": e.get("reason"), "category": e.get("category"),
                     "location": f"{e.get('file')}:{e.get('line')}"} for e in review.get("excluded") or []]
        agent["upstreamFilterExclusions"] = run_entry(excluded, review.get("findings_excluded", len(excluded)))
        agent.update({"mode": self.review_options.mode, "filterMode": self.filter_mode(),
                      "categoryMap": category_map.VERSION,
                      "scanInstructionsSource": review.get("scan_instructions_source"),
                      "filterExclusionsDropped": [e["upstream_number"] for e in review.get(
                          "filter_exclusions_dropped") or []]})
        return props

    async def _files_in_scope(self, environment: BaseEnvironment, roots: list[str], excludes: list[str]) -> list[str]:
        """Every regular file under the roots, minus the excludes and .git, sorted."""
        paths = " ".join(shlex.quote(r) for r in roots)
        result = await self._exec(environment, f"find {paths} -name .git -prune -o -type f -print 2>/dev/null",
                                  timeout_sec=120, what="listing the files in scope", cwd=REPO_DIR)
        found = {repo_path(line.strip()) for line in (result.stdout or "").splitlines() if line.strip()}
        return sorted(f for f in found if f and in_scope(f, roots, excludes))

    async def _run_driver(
        self,
        environment: BaseEnvironment,
        key: str,
        install: dict[str, Any],
        request_file: str,
        key_file: str,
        out_file: str,
        seconds: float,
        review: dict[str, Any],
        secret_name: str = KEY_ENV,
    ) -> dict[str, Any]:
        python = install["venv_python"]
        claude_dir = str(Path(install.get("claude") or f"{pins.INSTALL_DIR}/bin/claude").parent)
        work = self._work_dir
        # No secret here: Harbor puts the env on the exec command line.
        env = {"HOME": f"{work}/{CLI_HOME}", "PATH": f"{claude_dir}:{SYSTEM_PATH}", "PYTHONDONTWRITEBYTECODE": "1"}
        command = (
            f"rm -f {shlex.quote(out_file)} && mkdir -p {shlex.quote(work + '/' + CLI_HOME)} && exec "
            + bounded(" ".join(shlex.quote(p) for p in [python, "-I", "-B", f"{work}/driver.py",
                                                         "--request", request_file, "--keyfile", key_file,
                                                         "--out", out_file]), seconds)
        )
        result = await self._run_logged(environment, "command-1", command, key, env=env,
                                        timeout_sec=exec_timeout(seconds), what="the Claude Code security review",
                                        cwd=REPO_DIR, secret_name=secret_name, tool_step=True)
        review["driver_exit_code"] = result.return_code
        review["driver_result"] = _result_line(result.stdout or "", "DRIVER_RESULT")
        document = await self._read_output(environment, out_file, key)
        if document is not None:
            self._record(document, review)
        if document is None:
            raise ScannerError("the review driver exited {} without a readable result (full log: "
                               "agent/command-1/stdout.txt): {}".format(
                                   result.return_code, _scrub((result.stderr or result.stdout or "")[-400:], key)))
        error = document.get("error")
        if result.return_code != 0 or document.get("status") != "ok" or error:
            code = (error or {}).get("code") if isinstance(error, dict) else None
            message = (error or {}).get("message") if isinstance(error, dict) else str(error)
            hint = ERROR_HINTS.get(code or "", "the review failed")
            text = _scrub(f"Claude Code security review: {hint} [{code or 'exit ' + str(result.return_code)}]"
                          f": {message}", key)
            if code in OUTCOME_CODES:
                raise ToolOutcome(OUTCOME_CODES[code], text)
            raise ScannerError(text)
        return document

    @staticmethod
    def _record(document: dict[str, Any], review: dict[str, Any]) -> None:
        """What the run metadata keeps from the driver's result (no findings text)."""
        def record(key: str) -> dict[str, Any]:
            value = document.get(key)
            return value if isinstance(value, dict) else {}

        cli = record("cli")
        wrapper = cli.get("cli") if isinstance(cli.get("cli"), dict) else {}
        attempts = [a for a in (cli.get("attempts") or []) if isinstance(a, dict)]
        review.update({
            "driver_status": document.get("status"),
            "driver_error": document.get("error"),
            "driver_seconds": document.get("seconds"),
            "claude_code_version": document.get("claude_code_version"),
            "versions": document.get("versions"),
            "upstream_default_model_seen": document.get("upstream_default_model"),
            "network": document.get("network"),
            "preflight": document.get("preflight"),
            "cli_argv": document.get("cli_argv"),
            "cli_settings": document.get("cli_settings"),
            "environment_removed": document.get("environment_removed"),
            "cli_init": cli.get("init"),
            # Where the CLI says its credential came from (a source name such as "none" or
            # "apiKeyHelper", never a value).
            "cli_credential_source": (cli.get("init") if isinstance(cli.get("init"), dict) else {}).get("apiKeySource"),
            "prompt_sha256": cli.get("prompt_sha256"),
            "prompt_bytes": cli.get("prompt_bytes"),
            "diff_omitted": cli.get("diff_omitted"),
            "attempts": len(attempts),
            "attempt_outcomes": [{k: a.get(k) for k in ("exit_code", "seconds", "outcome", "reason", "include_diff")}
                                 for a in attempts],
            "total_cost_usd": wrapper.get("total_cost_usd"),
            "num_turns": wrapper.get("num_turns"),
            "duration_ms": wrapper.get("duration_ms"),
            "duration_api_ms": wrapper.get("duration_api_ms"),
            "usage": wrapper.get("usage"),
            "model_usage": wrapper.get("modelUsage"),
            "session_id": wrapper.get("session_id"),
            "cli_subtype": wrapper.get("subtype"),
            "cli_is_error": wrapper.get("is_error"),
            "permission_denials": wrapper.get("permission_denials"),
            "attempt_cost_usd": [((a.get("wrapper") or {}).get("total_cost_usd")) for a in attempts],
            "api_usage": document.get("api_usage"),
            "api_calls": document.get("api_calls"),
            "review_summary": document.get("review_summary"),
            "findings_raw": len(record("review").get("findings") or []),
            "findings_kept": len(document.get("kept") or []),
            "findings_excluded": len(document.get("excluded") or []),
            "excluded": [
                {"file": (e.get("finding") or {}).get("file"), "line": (e.get("finding") or {}).get("line"),
                 "category": (e.get("finding") or {}).get("category"), "stage": e.get("filter_stage"),
                 "reason": str(e.get("exclusion_reason") or "")[:300]}
                for e in (document.get("excluded") or []) if isinstance(e, dict)
            ][:200],
            "filter_summary": record("filter").get("summary"),
            "filter_calls": len(record("filter").get("calls") or []),
            "pr": {k: v for k, v in record("pr").items() if k != "line_counts"},
            "request_options": record("request_options"),
            # The CLI ran in a copy of the in-scope files; every tool call it made, and those outside the scope.
            "scope_copy": document.get("scope_copy"),
            "paths_relativised": document.get("paths_relativised"),
            "tool_uses_count": cli.get("tool_uses_count"),
            "tool_uses": (cli.get("tool_uses") or [])[:MAX_TOOL_USES_META],
            "tool_uses_outside_scope": cli.get("tool_uses_outside_scope") or [],
            "tool_uses_outside_scope_count": len(cli.get("tool_uses_outside_scope") or []),
        })

    def artifact_files(self) -> dict[str, str]:
        work = getattr(self, "_work_dir", None)
        if not work:
            return {}
        return {"claude_review.json": f"{work}/{DRIVER_OUT}"}

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
        secret_name: str = KEY_ENV,
        tool_step: bool = False,
    ) -> ExecResult:
        """One exec, logged with the credential scrubbed. It is in neither the command nor the env."""
        if key in command or any(key in value for value in env.values()) or \
                any(name in CREDENTIAL_ENV.values() for name in env):  # a programming error
            raise ScannerError(f"refusing to run a command whose command line or env contains {secret_name}")
        started = time.monotonic()
        try:
            result = await self._exec(environment, command, timeout_sec=timeout_sec, what=what, cwd=cwd, env=env,
                                      scrub=lambda text: _scrub(text, key), tool_step=tool_step)
        except ToolOutcome as exc:
            raise exc.with_message(_scrub(str(exc), key)) from None
        except ScannerError as exc:
            raise ScannerError(_scrub(str(exc), key)) from None
        clean = ExecResult(stdout=_scrub(result.stdout, key), stderr=_scrub(result.stderr, key),
                           return_code=result.return_code)
        self._write_log(log_name, command, clean, round(time.monotonic() - started, 1))
        return clean

    async def _read_output(self, environment: BaseEnvironment, path: str, key: str) -> dict[str, Any] | None:
        """The driver's result. If it holds the key (the driver scrubs it, so this
        is a backstop), a scrubbed copy replaces it before it can become an artifact."""
        try:
            data = await self._download_bytes(environment, path)
        except ScannerError:
            return None
        if key.encode() in data:
            data = data.replace(key.encode(), b"***")
            await self._upload_bytes(environment, data, path)
        try:
            document = json.loads(data)
        except ValueError:
            return None
        return document if isinstance(document, dict) else None

    async def _write_key(
        self, environment: BaseEnvironment, key_dir: str, key_file: str, key: str, review: dict[str, Any]
    ) -> None:
        """The credential as a mode 600 file in a mode 700 directory. No command here holds it.

        Same steps as the SonarQube token: the upload may arrive owned by another
        user, so the sandbox user copies it under umask 077 and removes the
        upload. The caller removes the whole directory in a ``finally``.
        """
        quoted_dir, quoted_file = shlex.quote(key_dir), shlex.quote(key_file)
        upload = f"{key_file}.upload"
        quoted_upload = shlex.quote(upload)
        result = await self._exec(environment, f"rm -rf {quoted_dir} && mkdir -p {quoted_dir} && chmod 700 {quoted_dir}",
                                  timeout_sec=60, what="preparing the key directory")
        if result.return_code != 0:
            raise ScannerError(f"could not prepare the key directory {key_dir} (exit {result.return_code})")
        await self._upload_bytes(environment, key.encode("utf-8"), upload)
        result = await self._exec(
            environment,
            f"umask 077 && cat {quoted_upload} > {quoted_file} && rm -f {quoted_upload} && "
            f"chmod 600 {quoted_file} && test -s {quoted_file}",
            timeout_sec=60, what="protecting the key file")
        if result.return_code != 0:
            raise ScannerError(f"could not protect the key file {key_file} (exit {result.return_code})")
        review["key_file"] = key_file

    async def _remove_key(self, environment: BaseEnvironment, key_dir: str, review: dict[str, Any]) -> None:
        try:
            result = await self._exec(environment, f"rm -rf {shlex.quote(key_dir)}", timeout_sec=CLEANUP_SLICE_SEC,
                                      what="removing the key file")
            review["key_file_removed"] = result.return_code == 0
        except ScannerError:
            review["key_file_removed"] = False
