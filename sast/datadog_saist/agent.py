"""``sast.datadog_saist.agent:DatadogSaistAgent``: Datadog's open-source AI SAST
engine, datadog-saist (DataDog/datadog-saist, Apache-2.0, preview), as a Harbor agent.

datadog-saist runs locally: for each (file, rule) pair its keyword prefilter
selects, it asks a detection model for violations and a validation model to
confirm them, and writes SARIF. Its rules are downloaded from Datadog's public
endpoint at run time (no Datadog account). See docs/datadog-saist-agent.md.

Configuration, read on the host:

- The credential: the variable of the model's provider (``OPENAI_API_KEY``,
  ``ANTHROPIC_API_KEY`` or ``GOOGLE_API_KEY``). None fails the trial before
  anything runs.
- Options (``--ak key=value`` or ``DATADOG_SAIST_<KEY>``): ``model``,
  ``validation_model``, ``mode``, ``rules``, ``request_timeout_sec``,
  ``file_concurrency``, ``skip_indexing``, ``timeout_sec``, ``scan_roots``,
  ``exclude``. See options.py.

The key is handled like the Claude review's: uploaded into a mode 700 folder,
copied under umask 077 into a mode 600 file, read by the driver, which puts it
only in the binary's own environment, and removed in a ``finally``. It is never
on a command line, in Harbor's exec env, the metadata, a log or an artifact.

A scan that did not deliver (the deadline, the binary crashing, an unreadable
SARIF, nothing analysed) is a ``ToolOutcome`` (no SARIF, scored 0). A refused
key, no quota, an unknown model, a closed network, an unreachable rule
endpoint or every model call failing are ``ScannerError``.
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

from .. import pricing
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
from . import pins, rule_map
from .driver import MASKED_KEY
from .options import DatadogSaistOptions, cli_model

_HERE = Path(__file__).parent

KEY_DIR = "secret-datadog-saist"
KEY_FILE = "provider-key"
SCOPE_DIR = "datadog-saist-scope"
PRIVATE_DIR = "datadog-saist-private"
DRIVER_OUT = "out/datadog_saist.json"
PROVIDER_URLS = {"openai": "https://api.openai.com/v1/models", "anthropic": "https://api.anthropic.com/v1/models",
                 "google": "https://generativelanguage.googleapis.com/v1beta/models"}
PREPARE_RESERVE_SEC = 60
MIN_DRIVER_SEC = 120
MAX_FILES = 5000
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ERROR_HINTS = {
    "no_key": "the credential file could not be read in the sandbox",
    "network": "the sandbox cannot reach the model provider. This agent needs HTTPS egress from the task container",
    "rules_unavailable": "datadog-saist could not download its rules from Datadog's public endpoint "
                         f"({pins.RULES_URL}); --ak rules=embedded uses the binary's own 12 rules instead",
    "api_auth": "the model provider refused the key",
    "quota": "the provider account has no quota or billing for this key",
    "rate_limited": "the provider kept rate-limiting the scan",
    "model_unavailable": "the model is not available to this key",
    "prompt_too_long": "a prompt does not fit the model's context window",
    "llm_failed": "every model call of the scan failed",
    "tool_crashed": "datadog-saist exited with an error",
    "bad_output": "datadog-saist wrote no readable SARIF",
    "deadline": "the scan ran out of time",
    "tool_saw_nothing": "datadog-saist analysed none of the in-scope files",
    "nothing_to_review": "none of the in-scope files could be read",
}
OUTCOME_CODES = {"deadline": "deadline", "tool_crashed": "tool_crashed", "bad_output": "bad_review_output",
                 "tool_saw_nothing": "tool_saw_nothing", "prompt_too_long": "prompt_too_long"}


def scrub(text: str | None, key: str) -> str:
    text = text or ""
    if key:
        text = text.replace(key, "***")
    return MASKED_KEY.sub("***", text)


def rules_digest(sarif: dict[str, Any]) -> tuple[str | None, int]:
    """sha256 of the rule descriptors the run used (id, descriptions, tags), and their count."""
    rules = normalise_module.rule_descriptors(sarif)
    if not rules:
        return None, 0
    canon = json.dumps([[r, rules[r].get("shortDescription"), rules[r].get("fullDescription"),
                         (rules[r].get("properties") or {}).get("tags")] for r in sorted(rules)], sort_keys=True)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest(), len(rules)


class DatadogSaistAgent(ScannerAgent):
    options_model: ClassVar[type[DatadogSaistOptions]] = DatadogSaistOptions
    tool_name: ClassVar[str] = "datadog-saist"

    _write_key = ClaudeReviewAgent._write_key
    _remove_key = ClaudeReviewAgent._remove_key
    _files_in_scope = ClaudeReviewAgent._files_in_scope
    _read_output = ClaudeReviewAgent._read_output
    _contract_gaps = staticmethod(ClaudeReviewAgent._contract_gaps)

    @staticmethod
    def name() -> str:
        return "datadog-saist"

    @classmethod
    def preflight(cls, kwargs=None, env=None) -> None:
        """Before any trial is queued: valid options and the provider's key on the host."""
        super().preflight(kwargs, env)
        options = cls.parse_options(kwargs, env)
        agent_model = options.model or pins.DEFAULT_MODEL
        provider = pins.MODELS[agent_model][0]
        name = pins.KEY_ENVS[provider]
        if not str(os.environ.get(name, "") or "").strip():
            raise ValueError(f"{name} is not set on the host: datadog-saist with {agent_model} needs a {provider} key")

    def tool_version(self) -> str:
        return pins.VERSION

    # ------------------------------------------------------------ the model

    @property
    def saist_options(self) -> DatadogSaistOptions:
        return self.options  # type: ignore[return-value]

    def _harbor_cli_model(self) -> str | None:
        """Harbor's -m as the binary's model name when it names an OpenAI model the binary supports, else None.

        Only OpenAI: the platform names a model on every run, often another provider's, and following it
        would make the run need that provider's key. Other providers are chosen with --ak model."""
        name = self.harbor_model("openai", ("gpt-", "openai-"))
        if not name:
            return None
        try:
            return cli_model(name)
        except ValueError:
            return None

    def detection_model(self) -> str:
        return self.saist_options.model or self._harbor_cli_model() or pins.DEFAULT_MODEL

    def validation_model(self) -> str:
        return self.saist_options.validation_model or self.detection_model()

    def model_source(self) -> str:
        if self.saist_options.model:
            return "option"
        return "harbor_model_name" if self._harbor_cli_model() else "default"

    def provider(self) -> str:
        return pins.MODELS[self.detection_model()][0]

    def key_env(self) -> str:
        return pins.KEY_ENVS[self.provider()]

    def to_agent_info(self) -> AgentInfo:
        return AgentInfo(name=self.name(), version=self.version() or "unknown",
                         model_info=ModelInfo(name=pins.MODELS[self.detection_model()][1], provider=self.provider()))

    def model_metadata(self) -> dict[str, Any]:
        options = self.saist_options
        return {
            "engine": "datadog-saist",
            "model": self.detection_model(),
            "model_api_id": pins.MODELS[self.detection_model()][1],
            "validation_model": self.validation_model(),
            "model_source": self.model_source(),
            "mode": options.mode,
            "mode_effective": "stock",
            "rules_source": options.rules,
            "auth_source": self.key_env(),
            "harbor_model_name": self.model_name,
            "harbor_model_name_used": self.model_source() == "harbor_model_name",
        }

    def usage_summary(self, meta: dict[str, Any]) -> dict[str, Any] | None:
        """The tool reports total input and output tokens (no cache split): priced as uncached, an upper bound."""
        scan = meta.get("datadog_saist") if isinstance(meta.get("datadog_saist"), dict) else None
        summary = (scan or {}).get("summary") or {}
        tokens_in, tokens_out = summary.get("input_tokens"), summary.get("output_tokens")
        if not isinstance(tokens_in, int) or not isinstance(tokens_out, int) or not (tokens_in or tokens_out):
            return None
        detection = pins.MODELS[self.detection_model()][1]
        validation = pins.MODELS[self.validation_model()][1]
        cost = pricing.cost(detection, tokens_in, 0, 0, tokens_out) if detection == validation else None
        return {
            "n_input_tokens": tokens_in,
            "n_cache_tokens": 0,
            "n_output_tokens": tokens_out,
            "cost_usd": cost,
            "cost_source": "estimate: datadog-saist token totals x {} list price as of {}, all input priced as "
                           "uncached (the tool reports no cache split), so an upper bound{}".format(
                               detection, pricing.PRICES_AS_OF,
                               "" if cost is not None else " (model not in the price table, or two models)"),
        }

    def sarif_driver_properties(self) -> dict[str, Any]:
        options = self.saist_options
        return {"engine": "datadog-saist", "datadogSaistVersion": pins.VERSION, "commit": pins.COMMIT,
                "model": self.detection_model(), "validationModel": self.validation_model(),
                "mode": options.mode, "modeEffective": "stock", "rules": options.rules,
                "ruleMap": rule_map.VERSION}

    # ------------------------------------------------------------ install

    def install_files(self) -> dict[str, bytes]:
        return {
            "datadog_saist_install.py": (_HERE / "install.py").read_bytes(),
            "datadog_saist_driver.py": (_HERE / "driver.py").read_bytes(),
            "ccsr_driver.py": (_HERE.parent / "claude_review" / "driver.py").read_bytes(),
            "datadog_saist_pins.json": json.dumps(pins.as_dict(), indent=2).encode("utf-8"),
        }

    def install_command(self, work_dir: str) -> str:
        return (
            "PY=python3; [ -x /opt/sast/venv/bin/python ] && PY=/opt/sast/venv/bin/python; "
            f'SAST_ROOT={shlex.quote(work_dir)} "$PY" {shlex.quote(work_dir + "/datadog_saist_install.py")} '
            f"{shlex.quote(work_dir + '/datadog_saist_pins.json')}"
        )

    # ------------------------------------------------------------ scan

    def _scan_budget(self, settings: TaskSettings) -> float:
        options = self.saist_options
        explicit = options.timeout_sec or options.scan_budget_sec
        return float(explicit) if explicit else super()._scan_budget(settings)

    def _credential(self) -> tuple[str, str]:
        if pins.MODELS[self.validation_model()][0] != self.provider():
            raise ScannerError("the detection and validation models use different providers; one key is passed")
        name = self.key_env()
        key = os.environ.get(name, "").strip()
        if not key:
            raise ScannerError(f"{name} is not set on the host: datadog-saist with {self.detection_model()} needs it")
        return name, key

    async def scan(self, environment: BaseEnvironment, settings: TaskSettings, budget_sec: float,
                   meta: dict[str, Any]) -> list[Finding]:
        auth_source, key = self._credential()
        work = getattr(self, "_work_dir", None)
        install = getattr(self, "_install", None) or {}
        if work is None or not install.get("binary"):
            raise ScannerError("setup() did not run: the datadog-saist binary was not checked")
        deadline = time.monotonic() + budget_sec
        options = self.saist_options
        scan: dict[str, Any] = {
            "version_pinned": pins.VERSION, "commit": pins.COMMIT, "binary_sha256": install.get("binary_sha256"),
            "mode": options.mode, "mode_effective": "stock",
            "detection_model": self.detection_model(), "validation_model": self.validation_model(),
            "auth_source": auth_source, "rules": options.rules,
            "rules_url": pins.RULES_URL if options.rules == "api" else None,
            "request_timeout_sec": options.request_timeout_sec, "file_concurrency": options.file_concurrency,
            "skip_indexing": options.skip_indexing, "normaliser": normalise_module.VERSION,
            "rule_map": rule_map.VERSION, "cost_usd": None,
        }
        meta["datadog_saist"] = scan
        note = budget_note(budget_sec, bool(options.timeout_sec or options.scan_budget_sec), settings.agent_timeout_sec)
        if note:
            scan["harbor_limit_needed_sec"] = int(budget_sec) + TIMEOUT_MARGIN_SEC
            scan["budget_note"] = note
        # Scoped mode: the contract is parsed and recorded, but the tool takes no instructions (see options.py).
        if options.mode == "scoped":
            parsed = contract.parse(getattr(self, "_instruction", None))
            scan["contract"] = parsed.describe() if parsed else None
            scan["contract_passed_to_tool"] = False
            scan["contract_note"] = ("datadog-saist has no way to take extra instructions (rules come from Datadog's "
                                     "endpoint or the binary; the answer schema is fixed), so scoped runs as stock")
            scan["rule_map_targets_not_in_contract"] = sorted(
                {r for r, _, _ in rule_map.RULE_MAP.values() if r} - {r for r, _ in parsed.rules}) if parsed else None

        roots, excludes = task_scope(options.scan_roots or settings.scanner_roots,
                                     options.exclude or settings.excluded_paths, "scan_roots", "exclude")
        roots = await self._existing_roots(environment, roots, meta)
        files = await self._files_in_scope(environment, roots, excludes)
        meta["scan"] = {"roots": roots, "excludes": excludes, "files_in_scope": len(files)}
        if not files:
            raise ScannerError("no file is in scope: nothing to scan")
        if len(files) > MAX_FILES:
            raise ToolOutcome("too_many_files", f"{len(files)} files are in scope, more than {MAX_FILES}")

        key_dir = f"{work}/{KEY_DIR}"
        key_file = f"{key_dir}/{KEY_FILE}"
        out_file = f"{work}/{DRIVER_OUT}"
        left = deadline - time.monotonic() - PREPARE_RESERVE_SEC
        driver_seconds = left - KILL_AFTER_SEC - EXEC_SLACK_SEC
        if driver_seconds < MIN_DRIVER_SEC:
            raise ScannerError(f"the scan budget ({int(budget_sec)} s) leaves {int(driver_seconds)} s for the scan")
        request = {
            "repo": REPO_DIR, "files": files, "binary": install["binary"],
            "detection_model": self.detection_model(), "validation_model": self.validation_model(),
            "key_env": auth_source, "rules": options.rules, "rules_url": pins.RULES_URL,
            "provider_url": PROVIDER_URLS[self.provider()],
            "request_timeout_sec": options.request_timeout_sec, "file_concurrency": options.file_concurrency,
            "skip_indexing": options.skip_indexing, "budget_sec": int(driver_seconds),
            "scope_dir": f"{work}/{SCOPE_DIR}", "private_dir": f"{work}/{PRIVATE_DIR}",
        }
        request_bytes = json.dumps(request, indent=1).encode("utf-8")
        if key.encode() in request_bytes:  # a programming error
            raise ScannerError(f"refusing to upload a request that contains {auth_source}")
        scan["request_sha256"] = _sha256(request_bytes)
        request_file = f"{work}/out/datadog_saist_request.json"
        await self._upload_bytes(environment, request_bytes, request_file)

        try:
            await self._write_key(environment, key_dir, key_file, key, scan)
            document = await self._run_driver(environment, key, request_file, key_file, out_file, driver_seconds,
                                              scan, auth_source)
        finally:
            await self._remove_key(environment, key_dir, scan)

        line_counts = {str(k): int(v) for k, v in (document.get("line_counts") or {}).items() if isinstance(v, int)}
        sarif_doc = document.get("sarif") if isinstance(document.get("sarif"), dict) else {}
        scan["rules_sha256"], scan["rules_count"] = rules_digest(sarif_doc)
        findings, counts = normalise_module.normalise(sarif_doc, line_counts=line_counts, roots=roots,
                                                      excludes=excludes)
        meta.update(counts)
        return findings

    async def _run_driver(self, environment: BaseEnvironment, key: str, request_file: str, key_file: str,
                          out_file: str, seconds: float, scan: dict[str, Any], secret_name: str) -> dict[str, Any]:
        work = self._work_dir
        env = {"PATH": SYSTEM_PATH, "PYTHONDONTWRITEBYTECODE": "1"}
        command = (
            "PY=python3; [ -x /opt/sast/venv/bin/python ] && PY=/opt/sast/venv/bin/python; "
            f"rm -f {shlex.quote(out_file)} && mkdir -p {shlex.quote(work + '/out')} && exec "
            + bounded('"$PY" ' + " ".join(shlex.quote(p) for p in [
                "-I", "-B", f"{work}/datadog_saist_driver.py", "--request", request_file, "--keyfile", key_file,
                "--out", out_file]), seconds)
        )
        if key in command or any(key in v for v in env.values()) or any(n in pins.KEY_ENVS.values() for n in env):
            raise ScannerError(f"refusing to run a command whose command line or env contains {secret_name}")
        started = time.monotonic()
        try:
            result = await self._exec(environment, command, timeout_sec=exec_timeout(seconds), what="datadog-saist",
                                      cwd=REPO_DIR, env=env, scrub=lambda text: scrub(text, key), tool_step=True)
        except ToolOutcome as exc:
            raise exc.with_message(scrub(str(exc), key)) from None
        except ScannerError as exc:
            raise ScannerError(scrub(str(exc), key)) from None
        result = ExecResult(stdout=scrub(result.stdout, key), stderr=scrub(result.stderr, key),
                            return_code=result.return_code)
        self._write_log("command-1", command, result, round(time.monotonic() - started, 1))
        scan["driver_exit_code"] = result.return_code
        scan["driver_result"] = _result_line(result.stdout or "", "DRIVER_RESULT")
        document = await self._read_output(environment, out_file, key)
        if document is None:
            raise ScannerError("the datadog-saist driver exited {} without a readable result (full log: "
                               "agent/command-1/stdout.txt): {}".format(
                                   result.return_code, scrub((result.stderr or result.stdout or "")[-400:], key)))
        self._record(document, scan)
        error = document.get("error")
        if result.return_code != 0 or document.get("status") != "ok" or error:
            code = (error or {}).get("code") if isinstance(error, dict) else None
            message = (error or {}).get("message") if isinstance(error, dict) else str(error)
            hint = ERROR_HINTS.get(code or "", "the scan failed")
            text = scrub(f"datadog-saist: {hint} [{code or 'exit ' + str(result.return_code)}]: {message}", key)
            if code in OUTCOME_CODES:
                raise ToolOutcome(OUTCOME_CODES[code], text)
            raise ScannerError(text)
        return document

    @staticmethod
    def _record(document: dict[str, Any], scan: dict[str, Any]) -> None:
        """What the run metadata keeps from the driver's result (no finding text, no SARIF)."""
        scan.update({k: document.get(k) for k in (
            "status", "error", "seconds", "tool_seconds", "exit_code", "network", "argv", "tool_environment",
            "scope_copy", "not_text", "summary", "failure_code", "warnings", "private_dir_removed")})
        scan["driver_status"] = scan.pop("status")
        scan["driver_error"] = scan.pop("error")

    def sarif_run_properties(self, meta: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
        props = super().sarif_run_properties(meta, findings)
        agent = props["sastAgent"]
        dropped = agent["dropped"]
        dropped["outOfScope"] = run_entry(meta.get("dropped_out_of_scope"), meta.get("dropped_out_of_scope_count"))
        dropped["badLocation"] = run_entry(meta.get("dropped_bad_location"), meta.get("dropped_bad_location_count"))
        for key, name in (("rule_not_reported", "ruleOutsideTaskRules"), ("rule_not_in_map", "ruleNotInMap")):
            by_rule = meta.get(key) or {}
            dropped[name] = run_entry([[k, v] for k, v in by_rule.items()],
                                      sum(v for v in by_rule.values() if isinstance(v, int)))
        scan = meta.get("datadog_saist") or {}
        summary = scan.get("summary") or {}
        agent["remapped"] = run_entry([{"datadogRuleId": f.tool_rule_id, "ruleId": f.task_rule,
                                        "location": f"{f.file}:{f.start_line}"} for f in findings])
        agent["scanFailures"] = run_entry(summary.get("scan_failures"), summary.get("scans_failed"))
        agent.update({"engine": "datadog-saist", "ruleMap": rule_map.VERSION, "mode": self.saist_options.mode,
                      "modeEffective": "stock", "rules": self.saist_options.rules,
                      "rulesSha256": scan.get("rules_sha256"), "endLineReplaced": meta.get("end_line_replaced")})
        return props

    def artifact_files(self) -> dict[str, str]:
        work = getattr(self, "_work_dir", None)
        return {"datadog_saist.json": f"{work}/{DRIVER_OUT}"} if work else {}
