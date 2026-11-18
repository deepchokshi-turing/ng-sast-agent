"""``--ak`` settings for the Promptfoo Code Scanning agent.

Every option can also come from the host's environment, as
``PROMPTFOO_SCAN_<OPTION>`` (for example ``PROMPTFOO_SCAN_MODE``). The prefix is
not ``PROMPTFOO_`` because promptfoo reads many ``PROMPTFOO_*`` variables of its
own. An ``--ak`` value wins over the environment. The credential is not an
option: it is read from ``PROMPTFOO_API_KEY`` on the host only, so it never sits
in a job config.

There is no model, cost or turn option: the Promptfoo service chooses the model
and the CLI has no flag for it, nor for a budget. There is no ``api_host``
option either: the key only ever goes to promptfoo's default host,
https://api.promptfoo.app.

Unknown keys are accepted and recorded instead of rejected, as for the other
agents: Harbor validates options once per job, so one stray key would fail
every trial of the job before any of them starts.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from harbor.agents.options import AgentOptions, Env
from pydantic import ConfigDict, Field, field_validator

ENV_PREFIX = "PROMPTFOO_SCAN_"


def _env(option: str) -> Env:
    name = f"{ENV_PREFIX}{option.upper()}"
    return Env(name, fallback=name)


class PromptfooOptions(AgentOptions):
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    mode: Annotated[Literal["stock", "scoped"], _env("mode")] = Field(
        default="scoped",
        description="scoped is the default (the benchmark's output contract); stock: promptfoo's own prompt, no guidance. Its findings carry no task ruleId, so none can be "
        "scored: they are kept in the SARIF run properties and the metadata only. scoped: the task's output "
        "contract is given as --guidance-file, asking for a parseable header (ruleId, CWEs, path, controls, "
        "recommendations) at the start of every finding.",
    )
    timeout_sec: Annotated[int | None, _env("timeout_sec")] = Field(
        default=None,
        ge=120,
        description="Wall-clock limit for the whole scan (copy, git, promptfoo). Default: the task's agent timeout "
        "minus 120 s. Raise Harbor's own limit to match (--agent-timeout-multiplier).",
    )
    scan_budget_sec: int | None = Field(default=None, ge=120, description="Same as timeout_sec (the other agents' name).")
    min_severity: Annotated[Literal["low", "medium", "high", "critical"] | None, _env("min_severity")] = Field(
        default=None,
        description="promptfoo --min-severity. Default: not passed, so promptfoo's own default (medium) applies.",
    )
    diffs_only: Annotated[bool, _env("diffs_only")] = Field(
        default=False,
        description="promptfoo --diffs-only: no filesystem MCP access, the service sees the change set only. Default "
        "false, promptfoo's own default (\"diffs + tracing into repo\"). The change set is the whole scope either way.",
    )
    scan_roots: list[str] | None = Field(
        default=None,
        description="Paths inside /app/repo to scan (comma-separated). Default: the task's metadata.scanner_roots, "
        "else the whole repository.",
    )
    exclude: list[str] | None = Field(
        default=None, description="Paths to skip (comma-separated). Default: the task's metadata.excluded_paths."
    )

    @field_validator("scan_roots", "exclude", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("min_severity", mode="before")
    @classmethod
    def _severity(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip().lower()
            return value or None
        return value
