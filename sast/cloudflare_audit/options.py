"""``--ak`` settings for the Cloudflare security-audit skill agent.

Every option can also come from the host's environment, as
``CLOUDFLARE_AUDIT_<OPTION>`` (for example ``CLOUDFLARE_AUDIT_MODEL``). An
``--ak`` value wins over the environment. The credential is not an option: it
is read from ``CLAUDE_CODE_OAUTH_TOKEN`` or ``ANTHROPIC_API_KEY`` on the host,
so it never sits in a job config. ``auth`` only says which of the two to use.

Unknown keys are accepted and recorded instead of rejected, as for the other
agents: Harbor validates options once per job, so one stray key would fail
every trial of the job before any of them starts.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from harbor.agents.options import AgentOptions, Env
from pydantic import ConfigDict, Field, field_validator

from . import pins


def _env(option: str) -> Env:
    name = f"CLOUDFLARE_AUDIT_{option.upper()}"
    return Env(name, fallback=name)


class CloudflareAuditOptions(AgentOptions):
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    model: Annotated[str | None, _env("model")] = Field(
        default=None,
        description=f"Claude Code --model for the audit and its sub-agents. Default: {pins.DEFAULT_MODEL} (the skill "
        "names none). Harbor's -m is used when it names an Anthropic model. The audit stops when Claude Code "
        "reports another model.",
    )
    mode: Annotated[Literal["stock", "scoped"], _env("mode")] = Field(
        default="scoped",
        description="scoped (default): the skill's full audit plus the task's output contract as guidance and a "
        "side file with ruleId, CWE, location, path roles, control status, residual risk and REC ids per "
        "fingerprint. stock: the skill's full audit as its README asks for it, plus a side file with CWE ids only.",
    )
    auth: Annotated[Literal["api_key", "oauth", "auto"], _env("auth")] = Field(
        default="auto",
        description="Which host credential to use. oauth: CLAUDE_CODE_OAUTH_TOKEN (a subscription token from "
        "`claude setup-token`). api_key: ANTHROPIC_API_KEY. auto: api_key when ANTHROPIC_API_KEY is set, else oauth.",
    )
    profile: Annotated[Literal["quick", "standard", "deep"], _env("profile")] = Field(
        default="quick",
        description="The skill's run profile. quick (default here; the skill's default is standard): one hunter "
        "wave, one critic, one verifier per candidate, which fits a benchmark time limit.",
    )
    agent_budget: Annotated[int | None, _env("agent_budget")] = Field(
        default=None, ge=6,
        description="The skill's strict budget: the most agent invocations across all phases. Default: none.",
    )
    include_needs_validation: Annotated[bool, _env("include_needs_validation")] = Field(
        default=True,
        description="Report needs_validation records (a source-grounded lead whose decisive check is blocked, for "
        "example because target code may not be executed). confirmed records are always reported; rejected never.",
    )
    max_turns: Annotated[int | None, _env("max_turns")] = Field(
        default=None, ge=1, description="Claude Code --max-turns. Default: none."
    )
    max_budget_usd: Annotated[float | None, _env("max_budget_usd")] = Field(
        default=None, gt=0, description="Claude Code --max-budget-usd. Default: none."
    )
    reasoning_effort: Annotated[Literal["low", "medium", "high", "xhigh", "max"] | None,
                                _env("reasoning_effort")] = Field(
        default=None, description="Claude Code --effort. Default: none (the CLI's own default)."
    )
    timeout_sec: Annotated[int | None, _env("timeout_sec")] = Field(
        default=None, ge=300,
        description="Wall-clock limit for the whole audit. Default: the task's agent timeout minus 120 s. Raise "
        "Harbor's own limit to match (--agent-timeout-multiplier).",
    )
    scan_budget_sec: int | None = Field(default=None, ge=300, description="Same as timeout_sec (the other agents' name).")
    attempts: Annotated[int, _env("attempts")] = Field(
        default=1, ge=1, le=2,
        description="Claude Code runs when a run ends without the audit's files (a refused credential, a wrong "
        "model or the deadline stop at once).",
    )
    scan_roots: list[str] | None = Field(
        default=None,
        description="Paths inside /app/repo to audit (comma-separated). Default: the task's metadata.scanner_roots, "
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

    @field_validator("model", mode="before")
    @classmethod
    def _model(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("anthropic/"):
                value = value.split("/", 1)[1]
            if not value:
                return None
            if any(c.isspace() for c in value) or value.startswith("-"):
                raise ValueError(f"not a model id: {value!r}")
        return value
