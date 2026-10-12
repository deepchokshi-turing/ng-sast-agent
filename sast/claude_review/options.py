"""``--ak`` settings for the Claude Code security review agent.

Every option can also come from the host's environment, as
``CLAUDE_REVIEW_<OPTION>`` (for example ``CLAUDE_REVIEW_MODEL``). An ``--ak``
value wins over the environment. The API key is not an option: it is read from
``ANTHROPIC_API_KEY`` on the host, so it never sits in a job config.

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
    name = f"CLAUDE_REVIEW_{option.upper()}"
    return Env(name, fallback=name)


class ClaudeReviewOptions(AgentOptions):
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    model: Annotated[str | None, _env("model")] = Field(
        default=None,
        description=f"Model for the review and, unless filter_model says otherwise, the filter. Default: the upstream "
        f"tool's own default, {pins.UPSTREAM_DEFAULT_MODEL}, which Anthropic may retire. The review stops when "
        "Claude Code reports another model than this one. Harbor's -m is not used.",
    )
    filter_model: Annotated[str | None, _env("filter_model")] = Field(
        default=None, description="Model for the false-positive filter. Default: the review model (as upstream)."
    )
    mode: Annotated[Literal["stock", "scoped"], _env("mode")] = Field(
        default="stock",
        description="stock: upstream prompts and filter unchanged. scoped: adds the benchmark's LLM02/LLM03 scope "
        "and the security_manifest.json pointer through the upstream custom instructions, asks for a CWE list per "
        "finding, and uses a filter text without two default exclusions that cover those risks.",
    )
    filter: Annotated[Literal["claude", "hard_rules"], _env("filter")] = Field(
        default="claude",
        description="claude: upstream hard rules plus the per-finding Claude check (the action's default with "
        "filtering on). hard_rules: the regex rules only, no API calls.",
    )
    max_turns: Annotated[int | None, _env("max_turns")] = Field(
        default=None, ge=1, description="Claude Code --max-turns for the review. Default: none, as upstream."
    )
    max_budget_usd: Annotated[float | None, _env("max_budget_usd")] = Field(
        default=None, gt=0, description="Claude Code --max-budget-usd for the review. Default: none, as upstream."
    )
    timeout_sec: Annotated[int | None, _env("timeout_sec")] = Field(
        default=None,
        ge=120,
        description="Wall-clock limit for the whole review (CLI and filter). Default: the task's agent timeout "
        "minus 120 s. Raise Harbor's own limit to match (--agent-timeout-multiplier).",
    )
    scan_budget_sec: int | None = Field(default=None, ge=120, description="Same as timeout_sec (the other agents' name).")
    cli_share: Annotated[float, _env("cli_share")] = Field(
        default=0.6, ge=0.2, le=0.95,
        description="Share of the time limit the CLI review may use. The filter gets the rest.",
    )
    cli_attempts: Annotated[int, _env("cli_attempts")] = Field(
        default=3, ge=1, le=5, description="CLI attempts, as upstream's 3."
    )
    cli_auth: Annotated[Literal["api_key_helper", "env"], _env("cli_auth")] = Field(
        default="api_key_helper",
        description="How the CLI gets the key: an apiKeyHelper that reads the key file (default), or the CLI "
        "process's own environment (fallback if a CLI version ignores apiKeyHelper). Never on a command line.",
    )
    scan_roots: list[str] | None = Field(
        default=None,
        description="Paths inside /app/repo to review (comma-separated). Default: the task's metadata.scanner_roots, "
        "else the whole repository.",
    )
    exclude: list[str] | None = Field(
        default=None, description="Paths to skip (comma-separated). Default: the task's metadata.excluded_paths."
    )
    reasoning_effort: str | None = Field(
        default=None, description="Accepted and recorded, not used: the upstream tool sets no effort."
    )

    @field_validator("scan_roots", "exclude", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("model", "filter_model", mode="before")
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
