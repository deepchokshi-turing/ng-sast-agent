"""``--ak`` settings for the Claude Code security review agent.

Every option can also come from the host's environment, as
``CLAUDE_REVIEW_<OPTION>`` (for example ``CLAUDE_REVIEW_MODEL``). An ``--ak``
value wins over the environment. The credential is not an option: it is read
from ``ANTHROPIC_API_KEY`` or ``CLAUDE_CODE_OAUTH_TOKEN`` on the host, so it
never sits in a job config. ``auth`` only says which of the two to use.

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
        default="scoped",
        description="scoped is the default (the benchmark's output contract); stock: upstream prompts and filter unchanged. scoped: adds the benchmark's LLM02/LLM03 scope "
        "and the security_manifest.json pointer through the upstream custom instructions, asks for a CWE list per "
        "finding, and uses a filter text without two default exclusions that cover those risks.",
    )
    auth: Annotated[Literal["api_key", "oauth", "auto"], _env("auth")] = Field(
        default="auto",
        description="Which host credential to use. api_key: ANTHROPIC_API_KEY. oauth: CLAUDE_CODE_OAUTH_TOKEN, a "
        "subscription token made with `claude setup-token` (the filter then runs its regex rules only and there is "
        "no API preflight). auto: api_key when ANTHROPIC_API_KEY is set, else oauth when CLAUDE_CODE_OAUTH_TOKEN "
        "is set.",
    )
    filter: Annotated[Literal["claude", "hard_rules"] | None, _env("filter")] = Field(
        default=None,
        description="claude: upstream hard rules plus the per-finding Claude check (the action's default with "
        "filtering on). hard_rules: the regex rules only, no API calls. Default: claude with an API key, "
        "hard_rules with a subscription token (which cannot call the API). claude with a subscription token is "
        "refused.",
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
        description="How the CLI gets an API key: an apiKeyHelper that reads the key file (default), or the CLI "
        "process's own environment (fallback if a CLI version ignores apiKeyHelper). Never on a command line. Not "
        "used with auth oauth: a subscription token always goes into the CLI process's environment.",
    )
    scan_roots: list[str] | None = Field(
        default=None,
        description="Paths inside /app/repo to review (comma-separated). Default: the task's metadata.scanner_roots, "
        "else the whole repository.",
    )
    exclude: list[str] | None = Field(
        default=None, description="Paths to skip (comma-separated). Default: the task's metadata.excluded_paths."
    )
    reasoning_effort: Annotated[Literal["low", "medium", "high", "xhigh", "max"] | None, _env("reasoning_effort")] = Field(
        default=None,
        description="Claude Code --effort for the review (low, medium, high, xhigh, max). Default: none, the CLI's "
        "own default, as upstream (which sets no effort). Setting it is a deviation from upstream and is recorded "
        "in the metadata and SARIF. The filter's API calls are not affected.",
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
