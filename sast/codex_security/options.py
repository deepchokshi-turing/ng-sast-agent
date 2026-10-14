"""``--ak`` settings for the Codex security review agent.

Every option can also come from the host's environment, as
``CODEX_SECURITY_<OPTION>`` (for example ``CODEX_SECURITY_MODEL``). An ``--ak``
value wins over the environment. The credential is not an option: it is read
from ``OPENAI_API_KEY`` or ``CODEX_API_KEY`` on the host, so it never sits in a
job config. ``auth`` only says which of the two to use.

Unknown keys are accepted and recorded instead of rejected, as for the other
agents: Harbor validates options once per job, so one stray key would fail
every trial of the job before any of them starts.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from harbor.agents.options import AgentOptions, Env
from pydantic import ConfigDict, Field, field_validator

from . import pins

_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


def _env(option: str) -> Env:
    name = f"CODEX_SECURITY_{option.upper()}"
    return Env(name, fallback=name)


class CodexSecurityOptions(AgentOptions):
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    model: Annotated[str | None, _env("model")] = Field(
        default=None,
        description=f"Model for the review (codex exec -m). Default: {pins.DEFAULT_MODEL}, the default scan model "
        "of OpenAI's Codex Security CLI. Harbor's -m is not used.",
    )
    reasoning_effort: Annotated[str | None, _env("reasoning_effort")] = Field(
        default=None,
        description="Codex model_reasoning_effort (low, medium, high, xhigh, ... as the model supports). Default: "
        "none set, so the model's own default from Codex's catalog applies (low for gpt-5.6-sol).",
    )
    mode: Annotated[Literal["stock", "scoped"], _env("mode")] = Field(
        default="scoped",
        description="scoped is the default (the benchmark's output contract); stock: a fixed security review prompt and Codex's own review finding shape (plus category and "
        "CWE). scoped: adds the task's output contract (ruleIds, path roles, control status, residual risk, "
        "recommendation catalogue) to the prompt and to the output schema.",
    )
    auth: Annotated[Literal["auto", "openai_api_key", "codex_api_key"], _env("auth")] = Field(
        default="auto",
        description="Which host variable holds the API key. auto: OPENAI_API_KEY when set, else CODEX_API_KEY.",
    )
    sandbox: Annotated[Literal["read-only", "container"], _env("sandbox")] = Field(
        default="read-only",
        description="read-only: Codex's own read-only sandbox (bubblewrap; needs unprivileged user namespaces in "
        "the task container, which default Docker does not allow: the run then stops with sandbox_unavailable). "
        "container: Codex's sandbox off (--dangerously-bypass-approvals-and-sandbox), the task container is the "
        "only boundary. An explicit opt-in, see docs/codex-security-agent.md.",
    )
    timeout_sec: Annotated[int | None, _env("timeout_sec")] = Field(
        default=None,
        ge=120,
        description="Wall-clock limit for the whole review. Default: the task's agent timeout minus 120 s. Raise "
        "Harbor's own limit to match (--agent-timeout-multiplier).",
    )
    scan_budget_sec: int | None = Field(default=None, ge=120, description="Same as timeout_sec (the other agents' name).")
    attempts: Annotated[int, _env("attempts")] = Field(
        default=2, ge=1, le=3,
        description="codex exec attempts when an attempt gives no usable answer (a refused key, an unknown model or "
        "a closed network stop at once).",
    )
    scan_roots: list[str] | None = Field(
        default=None,
        description="Paths inside /app/repo to review (comma-separated). Default: the task's metadata.scanner_roots, "
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

    @field_validator("model", "reasoning_effort", mode="before")
    @classmethod
    def _word(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("openai/"):
                value = value.split("/", 1)[1]
            if not value:
                return None
            if not _WORD.match(value):
                raise ValueError(f"not a model id or effort: {value!r}")
        return value
