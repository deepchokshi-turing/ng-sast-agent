"""``--ak`` settings for the CodeQL agent.

The CodeQL version and the query suites are pinned in ``pins.py`` and are not
options, so a run cannot quietly use a different engine or query set.

Unknown keys are accepted and recorded instead of rejected: Harbor validates
options once per job, so one stray key would otherwise fail every trial.
"""

from __future__ import annotations

from typing import Any

from harbor.agents.options import AgentOptions
from pydantic import ConfigDict, Field, field_validator


class CodeQLOptions(AgentOptions):
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    scan_roots: list[str] | None = Field(
        default=None,
        description="Paths inside /app/repo to scan (comma-separated). Default: the task's "
        "metadata.scanner_roots, else the whole repository.",
    )
    exclude: list[str] | None = Field(
        default=None,
        description="Paths to skip (comma-separated). Default: the task's metadata.excluded_paths.",
    )
    threads: int | None = Field(default=None, ge=1, description="CodeQL --threads. Default: the sandbox's CPUs.")
    ram_mb: int | None = Field(
        default=None,
        ge=256,
        description="CodeQL --ram in MB. Default: the sandbox's memory minus 512 MB for the extractors.",
    )
    scan_budget_sec: int | None = Field(
        default=None,
        ge=1,
        description="Wall-clock limit for database creation plus analysis. Default: the task's agent timeout "
        "minus 120 s.",
    )
    reasoning_effort: str | None = Field(default=None, description="Accepted and ignored: no model is called.")

    @field_validator("scan_roots", "exclude", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value
