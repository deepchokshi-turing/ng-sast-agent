"""``--ak`` settings for the Semgrep agent.

The Semgrep version and the rules are pinned in ``pins.py`` and are not options,
so a run cannot quietly use a different engine or rule set.

Unknown keys are accepted and recorded instead of rejected: Harbor validates
options once per job, so one stray key (a QC stage's agent args, an effort level)
would otherwise fail every trial of the job before any of them starts.
"""

from __future__ import annotations

from typing import Any

from harbor.agents.options import AgentOptions
from pydantic import ConfigDict, Field, field_validator


class SemgrepOptions(AgentOptions):
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    scan_roots: list[str] | None = Field(
        default=None,
        description="Paths inside /app/repo to scan (comma-separated). Default: the task's "
        "metadata.scanner_roots, else the whole repository.",
    )
    exclude: list[str] | None = Field(
        default=None,
        description="Paths to skip (comma-separated), passed to semgrep --exclude. Default: the "
        "task's metadata.excluded_paths.",
    )
    jobs: int | None = Field(default=None, ge=1, description="Semgrep -j. Default: the task's cpus, else nproc.")
    per_file_timeout_sec: int = Field(default=30, ge=1, description="Semgrep --timeout per rule and file.")
    scan_budget_sec: int | None = Field(
        default=None,
        ge=1,
        description="Wall-clock limit for the scan. Default: the task's agent timeout minus 120 s.",
    )
    max_memory_mb: int | None = Field(
        default=None,
        ge=1,
        description="Semgrep --max-memory. Default: the task's memory_mb minus 512.",
    )
    reasoning_effort: str | None = Field(default=None, description="Accepted and ignored: no model is called.")

    @field_validator("scan_roots", "exclude", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value
