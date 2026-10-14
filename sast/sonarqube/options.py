"""``--ak`` settings for the SonarQube agent.

The server and the token are not options: they come from the host's
environment (``SONAR_HOST_URL``, ``SONAR_TOKEN``), so the token never sits in a
job config. Unknown keys are accepted and recorded, as for the Semgrep agent.
"""

from __future__ import annotations

from typing import Any

from harbor.agents.options import AgentOptions
from pydantic import ConfigDict, Field, field_validator


class SonarQubeOptions(AgentOptions):
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    scan_roots: list[str] | None = Field(
        default=None,
        description="Paths inside /app/repo to scan (comma-separated), as sonar.sources. Default: the task's "
        "metadata.scanner_roots, else the whole repository.",
    )
    exclude: list[str] | None = Field(
        default=None,
        description="Paths to skip (comma-separated), turned into sonar.exclusions globs. Default: the task's "
        "metadata.excluded_paths.",
    )
    scan_budget_sec: int | None = Field(
        default=None,
        ge=1,
        description="Wall-clock limit for the server check, sonar-scanner and collecting the results together. "
        "Default: the task's agent timeout minus 120 s.",
    )
    keep_project: bool = Field(
        default=False,
        description="Leave the scanned project on the server instead of deleting it (to look at it in the UI).",
    )
    reasoning_effort: str | None = Field(default=None, description="Accepted and ignored: no model is called.")

    @field_validator("scan_roots", "exclude", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value
