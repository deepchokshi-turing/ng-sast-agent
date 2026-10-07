"""``--ak`` settings for the CodeQL agent.

The CodeQL version and the query suite are pinned in ``pins.py`` and are not
options. The scan scope, threads and memory come from the task.

Unknown keys are accepted and recorded instead of rejected, as for the Semgrep
agent: Harbor validates options once per job, so one stray key would otherwise
fail every trial of the job before any of them starts.
"""

from __future__ import annotations

from harbor.agents.options import AgentOptions
from pydantic import ConfigDict, Field


class CodeQLOptions(AgentOptions):
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    scan_budget_sec: int | None = Field(
        default=None,
        ge=1,
        description="Wall-clock limit for database create plus analyze. Default: the task's agent "
        "timeout minus 120 s.",
    )
    reasoning_effort: str | None = Field(default=None, description="Accepted and ignored: no model is called.")
