"""A scanner finding, normalised from the tool's own output."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TraceStep:
    """One step of a dataflow trace the tool itself reported."""

    #: Relative to /app/repo, like ``Finding.file``.
    file: str
    start_line: int
    end_line: int
    #: The step's role when the tool names it itself (one of ``PATH_ROLES``),
    #: else None and the SARIF writer marks only the first and last step.
    role: str | None = None


#: The step roles of the output contract (``properties.role`` in each task's instruction.md).
PATH_ROLES = ("source", "root_cause", "context_assembly", "model_consumption", "model_decision", "control_point",
              "sink")
CONTROL_STATUSES = ("none", "partial", "complete")
RISK_LEVELS = ("low", "medium", "high")


@dataclass(frozen=True)
class Finding:
    tool_rule_id: str
    #: Exact "CWE-<n>" strings, in the rule's own order (primary CWE first).
    cwes: tuple[str, ...]
    #: Relative to /app/repo, "/"-separated, no leading "./" or "/".
    file: str
    start_line: int
    end_line: int
    message: str
    #: SARIF level: "error", "warning" or "note".
    level: str
    #: "low", "medium" or "high", from the rule's severity and impact metadata
    #: (``sast.heuristics.residual_risk``).
    residual_risk: str = "medium"
    #: The tool's own dataflow path, source first and sink last. Empty when the
    #: tool reported none. Never made up from the match location.
    trace: tuple[TraceStep, ...] = ()
    #: Tool-specific labels copied into the SARIF result's properties under
    #: ``toolProperties`` (for example SonarQube's sonarType). Never scored.
    extra: tuple[tuple[str, str], ...] = ()
    #: The tool's own assessment of the controls on the path, residual risk and
    #: catalogue recommendations, written to the scored top-level SARIF
    #: properties. None (or empty) when the tool gave none. Only a tool that
    #: reports these itself sets them; the fixed tables in ``sast.heuristics``
    #: never do.
    control_status: str | None = None
    assessed_residual_risk: str | None = None
    recommendations: tuple[str, ...] = ()
    #: The task ruleId when the tool names it itself (Claude review in scoped
    #: mode, one of ``cwe_map.TASK_RULES``). None means the ruleId comes from
    #: the CWE table, as for every pattern or taint scanner.
    task_rule: str | None = None

    def compact(self, emitted_rule: str | None) -> list:
        """One row of the run's metadata, small enough to keep thousands."""
        return [self.tool_rule_id, list(self.cwes), self.file, self.start_line, self.end_line, emitted_rule]
