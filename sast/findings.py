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

    def compact(self, emitted_rule: str | None) -> list:
        """One row of the run's metadata, small enough to keep thousands."""
        return [self.tool_rule_id, list(self.cwes), self.file, self.start_line, self.end_line, emitted_rule]
