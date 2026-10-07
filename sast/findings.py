"""A scanner finding, normalised from the tool's own output."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TraceStep:
    """One location the tool itself reported on a dataflow trace."""

    #: Relative to /app/repo, "/"-separated, no leading "./" or "/".
    file: str
    start_line: int
    end_line: int
    #: The code at that location as the tool printed it ("" when it gave none).
    content: str = ""


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
    #: Where the tool says the tainted data comes from (taint rules run with
    #: ``--dataflow-traces`` only). None when the tool gave no trace.
    trace_source: TraceStep | None = None
    #: Variables the tool says the data passed through, in order.
    trace_intermediate: tuple[TraceStep, ...] = ()
    #: Code the tool reported at the sink end of the trace (the match itself,
    #: or the call inside a callee for an interprocedural trace).
    trace_sink_code: tuple[str, ...] = ()

    @property
    def has_trace(self) -> bool:
        return self.trace_source is not None or bool(self.trace_intermediate) or bool(self.trace_sink_code)

    def compact(self, emitted_rule: str | None) -> list:
        """One row of the run's metadata, small enough to keep thousands."""
        return [self.tool_rule_id, list(self.cwes), self.file, self.start_line, self.end_line, emitted_rule]
