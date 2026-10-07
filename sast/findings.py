"""A scanner finding, normalised from the tool's own output."""

from __future__ import annotations

from dataclasses import dataclass


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

    def compact(self, emitted_rule: str | None) -> list:
        """One row of the run's metadata, small enough to keep thousands."""
        return [self.tool_rule_id, list(self.cwes), self.file, self.start_line, self.end_line, emitted_rule]
