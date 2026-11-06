"""The two ways a scanner agent's run can fail.

Harbor 0.23 records ``AgentTimeoutError`` and ``NonZeroAgentExitCodeError`` and
still runs the verifier; any other exception skips the verifier, so the trial is
recorded as errored and can be re-run. The two classes below follow that split.

- ``ScannerError``: an infrastructure failure. The tool could not be installed,
  the sandbox, Docker or Harbor misbehaved, a credential is missing or refused,
  the API or the SonarQube server could not be reached, the agent's own output
  could not be read. Nothing was learnt about the tool, so the agent raises it,
  the verifier does not run and the trial can be re-run.
- ``ToolOutcome``: the tool itself did not deliver on this repository. The scan
  budget or the review deadline ran out, the review said it was incomplete or
  reviewed no file, the CLI hit its turn or budget limit, the tool crashed on
  the code. That is a result about the tool, not a broken run. The agent records
  it (``tool_outcome`` in the run metadata), writes no SARIF and returns
  normally, so Harbor runs the verifier and the grader scores the missing SARIF
  0, on a positive task and on a negative one alike (an unfinished scan must not
  earn the credit of a clean one).

``ToolOutcome`` is a subclass of ``ScannerError`` so that every cleanup path
that catches ``ScannerError`` (removing a key file, deleting a SonarQube
project) still runs; ``ScannerAgent.run`` tells the two apart.
"""

from __future__ import annotations

#: Reasons a ``ToolOutcome`` may carry. Recorded as ``tool_outcome.reason``.
TOOL_OUTCOME_REASONS = (
    "deadline",             # the scan budget or the review deadline ran out
    "tool_killed",          # the tool was killed (out of memory, SIGTERM) while scanning
    "tool_crashed",         # the tool exited with an error on this repository
    "tool_saw_nothing",     # the tool ran but analysed none of the in-scope code
    "review_incomplete",    # the model said review_completed false
    "files_reviewed_zero",  # the model said it reviewed no file
    "cli_limit",            # the Claude CLI stopped at --max-turns or --max-budget-usd
    "prompt_too_long",      # the review prompt is too long even without the diff
    "bad_review_output",    # the model's findings are not usable JSON objects
    "too_many_files",       # more files in scope than the agent reviews
)


class ScannerError(RuntimeError):
    """An infrastructure failure: the run tells nothing about the tool.

    Deliberately not a Harbor error type, so the verifier does not run and the
    trial is recorded as errored and can be re-run. A scan that could not run is
    not a scan that found nothing.
    """


class ToolOutcome(ScannerError):
    """The tool did not finish or failed on the repository: scored, not re-run.

    ``reason`` is one of :data:`TOOL_OUTCOME_REASONS`. See the module docstring.
    """

    def __init__(self, reason: str, message: str):
        if reason not in TOOL_OUTCOME_REASONS:
            raise ValueError(f"unknown tool outcome reason {reason!r}")
        super().__init__(message)
        self.reason = reason

    def with_message(self, message: str) -> "ToolOutcome":
        """The same outcome with another message (for example a scrubbed one)."""
        return ToolOutcome(self.reason, message)
