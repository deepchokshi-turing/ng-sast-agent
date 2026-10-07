"""The one exception a scanner agent raises."""


class ScannerError(RuntimeError):
    """The scanner could not produce a trustworthy result.

    Deliberately not a Harbor error type. Harbor grades a trial whose agent raised
    ``AgentTimeoutError`` or ``NonZeroAgentExitCodeError`` (the verifier still runs
    and scores the missing output 0), but any other exception skips the verifier,
    so the trial is recorded as errored and can be re-run. A scan that failed is
    not a scan that found nothing.
    """
