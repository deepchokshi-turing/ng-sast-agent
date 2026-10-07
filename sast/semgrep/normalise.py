"""Semgrep ``--json`` output -> findings.

Only ``metadata.category == "security"`` results are kept, the same filter as the
earlier SAST sheet. It covers audit, secure-default and secrets rules.

With ``--dataflow-traces``, a taint rule's result carries ``extra.dataflow_trace``
(semgrep_output_v1)::

    "dataflow_trace": {
      "taint_source": ["CliLoc", [{"path": ..., "start": {"line": ..}, "end": {..}}, "<code>"]],
      "intermediate_vars": [{"location": {"path": .., "start": .., "end": ..}, "content": "<code>"}],
      "taint_sink": ["CliLoc", [<location>, "<code>"]]
    }

A source or sink inside a called function is ``["CliCall", [[<call site
location>, "<code>"], [<intermediate vars>], <inner trace>]]``. Only what the
tool printed is kept: the innermost source location, the intermediate
variables, and the code at every level of the sink. Nothing is inferred.
"""

from __future__ import annotations

import re
from typing import Any

from .. import heuristics
from ..findings import Finding, TraceStep

_CWE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)

# Semgrep severities across versions -> SARIF levels.
_LEVELS = {
    "ERROR": "error",
    "CRITICAL": "error",
    "HIGH": "error",
    "WARNING": "warning",
    "MEDIUM": "warning",
    "INFO": "note",
    "LOW": "note",
    "INVENTORY": "note",
    "EXPERIMENT": "note",
}


def cwes_of(metadata: dict[str, Any]) -> tuple[str, ...]:
    """Exact "CWE-<n>" ids from metadata.cwe (a string or a list), in order."""
    raw = metadata.get("cwe")
    items = [raw] if isinstance(raw, str) else (raw if isinstance(raw, list) else [])
    seen: list[str] = []
    for item in items:
        for number in _CWE.findall(str(item)):
            cwe = f"CWE-{int(number)}"
            if cwe not in seen:
                seen.append(cwe)
    return tuple(seen)


def repo_path(path: str, repo_dir: str = "/app/repo") -> str:
    """A result path relative to the repository root, "/"-separated."""
    path = path.replace("\\", "/")
    if path.startswith(repo_dir.rstrip("/") + "/"):
        path = path[len(repo_dir.rstrip("/")) + 1:]
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def _step(location: Any, content: Any = "") -> TraceStep | None:
    """A TraceStep from a semgrep_output_v1 location, or None if it has no line."""
    if not isinstance(location, dict):
        return None
    try:
        start = int((location.get("start") or {}).get("line") or 0)
        end = int((location.get("end") or {}).get("line") or start)
    except (TypeError, ValueError):
        return None
    if start < 1:
        return None
    return TraceStep(repo_path(str(location.get("path") or "")), start, max(start, end),
                     " ".join(str(content or "").split())[:300])


def _call_trace(node: Any, depth: int = 0) -> list[tuple[Any, Any]]:
    """[(location, content)] for a match_call_trace, outermost first.

    ``CliLoc`` is one (location, code) pair; ``CliCall`` is the call site, the
    variables inside the callee, then the callee's own trace.
    """
    if depth > 50 or not isinstance(node, list) or len(node) != 2:
        return []
    kind, payload = node
    if kind == "CliLoc" and isinstance(payload, list) and len(payload) == 2:
        return [(payload[0], payload[1])]
    if kind == "CliCall" and isinstance(payload, list) and len(payload) == 3:
        site = payload[0] if isinstance(payload[0], list) and len(payload[0]) == 2 else [None, ""]
        return [(site[0], site[1]), *_call_trace(payload[2], depth + 1)]
    return []


def dataflow(extra: dict[str, Any]) -> dict[str, Any]:
    """Finding fields from ``extra.dataflow_trace``; {} when there is no trace."""
    trace = extra.get("dataflow_trace")
    if not isinstance(trace, dict):
        return {}
    source_chain = _call_trace(trace.get("taint_source"))
    # The innermost location is where the data originates; call sites on the
    # way out are propagation, like intermediate variables.
    source = next((s for s in (_step(*pair) for pair in reversed(source_chain)) if s is not None), None)
    intermediate = tuple(
        step for step in (
            _step(var.get("location"), var.get("content"))
            for var in (trace.get("intermediate_vars") or []) if isinstance(var, dict)
        ) if step is not None
    )
    sink_code = tuple(
        code for code in (" ".join(str(c or "").split())[:300] for _, c in _call_trace(trace.get("taint_sink")))
        if code
    )
    if source is None and not intermediate and not sink_code:
        return {}
    return {"trace_source": source, "trace_intermediate": intermediate, "trace_sink_code": sink_code}


def normalise(output: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    """(security findings, counts) from one Semgrep JSON document."""
    results = output.get("results")
    if not isinstance(results, list):
        raise ValueError("Semgrep output has no results list")

    findings: list[Finding] = []
    categories: dict[str, int] = {}
    for result in results:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        category = str(metadata.get("category") or "none")
        categories[category] = categories.get(category, 0) + 1
        if category != "security":
            continue
        start = int((result.get("start") or {}).get("line") or 0)
        end = int((result.get("end") or {}).get("line") or start)
        if start < 1:
            continue
        findings.append(Finding(
            tool_rule_id=str(result.get("check_id") or ""),
            cwes=cwes_of(metadata),
            file=repo_path(str(result.get("path") or "")),
            start_line=start,
            end_line=max(end, start),
            message=" ".join(str(extra.get("message") or "").split())[:1000],
            level=_LEVELS.get(str(extra.get("severity") or "").upper(), "warning"),
            residual_risk=heuristics.residual_risk(extra.get("severity"), metadata.get("impact")),
            **dataflow(extra),
        ))

    errors = output.get("errors") or []
    error_types: dict[str, int] = {}
    for error in errors:
        kind = error.get("type", "unknown") if isinstance(error, dict) else "unknown"
        if isinstance(kind, list):  # some versions write ["Timeout", ...]
            kind = kind[0] if kind else "unknown"
        error_types[str(kind)] = error_types.get(str(kind), 0) + 1
    paths = output.get("paths") or {}
    counts = {
        "results_raw": len(results),
        "findings_with_dataflow_trace": sum(1 for f in findings if f.has_trace),
        "results_by_category": dict(sorted(categories.items())),
        "semgrep_errors": len(errors),
        "semgrep_error_types": dict(sorted(error_types.items())),
        "files_scanned": len(paths.get("scanned") or []),
        "skipped_rules": len(output.get("skipped_rules") or []),
    }
    return findings, counts
