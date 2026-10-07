"""Semgrep ``--json`` output -> findings.

Only ``metadata.category == "security"`` results are kept, the same filter as the
earlier SAST sheet. It covers audit, secure-default and secrets rules.
"""

from __future__ import annotations

import re
from typing import Any

from ..findings import Finding

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
        "results_by_category": dict(sorted(categories.items())),
        "semgrep_errors": len(errors),
        "semgrep_error_types": dict(sorted(error_types.items())),
        "files_scanned": len(paths.get("scanned") or []),
        "skipped_rules": len(output.get("skipped_rules") or []),
    }
    return findings, counts
