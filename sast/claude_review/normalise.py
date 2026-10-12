"""The driver's kept findings -> ``Finding`` objects.

Each kept finding (after the upstream filter) has ``file``, ``line``,
``severity`` (HIGH/MEDIUM/LOW), a free-text ``category``, ``description``,
``exploit_scenario``, ``recommendation``, ``confidence`` and the filter's
``_filter_metadata``. In scoped mode it may also have ``cwe``.

- Location: ``file`` relative to /app/repo (``scope.repo_path``) must be one of
  the in-scope text files the driver read, and ``line`` a positive integer no
  larger than that file's line count. It is used as start and end line, since
  the review gives one line. Anything else is dropped and counted.
- CWEs: in scoped mode the model's list when at least one entry is valid
  (``category_map.valid_cwes``), else the category table. In stock mode the
  table only. The set is decided by ``cwe_map.decide_unordered``, as for
  CodeQL and SonarQube: an ambiguous set is dropped and counted, and a finding
  with no mapped CWE is passed on and counted by the SARIF writer as unmapped.
- Level and residual risk: HIGH gives ``error``/``high``, MEDIUM
  ``warning``/``medium``, LOW ``note``/``low`` (``heuristics.residual_risk``).
  Any other severity gives ``warning``/``medium`` and is counted.
- No trace: the review reports an exploit scenario in prose, not a path, so no
  codeFlows are written (see ``sast.sarif``).
- The category, severity, both confidences, the CWE source and short copies of
  the exploit scenario and recommendation go to ``Finding.extra``, which the
  SARIF writer puts under ``toolProperties``. They are never scored. Control
  status and recommendations come from ``sast.heuristics`` as for every
  scanner, because the review's free-text recommendation cannot be turned into
  the task's REC ids without guessing.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .. import cwe_map, heuristics
from ..findings import Finding
from ..scope import in_scope, repo_path
from . import category_map

LEVELS = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
MESSAGE_CHARS = 1000
EXTRA_CHARS = 500


def _text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _line(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def normalise(
    kept: list[dict[str, Any]],
    *,
    mode: str,
    line_counts: dict[str, int],
    roots: list[str],
    excludes: list[str],
) -> tuple[list[Finding], dict[str, Any]]:
    """(findings, counts for the run metadata)."""
    findings: list[Finding] = []
    dropped_location: list[list[Any]] = []
    dropped_scope: list[list[Any]] = []
    ambiguous: list[list[Any]] = []
    unmapped_category: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    decisions: Counter[str] = Counter({"none": 0, "unmapped": 0, "mapped": 0, "ambiguous": 0})
    rejected: list[str] = []
    severities: Counter[str] = Counter()

    for item in kept:
        if not isinstance(item, dict):
            dropped_location.append(["not an object", None, None])
            continue
        raw_file = str(item.get("file") or "")
        file = repo_path(raw_file)
        line = _line(item.get("line"))
        if not file or not in_scope(file, roots, excludes):
            dropped_scope.append([raw_file[:200], item.get("line")])
            continue
        if file not in line_counts:
            dropped_location.append(["not a text file the review was given", file, item.get("line")])
            continue
        if line is None or line < 1 or line > line_counts[file]:
            dropped_location.append(["line outside the file", file, item.get("line")])
            continue

        category = category_map.normalise(item.get("category"))
        model_cwes: tuple[str, ...] = ()
        if mode == "scoped":
            model_cwes, bad = category_map.valid_cwes(item.get("cwe", item.get("cwes")))
            rejected += bad
        if model_cwes:
            cwes, source = model_cwes, "model"
        else:
            table = category_map.lookup(category)
            cwes = (table,) if table else ()
            source = ("table" if mode == "stock" else "table_fallback") if table else "none"
            if not table:
                unmapped_category[category or "(empty)"] += 1
        sources[source] += 1
        decision, _family, ordered = cwe_map.decide_unordered(cwes)
        decisions[decision] += 1
        if decision == "ambiguous":
            ambiguous.append([category, list(ordered), file, line])
            continue

        severity = str(item.get("severity") or "").strip().upper()
        severities[severity if severity in LEVELS else "other"] += 1
        meta = item.get("_filter_metadata") if isinstance(item.get("_filter_metadata"), dict) else {}
        extra = [
            ("category", _text(item.get("category"), 100)),
            ("severity", severity or "missing"),
            ("confidence", _text(item.get("confidence"), 20)),
            ("filterConfidence", _text(meta.get("confidence_score"), 20)),
            ("cweSource", source),
        ]
        for key, field in (("exploitScenario", "exploit_scenario"), ("recommendation", "recommendation")):
            if item.get(field):
                extra.append((key, _text(item.get(field), EXTRA_CHARS)))
        findings.append(Finding(
            tool_rule_id="ccsr/" + (category or "uncategorised"),
            cwes=ordered,
            file=file,
            start_line=line,
            end_line=line,
            message=_text(item.get("description"), MESSAGE_CHARS) or category,
            level=LEVELS.get(severity, "warning"),
            residual_risk=heuristics.residual_risk(severity, None),
            extra=tuple(extra),
        ))

    counts = {
        "category_map": category_map.VERSION,
        "findings_kept_by_filter": len(kept),
        "dropped_bad_location": dropped_location[:200],
        "dropped_bad_location_count": len(dropped_location),
        "dropped_out_of_scope": dropped_scope[:200],
        "dropped_out_of_scope_count": len(dropped_scope),
        "unmapped_by_category": dict(sorted(unmapped_category.items())),
        "cwe_source": dict(sorted(sources.items())),
        "cwes_rejected": rejected[:200],
        "results_by_cwe_decision": dict(decisions),
        "results_cwe_ambiguous": ambiguous[:200],
        "findings_by_severity": dict(sorted(severities.items())),
    }
    return findings, counts
