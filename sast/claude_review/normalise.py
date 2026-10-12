"""The driver's kept findings -> ``Finding`` objects.

Each kept finding (after the upstream filter) has ``file``, ``line``,
``severity`` (HIGH/MEDIUM/LOW), a free-text ``category``, ``description``,
``exploit_scenario``, ``recommendation``, ``confidence`` and the filter's
``_filter_metadata``. In scoped mode it may also have ``cwe``.

- Location: ``file`` relative to /app/repo (``scope.repo_path``) must be one of
  the in-scope text files the driver read, and ``line`` a positive integer no
  larger than that file's line count. It is used as start and end line, since
  the review gives one line. Anything else is dropped and counted.
- CWEs: in scoped mode the model's list when at least one entry is a
  well-formed CWE id (``category_map.valid_cwes``; any id is accepted, only
  malformed values are rejected and counted), else the category table. In stock mode the
  table only. The set is decided by ``cwe_map.decide_unordered``, as for
  CodeQL and SonarQube: an ambiguous set is dropped and counted, and a finding
  with no mapped CWE is passed on and counted by the SARIF writer as unmapped.
- RuleId, scoped mode: the model's ``rule_id`` when it is one of the task
  profile's ruleIds (``cwe_map.TASK_RULES``), as the task instruction asks every
  scanner to report. It is kept as ``Finding.task_rule``, so the CWEs no longer
  decide the ruleId: an ambiguous or unmapped CWE set does not drop the finding,
  and ``LLM03.EA.AUTONOMY``, which no CWE maps to, can be reported. Without a
  valid ``rule_id`` the CWEs decide as above. ``rule_source`` counts both.
- Level and residual risk: HIGH gives ``error``/``high``, MEDIUM
  ``warning``/``medium``, LOW ``note``/``low`` (``heuristics.residual_risk``).
  Any other severity gives ``warning``/``medium`` and is counted.
- Path (scoped mode only): the model's ``path`` list becomes ``Finding.trace``
  and so the result's codeFlows. A step must be an object whose ``file`` and
  ``line`` pass the same checks as the finding's own location, else it is
  dropped and counted. Its ``role`` is kept when it is one of
  ``findings.PATH_ROLES``. At most ``MAX_PATH_STEPS`` steps are kept. In stock
  mode the review gives only an exploit scenario in prose, so no codeFlows are
  written (see ``sast.sarif``).
- Controls and recommendations (scoped mode only): ``control_status`` and
  ``residual_risk`` are kept when they are one of the profile's values, and
  ``recommendation_ids`` keeps the ids found in the task's catalogue
  (``heuristics.CATALOGUE``), in order and without repeats. Anything else is
  dropped and counted. These go to the scored top-level SARIF properties. In
  stock mode, and for a field the model left out, nothing is scored: the
  review's free-text recommendation cannot be turned into the task's REC ids
  without guessing, and the fixed values from ``sast.heuristics`` stay under
  ``properties.heuristics`` as for every scanner.
- The category, severity, both confidences, the CWE source and short copies of
  the exploit scenario and recommendation go to ``Finding.extra``, which the
  SARIF writer puts under ``toolProperties``. They are never scored.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .. import cwe_map, heuristics
from ..findings import CONTROL_STATUSES, PATH_ROLES, RISK_LEVELS, Finding, TraceStep
from ..scope import in_scope, repo_path
from . import category_map

LEVELS = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
MESSAGE_CHARS = 1000
EXTRA_CHARS = 500
MAX_PATH_STEPS = 20


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


def _location_problem(file: str, line: int | None, line_counts: dict[str, int], roots: list[str],
                      excludes: list[str]) -> str | None:
    """Why (file, line) is not a usable location, or None when it is."""
    if not file or not in_scope(file, roots, excludes):
        return "out of scope"
    if file not in line_counts:
        return "not a text file the review was given"
    if line is None or line < 1 or line > line_counts[file]:
        return "line outside the file"
    return None


def _path(value: Any, line_counts: dict[str, int], roots: list[str], excludes: list[str],
          dropped: list[list[Any]]) -> tuple[TraceStep, ...]:
    """The model's ``path`` list as trace steps; bad steps go to ``dropped``."""
    if value is None:
        return ()
    if not isinstance(value, list):
        dropped.append(["path is not a list", _text(value, 100), None])
        return ()
    steps: list[TraceStep] = []
    for raw in value:
        if not isinstance(raw, dict):
            dropped.append(["step is not an object", _text(raw, 100), None])
            continue
        file = repo_path(str(raw.get("file") or ""))
        line = _line(raw.get("line"))
        problem = _location_problem(file, line, line_counts, roots, excludes)
        if problem:
            dropped.append([problem, str(raw.get("file") or "")[:200], raw.get("line")])
            continue
        if len(steps) == MAX_PATH_STEPS:
            dropped.append(["more than {} steps".format(MAX_PATH_STEPS), file, line])
            continue
        role = str(raw.get("role") or "").strip().lower()
        steps.append(TraceStep(file=file, start_line=line, end_line=line, role=role if role in PATH_ROLES else None))
    return tuple(steps)


def _choice(value: Any, allowed: tuple[str, ...], rejected: list[str], normal=str.lower) -> str | None:
    """``value`` when it is one of ``allowed`` (any case), else None (and counted unless missing)."""
    if value is None:
        return None
    text = normal(str(value).strip())
    if text in allowed:
        return text
    rejected.append(_text(value, 50))
    return None


def _recommendations(value: Any, rejected: list[str]) -> tuple[str, ...]:
    """The catalogue ids in ``value`` (a list, or one string), in order and without repeats."""
    if value is None:
        return ()
    items = [value] if isinstance(value, str) else (value if isinstance(value, list) else [value])
    ids: list[str] = []
    for item in items:
        text = item.strip().upper() if isinstance(item, str) else ""
        if text in heuristics.CATALOGUE:
            if text not in ids:
                ids.append(text)
        else:
            rejected.append(_text(item, 60))
    return tuple(ids)


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
    path_dropped: list[list[Any]] = []
    assessed: Counter[str] = Counter({"path": 0, "path_steps": 0, "control_status": 0, "residual_risk": 0,
                                      "recommendations": 0})
    values_rejected: list[str] = []
    rules_rejected: list[str] = []
    rule_sources: Counter[str] = Counter()
    recs_rejected: list[str] = []

    for item in kept:
        if not isinstance(item, dict):
            dropped_location.append(["not an object", None, None])
            continue
        raw_file = str(item.get("file") or "")
        file = repo_path(raw_file)
        line = _line(item.get("line"))
        problem = _location_problem(file, line, line_counts, roots, excludes)
        if problem == "out of scope":
            dropped_scope.append([raw_file[:200], item.get("line")])
            continue
        if problem:
            dropped_location.append([problem, file, item.get("line")])
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
        task_rule = _choice(item.get("rule_id"), cwe_map.TASK_RULES, rules_rejected,
                            normal=str.upper) if mode == "scoped" else None
        rule_sources["model" if task_rule else "cwe_table"] += 1
        if decision == "ambiguous" and not task_rule:
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
        trace: tuple[TraceStep, ...] = ()
        control_status = residual = None
        recs: tuple[str, ...] = ()
        if mode == "scoped":
            trace = _path(item.get("path"), line_counts, roots, excludes, path_dropped)
            control_status = _choice(item.get("control_status"), CONTROL_STATUSES, values_rejected)
            residual = _choice(item.get("residual_risk"), RISK_LEVELS, values_rejected)
            recs = _recommendations(item.get("recommendation_ids"), recs_rejected)
            assessed.update({"path": bool(trace), "path_steps": len(trace), "control_status": bool(control_status),
                             "residual_risk": bool(residual), "recommendations": bool(recs)})
        findings.append(Finding(
            tool_rule_id="ccsr/" + (category or "uncategorised"),
            cwes=ordered,
            file=file,
            start_line=line,
            end_line=line,
            message=_text(item.get("description"), MESSAGE_CHARS) or category,
            level=LEVELS.get(severity, "warning"),
            residual_risk=heuristics.residual_risk(severity, None),
            trace=trace,
            extra=tuple(extra),
            control_status=control_status,
            assessed_residual_risk=residual,
            recommendations=recs,
            task_rule=task_rule,
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
        # Scoped mode: malformed CWE values (any well-formed id is accepted).
        "cwes_rejected": rejected[:200],
        "cwes_rejected_count": len(rejected),
        "results_by_cwe_decision": dict(decisions),
        "results_cwe_ambiguous": ambiguous[:200],
        "findings_by_severity": dict(sorted(severities.items())),
        # Scoped mode: how many findings carried each assessed field.
        "assessed_fields": dict(assessed),
        "path_steps_dropped": path_dropped[:200],
        "path_steps_dropped_count": len(path_dropped),
        "assessed_values_rejected": values_rejected[:200],
        "recommendations_rejected": recs_rejected[:200],
        "rule_source": dict(sorted(rule_sources.items())),
        "rule_ids_rejected": rules_rejected[:200],
    }
    return findings, counts
