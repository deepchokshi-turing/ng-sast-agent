"""The Codex review's findings -> ``Finding`` objects.

Each finding has Codex's own review shape (``title``, ``body``,
``confidence_score``, ``priority``, ``code_location`` with
``absolute_file_path`` and ``line_range``) plus ``category`` and ``cwe``, and in
scoped mode ``rule_id``, ``path``, ``control_status``, ``residual_risk`` and
``recommendation_ids`` (request.py). The rules are the Claude review's
(``sast.claude_review.normalise``, whose helpers are reused):

- Location: ``absolute_file_path`` (made relative to the scope copy by the
  driver) relative to /app/repo must be an in-scope text file the driver
  counted, and ``line_range.start`` a line of it. ``line_range.end`` is used
  when it is a line of the file at or after the start, else the start line
  (counted as ``end_line_replaced``). Anything else is dropped and counted.
- CWEs, both modes: the model's ``cwe`` list when at least one entry is well
  formed (``category_map.valid_cwes``), else the Claude review's category table
  for the ``category`` (``table_fallback``). Malformed ids are counted. The set
  is decided by ``cwe_map.decide_unordered``.
- RuleId, scoped mode: the model's ``rule_id`` when it is one of the task's
  ruleIds, kept as ``Finding.task_rule``. Otherwise, and in stock mode, the
  CWEs decide; an ambiguous set without a valid ``rule_id`` is dropped and
  counted.
- Level and residual risk from Codex's ``priority``: 0 and 1 give
  ``error``/``high``, 2 ``warning``/``medium``, 3 ``note``/``low``. A missing or
  other value gives ``warning``/``medium`` and is counted.
- Scoped mode only: ``path`` steps that pass the location checks become the
  trace (``role`` kept when it is a contract role), ``control_status``,
  ``residual_risk`` and ``recommendation_ids`` are kept when they are the
  profile's values. Stock mode asks for none of these and uses none.
- Title, category, priority, confidence, the CWE source and a short copy of the
  body go to ``Finding.extra`` (SARIF ``toolProperties``, never scored).
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .. import cwe_map, heuristics
from ..claude_review import category_map
from ..claude_review.normalise import _choice, _line, _location_problem, _path, _recommendations, _text
from ..findings import CONTROL_STATUSES, RISK_LEVELS, Finding, TraceStep
from ..scope import repo_path

#: Codex's review priority -> (SARIF level, severity word for ``heuristics.residual_risk``).
PRIORITIES = {0: ("error", "HIGH"), 1: ("error", "HIGH"), 2: ("warning", "MEDIUM"), 3: ("note", "LOW")}
MESSAGE_CHARS = 1000
EXTRA_CHARS = 500
VERSION = "codex-normalise-1"


def _priority(value: Any) -> int | None:
    line = _line(value)
    return line if line in PRIORITIES else None


def normalise(
    findings_in: list[dict[str, Any]],
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
    priorities: Counter[str] = Counter()
    end_replaced = 0
    path_dropped: list[list[Any]] = []
    assessed: Counter[str] = Counter({"path": 0, "path_steps": 0, "control_status": 0, "residual_risk": 0,
                                      "recommendations": 0})
    values_rejected: list[str] = []
    rules_rejected: list[str] = []
    rule_sources: Counter[str] = Counter()
    recs_rejected: list[str] = []

    for item in findings_in:
        if not isinstance(item, dict):
            dropped_location.append(["not an object", None, None])
            continue
        location = item.get("code_location") if isinstance(item.get("code_location"), dict) else {}
        span = location.get("line_range") if isinstance(location.get("line_range"), dict) else {}
        raw_file = str(location.get("absolute_file_path") or "")
        file = repo_path(raw_file)
        line = _line(span.get("start"))
        problem = _location_problem(file, line, line_counts, roots, excludes)
        if problem == "out of scope":
            dropped_scope.append([raw_file[:200], span.get("start")])
            continue
        if problem:
            dropped_location.append([problem, file or raw_file[:200], span.get("start")])
            continue
        end = _line(span.get("end"))
        if end is None or end < line or end > line_counts[file]:
            end_replaced += 1
            end = line

        category = category_map.normalise(item.get("category"))
        model_cwes, bad = category_map.valid_cwes(item.get("cwe"))
        rejected += bad
        if model_cwes:
            cwes, source = model_cwes, "model"
        else:
            table = category_map.lookup(category)
            cwes = (table,) if table else ()
            source = "table_fallback" if table else "none"
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

        priority = _priority(item.get("priority"))
        priorities[f"P{priority}" if priority is not None else "missing_or_other"] += 1
        level, severity = PRIORITIES.get(priority, ("warning", "MEDIUM"))
        extra = [
            ("title", _text(item.get("title"), 200)),
            ("category", _text(item.get("category"), 100)),
            ("priority", str(priority) if priority is not None else "missing"),
            ("confidence", _text(item.get("confidence_score"), 20)),
            ("cweSource", source),
        ]
        if item.get("body"):
            extra.append(("body", _text(item.get("body"), EXTRA_CHARS)))
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
        message = _text(item.get("body"), MESSAGE_CHARS) or _text(item.get("title"), MESSAGE_CHARS) or category
        findings.append(Finding(
            tool_rule_id="codex/" + (category or "uncategorised"),
            cwes=ordered,
            file=file,
            start_line=line,
            end_line=end,
            message=message,
            level=level,
            residual_risk=heuristics.residual_risk(severity, None),
            trace=trace,
            extra=tuple(extra),
            control_status=control_status,
            assessed_residual_risk=residual,
            recommendations=recs,
            task_rule=task_rule,
        ))

    counts = {
        "codex_normalise": VERSION,
        "category_map": category_map.VERSION,
        "findings_reported": len(findings_in),
        "dropped_bad_location": dropped_location[:200],
        "dropped_bad_location_count": len(dropped_location),
        "dropped_out_of_scope": dropped_scope[:200],
        "dropped_out_of_scope_count": len(dropped_scope),
        "end_line_replaced": end_replaced,
        "unmapped_by_category": dict(sorted(unmapped_category.items())),
        "cwe_source": dict(sorted(sources.items())),
        "cwes_rejected": rejected[:200],
        "cwes_rejected_count": len(rejected),
        "results_by_cwe_decision": dict(decisions),
        "results_cwe_ambiguous": ambiguous[:200],
        "findings_by_priority": dict(sorted(priorities.items())),
        "assessed_fields": dict(assessed),
        "path_steps_dropped": path_dropped[:200],
        "path_steps_dropped_count": len(path_dropped),
        "assessed_values_rejected": values_rejected[:200],
        "recommendations_rejected": recs_rejected[:200],
        "rule_source": dict(sorted(rule_sources.items())),
        "rule_ids_rejected": rules_rejected[:200],
    }
    return findings, counts
