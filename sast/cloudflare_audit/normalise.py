"""The skill's ``findings.json`` and the side file -> ``Finding`` objects.

``findings.json`` is the skill's own output (its ``report-schema.json``): a
list of records with ``verdict`` (``confirmed``, ``needs_validation`` or
``rejected``), ``fingerprint``, ``title``, ``description``, a ``trace`` of
``{kind: entrypoint|propagation|sink, file, line, scope, description}``,
``evidence``, and for a confirmed record ``remediation`` (``strategy`` and
``code_changes``), ``severity`` and ``confidence``. It has no CWE, no ruleId
and no single "code that must change" location. ``sast-annotations.json`` (the
side file the request asks for, see request.py) adds them per fingerprint.

The rules (as strict as the other AI agents'):

- Records: ``rejected`` is never reported; ``needs_validation`` only with
  ``include_needs_validation``; anything else (no verdict, no fingerprint) is
  dropped and counted.
- Trace: every step must have a known ``kind`` and a ``file`` and ``line`` that
  are an in-scope text file the driver counted and a line of it, else it is
  dropped and counted. A trace that no longer starts at its ``entrypoint`` and
  ends at its ``sink`` after that (the skill's own shape; a one-step trace is
  either) is dropped as a whole and counted, so the SARIF writer never labels
  a middle step as the start or the end. Roles: an ``entrypoint`` is
  ``source``, a ``sink`` is ``sink``, a ``propagation`` has none; in scoped
  mode the side file's ``trace_roles`` (one per step of the original trace)
  may refine them, only to a role the contract allows for that kind
  (``request.KIND_ROLES``), else the value is counted as rejected.
- Location (``locations[0]``): in scoped mode the side file's ``location``
  when it passes the same checks (``end_line`` kept when it is a line of the
  file at or after the start, else the start line, counted); otherwise the
  trace's ``sink`` step; otherwise the record is dropped and counted.
- CWEs: the side file's ``cwe`` list when at least one entry is well formed
  (``category_map.valid_cwes``); malformed ids are counted. The skill gives no
  CWE of its own, so a record without one has none and, unless its ruleId
  comes from the side file, the SARIF writer counts it as unmapped.
- RuleId, scoped mode: the side file's ``rule_id`` when it is one of the
  task's ruleIds (``Finding.task_rule``); else the CWEs decide
  (``cwe_map.decide_unordered``), an ambiguous set is dropped and counted. A
  fingerprint with several side-file entries (one per ruleId) gives one finding
  per entry.
- ``control_status``, ``residual_risk`` and ``recommendation_ids``, scoped mode
  only: kept when they are the profile's values or catalogue ids, else counted.
- Level and residual risk from the skill's ``severity.overall_severity``:
  critical and high give ``error``/``high``, medium ``warning``/``medium``, low
  and informational ``note``/``low``. A ``needs_validation`` record has no
  severity (the skill forbids one): ``warning``/``medium``, counted.
- The skill's own text is kept verbatim under ``toolProperties`` for a later
  LLM judge, never scored: ``recommendation`` (remediation strategy),
  ``remediationCodeChanges`` (JSON), ``rootCause``, ``intendedBehavior``,
  ``exploitScenario`` and ``observedResult`` (from ``execution``),
  ``blockers`` and ``validationPlan`` (JSON) of a needs_validation record, and
  the verdict, fingerprint, title, confidence, severity, the trace kinds and
  where the location and CWEs came from.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from .. import cwe_map, heuristics
from ..claude_review import category_map
from ..claude_review.normalise import _choice, _line, _location_problem, _recommendations, _text
from ..findings import CONTROL_STATUSES, PATH_ROLES, RISK_LEVELS, Finding, TraceStep
from ..scope import repo_path
from .request import KIND_ROLES

VERSION = "cloudflare-normalise-1"
#: overall_severity -> (SARIF level, severity word for ``heuristics.residual_risk``).
SEVERITIES = {"critical": ("error", "HIGH"), "high": ("error", "HIGH"), "medium": ("warning", "MEDIUM"),
              "low": ("note", "LOW"), "informational": ("note", "LOW")}
DEFAULT_ROLE = {"entrypoint": "source", "propagation": None, "sink": "sink"}
MESSAGE_CHARS = 1000
MAX_TRACE_STEPS = 20
VERDICTS = ("confirmed", "needs_validation", "rejected")


def _verbatim(value: Any) -> str | None:
    """A text kept as the skill wrote it (strings as they are, anything else as JSON)."""
    if value is None or value == "" or value == [] or value == {}:
        return None
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)


def _annotation_index(annotations: Any, counts: Counter) -> dict[str, list[dict[str, Any]]]:
    entries = annotations.get("findings") if isinstance(annotations, dict) else None
    if annotations is None:
        counts["annotations_missing"] = 1
        return {}
    if not isinstance(entries, list):
        counts["annotations_unusable"] = 1
        return {}
    index: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        fingerprint = entry.get("fingerprint") if isinstance(entry, dict) else None
        if not isinstance(fingerprint, str) or not fingerprint:
            counts["annotation_entries_bad"] += 1
            continue
        index.setdefault(fingerprint, []).append(entry)
    return index


def _trace(raw: Any, roles: Any, scoped: bool, line_counts: dict[str, int], roots: list[str], excludes: list[str],
           dropped: list[list[Any]], roles_rejected: list[str]) -> tuple[tuple[TraceStep, ...], list[str], str | None]:
    """(steps, their kinds, why the whole trace was dropped or None)."""
    if not isinstance(raw, list) or not raw:
        return (), [], "no trace"
    role_list = roles if scoped and isinstance(roles, list) else []
    steps: list[TraceStep] = []
    kinds: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or item.get("kind") not in KIND_ROLES:
            dropped.append(["step is not an entrypoint, propagation or sink", _text(item, 100), None])
            continue
        file = repo_path(str(item.get("file") or ""))
        line = _line(item.get("line"))
        problem = _location_problem(file, line, line_counts, roots, excludes)
        if problem:
            dropped.append([problem, str(item.get("file") or "")[:200], item.get("line")])
            continue
        if len(steps) == MAX_TRACE_STEPS:
            dropped.append(["more than {} steps".format(MAX_TRACE_STEPS), file, line])
            continue
        kind = item["kind"]
        role = DEFAULT_ROLE[kind]
        given = role_list[index] if index < len(role_list) else None
        if given is not None:
            text = str(given).strip().lower()
            if text in KIND_ROLES[kind] and text in PATH_ROLES:
                role = text
            else:
                roles_rejected.append("{}:{}".format(kind, _text(given, 40)))
        steps.append(TraceStep(file=file, start_line=line, end_line=line, role=role))
        kinds.append(kind)
    if not steps:
        return (), [], "no valid step"
    if len(raw) == 1:
        if kinds[0] not in ("entrypoint", "sink"):
            return (), [], "a one-step trace that is not an entrypoint or a sink"
        return tuple(steps), kinds, None
    if len(steps) < 2 or kinds[0] != "entrypoint" or kinds[-1] != "sink" or any(k != "propagation" for k in kinds[1:-1]):
        return (), [], "no longer runs from its entrypoint to its sink"
    return tuple(steps), kinds, None


def normalise(
    records: list[Any],
    annotations: Any,
    *,
    mode: str,
    include_needs_validation: bool,
    line_counts: dict[str, int],
    roots: list[str],
    excludes: list[str],
) -> tuple[list[Finding], dict[str, Any]]:
    """(findings, counts for the run metadata)."""
    scoped = mode == "scoped"
    counts: Counter = Counter({"annotation_entries_bad": 0})
    index = _annotation_index(annotations, counts)
    findings: list[Finding] = []
    verdicts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    dropped_location: list[list[Any]] = []
    dropped_scope: list[list[Any]] = []
    dropped_records: list[list[Any]] = []
    ambiguous: list[list[Any]] = []
    path_dropped: list[list[Any]] = []
    traces_dropped: list[list[Any]] = []
    roles_rejected: list[str] = []
    cwes_rejected: list[str] = []
    values_rejected: list[str] = []
    rules_rejected: list[str] = []
    recs_rejected: list[str] = []
    rule_sources: Counter[str] = Counter()
    cwe_sources: Counter[str] = Counter()
    location_sources: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    decisions: Counter[str] = Counter({"none": 0, "unmapped": 0, "mapped": 0, "ambiguous": 0})
    assessed: Counter[str] = Counter({"path": 0, "path_steps": 0, "control_status": 0, "residual_risk": 0,
                                      "recommendations": 0})
    end_replaced = 0
    without_annotation: list[str] = []
    used_fingerprints: set[str] = set()

    for record in records:
        if not isinstance(record, dict):
            dropped_records.append(["not an object", None])
            continue
        verdict = record.get("verdict")
        fingerprint = record.get("fingerprint")
        if verdict not in VERDICTS or not isinstance(fingerprint, str) or not fingerprint:
            dropped_records.append(["no known verdict or no fingerprint", _text(fingerprint, 100) or None])
            continue
        verdicts[verdict] += 1
        if verdict == "rejected":
            skipped["rejected"] += 1
            continue
        if verdict == "needs_validation" and not include_needs_validation:
            skipped["needs_validation"] += 1
            continue
        entries = index.get(fingerprint) or []
        if fingerprint in index:
            used_fingerprints.add(fingerprint)
        else:
            without_annotation.append(fingerprint[:120])
        if not scoped:
            entries = entries[:1]
        for entry in entries or [{}]:
            trace, kinds, why = _trace(record.get("trace"), entry.get("trace_roles"), scoped, line_counts, roots,
                                       excludes, path_dropped, roles_rejected)
            if why and why != "no trace":
                traces_dropped.append([fingerprint[:120], why])

            # The location: the side file's (scoped), else the trace's sink.
            file = line = end = None
            source = None
            location = entry.get("location") if scoped and isinstance(entry.get("location"), dict) else None
            if location is not None:
                raw_file = str(location.get("file") or "")
                candidate = repo_path(raw_file)
                start = _line(location.get("start_line"))
                problem = _location_problem(candidate, start, line_counts, roots, excludes)
                if problem:
                    (dropped_scope if problem == "out of scope" else dropped_location).append(
                        [problem, raw_file[:200], location.get("start_line")])
                else:
                    file, line, source = candidate, start, "annotation"
                    end = _line(location.get("end_line"))
                    if end is None or end < line or end > line_counts[file]:
                        end_replaced += 1
                        end = line
            if file is None and trace and kinds[-1] == "sink":
                file, line, end, source = trace[-1].file, trace[-1].start_line, trace[-1].end_line, "trace_sink"
            if file is None:
                dropped_location.append(["no usable location (no valid annotation location and no valid sink step)",
                                         fingerprint[:120], None])
                continue
            location_sources[source] += 1

            model_cwes, bad = category_map.valid_cwes(entry.get("cwe"))
            cwes_rejected += bad
            cwe_sources["annotation" if model_cwes else "none"] += 1
            decision, _family, ordered = cwe_map.decide_unordered(model_cwes)
            decisions[decision] += 1
            task_rule = _choice(entry.get("rule_id"), cwe_map.TASK_RULES, rules_rejected,
                                normal=str.upper) if scoped else None
            rule_sources["annotation" if task_rule else "cwe_table"] += 1
            if decision == "ambiguous" and not task_rule:
                ambiguous.append([fingerprint[:120], list(ordered), file, line])
                continue

            severity = record.get("severity") if isinstance(record.get("severity"), dict) else {}
            overall = str(severity.get("overall_severity") or "").lower()
            severities[overall if overall in SEVERITIES else "missing_or_other"] += 1
            level, word = SEVERITIES.get(overall, ("warning", "MEDIUM"))

            control_status = residual = None
            recs: tuple[str, ...] = ()
            if scoped:
                control_status = _choice(entry.get("control_status"), CONTROL_STATUSES, values_rejected)
                residual = _choice(entry.get("residual_risk"), RISK_LEVELS, values_rejected)
                recs = _recommendations(entry.get("recommendation_ids"), recs_rejected)
                assessed.update({"path": bool(trace), "path_steps": len(trace), "control_status": bool(control_status),
                                 "residual_risk": bool(residual), "recommendations": bool(recs)})

            remediation = record.get("remediation") if isinstance(record.get("remediation"), dict) else {}
            execution = record.get("execution") if isinstance(record.get("execution"), dict) else {}
            confidence = record.get("confidence") if isinstance(record.get("confidence"), dict) else {}
            extra = [
                ("verdict", verdict),
                ("fingerprint", fingerprint),
                ("title", _verbatim(record.get("title"))),
                ("severity", overall or None),
                ("confidence", _verbatim(confidence.get("score"))),
                ("cweSource", "annotation" if model_cwes else "none"),
                ("locationSource", source),
                ("traceKinds", ",".join(kinds) if kinds else None),
                ("recommendation", _verbatim(remediation.get("strategy"))),
                ("remediationCodeChanges", _verbatim(remediation.get("code_changes"))),
                ("rootCause", _verbatim(record.get("root_cause") or record.get("claimed_root_cause"))),
                ("intendedBehavior", _verbatim(record.get("intended_behavior"))),
                ("exploitScenario", _verbatim(execution.get("attacker_perspective"))),
                ("observedResult", _verbatim(execution.get("observed_result"))),
                ("blockers", _verbatim(record.get("blockers"))),
                ("validationPlan", _verbatim(record.get("validation_plan"))),
            ]
            title = _text(record.get("title"), 200)
            description = _text(record.get("description"), MESSAGE_CHARS)
            message = (f"{title}: {description}" if title and description else title or description)[:MESSAGE_CHARS]
            findings.append(Finding(
                tool_rule_id="cloudflare-audit/" + verdict,
                cwes=ordered,
                file=file,
                start_line=line,
                end_line=end,
                message=message or fingerprint,
                level=level,
                residual_risk=heuristics.residual_risk(word, None),
                trace=trace,
                extra=tuple((k, v) for k, v in extra if v is not None),
                control_status=control_status,
                assessed_residual_risk=residual,
                recommendations=recs,
                task_rule=task_rule,
            ))

    orphans = sorted(set(index) - used_fingerprints)
    counts_out = {
        "cloudflare_normalise": VERSION,
        "records_reported": len(records),
        "records_by_verdict": dict(sorted(verdicts.items())),
        "records_skipped": dict(sorted(skipped.items())),
        "dropped_records": dropped_records[:200],
        "dropped_records_count": len(dropped_records),
        "dropped_bad_location": dropped_location[:200],
        "dropped_bad_location_count": len(dropped_location),
        "dropped_out_of_scope": dropped_scope[:200],
        "dropped_out_of_scope_count": len(dropped_scope),
        "end_line_replaced": end_replaced,
        "location_source": dict(sorted(location_sources.items())),
        "cwe_source": dict(sorted(cwe_sources.items())),
        "cwes_rejected": cwes_rejected[:200],
        "cwes_rejected_count": len(cwes_rejected),
        "results_by_cwe_decision": dict(decisions),
        "results_cwe_ambiguous": ambiguous[:200],
        "findings_by_severity": dict(sorted(severities.items())),
        "assessed_fields": dict(assessed),
        "path_steps_dropped": path_dropped[:200],
        "path_steps_dropped_count": len(path_dropped),
        "traces_dropped": traces_dropped[:200],
        "traces_dropped_count": len(traces_dropped),
        "trace_roles_rejected": roles_rejected[:200],
        "assessed_values_rejected": values_rejected[:200],
        "recommendations_rejected": recs_rejected[:200],
        "rule_source": dict(sorted(rule_sources.items())),
        "rule_ids_rejected": rules_rejected[:200],
        "records_without_annotation": without_annotation[:200],
        "records_without_annotation_count": len(without_annotation),
        "annotations_orphaned": orphans[:200],
        "annotations_orphaned_count": len(orphans),
        "annotations_missing": bool(counts.get("annotations_missing")),
        "annotations_unusable": bool(counts.get("annotations_unusable")),
        "annotation_entries_bad": counts["annotation_entries_bad"],
    }
    return findings, counts_out
