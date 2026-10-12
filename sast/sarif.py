"""Findings -> SARIF 2.1.0 in the task's output profile (see the task's instruction.md).

What each field is built from:

- ``ruleId``: the CWE table (``sast.cwe_map.task_rule``). An LLM02 result is
  HIGH when one of its CWEs shows data leaving its boundary, else MEDIUM. A
  tool that names the task ruleId itself (``Finding.task_rule``, Claude review
  in scoped mode) keeps it, and its CWEs are written but do not decide it.
  Findings merged into one result keep the family of the group they were
  merged by: the combined CWE list only chooses LLM02 HIGH or MEDIUM
  (``cwe_map.family_rule``), so a merge can never lose the family.
- ``locations[0]``: the match.
- ``codeFlows``: written only from a dataflow trace the tool itself reported
  (``Finding.trace``), taken from the first finding of the merged group that
  has one, as ``codeFlows[0].threadFlows[0].locations``. The first step
  (threadFlowLocation) gets ``properties.role = "source"``, the last gets
  ``"sink"`` and the steps in between get no role, because no tool says which
  of them is a root cause or a context step. A one-step trace is a sink only.
  When the tool names the role of every step itself (Claude review in scoped
  mode), those roles are written instead.
  With no trace there is no ``codeFlows``: a flow made up from the match alone
  would earn path credit through the grader's line tolerance with nothing
  behind it. Semgrep OSS 1.179.0 gives no trace in JSON without a login, so
  Semgrep results never carry one. CodeQL path queries do.
- ``properties.cwe``: every CWE of every rule merged into the result.
- ``properties.toolProperties``: tool labels from ``Finding.extra`` (for example
  SonarQube's sonarType). Not read by the grader.
- ``properties.heuristics``: ``controlStatus``, ``residualRisk`` and
  ``recommendations`` from ``sast.heuristics`` (fixed tables, not analysis),
  plus the table ``version``. They sit under their own key so the grader, which
  reads only the top-level ``properties.controlStatus``, ``residualRisk`` and
  ``recommendations``, never scores them. Reports show them as a separate
  heuristic track.
- ``properties.controlStatus``, ``residualRisk`` and ``recommendations`` (top
  level, scored): only when the tool assessed them itself
  (``Finding.control_status``, ``assessed_residual_risk`` and
  ``recommendations``), taken from the first finding of the merged group that
  has each. Pattern and taint scanners never set them.

- ``runs[0].properties`` (never scored): what the agent dropped or re-mapped
  on the way from the tool's output to these results (counts and short lists),
  so a report can show it next to the scores. See
  ``ScannerAgent.sarif_run_properties``.

The grader (v3) matches results to ground-truth findings one to one by an
optimal assignment that maximises the task reward (``task_format/grade.py``,
``assign``), so the order of the results does not change which finding a
result is credited to. Results are still sorted (file, line, ruleId) so the
same scan always gives a byte-identical SARIF.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import cwe_map, heuristics
from .findings import Finding, TraceStep

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL_RANK = {"note": 0, "warning": 1, "error": 2}
_RISK_RANK = {"low": 0, "medium": 1, "high": 2}


def _region(file: str, start: int, end: int) -> dict[str, Any]:
    return {
        "artifactLocation": {"uri": file},
        "region": {"startLine": int(start), "endLine": int(max(end, start))},
    }


def _code_flows(trace: tuple[TraceStep, ...]) -> list[dict[str, Any]]:
    """SARIF codeFlows from a tool-reported trace (see the module docstring)."""
    locations = []
    last = len(trace) - 1
    own_roles = all(step.role for step in trace)
    for i, step in enumerate(trace):
        location: dict[str, Any] = {"location": {"physicalLocation": _region(step.file, step.start_line, step.end_line)}}
        if own_roles:
            role = step.role
        else:
            role = "sink" if i == last else ("source" if i == 0 else None)
        if role:
            location["properties"] = {"role": role}
        locations.append(location)
    return [{"threadFlows": [{"locations": locations}]}]


def _family(f: Finding) -> str | None:
    """The family a finding is grouped under: its own task ruleId's, else its primary CWE's."""
    if f.task_rule:
        return cwe_map.SID_HIGH if f.task_rule.startswith("LLM02.") else f.task_rule
    return cwe_map.rule_for(f.cwes)


def _group(findings: list[Finding]) -> tuple[dict[tuple[str, int, str], dict[str, Any]], list[Finding], int]:
    """Findings merged by (file, line, ruleId family), and the unmapped ones left out."""
    groups: dict[tuple[str, int, str], dict[str, Any]] = {}
    unmapped: list[Finding] = []
    mapped = 0
    for f in sorted(findings, key=lambda f: (f.file, f.start_line, f.tool_rule_id)):
        family = _family(f)
        if family is None:
            unmapped.append(f)
            continue
        mapped += 1
        key = (f.file, f.start_line, family)
        group = groups.get(key)
        if group is None:
            groups[key] = {
                "end_line": f.end_line,
                "level": f.level,
                "message": f.message,
                "cwes": list(f.cwes),
                "tool_rule_ids": [f.tool_rule_id],
                "residual_risk": f.residual_risk,
                "trace": f.trace,
                "task_rule": f.task_rule,
                "control_status": f.control_status,
                "assessed_residual_risk": f.assessed_residual_risk,
                "recommendations": f.recommendations,
                "extra": {k: [v] for k, v in f.extra},
                "members": [f],
            }
            continue
        # Same weakness class on the same line from several rules: one result,
        # since the grader would count every extra copy as a false positive.
        group["end_line"] = max(group["end_line"], f.end_line)
        if _LEVEL_RANK.get(f.level, 0) > _LEVEL_RANK.get(group["level"], 0):
            group["level"] = f.level
        if _RISK_RANK.get(f.residual_risk, 1) > _RISK_RANK.get(group["residual_risk"], 1):
            group["residual_risk"] = f.residual_risk
        group["cwes"] += [c for c in f.cwes if c not in group["cwes"]]
        if f.tool_rule_id not in group["tool_rule_ids"]:
            group["tool_rule_ids"].append(f.tool_rule_id)
        if not group["trace"] and f.trace:
            group["trace"] = f.trace
        for key in ("task_rule", "control_status", "assessed_residual_risk", "recommendations"):
            if not group[key] and getattr(f, key):
                group[key] = getattr(f, key)
        for k, v in f.extra:
            values = group["extra"].setdefault(k, [])
            if v not in values:
                values.append(v)
        group["members"].append(f)
    for (_file, _line, family), group in groups.items():
        # From the group's family, never from the combined CWEs alone: a generic
        # CWE next to a NOT_DISCLOSURE one gives no family (cwe-map-5).
        group["rule"] = group["task_rule"] or cwe_map.family_rule(family, group["cwes"])
    return groups, unmapped, mapped


def emitted_rules(findings: list[Finding]) -> list[str | None]:
    """The ruleId each finding was reported under (None if not reported), in input order."""
    groups, _, _ = _group(findings)
    by_id = {id(m): g["rule"] for g in groups.values() for m in g["members"]}
    return [by_id.get(id(f)) for f in findings]


def unmapped_findings(findings: list[Finding]) -> list[Finding]:
    """The findings ``build`` leaves out because no CWE maps them to a task ruleId."""
    return _group(findings)[1]


def unmapped_rows(unmapped: list[Finding]) -> list[list[Any]]:
    """[tool rule id, CWEs, file, line] of each finding left out for want of a mapped CWE."""
    return [[f.tool_rule_id, list(f.cwes), f.file, f.start_line] for f in unmapped]


def build(
    findings: list[Finding],
    *,
    tool_name: str,
    tool_version: str,
    run_properties: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(sarif, stats). Findings with no mapped CWE are left out and counted.

    ``run_properties`` go to ``runs[0].properties`` as they are: the agent's
    account of what it dropped or re-mapped (``ScannerAgent.sarif_run_properties``).
    The grader never reads them, and they change nothing about the results.
    """
    groups, unmapped, mapped = _group(findings)
    dropped_by_cwe: Counter[str] = Counter(f.cwes[0] if f.cwes else "none" for f in unmapped)

    results = []
    for (file, start, _family), g in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[1]["rule"])):
        rule = g["rule"]
        end = max(g["end_line"], start)
        result: dict[str, Any] = {
            "ruleId": rule,
            "level": g["level"],
            "message": {"text": g["message"] or rule},
            "locations": [{"physicalLocation": _region(file, start, end)}],
        }
        if g["trace"]:
            result["codeFlows"] = _code_flows(g["trace"])
        result.update({
            "properties": {
                "cwe": g["cwes"],
                "toolRuleIds": g["tool_rule_ids"],
                **({"toolProperties": {k: v[0] if len(v) == 1 else v for k, v in g["extra"].items()}}
                   if g["extra"] else {}),
                # Scored: the tool's own assessment, never a heuristic.
                **({"controlStatus": g["control_status"]} if g["control_status"] else {}),
                **({"residualRisk": g["assessed_residual_risk"]} if g["assessed_residual_risk"] else {}),
                **({"recommendations": list(g["recommendations"])} if g["recommendations"] else {}),
                # Never scored: see the module docstring.
                "heuristics": {
                    "controlStatus": heuristics.CONTROL_STATUS,
                    "residualRisk": g["residual_risk"],
                    "recommendations": heuristics.recommendations(rule, g["cwes"]),
                    "version": heuristics.VERSION,
                },
            },
        })
        results.append(result)

    used = sorted({r["ruleId"] for r in results})
    sarif = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "rules": [
                        {"id": rule, "shortDescription": {"text": cwe_map.RULE_DESCRIPTIONS[rule]}}
                        for rule in used
                    ],
                    "properties": {"cweMap": cwe_map.VERSION, "heuristics": heuristics.VERSION},
                }
            },
            "results": results,
        }],
    }
    if run_properties:
        sarif["runs"][0]["properties"] = run_properties
    stats = {
        "findings_mapped": mapped,
        "findings_unmapped": sum(dropped_by_cwe.values()),
        "unmapped_by_cwe": dict(sorted(dropped_by_cwe.items())),
        "unmapped_findings": unmapped_rows(unmapped)[:200],
        "results_emitted": len(results),
        "results_by_rule": dict(sorted(Counter(r["ruleId"] for r in results).items())),
    }
    return sarif, stats
