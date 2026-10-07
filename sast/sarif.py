"""Findings -> SARIF 2.1.0 in the task's output profile (see the task's instruction.md).

What each field is built from:

- ``ruleId``: the CWE table (``sast.cwe_map.task_rule``). An LLM02 result is
  HIGH when a CWE or the trace's sink shows data leaving its boundary, else MEDIUM.
- ``locations[0]``: the match.
- ``codeFlows[0].threadFlows[0].locations``: only what the tool reported. With a
  Semgrep dataflow trace: the trace's taint source (role ``source``), then the
  match (role ``sink``). Without one: the match alone as ``sink``. Intermediate
  variables are not emitted: a variable on the taint path is propagation, and
  none of the task's roles (``context_assembly`` means data placed into model
  context) describes it honestly. No step is ever made up.
- ``properties.cwe``: every CWE of every rule merged into the result.
- ``properties.controlStatus``, ``residualRisk`` and ``recommendations``: fixed
  heuristics from ``sast.heuristics``, not semantic analysis.

The grader matches each ground-truth finding to the first result near it, in
results order, so results are sorted (file, line, ruleId) to make that order
deterministic.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import cwe_map, heuristics
from .findings import Finding

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL_RANK = {"note": 0, "warning": 1, "error": 2}
_RISK_RANK = {"low": 0, "medium": 1, "high": 2}


def boundary_sink(finding: Finding) -> str | None:
    """The kind of boundary-crossing call at the end of the finding's trace, if any."""
    if not finding.has_trace:
        return None
    for code in finding.trace_sink_code:
        kind = heuristics.boundary_sink_kind(code)
        if kind:
            return kind
    return None


def _region(file: str, start: int, end: int) -> dict[str, Any]:
    return {
        "artifactLocation": {"uri": file},
        "region": {"startLine": int(start), "endLine": int(max(end, start))},
    }


def _group(findings: list[Finding]) -> tuple[dict[tuple[str, int, str], dict[str, Any]], Counter[str], int]:
    """Findings merged by (file, line, ruleId family), with unmapped ones counted."""
    groups: dict[tuple[str, int, str], dict[str, Any]] = {}
    dropped_by_cwe: Counter[str] = Counter()
    mapped = 0
    for f in sorted(findings, key=lambda f: (f.file, f.start_line, f.tool_rule_id)):
        family = cwe_map.rule_for(f.cwes)
        if family is None:
            dropped_by_cwe[f.cwes[0] if f.cwes else "none"] += 1
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
                "boundary_sink": boundary_sink(f),
                "traced": f if f.trace_source is not None else None,
                "has_trace": f.has_trace,
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
        group["boundary_sink"] = group["boundary_sink"] or boundary_sink(f)
        if group["traced"] is None and f.trace_source is not None:
            group["traced"] = f
        group["has_trace"] = group["has_trace"] or f.has_trace
        group["members"].append(f)
    for group in groups.values():
        group["rule"] = cwe_map.task_rule(group["cwes"], boundary_sink=group["boundary_sink"] is not None)
    return groups, dropped_by_cwe, mapped


def emitted_rules(findings: list[Finding]) -> list[str | None]:
    """The ruleId each finding was reported under (None if not reported), in input order."""
    groups, _, _ = _group(findings)
    by_id = {id(m): g["rule"] for g in groups.values() for m in g["members"]}
    return [by_id.get(id(f)) for f in findings]


def _code_flow(file: str, start: int, end: int, group: dict[str, Any]) -> dict[str, Any]:
    steps = []
    traced: Finding | None = group["traced"]
    if traced is not None and traced.trace_source is not None:
        src = traced.trace_source
        steps.append({
            "location": {
                "physicalLocation": _region(src.file, src.start_line, src.end_line),
                "message": {"text": "Taint source reported by Semgrep" + (f": {src.content}" if src.content else "")},
            },
            "properties": {"role": "source"},
        })
    steps.append({
        "location": {
            "physicalLocation": _region(file, start, end),
            "message": {"text": "Match reported by " + ", ".join(group["tool_rule_ids"])},
        },
        "properties": {"role": "sink"},
    })
    return {"threadFlows": [{"locations": steps}]}


def build(findings: list[Finding], *, tool_name: str, tool_version: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """(sarif, stats). Findings with no mapped CWE are left out and counted."""
    groups, dropped_by_cwe, mapped = _group(findings)

    results = []
    for (file, start, _family), g in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[1]["rule"])):
        rule = g["rule"]
        end = max(g["end_line"], start)
        results.append({
            "ruleId": rule,
            "level": g["level"],
            "message": {"text": g["message"] or rule},
            "locations": [{"physicalLocation": _region(file, start, end)}],
            "codeFlows": [_code_flow(file, start, end, g)],
            "properties": {
                "cwe": g["cwes"],
                "toolRuleIds": g["tool_rule_ids"],
                "controlStatus": heuristics.CONTROL_STATUS,
                "residualRisk": g["residual_risk"],
                "recommendations": heuristics.recommendations(rule, g["cwes"]),
                "dataflowTrace": g["has_trace"],
                "boundarySink": g["boundary_sink"],
            },
        })

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
    stats = {
        "findings_mapped": mapped,
        "findings_unmapped": sum(dropped_by_cwe.values()),
        "unmapped_by_cwe": dict(sorted(dropped_by_cwe.items())),
        "results_emitted": len(results),
        "results_by_rule": dict(sorted(Counter(r["ruleId"] for r in results).items())),
        "results_with_trace_source": sum(
            1 for r in results if r["codeFlows"][0]["threadFlows"][0]["locations"][0]["properties"]["role"] == "source"
        ),
    }
    return sarif, stats
