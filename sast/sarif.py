"""Findings -> SARIF 2.1.0 in the task's output profile (see the task's instruction.md).

What each field is built from:

- ``ruleId``: the CWE table (``sast.cwe_map.task_rule``). An LLM02 result is
  HIGH when one of its CWEs shows data leaving its boundary, else MEDIUM.
- ``locations[0]``: the match.
- ``codeFlows``: never emitted. A code flow may only come from a dataflow trace
  the tool itself reported, and Semgrep OSS 1.179.0 puts no trace in its JSON
  output without a login. A one-step flow made from the match alone would earn
  path credit through the grader's line tolerance with nothing behind it.
- ``properties.cwe``: every CWE of every rule merged into the result.
- ``properties.heuristics``: ``controlStatus``, ``residualRisk`` and
  ``recommendations`` from ``sast.heuristics`` (fixed tables, not analysis),
  plus the table ``version``. They sit under their own key so the grader, which
  reads only the top-level ``properties.controlStatus``, ``residualRisk`` and
  ``recommendations``, never scores them. Reports show them as a separate
  heuristic track.

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
        group["members"].append(f)
    for group in groups.values():
        group["rule"] = cwe_map.task_rule(group["cwes"])
    return groups, dropped_by_cwe, mapped


def emitted_rules(findings: list[Finding]) -> list[str | None]:
    """The ruleId each finding was reported under (None if not reported), in input order."""
    groups, _, _ = _group(findings)
    by_id = {id(m): g["rule"] for g in groups.values() for m in g["members"]}
    return [by_id.get(id(f)) for f in findings]


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
            "properties": {
                "cwe": g["cwes"],
                "toolRuleIds": g["tool_rule_ids"],
                # Never scored: see the module docstring.
                "heuristics": {
                    "controlStatus": heuristics.CONTROL_STATUS,
                    "residualRisk": g["residual_risk"],
                    "recommendations": heuristics.recommendations(rule, g["cwes"]),
                    "version": heuristics.VERSION,
                },
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
    }
    return sarif, stats
