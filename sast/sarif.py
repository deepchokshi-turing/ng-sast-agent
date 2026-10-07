"""Findings -> SARIF 2.1.0 in the task's output profile (see the task's instruction.md).

What a scanner can fill in: ``ruleId`` (from the CWE table), ``locations[0]``,
``properties.cwe`` and a message. What it cannot, and so never writes:
``codeFlows`` (the free engines give no machine-readable trace, and a made-up
one-step flow would earn path credit the tool did not earn), ``controlStatus``,
``residualRisk`` and ``recommendations``.

The grader matches each ground-truth finding to the first result near it, in
results order, so results are sorted (file, line, ruleId) to make that order
deterministic.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import cwe_map
from .findings import Finding

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL_RANK = {"note": 0, "warning": 1, "error": 2}


def build(findings: list[Finding], *, tool_name: str, tool_version: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """(sarif, stats). Findings with no mapped CWE are left out and counted."""
    groups: dict[tuple[str, int, str], dict[str, Any]] = {}
    dropped_by_cwe: Counter[str] = Counter()
    mapped = 0

    for f in sorted(findings, key=lambda f: (f.file, f.start_line, f.tool_rule_id)):
        rule = cwe_map.rule_for(f.cwes)
        if rule is None:
            dropped_by_cwe[f.cwes[0] if f.cwes else "none"] += 1
            continue
        mapped += 1
        key = (f.file, f.start_line, rule)
        group = groups.get(key)
        if group is None:
            groups[key] = {
                "end_line": f.end_line,
                "level": f.level,
                "message": f.message,
                "cwes": list(f.cwes),
                "tool_rule_ids": [f.tool_rule_id],
            }
            continue
        # Same weakness class on the same line from several rules: one result,
        # since the grader would count every extra copy as a false positive.
        group["end_line"] = max(group["end_line"], f.end_line)
        if _LEVEL_RANK.get(f.level, 0) > _LEVEL_RANK.get(group["level"], 0):
            group["level"] = f.level
        group["cwes"] += [c for c in f.cwes if c not in group["cwes"]]
        if f.tool_rule_id not in group["tool_rule_ids"]:
            group["tool_rule_ids"].append(f.tool_rule_id)

    results = []
    for (file, start, rule), g in sorted(groups.items()):
        results.append({
            "ruleId": rule,
            "level": g["level"],
            "message": {"text": g["message"] or rule},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {"startLine": int(start), "endLine": int(max(g["end_line"], start))},
                }
            }],
            "properties": {"cwe": g["cwes"], "toolRuleIds": g["tool_rule_ids"]},
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
                    "properties": {"cweMap": cwe_map.VERSION},
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
