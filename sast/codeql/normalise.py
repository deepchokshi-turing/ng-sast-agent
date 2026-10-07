"""CodeQL SARIF -> findings.

Only results of queries tagged ``security`` are kept (the ``security-extended``
suites hold security queries only, so this is a guard, not a filter that changes
anything today). The CWE ids come from the query's own tags
(``external/cwe/cwe-094`` -> ``CWE-94``), in the query's order, so the first is
its primary CWE, as with Semgrep's rule metadata.

A path query reports how the data flows (``codeFlows``); the first one is kept as
the finding's ``flow``. Nothing is added to it.
"""

from __future__ import annotations

import re
from typing import Any

from .. import heuristics
from ..findings import Finding
from ..scope import repo_path

_CWE_TAG = re.compile(r"^external/cwe/cwe-0*(\d+)$", re.IGNORECASE)
_LEVELS = {"error": "error", "warning": "warning", "note": "note", "recommendation": "note", "none": "note"}
#: Steps of a reported path kept per finding.
MAX_FLOW_STEPS = 50


def _rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Every rule the run describes, by id: the driver's and each query pack's."""
    tool = run.get("tool") or {}
    components = [tool.get("driver") or {}, *(tool.get("extensions") or [])]
    found: dict[str, dict[str, Any]] = {}
    for component in components:
        for rule in component.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                found.setdefault(rule["id"], rule)
    return found


def cwes_of(rule: dict[str, Any]) -> tuple[str, ...]:
    """Exact "CWE-<n>" ids from the query's tags, in the query's order."""
    seen: list[str] = []
    for tag in (rule.get("properties") or {}).get("tags") or []:
        match = _CWE_TAG.match(str(tag))
        if match and f"CWE-{int(match.group(1))}" not in seen:
            seen.append(f"CWE-{int(match.group(1))}")
    return tuple(seen)


def _severity(rule: dict[str, Any]) -> str:
    """The query's security-severity score as a Semgrep-style word, for the residual-risk heuristic."""
    props = rule.get("properties") or {}
    try:
        score = float(props.get("security-severity"))
    except (TypeError, ValueError):
        return str(props.get("problem.severity") or "")
    return "ERROR" if score >= 7.0 else "WARNING" if score >= 4.0 else "INFO"


def _location(physical: dict[str, Any]) -> tuple[str, int, int] | None:
    uri = ((physical or {}).get("artifactLocation") or {}).get("uri")
    region = (physical or {}).get("region") or {}
    start = region.get("startLine")
    if not uri or not isinstance(start, int) or start < 1:
        return None
    end = region.get("endLine")
    return repo_path(str(uri).replace("file://", "")), start, end if isinstance(end, int) and end >= start else start


def _flow(result: dict[str, Any]) -> tuple[tuple[str, int, int, str], ...]:
    for code_flow in result.get("codeFlows") or []:
        for thread in code_flow.get("threadFlows") or []:
            steps = []
            for step in (thread.get("locations") or [])[:MAX_FLOW_STEPS]:
                location = step.get("location") or {}
                where = _location(location.get("physicalLocation") or {})
                if where:
                    message = " ".join(str((location.get("message") or {}).get("text") or "").split())[:200]
                    steps.append((*where, message))
            if steps:
                return tuple(steps)
    return ()


def normalise(document: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    """(security findings, counts) from one CodeQL SARIF document."""
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("CodeQL SARIF has no runs")

    findings: list[Finding] = []
    raw = non_security = no_location = with_flow = rule_count = 0
    notifications = 0
    for run in runs:
        rules = _rules(run)
        rule_count += len(rules)
        for invocation in run.get("invocations") or []:
            notifications += sum(
                1 for n in invocation.get("toolExecutionNotifications") or []
                if str(n.get("level", "")).lower() == "error"
            )
        results = run.get("results")
        if not isinstance(results, list):
            raise ValueError("CodeQL SARIF run has no results list")
        for result in results:
            raw += 1
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or ""
            rule = rules.get(rule_id, {})
            tags = (rule.get("properties") or {}).get("tags") or []
            if "security" not in tags:
                non_security += 1
                continue
            where = _location(((result.get("locations") or [{}])[0] or {}).get("physicalLocation") or {})
            if where is None:
                no_location += 1
                continue
            flow = _flow(result)
            with_flow += bool(flow)
            level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            findings.append(Finding(
                tool_rule_id=str(rule_id),
                cwes=cwes_of(rule),
                file=where[0],
                start_line=where[1],
                end_line=where[2],
                message=" ".join(str((result.get("message") or {}).get("text") or "").split())[:1000],
                level=_LEVELS.get(str(level).lower(), "warning"),
                residual_risk=heuristics.residual_risk(_severity(rule), None),
                flow=flow,
            ))
    counts = {
        "results_raw": raw,
        "results_non_security": non_security,
        "results_without_location": no_location,
        "findings_with_tool_flow": with_flow,
        "rules_in_run": rule_count,
        "codeql_error_notifications": notifications,
    }
    return findings, counts
