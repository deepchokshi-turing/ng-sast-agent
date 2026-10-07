"""CodeQL SARIF (``--format=sarif-latest``) -> findings.

- CWEs: the rule's ``external/cwe/cwe-NNN`` tags, in the rule's order, written
  as ``CWE-<n>``. The rule is looked up in the driver and in the query packs
  (``tool.extensions``), where CodeQL lists the rules it ran.
- Location: ``locations[0]``, made relative to /app/repo. CodeQL writes URIs
  relative to ``%SRCROOT%`` and gives that base in ``originalUriBaseIds``, so a
  result is placed by resolving the base first.
- Trace: the first thread flow of the first code flow, step by step, only when
  CodeQL reported one (path queries). Steps outside /app/repo are left out and
  counted.
- ``residual_risk`` (heuristic only, never scored): from the rule's
  ``security-severity``: 7.0 and above is high, 4.0 to 6.9 medium, lower low,
  missing medium.

Every result is kept: the ``security-extended`` suite runs security queries
only, and ``sast.sarif`` counts and drops the ones whose primary CWE is not in
the shared table.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

from ..findings import Finding, TraceStep

REPO_DIR = "/app/repo"
_CWE_TAG = re.compile(r"^external/cwe/cwe-0*(\d+)$", re.IGNORECASE)
_LEVELS = {"error": "error", "warning": "warning", "note": "note", "recommendation": "note"}


def cwes_of(rule: dict[str, Any]) -> tuple[str, ...]:
    tags = ((rule or {}).get("properties") or {}).get("tags") or []
    seen: list[str] = []
    for tag in tags:
        match = _CWE_TAG.match(str(tag).strip())
        if match:
            cwe = f"CWE-{int(match.group(1))}"
            if cwe not in seen:
                seen.append(cwe)
    return tuple(seen)


def residual_risk(rule: dict[str, Any]) -> str:
    raw = ((rule or {}).get("properties") or {}).get("security-severity")
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return "medium"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _rules_by_id(run: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[list[dict[str, Any]]]]:
    """Every rule CodeQL listed, by id, and the rules of each tool component
    (0 is the driver, then the extensions in order) for index lookups."""
    tool = run.get("tool") or {}
    components = [tool.get("driver") or {}, *(tool.get("extensions") or [])]
    by_component = [list(c.get("rules") or []) for c in components]
    by_id: dict[str, dict[str, Any]] = {}
    for rules in by_component:
        for rule in rules:
            if isinstance(rule, dict) and rule.get("id") and rule["id"] not in by_id:
                by_id[rule["id"]] = rule
    return by_id, by_component


def _rule_of(result: dict[str, Any], by_id, by_component) -> dict[str, Any]:
    ref = result.get("rule") or {}
    index = ref.get("index")
    # No toolComponent means the driver (SARIF 2.1.0, 3.52.7).
    component = (ref.get("toolComponent") or {}).get("index", 0)
    if isinstance(index, int) and isinstance(component, int) and 0 <= component < len(by_component):
        rules = by_component[component]
        if 0 <= index < len(rules):
            return rules[index]
    rule_id = result.get("ruleId") or ref.get("id")
    return by_id.get(rule_id, {})


def base_uris(run: dict[str, Any]) -> dict[str, str]:
    """The run's originalUriBaseIds, as {name: uri}."""
    bases = {}
    for name, value in (run.get("originalUriBaseIds") or {}).items():
        uri = (value or {}).get("uri") if isinstance(value, dict) else None
        if uri:
            bases[name] = uri
    return bases


def repo_path(artifact: dict[str, Any], bases: dict[str, str], repo_dir: str = REPO_DIR) -> str | None:
    """The file relative to /app/repo, or None when it is outside the repository."""
    uri = str((artifact or {}).get("uri") or "")
    if not uri:
        return None
    base_id = (artifact or {}).get("uriBaseId")
    if not uri.startswith("file:") and base_id:
        base = bases.get(base_id)
        if base is None:
            # %SRCROOT% without a stated base: CodeQL means the source root.
            return _relative(uri) if base_id == "%SRCROOT%" else None
        uri = base.rstrip("/") + "/" + uri.lstrip("/")
    if uri.startswith("file:"):
        path = unquote(re.sub(r"^file:(//)?", "", uri))
        root = repo_dir.rstrip("/") + "/"
        if not path.startswith(root):
            return None
        return _relative(path[len(root):])
    if uri.startswith("/"):
        root = repo_dir.rstrip("/") + "/"
        return _relative(uri[len(root):]) if uri.startswith(root) else None
    return _relative(uri)


def _relative(path: str) -> str | None:
    path = unquote(path).replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    if not path or ".." in path.split("/"):
        return None
    return path


def _region(location: dict[str, Any], bases: dict[str, str]) -> tuple[str, int, int] | None:
    physical = (location or {}).get("physicalLocation") or {}
    file = repo_path(physical.get("artifactLocation") or {}, bases)
    region = physical.get("region") or {}
    start = region.get("startLine")
    if file is None or not isinstance(start, int) or start < 1:
        return None
    end = region.get("endLine")
    end = end if isinstance(end, int) and end >= start else start
    return file, start, end


def trace_of(result: dict[str, Any], bases: dict[str, str]) -> tuple[tuple[TraceStep, ...], int]:
    """(steps of the first thread flow, steps left out because they are outside the repo)."""
    flows = result.get("codeFlows") or []
    if not flows:
        return (), 0
    thread_flows = (flows[0] or {}).get("threadFlows") or []
    if not thread_flows:
        return (), 0
    steps: list[TraceStep] = []
    dropped = 0
    for item in (thread_flows[0] or {}).get("locations") or []:
        place = _region((item or {}).get("location") or {}, bases)
        if place is None:
            dropped += 1
            continue
        steps.append(TraceStep(*place))
    return tuple(steps), dropped


def normalise(document: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    """(findings, counts) from one CodeQL SARIF document."""
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list) or not runs:
        raise ValueError("CodeQL SARIF has no runs")
    run = runs[0] or {}
    results = run.get("results")
    if not isinstance(results, list):
        raise ValueError("CodeQL SARIF has no results list")
    for invocation in run.get("invocations") or []:
        if isinstance(invocation, dict) and invocation.get("executionSuccessful") is False:
            raise ValueError("CodeQL reports that the analysis did not complete (executionSuccessful: false)")

    by_id, by_component = _rules_by_id(run)
    bases = base_uris(run)
    findings: list[Finding] = []
    by_rule: dict[str, int] = {}
    outside_repo = 0
    with_trace = 0
    trace_steps_dropped = 0
    for result in results:
        if not isinstance(result, dict):
            continue
        rule = _rule_of(result, by_id, by_component)
        rule_id = str(result.get("ruleId") or rule.get("id") or "")
        by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
        place = _region((result.get("locations") or [{}])[0], bases)
        if place is None:
            outside_repo += 1
            continue
        file, start, end = place
        trace, dropped = trace_of(result, bases)
        trace_steps_dropped += dropped
        with_trace += bool(trace)
        level = result.get("level") or ((rule.get("defaultConfiguration") or {}).get("level")) or "warning"
        findings.append(Finding(
            tool_rule_id=rule_id,
            cwes=cwes_of(rule),
            file=file,
            start_line=start,
            end_line=end,
            message=" ".join(str((result.get("message") or {}).get("text") or "").split())[:1000],
            level=_LEVELS.get(str(level).lower(), "warning"),
            residual_risk=residual_risk(rule),
            trace=trace,
        ))

    notifications = []
    for invocation in run.get("invocations") or []:
        notifications += (invocation or {}).get("toolExecutionNotifications") or []
    errors = [n for n in notifications if isinstance(n, dict) and n.get("level") == "error"]
    counts = {
        "results_raw": len(results),
        "results_by_tool_rule": dict(sorted(by_rule.items())),
        "results_outside_repo": outside_repo,
        "results_with_trace": with_trace,
        "trace_steps_outside_repo": trace_steps_dropped,
        "codeql_rules_run": len(by_id),
        "codeql_error_notifications": len(errors),
        "files_in_sarif": len(run.get("artifacts") or []),
    }
    return findings, counts
