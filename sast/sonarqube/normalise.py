"""fetch.py's raw SonarQube API JSON -> findings.

Both kinds of security result are kept: issues of type VULNERABILITY and
Security Hotspots. For each one:

- CWEs come from the ``cwe`` facet of ``api/rules/search?rule_key=<key>``,
  which fetch.py stores per rule under ``rule_facets``. SonarQube Community
  Build 26.9 does not return ``securityStandards`` from ``api/rules/show``
  (only sysTags such as ``cwe``), so the facet is the one source. A rule whose
  lookup failed or came back empty has no CWE, and so has every rule in a
  ``fetch_format`` 1 document, which was written before fetch.py asked for
  the facet. Such results are passed on with no CWE (never reported) and
  counted.
- The facet is an unordered set, while ``sast.cwe_map`` maps a rule by its
  primary CWE so that a rule is never reported through a secondary CWE.
  Sonar names no primary CWE, so this module applies the one choice that
  gives the cwe-map-3 answer whatever the primary would have been: each CWE
  of the rule is mapped on its own with ``cwe_map.rule_for``. When every CWE
  gives the same answer (the same ruleId family, or unmapped for all of
  them), that answer is certain and the result is passed on with its CWEs in
  numeric order, so ``rule_for`` on the tuple gives that same answer. When
  the answers differ (two families, or a family and an unmapped CWE), the
  result depends on which CWE Sonar would call primary. It is then dropped
  as ambiguous and counted, never reported. See :func:`cwe_decision`.
- The location is ``textRange`` (or ``line``), and the file is the part of
  ``component`` after ``<projectKey>:``, which is relative to
  ``sonar.projectBaseDir`` (/app/repo). A result with no line is skipped and
  counted.
- No trace. The Community Build has no taint engine, so its issues carry no
  dataflow, and the order of a flow's locations was never checked against a
  real taint flow. ``Finding.trace`` is always empty for SonarQube. The number
  of raw flows is counted so a server that does return them is noticed.
- ``api/issues/search`` is asked for ``types=VULNERABILITY``. Every issue's
  own ``type`` is checked as well: anything else is skipped and counted.
- ``sonarType`` is ``VULNERABILITY`` or ``SECURITY_HOTSPOT`` and reaches the
  SARIF properties through ``Finding.extra``.
- ``residual_risk`` (a heuristic, never scored) comes from the issue's
  SECURITY impact severity, else its legacy severity, or the hotspot's
  ``vulnerabilityProbability``.
"""

from __future__ import annotations

from typing import Any, Iterable

from .. import cwe_map, heuristics
from ..findings import Finding

#: Sonar severities (legacy and MQR impact) and hotspot probabilities, in the
#: words ``sast.heuristics.residual_risk`` knows.
_RISK_WORDS = {
    "BLOCKER": "HIGH",
    "CRITICAL": "HIGH",
    "HIGH": "HIGH",
    "MAJOR": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "MINOR": "LOW",
    "LOW": "LOW",
    "INFO": "LOW",
}
_LEVELS = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

VULNERABILITY = "VULNERABILITY"
SECURITY_HOTSPOT = "SECURITY_HOTSPOT"

#: Where the CWEs of the rules came from, as recorded in the metadata.
CWE_SOURCE_FACET = "api/rules/search cwe facet"
CWE_SOURCE_NONE = "none: fetch_format 1 has no cwe facet"


def facet_cwes(search: dict[str, Any] | None) -> tuple[str, ...]:
    """"CWE-<n>" ids from one api/rules/search response's ``cwe`` facet, in numeric order.

    Values that are not a number (the server may list ``unknown``) are ignored.
    """
    numbers: set[int] = set()
    for facet in (search or {}).get("facets") or []:
        if not isinstance(facet, dict) or facet.get("property") != "cwe":
            continue
        for value in facet.get("values") or []:
            val = str((value or {}).get("val") or "").strip() if isinstance(value, dict) else ""
            if val.isdigit() and int((value or {}).get("count") or 0) > 0:
                numbers.add(int(val))
    return tuple(f"CWE-{n}" for n in sorted(numbers))


def cwe_decision(cwes: Iterable[str]) -> tuple[str, tuple[str, ...]]:
    """("none" | "unmapped" | "mapped" | "ambiguous", the CWEs in numeric order).

    Each CWE is mapped on its own, as if it were the primary one. "mapped"
    means all of them land in the same family, "unmapped" that none of them
    maps, "ambiguous" that the answer depends on which one is primary.
    """
    ordered = tuple(sorted(set(cwes), key=lambda c: int(c.split("-", 1)[1])))
    if not ordered:
        return "none", ordered
    families = {cwe_map.rule_for((cwe,)) for cwe in ordered}
    if len(families) > 1:
        return "ambiguous", ordered
    return ("unmapped" if families == {None} else "mapped"), ordered


def component_path(component: str, project_key: str) -> str:
    """The repo-relative file of a "<projectKey>:<path>" component."""
    prefix = project_key + ":"
    path = component[len(prefix):] if component.startswith(prefix) else component.split(":", 1)[-1]
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def _lines(item: dict[str, Any]) -> tuple[int, int]:
    text_range = item.get("textRange") or {}
    start = int(text_range.get("startLine") or item.get("line") or 0)
    end = int(text_range.get("endLine") or start)
    return start, max(end, start)


def _security_severity(issue: dict[str, Any]) -> str | None:
    for impact in issue.get("impacts") or []:
        if isinstance(impact, dict) and impact.get("softwareQuality") == "SECURITY":
            return impact.get("severity")
    return issue.get("severity")


def _risk_word(value: Any) -> str | None:
    return _RISK_WORDS.get(str(value or "").strip().upper())


def _flatten(pages: Iterable[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    return [item for page in pages or [] for item in (page or {}).get(key) or [] if isinstance(item, dict)]


def rule_cwes(document: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """Every looked-up rule's CWEs, from the document's ``rule_facets``."""
    facets = document.get("rule_facets") or {}
    keys = set(facets) | set(document.get("rules") or {})
    return {key: facet_cwes(facets.get(key)) for key in keys}


def normalise(document: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    """(findings, counts) from one sonarqube.json written by fetch.py."""
    if not isinstance(document, dict) or "issues_pages" not in document or "hotspots_pages" not in document:
        raise ValueError("sonarqube.json has no issues_pages or hotspots_pages")
    project = str(document.get("project_key") or "")
    has_facets = "rule_facets" in document
    cwes_by_rule = rule_cwes(document)
    issues = _flatten(document["issues_pages"], "issues")
    hotspots = _flatten(document["hotspots_pages"], "hotspots")

    findings: list[Finding] = []
    no_line = {VULNERABILITY: 0, SECURITY_HOTSPOT: 0}
    other_types: dict[str, int] = {}
    decisions = {"none": 0, "unmapped": 0, "mapped": 0, "ambiguous": 0}
    ambiguous: list[list[Any]] = []
    flows = 0
    issues_with_flows = 0

    def add(sonar_type: str, item: dict[str, Any], rule: str, word: str | None) -> None:
        start, end = _lines(item)
        if start < 1:
            no_line[sonar_type] += 1
            return
        file = component_path(str(item.get("component") or ""), project)
        decision, cwes = cwe_decision(cwes_by_rule.get(rule, ()))
        decisions[decision] += 1
        if decision == "ambiguous":
            ambiguous.append([rule, list(cwes), file, start])
            return
        findings.append(Finding(
            tool_rule_id=rule,
            cwes=cwes,
            file=file,
            start_line=start,
            end_line=end,
            message=" ".join(str(item.get("message") or "").split())[:1000],
            level=_LEVELS.get(word or "", "warning"),
            residual_risk=heuristics.residual_risk(word, None),
            extra=(("sonarType", sonar_type),),
        ))

    for issue in issues:
        kind = str(issue.get("type") or "")
        if kind != VULNERABILITY:
            other_types[kind or "missing"] = other_types.get(kind or "missing", 0) + 1
            continue
        issue_flows = [f for f in issue.get("flows") or [] if isinstance(f, dict)]
        flows += len(issue_flows)
        issues_with_flows += bool(issue_flows)
        add(VULNERABILITY, issue, str(issue.get("rule") or ""), _risk_word(_security_severity(issue)))
    for hotspot in hotspots:
        add(SECURITY_HOTSPOT, hotspot, str(hotspot.get("ruleKey") or ""),
            _risk_word(hotspot.get("vulnerabilityProbability")))

    vulnerabilities = len(issues) - sum(other_types.values())
    counts = {
        "results_raw": len(issues) + len(hotspots),
        "results_by_sonar_type": {VULNERABILITY: vulnerabilities, SECURITY_HOTSPOT: len(hotspots)},
        "issues_not_vulnerability": dict(sorted(other_types.items())),
        "results_without_line": no_line,
        "rule_cwe_source": CWE_SOURCE_FACET if has_facets else CWE_SOURCE_NONE,
        "rules_without_cwe": sorted(k for k, v in cwes_by_rule.items() if not v),
        "rule_lookup_errors": dict(sorted((document.get("rule_errors") or {}).items())),
        "results_by_cwe_decision": decisions,
        "results_cwe_ambiguous": ambiguous,
        "flows_raw": flows,
        "issues_with_flows": issues_with_flows,
    }
    return findings, counts


def sonar_types(findings: list[Finding]) -> dict[str, int]:
    """Findings per sonarType, read from ``Finding.extra``."""
    counts = {VULNERABILITY: 0, SECURITY_HOTSPOT: 0}
    for f in findings:
        kind = dict(f.extra).get("sonarType") or VULNERABILITY
        counts[kind] = counts.get(kind, 0) + 1
    return counts
