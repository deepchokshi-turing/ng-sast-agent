"""datadog-saist's SARIF -> ``Finding`` objects, strictly.

What datadog-saist v0.0.32 writes for each result (internal/sarif/sarif.go):
``ruleId`` (``datadog/<language>-<kind>``), one location (file relative to the
scanned directory, start/end line and column), ``message.text`` (the rule's
short description, not the model's text), ``properties.tags`` with
``CWE:<n>``, ``DATADOG_CONFIDENCE:HIGH`` and ``DATADOG_CONFIDENCE_REASON:<the
model's reason>``, and a fingerprint. The rule descriptors carry the rule's
full description (with a generic "How to remediate" section) and
``SEVERITY``/``CATEGORY`` tags. There is no ``codeFlows``, no control status,
no residual risk and no catalogue recommendation, so none is ever written.

- RuleId: the frozen table ``rule_map`` (datadog-map-1), kept as
  ``Finding.task_rule``. A rule kind the table leaves out (``None``) or does
  not know is not reported and is counted.
- Location: the uri must be an in-scope text file the driver counted and
  ``startLine`` a line of it; ``endLine`` is used when it is a line at or after
  the start, else the start line (counted). Anything else is dropped and counted.
- CWEs: the result's own ``CWE:`` tag, else the rule descriptor's (written,
  never deciding the ruleId).
- Level and the heuristic residual risk: the rule's ``SEVERITY`` tag.
- Free text for a later LLM judge, verbatim under ``toolProperties`` (never
  scored): ``reason`` (the model's reason for this finding) and
  ``ruleRemediation`` (the rule's generic "How to remediate" section, the same
  for every finding of the rule).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .. import heuristics
from ..claude_review.normalise import _line, _location_problem
from ..findings import Finding
from ..scope import repo_path
from . import rule_map

VERSION = "datadog-normalise-1"
MESSAGE_CHARS = 1000
REASON_CHARS = 4000
REMEDIATION_CHARS = 4000
_CWE = re.compile(r"^(?:CWE-)?(\d{1,5})$", re.IGNORECASE)
_LEVELS = {"ERROR": "error", "WARNING": "warning", "NOTICE": "note"}
_REMEDIATION = re.compile(r"#+\s*How to remediate:?\s*\n(.*)", re.IGNORECASE | re.DOTALL)


def _tags(obj: Any) -> list[str]:
    props = obj.get("properties") if isinstance(obj, dict) else None
    tags = props.get("tags") if isinstance(props, dict) else None
    return [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []


def _tag(tags: list[str], name: str) -> str | None:
    for tag in tags:
        if tag.startswith(name + ":"):
            return tag[len(name) + 1:]
    return None


def _cwe(value: str | None) -> str | None:
    match = _CWE.match(str(value or "").strip())
    return f"CWE-{int(match.group(1))}" if match else None


def _text(obj: Any) -> str:
    return str(obj.get("text") or "") if isinstance(obj, dict) else ""


def remediation(full_description: str) -> str | None:
    """The rule's "How to remediate" section, verbatim (up to the next heading), or None."""
    match = _REMEDIATION.search(full_description or "")
    if not match:
        return None
    body = re.split(r"\n#+\s", match.group(1), maxsplit=1)[0].strip()
    return body[:REMEDIATION_CHARS] or None


def rule_descriptors(sarif: dict[str, Any]) -> dict[str, dict[str, Any]]:
    run = (sarif.get("runs") or [{}])[0] if isinstance(sarif, dict) else {}
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") if isinstance(run, dict) else None
    return {r["id"]: r for r in rules or [] if isinstance(r, dict) and isinstance(r.get("id"), str)}


def normalise(sarif: dict[str, Any], *, line_counts: dict[str, int], roots: list[str],
              excludes: list[str]) -> tuple[list[Finding], dict[str, Any]]:
    """(findings, counts for the run metadata)."""
    run = (sarif.get("runs") or [{}])[0] if isinstance(sarif, dict) else {}
    results = run.get("results") if isinstance(run, dict) and isinstance(run.get("results"), list) else []
    rules = rule_descriptors(sarif)
    findings: list[Finding] = []
    dropped_location: list[list[Any]] = []
    dropped_scope: list[list[Any]] = []
    not_reported: Counter[str] = Counter()
    not_in_map: Counter[str] = Counter()
    by_rule: Counter[str] = Counter()
    end_replaced = 0

    for item in results:
        if not isinstance(item, dict):
            dropped_location.append(["not an object", None, None])
            continue
        rule_id = str(item.get("ruleId") or "")
        by_rule[rule_id] += 1
        locations = item.get("locations") if isinstance(item.get("locations"), list) else []
        physical = (locations[0] or {}).get("physicalLocation") if locations and isinstance(locations[0], dict) else {}
        physical = physical if isinstance(physical, dict) else {}
        raw_file = str((physical.get("artifactLocation") or {}).get("uri") or "")
        region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
        file = repo_path(raw_file)
        line = _line(region.get("startLine"))
        problem = "no location" if not file else _location_problem(file, line, line_counts, roots, excludes)
        if problem == "out of scope":
            dropped_scope.append([rule_id, raw_file[:200], region.get("startLine")])
            continue
        if problem:
            dropped_location.append([problem, file or raw_file[:200], region.get("startLine")])
            continue
        kind, task_rule, known = rule_map.lookup(rule_id)
        if task_rule is None:
            (not_reported if known else not_in_map)[rule_id or "(none)"] += 1
            continue
        end = _line(region.get("endLine"))
        if end is None or end < line or end > line_counts[file]:
            end_replaced += 1
            end = line

        result_tags = _tags(item)
        descriptor = rules.get(rule_id, {})
        rule_tags = _tags(descriptor)
        cwe = _cwe(_tag(result_tags, "CWE")) or _cwe(_tag(rule_tags, "CWE"))
        severity = (_tag(rule_tags, "SEVERITY") or "").upper()
        reason = _tag(result_tags, "DATADOG_CONFIDENCE_REASON") or ""
        short = _text(descriptor.get("shortDescription")) or _text(item.get("message"))
        extra = [("datadogRuleId", rule_id), ("ruleKind", kind), ("mapVersion", rule_map.VERSION),
                 ("ruleShortDescription", short[:300]), ("severity", severity or "missing"),
                 ("confidence", _tag(result_tags, "DATADOG_CONFIDENCE") or "missing")]
        if reason:
            extra.append(("reason", reason[:REASON_CHARS]))
        fix = remediation(_text(descriptor.get("fullDescription")))
        if fix:
            extra.append(("ruleRemediation", fix))
        fingerprint = (item.get("partialFingerprints") or {}).get("DATADOG_FINGERPRINT") \
            if isinstance(item.get("partialFingerprints"), dict) else None
        if isinstance(fingerprint, str):
            extra.append(("fingerprint", fingerprint[:100]))
        findings.append(Finding(
            tool_rule_id=rule_id,
            cwes=(cwe,) if cwe else (),
            file=file,
            start_line=line,
            end_line=end,
            message=" ".join(reason.split())[:MESSAGE_CHARS] or short or rule_id,
            level=_LEVELS.get(severity, "warning"),
            residual_risk=heuristics.residual_risk(severity, None),
            extra=tuple(extra),
            task_rule=task_rule,
        ))

    counts = {
        "datadog_normalise": VERSION,
        "rule_map": rule_map.VERSION,
        "findings_reported": len(results),
        "results_by_datadog_rule": dict(sorted(by_rule.items())),
        "dropped_bad_location": dropped_location[:200],
        "dropped_bad_location_count": len(dropped_location),
        "dropped_out_of_scope": dropped_scope[:200],
        "dropped_out_of_scope_count": len(dropped_scope),
        "rule_not_reported": dict(sorted(not_reported.items())),
        "rule_not_in_map": dict(sorted(not_in_map.items())),
        "end_line_replaced": end_replaced,
    }
    return findings, counts
