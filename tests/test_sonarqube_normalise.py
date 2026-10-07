"""sast/sonarqube/normalise.py on SonarQube output recorded from a real run.

Provenance of tests/fixtures/sonarqube_26.9_<task>.json (also in
tests/fixtures/sonarqube_26.9_PROVENANCE.txt): SonarQube Community Build
26.9.0.129388 in Docker, sonar-scanner 8.1.0.6389, recorded on 2026-10-07 by
the agent's own fetch.py during a real Harbor run (four trials, status ok).
They are in the OLD fetch format (``fetch_format`` 1), written before fetch.py
asked ``api/rules/search`` for the cwe facet, so they hold no CWE at all. The
normaliser must read them without failing, report nothing from them and count
why.

Fresh recordings in fetch_format 2 (with ``rule_facets``) from a second real
run on 2026-10-08 are in tests/fixtures/sonarqube_26.9-f2_<task>.json, checked
by :func:`test_format_2_recordings` and :func:`test_format_2_exact_results`.

The CWE sets used for the mapping tests (python:S5332 -> 200, 319 and
python:S4423 -> 295, 326, 327) are what the real 26.9 server returned from
``api/rules/search?rule_key=<key>&facets=cwe&ps=1``, checked by the main
session. The facet response is the documented shape with those values.
"""

from __future__ import annotations

import copy
import itertools
import json

import pytest

from sast import cwe_map, sarif
from sast.sonarqube.normalise import (
    CWE_SOURCE_FACET,
    CWE_SOURCE_NONE,
    cwe_decision,
    facet_cwes,
    normalise,
    sonar_types,
)
from tests.conftest import FIXTURES

RECORDED = sorted(FIXTURES.glob("sonarqube_26.9_*.json"))


def recorded(task: str) -> dict:
    return json.loads((FIXTURES / f"sonarqube_26.9_{task}.json").read_text())


def facet_response(key: str, cwes: list[str]) -> dict:
    """api/rules/search?rule_key=<key>&facets=cwe&ps=1, with the CWEs the real server gave."""
    return {"total": 1, "p": 1, "ps": 1, "rules": [{"key": key}],
            "facets": [{"property": "cwe", "values": [{"val": c, "count": 1} for c in cwes]}]}


#: Verified on the real 26.9 server.
S5332_CWES = ["200", "319"]
S4423_CWES = ["295", "326", "327"]

#: (task, [(rule, file, line, level, residual risk)]) as recorded.
EXPECTED = {
    "task_4da5ab_negative": [("python:S4423", "src/pydantic_ai_mini/_compat/httpx2.py", 145, "error", "high")],
    "task_4da5ab_positive": [("python:S4423", "src/pydantic_ai_mini/_compat/httpx2.py", 145, "error", "high")],
    "task_dc4b7a_negative": [
        ("python:S5332", "src/crewai_rag_web_mini/_compat/requests.py", 115, "note", "low"),
        ("python:S5332", "src/crewai_rag_web_mini/security/safe_requests.py", 77, "note", "low"),
    ],
    "task_dc4b7a_positive": [("python:S5332", "src/crewai_rag_web_mini/_compat/requests.py", 115, "note", "low")],
}


def test_all_recordings_are_known():
    assert {p.name for p in RECORDED} >= {f"sonarqube_26.9_{t}.json" for t in EXPECTED}


# ---------------------------------------------------------------- old format, as recorded


@pytest.mark.parametrize("task", sorted(EXPECTED))
def test_recorded_old_format_reads_but_reports_nothing(task):
    document = recorded(task)
    assert document["fetch_format"] == 1 and "rule_facets" not in document
    findings, counts = normalise(document)

    assert [(f.tool_rule_id, f.file, f.start_line, f.level, f.residual_risk) for f in findings] == EXPECTED[task]
    assert all(f.cwes == () and f.trace == () and f.end_line == f.start_line for f in findings)
    assert all(dict(f.extra) == {"sonarType": "VULNERABILITY"} for f in findings)

    n = len(EXPECTED[task])
    assert counts["results_raw"] == n
    assert counts["results_by_sonar_type"] == {"VULNERABILITY": n, "SECURITY_HOTSPOT": 0}
    assert counts["issues_not_vulnerability"] == {}
    assert counts["rule_cwe_source"] == CWE_SOURCE_NONE
    assert counts["rules_without_cwe"] == [EXPECTED[task][0][0]]
    assert counts["results_by_cwe_decision"] == {"none": n, "unmapped": 0, "mapped": 0, "ambiguous": 0}
    assert counts["flows_raw"] == 0 and counts["issues_with_flows"] == 0
    assert sonar_types(findings) == {"VULNERABILITY": n, "SECURITY_HOTSPOT": 0}

    built, stats = sarif.build(findings, tool_name="sonarqube", tool_version="8.1.0.6389")
    assert built["runs"][0]["results"] == []
    assert stats["findings_unmapped"] == n and stats["unmapped_by_cwe"] == {"none": n}


@pytest.mark.parametrize("path", RECORDED, ids=lambda p: p.name)
def test_recordings_hold_only_vulnerabilities_without_flows(path):
    """issues/search honoured types=VULNERABILITY, and the Community Build gave no flows."""
    document = json.loads(path.read_text())
    issues = [i for page in document["issues_pages"] for i in page.get("issues") or []]
    assert issues and {i["type"] for i in issues} == {"VULNERABILITY"}
    assert all(i.get("flows") == [] for i in issues)
    assert sum(len(page.get("hotspots") or []) for page in document["hotspots_pages"]) == 0
    assert all("securityStandards" not in (rule or {}).get("rule", {}) for rule in document["rules"].values())
    assert "squ_" not in path.read_text()


# ---------------------------------------------------------------- with the cwe facet


def test_facet_cwes_reads_the_cwe_facet_in_numeric_order():
    response = facet_response("python:S5332", ["319", "200"])
    response["facets"].append({"property": "owaspTop10-2021", "values": [{"val": "a2", "count": 1}]})
    response["facets"][0]["values"] += [{"val": "unknown", "count": 1}, {"val": "79", "count": 0}]
    assert facet_cwes(response) == ("CWE-200", "CWE-319")
    assert facet_cwes(None) == () and facet_cwes({"total": 0, "rules": [], "facets": []}) == ()


def test_s5332_is_ambiguous_and_dropped():
    """CWE-200 maps to LLM02 but CWE-319 is unmapped: which is primary decides, so nothing is reported."""
    document = recorded("task_dc4b7a_negative")
    document["rule_facets"] = {"python:S5332": facet_response("python:S5332", S5332_CWES)}
    findings, counts = normalise(document)
    assert findings == []
    assert counts["rule_cwe_source"] == CWE_SOURCE_FACET and counts["rules_without_cwe"] == []
    assert counts["results_by_cwe_decision"] == {"none": 0, "unmapped": 0, "mapped": 0, "ambiguous": 2}
    assert counts["results_cwe_ambiguous"] == [
        ["python:S5332", ["CWE-200", "CWE-319"], "src/crewai_rag_web_mini/_compat/requests.py", 115],
        ["python:S5332", ["CWE-200", "CWE-319"], "src/crewai_rag_web_mini/security/safe_requests.py", 77],
    ]


def test_s4423_is_unmapped_and_passed_on_in_numeric_order():
    document = recorded("task_4da5ab_positive")
    document["rule_facets"] = {"python:S4423": facet_response("python:S4423", list(reversed(S4423_CWES)))}
    findings, counts = normalise(document)
    assert [f.cwes for f in findings] == [("CWE-295", "CWE-326", "CWE-327")]
    assert counts["results_by_cwe_decision"]["unmapped"] == 1
    built, stats = sarif.build(findings, tool_name="sonarqube", tool_version="8.1.0.6389")
    assert built["runs"][0]["results"] == [] and stats["unmapped_by_cwe"] == {"CWE-295": 1}


def test_failed_rule_lookups_are_counted_not_fatal():
    document = recorded("task_4da5ab_positive")
    document["rule_facets"] = {"python:S4423": None}
    document["rule_errors"] = {"python:S4423": "GET api/rules/search failed: not found"}
    findings, counts = normalise(document)
    assert [f.cwes for f in findings] == [()]
    assert counts["rule_lookup_errors"] == {"python:S4423": "GET api/rules/search failed: not found"}
    assert counts["rules_without_cwe"] == ["python:S4423"]


@pytest.mark.parametrize("cwes, decision, ordered", [
    (S5332_CWES, "ambiguous", ("CWE-200", "CWE-319")),
    (S4423_CWES, "unmapped", ("CWE-295", "CWE-326", "CWE-327")),
    (["89", "78"], "mapped", ("CWE-78", "CWE-89")),
    (["532", "200"], "mapped", ("CWE-200", "CWE-532")),
    (["22", "200"], "ambiguous", ("CWE-22", "CWE-200")),
    (["502"], "mapped", ("CWE-502",)),
    ([], "none", ()),
])
def test_cwe_decision(cwes, decision, ordered):
    assert cwe_decision([f"CWE-{c}" for c in cwes]) == (decision, ordered)


def test_reported_family_never_depends_on_which_cwe_is_primary():
    """For every set the rule passes on, cwe-map-3 gives the same answer whichever CWE comes first."""
    pool = sorted(cwe_map.CWE_MAP, key=lambda c: int(c[4:]))[::4] + ["CWE-319", "CWE-327", "CWE-79"]
    for size in (1, 2, 3):
        for combo in itertools.combinations(pool, size):
            decision, ordered = cwe_decision(combo)
            answers = {cwe_map.task_rule(p) for p in itertools.permutations(combo)}
            if decision in ("mapped", "unmapped"):
                assert answers == {cwe_map.task_rule(ordered)}, combo
            else:
                families = {cwe_map.rule_for(p) for p in itertools.permutations(combo)}
                assert len(families) > 1, combo


# ---------------------------------------------------------------- guards


def test_issue_types_other_than_vulnerability_are_skipped_and_counted():
    document = recorded("task_dc4b7a_negative")
    document["issues_pages"][0]["issues"][1]["type"] = "CODE_SMELL"
    findings, counts = normalise(document)
    assert len(findings) == 1
    assert counts["issues_not_vulnerability"] == {"CODE_SMELL": 1}
    assert counts["results_by_sonar_type"]["VULNERABILITY"] == 1


def test_flows_are_counted_but_never_become_a_trace():
    document = copy.deepcopy(recorded("task_dc4b7a_positive"))
    issue = document["issues_pages"][0]["issues"][0]
    location = {"component": issue["component"], "textRange": issue["textRange"]}
    issue["flows"] = [{"locations": [location, location]}]
    findings, counts = normalise(document)
    assert counts["flows_raw"] == 1 and counts["issues_with_flows"] == 1
    assert all(f.trace == () for f in findings)


def test_document_without_pages_is_refused():
    with pytest.raises(ValueError):
        normalise({"issues_pages": []})


# ---------------------------------------------------------------- fresh recordings (fetch_format 2)


FORMAT_2 = sorted(FIXTURES.glob("sonarqube_26.9-f2_*.json"))


def test_format_2_recordings_exist():
    assert len(FORMAT_2) == 4


@pytest.mark.parametrize("path", FORMAT_2, ids=lambda p: p.name)
def test_format_2_recordings(path):
    document = json.loads(path.read_text())
    assert document.get("fetch_format") == 2
    findings, counts = normalise(document)
    assert counts["rule_cwe_source"] == CWE_SOURCE_FACET
    decisions = counts["results_by_cwe_decision"]
    assert sum(decisions.values()) == len(findings) + decisions["ambiguous"]
    for f in findings:
        assert list(f.cwes) == sorted(f.cwes, key=lambda c: int(c[4:])) and f.trace == ()


#: Exact outcome of the real 2026-10-08 run, per task.
F2_EXPECTED = {
    "task_4da5ab_positive": ("python:S4423", ("CWE-295", "CWE-326", "CWE-327"), "unmapped"),
    "task_4da5ab_negative": ("python:S4423", ("CWE-295", "CWE-326", "CWE-327"), "unmapped"),
    "task_dc4b7a_positive": ("python:S5332", ("CWE-200", "CWE-319"), "ambiguous"),
    "task_dc4b7a_negative": ("python:S5332", ("CWE-200", "CWE-319"), "ambiguous"),
}


@pytest.mark.parametrize("task", sorted(F2_EXPECTED))
def test_format_2_exact_results(task):
    rule, cwes, decision = F2_EXPECTED[task]
    document = json.loads((FIXTURES / f"sonarqube_26.9-f2_{task}.json").read_text())
    findings, counts = normalise(document)
    assert counts["results_by_cwe_decision"][decision] >= 1
    assert all(f.tool_rule_id == rule and f.cwes == cwes for f in findings)
    built, _ = sarif.build(findings, tool_name="sonarqube", tool_version="8.1.0.6389")
    # Neither rule maps to an OWASP LLM ruleId, so nothing is reported, as in the real trials.
    assert built["runs"][0]["results"] == []
