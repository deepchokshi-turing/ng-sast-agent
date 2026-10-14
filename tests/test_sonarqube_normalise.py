"""sast/sonarqube/normalise.py on SonarQube output recorded from real runs.

Provenance (also in tests/fixtures/sonarqube_26.9_PROVENANCE.txt): SonarQube
Community Build 26.9.0.129388 in Docker, sonar-scanner 8.1.0.6389, written by
the agent's own fetch.py during real Harbor runs, unedited.

- tests/fixtures/sonarqube_26.9-f2_<task>.json (2026-10-08, ``fetch_format``
  2): with the per-rule cwe facet from ``api/rules/search``. These are what the
  agent accepts, and most tests here read them as they are.
- tests/fixtures/sonarqube_26.9_<task>.json (2026-10-07, ``fetch_format`` 1):
  written before fetch.py asked for the facet, so they hold no CWE. The
  normaliser refuses them unless ``allow_old_format=True`` (tests only).
- tests/fixtures/sonarqube_26.9-f3_smoke_sonar.json (2026-10-08, ``fetch_format``
  2): a later run of the smoke_sonar task, with the ``api/measures/component``
  answer and the hotspot rule counts the f2 recordings predate.

Tests of guard paths that no recording shows (a failed rule lookup, an issue
type other than VULNERABILITY, flows) change a copy of a recording and say so.
"""

from __future__ import annotations

import copy
import json

import pytest

from sast import sarif
from sast.sonarqube.normalise import (
    CWE_SOURCE_FACET,
    CWE_SOURCE_NONE,
    facet_cwes,
    normalise,
    sonar_types,
)
from tests.conftest import FIXTURES

OLD_FORMAT = sorted(FIXTURES.glob("sonarqube_26.9_*.json"))
FORMAT_2 = sorted(FIXTURES.glob("sonarqube_26.9-f2_*.json"))


def recorded(task: str) -> dict:
    """A fetch_format 1 recording."""
    return json.loads((FIXTURES / f"sonarqube_26.9_{task}.json").read_text())


def recorded_f2(task: str) -> dict:
    return json.loads((FIXTURES / f"sonarqube_26.9-f2_{task}.json").read_text())


#: (task, [(rule, file, line, level, residual risk)]) as recorded, the same in both formats.
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
    assert {p.name for p in OLD_FORMAT} >= {f"sonarqube_26.9_{t}.json" for t in EXPECTED}
    assert {p.name for p in FORMAT_2} == {f"sonarqube_26.9-f2_{t}.json" for t in EXPECTED} | {"sonarqube_26.9-f2_smoke_sonar.json"}


@pytest.mark.parametrize("path", OLD_FORMAT + FORMAT_2, ids=lambda p: p.name)
def test_recordings_hold_only_vulnerabilities_without_flows(path):
    """issues/search honoured types=VULNERABILITY, and the Community Build gave no flows."""
    document = json.loads(path.read_text())
    issues = [i for page in document["issues_pages"] for i in page.get("issues") or []]
    assert issues and {i["type"] for i in issues} == {"VULNERABILITY"}
    assert all(i.get("flows") == [] for i in issues)
    assert sum(len(page.get("hotspots") or []) for page in document["hotspots_pages"]) == 0
    assert all("securityStandards" not in (rule or {}).get("rule", {}) for rule in document["rules"].values())
    assert "squ_" not in path.read_text()


# ---------------------------------------------------------------- fetch_format 2, as recorded


#: Exact outcome of the real 2026-10-08 run under cwe-map-5, per task:
#: (rule, CWEs in the order passed on, decision, emitted ruleId or None).
F2_EXPECTED = {
    "task_4da5ab_positive": ("python:S4423", ("CWE-295", "CWE-326", "CWE-327"), "unmapped", None),
    "task_4da5ab_negative": ("python:S4423", ("CWE-295", "CWE-326", "CWE-327"), "unmapped", None),
    # cwe-map-4 emitted S5332 as LLM02.SID.HIGH. cwe-map-5: clear-text transport is not disclosure.
    "task_dc4b7a_positive": ("python:S5332", ("CWE-319", "CWE-200"), "unmapped", None),
    "task_dc4b7a_negative": ("python:S5332", ("CWE-319", "CWE-200"), "unmapped", None),
}


@pytest.mark.parametrize("task", sorted(F2_EXPECTED))
def test_format_2_exact_results(task):
    rule, cwes, decision, emitted = F2_EXPECTED[task]
    findings, counts = normalise(recorded_f2(task))
    n = len(EXPECTED[task])
    assert [(f.tool_rule_id, f.file, f.start_line, f.level, f.residual_risk) for f in findings] == EXPECTED[task]
    assert all(f.cwes == cwes and f.trace == () and dict(f.extra) == {"sonarType": "VULNERABILITY"}
               for f in findings)
    assert counts["rule_cwe_source"] == CWE_SOURCE_FACET and counts["rules_without_cwe"] == []
    assert counts["results_by_cwe_decision"] == {**{"none": 0, "unmapped": 0, "mapped": 0, "ambiguous": 0},
                                                 decision: n}
    assert counts["results_cwe_ambiguous"] == []
    assert counts["results_by_sonar_type"] == {"VULNERABILITY": n, "SECURITY_HOTSPOT": 0}
    assert counts["flows_raw"] == 0 and counts["issues_with_flows"] == 0
    assert sonar_types(findings) == {"VULNERABILITY": n, "SECURITY_HOTSPOT": 0}

    built, stats = sarif.build(findings, tool_name="sonarqube", tool_version="8.1.0.6389")
    results = built["runs"][0]["results"]
    if emitted is None:
        assert results == [] and stats["unmapped_by_cwe"] == {cwes[0]: n}
    else:
        assert [r["ruleId"] for r in results] == [emitted] * n
        assert all(r["properties"]["cwe"] == list(cwes) and "codeFlows" not in r for r in results)


@pytest.mark.parametrize("task", sorted(F2_EXPECTED))
def test_decision_does_not_depend_on_the_facet_order(task):
    document = recorded_f2(task)
    for facet in document["rule_facets"].values():
        facet["facets"][0]["values"].reverse()
    assert normalise(document) == normalise(recorded_f2(task))


def test_facet_cwes_reads_the_cwe_facet_in_numeric_order():
    response = copy.deepcopy(recorded_f2("task_4da5ab_positive")["rule_facets"]["python:S4423"])
    response["facets"][0]["values"].reverse()
    response["facets"].append({"property": "owaspTop10-2021", "values": [{"val": "a2", "count": 1}]})
    response["facets"][0]["values"] += [{"val": "unknown", "count": 1}, {"val": "79", "count": 0}]
    assert facet_cwes(response) == ("CWE-295", "CWE-326", "CWE-327")
    assert facet_cwes(None) == () and facet_cwes({"total": 0, "rules": [], "facets": []}) == ()


# ---------------------------------------------------------------- strictness


@pytest.mark.parametrize("task", sorted(EXPECTED))
def test_old_format_is_refused(task):
    with pytest.raises(ValueError, match="fetch_format 1"):
        normalise(recorded(task))


@pytest.mark.parametrize("task", sorted(EXPECTED))
def test_old_format_reads_with_the_test_flag_but_reports_nothing(task):
    document = recorded(task)
    assert document["fetch_format"] == 1 and "rule_facets" not in document
    findings, counts = normalise(document, allow_old_format=True)
    n = len(EXPECTED[task])
    assert [(f.tool_rule_id, f.file, f.start_line, f.level, f.residual_risk) for f in findings] == EXPECTED[task]
    assert all(f.cwes == () for f in findings)
    assert counts["rule_cwe_source"] == CWE_SOURCE_NONE
    assert counts["results_by_cwe_decision"] == {"none": n, "unmapped": 0, "mapped": 0, "ambiguous": 0}
    built, _ = sarif.build(findings, tool_name="sonarqube", tool_version="8.1.0.6389")
    assert built["runs"][0]["results"] == []


def test_recorded_rule_errors_are_refused():
    """No recording has a failed lookup: a copy of a recording with one added."""
    document = recorded_f2("task_4da5ab_positive")
    document["rule_errors"] = {"python:S4423": "GET api/rules/search failed: not found"}
    with pytest.raises(ValueError, match="rule lookups failed"):
        normalise(document)


@pytest.mark.parametrize("facet", [
    None,
    {"paging": {"total": 0}, "rules": [], "facets": []},
    {"paging": {"total": 1}, "rules": [{"key": "python:S9999"}], "facets": []},
])
def test_a_rule_without_its_own_facet_is_refused(facet):
    """A copy of a recording whose facet answer is missing, empty or for another rule."""
    document = recorded_f2("task_dc4b7a_positive")
    document["rule_facets"]["python:S5332"] = facet
    with pytest.raises(ValueError, match="python:S5332"):
        normalise(document)


def test_issue_types_other_than_vulnerability_are_skipped_and_counted():
    """No recording has another type (fetch.py asks for VULNERABILITY only): one issue's type changed."""
    document = recorded_f2("task_dc4b7a_negative")
    document["issues_pages"][0]["issues"][1]["type"] = "CODE_SMELL"
    findings, counts = normalise(document)
    assert len(findings) == 1
    assert counts["issues_not_vulnerability"] == {"CODE_SMELL": 1}
    assert counts["results_by_sonar_type"]["VULNERABILITY"] == 1


def test_flows_are_counted_but_never_become_a_trace():
    """The Community Build returns no flows: a copy of a recorded issue given one."""
    document = recorded_f2("task_dc4b7a_positive")
    issue = document["issues_pages"][0]["issues"][0]
    location = {"component": issue["component"], "textRange": issue["textRange"]}
    issue["flows"] = [{"locations": [location, location]}]
    findings, counts = normalise(document)
    assert counts["flows_raw"] == 1 and counts["issues_with_flows"] == 1
    assert all(f.trace == () for f in findings)


def test_document_without_pages_is_refused():
    with pytest.raises(ValueError):
        normalise({"issues_pages": []})


def test_ambiguous_cwe_sets_are_dropped_and_listed():
    """No recorded rule is ambiguous: a copy whose facet holds CWE-22 (FUNCTIONALITY) and CWE-532 (LLM02).

    Under cwe-map-5 a generic CWE such as 200 gives way to a specific one, so the
    copy uses two specific CWEs of different families.
    """
    document = recorded_f2("task_dc4b7a_positive")
    document["rule_facets"]["python:S5332"]["facets"][0]["values"] = [
        {"val": "532", "count": 1}, {"val": "22", "count": 1}]
    findings, counts = normalise(document)
    assert findings == []
    assert counts["results_by_cwe_decision"]["ambiguous"] == 1
    assert counts["results_cwe_ambiguous"] == [
        ["python:S5332", ["CWE-22", "CWE-532"], "src/crewai_rag_web_mini/_compat/requests.py", 115]]


def test_pillar_cwe_gives_way_to_a_specific_one():
    """docker:S6471 (container runs as root) carries {250, 284}. cwe-map-4 dropped it as
    ambiguous, cwe-map-5 reports it through the specific CWE-250 as EA permissions."""
    document = recorded_f2("task_dc4b7a_positive")
    document["rule_facets"]["python:S5332"]["facets"][0]["values"] = [
        {"val": "284", "count": 1}, {"val": "250", "count": 1}]
    findings, counts = normalise(document)
    assert counts["results_by_cwe_decision"]["mapped"] == 1 and counts["results_cwe_ambiguous"] == []
    assert [f.cwes for f in findings] == [("CWE-250", "CWE-284")]
    assert sarif.emitted_rules(findings) == ["LLM03.EA.PERMISSIONS"]


def test_smoke_sonar_recording_maps_two_vulnerabilities():
    """Real run on tests/fixtures/tasks/smoke_sonar (2026-10-08): the first recording with mapped results (two under cwe-map-4)."""
    document = json.loads((FIXTURES / "sonarqube_26.9-f2_smoke_sonar.json").read_text())
    findings, counts = normalise(document)
    # cwe-map-4 also mapped python:S5332 at line 11 to LLM02.SID.HIGH. cwe-map-5 drops it.
    assert counts["results_by_cwe_decision"]["mapped"] == 1 and counts["results_by_cwe_decision"]["unmapped"] == 1
    built, stats = sarif.build(findings, tool_name="sonarqube", tool_version="8.1.0.6389")
    results = sorted((r["ruleId"], r["locations"][0]["physicalLocation"]["region"]["startLine"])
                     for r in built["runs"][0]["results"])
    assert results == [("LLM03.EA.PERMISSIONS", 29)]
    assert stats["unmapped_by_cwe"] == {"CWE-319": 1}
    for r in built["runs"][0]["results"]:
        assert "codeFlows" not in r
        assert r["properties"]["toolProperties"]["sonarType"] == "VULNERABILITY"
        assert not {"controlStatus", "residualRisk", "recommendations"} & set(r["properties"])


def test_smoke_sonar_f3_recording_has_measures_and_no_hotspot_rules():
    """Real run 2026-10-08 (harbor-jobs/sonarqube-smoke-040f): same results as f2.

    SonarQube 26.9 Community Build has no Security Hotspot rules for Python left
    (all were turned into vulnerability rules), so a hotspots-only result can't
    happen on this server. The recording says so from the server itself.
    """
    document = json.loads((FIXTURES / "sonarqube_26.9-f3_smoke_sonar.json").read_text())
    assert document["fetch_format"] == 2 and document["deleted"] is True
    assert document["error"] is None and document["rule_errors"] == {}
    assert document["hotspot_rules_total"] == 0 and document["hotspot_rules_active"] == 0
    assert document["hotspot_rules_error"] is None
    measures = {m["metric"]: m["value"] for m in document["measures"]["component"]["measures"]}
    assert measures == {"files": "3", "ncloc": "34", "ncloc_language_distribution": "py=34"}
    assert [h for page in document["hotspots_pages"] for h in page["hotspots"]] == []
    findings, counts = normalise(document)
    # cwe-map-4 also mapped python:S5332 at line 11 to LLM02.SID.HIGH. cwe-map-5 drops it.
    assert counts["results_by_cwe_decision"]["mapped"] == 1 and counts["results_by_cwe_decision"]["unmapped"] == 1
    built, stats = sarif.build(findings, tool_name="sonarqube", tool_version="8.1.0.6389")
    results = sorted((r["ruleId"], r["locations"][0]["physicalLocation"]["region"]["startLine"])
                     for r in built["runs"][0]["results"])
    assert results == [("LLM03.EA.PERMISSIONS", 29)]
    assert stats["unmapped_by_cwe"] == {"CWE-319": 1}
