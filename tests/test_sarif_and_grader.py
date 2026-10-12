"""The SARIF writer, and what the task's own grade.py makes of its output."""

import json

from sast import sarif
from sast.findings import Finding, TraceStep
from sast.semgrep.normalise import normalise
from tests.conftest import SAMPLE_TASKS, fixture_json


def f(file="src/calc_agent/agent.py", line=8, cwes=("CWE-95",), rule="r1", level="warning"):
    return Finding(rule, tuple(cwes), file, line, line, "msg", level)


def semgrep_sarif(fixture):
    findings, _ = normalise(fixture_json(fixture))
    return sarif.build(findings, tool_name="semgrep", tool_version="1.179.0")


def test_profile_shape():
    doc, stats = sarif.build([f()], tool_name="semgrep", tool_version="1.179.0")
    assert doc["version"] == "2.1.0"
    (result,) = doc["runs"][0]["results"]
    assert result["ruleId"] == "LLM03.EA.FUNCTIONALITY"
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 8, "endLine": 8}
    assert all(isinstance(v, int) for v in region.values())
    assert result["properties"] == {
        "cwe": ["CWE-95"], "toolRuleIds": ["r1"],
        "heuristics": {"controlStatus": "none", "residualRisk": "medium",
                       "recommendations": ["REC-NARROW-TYPED-TOOLS"], "version": "heuristics-1"},
    }
    # No trace from the tool, so no code flow, not even a one-step one.
    assert "codeFlows" not in result
    assert stats["results_emitted"] == 1
    json.dumps(doc)  # serialisable


def test_same_class_same_line_is_one_result():
    doc, stats = sarif.build(
        [f(rule="b", cwes=("CWE-94",), level="error"), f(rule="a", cwes=("CWE-95",))],
        tool_name="semgrep", tool_version="x",
    )
    (result,) = doc["runs"][0]["results"]
    assert result["level"] == "error"
    assert result["properties"]["toolRuleIds"] == ["a", "b"]
    assert result["properties"]["cwe"] == ["CWE-95", "CWE-94"]
    assert stats["findings_mapped"] == 2


def test_results_are_sorted_and_unmapped_are_counted():
    doc, stats = sarif.build(
        [f(file="b.py", line=1), f(file="a.py", line=9), f(file="a.py", line=2, cwes=("CWE-532",)),
         f(file="a.py", line=5, cwes=("CWE-1236",)), f(file="a.py", line=6, cwes=())],
        tool_name="semgrep", tool_version="x",
    )
    keys = [(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
             r["locations"][0]["physicalLocation"]["region"]["startLine"]) for r in doc["runs"][0]["results"]]
    assert keys == [("a.py", 2), ("a.py", 9), ("b.py", 1)]
    assert stats["unmapped_by_cwe"] == {"CWE-1236": 1, "none": 1}


def flow_steps(result):
    (flow,) = result["codeFlows"]
    (thread,) = flow["threadFlows"]
    return [(l["location"]["physicalLocation"]["artifactLocation"]["uri"],
             l["location"]["physicalLocation"]["region"]["startLine"],
             l["location"]["physicalLocation"]["region"]["endLine"],
             (l.get("properties") or {}).get("role")) for l in thread["locations"]]


def test_a_tool_trace_becomes_the_code_flow():
    trace = (TraceStep("src/a.py", 3, 3), TraceStep("src/b.py", 10, 12), TraceStep("src/a.py", 8, 8))
    finding = Finding("r1", ("CWE-95",), "src/a.py", 8, 8, "m", "error", trace=trace)
    doc, _ = sarif.build([finding], tool_name="codeql", tool_version="x")
    (result,) = doc["runs"][0]["results"]
    # Source first, sink last, no role in between: no tool says what the middle steps are.
    assert flow_steps(result) == [("src/a.py", 3, 3, "source"), ("src/b.py", 10, 12, None), ("src/a.py", 8, 8, "sink")]
    assert "properties" not in result["codeFlows"][0]["threadFlows"][0]["locations"][1]
    assert not {"controlStatus", "residualRisk", "recommendations"} & set(result["properties"])


def test_a_one_step_trace_is_a_sink_only():
    finding = Finding("r1", ("CWE-95",), "a.py", 8, 8, "m", "error", trace=(TraceStep("a.py", 8, 8),))
    doc, _ = sarif.build([finding], tool_name="codeql", tool_version="x")
    assert flow_steps(doc["runs"][0]["results"][0]) == [("a.py", 8, 8, "sink")]


def test_a_merged_result_takes_the_first_member_with_a_trace():
    traced = (TraceStep("a.py", 1, 1), TraceStep("a.py", 8, 8))
    doc, _ = sarif.build(
        [f(rule="a"), Finding("c", ("CWE-94",), "src/calc_agent/agent.py", 8, 8, "m", "warning", trace=traced)],
        tool_name="codeql", tool_version="x",
    )
    (result,) = doc["runs"][0]["results"]
    assert result["properties"]["toolRuleIds"] == ["a", "c"]
    assert flow_steps(result) == [("a.py", 1, 1, "source"), ("a.py", 8, 8, "sink")]


def test_findings_have_no_trace_by_default():
    assert f().trace == ()


def test_empty_is_a_valid_sarif():
    doc, stats = sarif.build([], tool_name="semgrep", tool_version="x")
    assert doc["runs"][0]["results"] == [] and stats["results_emitted"] == 0


# ---- the real grader on the real Semgrep output ---------------------------------

def test_grader_scores_the_eval_hit(grade_sarif):
    doc, _ = semgrep_sarif("semgrep_1.179.0_smoke_eval.json")
    score = grade_sarif("smoke_eval", doc)
    assert (score["tp"], score["fp"], score["fn"]) == (1, 0, 0)
    assert score["fp_outside_scope"] == 1  # maintenance.py: not a file the fix changed
    # Path, controls and recommendations score 0 by design: no trace, and the
    # heuristics sit under properties.heuristics, which the grader does not read.
    assert (score["controls"], score["recommendations"], score["path"]) == (0.0, 0.0, 0.0)
    assert score["classification"] == 1.0
    assert score["reward"] == 0.4  # detection and classification only, the scanner ceiling


def test_grader_twin_passes_with_findings_elsewhere(grade_sarif):
    doc, _ = semgrep_sarif("semgrep_1.179.0_smoke_eval_twin.json")
    score = grade_sarif("smoke_eval_twin", doc)
    assert (score["reward"], score["fp"], score["fp_outside_scope"]) == (1.0, 0, 1)


def test_grader_clean_repo_is_full_marks(grade_sarif):
    doc, _ = semgrep_sarif("semgrep_1.179.0_smoke_empty.json")
    assert grade_sarif("smoke_empty", doc)["reward"] == 1.0


def test_grader_reference_task_is_a_miss(grade_sarif):
    doc, stats = semgrep_sarif("semgrep_1.179.0_task_7f3a91.json")
    assert stats["unmapped_by_cwe"] == {"CWE-1236": 1}
    score = grade_sarif("task_7f3a91", doc)
    assert (score["tp"], score["fp"], score["fn"], score["reward"]) == (0, 0, 1, 0.0)


def test_grader_wrong_prefix_is_a_false_positive_and_a_miss(grade_sarif):
    doc, _ = sarif.build([f(cwes=("CWE-532",))], tool_name="semgrep", tool_version="x")
    score = grade_sarif("smoke_eval", doc)
    assert (score["tp"], score["fp"], score["fn"], score["reward"]) == (0, 1, 1, 0.0)


def test_grader_accepts_absolute_uris(grade_sarif):
    doc, _ = sarif.build([f(file="/app/repo/src/calc_agent/agent.py")], tool_name="semgrep", tool_version="x")
    assert grade_sarif("smoke_eval", doc)["tp"] == 1


def test_grader_extra_result_in_a_fixed_file_lowers_detection(grade_sarif):
    # Wrong class on a line of the file the fix changed: a false positive in scope.
    doc, _ = sarif.build([f(), f(line=12, cwes=("CWE-532",))], tool_name="semgrep", tool_version="x")
    score = grade_sarif("smoke_eval", doc)
    assert (score["tp"], score["fp"], score["fp_outside_scope"]) == (1, 1, 0)
    assert score["detection"] < 1.0


# ---- CWE lists, heuristics, LLM02 severity ------------------------------------

import re  # noqa: E402

from sast import cwe_map, heuristics  # noqa: E402

INSTRUCTION = SAMPLE_TASKS / "task_7f3a91" / "instruction.md"


def test_no_result_has_a_code_flow_or_scored_heuristic():
    for name in ("semgrep_1.179.0_smoke_eval.json", "semgrep_1.179.0_smoke_eval_twin.json",
                 "semgrep_1.179.0_task_7f3a91.json"):
        doc, _ = semgrep_sarif(name)
        for r in doc["runs"][0]["results"]:
            assert "codeFlows" not in r
            assert not {"controlStatus", "residualRisk", "recommendations"} & set(r["properties"])
            assert set(r["properties"]["heuristics"]) == {"controlStatus", "residualRisk", "recommendations", "version"}


def test_all_cwes_of_the_rules_are_listed():
    doc, _ = sarif.build([f(rule="a", cwes=("CWE-862", "CWE-200")), f(rule="b", cwes=("CWE-200", "CWE-359"))],
                         tool_name="semgrep", tool_version="x")
    (result,) = doc["runs"][0]["results"]
    assert result["properties"]["cwe"] == ["CWE-862", "CWE-200", "CWE-359"]
    assert all(re.fullmatch(r"CWE-[1-9]\d*", c) for c in result["properties"]["cwe"])


def test_llm02_severity_from_boundary_cwes():
    doc, _ = sarif.build([f(file="a.py", cwes=("CWE-200", "CWE-532")), f(file="b.py", cwes=("CWE-862",))],
                         tool_name="semgrep", tool_version="x")
    assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["LLM02.SID.HIGH", "LLM02.SID.MEDIUM"]


def test_high_and_medium_on_one_line_stay_one_result():
    high = Finding("h", ("CWE-532",), "a.py", 5, 5, "m", "warning")
    plain = Finding("p", ("CWE-209",), "a.py", 5, 5, "m", "warning")
    doc, stats = sarif.build([plain, high], tool_name="semgrep", tool_version="x")
    (result,) = doc["runs"][0]["results"]
    assert result["ruleId"] == "LLM02.SID.HIGH"
    assert sarif.emitted_rules([plain, high]) == ["LLM02.SID.HIGH", "LLM02.SID.HIGH"]
    assert stats["results_emitted"] == 1


def test_heuristic_risk_and_recommendations():
    doc, _ = sarif.build([Finding("t", ("CWE-862", "CWE-200"), "a.py", 5, 5, "m", "warning"),
                          Finding("e", ("CWE-95",), "b.py", 3, 3, "m", "error", residual_risk="high")],
                         tool_name="semgrep", tool_version="x")
    disclosure, ev = (r["properties"]["heuristics"] for r in doc["runs"][0]["results"])
    assert disclosure["controlStatus"] == "none" and disclosure["residualRisk"] == "medium"
    assert disclosure["recommendations"] == ["REC-AUTHZ-BEFORE-RETRIEVAL", "REC-SENSITIVE-DATA-FILTER"]
    assert ev["residualRisk"] == "high" and ev["recommendations"] == ["REC-NARROW-TYPED-TOOLS"]


def test_merged_result_takes_the_highest_residual_risk():
    doc, _ = sarif.build([Finding("a", ("CWE-95",), "a.py", 3, 3, "m", "note", residual_risk="low"),
                          Finding("b", ("CWE-94",), "a.py", 3, 3, "m", "error", residual_risk="high")],
                         tool_name="semgrep", tool_version="x")
    (result,) = doc["runs"][0]["results"]
    assert result["properties"]["heuristics"]["residualRisk"] == "high"


def test_recommendation_ids_are_the_instructions_catalogue():
    catalogue = re.findall(r"^\| `(REC-[A-Z-]+)` \|", INSTRUCTION.read_text(), re.MULTILINE)
    assert tuple(catalogue) == heuristics.CATALOGUE
    used = {r for recs in heuristics.RULE_RECOMMENDATIONS.values() for r in recs}
    used |= {r for recs in heuristics.CWE_RECOMMENDATIONS.values() for r in recs}
    assert used <= set(catalogue)
    # Every rule the agent can emit has a recommendation.
    emittable = {rule for rule, _ in cwe_map.CWE_MAP.values()} | {cwe_map.SID_MEDIUM}
    assert emittable <= set(heuristics.RULE_RECOMMENDATIONS)
    # CWE extras stay within their family.
    assert heuristics.recommendations("LLM03.EA.FUNCTIONALITY", ["CWE-95", "CWE-862"]) == ["REC-NARROW-TYPED-TOOLS"]


def test_driver_reports_the_versions():
    doc, _ = sarif.build([f()], tool_name="semgrep", tool_version="x")
    assert doc["runs"][0]["tool"]["driver"]["properties"] == {"cweMap": "cwe-map-5", "heuristics": "heuristics-1"}
    assert {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]} == {"LLM03.EA.FUNCTIONALITY"}


def test_grader_ignores_the_heuristics(grade_sarif):
    # The same detection scores the same whatever the heuristic tables say.
    doc, _ = semgrep_sarif("semgrep_1.179.0_smoke_eval.json")
    base = grade_sarif("smoke_eval", doc)
    for r in doc["runs"][0]["results"]:
        r["properties"]["heuristics"] = {"controlStatus": "partial", "residualRisk": "low", "recommendations": []}
    assert grade_sarif("smoke_eval", doc)["reward"] == base["reward"]


def test_tool_labels_go_to_tool_properties_and_merge():
    from sast.findings import Finding
    from sast import sarif as sarif_mod

    base = dict(cwes=("CWE-22",), file="src/a.py", start_line=10, end_line=10, message="m", level="warning")
    findings = [
        Finding(tool_rule_id="python:S1", extra=(("sonarType", "VULNERABILITY"),), **base),
        Finding(tool_rule_id="python:S2", extra=(("sonarType", "SECURITY_HOTSPOT"),), **base),
        Finding(tool_rule_id="other", cwes=("CWE-22",), file="src/b.py", start_line=3, end_line=3, message="m",
                level="warning"),
    ]
    document, _ = sarif_mod.build(findings, tool_name="t", tool_version="1")
    results = document["runs"][0]["results"]
    a = next(r for r in results if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/a.py")
    b = next(r for r in results if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/b.py")
    assert a["properties"]["toolProperties"] == {"sonarType": ["VULNERABILITY", "SECURITY_HOTSPOT"]}
    assert "toolProperties" not in b["properties"]
    for r in results:
        assert not {"controlStatus", "residualRisk", "recommendations"} & set(r["properties"])
