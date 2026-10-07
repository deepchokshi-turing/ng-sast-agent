"""The SARIF writer, and what the task's own grade.py makes of its output."""

import json

from sast import sarif
from sast.findings import Finding
from sast.semgrep.normalise import normalise
from tests.conftest import fixture_json


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
        "cwe": ["CWE-95"], "toolRuleIds": ["r1"], "controlStatus": "none", "residualRisk": "medium",
        "recommendations": ["REC-NARROW-TYPED-TOOLS"], "dataflowTrace": False, "boundarySink": None,
    }
    # No trace: one step, the match itself, as the sink.
    (step,) = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert step["properties"] == {"role": "sink"}
    assert step["location"]["physicalLocation"] == result["locations"][0]["physicalLocation"]
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


def test_empty_is_a_valid_sarif():
    doc, stats = sarif.build([], tool_name="semgrep", tool_version="x")
    assert doc["runs"][0]["results"] == [] and stats["results_emitted"] == 0


# ---- the real grader on the real Semgrep output ---------------------------------

def test_grader_scores_the_eval_hit(grade_sarif):
    doc, _ = semgrep_sarif("semgrep_1.179.0_smoke_eval.json")
    score = grade_sarif("smoke_eval", doc)
    assert (score["tp"], score["fp"], score["fn"]) == (1, 0, 0)
    assert score["fp_outside_scope"] == 1  # maintenance.py: not a file the fix changed
    # controlStatus "none", residualRisk "high" (impact HIGH) and REC-NARROW-TYPED-TOOLS all
    # score. The path is full only because this tiny task's steps (lines 8 and 12) sit
    # inside the 10-line tolerance of the one-step flow at the match: no trace was used.
    assert (score["controls"], score["recommendations"], score["path"]) == (1.0, 1.0, 1.0)
    assert score["reward"] == 1.0


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


# ---- codeFlows, CWE lists, heuristics, LLM02 severity ---------------------------

import re  # noqa: E402
from pathlib import Path  # noqa: E402

from sast import cwe_map, heuristics  # noqa: E402
from sast.findings import TraceStep  # noqa: E402

INSTRUCTION = Path(__file__).resolve().parents[1] / "dev/tasks/task_7f3a91/instruction.md"


def results_by_tool_rule(doc):
    return {r["properties"]["toolRuleIds"][0]: r for r in doc["runs"][0]["results"]}


def steps(result):
    return [(s["properties"]["role"],
             s["location"]["physicalLocation"]["artifactLocation"]["uri"],
             s["location"]["physicalLocation"]["region"]["startLine"])
            for s in result["codeFlows"][0]["threadFlows"][0]["locations"]]


def test_trace_becomes_source_then_sink_and_nothing_is_invented():
    doc, stats = semgrep_sarif("crafted_semgrep_dataflow_trace.json")
    by_rule = results_by_tool_rule(doc)
    email = by_rule["crafted.taint.tenant-data-to-email"]
    # Intermediate variables are propagation, not context assembly: left out.
    assert steps(email) == [("source", "src/support_copilot/store.py", 21),
                            ("sink", "src/support_copilot/retrieval.py", 11)]
    assert steps(by_rule["crafted.taint.pii-into-prompt"]) == [
        ("source", "src/support_copilot/users.py", 8), ("sink", "src/support_copilot/agent.py", 30)]
    assert steps(by_rule["crafted.pattern.eval"]) == [("sink", "src/support_copilot/tools.py", 40)]
    for r in doc["runs"][0]["results"]:
        roles = [role for role, _, _ in steps(r)]
        assert set(roles) <= {"source", "sink"} and roles[-1] == "sink"
    assert stats["results_with_trace_source"] == 2


def test_all_cwes_of_the_rule_are_listed():
    doc, _ = semgrep_sarif("crafted_semgrep_dataflow_trace.json")
    for r in doc["runs"][0]["results"]:
        assert all(re.fullmatch(r"CWE-[1-9]\d*", c) for c in r["properties"]["cwe"])
    assert results_by_tool_rule(doc)["crafted.taint.tenant-data-to-email"]["properties"]["cwe"] == [
        "CWE-862", "CWE-200"]


def test_llm02_severity_from_trace_sink_and_boundary_cwes():
    doc, _ = semgrep_sarif("crafted_semgrep_dataflow_trace.json")
    by_rule = results_by_tool_rule(doc)
    email = by_rule["crafted.taint.tenant-data-to-email"]
    assert email["ruleId"] == "LLM02.SID.HIGH"  # trace ends in smtp.send_message
    assert email["properties"]["boundarySink"] == "email"
    prompt = by_rule["crafted.taint.pii-into-prompt"]
    assert prompt["ruleId"] == "LLM02.SID.MEDIUM" and prompt["properties"]["boundarySink"] is None
    # No trace: a boundary CWE decides; otherwise MEDIUM.
    doc, _ = sarif.build([f(file="a.py", cwes=("CWE-200", "CWE-532")), f(file="b.py", cwes=("CWE-862",))],
                         tool_name="semgrep", tool_version="x")
    assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["LLM02.SID.HIGH", "LLM02.SID.MEDIUM"]


def test_a_boundary_sink_needs_a_trace():
    # Sink code is only ever read from a trace; a finding without one is judged by CWE.
    plain = f(cwes=("CWE-200",))
    assert sarif.boundary_sink(plain) is None
    traced = Finding("r", ("CWE-200",), "a.py", 5, 5, "m", "warning",
                     trace_source=TraceStep("a.py", 2, 2, "x"), trace_sink_code=("requests.post(url, data=x)",))
    assert sarif.boundary_sink(traced) == "network"


def test_high_and_medium_on_one_line_stay_one_result():
    traced = Finding("t", ("CWE-200",), "a.py", 5, 5, "m", "warning",
                     trace_source=TraceStep("a.py", 2, 2, "x"), trace_sink_code=("logger.info(x)",))
    plain = Finding("p", ("CWE-209",), "a.py", 5, 5, "m", "warning")
    doc, stats = sarif.build([plain, traced], tool_name="semgrep", tool_version="x")
    (result,) = doc["runs"][0]["results"]
    assert result["ruleId"] == "LLM02.SID.HIGH" and result["properties"]["boundarySink"] == "logging"
    assert steps(result) == [("source", "a.py", 2), ("sink", "a.py", 5)]
    assert sarif.emitted_rules([plain, traced]) == ["LLM02.SID.HIGH", "LLM02.SID.HIGH"]
    assert stats["results_emitted"] == 1


def test_controls_risk_and_recommendations():
    doc, _ = semgrep_sarif("crafted_semgrep_dataflow_trace.json")
    by_rule = results_by_tool_rule(doc)
    email = by_rule["crafted.taint.tenant-data-to-email"]["properties"]
    assert email["controlStatus"] == "none" and email["residualRisk"] == "medium"
    assert email["recommendations"] == ["REC-AUTHZ-BEFORE-RETRIEVAL", "REC-SENSITIVE-DATA-FILTER",
                                        "REC-SINK-SIDE-IFC"]
    prompt = by_rule["crafted.taint.pii-into-prompt"]["properties"]
    assert prompt["residualRisk"] == "low" and prompt["recommendations"] == ["REC-SENSITIVE-DATA-FILTER"]
    ev = by_rule["crafted.pattern.eval"]["properties"]
    assert ev["residualRisk"] == "high" and ev["recommendations"] == ["REC-NARROW-TYPED-TOOLS"]


def test_merged_result_takes_the_highest_residual_risk():
    doc, _ = sarif.build([Finding("a", ("CWE-95",), "a.py", 3, 3, "m", "note", residual_risk="low"),
                          Finding("b", ("CWE-94",), "a.py", 3, 3, "m", "error", residual_risk="high")],
                         tool_name="semgrep", tool_version="x")
    (result,) = doc["runs"][0]["results"]
    assert result["properties"]["residualRisk"] == "high"


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
    assert doc["runs"][0]["tool"]["driver"]["properties"] == {"cweMap": "cwe-map-3", "heuristics": "heuristics-1"}
    assert {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]} == {"LLM03.EA.FUNCTIONALITY"}


def test_grader_scores_a_traced_disclosure(grade_sarif):
    # Contract check on the reference task with the crafted trace: everything the
    # grader reads is present and well-formed. Not a claim about real Semgrep runs.
    doc, _ = semgrep_sarif("crafted_semgrep_dataflow_trace.json")
    doc["runs"][0]["results"] = [r for r in doc["runs"][0]["results"]
                                 if r["properties"]["toolRuleIds"] == ["crafted.taint.tenant-data-to-email"]]
    score = grade_sarif("task_7f3a91", doc)
    assert (score["tp"], score["fp"], score["fn"]) == (1, 0, 0)
    assert score["classification"] == 1.0          # LLM02.SID.HIGH and CWE-862 acceptable
    assert score["controls"] == 0.75               # controlStatus right, residualRisk medium vs high
    assert score["recommendations"] == 1.0         # all three are applicable
    assert 0.0 < score["path"] < 1.0               # root cause covered, model steps and tools.py sink not
