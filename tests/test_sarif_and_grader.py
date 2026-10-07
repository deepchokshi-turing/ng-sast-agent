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
    assert result["properties"] == {"cwe": ["CWE-95"], "toolRuleIds": ["r1"]}
    for absent in ("codeFlows",):
        assert absent not in result
    for absent in ("controlStatus", "residualRisk", "recommendations"):
        assert absent not in result["properties"]
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

def test_grader_scores_the_eval_hit_at_the_scanner_ceiling(grade_sarif):
    doc, _ = semgrep_sarif("semgrep_1.179.0_smoke_eval.json")
    score = grade_sarif("smoke_eval", doc)
    assert (score["tp"], score["fp"], score["fn"]) == (1, 0, 0)
    assert score["fp_outside_scope"] == 1  # maintenance.py: not a file the fix changed
    assert score["reward"] == 0.4  # detection 0.35 + classification 0.05; no path, controls, recommendations


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
