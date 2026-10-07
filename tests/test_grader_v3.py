"""task_format/grade.py (grader v3): require_cwe, minimal-contrast negatives,
task-level and category outcomes, linked findings, Harbor-safe reward.json."""

from __future__ import annotations

import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT

GRADER = ROOT / "task_format" / "grade.py"
TOOL = "src/mini/tools/file_tool.py"
APP = "src/mini/app.py"
WEIGHTS = {"detection": 0.35, "classification": 0.05, "path": 0.3, "controls": 0.15, "recommendations": 0.15}


def run(sarif: dict | None, truth: dict, tmp_path: Path) -> tuple[dict, dict]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "truth.json").write_text(json.dumps(truth))
    sarif_file = tmp_path / "findings.sarif"
    if sarif is not None:
        sarif_file.write_text(json.dumps(sarif))
    out = tmp_path / "out"
    subprocess.run([sys.executable, str(GRADER), "--sarif", str(sarif_file), "--truth", str(tmp_path / "truth.json"),
                    "--out", str(out)], check=True, capture_output=True)
    return json.loads((out / "reward.json").read_text()), json.loads((out / "grading_detail.json").read_text())


def result(rule, file, line, cwe=None, **props):
    res = {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": file},
                                                                "region": {"startLine": line, "endLine": line}}}]}
    if cwe is not None:
        props["cwe"] = cwe
    if props:
        res["properties"] = props
    return res


def sarif(*results):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": list(results)}]}


def finding(fid, rule, risk, line, cwes, primary, links=None):
    f = {
        "id": fid, "risk_type": risk, "rule_id": rule, "acceptable_rule_ids": [rule], "partial_credit_rule_ids": [],
        "primary_cwe": primary, "acceptable_cwes": cwes,
        "primary_location": {"file": TOOL, "start_line": line, "end_line": line},
        "alternative_primary_locations": [{"file": APP, "start_line": 40, "end_line": 40, "why": "sink: dispatch"}],
        "path": [{"step": 1, "role": "sink", "required": True, "file": TOOL, "start_line": line, "end_line": line}],
        "control_status": "none", "residual_risk": "high",
        "recommendations": {"required_any_of": ["REC-A"], "acceptable": ["REC-B"]},
    }
    if links:
        f.update(links)
    return f


def positive(require_cwe=True):
    return {
        "schema_version": "gt-0.1", "variant_role": "positive",
        "risk_types_present": ["excessive_agency", "sensitive_information_disclosure"],
        "matching": {"line_tolerance": 10, "path_line_tolerance": 10, "require_cwe": require_cwe},
        "findings": [
            finding("F1", "LLM03.EA.FUNCTIONALITY", "excessive_agency", 20, ["CWE-22", "CWE-23"], "CWE-22",
                    {"linked_finding_ids": ["F2"], "link_relation": "ea_exposes_sid"}),
            finding("F2", "LLM02.SID.HIGH", "sensitive_information_disclosure", 60, ["CWE-200"], "CWE-201"),
        ],
        "negative_analyses": [], "scoring_weights": WEIGHTS,
        "fix_changed_files": [TOOL],
    }


def negative():
    return {
        "schema_version": "gt-0.1", "variant_role": "negative", "risk_types_present": [],
        "matching": {"line_tolerance": 10, "path_line_tolerance": 10, "require_cwe": True},
        "findings": [], "negative_analyses": [], "scoring_weights": WEIGHTS,
        "contrast_rule_ids": ["LLM03.EA.FUNCTIONALITY", "LLM02.SID.HIGH"],
        "fixed_locations": [{"file": TOOL, "start_line": 20, "end_line": 24, "why": "path kept inside base"}],
        "fix_changed_files": [TOOL],
    }


def ea_only_negative():
    t = negative()
    t["contrast_rule_ids"] = ["LLM03.EA.FUNCTIONALITY"]
    return t


# ---- require_cwe --------------------------------------------------------------------

@pytest.mark.parametrize("cwe, tp", [
    (["CWE-22"], 1), ("CWE-23", 1), (["22"], 1), (["cwe-22"], 1), ([22], 1),
    (["CWE-79"], 0), (None, 0), ([], 0),
])
def test_require_cwe_gates_the_match(tmp_path, cwe, tp):
    score, _ = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 21, cwe)), positive(), tmp_path)
    assert (score["tp"], score["fp"]) == (tp, 1 - tp)  # a wrong-CWE result in a fix file is a false positive


def test_primary_cwe_counts_even_if_not_listed_as_acceptable(tmp_path):
    score, _ = run(sarif(result("LLM02.SID.HIGH", TOOL, 60, ["CWE-201"])), positive(), tmp_path)
    assert score["tp"] == 1


def test_require_cwe_applies_to_alternative_locations(tmp_path):
    ok, _ = run(sarif(result("LLM03.EA.FUNCTIONALITY", APP, 40, ["CWE-22"])), positive(), tmp_path / "a")
    bad, _ = run(sarif(result("LLM03.EA.FUNCTIONALITY", APP, 40, ["CWE-94"])), positive(), tmp_path / "b")
    assert (ok["tp"], bad["tp"]) == (1, 0)
    assert (bad["fp"], bad["fp_outside_scope"]) == (0, 1)  # app.py is not a fix file


def test_without_require_cwe_the_location_is_enough(tmp_path):
    score, _ = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 21, ["CWE-79"])), positive(False), tmp_path)
    assert score["tp"] == 1 and score["classification"] < 0.5


# ---- negatives ------------------------------------------------------------------------

@pytest.mark.parametrize("doc, reward, fp, outside", [
    (sarif(), 1.0, 0, 0),
    (sarif(result("LLM03.EA.AUTONOMY", TOOL, 22, ["CWE-79"])), 0.0, 1, 0),   # no CWE agreement needed
    (sarif(result("LLM02.SID.MEDIUM", TOOL, 200)), 0.0, 1, 0),               # inside a fix file, far away
    (sarif(result("LLM03.EA.FUNCTIONALITY", APP, 5)), 1.0, 0, 1),            # elsewhere
    (sarif(result("OTHER.X", TOOL, 21)), 1.0, 0, 1),                         # not a contrast prefix
])
def test_negative_fails_only_on_contrast_results_in_scope(tmp_path, doc, reward, fp, outside):
    score, _ = run(doc, negative(), tmp_path)
    assert (score["reward"], score["fp"], score["fp_outside_scope"]) == (reward, fp, outside)


def test_negative_ignores_other_risk_family(tmp_path):
    score, detail = run(sarif(result("LLM02.SID.HIGH", TOOL, 21)), ea_only_negative(), tmp_path)
    assert score["reward"] == 1.0 and score["fp_outside_scope"] == 1
    # but the task-level view still records that the tool claimed SID in scope
    assert detail["task_level"]["risk_types"]["sensitive_information_disclosure"] == "FP"
    assert detail["task_level"]["categories"] == {"LLM03.EA.FUNCTIONALITY": "TN"}


def test_positive_oracle_on_negative_truth_scores_zero(tmp_path):
    doc = sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 20, ["CWE-22"]), result("LLM02.SID.HIGH", TOOL, 60, ["CWE-200"]))
    score, detail = run(doc, negative(), tmp_path)
    assert score["reward"] == 0.0
    assert detail["task_level"]["categories"] == {"LLM02.SID": "FP", "LLM03.EA.FUNCTIONALITY": "FP"}


def test_negative_without_sarif_is_unscored(tmp_path):
    score, _ = run(None, negative(), tmp_path)
    assert score["reward"] == 0.0 and score["sarif_missing"] == 1


# ---- task-level outcomes ---------------------------------------------------------------

def test_task_level_both_risks_detected(tmp_path):
    doc = sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 20, ["CWE-22"]), result("LLM02.SID.MEDIUM", TOOL, 61, ["CWE-200"]))
    score, detail = run(doc, positive(), tmp_path)
    tl = detail["task_level"]
    assert tl["truth_risk_types"] == tl["predicted_risk_types"] == ["excessive_agency", "sensitive_information_disclosure"]
    assert tl["risk_types"] == {"sensitive_information_disclosure": "TP", "excessive_agency": "TP"}
    assert tl["categories"] == {"LLM02.SID": "TP", "LLM03.EA.FUNCTIONALITY": "TP"}
    assert score["cat.LLM02.SID.truth"] == score["cat.LLM02.SID.detected"] == 1
    assert (score["tl.truth.SID"], score["tl.pred.SID"], score["tl.truth.EA"], score["tl.pred.EA"]) == (1, 1, 1, 1)


def test_task_level_one_of_two_and_out_of_scope_ignored(tmp_path):
    doc = sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 20, ["CWE-22"]), result("LLM02.SID.HIGH", "src/mini/other.py", 3))
    score, detail = run(doc, positive(), tmp_path)
    tl = detail["task_level"]
    assert tl["predicted_risk_types"] == ["excessive_agency"]
    assert tl["risk_types"]["sensitive_information_disclosure"] == "FN"
    assert tl["categories"] == {"LLM02.SID": "FN", "LLM03.EA.FUNCTIONALITY": "TP"}
    assert (score["cat.LLM02.SID.truth"], score["cat.LLM02.SID.detected"]) == (1, 0)


def test_task_level_in_scope_false_positive_predicts_the_risk(tmp_path):
    # A wrong-CWE SID result inside the fix file: no match, but the tool did claim SID there.
    doc = sarif(result("LLM02.SID.HIGH", TOOL, 60, ["CWE-79"]))
    _, detail = run(doc, positive(), tmp_path)
    tl = detail["task_level"]
    assert tl["risk_types"]["sensitive_information_disclosure"] == "TP"
    assert tl["categories"]["LLM02.SID"] == "FN"


def test_v2_ground_truth_gets_task_level_too(tmp_path):
    from tests.conftest import DEV_TASKS
    truth = json.loads((DEV_TASKS / "task_7f3a91" / "tests" / "ground_truth.json").read_text())
    _, detail = run(sarif(), truth, tmp_path)
    assert detail["task_level"]["categories"] == {"LLM02.SID": "FN"}
    assert detail["task_level"]["risk_types"]["excessive_agency"] == "TN"


# ---- per-finding detail, measurements, Harbor contract --------------------------------------

def test_links_and_measurements_are_reported(tmp_path):
    doc = sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 20, ["CWE-22"], controlStatus="none", residualRisk="high",
                       recommendations=["REC-A"]))
    score, detail = run(doc, positive(), tmp_path)
    f1, f2 = detail["per_finding"]
    assert (f1["linked_finding_ids"], f1["link_relation"]) == (["F2"], "ea_exposes_sid")
    assert "linked_finding_ids" not in f2 and f2["matched"] is False
    assert detail["measurements"]["controls"] == score["controls"] == 0.5
    assert detail["measurements_on_detected"]["controls"] == 1.0
    assert detail["measurements_on_detected"]["path"] == 0.0


@pytest.mark.parametrize("truth", [positive(), negative(), ea_only_negative()])
def test_reward_json_is_flat_and_numeric_for_harbor(tmp_path, truth):
    score, _ = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 20, ["CWE-22"])), truth, tmp_path)
    for value in score.values():
        assert isinstance(value, (int, float)) and math.isfinite(value)
    assert (tmp_path / "out" / "reward.txt").read_text().strip() == str(score["reward"])


def test_oracle_style_sarif_scores_full_marks(tmp_path):
    def oracle(rule, line, cwe):
        r = result(rule, TOOL, line, [cwe], controlStatus="none", residualRisk="high", recommendations=["REC-A"])
        r["codeFlows"] = [{"threadFlows": [{"locations": [{"location": r["locations"][0]}]}]}]
        return r
    score, _ = run(sarif(oracle("LLM03.EA.FUNCTIONALITY", 20, "CWE-22"), oracle("LLM02.SID.HIGH", 60, "CWE-201")),
                   positive(), tmp_path)
    assert score["reward"] == 1.0
