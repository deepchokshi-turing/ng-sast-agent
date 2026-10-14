"""task_format/grade.py (grader v3): require_cwe, minimal-contrast negatives
(near-fix rule plus trap hits), task-level and category outcomes (matched-only
and loose), linked findings, Harbor-safe reward.json, robustness of the SARIF
reader, and the --check-truth schema check."""

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
        "negative_analyses": [], "scoring_weights": dict(WEIGHTS),
        "fix_changed_files": [TOOL],
    }


TRAP = {"id": "N2", "kind": "hard_negative_trap", "file": TOOL, "start_line": 300, "end_line": 310,
        "trap_rule_prefixes": ["LLM03"], "why_not_a_finding": "operator-only path"}
CONTRAST = {"id": "N1", "kind": "minimal_contrast", "contrast_of": "F1", "file": TOOL, "start_line": 20,
            "end_line": 24, "rationale": "path kept inside base"}


def negative():
    return {
        "schema_version": "gt-0.1", "variant_role": "negative", "risk_types_present": [],
        "matching": {"line_tolerance": 10, "path_line_tolerance": 10, "require_cwe": True},
        "findings": [], "negative_analyses": [dict(CONTRAST), dict(TRAP)], "scoring_weights": dict(WEIGHTS),
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

@pytest.mark.parametrize("doc, reward, fp, outside, bucket", [
    (sarif(), 1.0, 0, 0, None),
    (sarif(result("LLM03.EA.AUTONOMY", TOOL, 22, ["CWE-79"])), 0.0, 1, 0, "near_fix"),  # no CWE agreement needed
    # v3.2 (F-B1): a contrast-family claim anywhere in scope fails; without scanner_roots the scope is
    # fix_changed_files. These two passed before v3.2.
    (sarif(result("LLM02.SID.MEDIUM", TOOL, 200)), 0.0, 1, 0, "in_scope"),  # in a fix file, far from the fix
    (sarif(result("LLM03.EA.FUNCTIONALITY", APP, 5)), 1.0, 0, 1, None),  # elsewhere
    (sarif(result("OTHER.X", TOOL, 21)), 1.0, 0, 1, None),               # not a contrast prefix
    (sarif(result("LLM03.EA.AUTONOMY", TOOL, 305)), 0.0, 1, 0, "trap"),  # the negative's own trap
    (sarif(result("LLM03.EA.AUTONOMY", TOOL, 318)), 0.0, 1, 0, "trap"),  # within tolerance of the trap
    (sarif(result("LLM02.SID.HIGH", TOOL, 305)), 0.0, 1, 0, "in_scope"),  # trap is LLM03 only, SID in scope
    (sarif(result("LLM02.SID.HIGH", APP, 305)), 1.0, 0, 1, None),        # outside the scope
    (sarif(result("LLM03.EA.AUTONOMY", TOOL, 21), result("LLM03.EA.AUTONOMY", TOOL, 302)), 0.0, 2, 0,
     "near_fix+trap"),
])
def test_negative_fails_near_the_fix_or_on_a_trap(tmp_path, doc, reward, fp, outside, bucket):
    score, detail = run(doc, negative(), tmp_path)
    assert (score["reward"], score["fp"], score["fp_outside_scope"]) == (reward, fp, outside)
    assert detail["failure_bucket"] == bucket
    assert score["neg.fail.near_fix"] == int("near_fix" in (bucket or ""))
    assert score["neg.fail.trap"] == int("trap" in (bucket or ""))
    assert score["neg.fail.in_scope"] == int("in_scope" in (bucket or ""))
    assert score["trap_hits"] == len(detail["trap_hits"])


def test_trap_hit_detail_names_the_trap(tmp_path):
    score, detail = run(sarif(result("LLM03.EA.AUTONOMY", TOOL, 305)), negative(), tmp_path)
    assert [h["traps"] for h in detail["trap_hits"]] == [["N2"]]
    assert detail["results_near_fixed_code"] == []
    assert detail["task_level"]["risk_types"]["excessive_agency"] == "FP"
    # v3.2 (A6): the failing result counts against the category it claims (AUTONOMY), not the
    # contrast category that shares its prefix (FUNCTIONALITY, FP before v3.2).
    assert detail["task_level"]["categories"] == {"LLM02.SID": "TN", "LLM03.EA.AUTONOMY": "FP",
                                                  "LLM03.EA.FUNCTIONALITY": "TN"}


def test_minimal_contrast_entry_is_not_a_trap(tmp_path):
    t = negative()
    t["fixed_locations"] = [{"file": TOOL, "start_line": 500, "end_line": 500, "why": "moved"}]
    t["fix_changed_files"] = [APP]  # v3.2: keep TOOL out of scope so only the trap rule could fail it
    score, _ = run(sarif(result("LLM03.EA.AUTONOMY", TOOL, 21)), t, tmp_path)  # on N1 (minimal_contrast) only
    assert score["reward"] == 1.0 and score["fp_outside_scope"] == 1


def test_negative_fails_on_other_risk_family(tmp_path):
    # v3.3 (final audit D2): a negative is "neither", so an SID claim on an EA-only negative fails too.
    score, detail = run(sarif(result("LLM02.SID.HIGH", TOOL, 21)), ea_only_negative(), tmp_path)
    assert score["reward"] == 0.0 and score["fp_outside_scope"] == 0
    assert detail["failure_bucket"] == "in_scope"
    tl = detail["task_level"]
    assert tl["risk_types"]["sensitive_information_disclosure"] == "FP"
    assert (score["tl.pred.SID"], score["tl.pred_loose.SID"]) == (1, 1)
    assert tl["categories"] == {"LLM03.EA.FUNCTIONALITY": "TN", "LLM02.SID": "FP"}


def test_negative_other_family_complete_claim_is_not_a_failure(tmp_path):
    res = result("LLM02.SID.HIGH", TOOL, 21, controlStatus="complete")
    score, _ = run(sarif(res), ea_only_negative(), tmp_path)
    assert score["reward"] == 1.0


def test_negative_noise_in_fix_file_now_fails(tmp_path):
    # Before v3.2 this passed and counted only in the loose view (audit F-B1 / A7).
    score, detail = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 200)), negative(), tmp_path)
    assert score["reward"] == 0.0 and detail["failure_bucket"] == "in_scope"
    assert (score["tl.pred.EA"], score["tl.pred_loose.EA"]) == (1, 1)
    assert detail["task_level"]["categories"]["LLM03.EA.FUNCTIONALITY"] == "FP"


def test_positive_oracle_on_negative_truth_scores_zero(tmp_path):
    doc = sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 20, ["CWE-22"]), result("LLM02.SID.HIGH", TOOL, 24, ["CWE-200"]))
    score, detail = run(doc, negative(), tmp_path)
    assert score["reward"] == 0.0 and detail["failure_bucket"] == "near_fix"
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


def test_task_level_counts_only_matched_results(tmp_path):
    # A wrong-CWE SID result inside the fix file: no match, so no SID prediction.
    # The loose view (pre-audit rule) still counts it.
    doc = sarif(result("LLM02.SID.HIGH", TOOL, 60, ["CWE-79"]))
    score, detail = run(doc, positive(), tmp_path)
    tl = detail["task_level"]
    assert tl["risk_types"]["sensitive_information_disclosure"] == "FN"
    assert tl["risk_types_loose"]["sensitive_information_disclosure"] == "TP"
    assert (score["tl.pred.SID"], score["tl.pred_loose.SID"]) == (0, 1)
    assert tl["categories"]["LLM02.SID"] == "FN"


def test_matched_and_loose_agree_when_everything_matches(tmp_path):
    doc = sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 20, ["CWE-22"]))
    score, _ = run(doc, positive(), tmp_path)
    assert (score["tl.pred.EA"], score["tl.pred_loose.EA"], score["tl.pred.SID"], score["tl.pred_loose.SID"]) == (1, 1, 0, 0)


def test_v2_ground_truth_gets_task_level_too(tmp_path):
    from tests.conftest import SAMPLE_TASKS
    truth = json.loads((SAMPLE_TASKS / "task_7f3a91" / "tests" / "ground_truth.json").read_text())
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
        # v3.2 scores the step role too, so the oracle names it.
        r["codeFlows"] = [{"threadFlows": [{"locations": [{"location": r["locations"][0],
                                                           "properties": {"role": "sink"}}]}]}]
        return r
    score, _ = run(sarif(oracle("LLM03.EA.FUNCTIONALITY", 20, "CWE-22"), oracle("LLM02.SID.HIGH", 60, "CWE-201")),
                   positive(), tmp_path)
    assert score["reward"] == 1.0


def test_twin_and_missing_sarif_have_loose_flags(tmp_path):
    score, _ = run(None, negative(), tmp_path)
    assert (score["tl.pred_loose.SID"], score["neg.fail.near_fix"], score["neg.fail.trap"]) == (0, 0, 0)


# ---- robustness (audit G2) ---------------------------------------------------------------

def _grade_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("grade_v3_under_test", GRADER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("value, expected", [
    ("CWE-749", "CWE-749"), ("cwe-22", "CWE-22"), ("A01:2021 - CWE-749", "CWE-749"), ("22", "CWE-22"),
    (" 22 ", "CWE-22"), (22, "CWE-22"), ("A01:2021", None), ("OWASP 2021", None), ("", None), (None, None),
    (True, None), ("CWE-022", "CWE-22"),
])
def test_norm_cwe(value, expected):
    assert _grade_module().norm_cwe(value) == expected


def test_owasp_prefixed_cwe_matches(tmp_path):
    score, _ = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 21, "A01:2021 - CWE-22")), positive(), tmp_path)
    assert score["tp"] == 1
    score, _ = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 21, "A01:2021 - CWE-1")), positive(), tmp_path / "b")
    assert score["tp"] == 0


@pytest.mark.parametrize("truth, reward", [(positive(), 0.0), (negative(), 1.0)])
def test_null_results_are_empty(tmp_path, truth, reward):
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": None}]}
    score, detail = run(doc, truth, tmp_path)
    assert "grader_error" not in score and "error" not in detail
    assert score["reward"] == reward


def test_recommendations_as_string_is_one_item(tmp_path):
    def doc(recs):
        r = result("LLM03.EA.FUNCTIONALITY", TOOL, 20, ["CWE-22"], recommendations=recs)
        return sarif(r)
    as_str, _ = run(doc("REC-A"), positive(), tmp_path / "s")
    as_list, _ = run(doc(["REC-A"]), positive(), tmp_path / "l")
    assert as_str["recommendations"] == as_list["recommendations"] == 0.5  # 1.0 for F1, F2 missed
    junk, _ = run(doc({"x": 1}), positive(), tmp_path / "j")
    assert junk["recommendations"] == 0.0 and "grader_error" not in junk


# ---- ground-truth schema check (audit G2 and T8) ------------------------------------------

def check(truth: dict, tmp_path: Path) -> subprocess.CompletedProcess:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "truth.json").write_text(json.dumps(truth))
    return subprocess.run([sys.executable, str(GRADER), "--check-truth", "--truth", str(tmp_path / "truth.json")],
                          capture_output=True, text=True)


@pytest.mark.parametrize("truth", [positive(), positive(False), negative(), ea_only_negative()])
def test_check_truth_accepts_good_ground_truth(tmp_path, truth):
    proc = check(truth, tmp_path)
    assert proc.returncode == 0, proc.stdout
    assert _grade_module().check_truth(truth) == []


def _mutated(fn):
    t = positive()
    fn(t)
    return t


@pytest.mark.parametrize("truth, message", [
    (_mutated(lambda t: [t["findings"][0].pop(k) for k in ("primary_cwe", "acceptable_cwes")]),
     "require_cwe is true but primary_cwe and acceptable_cwes give no CWE"),
    (_mutated(lambda t: t["findings"][0].update(primary_cwe="A01:2021", acceptable_cwes=[])), "give no CWE"),
    (_mutated(lambda t: t["findings"][1].pop("path")), "F2: missing path"),
    (_mutated(lambda t: t["findings"][1].pop("risk_type")), "F2: missing risk_type"),
    (_mutated(lambda t: t["findings"][0]["primary_location"].update(start_line=30, end_line=25)), "end_line 25"),
    (_mutated(lambda t: t["findings"][0]["primary_location"].update(start_line=0)), "start_line must be"),
    (_mutated(lambda t: t["findings"][0]["path"][0].update(start_line="7")), "path[0]: start_line"),
    (_mutated(lambda t: t.pop("matching")), "missing matching"),
    (_mutated(lambda t: t["scoring_weights"].pop("path")), "scoring_weights.path"),
    (_mutated(lambda t: t["findings"][1].update(id="F1")), "duplicate finding id"),
])
def test_check_truth_reports_problems(tmp_path, truth, message):
    proc = check(truth, tmp_path)
    assert proc.returncode == 1 and message in proc.stdout, proc.stdout


def _overlapping(gap, same_cwe=True, same_risk=True):
    t = positive()
    f2 = t["findings"][1]
    if same_risk:
        f2.update(risk_type="excessive_agency", rule_id="LLM03.EA.FUNCTIONALITY",
                  acceptable_rule_ids=["LLM03.EA.FUNCTIONALITY"])
    f2["acceptable_cwes"] = ["CWE-22"] if same_cwe else ["CWE-200"]
    f2["primary_cwe"] = f2["acceptable_cwes"][0]
    f2["alternative_primary_locations"] = [{"file": TOOL, "start_line": 20 + gap, "end_line": 20 + gap, "why": "x"}]
    return t


@pytest.mark.parametrize("truth, overlap", [
    (_overlapping(8), True),            # the task_781350 case: 8 lines apart, tolerance 10
    (_overlapping(20), True),           # windows of +-10 still touch
    (_overlapping(21), False),
    (_overlapping(8, same_cwe=False), False),   # require_cwe keeps them apart
    (_overlapping(8, same_risk=False), False),  # different risk family never competes
])
def test_check_truth_flags_overlapping_accepted_locations(tmp_path, truth, overlap):
    proc = check(truth, tmp_path)
    assert ("overlapping accepted locations" in proc.stdout) is overlap, proc.stdout
    assert proc.returncode == int(overlap)


def test_check_truth_does_not_grade(tmp_path):
    proc = check(positive(), tmp_path)
    assert not (tmp_path / "out").exists() and "ok" in proc.stdout
