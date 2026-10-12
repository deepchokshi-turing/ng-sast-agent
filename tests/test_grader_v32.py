"""Grader v3.2, the scoring changes made in response to the external audit:

- negatives fail on any contrast-family claim in scope that is not "complete" (F-B1, A7),
- positives count unmatched results anywhere in the scanner roots as false positives (F-M1),
- a result may match a finding of the other risk family on CWE, with the linked-pair guard (A1),
- the path score has order, role and precision terms (A3),
- traps with ``trap_rule_ids`` fail only on those rule ids (F-M5),
- negative-side category outcomes name the emitted category (A6),
- ``norm_uri`` strips more prefixes (m9).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tests.conftest import ROOT
from tests.test_grader_v3 import APP, TOOL, WEIGHTS, _grade_module, negative, result, run, sarif

HARBOR = ROOT.parent / "harbor-tasks"
OTHER = "src/mini/other.py"            # in the scanner roots, not a fix file
TESTS = "tests/test_file_tool.py"      # excluded path
DOCS = "docs/notes.py"                 # outside the scanner roots
ROOTS = {"scanner_roots": ["src", "security_manifest.json"], "excluded_paths": ["tests", "src/mini/_vendor"]}
LINKED = "src/mini/link.py"

g = _grade_module()


def with_roots(truth: dict) -> dict:
    truth = copy.deepcopy(truth)
    truth["matching"].update(copy.deepcopy(ROOTS))
    return truth


def flow(*steps):
    """codeFlows from (file, line, role) steps; role None leaves it out."""
    locs = []
    for file, line, role in steps:
        loc = {"location": {"physicalLocation": {"artifactLocation": {"uri": file},
                                                 "region": {"startLine": line, "endLine": line}}}}
        if role is not None:
            loc["properties"] = {"role": role}
        locs.append(loc)
    return [{"threadFlows": [{"locations": locs}]}]


def path_finding(path, fid="F1", rule="LLM03.EA.FUNCTIONALITY", risk="excessive_agency", line=100, cwes=("CWE-22",)):
    return {
        "id": fid, "risk_type": risk, "rule_id": rule, "acceptable_rule_ids": [rule], "partial_credit_rule_ids": [],
        "primary_cwe": cwes[0], "acceptable_cwes": list(cwes),
        "primary_location": {"file": TOOL, "start_line": line, "end_line": line},
        "path": [{"step": i + 1, "role": role, "required": req, "file": TOOL, "start_line": ln, "end_line": ln}
                 for i, (ln, role, req) in enumerate(path)],
        "control_status": "none", "residual_risk": "high",
        "recommendations": {"required_any_of": ["REC-A"], "acceptable": []},
    }


def positive_with(findings, roots=True):
    t = {
        "schema_version": "gt-0.1", "variant_role": "positive",
        "risk_types_present": sorted({f["risk_type"] for f in findings}),
        "matching": {"line_tolerance": 10, "path_line_tolerance": 10, "require_cwe": False},
        "findings": findings, "negative_analyses": [], "scoring_weights": dict(WEIGHTS),
        "fix_changed_files": [TOOL],
    }
    return with_roots(t) if roots else t


def good(rule="LLM03.EA.FUNCTIONALITY", line=100, cwe=("CWE-22",), **extra):
    props = {"controlStatus": "none", "residualRisk": "high", "recommendations": ["REC-A"], **extra}
    return result(rule, TOOL, line, list(cwe), **props)


# ---- 1. negatives (F-B1, A7) ------------------------------------------------------------------

@pytest.mark.parametrize("res, reward, bucket, outside", [
    (result("LLM02.SID.HIGH", OTHER, 70), 0.0, "in_scope", 0),           # confident false alarm away from the fix
    (result("LLM03.EA.PERMISSIONS", OTHER, 5), 0.0, "in_scope", 0),      # any subtype of a contrast family
    (result("LLM02.SID.HIGH", OTHER, 70, controlStatus="partial"), 0.0, "in_scope", 0),
    (result("LLM02.SID.HIGH", "/app/repo/" + OTHER, 70), 0.0, "in_scope", 0),
    (result("LLM02.SID.HIGH", DOCS, 70), 1.0, None, 1),                  # outside the scanner roots
    (result("LLM02.SID.HIGH", TESTS, 70), 1.0, None, 1),                 # excluded path
    (result("LLM02.SID.HIGH", "src/mini/_vendor/x.py", 3), 1.0, None, 1),
    (result("OTHER.X", OTHER, 70), 1.0, None, 1),                        # not a contrast family
])
def test_negative_fails_on_a_contrast_claim_anywhere_in_scope(tmp_path, res, reward, bucket, outside):
    score, detail = run(sarif(res), with_roots(negative()), tmp_path)
    assert (score["reward"], detail["failure_bucket"], score["fp_outside_scope"]) == (reward, bucket, outside)
    assert score["neg.fail.in_scope"] == int(bucket == "in_scope")
    assert detail["scope"] == "scanner_roots" and detail["grader_version"] == "v3.2"


def test_auditor_probe_confident_false_alarm_away_from_the_fix(tmp_path):
    """B1_conf_fp: SID-H and EA-F results in scope, away from the fixed lines, scored 1.0 before v3.2."""
    doc = sarif(result("LLM02.SID.HIGH", OTHER, 70, ["CWE-200"], controlStatus="none", residualRisk="high"),
                result("LLM03.EA.FUNCTIONALITY", OTHER, 63, ["CWE-22"], controlStatus="none", residualRisk="high"))
    score, detail = run(doc, with_roots(negative()), tmp_path)
    assert score["reward"] == 0.0 and score["fp"] == 2 and score["fp_outside_scope"] == 0
    assert (score["tl.pred.SID"], score["tl.pred.EA"]) == (1, 1)
    assert detail["task_level"]["categories"] == {"LLM02.SID": "FP", "LLM03.EA.FUNCTIONALITY": "FP"}


@pytest.mark.parametrize("file, line", [(OTHER, 70), (TOOL, 21), (TOOL, 305)])
def test_complete_result_is_never_a_failure(tmp_path, file, line):
    """At the fix, elsewhere in scope, or on a trap: a "complete" result says a control closes the path."""
    score, detail = run(sarif(result("LLM03.EA.FUNCTIONALITY", file, line, controlStatus="complete")),
                        with_roots(negative()), tmp_path)
    assert score["reward"] == 1.0 and score["fp"] == 0 and detail["failure_bucket"] is None
    assert [c["index"] for c in detail["complete_claims"]] == [0]


def test_complete_control_credit_near_the_fix_is_kept(tmp_path):
    t = with_roots(negative())
    t["controls"] = [{"name": "confine", "status": "complete", "at": {"file": TOOL, "start_line": 20, "end_line": 24}}]
    t["residual_risk"] = "low"
    doc = sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 22, controlStatus="complete", residualRisk="low"),
                result("LLM02.SID.HIGH", OTHER, 70, controlStatus="complete"))
    score, detail = run(doc, t, tmp_path)
    assert score["reward"] == 1.0 and score["neg.controls"] == 1.0 and score["neg.complete_control_recognised"] == 1
    assert [c["index"] for c in detail["complete_claims"]] == [1]


def test_empty_sarif_is_clean_and_missing_sarif_is_zero_on_both_sides(tmp_path):
    neg = with_roots(negative())
    pos = positive_with([path_finding([(100, "sink", True)])])
    assert run(sarif(), neg, tmp_path / "a")[0]["reward"] == 1.0
    assert run(sarif(), pos, tmp_path / "b")[0]["reward"] == 0.0
    for name, truth in (("c", neg), ("d", pos)):
        score, detail = run(None, truth, tmp_path / name)
        assert score["reward"] == 0.0 and score["sarif_missing"] == 1
        assert detail["grader_version"] == "v3.2"
    assert run(None, neg, tmp_path / "e")[0]["neg.fail.in_scope"] == 0


def test_without_roots_the_negative_scope_is_the_fix_files(tmp_path):
    score, detail = run(sarif(result("LLM02.SID.HIGH", TOOL, 200)), negative(), tmp_path / "a")
    assert (score["reward"], detail["scope"]) == (0.0, "fix_changed_files")
    score, _ = run(sarif(result("LLM02.SID.HIGH", OTHER, 200)), negative(), tmp_path / "b")
    assert score["reward"] == 1.0 and score["fp_outside_scope"] == 1


def test_without_roots_or_fix_files_the_scope_is_the_repo(tmp_path):
    t = negative()
    t.pop("fix_changed_files")
    score, detail = run(sarif(result("LLM02.SID.HIGH", DOCS, 9)), t, tmp_path)
    assert (score["reward"], detail["scope"]) == (0.0, "repo")


# ---- 2. positives: false positives across the scanner roots (F-M1) ------------------------------

def test_unmatched_result_in_roots_is_a_false_positive(tmp_path):
    t = positive_with([path_finding([(100, "sink", True)])])
    doc = sarif(good(), result("LLM02.SID.HIGH", OTHER, 5), result("LLM02.SID.HIGH", DOCS, 5),
                result("LLM02.SID.HIGH", TESTS, 5))
    score, detail = run(doc, t, tmp_path)
    assert (score["tp"], score["fp"], score["fp_outside_scope"]) == (1, 1, 2)
    assert [u["location"][0] for u in detail["unmatched_results"]] == [OTHER]


def test_without_roots_false_positives_stay_in_the_fix_files(tmp_path):
    t = positive_with([path_finding([(100, "sink", True)])], roots=False)
    score, _ = run(sarif(good(), result("LLM02.SID.HIGH", OTHER, 5)), t, tmp_path)
    assert (score["fp"], score["fp_outside_scope"]) == (0, 1)


def test_auditor_probe_spray(tmp_path):
    """The correct result plus 30 junk results in the roots: precision, and so the reward, drops."""
    t = positive_with([path_finding([(100, "sink", True)])])
    alone, _ = run(sarif(good()), t, tmp_path / "a")
    junk = [result("LLM02.SID.HIGH", f"src/mini/registry_{k}.py", 10 + k) for k in range(30)]
    spray, _ = run(sarif(good(), *junk), t, tmp_path / "b")
    assert (spray["tp"], spray["fp"], spray["fp_outside_scope"]) == (1, 30, 0)
    assert spray["detection"] == round(2 * (1 / 31) / (1 + 1 / 31), 4)
    assert spray["reward"] < alone["reward"] - 0.3


def test_complete_claim_on_a_positive_is_neither_a_match_nor_a_false_positive(tmp_path):
    t = positive_with([path_finding([(100, "sink", True)])])
    score, detail = run(sarif(good(controlStatus="complete")), t, tmp_path)
    assert (score["tp"], score["fp"], score["fn"], score["reward"]) == (0, 0, 1, 0.0)
    assert [c["index"] for c in detail["complete_claims"]] == [0]


# ---- 3. no cross-family match (A1 reverted) ---------------------------------------------------
# A result matches only a finding of its own risk family, as an OWASP Benchmark result counts only
# in its own category. v3.2 briefly matched across families on a shared CWE; that was reverted on
# 2026-10-12 (client spec first, OWASP Benchmark where it is silent).

def authz_positive():
    """An AUTONOMY finding whose CWE (862) a CWE map may put in the SID family."""
    f = path_finding([(100, "sink", True)], rule="LLM03.EA.AUTONOMY", cwes=("CWE-862", "CWE-285"))
    return positive_with([f])


def test_other_family_result_does_not_match_even_with_a_shared_cwe(tmp_path):
    score, detail = run(sarif(good("LLM02.SID.HIGH", cwe=("CWE-862",))), authz_positive(), tmp_path)
    assert (score["tp"], score["fp"], score["fn"]) == (0, 1, 1)
    assert detail["per_finding"][0]["matched"] is False
    assert detail["task_level"]["risk_types"]["excessive_agency"] == "FN"


def test_own_family_result_matches(tmp_path):
    score, detail = run(sarif(good("LLM03.EA.AUTONOMY", cwe=("CWE-862",))), authz_positive(), tmp_path)
    assert (score["tp"], score["fp"], score["fn"]) == (1, 0, 0)
    assert detail["per_finding"][0]["cross_family"] is False


def linked_pair():
    """An ea_exposes_sid pair sharing CWE-918, 6 lines apart (like b7792387, e9c8c76e, ee27b8b8, f74b5b3a)."""
    ea = path_finding([(100, "sink", True)], cwes=("CWE-918", "CWE-20"))
    sid = path_finding([(106, "sink", True)], fid="F2", rule="LLM02.SID.HIGH",
                       risk="sensitive_information_disclosure", line=106, cwes=("CWE-200", "CWE-918"))
    sid["primary_location"]["file"] = sid["path"][0]["file"] = LINKED
    ea["alternative_primary_locations"] = [{"file": LINKED, "start_line": 100, "end_line": 100, "why": "sink"}]
    ea["linked_finding_ids"], ea["link_relation"] = ["F2"], "ea_exposes_sid"
    return positive_with([ea, sid])


def test_linked_pair_results_match_their_own_family(tmp_path):
    doc = sarif(result("LLM02.SID.HIGH", LINKED, 104, ["CWE-918"]))
    score, detail = run(doc, linked_pair(), tmp_path)
    matched = {p["finding"]: p for p in detail["per_finding"] if p["matched"]}
    assert list(matched) == ["F2"]
    assert g.check_truth(linked_pair()) == []


def test_sid_result_at_an_ea_only_location_is_not_taken_by_the_ea_finding(tmp_path):
    doc = sarif(result("LLM02.SID.HIGH", TOOL, 100, ["CWE-918"]))  # at F1 only, SID family, shared CWE
    score, detail = run(doc, linked_pair(), tmp_path)
    assert not any(p["matched"] for p in detail["per_finding"])


# ---- 4. path score (A3) -----------------------------------------------------------------------

PATH = [(10, "model_decision", True), (40, "root_cause", True), (70, "sink", True)]


def path_of(res_flow, path=PATH):
    r = good(line=70)
    r["codeFlows"] = res_flow
    score, steps = g.score_path(r, path_finding(path, line=70), 10)
    return score, steps


def test_correct_path_scores_one():
    assert path_of(flow((TOOL, 10, "model_decision"), (TOOL, 40, "root_cause"), (TOOL, 70, "sink")))[0] == 1.0


def test_source_and_model_decision_are_one_start_role_and_legacy_roles_map():
    assert path_of(flow((TOOL, 10, "source"), (TOOL, 40, "root_cause"), (TOOL, 70, "sink")))[0] == 1.0
    legacy = [(10, "source", True), (30, "tool_output", True), (50, "pass_through", True), (70, "action", True)]
    emitted = flow((TOOL, 10, "model_decision"), (TOOL, 30, "model_consumption"), (TOOL, 50, "context_assembly"),
                   (TOOL, 70, "sink"))
    assert path_of(emitted, legacy)[0] == 1.0


def test_reversed_all_sink_path_scores_well_below_one():
    score, steps = path_of(flow((TOOL, 70, "sink"), (TOOL, 40, "sink"), (TOOL, 10, "sink")))
    # coverage 1, order 1/3, role 1/3: 0.2 + 0.8 * 1/3 * 1/3
    assert score == pytest.approx(0.2 + 0.8 / 9) and score <= 0.6
    assert [s["role_ok"] for s in steps] == [False, False, True]


def test_order_and_role_terms_separately():
    reversed_roles_ok = path_of(flow((TOOL, 70, "sink"), (TOOL, 40, "root_cause"), (TOOL, 10, "model_decision")))[0]
    assert reversed_roles_ok == pytest.approx(0.2 + 0.8 / 3)
    no_roles = path_of(flow((TOOL, 10, None), (TOOL, 40, None), (TOOL, 70, None)))[0]
    assert no_roles == pytest.approx(0.2)
    ends_only = path_of(flow((TOOL, 10, "source"), (TOOL, 40, None), (TOOL, 70, "sink")))[0]
    assert ends_only == pytest.approx(0.2 + 0.8 * 2 / 3)


def test_clustered_steps_are_told_apart_by_role_only():
    """Two required steps within tolerance: order is 1 either way, so roles decide."""
    clustered = [(70, "model_decision", True), (75, "sink", True)]
    right = path_of(flow((TOOL, 70, "model_decision"), (TOOL, 75, "sink")), clustered)[0]
    wrong = path_of(flow((TOOL, 75, "sink"), (TOOL, 70, "sink")), clustered)[0]
    assert right == 1.0 and wrong == pytest.approx(0.6)


def test_precision_term_penalises_long_flows():
    steps = [(TOOL, 10, "model_decision"), (TOOL, 40, "root_cause"), (TOOL, 70, "sink")]
    filler = [(TOOL, 500 + 21 * k, "context_assembly") for k in range(7)]   # 10 steps, path 3 + slack 2
    assert path_of(flow(*steps, *filler))[0] == pytest.approx(5 / 10)
    assert path_of(flow(*steps, *filler[:2]))[0] == 1.0


def test_blanket_coverage_no_longer_scores_one():
    """A 20-step flow every 21 lines covers every step; precision and roles keep it low."""
    blanket = flow(*[(TOOL, 1 + 21 * k, "sink") for k in range(20)])
    assert path_of(blanket)[0] <= 0.2


def test_partial_coverage():
    score, _ = path_of(flow((TOOL, 10, "model_decision"), (TOOL, 70, "sink")))
    assert score == pytest.approx(2 / 3)


# ---- 5. traps with trap_rule_ids (F-M5) ------------------------------------------------------

def sid_negative_with_trap(**trap_rules):
    t = with_roots(negative())
    t["contrast_rule_ids"] = ["LLM02.SID.HIGH"]
    trap = next(n for n in t["negative_analyses"] if n["kind"] == "hard_negative_trap")
    trap.update(trap_rules)
    return t


@pytest.mark.parametrize("rule, reward", [
    ("LLM03.EA.AUTONOMY", 0.0),       # the wrong claim the trap is about
    ("LLM03.EA.PERMISSIONS", 1.0),    # a different weakness at the same place
    ("LLM03.EA.FUNCTIONALITY", 1.0),
])
def test_trap_rule_ids_fail_only_on_those_rules(tmp_path, rule, reward):
    t = sid_negative_with_trap(trap_rule_ids=["LLM03.EA.AUTONOMY"])
    score, detail = run(sarif(result(rule, TOOL, 305)), t, tmp_path)
    assert score["reward"] == reward and score["neg.fail.trap"] == int(reward == 0.0)
    assert g.check_truth(t) == []


def test_trap_without_rule_ids_keeps_the_prefix_rule(tmp_path):
    score, _ = run(sarif(result("LLM03.EA.PERMISSIONS", TOOL, 305)), sid_negative_with_trap(), tmp_path)
    assert score["reward"] == 0.0 and score["neg.fail.trap"] == 1


def test_trap_with_only_rule_ids_is_a_trap_and_passes_check_truth(tmp_path):
    t = sid_negative_with_trap(trap_rule_ids=["LLM03.EA.AUTONOMY"])
    trap = next(n for n in t["negative_analyses"] if n["kind"] == "hard_negative_trap")
    trap.pop("trap_rule_prefixes")
    assert g.check_truth(t) == []
    assert run(sarif(result("LLM03.EA.AUTONOMY", TOOL, 305)), t, tmp_path)[0]["reward"] == 0.0
    trap["trap_rule_ids"] = "LLM03.EA.AUTONOMY"
    assert any("trap_rule_ids must be a list" in p for p in g.check_truth(t))


def test_trap_rule_ids_on_a_positive(tmp_path):
    t = positive_with([path_finding([(100, "sink", True)])])
    t["negative_analyses"] = [{"id": "N2", "kind": "hard_negative_trap", "file": OTHER, "start_line": 50,
                               "end_line": 55, "trap_rule_prefixes": ["LLM03"],
                               "trap_rule_ids": ["LLM03.EA.AUTONOMY"]}]
    score, detail = run(sarif(result("LLM03.EA.AUTONOMY", OTHER, 52), result("LLM03.EA.PERMISSIONS", OTHER, 53)),
                        t, tmp_path)
    assert score["trap_hits"] == 1 and detail["trap_hits"] == [{"trap": "N2", "result_index": 0}]


# ---- 6. category attribution on negatives (A6) -------------------------------------------------

def test_failing_result_counts_against_its_own_category(tmp_path):
    """The f2a49e11 case: a PERMISSIONS result on an AUTONOMY contrast is a PERMISSIONS false positive."""
    t = with_roots(negative())
    t["contrast_rule_ids"] = ["LLM03.EA.AUTONOMY"]
    score, detail = run(sarif(result("LLM03.EA.PERMISSIONS", OTHER, 151)), t, tmp_path)
    assert score["reward"] == 0.0
    assert detail["task_level"]["categories"] == {"LLM03.EA.AUTONOMY": "TN", "LLM03.EA.PERMISSIONS": "FP"}
    assert (score["cat.LLM03.EA.AUTONOMY.truth"], score["cat.LLM03.EA.AUTONOMY.detected"]) == (0, 0)
    assert (score["cat.LLM03.EA.PERMISSIONS.truth"], score["cat.LLM03.EA.PERMISSIONS.detected"]) == (0, 1)


def test_unknown_subtype_falls_back_to_the_contrast_category(tmp_path):
    t = with_roots(negative())
    t["contrast_rule_ids"] = ["LLM03.EA.AUTONOMY"]
    score, detail = run(sarif(result("LLM03.EA.SOMETHING", OTHER, 151)), t, tmp_path)
    assert detail["task_level"]["categories"] == {"LLM03.EA.AUTONOMY": "FP"}


def test_severity_does_not_split_the_sid_category(tmp_path):
    score, detail = run(sarif(result("LLM02.SID.MEDIUM", OTHER, 9)), with_roots(negative()), tmp_path)
    assert detail["task_level"]["categories"]["LLM02.SID"] == "FP"


# ---- 7. norm_uri (m9) ---------------------------------------------------------------------------

@pytest.mark.parametrize("uri", [
    "src/a.py", "./src/a.py", "/src/a.py", "file:///app/repo/src/a.py", "file://app/repo/src/a.py",
    "/app/repo/src/a.py", "app/repo/src/a.py", "/home/runner/work/app/repo/src/a.py", "repo/src/a.py",
    "file:///repo/src/a.py", "FILE:///app/repo/./src/a.py", "src\\a.py",
])
def test_norm_uri(uri):
    assert g.norm_uri(uri) == "src/a.py"


def test_norm_uri_keeps_other_paths():
    assert g.norm_uri("src/repo/a.py") == "src/repo/a.py"
    assert g.norm_uri("") == "" and g.norm_uri(None) == ""


def test_absolute_uri_matches_through_the_grader(tmp_path):
    t = positive_with([path_finding([(100, "sink", True)])])
    r = good()
    r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "file:///workspace/app/repo/" + TOOL
    assert run(sarif(r), t, tmp_path)[0]["tp"] == 1


# ---- 8. version -----------------------------------------------------------------------------

def test_version_string():
    assert g.GRADER_VERSION == "v3.2"
    assert "v3.2" in (ROOT / "task_format" / "grade.py").read_text(encoding="utf-8").split('"""')[1]


# ---- the real dataset ----------------------------------------------------------------------------

REAL = sorted(p for p in HARBOR.iterdir() if (p / "tests" / "ground_truth.json").is_file()) \
    if HARBOR.is_dir() else []
needs_dataset = pytest.mark.skipif(not REAL, reason="harbor-tasks is not checked out next to ng-sast-agent")


def _truth(task: Path) -> dict:
    return json.loads((task / "tests" / "ground_truth.json").read_text(encoding="utf-8"))


def _oracle(task: Path) -> dict:
    return json.loads((task / "solution" / "findings.sarif").read_text(encoding="utf-8"))


POSITIVES = [p for p in REAL if _truth(p)["findings"]]


@needs_dataset
@pytest.mark.parametrize("task", POSITIVES, ids=lambda p: p.name)
def test_real_oracle_paths_score_one_and_reversed_all_sink_at_most_0_6(task, tmp_path):
    truth, doc = _truth(task), _oracle(task)
    (tmp_path / "o.sarif").write_text(json.dumps(doc))
    _, detail = g.grade(tmp_path / "o.sarif", truth)
    straight = [p["scores"]["path"] for p in detail["per_finding"] if p["matched"]]
    assert straight and all(s == 1.0 for s in straight), straight
    for res in doc["runs"][0]["results"]:
        for cf in res.get("codeFlows") or []:
            for tf in cf["threadFlows"]:
                tf["locations"] = tf["locations"][::-1]
                for loc in tf["locations"]:
                    loc["properties"] = {"role": "sink"}
    (tmp_path / "r.sarif").write_text(json.dumps(doc))
    _, detail = g.grade(tmp_path / "r.sarif", truth)
    reversed_ = [p["scores"]["path"] for p in detail["per_finding"] if p["matched"]]
    assert reversed_ and max(reversed_) <= 0.6, reversed_


@needs_dataset
@pytest.mark.parametrize("task", REAL, ids=lambda p: p.name)
def test_real_empty_sarif(task, tmp_path):
    truth = _truth(task)
    score, _ = run(sarif(), truth, tmp_path)
    assert score["reward"] == (1.0 if truth["variant_role"] == "negative" else 0.0)
    missing, _ = run(None, truth, tmp_path / "m")
    assert missing["reward"] == 0.0


def test_check_truth_accepts_and_validates_scope_fields():
    assert g.check_truth(with_roots(negative())) == []
    bad = with_roots(negative())
    bad["matching"]["scanner_roots"] = "src"
    assert any("matching.scanner_roots must be a list" in p for p in g.check_truth(bad))
