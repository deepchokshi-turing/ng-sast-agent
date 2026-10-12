"""Grader v3.1: complete controls on negatives (neg.controls), the gt-0.2 ground-truth
fields checked by --check-truth (snippet ids and hashes, affected_asset, egress,
consequence, violates, required path start, negative controls), tools/snippet_ids.py,
and the real harbor-tasks dataset (check_truth, snippet hashes, oracle 1.0)."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT
from tests.test_grader_v3 import TOOL, _grade_module, negative, result, run, sarif

GRADER = ROOT / "task_format" / "grade.py"
SNIPPETS = ROOT / "tools" / "snippet_ids.py"
HARBOR = ROOT.parent / "harbor-tasks"


# ---- complete controls on a negative -------------------------------------------------------

def neg_with_control(residual="low"):
    t = negative()
    t["controls"] = [{"name": "path_confinement", "status": "complete",
                      "at": {"file": TOOL, "start_line": 20, "end_line": 24}, "contrast_of": "F1", "note": "x"}]
    t["control_status"] = "complete"
    t["residual_risk"] = residual
    return t


def test_silent_negative_still_scores_one_and_reports_no_control_credit(tmp_path):
    score, detail = run(sarif(), neg_with_control(), tmp_path)
    assert score["reward"] == 1.0 and score["neg.controls"] == 0.0
    assert score["neg.complete_control_recognised"] == 0
    assert detail["complete_controls"][0]["recognised"] is False


@pytest.mark.parametrize("props, credit", [
    ({"controlStatus": "complete", "residualRisk": "low"}, 1.0),
    ({"controlStatus": "complete"}, 0.75),
    ({"controlStatus": "complete", "residualRisk": "high"}, 0.75),
])
def test_result_naming_the_complete_control_is_not_a_failure(tmp_path, props, credit):
    score, detail = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 22, **props)), neg_with_control(), tmp_path)
    assert score["reward"] == 1.0 and score["fp"] == 0 and score["neg.fail.near_fix"] == 0
    assert score["neg.controls"] == credit and score["neg.complete_control_recognised"] == 1
    assert detail["complete_control_recognised"][0]["controls"] == ["path_confinement"]
    assert detail["failure_bucket"] is None


@pytest.mark.parametrize("res", [
    result("LLM03.EA.FUNCTIONALITY", TOOL, 22),                                 # claims a weakness
    result("LLM03.EA.FUNCTIONALITY", TOOL, 22, controlStatus="partial"),        # not a complete control
])
def test_other_results_at_the_fix_still_fail_the_negative(tmp_path, res):
    score, detail = run(sarif(res), neg_with_control(), tmp_path)
    assert score["reward"] == 0.0 and score["neg.fail.near_fix"] == 1 and score["neg.controls"] == 0.0
    assert detail["failure_bucket"] == "near_fix"


def test_complete_control_far_from_the_control_is_not_recognised(tmp_path):
    score, detail = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 200, controlStatus="complete")),
                        neg_with_control(), tmp_path)
    # v3.2: a "complete" result is never a failure; it is a complete claim, not fp_outside_scope.
    assert score["neg.controls"] == 0.0 and score["reward"] == 1.0
    assert score["fp_outside_scope"] == 0 and [c["index"] for c in detail["complete_claims"]] == [0]


def test_complete_control_needs_a_contrast_prefix(tmp_path):
    t = neg_with_control()
    t["contrast_rule_ids"] = ["LLM02.SID.HIGH"]
    score, _ = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 22, controlStatus="complete")), t, tmp_path)
    assert score["neg.controls"] == 0.0 and score["reward"] == 1.0  # not a contrast prefix: outside scope


def test_one_failing_result_still_fails_with_a_recognised_control(tmp_path):
    doc = sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 22, controlStatus="complete", residualRisk="low"),
                result("LLM03.EA.AUTONOMY", TOOL, 21))
    score, _ = run(doc, neg_with_control(), tmp_path)
    assert score["reward"] == 0.0 and score["neg.controls"] == 1.0 and score["fp"] == 1


def test_negative_without_controls_has_no_control_keys(tmp_path):
    score, detail = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 22, controlStatus="complete")), negative(),
                        tmp_path)
    assert "neg.controls" not in score and "complete_controls" not in detail
    assert score["reward"] == 1.0  # v3.2: a "complete" result is never a failure (0.0 before v3.2)


def test_missing_sarif_reports_zero_control_credit(tmp_path):
    score, _ = run(None, neg_with_control(), tmp_path)
    assert score["neg.controls"] == 0.0 and score["sarif_missing"] == 1  # a missing SARIF scores 0 as before


def test_controls_mean_over_several_controls(tmp_path):
    t = neg_with_control()
    t["fixed_locations"].append({"file": TOOL, "start_line": 100, "end_line": 104, "why": "x"})
    t["controls"].append({"name": "other", "status": "complete",
                          "at": {"file": TOOL, "start_line": 100, "end_line": 104}, "note": "y"})
    score, _ = run(sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 102, controlStatus="complete", residualRisk="low")),
                   t, tmp_path)
    assert score["neg.controls"] == 0.5


# ---- gt-0.2 ground-truth checks --------------------------------------------------------------

CODE = "\n".join(f"line {n}" for n in range(1, 81)) + "\n"
MANIFEST = {
    "trust_boundaries": [{"id": "tb-model"}, {"id": "tb-workspace"}],
    "authorized_recipients": [{"channel": "chat_answer", "data_scope": "notes"}],
    "authorized_actions": [{"action": "read", "constraint": "inside the workspace"}],
    "fixtures": [{"fixture_id": "fx_secret", "asset_class": "secret", "canary_id": "CNRY-1"},
                 {"fixture_id": "fx_note", "asset_class": "notes", "canary_id": None}],
}


def make_repo(tmp_path: Path, crlf: bool = False) -> Path:
    repo = tmp_path / "environment" / "repo"
    (repo / Path(TOOL).parent).mkdir(parents=True)
    data = CODE.replace("\n", "\r\n") if crlf else CODE
    (repo / TOOL).write_bytes(data.encode())
    (repo / "security_manifest.json").write_text(json.dumps(MANIFEST))
    return repo


def loc(start, end, **extra):
    return {"file": TOOL, "start_line": start, "end_line": end, **extra}


def v2_positive():
    return {
        "schema_version": "gt-0.2", "task_id": "task_t", "variant_role": "positive",
        "risk_types_present": ["excessive_agency"],
        "matching": {"line_tolerance": 10, "path_line_tolerance": 10, "require_cwe": False},
        "scoring_weights": {"detection": 0.35, "classification": 0.05, "path": 0.3, "controls": 0.15,
                            "recommendations": 0.15},
        "negative_analyses": [],
        "findings": [{
            "id": "F1", "risk_type": "excessive_agency", "rule_id": "LLM03.EA.FUNCTIONALITY",
            "acceptable_rule_ids": ["LLM03.EA.FUNCTIONALITY"], "primary_cwe": "CWE-22",
            "primary_location": loc(20, 20),
            "alternative_primary_locations": [],
            "path": [
                {"step": 1, "role": "model_decision", "required": True, **loc(5, 6)},
                {"step": 2, "role": "sink", "required": True, **loc(20, 20),
                 "egress": {"kind": "internal", "boundary": "tb-workspace"}},
            ],
            "controls": [{"name": "path_confinement", "status": "absent", "expected_at": loc(20, 20)}],
            "control_status": "none", "residual_risk": "high",
            "recommendations": {"required_any_of": ["REC-A"]},
            "rationale": "The model picks the path. So a steered model reads the operator's secret.",
            "evidence": {"canary_id": "CNRY-1"},
            "affected_asset": {"fixture_ids": ["fx_secret"], "data_class": "secret", "canary_ids": ["CNRY-1"]},
            "consequence": "So a steered model reads the operator's secret.",
            "violates": [{"manifest_path": "authorized_actions[0].constraint", "summary": "reads outside"}],
        }],
    }


def v2_negative():
    return {
        "schema_version": "gt-0.2", "task_id": "task_t", "variant_role": "negative", "risk_types_present": [],
        "matching": {"line_tolerance": 10, "path_line_tolerance": 10, "require_cwe": False},
        "scoring_weights": {"detection": 0.35, "classification": 0.05, "path": 0.3, "controls": 0.15,
                            "recommendations": 0.15},
        "findings": [], "negative_analyses": [{"id": "N1", "kind": "minimal_contrast", **loc(20, 24)}],
        "contrast_rule_ids": ["LLM03.EA.FUNCTIONALITY"],
        "fixed_locations": [loc(20, 24, why="check")],
        "controls": [{"name": "path_confinement", "status": "complete", "at": loc(20, 24), "note": "x"}],
        "control_status": "complete", "residual_risk": "low",
    }


def stamped(truth: dict, repo: Path) -> dict:
    """``truth`` with every location stamped the way tools/snippet_ids.py does it."""
    mod = _load_snippets()
    problems = []
    out = mod.stamp(truth, truth["task_id"], repo, problems)
    assert problems == []
    return out


def _load_snippets():
    import importlib.util
    spec = importlib.util.spec_from_file_location("snippet_ids", SNIPPETS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("build", [v2_positive, v2_negative])
def test_good_gt02_truth_passes(tmp_path, build):
    repo = make_repo(tmp_path)
    assert _grade_module().check_truth(stamped(build(), repo), repo) == []


def test_snippet_hash_is_line_ending_independent(tmp_path):
    g = _grade_module()
    a = g.snippet_sha256(make_repo(tmp_path / "a"), TOOL, 5, 7)
    b = g.snippet_sha256(make_repo(tmp_path / "b", crlf=True), TOOL, 5, 7)
    assert a == b and g.snippet_text(make_repo(tmp_path / "c"), TOOL, 5, 6) == "line 5\nline 6"
    assert g.snippet_id("task_t", TOOL, 5, 7) == f"task_t:{TOOL}:5-7"


def test_snippet_outside_the_file_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        _grade_module().snippet_text(make_repo(tmp_path), TOOL, 79, 81)


def test_check_truth_flags_a_hash_that_no_longer_matches_the_code(tmp_path):
    repo = make_repo(tmp_path)
    truth = stamped(v2_positive(), repo)
    (repo / TOOL).write_text(CODE.replace("line 20\n", "line twenty\n"))
    problems = _grade_module().check_truth(truth, repo)
    assert any("primary_location: snippet_sha256 does not match" in p for p in problems), problems
    assert any("path[1]: snippet_sha256 does not match" in p for p in problems)


def test_check_truth_cli_finds_the_repo_next_to_the_truth(tmp_path):
    repo = make_repo(tmp_path)
    truth = stamped(v2_positive(), repo)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "ground_truth.json").write_text(json.dumps(truth))
    ok = subprocess.run([sys.executable, str(GRADER), "--check-truth", "--truth",
                         str(tmp_path / "tests" / "ground_truth.json")], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout
    (repo / TOOL).write_text(CODE.replace("line 5\n", "line five\n"))
    bad = subprocess.run([sys.executable, str(GRADER), "--check-truth", "--truth",
                          str(tmp_path / "tests" / "ground_truth.json")], capture_output=True, text=True)
    assert bad.returncode == 1 and "snippet_sha256 does not match" in bad.stdout


def _mut(fn, build=v2_positive):
    def make(repo):
        t = stamped(build(), repo)
        fn(t)
        return t
    return make


F = lambda t: t["findings"][0]  # noqa: E731


@pytest.mark.parametrize("make, message", [
    (_mut(lambda t: F(t)["primary_location"].pop("snippet_sha256")), "missing snippet_id or snippet_sha256"),
    (_mut(lambda t: F(t)["primary_location"].update(snippet_id="task_t:x:1-1")), "does not name"),
    (_mut(lambda t: F(t).pop("affected_asset")), "missing affected_asset"),
    (_mut(lambda t: F(t)["affected_asset"].update(fixture_ids=["fx_note"])), "miss ['fx_secret']"),
    (_mut(lambda t: F(t)["affected_asset"].update(fixture_ids=["fx_nope", "fx_secret"])), "'fx_nope' is not in"),
    (_mut(lambda t: F(t)["affected_asset"].update(data_class="notes")), "is not the asset_class"),
    (_mut(lambda t: F(t).update(affected_asset={"fixture_ids": []})), "must name a resource"),
    (_mut(lambda t: F(t)["path"][1].pop("egress")), "path[1] (sink): missing egress"),
    (_mut(lambda t: F(t)["path"][1]["egress"].update(kind="outbound")), "egress must be"),
    (_mut(lambda t: F(t)["path"][1]["egress"].update(boundary="tb-nope")), "not a manifest trust_boundaries id"),
    (_mut(lambda t: F(t).pop("consequence")), "missing consequence"),
    (_mut(lambda t: F(t).update(consequence="The model deletes the database.")), "not taken from the rationale"),
    (_mut(lambda t: F(t).pop("violates")), "missing violates"),
    (_mut(lambda t: F(t).update(violates=[{"manifest_path": "authorized_actions[3]", "summary": "x"}])),
     "is not in the manifest"),
    (_mut(lambda t: F(t).update(violates=[{"manifest_path": "authorized_actions[0]"}])), "needs manifest_path"),
    (_mut(lambda t: F(t)["path"][0].update(required=False)), "step 1) must be required"),
    (_mut(lambda t: F(t)["path"][0].update(role="pass_through")), "no source or model_decision step"),
    (_mut(lambda t: t.pop("controls"), v2_negative), "missing controls"),
    (_mut(lambda t: t["controls"][0].update(status="partial"), v2_negative), "must have status 'complete'"),
    (_mut(lambda t: t["controls"][0]["at"].update(end_line=23), v2_negative), "is not one of fixed_locations"),
    (_mut(lambda t: t.pop("residual_risk"), v2_negative), "missing residual_risk"),
])
def test_check_truth_reports_gt02_problems(tmp_path, make, message):
    repo = make_repo(tmp_path)
    problems = _grade_module().check_truth(make(repo), repo)
    assert any(message in p for p in problems), problems


def test_gt01_truth_does_not_need_the_new_fields(tmp_path):
    t = v2_positive()
    t["schema_version"] = "gt-0.1"
    for k in ("affected_asset", "consequence", "violates"):
        t["findings"][0].pop(k)
    t["findings"][0]["path"][1].pop("egress")
    t["findings"][0]["path"][0]["required"] = False
    assert _grade_module().check_truth(t) == []


def test_new_fields_do_not_change_a_positive_grade(tmp_path):
    repo = make_repo(tmp_path)
    plain = v2_positive()
    for k in ("affected_asset", "consequence", "violates"):
        plain["findings"][0].pop(k)
    doc = sarif(result("LLM03.EA.FUNCTIONALITY", TOOL, 20, ["CWE-22"]))
    a, _ = run(doc, stamped(v2_positive(), repo), tmp_path / "a")
    b, _ = run(doc, plain, tmp_path / "b")
    assert a == b


# ---- tools/snippet_ids.py --------------------------------------------------------------------

def test_snippet_ids_tool_is_idempotent_and_keeps_the_style(tmp_path):
    task = tmp_path / "harbor" / "task_t"
    repo = make_repo(task)
    (task / "tests").mkdir()
    gt = task / "tests" / "ground_truth.json"
    raw = json.dumps(v2_positive(), indent=1) + "\n"
    gt.write_bytes(raw.encode())
    check = [sys.executable, str(SNIPPETS), str(tmp_path / "harbor"), "--check"]
    assert subprocess.run(check, capture_output=True).returncode == 1
    subprocess.run([sys.executable, str(SNIPPETS), str(tmp_path / "harbor")], check=True, capture_output=True)
    once = gt.read_bytes()
    subprocess.run([sys.executable, str(SNIPPETS), str(tmp_path / "harbor")], check=True, capture_output=True)
    assert gt.read_bytes() == once and b"\r\n" not in once
    assert subprocess.run(check, capture_output=True).returncode == 0
    data = json.loads(once)
    assert once.decode() == json.dumps(data, indent=1) + "\n"
    pl = data["findings"][0]["primary_location"]
    assert list(pl) == ["file", "start_line", "end_line", "snippet_id", "snippet_sha256"]
    assert pl["snippet_id"] == f"task_t:{TOOL}:20-20"
    assert _grade_module().check_truth(data, repo) == []


# ---- the real dataset ------------------------------------------------------------------------

REAL = sorted(p for p in HARBOR.iterdir() if (p / "tests" / "ground_truth.json").is_file()) \
    if HARBOR.is_dir() else []
needs_dataset = pytest.mark.skipif(not REAL, reason="harbor-tasks is not checked out next to ng-sast-agent")


@needs_dataset
@pytest.mark.parametrize("task", REAL, ids=lambda p: p.name)
def test_real_task_ground_truth_passes_check_truth(task):
    truth = json.loads((task / "tests" / "ground_truth.json").read_text(encoding="utf-8"))
    assert truth["schema_version"] == "gt-0.2"
    assert truth["matching"]["require_cwe"] is False
    assert _grade_module().check_truth(truth, task / "environment" / "repo") == []


@needs_dataset
@pytest.mark.parametrize("task", REAL, ids=lambda p: p.name)
def test_real_task_grader_is_the_current_grader(task):
    assert (task / "tests" / "grade.py").read_bytes() == GRADER.read_bytes()


@needs_dataset
@pytest.mark.parametrize("task", REAL, ids=lambda p: p.name)
def test_real_task_oracle_scores_one(task, tmp_path):
    truth = json.loads((task / "tests" / "ground_truth.json").read_text(encoding="utf-8"))
    score, _ = run(json.loads((task / "solution" / "findings.sarif").read_text(encoding="utf-8")),
                   copy.deepcopy(truth), tmp_path)
    assert score["reward"] == 1.0
    if truth["variant_role"] == "negative":
        assert score["neg.controls"] == 1.0
    else:
        assert score["path"] == 1.0
