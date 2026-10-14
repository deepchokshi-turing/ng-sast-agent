"""task_format/grade.py: optimal one-to-one matching of results to findings
(audit 040, L3). The old grader gave each result, in file order, the first
unmatched finding near it, so a partial-credit result could take a finding
from an exact one."""

from __future__ import annotations

import importlib.util
import itertools
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT

GRADER = ROOT / "task_format" / "grade.py"
TASKS = ROOT / "tests" / "fixtures" / "tasks"
BASE = "src/langchain_mini/chains/api/base.py"


def _module():
    spec = importlib.util.spec_from_file_location("grade_matching_under_test", GRADER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gm = _module()


def greedy_assign(scores, n_results, n_findings, w, in_scope):
    """The pre-L3 matching: each result in order takes the first free finding it may match."""
    taken, pairs = set(), {}
    for i in range(n_results):
        for j in range(n_findings):
            if (i, j) in scores and j not in taken:
                pairs[i] = j
                taken.add(j)
                break
    return pairs


def grade_with(assign, sarif_path: Path, truth: dict):
    original = gm.assign
    gm.assign = assign
    try:
        return gm.grade(sarif_path, truth)
    finally:
        gm.assign = original


def all_matchings(scores, n_results):
    """Every one-to-one matching of the feasible pairs, as {result: finding}."""
    options = [[None] + sorted(j for (i, j) in scores if i == r) for r in range(n_results)]
    for choice in itertools.product(*options):
        used = [j for j in choice if j is not None]
        if len(used) == len(set(used)):
            yield {i: j for i, j in enumerate(choice) if j is not None}


def best_reward(sarif_path: Path, truth: dict) -> float:
    seen = {}

    def capture(scores, n_results, *_):
        seen["scores"], seen["n"] = scores, n_results
        return {}

    grade_with(capture, sarif_path, truth)
    if "scores" not in seen:  # negatives and twins do not match
        return gm.grade(sarif_path, truth)[0]["reward"]
    return max(grade_with(lambda *a, m=m: m, sarif_path, truth)[0]["reward"]
               for m in all_matchings(seen["scores"], seen["n"]))


def res(rule, file, line, cwe=None, **props):
    r = {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": file},
                                                              "region": {"startLine": line, "endLine": line}}}]}
    if cwe is not None:
        props["cwe"] = cwe
    if props:
        r["properties"] = props
    return r


def write_sarif(path: Path, results) -> Path:
    path.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": results}]}))
    return path


def truth_of(task: str) -> dict:
    return json.loads((TASKS / task / "tests" / "ground_truth.json").read_text())


def v3_tasks():
    old = set()
    for name in ("smoke_empty", "smoke_eval", "smoke_eval_node", "smoke_eval_twin", "task_7f3a91"):
        old.add(name)  # v1 and v2 graders kept on purpose
    return sorted(p.name for p in TASKS.iterdir() if (p / "tests" / "ground_truth.json").exists() and p.name not in old)


# ---- the audit's counter-example ------------------------------------------------------

L3_RESULTS = [
    res("LLM02.SID.MEDIUM", BASE, 89, ["CWE-200"]),  # partial credit for F2
    res("LLM02.SID.HIGH", BASE, 90, ["CWE-200"]),    # full credit for F2
]


@pytest.mark.parametrize("order", ["partial_first", "exact_first"])
def test_l3_exact_result_wins_the_finding(tmp_path, order):
    """task_3920a8_positive, F2 (LLM02.SID.HIGH at base.py:89-95, MEDIUM is partial credit).

    Greedy matched the MEDIUM result at :89 and left the HIGH one at :90 as a
    false positive: tp 1, fp 1, classification 0.3, reward 0.19. The optimal
    matching takes the HIGH result. One of the two results is still unmatched
    inside a fix file, so fp stays 1 (the audit's "fp 0" cannot happen with a
    one-to-one matching), and classification rises to 0.5 (1.0 on F2, F1 not
    found).
    """
    truth = truth_of("task_3920a8_positive")
    results = L3_RESULTS if order == "partial_first" else L3_RESULTS[::-1]
    sarif = write_sarif(tmp_path / "f.sarif", results)
    old, _ = grade_with(greedy_assign, sarif, truth)
    new, detail = gm.grade(sarif, truth)
    assert (new["tp"], new["fp"], new["fn"]) == (1, 1, 1)
    assert (new["classification"], new["reward"]) == (0.5, 0.2)
    f2 = next(p for p in detail["per_finding"] if p["finding"] == "F2")
    assert f2["ruleId"] == "LLM02.SID.HIGH"
    if order == "partial_first":
        assert (old["classification"], old["reward"]) == (0.3, 0.19)
    else:
        assert old == new


def test_l3_through_the_command_line(tmp_path):
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps(truth_of("task_3920a8_positive")))
    sarif = write_sarif(tmp_path / "f.sarif", L3_RESULTS)
    subprocess.run([sys.executable, str(GRADER), "--sarif", str(sarif), "--truth", str(truth),
                    "--out", str(tmp_path / "out")], check=True, capture_output=True)
    reward = json.loads((tmp_path / "out" / "reward.json").read_text())
    assert reward["reward"] == 0.2 and (tmp_path / "out" / "reward.txt").read_text() == "0.2\n"


def test_more_matches_beat_one_better_match():
    """A result that fits two findings goes to the one no other result can take."""
    w = {"detection": 0.35, "classification": 0.05, "path": 0.3, "controls": 0.15, "recommendations": 0.15}
    full = dict.fromkeys(gm.MEASUREMENTS, 1.0)
    low = dict.fromkeys(gm.MEASUREMENTS, 0.0)
    # result 0 fits F0 (full) and F1 (low), result 1 fits F0 only (low)
    scores = {(0, 0): full, (0, 1): low, (1, 0): low}
    assert greedy_assign(scores, 2, 2, w, 2) == {0: 0}
    # reward of {0: 0}: F1 = 2*1/(2+2) gives 0.175, measurements 0.65/2 = 0.325, total 0.5
    # reward of {0: 1, 1: 0}: detection 0.35, measurements 0, total 0.35
    assert gm.assign(scores, 2, 2, w, 2) == {0: 0}
    # with a heavier detection weight the second matching is better
    heavy = {"detection": 0.9, "classification": 0.025, "path": 0.025, "controls": 0.025, "recommendations": 0.025}
    assert gm.assign(scores, 2, 2, heavy, 2) == {0: 1, 1: 0}


# ---- greedy-optimal ground truths are graded exactly as before --------------------------

def _random_results(truth: dict, rng: random.Random, n: int) -> list:
    findings = truth["findings"]
    rules = sorted({r for f in findings for r in f["acceptable_rule_ids"] + f.get("partial_credit_rule_ids", [])}
                   | {"LLM02.SID.LOW", "LLM03.EA.AUTONOMY", "OTHER.X"})
    out = []
    for _ in range(n):
        f = rng.choice(findings)
        loc = rng.choice([f["primary_location"]] + f.get("alternative_primary_locations", []))
        cwes = sorted(gm.finding_cwes(f)) + ["CWE-79"]
        props = {"cwe": [rng.choice(cwes)],
                 "controlStatus": rng.choice([f["control_status"], "none", "partial"]),
                 "residualRisk": rng.choice([f["residual_risk"], "low"]),
                 "recommendations": rng.sample(f["recommendations"]["required_any_of"]
                                               + f["recommendations"].get("acceptable", []) + ["REC-ZZ"], 1)}
        r = res(rng.choice(rules), loc["file"], loc["start_line"] + rng.randint(-12, 12), **props)
        if rng.random() < 0.5:
            steps = [s for s in f["path"] if rng.random() < 0.7]
            r["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": s["file"]},
                                                   "region": {"startLine": s["start_line"]}}}} for s in steps]}]}]
        out.append(r)
    return out


@pytest.mark.parametrize("task", [t for t in v3_tasks() if truth_of(t)["findings"]])
def test_optimal_and_unchanged_where_greedy_was_optimal(tmp_path, task):
    """Only tasks with findings: negatives and twins match no results to findings."""
    truth = truth_of(task)
    rng = random.Random(task)
    changed = 0
    for k in range(40):
        sarif = write_sarif(tmp_path / f"{k}.sarif", _random_results(truth, rng, rng.randint(1, 5)))
        old = grade_with(greedy_assign, sarif, truth)
        new = gm.grade(sarif, truth)
        best = best_reward(sarif, truth)
        assert new[0]["reward"] == best
        assert new[0]["reward"] >= old[0]["reward"]
        if old[0]["reward"] == best:
            assert new == old  # same assignment, same reward.json and detail
        else:
            changed += 1
    assert changed < 40


@pytest.mark.parametrize("task", v3_tasks())
def test_oracle_style_sarif_is_unchanged(tmp_path, task):
    """One exact result per finding at its primary location, as the task oracles write them."""
    truth = truth_of(task)
    results = []
    for f in truth["findings"]:
        loc = f["primary_location"]
        results.append(res(f["acceptable_rule_ids"][0], loc["file"], loc["start_line"], sorted(gm.finding_cwes(f)),
                           controlStatus=f["control_status"], residualRisk=f["residual_risk"],
                           recommendations=f["recommendations"]["required_any_of"][:1]))
    sarif = write_sarif(tmp_path / "o.sarif", results)
    assert gm.grade(sarif, truth) == grade_with(greedy_assign, sarif, truth)


# ---- determinism ------------------------------------------------------------------------

def test_identical_results_go_to_the_first(tmp_path):
    truth = truth_of("task_3920a8_positive")
    same = res("LLM02.SID.HIGH", BASE, 90, ["CWE-200"])
    sarif = write_sarif(tmp_path / "f.sarif", [same, same, same])
    _, detail = gm.grade(sarif, truth)
    f2 = next(p for p in detail["per_finding"] if p["finding"] == "F2")
    assert f2["result_index"] == 0
    assert [u["index"] for u in detail["unmatched_results"]] == [1, 2]


def test_equal_findings_go_in_finding_order():
    w = {"detection": 0.35, "classification": 0.05, "path": 0.3, "controls": 0.15, "recommendations": 0.15}
    s = dict.fromkeys(gm.MEASUREMENTS, 0.5)
    scores = {(0, 0): s, (0, 1): s, (1, 0): s, (1, 1): s, (2, 1): s}
    assert gm.assign(scores, 3, 2, w, 3) == {0: 0, 1: 1}


def test_grading_is_repeatable(tmp_path):
    truth = truth_of("task_3920a8_positive")
    rng = random.Random(7)
    sarif = write_sarif(tmp_path / "f.sarif", _random_results(truth, rng, 6))
    outs = []
    for k in range(3):
        out = tmp_path / f"out{k}"
        (tmp_path / "t.json").write_text(json.dumps(truth))
        subprocess.run([sys.executable, str(GRADER), "--sarif", str(sarif), "--truth", str(tmp_path / "t.json"),
                        "--out", str(out)], check=True, capture_output=True)
        outs.append([(out / n).read_text() for n in ("reward.txt", "reward.json", "grading_detail.json")])
    assert outs[0] == outs[1] == outs[2]


# ---- the assignment solver -----------------------------------------------------------------

@pytest.mark.parametrize("seed", range(60))
def test_max_weight_matching_against_brute_force(seed):
    rng = random.Random(seed)
    rows, cols = rng.randint(1, 5), rng.randint(1, 5)
    weight = [[rng.choice([0, 0, rng.randint(1, 9), rng.randint(1, 10 ** 30)]) for _ in range(cols)]
              for _ in range(rows)]
    got = gm.max_weight_matching(weight)
    assert len(set(got.values())) == len(got)
    assert all(weight[r][c] > 0 for r, c in got.items())
    best = 0
    for perm in itertools.permutations(range(max(rows, cols)), rows):
        best = max(best, sum(weight[r][c] for r, c in enumerate(perm) if c < cols))
    assert sum(weight[r][c] for r, c in got.items()) == best


def test_shipped_task_copies_match_the_grader():
    """Every v3 fixture copy holds the current grader."""
    text = GRADER.read_bytes()
    for task in v3_tasks():
        assert (TASKS / task / "tests" / "grade.py").read_bytes() == text, task
