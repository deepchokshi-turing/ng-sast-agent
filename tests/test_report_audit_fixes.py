"""Report fixes after the external audit (B4 A2, A4, A5, A6, A15 and D F-B2, F-M11, m10): fixed-answer
baselines for measurements 3 and 4, the empty SARIF baseline, the strict view, category n and
cannot-emit exclusion with a suppressed mean, one result per finding in the location helper, fixed apps
with any warning and harness effects, the scoped-mode filter note, and family_id as the family key."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import eval_report  # noqa: E402
import report  # noqa: E402
from tests.test_eval_report import (  # noqa: E402
    GT_NEG, GT_POS, add, job_dir, make_tasks, neg_rewards, pos_rewards, result, run, write)
from tests.test_report_summary import BANNED  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tasks"


def truth(name: str) -> dict:
    return json.loads((FIXTURES / name / "tests" / "ground_truth.json").read_text(encoding="utf-8"))


def row(task: str, role: str, gt: dict | None = None, **extra) -> dict:
    rewards = {"reward": 1.0 if role == "negative" else 0.0, "tp": 0, "fp": 0, "fn": 0,
               "gt_findings": len((gt or {}).get("findings") or [])}
    rewards.update(extra.pop("rewards", {}))
    r = report.base_row(task, rewards, extra.pop("status", "ok"), truth=gt,
                        variants={task: {"family": "f", "role": role}})
    r.update({"_truth": gt, "tool_outcome": None, "matched_scores": None, "harness": {}})
    r.update(extra)
    return r


def no_jargon(text: str) -> None:
    for word in BANNED:
        assert not re.search(rf"\b{re.escape(word)}\b", text, re.I), (word, text)
    assert "—" not in text and ";" not in text, text


# ---- A4: fixed-answer baselines, computed with the grader's own functions -------------------------

def test_fixed_answer_baselines_use_the_graders_scoring():
    g = report.grader()
    assert g is not None
    gts = [truth("task_3920a8_positive"), truth("task_bd9abf_positive")]
    rows = [row("p1", "positive", gts[0]), row("p2", "positive", gts[1])]
    rec = report.common_recommendation(gts)
    assert rec == "REC-POLICY-GATE"  # in 3 of the 3 findings' required_any_of
    base = report.fixed_answer_baselines(rows)
    assert base["recommendation_id"] == rec

    # The expected values come straight from the grader: no formula is repeated here.
    def ctrl(f):
        res = {"ruleId": f["rule_id"], "locations": [], "properties": {"controlStatus": "none", "residualRisk": "high"}}
        return report._call(g.score_match, result=res, finding=f, ptol=10)["controls"]

    def recs(f):
        return g.score_recs({"properties": {"recommendations": [rec]}}, f)[0]
    per_task = [sum(fn(f) for f in t["findings"]) / len(t["findings"]) for t in gts for fn in (ctrl,)]
    assert base["controls"]["per_app"] == pytest.approx(sum(per_task) / 2)
    findings = [f for t in gts for f in t["findings"]]
    assert base["controls"]["per_finding"] == pytest.approx(sum(ctrl(f) for f in findings) / len(findings))
    assert base["recommendations"]["per_finding"] == pytest.approx(sum(recs(f) for f in findings) / len(findings))
    assert (base["controls"]["tasks"], base["controls"]["findings"]) == (2, 3)
    # A ground truth the grader cannot score has no baseline instead of an error.
    assert report.fixed_answer_baselines([row("x", "positive", GT_POS)])["controls"]["per_app"] is None


def test_matched_findings_only_next_to_the_mean_over_positives():
    rows = [row("p1", "positive", None, matched_scores=[{"path": 1.0, "controls": 0.75, "recommendations": 0.5}],
                rewards={"tp": 1, "controls": 0.375}),
            row("p2", "positive", None, matched_scores=[], rewards={"controls": 0.0})]
    m = report.matched_means(rows)
    assert m == {"findings": 1, "path": 1.0, "controls": 0.75, "recommendations": 0.5}


def tool_and_job(controls: float, base: float, status: str = "scored") -> tuple[dict, dict]:
    cell = {"status": status, "text": f"{eval_report.whole_percent(controls)}%", "value": controls}
    other = {"status": "not_provided", "text": eval_report.NOT_PROVIDED, "value": None}
    t = {"name": "Tool", "found": 1, "total": 2, "false_alarms": 0, "fixed_apps": 1, "fixed_flagged": 0,
         "path": other, "controls": cell, "recommendations": other, "wrong_type": 0}
    j = {"no_results": False, "summary": {"versions": {"fields": {}, "claude": None}, "harness_effects": {}},
         "measures": {"fixed_answer": {"controls": {"per_app": base}}}}
    return t, j


def test_summary_says_when_a_score_is_within_5_points_of_the_fixed_answer():
    t, j = tool_and_job(0.72, 0.70)
    text = " ".join(eval_report.tool_meaning(t, j))
    assert "Its 72% on judging existing protections is within 5 points of the 70% that a fixed answer gets" in text
    no_jargon(text)
    t, j = tool_and_job(0.77, 0.70)
    assert "within 5 points" not in " ".join(eval_report.tool_meaning(t, j))


def test_fixed_answer_caveat_in_read_this_first_is_plain():
    tools = [{"controls": {"status": "scored"}, "recommendations": {"status": "scored"}}]
    data = {"fixed_answer_baselines": {"controls": {"per_app": 0.702}, "recommendations": {"per_app": 0.855}}}
    text = eval_report.fixed_answer_caveat(data, tools)
    assert "would score 70% on judging existing protections" in text and "would score 86% on suggesting fixes" in text
    no_jargon(text)
    assert eval_report.fixed_answer_caveat(data, [{"controls": {"status": "not_provided"},
                                                   "recommendations": {"status": "not_provided"}}]) is None


# ---- empty SARIF baseline: computed, not assumed -------------------------------------------------

def test_empty_sarif_baseline_is_graded_by_the_current_grader(tmp_path):
    g = report.grader()
    pos, neg = truth("task_3920a8_positive"), truth("task_3920a8_negative")
    rows = [row("p", "positive", pos), row("p", "positive", pos), row("n", "negative", neg)]
    base = report.empty_sarif_baseline(rows)
    sarif = tmp_path / "s.sarif"
    sarif.write_text(json.dumps(report.EMPTY_SARIF))
    want = {"positive": g.grade(sarif, pos)[0]["reward"], "negative": g.grade(sarif, neg)[0]["reward"]}
    assert base["positive"] == {"tasks": 1, "mean_reward": want["positive"]}  # each task once
    assert base["negative"] == {"tasks": 1, "mean_reward": want["negative"]}
    assert base["all"]["mean_reward"] == pytest.approx((want["positive"] + want["negative"]) / 2)
    line = eval_report.empty_report_line({"empty_sarif_baseline": base})
    assert f"{eval_report.whole_percent(want['negative'])} on the fixed apps" in line
    no_jargon(line)


# ---- A5: strict view ---------------------------------------------------------------------------

def strict_rows():
    return [
        row("p1", "positive", None, rewards={"reward": 0.5, "tp": 1, "fn": 1, "gt_findings": 2}),
        row("p2", "positive", None, status="errored", rewards={"reward": None, "gt_findings": 2}),
        row("n1", "negative", None),
        row("n2", "negative", None, rewards={"sarif_missing": 1, "reward": 0.0}),
        row("n3", "negative", None, tool_outcome="review_incomplete"),
        row("n4", "negative", None, status="graded_as_old_role"),
    ]


def test_strict_view_counts_unfinished_trials_as_misses_and_failures():
    rows = strict_rows()
    s = report.strict_view(rows)
    assert s["differs"]
    assert (s["positive"]["tp"], s["positive"]["gt"], s["positive"]["recall"]) == (1, 4, 0.25)
    assert s["positive"]["mean_reward"] == pytest.approx(0.25) and s["positive"]["unfinished"] == 1
    assert (s["negative"]["tasks"], s["negative"]["failed"], s["negative"]["unfinished"]) == (3, 2, 2)
    assert s["negative"]["mean_reward"] == pytest.approx(1 / 3)
    assert s["negative"]["reasons"] == {"sarif_missing": 1, "tool_outcome review_incomplete": 1}
    # The scored-only view is unchanged: one positive, two negatives.
    assert report.reward_by_role(rows)["negative"]["tasks"] == 2
    assert not report.strict_view(rows[:1] + rows[2:3])["differs"]


def test_strict_view_has_a_plain_summary_line(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG,
                                  "task_fam2_positive": GT_POS, "task_fam2_negative": GT_NEG})
    job = job_dir(tmp_path, "semgrep")
    add(job, "task_fam1_positive", "semgrep", pos_rewards(hit=True), {"per_finding": []}, [], {"results_emitted": 1})
    add(job, "task_fam1_negative", "semgrep", neg_rewards(), {"negative": True}, [], {"results_emitted": 0})
    add(job, "task_fam2_positive", "semgrep", None, exception={"exception_message": "timed out"})
    add(job, "task_fam2_negative", "semgrep", neg_rewards(), {"negative": True}, [],
        {"results_emitted": 0, "tool_outcome": "deadline"})
    md, payload, _ = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    notes = payload["summary"]["notes"]
    line = next(n for n in notes if "Counting them as misses" in n)
    assert line == ("Semgrep: 2 of its runs did not finish or gave no answer, and the numbers above leave them out. "
                    "Counting them as misses, it found 1 of 4 known issues (not 1 of 2) and wrongly flagged 1 of 2 "
                    "fixed apps (not 0 of 2).")
    no_jargon(line)
    board = {r[0]: r[1:] for r in payload["scoreboard"]["rows"]}
    assert board[eval_report.STRICT_ROWS[0]] == ["0.250 (1/4)"]
    assert board[eval_report.STRICT_ROWS[2]] == ["1/2"]
    assert "Recall, strict" in md


# ---- A6: categories ----------------------------------------------------------------------------

def cat_rows(tool: str, n: int, mode: str | None = None) -> list[dict]:
    out = []
    for i in range(n):
        for role, truth_flag in (("positive", 1), ("negative", 0)):
            flags = {"LLM02.SID": {"truth": truth_flag, "detected": truth_flag},
                     "LLM03.EA.AUTONOMY": {"truth": truth_flag, "detected": 0}}
            r = row(f"{role}{i}", role, None, tool=tool, categories=flags,
                    run_info={"claude": {"mode": mode}} if mode else {})
            out.append(r)
    return out


def test_cwe_map_tools_cannot_emit_autonomy_and_small_means_are_suppressed():
    assert "LLM03.EA.AUTONOMY" not in report.cwe_map_rules()
    small = report.category_table(cat_rows("semgrep", 2))
    o = small["overall"]
    assert small["per_category"]["LLM03.EA.AUTONOMY"]["cannot_emit"]
    assert o["excluded_cannot_emit"] == ["LLM03.EA.AUTONOMY"] and o["categories"] == 1
    assert o["suppressed"] and o["too_few_tasks"] == ["LLM02.SID"]
    assert report.macro_text(o, "score") == "too few tasks"
    big = report.category_table(cat_rows("semgrep", 5))["overall"]
    assert not big["suppressed"] and big["score"] == pytest.approx(1.0)  # AUTONOMY's 0 is not averaged in
    assert report.macro_text(big, "score") == "1.000"
    # A stock Claude review takes its rule from the CWE map too, a scoped one names the rule itself.
    assert report.cannot_emit_categories(cat_rows("claude-code-security-review", 1, "stock")) == ["LLM03.EA.AUTONOMY"]
    assert report.cannot_emit_categories(cat_rows("claude-code-security-review", 1, "scoped")) == []
    scoped = report.category_table(cat_rows("claude-code-security-review", 5, "scoped"))["overall"]
    assert scoped["categories"] == 2 and scoped["score"] == pytest.approx(0.5)


def test_category_rows_print_n_and_the_cannot_emit_mark(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG})
    job = job_dir(tmp_path, "semgrep")
    pos = pos_rewards(**{"cat.LLM03.EA.AUTONOMY.truth": 1, "cat.LLM03.EA.AUTONOMY.detected": 0})
    neg = neg_rewards(**{"cat.LLM03.EA.AUTONOMY.truth": 0, "cat.LLM03.EA.AUTONOMY.detected": 0})
    add(job, "task_fam1_positive", "semgrep", pos, {"per_finding": []}, [], {"results_emitted": 0})
    add(job, "task_fam1_negative", "semgrep", neg, {"negative": True}, [], {"results_emitted": 0})
    md, payload, html = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    rows = {r[0]: r[1:] for r in eval_report.category_rows(
        [{**t, "rows": t["trials"]} for t in payload["tools"]])}
    assert rows["LLM02.SID"][0].startswith("n 1 positive, 1 negative: ")
    assert rows["LLM03.EA.AUTONOMY"][0].endswith(eval_report.CANNOT_EMIT)
    assert rows["Mean score over the categories it can emit"] == ["too few tasks"]
    board = {r[0]: r[1:] for r in payload["scoreboard"]["rows"]}
    assert board["OWASP score (mean TPR minus mean FPR)"] == ["too few tasks"]
    assert any("left out of the tool's OWASP mean" in o["text"] for o in payload["observations"])
    assert "cannot emit, left out of its mean" in html and "Left out: cannot emit" in html


# ---- A15: one result counts once -----------------------------------------------------------------

def test_location_helper_counts_each_result_once():
    gt = {"matching": {"line_tolerance": 10}, "findings": [
        {"primary_location": {"file": "base.py", "start_line": 84}, "acceptable_cwes": ["CWE-918"]},
        {"primary_location": {"file": "base.py", "start_line": 89}, "acceptable_cwes": ["CWE-918"]}]}
    one = [["r", ["CWE-918"], "base.py", 84, 84, "LLM03.EA.FUNCTIONALITY"]]
    assert report.ground_truth_hits(one, gt) == (2, 1, 1)
    two = one + [["r", ["CWE-918"], "base.py", 90, 90, "LLM02.SID.HIGH"]]
    assert report.ground_truth_hits(two, gt) == (2, 2, 2)
    # The matching finds the pairing that covers most findings, whatever the result order.
    wide = [["r", [], "base.py", 86, 86, ""], ["r", [], "base.py", 82, 82, ""]]
    gt2 = {"matching": {"line_tolerance": 3}, "findings": [
        {"primary_location": {"file": "base.py", "start_line": 84}},
        {"primary_location": {"file": "base.py", "start_line": 89}}]}
    assert report.ground_truth_hits(wide, gt2)[1] == 2


# ---- F-M11: any warning on fixed apps, harness and filter effects ---------------------------------

def test_harness_effects_from_run_properties_and_metadata(tmp_path):
    write(tmp_path / "agent" / "findings.sarif", {"version": "2.1.0", "runs": [{"results": [], "properties": {
        "findings_excluded": 2, "unmapped_by_category": {"a": 1, "b": 2}, "findings_remapped": [{"x": 1}],
        "dropped_new_kind": 4, "unrelated": 9}}]})
    effects = report.harness_effects({"claude_review": {"findings_excluded": 7}}, tmp_path)
    assert effects == {"excluded by the false-alarm filter": 2, "dropped, category not in the category map": 3,
                       "re-mapped to another rule or risk type": 1, "dropped_new_kind": 4}
    # Without SARIF run properties the agent metadata is read.
    meta = {"claude_review": {"findings_excluded": 1}, "unmapped_by_category": {}, "dropped_out_of_scope_count": 2}
    assert report.harness_effects(meta, tmp_path / "none") == {
        "excluded by the false-alarm filter": 1, "dropped, category not in the category map": 0,
        "dropped, outside the scanned files": 2}
    assert report.harness_effects({}, None) == {}


def test_fixed_apps_with_any_warning_and_harness_rows(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG})
    job = job_dir(tmp_path, "claude")
    meta = {"model": "claude-opus-5-5", "mode": "scoped", "auth": "api_key", "category_map": "m1",
            "claude_review": {"mode": "scoped", "filter_mode": "claude", "findings_excluded": 3}}
    add(job, "task_fam1_positive", "claude-code-security-review", pos_rewards(), {"per_finding": []}, [],
        {**meta, "results_emitted": 0})
    add(job, "task_fam1_negative", "claude-code-security-review", neg_rewards(fp_outside_scope=1),
        {"negative": True, "outside_scope_results": [{"index": 0, "ruleId": "LLM02.SID.HIGH",
                                                      "location": ["src/x.py", 1, 1]}]},
        [result("LLM02.SID.HIGH", "src/x.py", 1)], {**meta, "results_emitted": 1})
    md, payload, _ = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    glance = {r[0]: r[1:] for r in payload["summary"]["at_a_glance"]["rows"]}
    assert glance["Fixed apps wrongly flagged"] == ["0 of 1"]
    assert glance[eval_report.FIXED_ANY] == ["1 of 1"]
    versions = {r[0]: r[1:] for r in payload["versions"]["rows"]}
    assert versions[eval_report.HARNESS_LABEL] == ["excluded by the false-alarm filter 6"]
    assert "harness and filter effects, not scanner false alarms" in md
    meaning = " ".join(payload["summary"]["tools"][0]["meaning"])
    assert "6 of its findings were removed or changed by the reviewer's own false-alarm filter" in meaning
    # A2: the scoped-mode caveat says the filter is looser, in plain words.
    first = " ".join(payload["summary"]["read_first"])
    assert "filter that removes false alarms is also slightly looser in scoped mode" in first
    for text in payload["summary"]["read_first"] + [meaning]:
        no_jargon(text)
    # The ground truth never reaches the written files.
    assert '"_truth"' not in (tmp_path / "o" / "eval_report.json").read_text(encoding="utf-8")


# ---- m10: family_id is the family key ------------------------------------------------------------

def test_family_id_from_task_metadata_or_toml_with_the_variant_name(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_aa": GT_POS, "task_bb": GT_NEG})
    write(tasks / "VARIANTS.json", {"task_aa": {"family": "3920a8", "role": "positive"},
                                    "task_bb": {"family": "3920a8", "role": "negative"}})
    write(tasks / "task_aa" / "task_metadata.json", {"family_id": "fam_2109"})
    (tasks / "task_bb" / "task.toml").write_text('[metadata]\nfamily_id = "fam_2109"\n', encoding="utf-8")
    job = job_dir(tmp_path, "semgrep")
    add(job, "task_aa", "semgrep", pos_rewards(), {"per_finding": []}, [], {"results_emitted": 0})
    add(job, "task_bb", "semgrep", neg_rewards(), {"negative": True}, [], {"results_emitted": 0})
    md, payload, html = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    trials = payload["tools"][0]["trials"]
    assert {(r["family"], r["family_name"], r["family_id"]) for r in trials} == {("fam_2109", "3920a8", "fam_2109")}
    assert "| fam_2109 (3920a8) | task_aa | positive |" in md
    assert payload["dataset"]["families"] == 1
    assert "f.name" in html  # the HTML shows the variant name beside the family_id


# ---- grader v3.2 outputs -------------------------------------------------------------------------

def test_grader_v32_in_scope_bucket_complete_claims_cross_family_and_version(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG})
    job = job_dir(tmp_path, "claude")
    add(job, "task_fam1_positive", "t", pos_rewards(hit=True),
        {"grader_version": "v3.2", "complete_claims": [{"index": 1, "ruleId": "LLM03.EA.PERMISSIONS"}],
         "per_finding": [{"finding": "F1", "matched": True, "result_index": 0, "ruleId": "LLM03.EA.FUNCTIONALITY",
                          "cross_family": True, "scores": {"classification": 0.2}}]},
        [result("LLM03.EA.FUNCTIONALITY", "src/app.py", 10), result("LLM03.EA.PERMISSIONS", "src/tool.py", 5)],
        {"results_emitted": 2})
    add(job, "task_fam1_negative", "t", neg_rewards(fail=True, **{"neg.fail.near_fix": 0, "neg.fail.in_scope": 1}),
        {"grader_version": "v3.2", "negative": True, "failure_bucket": "in_scope", "complete_claims": [],
         "results_in_scope": [{"index": 0, "ruleId": "LLM02.SID.HIGH", "location": ["src/other.py", 70, 70]}]},
        [result("LLM02.SID.HIGH", "src/other.py", 70)], {"results_emitted": 1})
    md, payload, html = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    tool = payload["tools"][0]
    assert tool["summary"]["reward_by_role"]["negative"]["failed_in_scope"] == 1
    board = {r[0]: r[1:] for r in payload["scoreboard"]["rows"]}
    assert board["Negatives failed on a decoy / next to the fix / anywhere in scope"] == ["0 / 0 / 1"]
    assert {(f["kind"], f["rule"]) for f in tool["false_positives"]} == {("in_scope", "LLM02.SID.HIGH")}
    rows = {r[0]: r[1:] for r in payload["measurement_rows"]}
    assert rows["Matched findings credited across risk families through the CWE (cross_family)"] == ["1"]
    assert rows["Results claiming a complete control (complete_claims, neither failed nor counted as FP)"] == ["1"]
    versions = {r[0]: r[1:] for r in payload["versions"]["rows"]}
    assert versions["Grader version"] == ["v3.2"]
    assert "1 anywhere in scope" in md and "Anywhere in scope" in html
    # report.py prints the third bucket too.
    rr = report.rows_for(job, tasks)
    s = report.summarise(rr)
    assert "anywhere in scope 1" in report.render(rr, s)
    assert "grader version v3.2" in report.versions_text(s["versions"])
