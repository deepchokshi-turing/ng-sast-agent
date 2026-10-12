"""tools/eval_report.py on a small hand-built Harbor jobs folder.

The trial layout and field names follow the real jobs of 2026-10-08
(harbor-jobs/*-v040-all): <jobs>/<job>/<trial>/result.json with agent_result
.metadata and verifier_result.rewards, verifier/grading_detail.json from
grader v3 and agent/findings.sarif. The values are made up for the test.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import eval_report  # noqa: E402


def write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def sarif(results):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": results}]}


def result(rule, file, line):
    return {"ruleId": rule, "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": file}, "region": {"startLine": line, "endLine": line}}}]}


def trial(job: Path, name: str, tool: str, rewards: dict, detail: dict, results: list, meta: dict):
    t = job / f"{name}__abc"
    write(t / "result.json", {
        "trial_name": f"{name}__abc", "task_name": name,
        "agent_result": {"metadata": {"tool": tool, "status": "ok", "agent_version": f"0.4.0+{tool}",
                                      "scan_seconds": 5.0, **meta}},
        "verifier_result": {"rewards": rewards}})
    write(t / "verifier" / "grading_detail.json", detail)
    write(t / "agent" / "findings.sarif", sarif(results))


def build_jobs(root: Path, tool: str, hit: bool) -> Path:
    jobs = root / f"{tool}-all"
    job = jobs / "2026-10-08__10-00-00"
    write(job / "result.json", {"id": "job"})
    pos_rewards = {"reward": 0.5 if hit else 0.0, "tp": int(hit), "fp": 0, "fn": int(not hit), "gt_findings": 1,
                   "fp_outside_scope": 0, "detection": 1.0 if hit else 0.0,
                   "tl.truth.SID": 1, "tl.pred.SID": int(hit), "tl.truth.EA": 0, "tl.pred.EA": 0,
                   "cat.LLM02.SID.truth": 1, "cat.LLM02.SID.detected": int(hit)}
    pos_detail = {"per_finding": [
        {"finding": "F1", "matched": True, "result_index": 0, "ruleId": "LLM02.SID.HIGH", "cwe_ok": True,
         "scores": {"detection": 1.0, "classification": 1.0}} if hit else {"finding": "F1", "matched": False}],
        "unmatched_results": [], "trap_hits": []}
    trial(job, "task_aaaaaa_positive", tool, pos_rewards, pos_detail,
          [result("LLM02.SID.HIGH", "src/app.py", 12)] if hit else [],
          {"results_raw": 3, "findings_security": 2, "findings_mapped": int(hit),
           "results_emitted": int(hit), "unmapped_by_cwe": {"CWE-798": 1},
           "results_by_rule": {"LLM02.SID.HIGH": 1} if hit else {}})
    neg_rewards = {"reward": 0.0 if hit else 1.0, "tp": 0, "fp": int(hit), "fn": 0, "gt_findings": 0,
                   "fp_outside_scope": 0, "neg.fail.near_fix": int(hit), "neg.fail.trap": 0,
                   "tl.truth.SID": 0, "tl.pred.SID": int(hit), "tl.truth.EA": 0, "tl.pred.EA": 0,
                   "cat.LLM02.SID.truth": 0, "cat.LLM02.SID.detected": int(hit)}
    neg_detail = {"negative": True, "trap_hits": [],
                  "results_near_fixed_code": [{"index": 0, "ruleId": "LLM02.SID.HIGH",
                                               "location": ["src/app.py", 20, 20]}] if hit else []}
    trial(job, "task_aaaaaa_negative", tool, neg_rewards, neg_detail,
          [result("LLM02.SID.HIGH", "src/app.py", 20)] if hit else [],
          {"results_raw": 1, "findings_security": 1, "findings_mapped": int(hit), "results_emitted": int(hit)})
    return jobs


def test_report_compares_tools_and_lists_hits_and_false_positives(tmp_path, capsys, monkeypatch):
    a = build_jobs(tmp_path, "toola", hit=True)
    b = build_jobs(tmp_path, "toolb", hit=False)
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["eval_report.py", str(a), str(b), "--out", str(out)])
    eval_report.main()
    md = (out / "eval_report.md").read_text(encoding="utf-8")
    assert md.rstrip("\n") == capsys.readouterr().out.rstrip("\n")
    assert "| Measure | toola | toolb [no results, scores not meaningful] |" in md
    assert "| True positives (findings matched) | 1 | 0 |" in md
    assert "| Negatives clean | 0/1 | 1/1 |" in md
    assert "| aaaaaa | task_aaaaaa_positive | positive | 1/1 found | 0/1 found |" in md
    assert "| aaaaaa | task_aaaaaa_negative | negative | FAIL (1 FP) | clean |" in md
    assert "| toola | task_aaaaaa_positive | F1 | LLM02.SID.HIGH | src/app.py:12 | True | 1.000 | 1.000 |" in md
    assert "| Exact risk set, positives | 1/1 | 0/1 |" in md
    assert "| Exact risk set, negatives (neither) | 0/1 | 1/1 |" in md
    assert "| toola | task_aaaaaa_negative | near_fix | LLM02.SID.HIGH | src/app.py:20 |  |" in md
    assert "toolb wrote no result on any task" in md
    assert "| Top dropped CWEs (no OWASP rule) | CWE-798 x1 | CWE-798 x1 |" in md
    rows = list(csv.DictReader((out / "trials.csv").open(encoding="utf-8")))
    assert {(r["tool"], r["task"]) for r in rows} == {
        (t, f"task_aaaaaa_{role}") for t in ("toola", "toolb") for role in ("positive", "negative")}
    payload = json.loads((out / "eval_report.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "sast-eval-report/2"
    assert [p["tool"] for p in payload["tools"]] == ["toola", "toolb"] and len(payload["tools"][0]["trials"]) == 2
    html = (out / "eval_report.html").read_text(encoding="utf-8")
    start = html.index('<script id="report-data" type="application/json">') + len(
        '<script id="report-data" type="application/json">')
    assert json.loads(html[start:html.index("</script>", start)]) == payload


def test_html_embedding_cannot_close_the_script_element():
    payload = {"schema": "sast-eval-report/1", "tools": [], "note": "</script><script>alert(1)</script>"}
    html = eval_report.render_html(payload)
    start = html.index('<script id="report-data" type="application/json">') + len(
        '<script id="report-data" type="application/json">')
    embedded = html[start:html.index("</script>", start)]
    assert "<" not in embedded
    assert json.loads(embedded) == payload


def test_task_id_splits_the_twin_suffix():
    assert eval_report.task_id("task_3c67f1_positive") == ("3c67f1", "positive")
    assert eval_report.task_id("smoke_sonar") == ("smoke_sonar", "")
    assert eval_report.task_id("weird_name_positive") == ("weird_name_positive", "")  # no task_ prefix



# ---- robustness, roles, wording (QC_EVAL_REPORT MAJ-1 to MAJ-7, MIN-*, INF-*) ---------------

import pytest  # noqa: E402

GT_POS = {"variant_role": "positive", "family_id": "fam_1", "matching": {"line_tolerance": 5, "require_cwe": True},
          "findings": [{"id": "F1", "rule_id": "LLM02.SID.HIGH", "risk_type": "sensitive_information_disclosure",
                        "primary_location": {"file": "src/app.py", "start_line": 10, "end_line": 12},
                        "acceptable_cwes": ["CWE-200"], "primary_cwe": "CWE-532"},
                       {"id": "F2", "rule_id": "LLM03.EA.PERMISSIONS", "risk_type": "excessive_agency",
                        "primary_location": {"file": "src/tool.py", "start_line": 5}, "acceptable_cwes": ["CWE-250"]}]}
GT_NEG = {"variant_role": "negative", "family_id": "fam_1", "findings": [],
          "contrast_rule_ids": ["LLM02.SID.HIGH", "LLM03.EA.PERMISSIONS"]}


def make_tasks(root: Path, names: dict) -> Path:
    """names: task dir -> ground truth."""
    tasks = root / "tasks"
    for name, gt in names.items():
        write(tasks / name / "tests" / "ground_truth.json", gt)
    return tasks


def pos_rewards(hit=False, **extra):
    r = {"reward": 0.5 if hit else 0.0, "tp": int(hit), "fp": 0, "fn": 2 - int(hit), "gt_findings": 2,
         "fp_outside_scope": 0, "detection": 0.5 if hit else 0.0, "classification": 0.0, "path": 0.0,
         "controls": 0.0, "recommendations": 0.0,
         "tl.truth.SID": 1, "tl.pred.SID": int(hit), "tl.truth.EA": 1, "tl.pred.EA": 0,
         "cat.LLM02.SID.truth": 1, "cat.LLM02.SID.detected": int(hit),
         "cat.LLM03.EA.PERMISSIONS.truth": 1, "cat.LLM03.EA.PERMISSIONS.detected": 0}
    r.update(extra)
    return r


def neg_rewards(fail=False, **extra):
    r = {"reward": 0.0 if fail else 1.0, "tp": 0, "fp": int(fail), "fn": 0, "gt_findings": 0,
         "fp_outside_scope": 0, "neg.fail.near_fix": int(fail), "neg.fail.trap": 0,
         "tl.truth.SID": 0, "tl.pred.SID": int(fail), "tl.truth.EA": 0, "tl.pred.EA": 0,
         "cat.LLM02.SID.truth": 0, "cat.LLM02.SID.detected": int(fail),
         "cat.LLM03.EA.PERMISSIONS.truth": 0, "cat.LLM03.EA.PERMISSIONS.detected": 0}
    r.update(extra)
    return r


CRASH = {"reward": 0.0, "detection": 0.0, "classification": 0.0, "path": 0.0, "controls": 0.0,
         "recommendations": 0.0, "tp": 0, "fp": 0, "fn": 0, "trap_hits": 0, "fp_outside_scope": 0,
         "gt_findings": 0, "grader_error": 1}


def job_dir(root: Path, tool: str, folder: str | None = None) -> Path:
    job = root / (folder or f"{tool}-all") / "2026-10-12__10-00-00"
    write(job / "result.json", {"id": "job", "n_total_trials": 2, "stats": {
        "n_completed_trials": 2, "n_errored_trials": 0,
        "evals": {"x": {"metrics": [{"reward": 0.5, "path": 0.5}]}}}})
    return job


def add(job: Path, name: str, tool: str, rewards: dict | None, detail: dict | None = None, results=None,
        meta=None, exception=None):
    t = job / f"{name}__abc"
    write(t / "result.json", {
        "trial_name": f"{name}__abc", "task_name": name,
        "agent_result": {"metadata": {"tool": tool, "status": "ok", "agent_version": "1", **(meta or {})}},
        "verifier_result": {"rewards": rewards} if rewards is not None else None,
        "exception_info": exception})
    if detail is not None:
        write(t / "verifier" / "grading_detail.json", detail)
    write(t / "agent" / "findings.sarif", sarif(results or []))


def run(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["eval_report.py", *map(str, args)])
    eval_report.main()
    capsys.readouterr()
    out = Path(args[args.index("--out") + 1])
    md = (out / "eval_report.md").read_text(encoding="utf-8")
    payload = json.loads((out / "eval_report.json").read_text(encoding="utf-8"))
    html = (out / "eval_report.html").read_text(encoding="utf-8")
    return md, payload, html


def standard_pair(job, tool, emit=True):
    res = [result("LLM03.EA.FUNCTIONALITY", "src/other.py", 3)] if emit else []
    add(job, "task_fam1_positive", tool, pos_rewards(fp_outside_scope=len(res)),
        {"per_finding": [], "unmatched_results": [], "trap_hits": [],
         "outside_scope_results": [{"index": 0, "ruleId": "LLM03.EA.FUNCTIONALITY", "location": ["src/other.py", 3, 3]}]
         if emit else []}, res, {"results_emitted": len(res)})
    add(job, "task_fam1_negative", tool, neg_rewards(), {"negative": True, "trap_hits": [],
        "results_near_fixed_code": [], "outside_scope_results": []}, [], {"results_emitted": 0})


def test_measurements_2_to_4_not_supported_unless_a_field_is_emitted(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG})
    a = job_dir(tmp_path, "plain")
    standard_pair(a, "plain")
    b = job_dir(tmp_path, "rich")
    flow = {"codeFlows": [{"threadFlows": [{"locations": []}]}], "properties": {"recommendations": ["r1"]}}
    hit = {**result("LLM02.SID.HIGH", "src/app.py", 10), **flow}
    add(b, "task_fam1_positive", "rich", pos_rewards(hit=True, path=0.25, recommendations=0.5),
        {"per_finding": [{"finding": "F1", "matched": True, "result_index": 0, "ruleId": "LLM02.SID.HIGH",
                          "cwe_ok": True, "scores": {"path": 0.5}}], "unmatched_results": [], "trap_hits": []},
        [hit], {"results_emitted": 1})
    add(b, "task_fam1_negative", "rich", neg_rewards(), {"negative": True}, [], {"results_emitted": 0})
    md, payload, html = run(monkeypatch, capsys, a.parent, b.parent, "--tasks", tasks, "--out", tmp_path / "o")
    plain, rich = payload["tools"]
    assert plain["measures"]["supported"] == {"path": False, "controls": False, "recommendations": False}
    assert rich["measures"]["supported"] == {"path": True, "controls": False, "recommendations": True}
    assert "| Path tracing (measurement 2), mean on positives | not supported by this tool | 0.250 |" in md
    assert "| Recommendation (measurement 4), mean on positives | not supported by this tool | 0.500 |" in md
    assert "| Mitigation detection (measurement 3), mean on positives | not supported by this tool | " \
           "not supported by this tool |" in md
    assert "| Matched detections with a code flow | 0/0 | 1/1 |" in md
    # The HTML reads the same rows and shows the same words.
    assert payload["scoreboard"]["rows"] == [r for r in eval_report.headline(
        [{**t, "rows": t["trials"]} for t in payload["tools"]])]
    assert "renderScoreboard" in html and "DATA.scoreboard" in html and "nsCell" in html
    # Harbor's job means are never stored or shown.
    for text in (md, json.dumps(payload), html):
        assert '"metrics"' not in text and "0.5, \"path\"" not in text
    assert plain["harbor_job"] == {"n_total_trials": 2, "n_completed_trials": 2, "n_errored_trials": 0}


def test_no_results_badge_everywhere_and_exact_set_split(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG})
    a = job_dir(tmp_path, "loud")
    standard_pair(a, "loud")
    b = job_dir(tmp_path, "quiet")
    standard_pair(b, "quiet", emit=False)
    md, payload, html = run(monkeypatch, capsys, a.parent, b.parent, "--tasks", tasks, "--out", tmp_path / "o")
    badge = "quiet [no results, scores not meaningful]"
    headers = [line for line in md.splitlines() if line.startswith("| Measure") or line.startswith("| Risk type")
               or line.startswith("| Category") or line.startswith("| Stage") or line.startswith("| Family")]
    assert len(headers) >= 7 and all(badge in h for h in headers)
    assert "**no results, scores not meaningful.**" in md
    assert [t["no_results"] for t in payload["tools"]] == [False, True]
    assert payload["tools"][1]["label"] == badge
    # Exact risk set: positives and negatives apart, never added together.
    assert "| Exact risk set, positives | 0/1 | 0/1 |" in md
    assert "| Exact risk set, negatives (neither) | 1/1 | 1/1 |" in md
    assert "exactTotals" not in html and "badge(t)" in html


def test_risk_fpr_is_over_negatives_only(tmp_path, monkeypatch, capsys):
    """A one-risk positive cannot be a false positive for the other risk, so it stays out of FPR."""
    sid_only = {**GT_POS, "findings": GT_POS["findings"][:1]}
    tasks = make_tasks(tmp_path, {"task_fam1_positive": sid_only, "task_fam1_negative": GT_NEG,
                                  "task_fam2_positive": sid_only, "task_fam2_negative": GT_NEG})
    job = job_dir(tmp_path, "t")
    for fam in ("fam1", "fam2"):
        add(job, f"task_{fam}_positive", "t", pos_rewards(**{"tl.truth.EA": 0, "gt_findings": 1}), {}, [],
            {"results_emitted": 1})
    add(job, "task_fam1_negative", "t", neg_rewards(fail=True), {"negative": True}, [], {"results_emitted": 1})
    add(job, "task_fam2_negative", "t", neg_rewards(), {"negative": True}, [], {"results_emitted": 0})
    md, payload, _ = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    sid = payload["tools"][0]["summary"]["risk_types"]["sensitive_information_disclosure"]
    ea = payload["tools"][0]["summary"]["risk_types"]["excessive_agency"]
    assert (sid["FP"], sid["TN"], sid["FPR"]) == (1, 1, 0.5)
    assert (ea["FP"], ea["TN"], ea["TN_other_pos"]) == (0, 2, 2)
    assert "FPR 0.500 (1 of 2 negatives)" in md
    assert "TPR 0.000 (0 of 2 positives), FPR 0.500 (1 of 2 negatives), score -0.500" in md  # category table


def test_crashed_positive_is_not_a_negative_and_errors_are_listed(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {f"task_{f}_{r}": (GT_POS if r == "positive" else GT_NEG)
                                  for f in ("fam1", "fam2", "fam3") for r in ("positive", "negative")})
    job = job_dir(tmp_path, "t")
    standard_pair(job, "t")
    add(job, "task_fam2_positive", "t", CRASH, {"error": "boom"})  # grader crashed: gt_findings 0
    add(job, "task_fam2_negative", "t", neg_rewards(), {"negative": True})
    add(job, "task_fam3_positive", "t", None, None, exception={"exception_message": "timeout"})
    add(job, "task_fam3_negative", "t", neg_rewards(), {"negative": True})
    md, payload, _ = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    s = payload["tools"][0]["summary"]
    assert s["zero_finding_tasks_clean"] == [3, 3]  # the crashed positive is not a negative
    det = s["pooled_detection"]
    assert (det["tasks"], det["gt"], det["tasks_not_scored"], det["gt_not_scored"]) == (1, 2, 2, 4)
    rows = {r["task"]: r for r in payload["tools"][0]["trials"]}
    assert rows["task_fam2_positive"]["role"] == "positive" and rows["task_fam2_positive"]["status"] == "grader_error"
    assert rows["task_fam2_positive"]["gt"] == 2  # from the ground truth, not the crash's gt_findings 0
    assert "## Trials that did not finish cleanly" in md
    assert "| t | task_fam2_positive | positive | grader_error | 2 |" in md
    assert "| t | task_fam3_positive | positive | errored | 2 | timeout |" in md
    assert "| Ground-truth findings on scored positives | 2 (+4 not scored) |" in md
    assert "Recall leaves out 4 ground-truth findings on 2 of them." in md
    assert "not scored (grader_error)" in md  # task matrix


def test_missing_grading_detail_and_outside_scope_and_paths(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG})
    job = job_dir(tmp_path, "t")
    res = [result("LLM03.EA.FUNCTIONALITY", "src/other.py", 3)]
    add(job, "task_fam1_positive", "t", pos_rewards(fp=1), None, res, {"results_emitted": 1})
    add(job, "task_fam1_negative", "t", neg_rewards(fp_outside_scope=1),
        {"negative": True, "outside_scope_results": [{"index": 0, "ruleId": "LLM03.EA.FUNCTIONALITY",
                                                      "location": ["src/other.py", 3, 3]}]}, res,
        {"results_emitted": 1})
    md, payload, html = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    tool = payload["tools"][0]
    assert any("grading_detail.json is missing" in w["warning"] and w["task"] == "task_fam1_positive"
               for w in tool["warnings"])
    assert "## Warnings per trial" in md and "no readable grading_detail.json" in md
    assert tool["outside_scope"] == [{"task": "task_fam1_negative", "family": "fam1", "role": "negative",
                                      "rule": "LLM03.EA.FUNCTIONALITY", "location": ["src/other.py", 3, 3]}]
    assert "| t | task_fam1_negative | 1 | LLM03.EA.FUNCTIONALITY x1 |" in md
    assert "outside scope (not scored)" in html
    for text in (md, json.dumps(payload), html):
        assert str(tmp_path) not in text  # no absolute temp paths in the outputs


def test_duplicate_tools_different_task_sets_and_an_empty_job(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {f"task_{f}_{r}": (GT_POS if r == "positive" else GT_NEG)
                                  for f in ("fam1", "fam2") for r in ("positive", "negative")})
    a = job_dir(tmp_path, "semgrep", "run-a")
    standard_pair(a, "semgrep")
    b = job_dir(tmp_path, "semgrep", "run-b")
    standard_pair(b, "semgrep")
    add(b, "task_fam2_positive", "semgrep", pos_rewards(), {})
    add(b, "task_fam2_negative", "semgrep", neg_rewards(), {"negative": True})
    empty = tmp_path / "empty-job"
    empty.mkdir()
    md, payload, html = run(monkeypatch, capsys, a.parent, empty, b.parent, "--tasks", tasks,
                            "--out", tmp_path / "o")
    keys = [t["key"] for t in payload["tools"]]
    assert len(set(keys)) == 2 and all(k.startswith("semgrep") for k in keys)
    ds = payload["dataset"]
    assert (ds["families"], ds["positives"], ds["negatives"], ds["gt_findings"]) == (2, 2, 2, 4)
    assert ds["same_task_set"] is False
    assert any("different task sets" in w for w in payload["warnings"])
    assert any("empty-job, so it was left out" in w for w in payload["warnings"])
    assert "different task sets" in md and "empty-job" in md
    assert "t.key" in html and "visible.has(t.key)" in html  # chips toggle by unique key


def test_only_empty_jobs_stop_the_report(tmp_path, monkeypatch):
    (tmp_path / "nothing").mkdir()
    monkeypatch.setattr(sys, "argv", ["eval_report.py", str(tmp_path / "nothing")])
    with pytest.raises(SystemExit):
        eval_report.main()


def test_taxonomy_coverage_gap_is_stated(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG})
    job = job_dir(tmp_path, "t")
    standard_pair(job, "t")
    md, payload, html = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    cov = payload["dataset"]["taxonomy_coverage"]
    assert cov["missing"] == ["LLM02.SID.MEDIUM", "LLM03.EA.FUNCTIONALITY", "LLM03.EA.AUTONOMY"]
    assert "The dataset has no finding for LLM02.SID.MEDIUM, LLM03.EA.FUNCTIONALITY or LLM03.EA.AUTONOMY" in md
    assert payload["coverage_note"] in md and "DATA.coverage_note" in html


def test_variant_map_gives_family_and_role_for_random_task_ids(tmp_path, monkeypatch, capsys):
    names = {"t_9f2a": ("famX", "positive"), "t_17bc": ("famX", "negative")}
    # Ground truth that would say the opposite: the map wins.
    tasks = make_tasks(tmp_path, {"t_9f2a": GT_POS, "t_17bc": GT_NEG})
    write(tasks / "VARIANTS.json", {k: {"family": f, "role": r} for k, (f, r) in names.items()})
    job = job_dir(tmp_path, "t")
    add(job, "t_9f2a", "t", pos_rewards(), {})
    add(job, "t_17bc", "t", neg_rewards(), {"negative": True})
    md, payload, _ = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    rows = {r["task"]: r for r in payload["tools"][0]["trials"]}
    assert (rows["t_9f2a"]["family"], rows["t_9f2a"]["role"], rows["t_9f2a"]["role_source"]) == \
        ("famX", "positive", "variants")
    assert rows["t_17bc"]["role"] == "negative"
    assert "| famX | t_9f2a | positive | 0/2 found |" in md
    assert "| famX | t_17bc | negative | clean |" in md
    # An explicit --variants path overrides the default.
    other = tmp_path / "other.json"
    write(other, {"t_9f2a": {"family": "famY", "role": "positive"}, "t_17bc": {"family": "famY", "role": "negative"}})
    md, payload, _ = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--variants", other,
                         "--out", tmp_path / "o2")
    assert {r["family"] for r in payload["tools"][0]["trials"]} == {"famY"}


def test_role_falls_back_to_ground_truth_never_to_the_reward(tmp_path, monkeypatch, capsys):
    # No map, no task_<family>_<role> name: the ground truth decides. The positive's
    # grader crashed, so its reward and gt_findings say nothing, and it is still a positive.
    tasks = make_tasks(tmp_path, {"t_aa": GT_POS, "t_bb": GT_NEG})
    job = job_dir(tmp_path, "t")
    add(job, "t_aa", "t", CRASH, {"error": "boom"})
    add(job, "t_bb", "t", neg_rewards(), {"negative": True})
    md, payload, _ = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    rows = {r["task"]: r for r in payload["tools"][0]["trials"]}
    assert (rows["t_aa"]["role"], rows["t_aa"]["family"], rows["t_aa"]["role_source"]) == \
        ("positive", "fam_1", "ground truth")
    assert rows["t_bb"]["role"] == "negative"
    assert payload["dataset"]["families"] == 1


def test_role_unknown_without_any_source(tmp_path):
    import report
    row = report.base_row("odd", CRASH)
    assert row["role"] == "" and row["gt"] is None and row["status"] == "grader_error"
    assert report.base_row("odd", neg_rewards())["role"] == "negative"  # the grader's gt_findings count


def test_method_text_matches_the_grader():
    text = " ".join(eval_report.METHOD)
    assert "risk family" in text and "optimal assignment" in text and "does not gate" in text
    assert "same OWASP prefix" in text and "No CWE agreement is needed" in text
    assert "greedy" not in text and "first result" not in text


def test_html_has_distinct_colours_for_eight_tools_and_wraps_code():
    html = eval_report.HTML_TEMPLATE.read_text(encoding="utf-8")
    for i in range(1, 9):
        assert f"--tool-{i}:" in html
    assert "(t._i % 8) + 1" in html and "striped" in html
    assert "word-break: break-all" not in html and "<wbr>" not in html and 'el("wbr")' in html
    assert "risk_types_loose" in html  # the loose table is shown in both views


def test_writing_has_no_em_dash_or_semicolon_in_user_text():
    import report
    texts = eval_report.METHOD + [report.HARBOR_MEAN_WARNING, report.NO_RESULTS_WARNING, report.NOT_SUPPORTED]
    for t in texts:
        assert "—" not in t and ";" not in t, t


def test_location_recall_also_accepts_the_primary_cwe():
    import report
    truth = {"matching": {"line_tolerance": 2}, "findings": [
        {"primary_location": {"file": "a.py", "start_line": 10}, "acceptable_cwes": ["CWE-200"], "primary_cwe": "CWE-532"}]}
    rows = [["r", ["CWE-532"], "a.py", 11, 11, None]]
    assert report.ground_truth_hits(rows, truth) == (1, 1, 1)


# ---- task matrix keyed by task, not by role (REVIEW_FINAL M2) -------------------------------

def test_family_with_two_positives_keeps_both_in_the_matrix(tmp_path, monkeypatch, capsys):
    # ef77cd shape: an original positive plus a partial-control positive, no negative.
    tasks = make_tasks(tmp_path, {"t_orig": GT_POS, "t_partial": GT_POS})
    write(tasks / "VARIANTS.json", {"t_orig": {"family": "ef77cd", "role": "positive"},
                                    "t_partial": {"family": "ef77cd", "role": "positive"}})
    job = job_dir(tmp_path, "t")
    add(job, "t_orig", "t", pos_rewards(hit=True), {"per_finding": [
        {"finding": "F1", "matched": True, "result_index": 0, "ruleId": "LLM02.SID.HIGH", "cwe_ok": True}]},
        [result("LLM02.SID.HIGH", "src/app.py", 10)], {"results_emitted": 1})
    add(job, "t_partial", "t", pos_rewards(), {"per_finding": []}, [], {"results_emitted": 0})
    md, payload, html = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    assert "| ef77cd | t_orig | positive | 1/2 found |" in md
    assert "| ef77cd | t_partial | positive | 0/2 found |" in md
    assert "not run" not in md.split("## Task matrix")[1].split("## True positives")[0]
    outcomes = {o["task"]: o for o in payload["tools"][0]["task_outcomes"]}
    assert (outcomes["t_orig"]["kind"], outcomes["t_partial"]["kind"]) == ("ok", "bad")
    assert {o["family"] for o in outcomes.values()} == {"ef77cd"}
    assert "task_outcomes" in html and "byTool.get(t.key)[role]" not in html


def test_repeated_trials_are_summed_up_not_overwritten(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG})
    job = job_dir(tmp_path, "t")
    hit = {"per_finding": [{"finding": "F1", "matched": True, "result_index": 0, "ruleId": "LLM02.SID.HIGH"}]}
    for i, found in enumerate((True, False, True)):
        t = job / f"task_fam1_positive__r{i}"
        write(t / "result.json", {"trial_name": t.name, "task_name": "task_fam1_positive",
                                  "agent_result": {"metadata": {"tool": "t", "status": "ok"}},
                                  "verifier_result": {"rewards": pos_rewards(hit=found)}})
        write(t / "verifier" / "grading_detail.json", hit if found else {"per_finding": []})
        write(t / "agent" / "findings.sarif", sarif([result("LLM02.SID.HIGH", "src/app.py", 10)] if found else []))
    for i, fail in enumerate((False, True, False)):
        t = job / f"task_fam1_negative__r{i}"
        write(t / "result.json", {"trial_name": t.name, "task_name": "task_fam1_negative",
                                  "agent_result": {"metadata": {"tool": "t", "status": "ok"}},
                                  "verifier_result": {"rewards": neg_rewards(fail=fail)}})
        write(t / "verifier" / "grading_detail.json", {"negative": True})
    t = job / "task_fam1_negative__r3"  # a fourth run that errored
    write(t / "result.json", {"trial_name": t.name, "task_name": "task_fam1_negative",
                              "agent_result": {"metadata": {"tool": "t", "status": "ok"}},
                              "verifier_result": None, "exception_info": {"exception_message": "timeout"}})
    md, payload, _ = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    assert "| fam1 | task_fam1_positive | positive | 1/2 found in 2 of 3 runs, 0/2 found in 1 of 3 runs |" in md
    assert "| fam1 | task_fam1_negative | negative | FAIL in 1 of 3 runs (1 FP in total) (+1 not scored) |" in md
    outcomes = {o["task"]: o for o in payload["tools"][0]["task_outcomes"]}
    assert outcomes["task_fam1_positive"]["kind"] == "mixed" and outcomes["task_fam1_positive"]["runs"] == 3
    assert outcomes["task_fam1_negative"]["runs"] == 4 and outcomes["task_fam1_negative"]["scored"] == 3
    # Matched results of the repeated task stay apart by run number.
    assert [h["run"] for h in payload["tools"][0]["hits"]] == [1, 3]
    assert "| t | task_fam1_positive (run 1) | F1 |" in md and "| t | task_fam1_positive (run 3) | F1 |" in md
    assert "| t | task_fam1_negative (run 4) | negative | errored |" in md


def test_single_runs_read_as_before():
    rows = [{"task": "a", "family": "f", "role": "positive", "status": "ok", "reward": 0.5, "sarif_missing": False,
             "tp": 1, "fp": 2, "gt": 1},
            {"task": "b", "family": "f", "role": "negative", "status": "ok", "reward": 1.0, "sarif_missing": False,
             "tp": 0, "fp": 0, "gt": 0}]
    texts = {o["task"]: o["text"] for o in eval_report.task_outcomes(rows)}
    assert texts == {"a": "1/1 found, 2 FP", "b": "clean"}


# ---- jobs recorded before the rename (REVIEW_FINAL m1) ----------------------------------------

def test_former_name_resolves_role_family_and_ground_truth(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path, {"task_56cab0d1": GT_POS, "task_900bbee6": GT_POS})
    write(tasks / "VARIANTS.json", {
        "task_56cab0d1": {"family": "ef77cd", "role": "positive", "former_name": "task_ef77cd_positive"},
        "task_900bbee6": {"family": "ef77cd", "role": "positive", "former_name": "task_ef77cd_negative"}})
    job = job_dir(tmp_path, "t")
    add(job, "task_ef77cd_positive", "t", pos_rewards(), {"per_finding": []})
    add(job, "task_ef77cd_negative", "t", neg_rewards(fail=True), {"negative": True})
    md, payload, _ = run(monkeypatch, capsys, job.parent, "--tasks", tasks, "--out", tmp_path / "o")
    rows = {r["task"]: r for r in payload["tools"][0]["trials"]}
    old_neg = rows["task_ef77cd_negative"]
    assert (old_neg["family"], old_neg["role"], old_neg["role_source"]) == ("ef77cd", "positive",
                                                                             "variants (former name)")
    assert old_neg["has_truth"] and old_neg["gt"] == 2 and old_neg["relabelled"]
    assert not rows["task_ef77cd_positive"]["relabelled"]
    # Graded against the old negative label, so it is scored under neither role.
    assert old_neg["status"] == "graded_as_old_role"
    s = payload["tools"][0]["summary"]
    sid = s["risk_types"]["sensitive_information_disclosure"]
    assert sid["FP"] + sid["TN"] == 0 and s["zero_finding_tasks_clean"] == [0, 0]
    assert (s["pooled_detection"]["tasks"], s["pooled_detection"]["gt_not_scored"]) == (1, 2)
    assert any("before the rename" in w for w in payload["warnings"])
    assert "| ef77cd | task_ef77cd_negative | positive | not scored (graded_as_old_role) |" in md
    assert "| ef77cd | task_ef77cd_positive | positive | 0/2 found |" in md
    assert "| task_ef77cd_negative | positive | graded_as_old_role | 2 | graded as a negative before" in md


def test_former_name_never_hides_a_current_task(tmp_path):
    import report
    path = tmp_path / "VARIANTS.json"
    write(path, {"task_x_positive": {"family": "x", "role": "negative"},
                 "task_new": {"family": "y", "role": "positive", "former_name": "task_x_positive"}})
    v = report.load_variants(path)
    assert v["task_x_positive"] == {"family": "x", "role": "negative"}
    assert v["task_new"]["role"] == "positive"
