"""tools/report.py and tools/eval_report.py fixes from the PR 4 review: measurements 2 to 4 are
"not supported" only after a match, reward.json mode strips Harbor's trial suffix, Claude review
runs state their mode and the stock-mode caveat, every report states its versions and the task
set state, and the wording of unknown and repeated ground-truth counts."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import eval_report  # noqa: E402
import report  # noqa: E402

REPORT = Path(__file__).resolve().parents[1] / "tools" / "report.py"

GT_POS = {"variant_role": "positive", "family_id": "fam", "matching": {"line_tolerance": 5},
          "findings": [{"id": "F1", "rule_id": "LLM02.SID.HIGH", "risk_type": "sensitive_information_disclosure",
                        "primary_location": {"file": "src/app.py", "start_line": 10}, "acceptable_cwes": ["CWE-200"]}]}
GT_NEG = {"variant_role": "negative", "family_id": "fam", "findings": [], "contrast_rule_ids": ["LLM02.SID.HIGH"]}


def write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def rewards(role: str, tp: int = 0, gt: int = 1, **extra) -> dict:
    r = {"reward": 0.5 * tp if role == "positive" else 1.0, "tp": tp, "fp": 0, "fn": gt - tp if role == "positive"
         else 0, "gt_findings": gt if role == "positive" else 0, "fp_outside_scope": 0, "detection": 0.5 * tp,
         "classification": 0.0, "path": 0.0, "controls": 0.0, "recommendations": 0.0,
         "tl.truth.SID": int(role == "positive"), "tl.pred.SID": int(tp > 0), "tl.truth.EA": 0, "tl.pred.EA": 0,
         "cat.LLM02.SID.truth": int(role == "positive"), "cat.LLM02.SID.detected": int(tp > 0)}
    r.update(extra)
    return r


def sarif(results: list, driver_props: dict | None = None) -> dict:
    driver = {"name": "x", "rules": []}
    if driver_props:
        driver["properties"] = driver_props
    return {"version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results}]}


def hit(**extra) -> dict:
    r = {"ruleId": "LLM02.SID.HIGH", "message": {"text": "m"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 10}}}]}
    r.update(extra)
    return r


def add_trial(job: Path, task: str, meta: dict, rew: dict, results: list, suffix: str = "Ab12xYz",
              driver_props: dict | None = None, detail: dict | None = None) -> Path:
    t = job / f"{task}__{suffix}"
    write(t / "result.json", {"trial_name": t.name, "task_name": task,
                              "agent_result": {"metadata": {"status": "ok", **meta}},
                              "verifier_result": {"rewards": rew}})
    write(t / "verifier" / "reward.json", rew)
    write(t / "verifier" / "grading_detail.json", detail or {"per_finding": []})
    write(t / "agent" / "findings.sarif", sarif(results, driver_props))
    return t


def make_tasks(root: Path) -> Path:
    tasks = root / "tasks"
    write(tasks / "task_aa11" / "tests" / "ground_truth.json", GT_POS)
    write(tasks / "task_bb22" / "tests" / "ground_truth.json", GT_NEG)
    write(tasks / "VARIANTS.json", {"task_aa11": {"family": "fam", "role": "positive"},
                                    "task_bb22": {"family": "fam", "role": "negative"}})
    return tasks


BASE = {"tool": "t", "agent_version": "0.5.0+t-1", "cwe_map": "cwe-map-5", "heuristics": "heuristics-1",
        "results_emitted": 1}


def run_eval(monkeypatch, capsys, out: Path, *args):
    monkeypatch.setattr(sys, "argv", ["eval_report.py", *map(str, args), "--out", str(out)])
    eval_report.main()
    capsys.readouterr()
    return ((out / "eval_report.md").read_text(encoding="utf-8"),
            json.loads((out / "eval_report.json").read_text(encoding="utf-8")),
            (out / "eval_report.html").read_text(encoding="utf-8"))


# ---- item 6: "not supported" needs a matched result -----------------------------------------

def test_no_matched_result_is_no_results_not_unsupported(tmp_path):
    job = tmp_path / "job"
    # Results were written, but none matched: nothing shows whether the tool fills codeFlows.
    add_trial(job, "task_aa11", BASE, rewards("positive", tp=0), [hit()])
    add_trial(job, "task_bb22", BASE, rewards("negative"), [])
    rows = report.rows_for(job, make_tasks(tmp_path), report.load_variants(tmp_path / "tasks" / "VARIANTS.json"))
    m = report.measurement_means(rows)
    assert m["supported"] == {"path": None, "controls": None, "recommendations": None}
    assert m["no_results"] == ["path", "controls", "recommendations"]
    assert report.measurement_support(rows)["undetermined"]["path"] == "no_results"
    assert report.measure_text(m, "path") == report.NO_RESULTS_MEASURE == "n/a (no results)"
    assert m["path"] is None


def test_a_matched_result_without_the_field_is_unsupported(tmp_path):
    job = tmp_path / "job"
    add_trial(job, "task_aa11", BASE, rewards("positive", tp=1, path=0.0), [hit()])
    add_trial(job, "task_bb22", BASE, rewards("negative"), [])
    rows = report.rows_for(job, make_tasks(tmp_path), report.load_variants(tmp_path / "tasks" / "VARIANTS.json"))
    m = report.measurement_means(rows)
    assert m["supported"] == {"path": False, "controls": False, "recommendations": False}
    assert report.measure_text(m, "path") == report.NOT_SUPPORTED


# ---- item 7: reward.json mode reads the task name, not the trial folder ------------------------

@pytest.mark.parametrize("with_result_json", [True, False])
def test_reward_json_mode_uses_the_task_name(tmp_path, with_result_json):
    tasks = make_tasks(tmp_path)
    # The variant map is the only source of the role: the folder names carry no role.
    job = tmp_path / "job"
    pos = add_trial(job, "task_aa11", BASE, rewards("positive", tp=1), [hit()], suffix="itb9wZY")
    neg = add_trial(job, "task_bb22", BASE, rewards("negative"), [], suffix="WAjKabm")
    if not with_result_json:
        (pos / "result.json").unlink()
        (neg / "result.json").unlink()
    rows = report.rows_from_reward_files([pos / "verifier" / "reward.json", neg / "verifier" / "reward.json"],
                                         tasks, report.load_variants(tasks / "VARIANTS.json"))
    assert [(r["task"], r["role"], r["role_source"], r["has_truth"]) for r in rows] == [
        ("task_aa11", "positive", "variants", True), ("task_bb22", "negative", "variants", True)]
    assert [r["trial"] for r in rows] == ["task_aa11__itb9wZY", "task_bb22__WAjKabm"]


def test_reward_json_mode_cli_gives_the_variant_role(tmp_path):
    tasks = make_tasks(tmp_path)
    job = tmp_path / "job"
    # A role the reward would never give: a "negative" by the variant map with gt 1 in its rewards.
    write(tasks / "VARIANTS.json", {"task_aa11": {"family": "fam", "role": "negative"}})
    t = add_trial(job, "task_aa11", BASE, rewards("positive", tp=0), [])
    out = tmp_path / "o"
    subprocess.run([sys.executable, str(REPORT), str(t / "verifier" / "reward.json"), "--tasks", str(tasks),
                    "--write", str(out)], check=True, capture_output=True, text=True)
    trial = json.loads((out / "report.json").read_text(encoding="utf-8"))["trials"][0]
    assert (trial["task"], trial["role"]) == ("task_aa11", "negative")


def test_strip_trial_suffix():
    assert report.strip_trial_suffix("task_1496ad2e__itb9wZY") == "task_1496ad2e"
    assert report.strip_trial_suffix("task_1496ad2e") == "task_1496ad2e"


# ---- item 3: Claude review mode, auth and the stock-mode caveat ------------------------------

CLAUDE = {**BASE, "tool": "claude-code-security-review", "agent_version": "0.5.0+ccsr", "mode": "stock",
          "auth": "oauth", "category_map": "ccsr-category-map-1",
          "claude_review": {"mode": "stock", "auth": "oauth", "results_label": "stock CLI + hard-rule filter",
                            "category_map": "ccsr-category-map-1", "request_options": {"mode": "stock"}}}


def claude_job(root: Path, mode: str, dropped: dict, scoped_flow: bool = False) -> Path:
    job = root / f"claude-{mode}" / "2026-10-12__10-00-00"
    meta = json.loads(json.dumps(CLAUDE))
    meta["mode"] = meta["claude_review"]["mode"] = meta["claude_review"]["request_options"]["mode"] = mode
    if mode == "scoped":
        meta["claude_review"]["results_label"] = "scoped CLI"
    meta["unmapped_by_category"] = dropped
    meta["findings_unmapped"] = sum(dropped.values())
    res = hit(codeFlows=[{"threadFlows": [{"locations": []}]}], properties={"recommendations": ["r"]}) \
        if scoped_flow else hit()
    add_trial(job, "task_aa11", meta, rewards("positive", tp=1, path=0.4, recommendations=0.5), [res],
              detail={"per_finding": [{"finding": "F1", "matched": True, "result_index": 0,
                                       "ruleId": "LLM02.SID.HIGH"}]})
    add_trial(job, "task_bb22", {**meta, "unmapped_by_category": {}, "findings_unmapped": 0},
              rewards("negative"), [])
    return job


def test_stock_mode_states_mode_auth_and_dropped_categories(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path)
    stock = claude_job(tmp_path, "stock", {"injection_authorization_bypass": 4, "ssrf_redirect_bypass": 1})
    scoped = claude_job(tmp_path, "scoped", {}, scoped_flow=True)
    md, payload, html = run_eval(monkeypatch, capsys, tmp_path / "o", stock.parent, scoped.parent, "--tasks", tasks)
    assert "## Versions and run configuration" in md
    assert "| Claude review mode | stock | scoped |" in md
    assert "| Claude auth | oauth | oauth |" in md
    assert "| Claude results label | stock CLI + hard-rule filter | scoped CLI |" in md
    assert "| Claude category map | ccsr-category-map-1 | ccsr-category-map-1 |" in md
    assert "| Claude findings dropped, category not in the map | 5 (injection_authorization_bypass x4, " \
           "ssrf_redirect_bypass x1) | 0 |" in md
    notes = [n["text"] for n in payload["observations"]]
    caveat = [n for n in notes if "frozen category map ccsr-category-map-1" in n]
    assert len(caveat) == 1 and "5 finding(s) were dropped" in caveat[0] and "ran in stock mode" in caveat[0]
    # Scoped runs score paths and recommendations as any tool does.
    stock_t, scoped_t = payload["tools"]
    assert scoped_t["measures"]["supported"] == {"path": True, "controls": False, "recommendations": True}
    assert stock_t["measures"]["supported"] == {"path": False, "controls": False, "recommendations": False}
    assert "renderVersions" in html and '"Claude review mode"' in html


def test_claude_info_falls_back_to_the_saved_metadata(tmp_path):
    job = tmp_path / "job"
    t = add_trial(job, "task_aa11", {"tool": "claude-code-security-review"}, rewards("positive"), [],
                  driver_props={"cweMap": "cwe-map-5", "heuristics": "heuristics-1",
                                "categoryMap": "ccsr-category-map-1"})
    sast = t / "artifacts" / "logs" / "artifacts" / "sast"
    write(sast / "metadata.json", {"agent_version": "0.5.0+ccsr", "unmapped_by_category": {"x": 2}})
    write(sast / "claude_review.json", {"request_options": {"mode": "stock", "auth": "oauth"}, "auth": "oauth"})
    info = report.rows_for(job, None)[0]["run_info"]
    assert (info["agent_version"], info["cwe_map"], info["heuristics"], info["category_map"]) == (
        "0.5.0+ccsr", "cwe-map-5", "heuristics-1", "ccsr-category-map-1")
    assert info["claude"]["mode"] == "stock" and info["claude"]["auth"] == "oauth"
    assert info["claude"]["dropped_unmapped"] == 2


def test_report_py_prints_versions_and_the_caveat(tmp_path):
    job = claude_job(tmp_path, "stock", {"weird_category": 3})
    proc = subprocess.run([sys.executable, str(REPORT), str(job)], check=True, capture_output=True, text=True)
    assert "WARNING: stock mode: the upstream reviewer reports a free-text category" in proc.stdout
    assert "3 finding(s) were dropped this way (weird_category x3)" in proc.stdout
    assert "graded under agent version 0.5.0+ccsr, CWE map cwe-map-5, heuristics heuristics-1, " \
           "Claude category map ccsr-category-map-1" in proc.stdout
    assert "Claude review (2 trials): mode stock, auth oauth, results stock CLI + hard-rule filter." in proc.stdout


def test_non_claude_jobs_have_no_caveat(tmp_path):
    job = tmp_path / "job"
    add_trial(job, "task_aa11", BASE, rewards("positive"), [])
    s = report.summarise(report.rows_for(job, None))
    assert s["versions"]["claude"] is None and report.stock_mode_caveat(s["versions"]) is None


# ---- item 4: versions and the task set ------------------------------------------------------

def test_mixed_versions_are_warned_within_and_across_jobs(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path)
    a = tmp_path / "a" / "2026-10-12__10-00-00"
    add_trial(a, "task_aa11", BASE, rewards("positive"), [])
    add_trial(a, "task_bb22", {**BASE, "cwe_map": "cwe-map-4"}, rewards("negative"), [])
    b = tmp_path / "b" / "2026-10-12__10-00-00"
    add_trial(b, "task_aa11", {**BASE, "tool": "u", "agent_version": "0.4.0+u-1"}, rewards("positive"), [])
    add_trial(b, "task_bb22", {**BASE, "tool": "u", "agent_version": "0.4.0+u-1"}, rewards("negative"), [])
    md, payload, _ = run_eval(monkeypatch, capsys, tmp_path / "o", a.parent, b.parent, "--tasks", tasks)
    warnings = payload["warnings"]
    assert any(w.startswith("Mixed versions across the trials of t: CWE map cwe-map-5 (1), cwe-map-4 (1)")
               for w in warnings)
    assert any(w.startswith("Mixed agent release across jobs: 0.5.0 (t), 0.4.0 (u)") for w in warnings)
    assert any(w.startswith("Mixed CWE map across jobs: cwe-map-5 (t, u), cwe-map-4 (t)") for w in warnings)
    assert "| CWE map | cwe-map-5 (1), cwe-map-4 (1) | cwe-map-5 |" in md
    # report.py says the same for one job.
    proc = subprocess.run([sys.executable, str(REPORT), str(a.parent)], check=True, capture_output=True, text=True)
    assert "WARNING: mixed versions across the trials: CWE map cwe-map-5 (1), cwe-map-4 (1)" in proc.stdout


def test_same_versions_give_no_warning(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path)
    a = tmp_path / "a" / "2026-10-12__10-00-00"
    add_trial(a, "task_aa11", BASE, rewards("positive"), [])
    add_trial(a, "task_bb22", BASE, rewards("negative"), [])
    _, payload, _ = run_eval(monkeypatch, capsys, tmp_path / "o", a.parent, "--tasks", tasks)
    assert not any("Mixed" in w for w in payload["warnings"])


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not available")
def test_task_set_commit_and_dirty_state(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path)
    git = ["git", "-C", str(tasks), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "tasks"], check=True)
    head = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    assert report.task_set_state(tasks) == {"commit": head, "dirty": False, "changed_files": 0}
    job = tmp_path / "a" / "2026-10-12__10-00-00"
    add_trial(job, "task_aa11", BASE, rewards("positive"), [])
    md, payload, _ = run_eval(monkeypatch, capsys, tmp_path / "o", job.parent, "--tasks", tasks)
    assert f"task set git commit {head[:12]} (work tree clean)" in md
    assert payload["versions"]["task_set"]["commit"] == head
    write(tasks / "task_aa11" / "tests" / "ground_truth.json", {**GT_POS, "family_id": "changed"})
    md, payload, _ = run_eval(monkeypatch, capsys, tmp_path / "o2", job.parent, "--tasks", tasks)
    assert "work tree dirty, 1 changed file(s)" in md
    assert any(w.startswith("The task set has uncommitted changes (1 changed file(s)") for w in payload["warnings"])


def test_task_set_outside_git_is_skipped_quietly(tmp_path, monkeypatch):
    assert report.task_set_state(None) is None
    monkeypatch.setattr(report, "_git", lambda *a: None)  # no git, or not a work tree
    assert report.task_set_state(tmp_path) is None
    assert report.task_set_text(None).startswith("not recorded")


# ---- item 5: wording of unknown and repeated ground-truth counts -----------------------------

def test_unknown_ground_truth_of_a_not_scored_positive_is_said(tmp_path):
    job = tmp_path / "job"
    add_trial(job, "task_aa11_positive", BASE, rewards("positive", tp=1), [hit()])
    crash = {"reward": 0.0, "tp": 0, "fp": 0, "fn": 0, "gt_findings": 0, "grader_error": 1}
    add_trial(job, "task_cc33_positive", BASE, crash, [])
    s = report.summarise(report.rows_for(job, None))
    det = s["pooled_detection"]
    assert (det["tasks_not_scored"], det["gt_not_scored"], det["gt_not_scored_unknown"]) == (1, 0, 1)
    text = report.render(report.rows_for(job, None), s)
    assert "recall leaves out an unknown number of findings on 1 positive that was not scored" in text
    assert "recall leaves out 0 findings" not in text


def test_not_scored_text_mixes_known_and_unknown_counts():
    det = {"tasks_not_scored": 3, "gt_not_scored": 4, "gt_not_scored_unknown": 1}
    assert report.not_scored_text(det) == ("recall leaves out 4 findings (and an unknown number on 1 of them, "
                                           "whose ground truth was not found) on 3 positives that were not scored")
    assert report.not_scored_text({"tasks_not_scored": 1, "gt_not_scored": 2, "gt_not_scored_unknown": 0}) == \
        "recall leaves out 2 findings on 1 positive that was not scored"


def test_repeated_runs_say_how_ground_truth_is_counted(tmp_path, monkeypatch, capsys):
    tasks = make_tasks(tmp_path)
    write(tasks / "task_dd44" / "tests" / "ground_truth.json",
          {**GT_POS, "findings": GT_POS["findings"] * 2})
    write(tasks / "VARIANTS.json", {"task_aa11": {"family": "fam", "role": "positive"},
                                    "task_dd44": {"family": "fam2", "role": "positive"},
                                    "task_bb22": {"family": "fam", "role": "negative"}})
    job = tmp_path / "t" / "2026-10-12__10-00-00"
    for k in ("r1", "r2"):
        add_trial(job, "task_aa11", BASE, rewards("positive"), [], suffix=k)
        add_trial(job, "task_dd44", BASE, rewards("positive", gt=2), [], suffix=k)
        add_trial(job, "task_bb22", BASE, rewards("negative"), [], suffix=k)
    md, payload, _ = run_eval(monkeypatch, capsys, tmp_path / "o", job.parent, "--tasks", tasks)
    det = payload["tools"][0]["summary"]["pooled_detection"]
    assert (det["gt"], det["gt_distinct"], det["runs_per_task"]) == (6, 3, [2])
    assert "| Ground-truth findings on scored positives | 6 (3 findings x 2 runs) |" in md
    assert report.gt_text({"gt": 5, "gt_distinct": 3, "runs_per_task": [1, 2]}) == \
        "5 over all runs (3 distinct findings)"
    assert report.gt_text({"gt": 3, "gt_distinct": 3, "runs_per_task": [1]}) == "3"
