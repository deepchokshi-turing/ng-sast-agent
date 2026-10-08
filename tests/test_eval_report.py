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
    assert "| Measure | toola | toolb |" in md
    assert "| True positives | 1 | 0 |" in md
    assert "| Negatives clean | 0/1 | 1/1 |" in md
    assert "| aaaaaa | 1/1 found | FAIL (1 FP) | 0/1 found | clean |" in md
    assert "| toola | task_aaaaaa_positive | F1 | LLM02.SID.HIGH | src/app.py:12 | True | 1.000 | 1.000 |" in md
    assert "| toola | task_aaaaaa_negative | near_fix | LLM02.SID.HIGH | src/app.py:20 |  |" in md
    assert "toolb wrote no result on any task" in md
    assert "| Top dropped CWEs (no OWASP rule) | CWE-798 x1 | CWE-798 x1 |" in md
    rows = list(csv.DictReader((out / "trials.csv").open(encoding="utf-8")))
    assert {(r["tool"], r["task"]) for r in rows} == {
        (t, f"task_aaaaaa_{role}") for t in ("toola", "toolb") for role in ("positive", "negative")}
    payload = json.loads((out / "eval_report.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "sast-eval-report/1"
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
