"""tools/report.py category math (checked against a hand-computed example),
per-role reward means and the loose risk table, and tools/leak_scan.py (the
heuristic leak check) on a small twin pair, including the ground-truth shingle
check and the Dockerfile check."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT

REPORT = ROOT / "tools" / "report.py"
LEAK = ROOT / "tools" / "leak_scan.py"
SID, EA = "LLM02.SID", "LLM03.EA.FUNCTIONALITY"


def reward(gt, path, cats, truth, pred, **extra):
    r = {"reward": 0.5, "detection": 0.5, "classification": 0.0, "path": path, "controls": 0.0,
         "recommendations": 0.0, "tp": 0, "fp": 0, "fn": 0, "trap_hits": 0, "fp_outside_scope": 1,
         "gt_findings": gt}
    for cat, (t, d) in cats.items():
        r[f"cat.{cat}.truth"], r[f"cat.{cat}.detected"] = t, d
    for short in ("SID", "EA"):
        r[f"tl.truth.{short}"], r[f"tl.pred.{short}"] = int(short in truth), int(short in pred)
    r.update(extra)
    return r


# T1 both risks, finds SID only; T2 SID negative, flagged; T3 EA negative, clean;
# T4 EA positive, found; T5 positive whose SARIF was missing (left out of the tables).
TRIALS = {
    "t1": reward(2, 0.5, {SID: (1, 1), EA: (1, 0)}, {"SID", "EA"}, {"SID"}),
    "t2": reward(0, 0.0, {SID: (0, 1)}, set(), {"SID"}),
    "t3": reward(0, 0.0, {EA: (0, 0)}, set(), set()),
    "t4": reward(1, 1.0, {EA: (1, 1)}, {"EA"}, {"EA"}),
    "t5": reward(1, 0.0, {EA: (1, 0)}, {"EA"}, set(), sarif_missing=1),
}


@pytest.fixture
def report(tmp_path):
    files = []
    for name, r in TRIALS.items():
        f = tmp_path / name / "verifier" / "reward.json"
        f.parent.mkdir(parents=True)
        f.write_text(json.dumps(r))
        files.append(str(f))
    out = tmp_path / "report"
    proc = subprocess.run([sys.executable, str(REPORT), *files, "--write", str(out)],
                          check=True, capture_output=True, text=True)
    return json.loads((out / "report.json").read_text()), proc.stdout, (out / "report.md").read_text()


def test_category_math_matches_hand_computation(report):
    data, _, _ = report
    cats = data["summary"]["categories"]
    sid, ea = cats["per_category"][SID], cats["per_category"][EA]
    assert {k: sid[k] for k in ("TP", "FN", "TN", "FP")} == {"TP": 1, "FN": 0, "TN": 0, "FP": 1}
    assert (sid["TPR"], sid["FPR"], sid["youden"]) == (1.0, 1.0, 0.0)
    assert {k: ea[k] for k in ("TP", "FN", "TN", "FP")} == {"TP": 1, "FN": 1, "TN": 1, "FP": 0}
    assert (ea["TPR"], ea["FPR"], ea["youden"]) == (0.5, 0.0, 0.5)
    o = cats["overall"]
    assert o["mean_TPR"] == pytest.approx(0.75) and o["mean_FPR"] == pytest.approx(0.5)
    assert o["score"] == pytest.approx(0.25)
    assert o["precision_pooled"] == pytest.approx(2 / 3)
    assert o["F1"] == pytest.approx(2 * (2 / 3) * 0.75 / (2 / 3 + 0.75))
    assert data["summary"]["excluded_from_category_tables"] == 1


def test_risk_type_tables(report):
    risks = report[0]["summary"]["risk_types"]
    s = risks["sensitive_information_disclosure"]
    assert {k: s[k] for k in ("TP", "FN", "TN", "FP")} == {"TP": 1, "FN": 0, "TN": 2, "FP": 1}
    assert s["FPR"] == pytest.approx(1 / 3) and s["precision"] == 0.5
    e = risks["excessive_agency"]
    assert {k: e[k] for k in ("TP", "FN", "TN", "FP")} == {"TP": 1, "FN": 1, "TN": 2, "FP": 0}
    assert risks["by_truth_set"] == {
        "both": {"tasks": 1, "exact": 0, "exact_rate": 0.0},
        "neither": {"tasks": 2, "exact": 1, "exact_rate": 0.5},
        "EA only": {"tasks": 1, "exact": 1, "exact_rate": 1.0},
    }


def test_measurements_and_fp_out(report):
    data, stdout, md = report
    m = data["summary"]["measurements_positive_tasks"]
    assert m["tasks"] == 3 and m["path"] == pytest.approx(0.5)  # (0.5 + 1.0 + 0.0) / 3
    assert data["summary"]["fp_outside_scope"] == 5
    assert "fp_out" in stdout and "youden" in stdout and "| category |" in md


def test_reward_is_reported_per_role_never_combined(tmp_path):
    trials = {
        "pos": reward(1, 0.0, {EA: (1, 0)}, {"EA"}, set(), reward=0.2),
        "neg_clean": reward(0, 1.0, {EA: (0, 0)}, set(), set(), reward=1.0),
        "neg_near": reward(0, 0.0, {EA: (0, 1)}, set(), {"EA"}, reward=0.0,
                           **{"neg.fail.near_fix": 1, "neg.fail.trap": 0}),
        "neg_trap": reward(0, 0.0, {EA: (0, 1)}, set(), {"EA"}, reward=0.0,
                           **{"neg.fail.near_fix": 0, "neg.fail.trap": 1}),
    }
    files = []
    for name, r in trials.items():
        f = tmp_path / name / "verifier" / "reward.json"
        f.parent.mkdir(parents=True)
        f.write_text(json.dumps(r))
        files.append(str(f))
    out = tmp_path / "report"
    proc = subprocess.run([sys.executable, str(REPORT), *files, "--write", str(out)],
                          check=True, capture_output=True, text=True)
    summary = json.loads((out / "report.json").read_text())["summary"]
    roles = summary["reward_by_role"]
    assert roles["positive"] == {"tasks": 1, "mean_reward": pytest.approx(0.2)}
    assert roles["negative"]["tasks"] == 3 and roles["negative"]["mean_reward"] == pytest.approx(1 / 3)
    assert (roles["negative"]["failed"], roles["negative"]["failed_near_fix"], roles["negative"]["failed_trap"]) == (3 - 1, 1, 1)
    assert "mean_reward" not in summary  # no mean over positives and negatives together
    md = (out / "report.md").read_text()
    for text in (proc.stdout, md):
        assert "positives only (1 tasks): 0.200" in text
        assert "negatives only (3 tasks): 0.333" in text and "near the fix 1, on a trap 1" in text
        assert "not a score" in text and "Harbor" in text
        assert "0.40" not in text and "ceiling" not in text
        assert "mean task reward (composite" not in text


def test_report_text_has_no_stale_ceiling():
    assert "0.40" not in REPORT.read_text() and "ceiling" not in REPORT.read_text()


def test_loose_risk_table_is_separate(tmp_path):
    loose = reward(1, 0.0, {SID: (1, 0)}, {"SID"}, set(), **{"tl.pred_loose.SID": 1, "tl.pred_loose.EA": 0})
    f = tmp_path / "t" / "verifier" / "reward.json"
    f.parent.mkdir(parents=True)
    f.write_text(json.dumps(loose))
    out = tmp_path / "report"
    proc = subprocess.run([sys.executable, str(REPORT), str(f), "--write", str(out)], check=True,
                          capture_output=True, text=True)
    summary = json.loads((out / "report.json").read_text())["summary"]
    sid = "sensitive_information_disclosure"
    assert (summary["risk_types"][sid]["TP"], summary["risk_types"][sid]["FN"]) == (0, 1)
    assert (summary["risk_types_loose"][sid]["TP"], summary["risk_types_loose"][sid]["FN"]) == (1, 0)
    assert "loose" in proc.stdout


def test_job_directory_mode_still_works(tmp_path):
    job = tmp_path / "jobs" / "2026-10-07__run"
    for name, r in list(TRIALS.items())[:4]:
        (job / name).mkdir(parents=True)
        (job / name / "result.json").write_text(json.dumps({
            "trial_name": name, "task_name": name, "verifier_result": {"rewards": r},
            "agent_result": {"metadata": {"status": "ok"}}}))
    proc = subprocess.run([sys.executable, str(REPORT), str(tmp_path / "jobs")], check=True,
                          capture_output=True, text=True)
    assert "trials 4, graded 4" in proc.stdout and "mean TPR 0.750" in proc.stdout
    rows = json.loads(subprocess.run([sys.executable, str(REPORT), str(job), "--json"], check=True,
                                     capture_output=True, text=True).stdout)
    assert [r["fp_out"] for r in rows] == [1, 1, 1, 1]


# ---- leak scan -------------------------------------------------------------------------

def make_twin(root: Path, tool_neg: str = "def write(p):\n    return safe(p)\n") -> None:
    for role, tool in (("positive", "def write(p):\n    return open(p, 'w')\n"), ("negative", tool_neg)):
        t = root / f"task_abc_{role}"
        repo = t / "environment" / "repo"
        (repo / "src" / "mini").mkdir(parents=True)
        (repo / "fixtures").mkdir()
        (t / "tests").mkdir()
        (t / "validation").mkdir()
        (t / "task.toml").write_text('version = "1.0"\n')
        (t / "environment" / "Dockerfile").write_text("FROM python:3.12-slim\n")
        (repo / "security_manifest.json").write_text('{"intended_task": "write notes"}\n')
        (repo / "fixtures" / "secret.env").write_text("TOKEN=CNRY-abc123-tok\n")
        (repo / "src" / "mini" / "app.py").write_text("print('hi')\n")
        (repo / "src" / "mini" / "tool.py").write_text(tool)
        (t / "tests" / "ground_truth.json").write_text(json.dumps({
            "fix_changed_files": ["src/mini/tool.py"],
            "findings": [{"id": "F1", "rationale": "The model picks any path and the notes tool writes there unchecked."}],
            "evidence": {"upstream_fix_summary": "resolve the target and refuse paths outside the notes folder"},
        }))
        (t / "validation" / "provenance.json").write_text(json.dumps({"qc": {"label_leak_scan": None}}))


def leak(root: Path, *flags):
    return subprocess.run([sys.executable, str(LEAK), str(root), *flags], capture_output=True, text=True)


def test_clean_twin_passes_and_writes_qc(tmp_path):
    make_twin(tmp_path)
    proc = leak(tmp_path, "--write-qc")
    assert proc.returncode == 0, proc.stdout
    assert "task_abc_positive  pass" in proc.stdout and "task_abc_negative  pass" in proc.stdout
    qc = json.loads((tmp_path / "task_abc_negative" / "validation" / "provenance.json").read_text())["qc"]
    assert qc["label_leak_scan"] == "pass"


@pytest.mark.parametrize("mutate, message", [
    (lambda t: (t / "environment/repo/src/mini/app.py").write_text("# Patched CVE-2025-1 here\n"), "banned word"),
    (lambda t: (t / "environment/repo/ground_truth.json").write_text("{}"), "evaluator-only"),
    (lambda t: (t / "environment/repo/src/mini/app.py").write_text("print('bye')\n"), "outside fix_changed_files"),
    (lambda t: (t / "environment/repo/fixtures/secret.env").write_text("TOKEN=other\n"), "manifest or fixtures"),
    (lambda t: (t / "environment/repo/security_manifest.json").write_text("{}"), "manifest or fixtures"),
    (lambda t: (t / "environment/repo/src/mini/tool.py").write_text(
        "# Resolve the target, and refuse paths OUTSIDE the notes-folder.\ndef write(p):\n    return safe(p)\n"),
     "ground-truth text from evidence.upstream_fix_summary appears in environment/repo/src/mini/tool.py"),
    (lambda t: (t / "environment/Dockerfile").write_text("FROM python:3.12-slim\nCOPY tests/ /app/tests/\n"),
     "Dockerfile copies tests/"),
    (lambda t: (t / "environment/Dockerfile").write_text("FROM python:3.12-slim\nCOPY . /app/\n"),
     "Dockerfile copies ."),
    (lambda t: (t / "environment/Dockerfile").write_text('FROM python:3.12-slim\nADD ["repo/", "x.txt", "/app/"]\n'),
     "Dockerfile copies x.txt"),
    (lambda t: (t / "environment/Dockerfile").write_text("FROM python:3.12-slim\nCOPY repo/ \\\n  ../tests /app/\n"),
     "Dockerfile copies ../tests"),
])
def test_problems_fail_the_scan(tmp_path, mutate, message):
    make_twin(tmp_path)
    mutate(tmp_path / "task_abc_negative")
    proc = leak(tmp_path, "--write-qc")
    assert proc.returncode == 1 and message in proc.stdout
    assert "task_abc_negative  FAIL" in proc.stdout
    qc = json.loads((tmp_path / "task_abc_negative" / "validation" / "provenance.json").read_text())["qc"]
    assert qc["label_leak_scan"] == "fail"


def test_output_calls_itself_heuristic(tmp_path):
    make_twin(tmp_path)
    proc = leak(tmp_path)
    assert "heuristic leak check" in proc.stdout and "not proof" in proc.stdout
    assert "heuristic" in LEAK.read_text().split("\n\n")[0].lower()


@pytest.mark.parametrize("text, leaks", [
    ("# the model picks any path and the notes\n", True),     # six words of the rationale, case ignored
    ("# the model picks any path\n", False),                   # five words only
    ("# The model picks any\n# path and the notes\n", True),  # line breaks do not hide it
])
def test_ground_truth_shingles(tmp_path, text, leaks):
    make_twin(tmp_path)
    for role in ("positive", "negative"):
        (tmp_path / f"task_abc_{role}" / "environment/repo/src/mini/app.py").write_text(text)
    proc = leak(tmp_path)
    assert ("ground-truth text from findings[0].rationale" in proc.stdout) is leaks, proc.stdout


@pytest.mark.parametrize("dockerfile", [
    "ARG IMG=sast-tools:0.4.0\nFROM ${IMG} AS tools\nFROM python:3.12-slim\nCOPY --from=tools /opt/sast /opt/sast\n"
    "COPY repo/ /app/repo/\n",
    "FROM python:3.12-slim\nCOPY ./repo /app/repo\n",
    'FROM python:3.12-slim\nCOPY ["repo", "/app/repo"]\n',
    "FROM python:3.12-slim\nCOPY --chown=app:app repo/ /app/repo/\n",
])
def test_dockerfile_copying_only_repo_passes(tmp_path, dockerfile):
    make_twin(tmp_path)
    for role in ("positive", "negative"):
        (tmp_path / f"task_abc_{role}" / "environment/Dockerfile").write_text(dockerfile)
    proc = leak(tmp_path)
    assert proc.returncode == 0, proc.stdout


def test_missing_twin_is_reported(tmp_path):
    make_twin(tmp_path)
    import shutil
    shutil.rmtree(tmp_path / "task_abc_negative")
    proc = leak(tmp_path)
    assert proc.returncode == 1 and "twin task_abc_negative not found" in proc.stdout
