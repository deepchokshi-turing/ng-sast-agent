"""task_format/grade.py (grader v2): the two optional ground-truth fields, and
that a task without them is graded exactly as by the original grader."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT, SAMPLE_TASKS

V2 = ROOT / "task_format" / "grade.py"
#: The original grader as shipped in the reference task, kept for comparison.
V1 = ROOT / "tests" / "fixtures" / "grade_v1.py"


def run(grader: Path, sarif: dict | None, truth: dict, tmp_path: Path) -> dict:
    truth_file = tmp_path / "truth.json"
    truth_file.write_text(json.dumps(truth))
    sarif_file = tmp_path / "findings.sarif"
    if sarif is not None:
        sarif_file.write_text(json.dumps(sarif))
    out = tmp_path / f"out-{grader.stem}"
    subprocess.run([sys.executable, str(grader), "--sarif", str(sarif_file), "--truth", str(truth_file),
                    "--out", str(out)], check=True, capture_output=True)
    return json.loads((out / "reward.json").read_text())


def result(rule, file, line):
    return {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": file},
                                                                 "region": {"startLine": line, "endLine": line}}}]}


def sarif(*results):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": list(results)}]}


def truth(task):
    return json.loads((SAMPLE_TASKS / task / "tests" / "ground_truth.json").read_text())


TWIN = "smoke_eval_twin"
FIXED = "src/calc_agent/agent.py"


@pytest.mark.parametrize("doc, reward, fp, outside", [
    (sarif(), 1.0, 0, 0),
    (sarif(result("LLM03.EA.FUNCTIONALITY", FIXED, 35)), 0.0, 1, 0),             # near the fixed code
    (sarif(result("LLM02.SID.HIGH", FIXED, 44)), 0.0, 1, 0),                     # within tolerance
    (sarif(result("LLM03.EA.FUNCTIONALITY", "src/calc_agent/maintenance.py", 8)), 1.0, 0, 1),
    (sarif(result("LLM03.EA.FUNCTIONALITY", FIXED, 5)), 1.0, 0, 1),              # same file, far away
])
def test_twin_fails_only_near_the_fixed_code(tmp_path, doc, reward, fp, outside):
    score = run(V2, doc, truth(TWIN), tmp_path)
    assert (score["reward"], score["fp"], score["fp_outside_scope"]) == (reward, fp, outside)


def test_twin_with_no_output_still_fails(tmp_path):
    assert run(V2, None, truth(TWIN), tmp_path)["reward"] == 0.0


def test_positive_scope_counts_false_positives_in_fixed_files_only(tmp_path):
    hit = {**result("LLM03.EA.FUNCTIONALITY", FIXED, 8), "properties": {"cwe": ["CWE-95"]}}
    far = result("LLM02.SID.HIGH", "src/elsewhere.py", 1)
    score = run(V2, sarif(hit, far), truth("smoke_eval"), tmp_path)
    assert (score["tp"], score["fp"], score["fp_outside_scope"], score["reward"]) == (1, 0, 1, 0.4)


@pytest.mark.parametrize("task", ["task_7f3a91", "smoke_empty", "smoke_eval_node"])
@pytest.mark.parametrize("doc", [
    sarif(),
    sarif(result("LLM02.SID.HIGH", "src/support_copilot/retrieval.py", 11)),
    sarif(result("LLM02.SID.MEDIUM", "src/support_copilot/admin_export.py", 18),
          result("LLM03.EA.FUNCTIONALITY", "src/agent.js", 6), result("LLM02.SID.HIGH", "x.py", 1)),
])
def test_tasks_without_the_new_fields_score_as_before(tmp_path, task, doc):
    old = run(V1, doc, truth(task), tmp_path)
    new = run(V2, doc, truth(task), tmp_path)
    assert new.pop("fp_outside_scope") == 0
    assert {k: new[k] for k in old} == old  # v3 only adds keys (task-level flags)
