from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
DEV_TASKS = ROOT / "dev" / "tasks"


def fixture_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def grade(task: str, sarif: dict, tmp_path: Path) -> dict:
    """Score a SARIF document with the task's own grade.py, as Harbor's verifier does."""
    sarif_file = tmp_path / "findings.sarif"
    sarif_file.write_text(json.dumps(sarif))
    out = tmp_path / "verifier"
    subprocess.run(
        [sys.executable, str(DEV_TASKS / task / "tests" / "grade.py"),
         "--sarif", str(sarif_file),
         "--truth", str(DEV_TASKS / task / "tests" / "ground_truth.json"),
         "--out", str(out)],
        check=True, capture_output=True,
    )
    return json.loads((out / "reward.json").read_text())


@pytest.fixture
def grade_sarif(tmp_path):
    return lambda task, sarif: grade(task, sarif, tmp_path)
