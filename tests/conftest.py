from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
#: Sample tasks the tests run against, tracked in git. dev/tasks is a local,
#: untracked working area. These are a copy of it and are what the tests read.
SAMPLE_TASKS = FIXTURES / "tasks"
#: Old name, kept for test modules that still import it.
DEV_TASKS = SAMPLE_TASKS

# The sample tasks carry their own repos and repro tests. They are data here,
# not part of this suite.
collect_ignore = ["fixtures"]


def fixture_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def grade(task: str, sarif: dict, tmp_path: Path) -> dict:
    """Score a SARIF document with the task's own grade.py, as Harbor's verifier does."""
    sarif_file = tmp_path / "findings.sarif"
    sarif_file.write_text(json.dumps(sarif))
    out = tmp_path / "verifier"
    subprocess.run(
        [sys.executable, str(SAMPLE_TASKS / task / "tests" / "grade.py"),
         "--sarif", str(sarif_file),
         "--truth", str(SAMPLE_TASKS / task / "tests" / "ground_truth.json"),
         "--out", str(out)],
        check=True, capture_output=True,
    )
    return json.loads((out / "reward.json").read_text())


@pytest.fixture
def grade_sarif(tmp_path):
    return lambda task, sarif: grade(task, sarif, tmp_path)


def pytest_sessionstart(session):
    # A missing sample-task folder is a broken checkout, not a reason to skip.
    if not (SAMPLE_TASKS / "task_7f3a91" / "tests" / "grade.py").is_file():
        raise pytest.UsageError(
            f"sample tasks are missing: {SAMPLE_TASKS} must hold the tracked task fixtures"
        )
