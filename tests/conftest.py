from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
#: Sample tasks the tests run against, tracked in git. Harbor can run them in place.
SAMPLE_TASKS = FIXTURES / "tasks"

# The sample tasks carry their own repos and repro tests. They are data here,
# not part of this suite.
collect_ignore = ["fixtures"]


#: Where the real-bundle tests look for the CodeQL 2.27.1 CLI: $CODEQL_BIN (the
#: ``codeql`` launcher inside an unpacked bundle), else the tools image location.
CODEQL_DEFAULT_BIN = Path("/opt/sast/codeql/codeql")


def codeql_bin() -> Path | None:
    """The CodeQL CLI for the real-bundle tests, or None when there is none."""
    configured = os.environ.get("CODEQL_BIN")
    candidate = Path(configured) if configured else CODEQL_DEFAULT_BIN
    return candidate if candidate.is_file() and os.access(candidate, os.X_OK) else None


@pytest.fixture
def codeql_bundle() -> Path:
    """The unpacked CodeQL bundle folder. Skips, saying why, when no CLI is found."""
    cli = codeql_bin()
    if cli is None:
        where = os.environ.get("CODEQL_BIN") or str(CODEQL_DEFAULT_BIN)
        pytest.skip(f"CodeQL CLI not found at {where}: set CODEQL_BIN to the codeql launcher of an "
                    "unpacked 2.27.1 bundle to run the real-bundle tests")
    return cli.parent


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
