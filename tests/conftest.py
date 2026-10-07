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


# dev/tasks is not tracked in git (it is a local sample-task area). In a fresh
# clone without it, tests that read those sample tasks are skipped, not failed.
_DEV_MARKERS = ("DEV_TASKS", "grade_sarif", "dev/tasks", '"dev"')


def _uses_dev_tasks(fn, seen=None) -> bool:
    """True if the test, or a module-level helper it calls, reads dev/tasks."""
    import inspect
    import re

    seen = seen if seen is not None else set()
    if fn is None or fn in seen:
        return False
    seen.add(fn)
    try:
        src = inspect.getsource(fn)
    except (OSError, TypeError):
        return False
    if any(m in src for m in _DEV_MARKERS):
        return True
    module = inspect.getmodule(fn)
    for name in set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", src)):
        obj = getattr(module, name, None)
        if isinstance(obj, Path) and DEV_TASKS in (obj, *obj.parents):
            return True
        if (inspect.isfunction(obj) or inspect.isclass(obj)) and getattr(obj, "__module__", None) == module.__name__:
            if _uses_dev_tasks(obj, seen):
                return True
    return False


def pytest_collection_modifyitems(config, items):
    if DEV_TASKS.is_dir():
        return
    skip = pytest.mark.skip(reason="dev/tasks is not present (untracked sample tasks)")
    for item in items:
        if "grade_sarif" in getattr(item, "fixturenames", ()) or _uses_dev_tasks(getattr(item, "function", None)):
            item.add_marker(skip)
