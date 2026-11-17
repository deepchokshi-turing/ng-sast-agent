"""Tasker QC support: tools/pair_variants.py (VARIANTS entries for a downloaded pair), the
--warn-unverified-upstream mode of tools/leak_scan.py, and the vocabulary shipped with the tooling."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT

PAIR_VARIANTS = ROOT / "tools" / "pair_variants.py"
LEAK = ROOT / "tools" / "leak_scan.py"
FAM = "demo-fam"


def run(*args: str | Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True)


def write_view(task: Path, entry: dict) -> None:
    (task / "tests").mkdir(parents=True, exist_ok=True)
    (task / "tests" / "evaluator_view.json").write_text(json.dumps({"variant_map_entry": entry}))


def make_pair(root: Path, views: bool = True) -> None:
    for letter, role, twin, tid, var in (("a", "positive", "b", "task_aaaaaaaa", "var_b"),
                                         ("b", "negative", "a", "task_bbbbbbbb", "var_a")):
        t = root / f"{FAM}-{letter}"
        t.mkdir(parents=True)
        (t / "task.toml").write_text(f'[metadata]\ntask_id = "{tid}"\nvariant_id = "{var}"\nfamily_id = "fam_1"\n')
        if views:
            write_view(t, {"delivery_id": "D001", "family_id": "fam_1", "family_key": FAM, "role": role,
                           "slot": "P001", "task_id": tid, "twin": f"{FAM}-{twin}", "variant_id": var})


# ---- pair_variants.py ----------------------------------------------------------------------

def test_entries_come_from_the_evaluator_views_of_a_download(tmp_path):
    make_pair(tmp_path)
    proc = run(PAIR_VARIANTS, tmp_path, FAM, "")
    assert proc.returncode == 0, proc.stderr
    assert "evaluator_view.json" in proc.stdout
    v = json.loads((tmp_path / "VARIANTS.json").read_text())
    assert v[f"{FAM}-a"] == {"family": FAM, "delivery_id": "D001", "family_id": "fam_1", "role": "positive",
                             "slot": "P001", "task_id": "task_aaaaaaaa", "twin": f"{FAM}-b", "variant_id": "var_b"}
    assert v[f"{FAM}-b"]["role"] == "negative" and v[f"{FAM}-b"]["task_id"] == "task_bbbbbbbb"


def test_a_dataset_variants_file_wins(tmp_path):
    make_pair(tmp_path)
    known = {f"{FAM}-a": {"family": FAM, "role": "positive", "twin": f"{FAM}-b", "task_id": "x"},
             f"{FAM}-b": {"family": FAM, "role": "negative", "twin": f"{FAM}-a", "task_id": "y"},
             "other-a": {}}
    f = tmp_path / "dataset_VARIANTS.json"
    f.write_text(json.dumps(known))
    proc = run(PAIR_VARIANTS, tmp_path, FAM, f)
    assert proc.returncode == 0 and str(f) in proc.stdout
    v = json.loads((tmp_path / "VARIANTS.json").read_text())
    assert set(v) == {f"{FAM}-a", f"{FAM}-b"} and v[f"{FAM}-a"]["task_id"] == "x"


def test_falls_back_to_task_toml_without_views(tmp_path):
    make_pair(tmp_path, views=False)
    proc = run(PAIR_VARIANTS, tmp_path, FAM, tmp_path / "missing.json")
    assert proc.returncode == 0 and "synthesised" in proc.stdout
    v = json.loads((tmp_path / "VARIANTS.json").read_text())
    assert v[f"{FAM}-a"]["role"] == "positive" and v[f"{FAM}-a"]["task_id"] == "task_aaaaaaaa"


def test_a_view_with_the_wrong_role_is_not_trusted(tmp_path):
    make_pair(tmp_path)
    write_view(tmp_path / f"{FAM}-a", {"family_key": FAM, "role": "negative", "twin": f"{FAM}-b"})
    proc = run(PAIR_VARIANTS, tmp_path, FAM, "")
    assert "synthesised" in proc.stdout


# ---- leak_scan.py --warn-unverified-upstream --------------------------------------------------

def leak_twin(root: Path, app: str, readme: str = "Notes.\n") -> None:
    """A minimal pair with no _work/ folder (a download), whose app.java is the given text."""
    for letter in ("a", "b"):
        t = root / f"{FAM}-{letter}"
        repo = t / "environment" / "repo" / "src"
        repo.mkdir(parents=True)
        (t / "task.toml").write_text('version = "1.0"\n')
        (t / "environment" / "Dockerfile").write_text("FROM python:3.12-slim\nCOPY repo/ /app/repo/\n")
        (repo / "App.java").write_text(app)
        (repo / "README.md").write_text(readme)
        (t / "validation").mkdir()
        (t / "validation" / "provenance.json").write_text(json.dumps(
            {"source_url": "https://github.com/example/proj", "source_commit": "abc123"}))


CODE_HIT = 'class App {\n  String salt = "derived with a fixed public salt";\n}\n'


def test_code_hit_without_upstream_is_a_problem_by_default(tmp_path):
    leak_twin(tmp_path, CODE_HIT)
    proc = run(LEAK, tmp_path)
    assert proc.returncode == 1, proc.stdout
    assert "banned word 'fixed' at environment/repo/src/App.java:2" in proc.stdout


def test_code_hit_without_upstream_is_a_warning_with_a_link(tmp_path):
    leak_twin(tmp_path, CODE_HIT)
    proc = run(LEAK, tmp_path, "--warn-unverified-upstream")
    assert proc.returncode == 0, proc.stdout
    assert f"{FAM}-a  pass  (1 warnings)" in proc.stdout
    assert "https://github.com/example/proj/blob/abc123/src/App.java#L2" in proc.stdout


def test_comment_hit_stays_a_problem_in_warn_mode(tmp_path):
    leak_twin(tmp_path, "class App {\n  // the fixed version checks this\n}\n")
    proc = run(LEAK, tmp_path, "--warn-unverified-upstream")
    assert proc.returncode == 1, proc.stdout
    assert "banned word 'fixed' at environment/repo/src/App.java:2" in proc.stdout


def test_prose_hit_stays_a_problem_in_warn_mode(tmp_path):
    leak_twin(tmp_path, "class App {}\n", readme="This release fixed the bug.\n")
    proc = run(LEAK, tmp_path, "--warn-unverified-upstream")
    assert proc.returncode == 1, proc.stdout
    assert "environment/repo/src/README.md:1" in proc.stdout


def test_warn_mode_does_not_apply_when_upstream_trees_exist(tmp_path):
    leak_twin(tmp_path, CODE_HIT)
    up = tmp_path / FAM / "_work" / "upstream-positive" / "src"
    up.mkdir(parents=True)
    (up / "App.java").write_text("class App {}\n")  # the hit line is task-authored
    proc = run(LEAK, tmp_path, "--warn-unverified-upstream")
    assert proc.returncode == 1 and "warning:" not in proc.stdout


# ---- shipped vocabulary ---------------------------------------------------------------------

def test_shipped_vocabulary_matches_the_dataset():
    shipped = ROOT / "task_format" / "vocabulary.json"
    assert isinstance(json.loads(shipped.read_text(encoding="utf-8")), dict)
    dataset = ROOT.parent / "tasks" / "vocabulary.json"
    if not dataset.is_file():
        pytest.skip("no tasks/ dataset next to the tooling")
    assert json.loads(shipped.read_text(encoding="utf-8")) == json.loads(dataset.read_text(encoding="utf-8")), \
        "copy tasks/vocabulary.json to ng-sast-agent/task_format/vocabulary.json"
