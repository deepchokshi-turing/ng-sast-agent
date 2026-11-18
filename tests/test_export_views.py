"""tools/export_views.py: the scanner-visible task_metadata.json holds only the
allowlisted keys, the output is deterministic, and the proof step fails (and
writes nothing) when evaluator-only content reaches scanner input."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT

SCRIPT = ROOT / "tools" / "export_views.py"
_spec = importlib.util.spec_from_file_location("export_views", SCRIPT)
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)

POS, NEG = "task_11111111", "task_22222222"
RATIONALE = "The model picks any path and the notes tool writes there without any check at all."
MANIFEST = {k: f"{k} text" for k in ev.MANIFEST_FIELDS}


def toml_text(task_id: str, variant: str, related: str, entrypoint: str = "python -m mini") -> str:
    return f'''version = "1.0"

[metadata]
author_name = "Turing"
schema_version = "0.1"
task_id = "{task_id}"
repository_id = "repo_x"
family_id = "fam_1"
variant_id = "{variant}"
related_variant_ids = ["{related}"]
source_origin = "adapted_open_source"
languages = ["python"]
frameworks = ["crewai"]
package_versions = {{ python = "3.12.15", crewai-tools = "1.14.0a4" }}
architecture = "single_agent_tool_calling"
architecture_notes = "single-agent notes assistant with a file writing tool"
entrypoint = "{entrypoint}"
build_command = "python -m compileall -q src"
test_command = "python -m unittest discover -s tests -q"
scanner_roots = ["src", "config", "fixtures", "security_manifest.json", "pyproject.toml"]
excluded_paths = ["tests"]

[agent]
timeout_sec = 900.0
'''


def make_task(root: Path, name: str, variant: str, related: str, role: str, tool: str) -> Path:
    t = root / name
    repo = t / "environment" / "repo"
    (repo / "src" / "mini").mkdir(parents=True)
    (t / "tests").mkdir()
    (t / "validation").mkdir()
    (t / "task.toml").write_text(toml_text(name, variant, related))
    (repo / "security_manifest.json").write_text(json.dumps(MANIFEST))
    (repo / "src" / "mini" / "app.py").write_text("print('hi')\n")
    (repo / "src" / "mini" / "tool.py").write_text(tool)
    gt = {"schema_version": "gt-0.1", "task_id": name, "variant_role": role, "fix_changed_files": ["src/mini/tool.py"]}
    if role == "positive":
        gt["risk_types_present"] = ["excessive_agency"]
        gt["findings"] = [{"id": "F1", "rule_id": "LLM03.EA.FUNCTIONALITY", "rationale": RATIONALE,
                           "primary_location": {"file": "src/mini/tool.py", "start_line": 2},
                           "recommendations": {"required_any_of": ["REC-POLICY-GATE"]}}]
        gt["negative_analyses"] = []
    else:
        gt["risk_types_present"] = []
        gt["findings"] = []
        gt["negative_analyses"] = [{"id": "N1", "rationale": "The tool now resolves the path inside the notes folder."}]
    (t / "tests" / "ground_truth.json").write_text(json.dumps(gt))
    (t / "validation" / "provenance.json").write_text(json.dumps({
        "task_id": name, "source_url": "https://example.com/upstream", "source_commit": "a" * 40,
        "license": "MIT", "modifications": "Trimmed to the notes tool.", "qc": {"label_leak_scan": "pass"}}))
    return t


@pytest.fixture
def tasks(tmp_path: Path) -> Path:
    make_task(tmp_path, POS, "var_a", "fam_1:var_b", "positive", "def write(p):\n    return open(p, 'w')\n")
    make_task(tmp_path, NEG, "var_b", "fam_1:var_a", "negative", "def write(p):\n    return inside(p)\n")
    (tmp_path / "VARIANTS.json").write_text(json.dumps({
        POS: {"family": "abc", "role": "positive", "twin": NEG},
        NEG: {"family": "abc", "role": "negative", "twin": POS}}))
    return tmp_path


def run(root: Path, *flags) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), str(root), *flags], capture_output=True, text=True)


def test_metadata_has_exactly_the_allowlisted_keys(tasks):
    proc = run(tasks)
    assert proc.returncode == 0, proc.stdout
    meta = json.loads((tasks / POS / "task_metadata.json").read_text(encoding="utf-8"))
    assert set(meta) == ev.METADATA_ALLOWLIST
    assert "architecture_notes" not in meta and "author_name" not in meta
    assert meta["security_manifest_path"] == "security_manifest.json"
    assert meta["security_manifest_fields"] == list(ev.MANIFEST_FIELDS)
    assert meta["package_versions"] == {"python": "3.12.15", "crewai-tools": "1.14.0a4"}


def test_evaluator_view_holds_labels_and_provenance(tasks):
    assert run(tasks).returncode == 0
    view = json.loads((tasks / POS / "tests" / "evaluator_view.json").read_text(encoding="utf-8"))
    assert view["task_id"] == POS
    assert view["variant_role"] == "positive"
    assert view["source_url"] == "https://example.com/upstream" and view["license"] == "MIT"
    assert view["findings"][0]["rule_id"] == "LLM03.EA.FUNCTIONALITY"
    assert view["rationale"] == {"F1": RATIONALE}
    assert view["recommendations"] == {"F1": {"required_any_of": ["REC-POLICY-GATE"]}}
    assert view["provenance"]["qc"] == {"label_leak_scan": "pass"}
    assert "fix_changed_files" in view["ground_truth_other"]
    neg = json.loads((tasks / NEG / "tests" / "evaluator_view.json").read_text(encoding="utf-8"))
    assert neg["rationale"] == {"N1": "The tool now resolves the path inside the notes folder."}


def test_output_is_deterministic_with_sorted_keys(tasks):
    assert run(tasks).returncode == 0
    files = [tasks / POS / "task_metadata.json", tasks / POS / "tests" / "evaluator_view.json"]
    first = [f.read_bytes() for f in files]
    assert run(tasks).returncode == 0
    assert [f.read_bytes() for f in files] == first
    for raw in first:
        assert b"\r\n" not in raw and raw.endswith(b"\n")
        data = json.loads(raw)
        assert list(data) == sorted(data)
    assert run(tasks, "--check").returncode == 0


def test_check_reports_stale_views(tasks):
    assert run(tasks).returncode == 0
    gt = tasks / POS / "tests" / "ground_truth.json"
    data = json.loads(gt.read_text())
    data["findings"][0]["severity"] = "high"
    gt.write_text(json.dumps(data))
    proc = run(tasks, "--check")
    assert proc.returncode == 1 and "stale" in proc.stdout


def test_rationale_in_one_twins_code_fails_the_proof_and_writes_nothing(tasks):
    (tasks / POS / "environment" / "repo" / "src" / "mini" / "tool.py").write_text(
        f"# {RATIONALE}\ndef write(p):\n    return open(p, 'w')\n")
    proc = run(tasks)
    assert proc.returncode == 1
    assert "environment/repo/src/mini/tool.py" in proc.stdout
    assert not (tasks / POS / "task_metadata.json").exists()
    assert not (tasks / POS / "tests" / "evaluator_view.json").exists()


def test_text_both_twins_share_identically_is_allowed(tasks):
    for name in (POS, NEG):
        (tasks / name / "environment" / "repo" / "src" / "mini" / "app.py").write_text(f"# {RATIONALE}\n")
    assert run(tasks).returncode == 0


def test_rule_id_in_a_metadata_value_fails_the_proof(tasks):
    toml = tasks / POS / "task.toml"
    toml.write_text(toml_text(POS, "var_a", "fam_1:var_b", entrypoint="python -m mini LLM03.EA.FUNCTIONALITY"))
    proc = run(tasks)
    assert proc.returncode == 1
    assert "LLM03.EA.FUNCTIONALITY" in proc.stdout and "task_metadata.json" in proc.stdout


def test_role_word_in_a_metadata_value_fails_the_proof(tasks):
    toml = tasks / NEG / "task.toml"
    toml.write_text(toml_text(NEG, "var_b", "fam_1:var_a", entrypoint="python -m mini --fixed"))
    proc = run(tasks)
    assert proc.returncode == 1 and "role word" in proc.stdout


def test_prove_rejects_keys_outside_the_allowlist(tasks):
    meta = ev.build_metadata(tasks / POS)
    view = ev.build_evaluator(tasks / POS, json.loads((tasks / "VARIANTS.json").read_text()))
    assert ev.prove(tasks / POS, meta, view, tasks / NEG) == []
    leaked = dict(meta, findings=["F1"], variant_role="x")
    problems = ev.prove(tasks / POS, leaked, view, tasks / NEG)
    assert any("outside the allowlist" in p for p in problems)
    assert any("evaluator-only key 'findings'" in p for p in problems)


def test_missing_manifest_field_is_reported(tasks):
    manifest = dict(MANIFEST)
    del manifest["actors"]
    (tasks / POS / "environment" / "repo" / "security_manifest.json").write_text(json.dumps(manifest))
    proc = run(tasks)
    assert proc.returncode == 1 and "lacks actors" in proc.stdout
