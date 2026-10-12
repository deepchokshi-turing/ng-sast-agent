"""tools/leak_scan.py packaging checks (provenance keys out of task.toml, exact
package pins, controlled values from vocabulary.json, task_metadata.json key
allowlist and twin diff) and the Dockerfile parsing of tools/check_clean_build.py."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tests.conftest import ROOT
from tests.test_report_and_leak_scan import leak, make_twin, role_free

POS, NEG = "task_11111111", "task_22222222"
VOCAB = {"source_origin": ["adapted_open_source", "purpose_built_synthetic"], "languages": ["python"],
         "frameworks": ["crewai"], "architecture": ["single_agent_tool_calling"]}


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def write_toml(task: Path, task_id: str, variant: str, related: str, extra: str = "",
               python: str = "3.12.15", framework: str = "crewai") -> None:
    (task / "task.toml").write_text(
        'version = "1.0"\n\n[metadata]\n'
        f'task_id = "{task_id}"\nvariant_id = "{variant}"\nrelated_variant_ids = ["{related}"]\n'
        'source_origin = "adapted_open_source"\nlanguages = ["python"]\n'
        f'frameworks = ["{framework}"]\narchitecture = "single_agent_tool_calling"\n'
        f'package_versions = {{ python = "{python}", crewai-tools = "1.14.0a4" }}\n{extra}')


@pytest.fixture
def twins(tmp_path):
    make_twin(tmp_path)
    role_free(tmp_path)
    write_toml(tmp_path / POS, POS, "var_a", "fam_1:var_b")
    write_toml(tmp_path / NEG, NEG, "var_b", "fam_1:var_a")
    (tmp_path / "vocabulary.json").write_text(json.dumps(VOCAB))
    return tmp_path


def both(root: Path, **kw) -> None:
    write_toml(root / POS, POS, "var_a", "fam_1:var_b", **kw)
    write_toml(root / NEG, NEG, "var_b", "fam_1:var_a", **kw)


def test_clean_twins_with_vocabulary_pass(twins):
    proc = leak(twins)
    assert proc.returncode == 0, proc.stdout


# ---- point 10: provenance keys -----------------------------------------------------------------

@pytest.mark.parametrize("line", ['source_url = "https://github.com/x/y"\n', 'source_commit = "abc"\n',
                                  'license = "MIT"\n', 'modifications = "trimmed"\n'])
def test_provenance_keys_in_task_toml_fail(twins, line):
    both(twins, extra=line)
    proc = leak(twins)
    assert proc.returncode == 1
    key = line.split(" =")[0]
    assert f"task.toml has metadata.{key}, which is evaluator-only" in proc.stdout


def test_provenance_keys_fail_without_vocabulary_too(twins):
    (twins / "vocabulary.json").unlink()
    both(twins, extra='license = "MIT"\n')
    assert "task.toml has metadata.license" in leak(twins).stdout


# ---- point 11: exact pins ----------------------------------------------------------------------

@pytest.mark.parametrize("version", [">=3.10", "~=3.12", "==3.12.15", "3.12.*", "3.12.x", "3.10,<4", "^3.12", ""])
def test_range_pins_fail(twins, version):
    both(twins, python=version)
    proc = leak(twins)
    assert proc.returncode == 1
    assert f"package_versions.python = {version!r} is not an exact version" in proc.stdout


@pytest.mark.parametrize("version", ["3.12.15", "1.14.0a4", "2.43.1.dev23", "1.10.2rc2", "0.0.328", "1.0.post1"])
def test_exact_pins_pass(version):
    assert _load("leak_scan").EXACT_VERSION_RE.match(version)


def test_pins_are_checked_without_vocabulary_too(twins):
    (twins / "vocabulary.json").unlink()
    both(twins, python=">=3.10")
    assert "package_versions.python = '>=3.10' is not an exact version" in leak(twins).stdout


def test_vocabulary_is_not_checked_without_vocabulary_json(twins):
    (twins / "vocabulary.json").unlink()
    both(twins, framework="autogen")
    assert leak(twins).returncode == 0


# ---- point 12: controlled values ---------------------------------------------------------------

def test_value_outside_vocabulary_fails(twins):
    both(twins, framework="autogen")
    proc = leak(twins)
    assert proc.returncode == 1
    assert "task.toml frameworks value 'autogen' is not in vocabulary.json" in proc.stdout


def test_unreadable_vocabulary_fails_every_task(twins):
    (twins / "vocabulary.json").write_text("[1, 2")
    proc = leak(twins)
    assert proc.returncode == 1
    assert proc.stdout.count("cannot read vocabulary.json") == 2


# ---- point 13: task_metadata.json ----------------------------------------------------------------

def write_meta(task: Path, task_id: str, variant: str, related: str, **extra) -> None:
    data = {"task_id": task_id, "variant_id": variant, "related_variant_ids": [related],
            "languages": ["python"], "entrypoint": "python -m mini", **extra}
    (task / "task_metadata.json").write_text(json.dumps(data, sort_keys=True))


def test_metadata_view_within_allowlist_passes(twins):
    write_meta(twins / POS, POS, "var_a", "fam_1:var_b")
    write_meta(twins / NEG, NEG, "var_b", "fam_1:var_a")
    assert leak(twins).returncode == 0


def test_metadata_view_key_outside_allowlist_fails(twins):
    write_meta(twins / POS, POS, "var_a", "fam_1:var_b", findings=[])
    write_meta(twins / NEG, NEG, "var_b", "fam_1:var_a", findings=[])
    proc = leak(twins)
    assert proc.returncode == 1
    assert "task_metadata.json has keys outside the scanner-visible allowlist: findings" in proc.stdout


def test_metadata_view_twins_may_differ_only_in_ids(twins):
    write_meta(twins / POS, POS, "var_a", "fam_1:var_b")
    write_meta(twins / NEG, NEG, "var_b", "fam_1:var_a", entrypoint="python -m mini --other")
    proc = leak(twins)
    assert proc.returncode == 1
    assert "task_metadata.json differs between twins in entrypoint" in proc.stdout


def test_metadata_view_in_one_twin_only_fails(twins):
    write_meta(twins / POS, POS, "var_a", "fam_1:var_b")
    assert "task_metadata.json exists in only one twin" in leak(twins).stdout


def test_banned_word_in_metadata_view_fails(twins):
    write_meta(twins / POS, POS, "var_a", "fam_1:var_b", entrypoint="python -m mini --ssrf")
    write_meta(twins / NEG, NEG, "var_b", "fam_1:var_a", entrypoint="python -m mini --ssrf")
    assert "banned word 'ssrf' at task_metadata.json:" in leak(twins).stdout


def test_metadata_view_task_id_must_be_the_folder(twins):
    write_meta(twins / POS, "task_99999999", "var_a", "fam_1:var_b")
    write_meta(twins / NEG, NEG, "var_b", "fam_1:var_a")
    assert "task_metadata.json task_id = 'task_99999999' is not the task id" in leak(twins).stdout


# ---- check_clean_build.py ------------------------------------------------------------------

DOCKERFILE = """ARG SAST_TOOLS_IMAGE=sast-tools:0.5.0
FROM ${SAST_TOOLS_IMAGE} AS sast-tools

FROM python:3.12-slim
COPY --from=sast-tools /opt/sast /opt/sast

WORKDIR /app
COPY repo/ /app/repo/
"""


def test_check_clean_build_reads_the_dockerfile(tmp_path):
    ccb = _load("check_clean_build")
    (tmp_path / "environment").mkdir()
    (tmp_path / "environment" / "Dockerfile").write_text(DOCKERFILE)
    info = ccb.dockerfile_info(tmp_path)
    assert info == {"tools_image": "sast-tools:0.5.0", "base_images": ["sast-tools:0.5.0", "python:3.12-slim"],
                    "repo_dir": "/app/repo"}


def test_check_clean_build_relative_copy_uses_workdir(tmp_path):
    ccb = _load("check_clean_build")
    (tmp_path / "environment").mkdir()
    (tmp_path / "environment" / "Dockerfile").write_text("FROM python:3.12-slim\nWORKDIR /srv\nCOPY repo/ code/\n")
    assert ccb.dockerfile_info(tmp_path)["repo_dir"] == "/srv/code"


def test_check_clean_build_summary_line():
    ccb = _load("check_clean_build")
    r = {"pass": False, "python_version": "3.12.15", "docker_build": {"pass": True},
         "commands": {"build_command": {"pass": True}, "test_command": {"pass": False},
                      "entrypoint": {"pass": True}}}
    assert ccb.summary_line("task_x", r) == "task_x  FAIL  build=pass test=FAIL entrypoint=pass  python=3.12.15"
