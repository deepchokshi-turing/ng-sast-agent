"""tools/leak_scan.py checks on the ids in task.toml (task_id equals the folder
name, no role word in task_id, variant_id or related_variant_ids), on twin
instruction.md files, and on a VARIANTS.json that cannot be read."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_report_and_leak_scan import leak, make_twin, role_free

POS, NEG = "task_11111111", "task_22222222"


def write_ids(task: Path, task_id: str, variant: str, related: str) -> None:
    (task / "task.toml").write_text(
        'version = "1.0"\n\n[metadata]\n'
        f'task_id = "{task_id}"\nvariant_id = "{variant}"\nrelated_variant_ids = ["{related}"]\n')


@pytest.fixture
def twins(tmp_path):
    """A clean role-free twin pair with ids in task.toml and a shared instruction.md."""
    make_twin(tmp_path)
    role_free(tmp_path)
    write_ids(tmp_path / POS, POS, "var_a", "fam_1:var_b")
    write_ids(tmp_path / NEG, NEG, "var_b", "fam_1:var_a")
    for name in (POS, NEG):
        (tmp_path / name / "instruction.md").write_text("Scan the repository and write findings.sarif.\n")
    return tmp_path


def test_clean_role_free_twins_pass(twins):
    proc = leak(twins)
    assert proc.returncode == 0, proc.stdout
    assert f"{POS}  pass" in proc.stdout and f"{NEG}  pass" in proc.stdout


# ---- task_id and role words --------------------------------------------------------------

def test_task_id_must_equal_the_folder_name(twins):
    write_ids(twins / NEG, "task_33333333", "var_b", "fam_1:var_a")
    proc = leak(twins)
    assert proc.returncode == 1, proc.stdout
    assert "task.toml metadata.task_id = 'task_33333333' is not the folder name 'task_22222222'" in proc.stdout
    assert f"{NEG}  FAIL" in proc.stdout and f"{POS}  pass" in proc.stdout


def test_role_word_in_task_id_fails_even_when_the_folder_has_it_too(tmp_path):
    # The review's case: old role-bearing task_id in task.toml. Before, task_id was exempt from the
    # twin diff and "positive"/"negative" were not banned, so this passed.
    make_twin(tmp_path)
    for role in ("positive", "negative"):
        write_ids(tmp_path / f"task_abc_{role}", f"task_abc_{role}", "var_a", "fam_1:var_b")
    proc = leak(tmp_path)
    assert proc.returncode == 1, proc.stdout
    assert "role word 'positive' in task.toml metadata.task_id = 'task_abc_positive'" in proc.stdout
    assert "role word 'negative' in task.toml metadata.task_id = 'task_abc_negative'" in proc.stdout


def test_role_free_folder_with_old_role_task_id_fails(twins):
    write_ids(twins / POS, "task_abc_positive", "var_a", "fam_1:var_b")
    proc = leak(twins)
    assert proc.returncode == 1, proc.stdout
    assert "is not the folder name 'task_11111111'" in proc.stdout
    assert "role word 'positive' in task.toml metadata.task_id" in proc.stdout
    assert f"{POS}  FAIL" in proc.stdout


@pytest.mark.parametrize("variant, related, word", [
    ("var_positive", "fam_1:var_b", "positive"),
    ("var_a", "fam_1:negative", "negative"),
    ("var_vulnerable", "fam_1:var_b", "vulnerab"),
    ("var_a", "fam_1:var_patched", "patch"),
    ("var_fixed", "fam_1:var_b", "fixed"),
    ("var_a", "fam_1:var_benign", "benign"),
    ("var_neg", "fam_1:var_b", "neg"),
    ("var_a", "fam_1:pos", "pos"),
    ("vuln-1", "fam_1:var_b", "vuln"),
    ("var_a", "fam_1:safe", "safe"),
    ("unsafe.a", "fam_1:var_b", "unsafe"),
    ("var_a", "fam_1:fix", "fix"),
])
def test_role_word_in_variant_ids_fails(twins, variant, related, word):
    write_ids(twins / NEG, NEG, variant, related)
    proc = leak(twins)
    assert proc.returncode == 1, proc.stdout
    assert f"role word '{word}' in task.toml metadata." in proc.stdout
    assert f"{NEG}  FAIL" in proc.stdout


@pytest.mark.parametrize("variant, related", [
    ("var_b", "fam_1:var_a"),
    ("var_c", "fam_posh:var_a"),      # short words count only as a whole part
    ("var_b", "fam_negx:var_a"),
    ("var_b", "fam_9f3e:var_a"),
])
def test_ids_without_role_words_pass(twins, variant, related):
    write_ids(twins / NEG, NEG, variant, related)
    write_ids(twins / POS, POS, "var_a", related.rsplit(":", 1)[0] + ":var_b")
    proc = leak(twins)
    assert "role word" not in proc.stdout and "not the folder name" not in proc.stdout, proc.stdout
    assert proc.returncode == 0, proc.stdout


def test_task_toml_without_ids_is_not_required_to_have_them(tmp_path):
    make_twin(tmp_path)  # task.toml holds only version
    assert leak(tmp_path).returncode == 0


# ---- twin instruction.md -----------------------------------------------------------------

def test_twin_instructions_that_differ_fail_both_twins(twins):
    (twins / NEG / "instruction.md").write_text("Scan the repository and write findings.sarif. Take care.\n")
    proc = leak(twins)
    assert proc.returncode == 1, proc.stdout
    assert proc.stdout.count("instruction.md differs between twins") == 2
    assert f"{POS}  FAIL" in proc.stdout and f"{NEG}  FAIL" in proc.stdout


def test_twin_instruction_line_endings_count(twins):
    (twins / POS / "instruction.md").write_bytes(b"Scan the repository and write findings.sarif.\n")
    (twins / NEG / "instruction.md").write_bytes(b"Scan the repository and write findings.sarif.\r\n")
    proc = leak(twins)
    assert proc.returncode == 1 and "instruction.md differs between twins" in proc.stdout


def test_instruction_in_only_one_twin_fails(twins):
    (twins / NEG / "instruction.md").unlink()
    proc = leak(twins)
    assert proc.returncode == 1 and proc.stdout.count("instruction.md exists in only one twin") == 2


def test_twins_without_instructions_pass(twins):
    for name in (POS, NEG):
        (twins / name / "instruction.md").unlink()
    assert leak(twins).returncode == 0


# ---- malformed VARIANTS.json -------------------------------------------------------------

@pytest.mark.parametrize("text", [
    b'{"task_11111111": {"twin": ',         # truncated JSON
    b'["task_11111111", "task_22222222"]',  # not an object
    b'{"task_11111111": "task_22222222"}',  # entry not an object
    b"\xff\xfe{}",                          # not UTF-8
])
def test_malformed_variants_is_a_reported_failure(twins, text):
    (twins / "VARIANTS.json").write_bytes(text)
    proc = leak(twins, "--write-qc")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.stdout.count("cannot read VARIANTS.json, so no twin was checked") == 2
    assert f"{POS}  FAIL" in proc.stdout and f"{NEG}  FAIL" in proc.stdout
    for name in (POS, NEG):
        qc = json.loads((twins / name / "validation" / "provenance.json").read_text())["qc"]
        assert qc["label_leak_scan"] == "fail"

