"""/opt/sast/MANIFEST.json (audit L6): the writer the tools image build runs, the
reader each installer calls, and how the three installers record it."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sast import manifest
from sast.codeql import pins as codeql_pins
from sast.semgrep import pins as semgrep_pins
from sast.sonarqube import pins as sonar_pins
from tests.conftest import ROOT

DOCKERFILE = ROOT / "images" / "sast-tools" / "Dockerfile"
BUILD_SCRIPT = ROOT / "tools" / "build_tools_image.sh"
ALL_PINS = {"semgrep": semgrep_pins.as_dict(), "codeql": codeql_pins.as_dict(), "sonar-scanner": sonar_pins.as_dict()}


def exe(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def fake_tree(root: Path) -> Path:
    """A small /opt/sast: the three tool parts, plus loose files the agents upload."""
    exe(root / "python" / "bin" / "python3.12", "#!/bin/sh\n")
    exe(root / "venv" / "bin" / "semgrep", f"#!/bin/sh\necho {semgrep_pins.SEMGREP_VERSION}\n")
    (root / "venv" / "bin" / "python").symlink_to("../../python/bin/python3.12")
    for d in semgrep_pins.RULES_DIRS:
        merged = root / "rules-merged" / (d.replace("/", "_") + ".yaml")
        merged.parent.mkdir(parents=True, exist_ok=True)
        merged.write_text("rules: []\n")
    (root / "rules" / "python").mkdir(parents=True)
    (root / "rules" / "python" / "a.yaml").write_text("rules: []\n")
    exe(root / "bin" / "uv", "#!/bin/sh\n")
    (root / "install.json").write_text(json.dumps({"pins": semgrep_pins.as_dict(), "semgrep_version": "1.179.0"}))
    exe(root / "codeql" / "codeql", "#!/bin/sh\n")
    (root / "codeql" / "qlpacks").mkdir()
    (root / "codeql" / "qlpacks" / "x.yml").write_text("name: x\n")
    exe(root / "sonar-scanner" / "bin" / "sonar-scanner", "#!/bin/sh\necho 'SonarScanner CLI'\n")
    (root / "sonar-scanner" / "lib").mkdir()
    (root / "sonar-scanner" / "lib" / f"sonar-scanner-cli-{sonar_pins.SONAR_SCANNER_VERSION}.jar").write_bytes(b"jar")
    (root / "install.py").write_text("# uploaded at setup\n")
    (root / "home").mkdir()
    return root


def write_manifest(root: Path, pins: dict | None = None) -> dict:
    pins_file = root.parent / "manifest_pins.json"
    pins_file.write_text(json.dumps(ALL_PINS if pins is None else pins))
    assert manifest.write(str(root), str(pins_file)) == 0
    return json.loads((root / "MANIFEST.json").read_text())


# ---- writer --------------------------------------------------------------------

def test_writer_records_versions_files_and_tree_digests(tmp_path):
    root = fake_tree(tmp_path / "sast")
    doc = write_manifest(root)
    assert doc["tools"]["semgrep"]["version"] == semgrep_pins.SEMGREP_VERSION
    assert doc["tools"]["codeql"]["version"] == codeql_pins.CODEQL_VERSION
    assert doc["tools"]["sonar-scanner"]["version"] == sonar_pins.SONAR_SCANNER_VERSION
    assert doc["tools"]["codeql"]["pins"] == ALL_PINS["codeql"]

    files = doc["files"]
    assert "MANIFEST.json" not in files and "install.py" in files and doc["file_count"] == len(files)
    data = (root / "rules" / "python" / "a.yaml").read_bytes()
    assert files["rules/python/a.yaml"] == {"sha256": hashlib.sha256(data).hexdigest(), "mode": "100644",
                                            "size": len(data)}
    assert files["codeql/codeql"]["mode"] == "100755"
    link = files["venv/bin/python"]
    assert link["mode"].startswith("120") and link["size"] == 0
    assert link["sha256"] == hashlib.sha256(b"../../python/bin/python3.12").hexdigest()

    # The tree digest, computed independently over sorted (path, sha256, mode).
    lines = sorted(f"{p}\0{v['sha256']}\0{v['mode']}\n" for p, v in files.items())
    assert doc["tree_digest"] == hashlib.sha256("".join(lines).encode()).hexdigest()
    semgrep = {p: v for p, v in files.items() if p.split("/")[0] in manifest.PARTS["semgrep"]}
    lines = sorted(f"{p}\0{v['sha256']}\0{v['mode']}\n" for p, v in semgrep.items())
    assert doc["parts"]["semgrep"]["tree_digest"] == hashlib.sha256("".join(lines).encode()).hexdigest()
    assert doc["parts"]["semgrep"]["files"] == len(semgrep)
    assert doc["parts"]["codeql"]["files"] == 2 and doc["parts"]["sonar-scanner"]["files"] == 2


def test_writer_is_deterministic_and_sees_mode_changes(tmp_path):
    root = fake_tree(tmp_path / "sast")
    first = write_manifest(root)
    assert write_manifest(root)["tree_digest"] == first["tree_digest"]  # MANIFEST.json itself is left out
    (root / "rules" / "python" / "a.yaml").chmod(0o755)
    second = write_manifest(root)
    assert second["parts"]["semgrep"]["tree_digest"] != first["parts"]["semgrep"]["tree_digest"]
    assert second["parts"]["codeql"]["tree_digest"] == first["parts"]["codeql"]["tree_digest"]


def test_writer_refuses_missing_version_pins(tmp_path, capsys):
    root = fake_tree(tmp_path / "sast")
    pins_file = tmp_path / "p.json"
    pins_file.write_text(json.dumps({**ALL_PINS, "codeql": {}}))
    assert manifest.write(str(root), str(pins_file)) == 2
    assert "no version pinned for codeql" in capsys.readouterr().out
    assert not (root / "MANIFEST.json").exists()


# ---- reader --------------------------------------------------------------------

def test_reader_verifies_a_tool_part(tmp_path):
    root = fake_tree(tmp_path / "sast")
    doc = write_manifest(root)
    raw = (root / "MANIFEST.json").read_bytes()
    result = manifest.check("semgrep", root=str(root))
    assert result["status"] == "verified" and result["verified"] is True and result["present"] is True
    assert result["manifest_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["tree_digest"] == doc["tree_digest"]
    assert result["tool_tree_digest"] == doc["parts"]["semgrep"]["tree_digest"]
    assert result["tool_version"] == semgrep_pins.SEMGREP_VERSION and "recompute_seconds" in result


def test_files_the_agents_upload_do_not_break_verification(tmp_path):
    root = fake_tree(tmp_path / "sast")
    write_manifest(root)
    (root / "install.py").write_text("# a newer installer\n")
    (root / "pins.json").write_text("{}")
    (root / "home" / ".sonar").mkdir()
    (root / "out").mkdir()
    assert manifest.check("sonar-scanner", root=str(root))["status"] == "verified"
    assert manifest.check("semgrep", root=str(root))["status"] == "verified"


@pytest.mark.parametrize("change", [
    lambda r: (r / "venv" / "bin" / "semgrep").write_text("#!/bin/sh\necho other\n"),
    lambda r: (r / "rules" / "python" / "extra.yaml").write_text("rules: []\n"),
    lambda r: (r / "rules" / "python" / "a.yaml").unlink(),
    lambda r: (r / "bin" / "uv").chmod(0o644),
])
def test_reader_reports_a_mismatch_without_failing(tmp_path, change):
    root = fake_tree(tmp_path / "sast")
    doc = write_manifest(root)
    change(root)
    result = manifest.check("semgrep", root=str(root))
    assert result["status"] == "mismatch" and result["verified"] is False
    assert result["recomputed_tree_digest"] != doc["parts"]["semgrep"]["tree_digest"]
    # Other tools' parts are not affected.
    assert manifest.check("codeql", root=str(root))["status"] == "verified"


def test_reader_without_recompute_records_the_digest_only(tmp_path):
    root = fake_tree(tmp_path / "sast")
    doc = write_manifest(root)
    (root / "codeql" / "codeql").write_text("tampered")  # not seen without recomputing
    result = manifest.check("codeql", root=str(root), recompute="bundle too large")
    assert result["status"] == "not_recomputed" and result["verified"] is False
    assert result["reason"] == "bundle too large"
    assert result["tool_tree_digest"] == doc["parts"]["codeql"]["tree_digest"]


def test_reader_stops_at_its_time_limit(tmp_path):
    root = fake_tree(tmp_path / "sast")
    write_manifest(root)
    result = manifest.check("semgrep", root=str(root), max_seconds=-1)
    assert result["status"] == "not_recomputed" and "stopped after" in result["reason"]


def test_reader_without_or_with_a_broken_manifest(tmp_path, monkeypatch):
    root = fake_tree(tmp_path / "sast")
    monkeypatch.setenv("SAST_MANIFEST_ROOT", str(root))
    assert manifest.check("semgrep") == {"present": False, "path": str(root / "MANIFEST.json"),
                                         "verified": False, "status": "absent"}
    (root / "MANIFEST.json").write_text("{not json")
    result = manifest.check("semgrep")
    assert result["status"] == "unreadable" and result["present"] is True and result["verified"] is False


def test_manifest_module_is_stdlib_only_and_python36():
    text = (ROOT / "sast" / "manifest.py").read_text()
    ast.parse(text, feature_version=(3, 6))
    assert "f\"" not in text and "f'" not in text and "capture_output" not in text
    imports = {line.split()[1].split(".")[0] for line in text.splitlines() if line.startswith(("import ", "from "))}
    assert imports <= {"hashlib", "json", "os", "stat", "sys", "time"}


# ---- the installers record it ------------------------------------------------------

def result_of(stdout: str) -> dict:
    lines = [line for line in stdout.splitlines() if line.startswith("INSTALL_RESULT ")]
    return json.loads(lines[-1][len("INSTALL_RESULT "):])


def staged(tmp_path, script: Path, name: str) -> Path:
    """The installer and the reader side by side, as setup() uploads them."""
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    shutil.copy(script, work / name)
    shutil.copy(ROOT / "sast" / "manifest.py", work / "sast_manifest.py")
    return work


def test_semgrep_install_rehashes_its_part(tmp_path):
    root = fake_tree(tmp_path / "sast")
    write_manifest(root)
    # The installer runs inside /opt/sast itself, as on the tools image.
    shutil.copy(ROOT / "sast" / "semgrep" / "install.py", root / "install.py")
    shutil.copy(ROOT / "sast" / "manifest.py", root / "sast_manifest.py")
    (root / "pins.json").write_text(json.dumps(semgrep_pins.as_dict()))
    env = {**os.environ, "SAST_ROOT": str(root), "SAST_MANIFEST_ROOT": str(root)}
    proc = subprocess.run([sys.executable, str(root / "install.py"), str(root / "pins.json")], env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout
    result = result_of(proc.stdout)
    assert result["preinstalled"] is True
    assert result["image_manifest"]["status"] == "verified" and result["image_manifest"]["tool"] == "semgrep"
    assert "image_manifest" not in json.loads((root / "install.json").read_text())


def test_sonar_install_rehashes_its_part(tmp_path):
    root = fake_tree(tmp_path / "sast")
    write_manifest(root)
    work = staged(tmp_path, ROOT / "sast" / "sonarqube" / "install.py", "install.py")
    (work / "pins.json").write_text(json.dumps({**sonar_pins.as_dict(), "install_dir": str(root / "sonar-scanner")}))
    env = {**os.environ, "SAST_ROOT": str(work), "SAST_MANIFEST_ROOT": str(root)}
    env.pop("SONAR_SCANNER_HOME", None)
    proc = subprocess.run([sys.executable, str(work / "install.py"), str(work / "pins.json")], env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout
    info = result_of(proc.stdout)["image_manifest"]
    assert info["status"] == "verified" and info["tool"] == "sonar-scanner"


def test_codeql_install_records_the_digest_without_rehashing(tmp_path):
    from tests.test_codeql_install import fake_bundle

    root = fake_tree(tmp_path / "sast")
    shutil.rmtree(root / "codeql")
    fake_bundle(root)
    doc = write_manifest(root)
    work = staged(tmp_path, ROOT / "sast" / "codeql" / "install.py", "codeql_install.py")
    (work / "codeql_pins.json").write_text(json.dumps({**codeql_pins.as_dict(), "install_dir": str(root / "codeql")}))
    env = {**os.environ, "SAST_MANIFEST_ROOT": str(root)}
    proc = subprocess.run([sys.executable, str(work / "codeql_install.py"), str(work / "codeql_pins.json")],
                          env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout
    info = result_of(proc.stdout)["image_manifest"]
    assert info["status"] == "not_recomputed" and info["verified"] is False and "1.3 GB" in info["reason"]
    assert info["tool_tree_digest"] == doc["parts"]["codeql"]["tree_digest"]


def test_installer_without_the_reader_still_installs(tmp_path):
    root = fake_tree(tmp_path / "sast")
    work = tmp_path / "work"
    work.mkdir()
    shutil.copy(ROOT / "sast" / "sonarqube" / "install.py", work / "install.py")
    (work / "pins.json").write_text(json.dumps({**sonar_pins.as_dict(), "install_dir": str(root / "sonar-scanner")}))
    env = {**os.environ, "SAST_ROOT": str(work)}
    env.pop("SONAR_SCANNER_HOME", None)
    proc = subprocess.run([sys.executable, str(work / "install.py"), str(work / "pins.json")], env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout
    assert result_of(proc.stdout)["image_manifest"]["status"] == "reader not uploaded"


def test_setup_uploads_the_reader_and_run_metadata_carries_it(tmp_path):
    from sast import base

    assert base.MANIFEST_READER.read_bytes() == (ROOT / "sast" / "manifest.py").read_bytes()
    assert base.MANIFEST_READER_NAME == "sast_manifest.py"
    source = (ROOT / "sast" / "base.py").read_text()
    assert '"image_manifest": (getattr(self, "_install", None) or {}).get("image_manifest")' in source


# ---- the image build ---------------------------------------------------------------

def test_dockerfile_writes_the_manifest_in_a_pinned_stage_and_ships_only_that():
    text = DOCKERFILE.read_text()
    froms = [line for line in text.splitlines() if line.startswith("FROM ")]
    python_bases = {line.split()[1] for line in froms if line.startswith("FROM python")}
    assert len(python_bases) == 1 and "@sha256:" in python_bases.pop()
    assert froms[-2].endswith(" AS manifest") and froms[-1] == "FROM scratch"
    stage = text.split("AS manifest\n", 1)[1].split("FROM scratch", 1)[0]
    for part in ("semgrep", "codeql", "sonar"):
        assert f"COPY --from={part} /opt/sast /opt/sast" in stage
    assert "RUN python3 /tmp/sast_manifest.py write /opt/sast /tmp/manifest_pins.json" in stage
    assert text.split("\nFROM scratch\n", 1)[1].strip() == "COPY --from=manifest /opt/sast /opt/sast"
    header = " ".join(line.lstrip("# ").strip() for line in text.splitlines() if line.startswith("#"))
    assert "Semgrep wheel, its dependencies and uv's CPython are resolved with --exclude-newer" in header
    assert "not hash-checked" in header and "manifest now records what was actually installed" in header


def test_build_script_stages_the_writer_and_every_tools_pins(tmp_path):
    script = BUILD_SCRIPT.read_text()
    assert 'cp "$ROOT/sast/manifest.py" "$CONTEXT/sast_manifest.py"' in script
    line = next(line for line in script.splitlines() if "manifest_pins.json" in line and "python3 -c" in line)
    code = line.split('python3 -c "', 1)[1].rsplit('" >', 1)[0]
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         env={**os.environ, "PYTHONPATH": str(ROOT)}).stdout
    assert json.loads(out) == ALL_PINS
