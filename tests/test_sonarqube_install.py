"""install.py with a stand-in scanner directory: found, missing, wrong version, broken JRE.

The real scanner comes with the tools image and is exercised by the Harbor runs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from sast.sonarqube import pins
from tests.conftest import ROOT

INSTALL = ROOT / "sast" / "sonarqube" / "install.py"


def fake_scanner(home, version=pins.SONAR_SCANNER_VERSION, exit_code=0):
    (home / "bin").mkdir(parents=True)
    (home / "lib").mkdir()
    (home / "lib" / f"sonar-scanner-cli-{version}.jar").write_bytes(b"")
    script = home / "bin" / "sonar-scanner"
    script.write_text(f"#!/bin/sh\necho 'INFO: SonarScanner CLI {version}'\nexit {exit_code}\n")
    script.chmod(0o755)
    return home


def run_install(tmp_path, home, pinned=pins.SONAR_SCANNER_VERSION):
    pins_file = tmp_path / "pins.json"
    pins_file.write_text(json.dumps({**pins.as_dict(), "install_dir": str(home), "sonar_scanner_version": pinned}))
    env = {**os.environ, "SAST_ROOT": str(tmp_path / "root")}
    env.pop("SONAR_SCANNER_HOME", None)
    return subprocess.run([sys.executable, str(INSTALL), str(pins_file)], env=env, capture_output=True, text=True,
                          timeout=60)


def test_reports_the_scanner_and_python(tmp_path):
    home = fake_scanner(tmp_path / "sonar-scanner")
    proc = run_install(tmp_path, home)
    assert proc.returncode == 0, proc.stdout
    last = proc.stdout.strip().splitlines()[-1]
    assert last.startswith("INSTALL_RESULT ")
    result = json.loads(last[len("INSTALL_RESULT "):])
    assert result["scanner_version"] == pins.SONAR_SCANNER_VERSION and result["scanner_pinned"] is True
    assert result["scanner_home"] == str(home) and result["python"] == sys.executable
    assert f"INFO: SonarScanner CLI {pins.SONAR_SCANNER_VERSION}" in result["scanner_v_output"]


def test_an_unpinned_version_fails(tmp_path):
    home = fake_scanner(tmp_path / "sonar-scanner")
    proc = run_install(tmp_path, home, pinned=None)
    assert proc.returncode == 2 and "no sonar-scanner version is pinned" in proc.stdout


def test_missing_scanner_fails_clearly(tmp_path):
    proc = run_install(tmp_path, tmp_path / "nowhere")
    assert proc.returncode == 2
    assert "ERROR: sonar-scanner is not installed at" in proc.stdout and "sast-tools:0.5.0" in proc.stdout
    assert "INSTALL_RESULT" not in proc.stdout


def test_pinned_version_must_match(tmp_path):
    home = fake_scanner(tmp_path / "sonar-scanner", version="7.1.0.1")
    proc = run_install(tmp_path, home, pinned="7.2.0.5079")
    assert proc.returncode == 2 and "version 7.1.0.1, expected 7.2.0.5079" in proc.stdout


def test_a_scanner_that_does_not_start_fails(tmp_path):
    home = fake_scanner(tmp_path / "sonar-scanner", exit_code=1)
    proc = run_install(tmp_path, home)
    assert proc.returncode == 2 and "bundled JRE may not run" in proc.stdout


def test_pins_shape():
    p = pins.as_dict()
    assert p["install_dir"] == "/opt/sast/sonar-scanner"
    assert set(p["sonar_scanner_sha256"]) == {"x86_64", "aarch64"}
    assert pins.SONAR_SCANNER_VERSION == "8.1.0.6389"
    assert all(isinstance(v, str) and len(v) == 64 for v in p["sonar_scanner_sha256"].values())
