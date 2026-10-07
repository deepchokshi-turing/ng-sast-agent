"""sast/codeql/install.py: checks the baked-in bundle against the pins, never downloads.

Run as a subprocess, the way the sandbox runs it. The success case runs against a
real CodeQL 2.27.1 bundle when one is on this machine; the failure cases use a
fake ``codeql`` script, which only has to answer ``version --format=json``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sast.codeql import pins
from tests.conftest import ROOT

INSTALL = ROOT / "sast" / "codeql" / "install.py"


def run_install(tmp_path, **overrides):
    p = {**pins.as_dict(), **overrides}
    pins_file = tmp_path / "pins.json"
    pins_file.write_text(json.dumps(p))
    return subprocess.run([sys.executable, str(INSTALL), str(pins_file)], capture_output=True, text=True,
                          timeout=300)


def result_of(proc):
    lines = [line for line in proc.stdout.splitlines() if line.startswith("INSTALL_RESULT ")]
    return json.loads(lines[-1][len("INSTALL_RESULT "):]) if lines else None


def fake_bundle(tmp_path, version="2.27.1", pack_version=pins.PYTHON_QUERIES_VERSION, suite=True):
    bundle = tmp_path / "codeql"
    bundle.mkdir()
    cli = bundle / "codeql"
    cli.write_text(f"#!/bin/sh\necho 'Picked up JAVA_TOOL_OPTIONS: x' >&2\n"
                   f"echo '{{\"productName\": \"CodeQL\", \"version\": \"{version}\"}}'\n")
    cli.chmod(0o755)
    pack = bundle / "qlpacks" / "codeql" / "python-queries" / pack_version
    pack.mkdir(parents=True)
    (pack / "qlpack.yml").write_text(f"---\nlibrary: false\nname: codeql/python-queries\nversion: {pack_version}\n")
    if suite:
        (bundle / pins.SUITE_PATH).parent.mkdir(parents=True, exist_ok=True)
        (bundle / pins.SUITE_PATH).write_text("- import: x\n")
    return bundle


def test_pins():
    assert pins.CODEQL_VERSION == "2.27.1"
    assert pins.BUNDLE_TAG == "codeql-bundle-v2.27.1"
    assert {arch: asset for arch, (asset, _) in pins.BUNDLES.items()} == {
        "amd64": "codeql-bundle-linux64.tar.gz", "arm64": "codeql-bundle-linux-arm64.tar.gz"}
    assert pins.BUNDLES["arm64"][1] == "5f05cc0793971e48824d00e570afe6144a27a325360b43bd823d755aed919817"
    assert pins.bundle_url("arm64") == ("https://github.com/github/codeql-action/releases/download/"
                                        "codeql-bundle-v2.27.1/codeql-bundle-linux-arm64.tar.gz")
    assert pins.PYTHON_QUERIES_VERSION == "1.8.11"
    assert pins.SUITE_PATH == "qlpacks/codeql/python-queries/1.8.11/codeql-suites/python-security-extended.qls"
    assert pins.INSTALL_DIR == "/opt/sast/codeql"
    for _, sha in pins.BUNDLES.values():
        assert len(sha) == 64 and int(sha, 16) >= 0


def test_real_bundle_passes(tmp_path, codeql_bundle):
    proc = run_install(tmp_path, install_dir=str(codeql_bundle))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    result = result_of(proc)
    assert result["codeql_version"] == "2.27.1" and result["python_queries_version"] == "1.8.11"
    assert result["suite"] == f"{codeql_bundle}/{pins.SUITE_PATH}"


def test_fake_bundle_with_the_pinned_versions_passes(tmp_path):
    proc = run_install(tmp_path, install_dir=str(fake_bundle(tmp_path)))
    assert proc.returncode == 0, proc.stdout
    assert result_of(proc)["preinstalled"] is True


def test_missing_bundle_fails_clearly_without_downloading(tmp_path):
    proc = run_install(tmp_path, install_dir=str(tmp_path / "nowhere"))
    assert proc.returncode == 2 and result_of(proc) is None
    assert "ERROR: CodeQL is not installed at" in proc.stdout
    assert "sast-tools" in proc.stdout
    assert "urllib" not in INSTALL.read_text() and "download(" not in INSTALL.read_text()


@pytest.mark.parametrize("kwargs, message", [
    ({"version": "2.20.0"}, "is version 2.20.0, expected 2.27.1"),
    ({"pack_version": "1.0.0"}, "codeql/python-queries in the bundle is 1.0.0, expected exactly 1.8.11"),
    ({"suite": False}, "python-security-extended.qls is missing"),
])
def test_wrong_bundle_fails(tmp_path, kwargs, message):
    proc = run_install(tmp_path, install_dir=str(fake_bundle(tmp_path, **kwargs)))
    assert proc.returncode == 2 and result_of(proc) is None
    assert message in proc.stdout


def test_symlinked_bundle_fails(tmp_path):
    real = fake_bundle(tmp_path)
    link = tmp_path / "linked"
    link.symlink_to(real)
    proc = run_install(tmp_path, install_dir=str(link))
    assert proc.returncode == 2 and "is a symlink" in proc.stdout


def test_install_script_is_stdlib_only():
    imports = {line.split()[1].split(".")[0] for line in INSTALL.read_text().splitlines()
               if line.startswith(("import ", "from "))}
    assert imports <= {"json", "os", "re", "subprocess", "sys", "time"}
    assert os.access(INSTALL, os.R_OK)
    assert Path(INSTALL).read_text().startswith("#!/usr/bin/env python3")


def test_tools_image_fetches_the_pinned_bundle_for_each_cpu():
    """build_tools_image.sh passes both bundles' URL and sha256; the Dockerfile picks by TARGETARCH."""
    script = (ROOT / "tools" / "build_tools_image.sh").read_text()
    snippet = script.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    out = subprocess.run([sys.executable, "-c", snippet], capture_output=True, text=True, check=True,
                         env={**os.environ, "PYTHONPATH": str(ROOT)}).stdout.split()
    args = dict(value.split("=", 1) for value in out if value != "--build-arg")
    for arch in ("amd64", "arm64"):
        key = arch.upper()
        assert args[f"CODEQL_URL_{key}"] == pins.bundle_url(arch)
        assert args[f"CODEQL_SHA256_{key}"] == pins.BUNDLES[arch][1]
    dockerfile = (ROOT / "images" / "sast-tools" / "Dockerfile").read_text()
    codeql_stage = dockerfile.split("AS codeql", 1)[1].split("FROM ", 1)[0]
    for key in [k for k in args if k.startswith("CODEQL_")]:
        assert f"ARG {key}" in codeql_stage
    assert 'amd64) url="$CODEQL_URL_AMD64"; sha="$CODEQL_SHA256_AMD64"' in codeql_stage
    assert 'arm64) url="$CODEQL_URL_ARM64"; sha="$CODEQL_SHA256_ARM64"' in codeql_stage
    assert "fetch_archive.py" in codeql_stage and "exit 2" in codeql_stage
