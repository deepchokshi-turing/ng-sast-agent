"""sast/codeql/install.py: uses the baked bundle when it matches the pins,
otherwise downloads the pinned bundle for the CPU, checks it and unpacks it.

Run as a subprocess, the way the sandbox runs it. The success case against a
real CodeQL 2.27.1 bundle runs when one is on this machine. Everything else uses
a fake ``codeql`` script, which only has to answer ``version --format=json``,
and the download cases serve a small fake bundle from a local HTTP server.
These test the installer itself, not scanner output, so the fake bundle is not
a recording.
"""

from __future__ import annotations

import ast
import hashlib
import http.server
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

import pytest

from sast.codeql import pins
from tests.conftest import ROOT

INSTALL = ROOT / "sast" / "codeql" / "install.py"
CLOSED_URL = "http://127.0.0.1:9/never"  # discard port: nothing listens there


def load_install():
    spec = importlib.util.spec_from_file_location("codeql_install_under_test", INSTALL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_install(tmp_path, budget=None, **overrides):
    p = {**pins.as_dict(), **overrides}
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    pins_file = work / "codeql_pins.json"
    pins_file.write_text(json.dumps(p))
    command = [sys.executable, str(INSTALL), str(pins_file)]
    if budget is not None:
        command += ["--budget-sec", str(budget)]
    return subprocess.run(command, capture_output=True, text=True, timeout=300)


def result_of(proc):
    lines = [line for line in proc.stdout.splitlines() if line.startswith("INSTALL_RESULT ")]
    return json.loads(lines[-1][len("INSTALL_RESULT "):]) if lines else None


def fake_bundle(tmp_path, version="2.27.1", pack_version=pins.PYTHON_QUERIES_VERSION, suite=True, name="codeql"):
    bundle = tmp_path / name
    bundle.mkdir(parents=True)
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


def bundle_tarball(tmp_path, extra=None, **kwargs) -> bytes:
    """A .tar.gz shaped like the real bundle: one top-level ``codeql`` folder."""
    source = fake_bundle(tmp_path / "tarball-source", **kwargs)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        tar.add(str(source), arcname="codeql")
        for info, data in extra or []:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


class Server:
    """Serves bytes on 127.0.0.1; ``delay`` makes it trickle one byte at a time."""

    def __init__(self, payload: bytes, delay: float = 0.0):
        self.payload, self.delay, self.requests = payload, delay, 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests += 1
                self.send_response(200)
                self.send_header("Content-Length", str(len(outer.payload)))
                self.end_headers()
                try:
                    if outer.delay:
                        for i in range(len(outer.payload)):
                            self.wfile.write(outer.payload[i:i + 1])
                            self.wfile.flush()
                            time.sleep(outer.delay)
                    else:
                        self.wfile.write(outer.payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/codeql-bundle.tar.gz"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve():
    servers = []

    def start(payload: bytes, delay: float = 0.0) -> Server:
        server = Server(payload, delay)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def bundles_for(url: str, payload: bytes | None = None, sha: str | None = None) -> dict:
    sha = sha or hashlib.sha256(payload or b"").hexdigest()
    return {arch: {"asset": "codeql-bundle.tar.gz", "sha256": sha, "url": url} for arch in ("amd64", "arm64")}


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
    for arch in ("amd64", "arm64"):
        assert pins.as_dict()["bundles"][arch]["url"] == pins.bundle_url(arch)


def test_real_bundle_passes(tmp_path, codeql_bundle):
    proc = run_install(tmp_path, install_dir=str(codeql_bundle))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    result = result_of(proc)
    assert result["codeql_version"] == "2.27.1" and result["python_queries_version"] == "1.8.11"
    assert result["suite"] == f"{codeql_bundle}/{pins.SUITE_PATH}"
    assert result_of(proc)["install_dir"] == str(codeql_bundle)


def test_matching_baked_bundle_is_used_without_downloading(tmp_path):
    baked = fake_bundle(tmp_path)
    proc = run_install(tmp_path, install_dir=str(baked), bundles=bundles_for(CLOSED_URL, b"x"))
    assert proc.returncode == 0, proc.stdout
    result = result_of(proc)
    assert result["preinstalled"] is True and result["downloaded"] is False
    assert result["install_dir"] == str(baked)
    assert "downloading" not in proc.stdout


def test_missing_bundle_is_downloaded_checked_and_unpacked(tmp_path, serve):
    payload = bundle_tarball(tmp_path)
    server = serve(payload)
    target = tmp_path / "opt" / "codeql"
    proc = run_install(tmp_path, install_dir=str(target), bundles=bundles_for(server.url, payload))
    assert proc.returncode == 0, proc.stdout
    result = result_of(proc)
    assert result["downloaded"] is True and result["preinstalled"] is False
    assert result["install_dir"] == str(target)
    assert result["bundle_sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["codeql_version"] == "2.27.1" and result["python_queries_version"] == "1.8.11"
    assert (target / "codeql").is_file() and not (target / "codeql").is_symlink()
    # Nothing left beside it: no archive, no staging folder.
    assert sorted(p.name for p in target.parent.iterdir()) == ["codeql"]
    # A second setup in the same sandbox reuses it.
    again = result_of(run_install(tmp_path, install_dir=str(target), bundles=bundles_for(server.url, payload)))
    assert again["downloaded"] is False and server.requests == 1


def test_baked_bundle_with_other_versions_is_replaced_by_the_pinned_one(tmp_path, serve):
    payload = bundle_tarball(tmp_path)
    server = serve(payload)
    baked = fake_bundle(tmp_path / "opt", version="2.20.0")
    proc = run_install(tmp_path, install_dir=str(baked), bundles=bundles_for(server.url, payload))
    assert proc.returncode == 0, proc.stdout
    assert "is version 2.20.0, expected 2.27.1" in proc.stdout  # why it downloaded
    assert result_of(proc)["downloaded"] is True
    assert '"version": "2.27.1"' in (baked / "codeql").read_text()


def test_symlinked_install_dir_falls_back_to_the_work_folder(tmp_path, serve):
    payload = bundle_tarball(tmp_path)
    server = serve(payload)
    link = tmp_path / "linked"
    link.symlink_to(fake_bundle(tmp_path))
    proc = run_install(tmp_path, install_dir=str(link), bundles=bundles_for(server.url, payload))
    assert proc.returncode == 0, proc.stdout
    assert "is a symlink" in proc.stdout
    result = result_of(proc)
    assert result["install_dir"] == str(tmp_path / "work" / "codeql")
    assert link.is_symlink()  # left alone


def test_wrong_sha256_fails_and_leaves_nothing(tmp_path, serve):
    payload = bundle_tarball(tmp_path)
    server = serve(payload)
    target = tmp_path / "opt" / "codeql"
    proc = run_install(tmp_path, install_dir=str(target), bundles=bundles_for(server.url, sha="0" * 64))
    assert proc.returncode == 2 and result_of(proc) is None
    assert "ERROR: bundle sha256 is " + hashlib.sha256(payload).hexdigest() in proc.stdout
    assert list(target.parent.iterdir()) == []


@pytest.mark.parametrize("kwargs, message", [
    ({"version": "2.20.0"}, "is version 2.20.0, expected 2.27.1"),
    ({"pack_version": "1.0.0"}, "codeql/python-queries in the bundle is 1.0.0, expected exactly 1.8.11"),
    ({"suite": False}, "python-security-extended.qls is missing"),
])
def test_downloaded_bundle_that_does_not_match_the_pins_fails(tmp_path, serve, kwargs, message):
    payload = bundle_tarball(tmp_path, **kwargs)
    server = serve(payload)
    target = tmp_path / "opt" / "codeql"
    proc = run_install(tmp_path, install_dir=str(target), bundles=bundles_for(server.url, payload))
    assert proc.returncode == 2 and result_of(proc) is None
    assert "ERROR: the downloaded bundle does not match the pins" in proc.stdout and message in proc.stdout
    assert list(target.parent.iterdir()) == []


def test_a_download_that_cannot_finish_in_time_fails_clearly(tmp_path, serve):
    payload = bundle_tarball(tmp_path)
    server = serve(payload, delay=0.05)  # minutes for the whole file
    started = time.monotonic()
    proc = run_install(tmp_path, budget=6, install_dir=str(tmp_path / "opt" / "codeql"),
                       bundles=bundles_for(server.url, payload))
    assert time.monotonic() - started < 20
    assert proc.returncode == 2 and result_of(proc) is None
    assert "did not finish within its 4 s share of the setup limit" in proc.stdout
    assert list((tmp_path / "opt").iterdir()) == []


def test_unreachable_download_fails_clearly(tmp_path):
    proc = run_install(tmp_path, budget=30, install_dir=str(tmp_path / "opt" / "codeql"),
                       bundles=bundles_for(CLOSED_URL, b"x"))
    assert proc.returncode == 2 and "ERROR: could not download http://127.0.0.1:9/never" in proc.stdout


def test_no_bundle_pinned_for_this_cpu_fails(tmp_path):
    proc = run_install(tmp_path, install_dir=str(tmp_path / "nowhere"), bundles={})
    assert proc.returncode == 2 and result_of(proc) is None
    assert "ERROR: no CodeQL bundle pinned for this CPU" in proc.stdout


def _member(name, kind=tarfile.REGTYPE, linkname="", data=b""):
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.size = kind, linkname, (len(data) if kind == tarfile.REGTYPE else 0)
    return info, (data if kind == tarfile.REGTYPE else None)


@pytest.mark.parametrize("extra, message", [
    ([_member("codeql/../escape.txt", data=b"x")], "contains '..'"),
    ([_member("/abs.txt", data=b"x")], "absolute"),
    ([_member("other/file.txt", data=b"x")], "unexpected path in bundle"),
    ([_member("codeql/up", tarfile.SYMTYPE, "../..")], "leaves the target folder"),
    ([_member("codeql/abs", tarfile.SYMTYPE, "/etc")], "absolute symlink target"),
    # The audit's chained case: a link to '.', then a link through it.
    ([_member("codeql/d", tarfile.SYMTYPE, "."), _member("codeql/d/x", tarfile.SYMTYPE, "../../escape")],
     "goes through the symlink"),
    # A target that is fine on paper but escapes through another link.
    ([_member("codeql/d", tarfile.SYMTYPE, "."), _member("codeql/e", tarfile.SYMTYPE, "d/../..")],
     "leaves the target folder"),
    ([_member("codeql/hl", tarfile.LNKTYPE, "etc/passwd")], "points outside the bundle"),
    ([_member("codeql/fifo", tarfile.FIFOTYPE)], "is not a file, folder or link"),
])
def test_unsafe_archive_members_are_refused(tmp_path, serve, extra, message):
    payload = bundle_tarball(tmp_path, extra=extra)
    server = serve(payload)
    proc = run_install(tmp_path, install_dir=str(tmp_path / "opt" / "codeql"),
                       bundles=bundles_for(server.url, payload))
    assert proc.returncode == 2 and result_of(proc) is None
    assert message in proc.stdout, proc.stdout
    assert list((tmp_path / "opt").iterdir()) == []
    assert not (tmp_path / "escape").exists()


def test_safe_relative_links_inside_the_bundle_are_accepted():
    install = load_install()
    members = [_member("codeql/tools/java", tarfile.DIRTYPE)[0],
               _member("codeql/tools/java/bin/java", data=b"x")[0],
               _member("codeql/java", tarfile.SYMTYPE, "tools/java")[0],
               _member("codeql/javabin", tarfile.SYMTYPE, "java/bin/../bin/java")[0],
               _member("codeql/hard", tarfile.LNKTYPE, "codeql/tools/java/bin/java")[0]]
    install.check_members(members, top="codeql")


def test_install_script_is_stdlib_only_and_python36():
    text = INSTALL.read_text()
    imports = {line.split()[1].split(".")[0] for line in text.splitlines() if line.startswith(("import ", "from "))}
    assert imports <= {"hashlib", "json", "os", "platform", "re", "shutil", "subprocess", "sys", "tarfile",
                       "time", "urllib"}
    assert text.startswith("#!/usr/bin/env python3")
    ast.parse(text, feature_version=(3, 6))
    assert "capture_output" not in text and "text=True" not in text  # 3.7+ only
    assert "f\"" not in text and "f'" not in text  # keep the format() style of the semgrep installer


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
