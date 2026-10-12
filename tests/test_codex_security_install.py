"""sast/codex_security/pins.py and install.py: the pinned Codex release assets
and the checks before use. The installer runs against a local server that
serves stand-in tarballs (a tiny script in place of each executable); the real
assets are not downloaded here."""

from __future__ import annotations

import hashlib
import http.server
import io
import json
import platform
import re
import sys
import tarfile
import threading
from pathlib import Path

import pytest

from sast.codex_security import install, pins

LINUX = pytest.mark.skipif(platform.system() != "Linux" or sys.platform == "win32",
                           reason="the installer runs the Linux executables it installs")


def test_pins_are_exact_and_cover_both_cpus():
    assert re.fullmatch(r"\d+\.\d+\.\d+", pins.CODEX_VERSION) and pins.RELEASE_TAG == f"rust-v{pins.CODEX_VERSION}"
    data = pins.as_dict()
    assert set(data["assets"]) == {"x86_64", "aarch64"}
    for arch, assets in data["assets"].items():
        assert set(assets) == {"codex", "codex-code-mode-host", "bwrap"}
        for tool, entry in assets.items():
            assert entry["url"] == (f"https://github.com/openai/codex/releases/download/rust-v{pins.CODEX_VERSION}/"
                                    f"{tool}-{pins.TARGETS[arch]}.tar.gz")
            assert entry["member"] == f"{tool}-{pins.TARGETS[arch]}"
            assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) and re.fullmatch(r"[0-9a-f]{64}", entry["file_sha256"])
            assert entry["path"] == pins.INSTALL_PATHS[tool]
    # Codex finds bubblewrap at codex-resources/bwrap next to itself, and the code-mode host next to itself.
    assert pins.INSTALL_PATHS == {"codex": "bin/codex", "codex-code-mode-host": "bin/codex-code-mode-host",
                                  "bwrap": "bin/codex-resources/bwrap"}
    hashes = [e["sha256"] for a in data["assets"].values() for e in a.values()]
    assert len(set(hashes)) == len(hashes)
    assert "latest" not in json.dumps(data)


def test_installer_is_stdlib_only():
    source = Path(install.__file__).read_text()
    imports = set(re.findall(r"^\s*(?:import|from) (\w+)", source, re.MULTILINE))
    assert imports <= set(sys.stdlib_module_names) | {"sast_manifest"}


# ---------------------------------------------------------------- the installer, with stand-ins


def _tarball(member: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(member)
        info.size, info.mode = len(data), 0o755
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class Server:
    def __init__(self, files):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                data = files.get(self.path)
                self.send_response(200 if data is not None else 404)
                self.end_headers()
                if data is not None:
                    self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def served(tmp_path, monkeypatch):
    """pins.json whose assets are stand-ins served locally, with matching hashes."""
    version = f'#!/bin/sh\necho "codex-cli {pins.CODEX_VERSION}"\n'.encode()
    data = pins.as_dict()
    files = {}
    for arch, assets in data["assets"].items():
        for tool, entry in assets.items():
            body = version if tool == "codex" else f"#!/bin/sh\necho {tool}\n".encode()
            tarball = _tarball(entry["member"], body)
            files[f"/{arch}/{tool}.tgz"] = tarball
            entry["sha256"] = hashlib.sha256(tarball).hexdigest()
            entry["file_sha256"] = hashlib.sha256(body).hexdigest()
    server = Server(files)
    for arch, assets in data["assets"].items():
        for tool, entry in assets.items():
            entry["url"] = f"{server.base}/{arch}/{tool}.tgz"
    data["install_dir"] = str(tmp_path / "baked" / "codex-security")
    pins_file = tmp_path / "work" / "pins.json"
    pins_file.parent.mkdir()
    pins_file.write_text(json.dumps(data))
    monkeypatch.setattr(install, "ROOT", str(tmp_path / "work"))
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    yield pins_file, data, server, files
    server.server.shutdown()


def _result(capsys):
    line = [x for x in capsys.readouterr().out.splitlines() if x.startswith("INSTALL_RESULT ")][-1]
    return json.loads(line[len("INSTALL_RESULT "):])


@LINUX
def test_setup_installs_every_asset_and_checks_it(tmp_path, served, capsys):
    pins_file, data, _, _ = served
    assert install.main([str(pins_file)]) == 0
    result = _result(capsys)
    part = tmp_path / "work" / "codex-security"
    assert result["source"] == "setup" and result["part"] == str(part)
    assert result["codex"] == str(part / "bin" / "codex") and result["codex_version_output"] == f"codex-cli {pins.CODEX_VERSION}"
    assert result["bwrap"] == str(part / "bin" / "codex-resources" / "bwrap")
    assert result["code_mode_host"] == str(part / "bin" / "codex-code-mode-host")
    assert result["install_json"]["release_tag"] == pins.RELEASE_TAG
    assert not (tmp_path / "work" / "codex-security.partial").exists()


@LINUX
def test_a_baked_part_is_used_without_downloading(tmp_path, served, capsys):
    pins_file, data, server, files = served
    assert install.main([str(pins_file), "--build", "--target", data["install_dir"]]) == 0
    capsys.readouterr()
    files.clear()   # nothing can be downloaded any more
    assert install.main([str(pins_file)]) == 0
    result = _result(capsys)
    assert result["source"] == "image" and result["part"] == data["install_dir"]


@LINUX
@pytest.mark.parametrize("field, message", [("sha256", "has sha256"), ("file_sha256", "has sha256")])
def test_setup_refuses_an_asset_that_does_not_match(tmp_path, served, capsys, field, message):
    pins_file, data, _, _ = served
    arch = install.ARCH[platform.machine().lower()]
    data["assets"][arch]["bwrap"][field] = "0" * 64
    pins_file.write_text(json.dumps(data))
    with pytest.raises(SystemExit) as exc:
        install.main([str(pins_file)])
    assert exc.value.code == 2
    out = capsys.readouterr().out
    assert "ERROR:" in out and message in out and "INSTALL_RESULT" not in out


@LINUX
def test_a_wrong_version_is_refused(tmp_path, served, capsys):
    pins_file, data, _, _ = served
    data["codex_version"] = "0.0.1"
    pins_file.write_text(json.dumps(data))
    with pytest.raises(SystemExit):
        install.main([str(pins_file)])
    assert "expected 'codex-cli 0.0.1'" in capsys.readouterr().out


@LINUX
def test_a_tampered_baked_file_is_reinstalled(tmp_path, served, capsys):
    pins_file, data, _, _ = served
    assert install.main([str(pins_file), "--build", "--target", data["install_dir"]]) == 0
    capsys.readouterr()
    host = Path(data["install_dir"]) / "bin" / "codex-code-mode-host"
    host.write_text("#!/bin/sh\necho tampered\n")
    assert install.main([str(pins_file)]) == 0
    result = _result(capsys)
    assert result["source"] == "setup" and "has sha256" in result["baked_problem"]


def test_the_version_probe_inherits_no_host_openai_settings(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-x")
    monkeypatch.setenv("CODEX_HOME", "/host")
    monkeypatch.setenv("LANG", "C.UTF-8")
    env = install.quiet_env("/h")
    assert "OPENAI_API_KEY" not in env and env["LANG"] == "C.UTF-8"
    assert env["CODEX_HOME"].replace("\\", "/") == "/h/codex-home" and env["HOME"] == "/h"
