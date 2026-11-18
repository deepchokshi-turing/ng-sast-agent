"""sast/datadog_saist/install.py and pins.py: the zip and executable hashes are
checked before use. A fake release zip stands in for GitHub; nothing is downloaded."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import zipfile

import pytest

from sast.datadog_saist import install, pins

POSIX = pytest.mark.skipif(sys.platform == "win32", reason="runs a fake binary as an executable (POSIX only)")
FAKE_BINARY = "#!/bin/sh\necho '  -detection-model string'\necho '    \tModel (required). Available: openai-gpt5-mini, openai-gpt5.2'\nexit 0\n"


def fake_zip(member="datadog-saist", data=FAKE_BINARY.encode()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(member, data)
        z.writestr("LICENSE", "Apache-2.0")
    return buf.getvalue()


def pins_for(blob, file_data=FAKE_BINARY.encode(), install_dir="/nonexistent/datadog-saist"):
    p = pins.as_dict()
    entry = {"url": "https://example.invalid/x.zip", "sha256": hashlib.sha256(blob).hexdigest(),
             "file_sha256": hashlib.sha256(file_data).hexdigest()}
    p["assets"] = {"x86_64": entry, "aarch64": entry}
    p["install_dir"] = install_dir
    return p


def test_pins_are_exact():
    d = pins.as_dict()
    assert d["version"] == "0.0.32" and d["release_tag"] == "v0.0.32" and len(d["commit"]) == 40
    for arch, entry in d["assets"].items():
        assert entry["url"].startswith("https://github.com/DataDog/datadog-saist/releases/download/v0.0.32/")
        assert len(entry["sha256"]) == 64 and len(entry["file_sha256"]) == 64
    assert pins.DEFAULT_MODEL in pins.MODELS and pins.API_TO_CLI["gpt-5.2"] == "openai-gpt5.2"


@POSIX
def test_a_matching_zip_installs_and_runs(tmp_path, monkeypatch):
    blob = fake_zip()
    monkeypatch.setattr(install, "fetch", lambda url, deadline: blob)
    result = install.install(str(tmp_path / "part"), pins_for(blob), "x86_64", 1e18)
    assert result["binary"].endswith("bin/datadog-saist") and "openai-gpt5.2" in result["models"]
    assert json.loads((tmp_path / "part" / "install.json").read_text())["version"] == "0.0.32"


def test_a_zip_with_the_wrong_hash_is_refused_before_extraction(tmp_path, monkeypatch):
    blob = fake_zip()
    p = pins_for(blob)
    monkeypatch.setattr(install, "fetch", lambda url, deadline: blob + b"tampered")
    with pytest.raises(install.InstallError, match="sha256"):
        install.install(str(tmp_path / "part"), p, "x86_64", 1e18)
    assert not (tmp_path / "part").exists() and not (tmp_path / "part.partial").exists()


def test_an_executable_with_the_wrong_hash_is_refused(tmp_path, monkeypatch):
    blob = fake_zip(data=b"#!/bin/sh\necho evil\n")
    monkeypatch.setattr(install, "fetch", lambda url, deadline: blob)
    with pytest.raises(install.InstallError, match="sha256"):
        install.install(str(tmp_path / "part"), pins_for(blob), "x86_64", 1e18)


def test_a_zip_without_the_member_is_refused(tmp_path, monkeypatch):
    blob = fake_zip(member="other")
    monkeypatch.setattr(install, "fetch", lambda url, deadline: blob)
    with pytest.raises(install.InstallError, match="holds no"):
        install.install(str(tmp_path / "part"), pins_for(blob), "x86_64", 1e18)


def test_an_unpinned_cpu_is_refused():
    with pytest.raises(install.InstallError, match="no datadog-saist build"):
        install.asset_for(pins.as_dict(), "riscv64")
