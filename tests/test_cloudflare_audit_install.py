"""sast/cloudflare_audit/install.py and pins.py: every download hash-checked before use, nothing unpinned.
Downloads are replaced by a local fake fetch; nothing here reaches the network."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile

import pytest

from sast.claude_review import pins as claude_pins
from sast.cloudflare_audit import install, pins

POSIX = pytest.mark.skipif(sys.platform == "win32", reason="runs a fake node executable (POSIX only)")


def test_pins_are_exact_and_point_at_the_pinned_commit():
    data = pins.as_dict()
    assert len(pins.SKILL_COMMIT) == 40 and data["skill_commit"] == pins.SKILL_COMMIT
    assert set(data["skill_files"]) == set(pins.SKILL_FILES) and "SKILL.md" in data["skill_files"]
    assert not any(name.endswith(".test.cjs") for name in data["skill_files"])
    for rel, entry in data["skill_files"].items():
        assert len(entry["sha256"]) == 64 and pins.SKILL_COMMIT in entry["url"]
        assert entry["url"].endswith(("/skills/security-audit/" + rel) if rel != "LICENSE" else "/LICENSE")
    assert data["claude_code_version"] == claude_pins.CLAUDE_CODE_VERSION
    assert data["claude_code_packages"] == claude_pins.as_dict()["claude_code_packages"]
    for arch, entry in data["node"].items():
        assert entry["url"].startswith("https://nodejs.org/dist/v24.21.0/") and len(entry["sha256"]) == 64
        assert entry["member"].endswith("/bin/node") and "latest" not in entry["url"]
    assert json.loads(json.dumps(data)) == data


def fake_pins(files: dict[str, bytes], node_tar: bytes | None = None) -> dict:
    data = pins.as_dict()
    data["skill_files"] = {rel: {"sha256": hashlib.sha256(body).hexdigest(), "url": f"https://x.invalid/{rel}"}
                           for rel, body in files.items()}
    if node_tar is not None:
        data["node"]["x86_64"] = {"url": "https://x.invalid/node.tar.xz", "member": "node-v24.21.0-linux-x64/bin/node",
                                  "sha256": hashlib.sha256(node_tar).hexdigest()}
    return data


def fetcher(blobs: dict[str, bytes]):
    def fetch(url, deadline):
        return blobs[url.rsplit("/", 1)[1]]
    return fetch


def test_skill_files_are_checked_before_they_are_kept(tmp_path):
    files = {"SKILL.md": b"skill", "report-schema.json": b"{}"}
    data = fake_pins(files)
    install.install_skill(str(tmp_path), data, 1e12, fetch=fetcher(files))
    assert (tmp_path / "skill" / "security-audit" / "SKILL.md").read_bytes() == b"skill"
    assert install.check_skill(str(tmp_path), data)["skill_files"] == 2
    (tmp_path / "skill" / "security-audit" / "SKILL.md").write_bytes(b"changed")
    with pytest.raises(install.InstallError, match="sha256"):
        install.check_skill(str(tmp_path), data)
    with pytest.raises(install.InstallError, match="sha256"):
        install.install_skill(str(tmp_path / "x"), data, 1e12, fetch=fetcher(dict(files, **{"SKILL.md": b"evil"})))


def node_tarball(script: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
        info = tarfile.TarInfo("node-v24.21.0-linux-x64/bin/node")
        info.size = len(script)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(script))
    return buffer.getvalue()


def test_node_tarball_must_match_its_sha256(tmp_path):
    tar = node_tarball(b"#!/bin/sh\necho v24.21.0\n")
    data = fake_pins({}, tar)
    with pytest.raises(install.InstallError, match="sha256"):
        install.install_node(str(tmp_path), data, "x86_64", 1e12, fetch=lambda url, deadline: tar + b"x")
    with pytest.raises(install.InstallError, match="no Node.js tarball"):
        install.install_node(str(tmp_path), data, "riscv64", 1e12, fetch=lambda url, deadline: tar)
    install.install_node(str(tmp_path), data, "x86_64", 1e12, fetch=lambda url, deadline: tar)
    assert (tmp_path / "node" / "bin" / "node").read_bytes().startswith(b"#!/bin/sh")


@POSIX
def test_node_version_is_checked(tmp_path):
    for version, ok in (("v24.21.0", True), ("v22.0.0", False)):
        part = tmp_path / version
        tar = node_tarball(f"#!/bin/sh\necho {version}\n".encode())
        install.install_node(str(part), fake_pins({}, tar), "x86_64", 1e12, fetch=lambda url, deadline: tar)
        if ok:
            assert install.check_node(str(part), pins.as_dict(), str(tmp_path))["node_version_output"] == "v24.21.0"
        else:
            with pytest.raises(install.InstallError, match="expected v24.21.0"):
                install.check_node(str(part), pins.as_dict(), str(tmp_path))


def test_a_missing_part_is_not_usable(tmp_path):
    with pytest.raises(install.InstallError):
        install.check_part(str(tmp_path / "nothing"), pins.as_dict(), str(tmp_path))
