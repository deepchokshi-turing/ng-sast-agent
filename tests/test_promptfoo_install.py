"""The promptfoo pins and installer: every download is pinned and checked
before use, and the lock installs only what it names. No network: ``fetch`` is
replaced by an in-memory registry of synthetic archives."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile

import pytest

from sast.promptfoo import pins
from tests.conftest import ROOT

HERE = ROOT / "sast" / "promptfoo"
NPM = HERE / "npm"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


install = load("pf_install_under_test", HERE / "install.py")
prune_lock = load("pf_prune_under_test", NPM / "prune_lock.py")


def lf_sha256(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def sri(data, algo="sha512"):
    return f"{algo}-" + base64.b64encode(hashlib.new(algo, data).digest()).decode()


def tgz(files, prefix="package"):
    """A .tgz with ``files`` ({path: bytes or (bytes, mode)}) under ``prefix/``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, value in files.items():
            data, mode = value if isinstance(value, tuple) else (value, 0o644)
            info = tarfile.TarInfo(f"{prefix}/{name}" if prefix else name)
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class Registry:
    """``install.fetch`` replaced: URL -> bytes, and a log of what was fetched."""

    def __init__(self, monkeypatch, files):
        self.files, self.fetched = dict(files), []
        monkeypatch.setattr(install, "fetch", self.fetch)

    def fetch(self, url, deadline):
        self.fetched.append(url)
        if url not in self.files:
            raise install.InstallError(f"could not download {url}: 404")
        return self.files[url]


# ---------------------------------------------------------------- the pins


def test_the_npm_files_match_their_pins():
    assert lf_sha256(NPM / "package.json") == pins.PACKAGE_JSON_SHA256
    assert lf_sha256(NPM / "package-lock.json") == pins.PACKAGE_LOCK_SHA256
    package = json.loads((NPM / "package.json").read_text())
    assert package["dependencies"] == {"promptfoo": pins.PROMPTFOO_VERSION,
                                       "@modelcontextprotocol/server-filesystem": pins.MCP_FILESYSTEM_VERSION}
    lock = json.loads((NPM / "package-lock.json").read_text())
    packages = lock["packages"]
    assert lock["lockfileVersion"] == 3 and len(packages) - 1 == pins.PACKAGE_LOCK_ENTRIES
    assert packages[""]["dependencies"] == package["dependencies"]
    entry = packages["node_modules/promptfoo"]
    assert entry["version"] == pins.PROMPTFOO_VERSION and entry["integrity"] == pins.PROMPTFOO_INTEGRITY
    assert packages["node_modules/@modelcontextprotocol/server-filesystem"]["version"] == pins.MCP_FILESYSTEM_VERSION
    for path, value in packages.items():
        if path:
            assert value["resolved"].startswith(pins.NPM_REGISTRY), path
            assert value["integrity"].startswith("sha512-"), path
            assert not value.get("link") and not value.get("inBundle"), path
    # The libsql binding promptfoo loads at start-up is there for both CPUs.
    assert {"node_modules/@libsql/linux-x64-gnu", "node_modules/@libsql/linux-arm64-gnu"} <= set(packages)


def test_the_lock_is_already_pruned():
    lock = json.loads((NPM / "package-lock.json").read_text())
    assert prune_lock.prune(lock) == lock


def test_prune_keeps_required_edges_and_the_kept_optionals():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "1"}},
        "node_modules/a": {"version": "1", "dependencies": {"b": "1"}, "optionalDependencies": {
            "sdk": "1", "@libsql/linux-x64-gnu": "1"}, "peerDependencies": {"p": "*", "q": "*"},
            "peerDependenciesMeta": {"q": {"optional": True}}},
        "node_modules/a/node_modules/b": {"version": "2"},
        "node_modules/b": {"version": "1"},
        "node_modules/sdk": {"version": "1", "optional": True},
        "node_modules/@libsql/linux-x64-gnu": {"version": "1", "optional": True},
        "node_modules/p": {"version": "1"},
        "node_modules/q": {"version": "1"},
    }}
    kept = set(prune_lock.prune(lock)["packages"])
    assert kept == {"", "node_modules/a", "node_modules/a/node_modules/b", "node_modules/@libsql/linux-x64-gnu",
                    "node_modules/p"}


def test_pins_as_dict():
    data = pins.as_dict()
    assert data["node"]["x86_64"]["url"] == "https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-x64.tar.xz"
    assert data["node"]["aarch64"]["url"].endswith("node-v24.21.0-linux-arm64.tar.xz")
    assert data["git"]["x86_64"]["urls"] == [
        "https://deb.debian.org/debian/pool/main/g/git/git_2.47.3-0%2Bdeb13u1_amd64.deb",
        "https://snapshot.debian.org/file/bb5947667cef07307ce77aeb86fd95c2a3e85472"]
    for entry in [*data["node"].values(), *data["git"].values()]:
        assert len(entry["sha256"]) == 64
    assert data["install_dir"] == "/opt/sast/promptfoo"
    assert json.loads(json.dumps(data)) == data


# ---------------------------------------------------------------- integrity and the plan


def test_check_integrity():
    data = b"abc"
    assert install.check_integrity(data, sri(data))
    assert not install.check_integrity(b"abd", sri(data))
    # The strongest algorithm decides, as npm does.
    assert install.check_integrity(data, f"{sri(b'x', 'sha1')} {sri(data)}")
    assert not install.check_integrity(data, f"{sri(data, 'sha1')} {sri(b'x')}")
    assert not install.check_integrity(data, "") and not install.check_integrity(data, "md5-xyz")


def plan_lock(**entries):
    return {"packages": {"": {}, **entries}}


def plan_pins(count):
    return {"npm_cpu": pins.NPM_CPU, "package_lock_entries": count, "npm_registry": pins.NPM_REGISTRY}


def test_lock_plan_skips_optional_packages_for_other_platforms():
    lock = plan_lock(**{
        "node_modules/a": {"resolved": "https://registry.npmjs.org/a/-/a-1.tgz", "integrity": "sha512-x"},
        "node_modules/@libsql/linux-arm64-gnu": {"resolved": "https://registry.npmjs.org/x.tgz",
                                                 "integrity": "sha512-y", "os": ["linux"], "cpu": ["arm64"],
                                                 "optional": True},
    })
    plan, skipped = install.lock_plan(lock, plan_pins(2), "x86_64")
    assert [p for p, _, _ in plan] == ["node_modules/a"]
    assert skipped == [("node_modules/@libsql/linux-arm64-gnu", "platform")]


@pytest.mark.parametrize("entry, words", [
    ({"resolved": "https://evil.example/a.tgz", "integrity": "sha512-x"}, "resolves outside"),
    ({"resolved": "https://registry.npmjs.org/a.tgz"}, "no integrity"),
    ({"resolved": "https://registry.npmjs.org/a.tgz", "integrity": "sha512-x", "os": ["darwin"]}, "does not support"),
    ({"link": True, "resolved": "../x"}, "link or bundled"),
])
def test_lock_plan_refuses(entry, words):
    with pytest.raises(install.InstallError, match=words):
        install.lock_plan(plan_lock(**{"node_modules/a": entry}), plan_pins(1), "x86_64")


def test_lock_plan_refuses_an_unexpected_size_or_path():
    with pytest.raises(install.InstallError, match="the pin says"):
        install.lock_plan(plan_lock(), plan_pins(5), "x86_64")
    with pytest.raises(install.InstallError, match="unexpected lock path"):
        install.lock_plan(plan_lock(**{"node_modules/../../etc": {}}), plan_pins(1), "x86_64")


# ---------------------------------------------------------------- unpacking


def test_unpack_skips_links_and_paths_outside(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, data, mode in [("package/index.js", b"x", 0o644), ("package/bin/cli", b"#!", 0o755),
                                 ("package/../../evil", b"e", 0o644)]:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("package/link")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        archive.addfile(link)
    skipped = []
    with tarfile.open(fileobj=io.BytesIO(buf.getvalue())) as archive:
        install.unpack(archive, str(tmp_path / "out"), 1, skipped, "pkg")
    assert (tmp_path / "out" / "index.js").read_bytes() == b"x"
    assert not (tmp_path / "evil").exists() and not (tmp_path / "out" / "link").exists()
    assert sorted(skipped) == ["pkg: package/../../evil", "pkg: package/link"]
    if os.name == "posix":
        assert os.stat(tmp_path / "out" / "bin" / "cli").st_mode & 0o777 == 0o755


def test_install_packages_checks_every_tarball(tmp_path, monkeypatch):
    a, b = tgz({"package.json": b'{"name": "a"}', "index.js": b"a"}), tgz({"index.js": b"nested b"})
    lock = plan_lock(**{
        "node_modules/a": {"resolved": "https://registry.npmjs.org/a.tgz", "integrity": sri(a)},
        "node_modules/a/node_modules/b": {"resolved": "https://registry.npmjs.org/b.tgz", "integrity": sri(b)},
    })
    registry = Registry(monkeypatch, {"https://registry.npmjs.org/a.tgz": a, "https://registry.npmjs.org/b.tgz": b})
    result = install.install_packages(str(tmp_path), lock, plan_pins(2), "x86_64", deadline=1e18)
    assert result["npm_packages"] == 2 and sorted(registry.fetched) == sorted(registry.files)
    assert (tmp_path / "node_modules" / "a" / "index.js").read_bytes() == b"a"
    assert (tmp_path / "node_modules" / "a" / "node_modules" / "b" / "index.js").read_bytes() == b"nested b"

    registry.files["https://registry.npmjs.org/b.tgz"] = tgz({"index.js": b"tampered"})
    with pytest.raises(install.InstallError, match="does not match the lock's integrity"):
        install.install_packages(str(tmp_path / "again"), lock, plan_pins(2), "x86_64", deadline=1e18)


# ---------------------------------------------------------------- Node.js and git


def deb(files):
    """A minimal .deb (ar archive) whose data.tar.xz holds ``files``."""
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:xz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            archive.addfile(info, io.BytesIO(data))
    out = b"!<arch>\n"
    for name, body in [("debian-binary", b"2.0\n"), ("control.tar.xz", b"ctl"), ("data.tar.xz", payload.getvalue())]:
        out += f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(body):<10}`\n".encode() + body
        if len(body) % 2:
            out += b"\n"
    return out


def git_pins(data, urls):
    return {"git": {"x86_64": {"file": "git.deb", "sha256": hashlib.sha256(data).hexdigest(), "urls": urls}},
            "git_deb_version": pins.GIT_DEB_VERSION}


def test_install_git_takes_only_usr_bin_git_and_falls_back_to_the_snapshot(tmp_path, monkeypatch):
    data = deb({"./usr/bin/git": b"GIT-BINARY", "./usr/lib/git-core/git-remote-http": b"other"})
    registry = Registry(monkeypatch, {"https://pool/git.deb": b"a newer file", "https://snapshot/x": data})
    install.install_git(str(tmp_path), git_pins(data, ["https://pool/git.deb", "https://snapshot/x"]), "x86_64", 1e18)
    assert registry.fetched == ["https://pool/git.deb", "https://snapshot/x"]
    assert (tmp_path / "git" / "bin" / "git").read_bytes() == b"GIT-BINARY"
    assert not (tmp_path / "usr").exists()


def test_install_git_refuses_a_bad_hash_everywhere(tmp_path, monkeypatch):
    data = deb({"./usr/bin/git": b"GIT"})
    Registry(monkeypatch, {"https://pool/git.deb": b"bad", "https://snapshot/x": b"bad too"})
    with pytest.raises(install.InstallError, match="no usable git.deb"):
        install.install_git(str(tmp_path), git_pins(data, ["https://pool/git.deb", "https://snapshot/x"]), "x86_64",
                            1e18)
    assert not (tmp_path / "git").exists()


def test_deb_member_needs_an_ar_archive():
    with pytest.raises(install.InstallError, match="not a Debian package"):
        install.deb_member(b"PK\x03\x04", "data.tar")


def test_install_node_checks_the_sha256(tmp_path, monkeypatch):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:xz") as archive:
        info = tarfile.TarInfo("node-v24.21.0-linux-x64/bin/node")
        info.size, info.mode = 4, 0o755
        archive.addfile(info, io.BytesIO(b"NODE"))
    data = payload.getvalue()
    node_pins = {"node_version": "24.21.0", "node": {"x86_64": {
        "url": "https://nodejs.org/node.tar.xz", "sha256": hashlib.sha256(data).hexdigest()}}}
    Registry(monkeypatch, {"https://nodejs.org/node.tar.xz": data})
    install.install_node(str(tmp_path), node_pins, "x86_64", 1e18)
    assert (tmp_path / "node" / "bin" / "node").read_bytes() == b"NODE"
    node_pins["node"]["x86_64"]["sha256"] = "0" * 64
    with pytest.raises(install.InstallError, match="has sha256"):
        install.install_node(str(tmp_path / "again"), node_pins, "x86_64", 1e18)
    with pytest.raises(install.InstallError, match="no Node.js tarball is pinned"):
        install.install_node(str(tmp_path), node_pins, "s390x", 1e18)


def test_check_lock_refuses_a_changed_lock(tmp_path):
    for name in ("package.json", "package-lock.json"):
        (tmp_path / name).write_bytes((NPM / name).read_bytes())
    lock = install.check_lock(str(tmp_path), pins.as_dict())
    assert lock["packages"]["node_modules/promptfoo"]["version"] == pins.PROMPTFOO_VERSION
    text = (tmp_path / "package-lock.json").read_text().replace(pins.PROMPTFOO_INTEGRITY, "sha512-other")
    (tmp_path / "package-lock.json").write_text(text)
    with pytest.raises(install.InstallError, match="does not match its pinned sha256"):
        install.check_lock(str(tmp_path), pins.as_dict())


@pytest.mark.skipif(os.name != "posix", reason="runs shell-script stand-ins for node and git")
def test_check_part_runs_the_binaries(tmp_path):
    part = tmp_path / "part"
    for rel, text in [("node/bin/node", "#!/bin/sh\nif [ \"$1\" = --version ]; then echo v24.21.0; else echo 0.124.1; fi\n"),
                      ("git/bin/git", "#!/bin/sh\necho 'git version 2.47.3'\n")]:
        path = part / rel
        path.parent.mkdir(parents=True)
        path.write_text(text)
        path.chmod(0o755)
    app = part / "app"
    (app / "node_modules" / "promptfoo" / "dist" / "src").mkdir(parents=True)
    (app / "node_modules" / "promptfoo" / "dist" / "src" / "entrypoint.js").write_text("")
    (app / "node_modules" / "promptfoo" / "package.json").write_text('{"version": "0.124.1"}')
    mcp = app / "node_modules" / "@modelcontextprotocol" / "server-filesystem" / "dist"
    mcp.mkdir(parents=True)
    (mcp / "index.js").write_text("")
    for name in ("package.json", "package-lock.json"):
        (app / name).write_bytes((NPM / name).read_bytes())
    result = install.check_part(str(part), pins.as_dict(), str(tmp_path))
    assert result["node_version_output"] == "v24.21.0" and result["git_version_output"] == "git version 2.47.3"
    assert result["promptfoo_version_output"] == "0.124.1"
    (part / "git" / "bin" / "git").write_text("#!/bin/sh\necho 'git version 2.39.5'\n")
    with pytest.raises(install.InstallError, match="expected git version 2.47.3"):
        install.check_part(str(part), pins.as_dict(), str(tmp_path))


def test_installer_is_standard_library_only():
    text = (HERE / "install.py").read_text() + (HERE / "scan.py").read_text()
    imported = {line.split()[1].split(".")[0] for line in text.splitlines() if line.startswith(("import ", "from "))}
    assert imported <= set(sys.stdlib_module_names) | {"sast_manifest"}
