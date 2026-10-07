"""images/sast-tools/fetch_archive.py: unpacking refuses archives that escape the target.

The audit of 0.4.0 (L2) built a tar with ``top/d -> .``, then
``top/d/x -> ../../escape``, then ``top/x/pwned.txt``. The old realpath check
accepted it and the file landed outside the target. These archives are built
here in memory; they test the build helper, not scanner output.
"""

from __future__ import annotations

import importlib.util
import io
import tarfile
import zipfile

import pytest

from tests.conftest import ROOT

FETCH = ROOT / "images" / "sast-tools" / "fetch_archive.py"


def load():
    spec = importlib.util.spec_from_file_location("fetch_archive_under_test", FETCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def member(name, kind=tarfile.REGTYPE, linkname="", data=b""):
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, linkname
    info.size = len(data) if kind == tarfile.REGTYPE else 0
    return info, (io.BytesIO(data) if kind == tarfile.REGTYPE else None)


def tarball(path, members):
    with tarfile.open(path, "w:gz") as tar:
        for info, data in members:
            tar.addfile(info, data)
    return path


def unpack(tmp_path, members):
    archive = tarball(tmp_path / "a.tar.gz", members)
    root = tmp_path / "case" / "root"
    root.mkdir(parents=True)
    load().unpack_tar(str(archive), str(root.resolve()))
    return root


@pytest.mark.parametrize("members, message", [
    # The audit's archive.
    ([member("top/d", tarfile.SYMTYPE, "."), member("top/d/x", tarfile.SYMTYPE, "../../escape"),
      member("top/x/pwned.txt", data=b"pwned")], "goes through the symlink"),
    # Same trick with a link whose target is only bad once 'd' is followed.
    ([member("top/d", tarfile.SYMTYPE, "."), member("top/e", tarfile.SYMTYPE, "d/../.."),
      member("top/e/pwned.txt", data=b"pwned")], "points outside the target folder"),
    ([member("top/abs", tarfile.SYMTYPE, "/etc")], "is absolute"),
    ([member("top/up", tarfile.SYMTYPE, "../..")], "points outside the target folder"),
    ([member("top/../pwned.txt", data=b"x")], "contains '..'"),
    ([member("/pwned.txt", data=b"x")], "is absolute"),
    ([member("top/a", tarfile.SYMTYPE, "b"), member("top/b", tarfile.SYMTYPE, "a")], "symlink loop"),
    ([member("top/f", data=b"x"), member("top/f", tarfile.SYMTYPE, "../..")], "appears twice"),
    ([member("top/hl", tarfile.LNKTYPE, "../etc/passwd")], "contains '..'"),
    ([member("top/dev", tarfile.CHRTYPE)], "is not a file, folder or link"),
])
def test_escaping_archives_are_refused_before_anything_is_written(tmp_path, capsys, members, message):
    with pytest.raises(SystemExit) as exit_info:
        unpack(tmp_path, members)
    assert exit_info.value.code == 2
    assert message in capsys.readouterr().out
    assert list((tmp_path / "case" / "root").iterdir()) == []
    assert not (tmp_path / "case" / "escape").exists() and not (tmp_path / "escape").exists()


def test_a_normal_archive_with_inner_links_unpacks(tmp_path):
    root = unpack(tmp_path, [
        member("top/bin", tarfile.DIRTYPE),
        member("top/bin/tool", data=b"#!/bin/sh\n"),
        member("top/jre", tarfile.DIRTYPE),
        member("top/jre/lib/x.so", data=b"x"),
        member("top/current", tarfile.SYMTYPE, "jre"),
        member("top/tool", tarfile.SYMTYPE, "bin/../bin/tool"),
        member("top/hard", tarfile.LNKTYPE, "top/bin/tool"),
    ])
    assert (root / "top" / "tool").read_bytes() == b"#!/bin/sh\n"
    assert (root / "top" / "current" / "lib" / "x.so").read_bytes() == b"x"
    assert (root / "top" / "hard").read_bytes() == b"#!/bin/sh\n"


def test_zip_entries_cannot_leave_the_target(tmp_path, capsys):
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("top/../../pwned.txt", "x")
    root = tmp_path / "case" / "root"
    root.mkdir(parents=True)
    with pytest.raises(SystemExit):
        load().unpack_zip(str(archive), str(root.resolve()))
    assert "points outside the target folder" in capsys.readouterr().out
    assert not (tmp_path / "pwned.txt").exists()


def test_fetch_archive_is_stdlib_only():
    imports = {line.split()[1].split(".")[0] for line in FETCH.read_text().splitlines()
               if line.startswith(("import ", "from "))}
    assert imports <= {"hashlib", "os", "shutil", "sys", "tarfile", "tempfile", "urllib", "zipfile"}


def test_no_tools_image_step_hides_a_failure_behind_a_pipe():
    """Under /bin/sh without pipefail a pipe's status is its last command's,
    so `install.py | tail -1` built an image without Semgrep (audit L1)."""
    dockerfile = (ROOT / "images" / "sast-tools" / "Dockerfile").read_text()
    steps = dockerfile.replace("\\\n", " ").splitlines()
    for step in (s for s in steps if s.startswith("RUN ")):
        assert " | " not in step or "pipefail" in step, step
    assert "RUN python3 /opt/sast/install.py /opt/sast/pins.json\n" in dockerfile
