#!/usr/bin/env python3
"""Download one pinned archive, check its sha256 and unpack it into a folder.

Used only while building the sast-tools image (see Dockerfile), with the image's
python3 and the standard library:

    fetch_archive.py <url> <sha256> <dest dir> [--strip-top]

The archive is a .tar.gz or a .zip. With --strip-top its single top-level folder
is dropped, so the contents land directly in <dest dir>. Zip entries keep their
Unix permission bits, which zipfile would otherwise lose (the scanner's start
script and its bundled JRE need the execute bit). Any mismatch or a second
top-level entry stops the build.
"""

import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile


def fail(message):
    print("fetch_archive: ERROR: " + message, flush=True)
    sys.exit(2)


def download(url, path, attempts=4):
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=600) as response, open(path, "wb") as out:
                shutil.copyfileobj(response, out, 1024 * 1024)
            return
        except OSError as exc:
            if attempt == attempts:
                fail("download of {} failed: {}".format(url, exc))
            print("fetch_archive: retrying after: {}".format(exc), flush=True)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_target(root, name):
    target = os.path.realpath(os.path.join(root, name))
    if target != root and not target.startswith(root + os.sep):
        fail("archive entry {!r} points outside the target folder".format(name))
    return target


def unpack_zip(path, root):
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            target = safe_target(root, info.filename)
            mode = (info.external_attr >> 16) & 0o7777
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with archive.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            if mode:
                os.chmod(target, mode)


def _parts(name, what):
    if name.startswith("/") or "\\" in name:
        fail("{} {!r} is absolute or uses backslashes".format(what, name))
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        fail("{} {!r} is empty or contains '..'".format(what, name))
    return parts


def _resolve(base, target, links, depth=0):
    """Where a relative link target lands, following the archive's own symlinks
    the way the file system would. Fails when it leaves the root."""
    if depth > 40:
        fail("symlink loop at {!r}".format("/".join(base)))
    if target.startswith("/"):
        fail("archive symlink target {!r} is absolute".format(target))
    stack = list(base)
    for comp in target.split("/"):
        if comp in ("", "."):
            continue
        if comp == "..":
            if not stack:
                fail("archive symlink target {!r} points outside the target folder".format(target))
            stack.pop()
            continue
        stack.append(comp)
        key = "/".join(stack)
        if key in links:
            stack = _resolve(stack[:-1], links[key], links, depth + 1)
    return stack


def check_tar_members(members):
    """Refuse a tar that could write or point outside the folder it is unpacked into.

    Checking each name and link target with realpath before anything exists on
    disk is not enough: a link to '.' followed by a link through it escapes
    (audit 0.4.0, L2). So: only files, folders and links; no absolute name and
    no '..'; no member below a member that is a symlink; every symlink resolves
    inside the root through the archive's other symlinks; a hard link names a
    member path; no symlink shares its name with another member. The same
    rules as sast/codeql/install.py.
    """
    links = {}
    seen = {}
    for member in members:
        parts = _parts(member.name, "archive entry")
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            fail("archive entry {!r} is not a file, folder or link".format(member.name))
        key = "/".join(parts)
        if key in seen and (member.issym() or seen[key]):
            fail("archive entry {!r} appears twice and one is a symlink".format(member.name))
        seen[key] = seen.get(key, False) or member.issym()
        if member.issym():
            links[key] = member.linkname
    for member in members:
        parts = _parts(member.name, "archive entry")
        for i in range(1, len(parts)):
            if "/".join(parts[:i]) in links:
                fail("archive entry {!r} goes through the symlink {!r}".format(member.name, "/".join(parts[:i])))
        if member.issym():
            _resolve(parts[:-1], member.linkname, links)
        elif member.islnk():
            target = _parts(member.linkname, "hard link target")
            for i in range(1, len(target) + 1):
                if "/".join(target[:i]) in links:
                    fail("hard link {!r} goes through a symlink".format(member.name))


def unpack_tar(path, root):
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        check_tar_members(members)
        # Members checked above. The 'tar' filter (Python 3.11.4 and later)
        # also refuses absolute names and clears setuid bits.
        kwargs = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
        archive.extractall(root, members=members, **kwargs)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    strip_top = "--strip-top" in sys.argv[1:]
    if len(args) != 3:
        fail("usage: fetch_archive.py <url> <sha256> <dest dir> [--strip-top]")
    url, expected, dest = args
    if len(expected) != 64:
        fail("the pinned sha256 for {} is missing or malformed".format(url))

    work = tempfile.mkdtemp()
    archive = os.path.join(work, os.path.basename(url))
    download(url, archive)
    actual = sha256(archive)
    if actual != expected.lower():
        fail("sha256 of {} is {}, expected {}".format(url, actual, expected))

    staging = os.path.realpath(os.path.join(work, "unpacked"))
    os.makedirs(staging)
    if archive.endswith(".zip"):
        unpack_zip(archive, staging)
    else:
        unpack_tar(archive, staging)

    source = staging
    if strip_top:
        entries = os.listdir(staging)
        if len(entries) != 1 or not os.path.isdir(os.path.join(staging, entries[0])):
            fail("expected one top-level folder in {}, found {}".format(url, entries))
        source = os.path.join(staging, entries[0])

    os.makedirs(os.path.dirname(dest.rstrip("/")) or "/", exist_ok=True)
    if os.path.exists(dest):
        fail("{} already exists".format(dest))
    shutil.move(source, dest)
    shutil.rmtree(work, ignore_errors=True)
    print("fetch_archive: {} -> {} (sha256 ok)".format(os.path.basename(url), dest), flush=True)


if __name__ == "__main__":
    main()
