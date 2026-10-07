#!/usr/bin/env python3
"""Make the pinned CodeQL bundle available in the sandbox.

Uploaded to the sandbox by ``CodeQLAgent.setup`` and run with the image's own
``python3``, next to ``pins.json`` (written from ``sast/codeql/pins.py``).
Standard library only, and written for any Python 3.6+.

    install.py <pins.json> [--budget-sec N]

1. The tools image bakes the bundle at ``install_dir`` (/opt/sast/codeql). When
   that folder (a real folder, not a symlink) passes the checks below, it is
   used as it is and nothing is downloaded.
2. Otherwise the pinned bundle for this CPU (``linux64`` on x86_64,
   ``linux-arm64`` on aarch64) is downloaded, its sha256 is checked while it
   streams, every archive member is checked so that nothing can be written or
   point outside the target, and it is unpacked into ``install_dir`` when this
   user can write there, else into ``codeql`` next to ``pins.json`` (the
   agent's work folder). An earlier install at either place is reused when it
   passes the checks.

Checks of any bundle, baked or downloaded: the CLI exists at
``<dir>/codeql``, ``codeql version --format=json`` reports the pinned version,
the bundle's ``codeql/python-queries`` pack has exactly the pinned version, and
the pinned suite file is there. A downloaded bundle is checked in a staging
folder and only then moved into place.

Harbor gives setup 300 s in total. The whole script stops after
``--budget-sec`` (default 270 s): the download has a hard deadline that leaves
``EXTRACT_RESERVE_SEC`` (or a third of a smaller budget) for unpacking and
checking, and a download that does not
finish in time fails with a message saying so, instead of being killed by
Harbor without one.

Exit status 0 and a last line ``INSTALL_RESULT {json}`` on success; non-zero
with an ``ERROR:`` line otherwise. The result names the folder used
(``install_dir``), which the agent runs CodeQL from.
"""

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request

#: Setup's own limit is 300 s; stop before it with a clear message.
DEFAULT_BUDGET_SEC = 270
#: Time kept back from the download for unpacking (about a gigabyte) and checks.
EXTRACT_RESERVE_SEC = 90
#: Longest wait for one network read, so a stalled connection is noticed.
READ_TIMEOUT_SEC = 30

ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def log(message):
    print("[install] " + message, flush=True)


def fail(message):
    print("[install] ERROR: " + message, flush=True)
    sys.exit(2)


class Problem(Exception):
    """A bundle that cannot be used, with the reason."""


# ---------------------------------------------------------------- checks

def cli_version(binary):
    """The version ``codeql version --format=json`` reports."""
    try:
        proc = subprocess.run([binary, "version", "--format=json"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Problem("could not run {}: {}".format(binary, exc))
    if proc.returncode != 0:
        raise Problem("{} version exited {}: {}".format(
            binary, proc.returncode, proc.stderr.decode("utf-8", "replace").strip()[-400:]))
    text = proc.stdout.decode("utf-8", "replace")
    try:
        return json.loads(text[text.index("{"):])["version"]
    except (ValueError, KeyError) as exc:
        raise Problem("cannot read the CodeQL version from: {} ({})".format(text.strip()[:400], exc))


def pack_version(install_dir, pack):
    """Versions of a pack in the bundle's qlpacks folder, from each qlpack.yml."""
    folder = os.path.join(install_dir, "qlpacks", *pack.split("/"))
    found = []
    if not os.path.isdir(folder):
        return found
    for entry in sorted(os.listdir(folder)):
        qlpack = os.path.join(folder, entry, "qlpack.yml")
        if not os.path.isfile(qlpack):
            continue
        with open(qlpack) as f:
            text = f.read()
        name = re.search(r"^name:\s*(\S+)\s*$", text, re.MULTILINE)
        version = re.search(r"^version:\s*(\S+)\s*$", text, re.MULTILINE)
        if name and version and name.group(1) == pack:
            found.append(version.group(1))
    return found


def check_bundle(install_dir, pins):
    """{version, pack version, suite} of a bundle that matches the pins, else Problem."""
    binary = os.path.join(install_dir, "codeql")
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        raise Problem("CodeQL is not installed at {}".format(binary))
    if os.path.islink(install_dir.rstrip("/")):
        # Seen with 2.27.1: through a symlinked bundle folder, database create
        # does not find the bundled query packs and tries to fetch them from
        # ghcr.io, which fails offline.
        raise Problem("{} is a symlink; the bundle must be a real folder".format(install_dir))
    version = cli_version(binary)
    if version != pins["codeql_version"]:
        raise Problem("CodeQL at {} is version {}, expected {}".format(binary, version, pins["codeql_version"]))
    packs = pack_version(install_dir, pins["python_queries_pack"])
    if packs != [pins["python_queries_version"]]:
        raise Problem("{} in the bundle is {}, expected exactly {}".format(
            pins["python_queries_pack"], ", ".join(packs) or "missing", pins["python_queries_version"]))
    suite = os.path.join(install_dir, pins["suite_path"])
    if not os.path.isfile(suite):
        raise Problem("the query suite {} is missing".format(suite))
    return {"codeql_version": version, "python_queries_version": packs[0], "suite": suite}


# ---------------------------------------------------------------- archive safety

def _parts(name, what):
    if name.startswith("/") or "\\" in name:
        raise Problem("{} {!r} is absolute or uses backslashes".format(what, name))
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise Problem("{} {!r} is empty or contains '..'".format(what, name))
    return parts


def _resolve(base, target, links, depth=0):
    """Where a relative link target lands, following the archive's own symlinks
    the way the file system would. Raises Problem when it leaves the root."""
    if depth > 40:
        raise Problem("symlink loop at {!r}".format("/".join(base)))
    if target.startswith("/"):
        raise Problem("absolute symlink target {!r}".format(target))
    stack = list(base)
    for comp in target.split("/"):
        if comp in ("", "."):
            continue
        if comp == "..":
            if not stack:
                raise Problem("symlink target {!r} leaves the target folder".format(target))
            stack.pop()
            continue
        stack.append(comp)
        key = "/".join(stack)
        if key in links:
            stack = _resolve(stack[:-1], links[key], links, depth + 1)
    return stack


def check_members(members, top=None):
    """Refuse an archive that could write or point outside the folder it is unpacked into.

    Only files, folders and links. No absolute name, no '..', no member below a
    member that is a symlink (that is how chained links escape), every symlink
    resolves inside the root through the archive's other symlinks, a hard link
    names a member path, and no symlink shares its name with another member.
    With ``top``, every member is ``top`` or below it.
    """
    links = {}
    seen = {}
    for member in members:
        parts = _parts(member.name, "archive entry")
        if top is not None and parts[0] != top:
            raise Problem("unexpected path in bundle: {}".format(member.name))
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise Problem("archive entry {!r} is not a file, folder or link".format(member.name))
        key = "/".join(parts)
        if key in seen and (member.issym() or seen[key]):
            raise Problem("archive entry {!r} appears twice and one is a symlink".format(member.name))
        seen[key] = seen.get(key, False) or member.issym()
        if member.issym():
            links[key] = member.linkname
    for member in members:
        parts = _parts(member.name, "archive entry")
        for i in range(1, len(parts)):
            if "/".join(parts[:i]) in links:
                raise Problem("archive entry {!r} goes through the symlink {!r}".format(
                    member.name, "/".join(parts[:i])))
        if member.issym():
            _resolve(parts[:-1], member.linkname, links)
        elif member.islnk():
            target = _parts(member.linkname, "hard link target")
            for i in range(1, len(target) + 1):
                if "/".join(target[:i]) in links:
                    raise Problem("hard link {!r} goes through a symlink".format(member.name))
            if top is not None and target[0] != top:
                raise Problem("hard link {!r} points outside the bundle".format(member.name))


# ---------------------------------------------------------------- download

def download(url, dest, expected_sha256, deadline):
    """Stream ``url`` to ``dest``, hashing as it goes, and stop at ``deadline``."""
    attempt = 0
    last_error = None
    while True:
        attempt += 1
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            break
        digest = hashlib.sha256()
        size = 0
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "sast-agents-install"})
            with urllib.request.urlopen(request, timeout=min(READ_TIMEOUT_SEC, remaining)) as response, \
                    open(dest, "wb") as out:
                # read1 returns what has arrived, so a slow trickle still meets the deadline check.
                read = getattr(response, "read1", None) or response.read
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("deadline reached after {} bytes".format(size))
                    block = read(1 << 16)
                    if not block:
                        break
                    digest.update(block)
                    out.write(block)
                    size += len(block)
            actual = digest.hexdigest()
            if actual != expected_sha256.lower():
                fail("bundle sha256 is {}, expected {} ({} bytes from {})".format(
                    actual, expected_sha256, size, url))
            return actual, size
        except (OSError, ValueError) as exc:  # URLError, timeouts and resets are OSErrors
            last_error = exc
            log("download attempt {} of {} failed: {}".format(attempt, url, exc))
            if attempt >= 3:
                break
            time.sleep(min(2 * attempt, max(0, deadline - time.monotonic())))
    if time.monotonic() >= deadline - 1:
        fail("downloading {} did not finish within its {} s share of the setup limit ({}); "
             "use the sast-tools image, which has the bundle baked in".format(
                 url, int(deadline - _STARTED), last_error))
    fail("could not download {}: {}".format(url, last_error))


def extract(archive, staging):
    """Unpack the bundle into ``staging``; returns <staging>/codeql."""
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        try:
            check_members(members, top="codeql")
        except Problem as exc:
            fail(str(exc))
        # Members were checked above. The 'tar' filter (when this Python has
        # one) also keeps 3.12+ from warning, and refuses absolute names.
        kwargs = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
        tar.extractall(staging, members=members, **kwargs)
    return os.path.join(staging, "codeql")


def image_manifest(tool, recompute):
    """The tools image's MANIFEST.json entry for this tool (see sast_manifest.py,
    uploaded next to this script). Never fails the install."""
    try:
        import sast_manifest
    except ImportError:
        return {"present": None, "verified": False, "status": "reader not uploaded"}
    try:
        return sast_manifest.check(tool, recompute=recompute)
    except Exception as exc:  # a broken manifest must not stop the scan
        return {"present": None, "verified": False, "status": "error", "reason": str(exc)}


# ---------------------------------------------------------------- main

_STARTED = time.monotonic()


def _writable_target(path):
    """True when ``path`` can be made (or replaced) as a real folder by this user."""
    if os.path.islink(path.rstrip("/")):
        return False
    parent = os.path.dirname(path.rstrip("/")) or "/"
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        return False
    return os.access(parent, os.W_OK | os.X_OK)


def main():
    args = sys.argv[1:]
    budget = DEFAULT_BUDGET_SEC
    if "--budget-sec" in args:
        i = args.index("--budget-sec")
        budget = float(args[i + 1])
        del args[i:i + 2]
    pins_path = args[0] if args else "pins.json"
    with open(pins_path) as f:
        pins = json.load(f)
    deadline = _STARTED + budget
    # The bundle is about 1.3 GB in 35,000 files (60 s to hash with a cold
    # cache), so its recorded digest is taken as it is, without recomputing.
    manifest = image_manifest("codeql", recompute="bundle too large to hash in setup (about 1.3 GB)")

    install_dir = pins["install_dir"].rstrip("/")
    fallback = os.path.join(os.path.dirname(os.path.abspath(pins_path)), "codeql")
    candidates = [install_dir] + ([fallback] if fallback != install_dir else [])

    reasons = []
    for place in candidates:
        try:
            info = check_bundle(place, pins)
        except Problem as exc:
            reasons.append(str(exc))
            continue
        log("codeql {} at {} matches the pins".format(info["codeql_version"], place))
        result = dict(info, pins=pins, install_dir=place, preinstalled=place == install_dir,
                      downloaded=False, image_manifest=manifest, seconds=round(time.monotonic() - _STARTED, 1))
        print("INSTALL_RESULT " + json.dumps(result), flush=True)
        return
    log("no usable bundle: " + "; ".join(reasons))

    machine = platform.machine().lower()
    arch = ARCH.get(machine)
    bundle = (pins.get("bundles") or {}).get(arch or "")
    if not bundle or not bundle.get("url") or len(bundle.get("sha256") or "") != 64:
        fail("no CodeQL bundle pinned for this CPU ({}), and none is installed at {}".format(
            machine, install_dir))

    target = install_dir if _writable_target(install_dir) else fallback
    if target == fallback and not _writable_target(fallback):
        fail("cannot write {} or {} to install CodeQL".format(install_dir, fallback))
    parent = os.path.dirname(target)
    archive = os.path.join(parent, ".codeql-bundle-{}.tar.gz".format(os.getpid()))
    staging = os.path.join(parent, ".codeql-staging-{}".format(os.getpid()))
    try:
        log("downloading {} into {}".format(bundle["url"], target))
        download_deadline = deadline - min(EXTRACT_RESERVE_SEC, budget / 3)
        started = time.monotonic()
        sha, size = download(bundle["url"], archive, bundle["sha256"], download_deadline)
        download_seconds = round(time.monotonic() - started, 1)
        log("downloaded {} bytes in {} s, sha256 ok".format(size, download_seconds))

        unpacked = extract(archive, staging)
        os.remove(archive)
        if time.monotonic() > deadline:
            fail("unpacking the bundle went past the {} s setup budget".format(int(budget)))
        if not os.path.isdir(unpacked):
            fail("the bundle has no codeql folder")
        try:
            check_bundle(unpacked, pins)
        except Problem as exc:
            fail("the downloaded bundle does not match the pins: {}".format(exc))
        if os.path.lexists(target):
            if os.path.islink(target):
                os.remove(target)
            else:
                shutil.rmtree(target)
        os.rename(unpacked, target)
        try:
            info = check_bundle(target, pins)
        except Problem as exc:
            fail("the bundle stopped matching the pins after the move to {}: {}".format(target, exc))
    except (OSError, tarfile.TarError) as exc:
        fail("installing the bundle into {} failed: {}".format(target, exc))
    finally:
        for leftover in (archive, staging):
            if os.path.lexists(leftover):
                if os.path.isdir(leftover) and not os.path.islink(leftover):
                    shutil.rmtree(leftover, ignore_errors=True)
                else:
                    os.remove(leftover)

    result = dict(info, pins=pins, install_dir=target, preinstalled=False, downloaded=True, arch=arch,
                  image_manifest=manifest,
                  bundle_url=bundle["url"], bundle_sha256=sha, bundle_bytes=size,
                  download_seconds=download_seconds, seconds=round(time.monotonic() - _STARTED, 1))
    print("INSTALL_RESULT " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
