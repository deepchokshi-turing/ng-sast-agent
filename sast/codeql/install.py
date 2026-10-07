#!/usr/bin/env python3
"""Install the pinned CodeQL bundle inside a task sandbox (or into the tools image).

Uploaded by ``CodeQLAgent.setup`` next to ``codeql-pins.json`` (written from
``sast/codeql/pins.py``) and run with the image's own ``python3``. The bundle
carries its own Java runtime and the query packs, so no other package is needed
and nothing is downloaded at scan time.

The bundle is large (about 650 MB), so the normal place for it is the
pre-built ``sast-tools`` image. When ``$SAST_ROOT/codeql`` already holds an
install that matches the pins, this script only checks it and exits.

Written for any Python 3.6+. The install root is ``$SAST_ROOT`` (default
``/opt/sast``); CodeQL goes to ``$SAST_ROOT/codeql``.

Exit status 0 and a last line ``INSTALL_RESULT {json}`` on success; non-zero
with an ``ERROR:`` line otherwise.
"""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request

ROOT = os.environ.get("SAST_ROOT", "/opt/sast")
CODEQL_HOME = ROOT + "/codeql"
CLI = CODEQL_HOME + "/codeql"
RESULT_FILE = CODEQL_HOME + "/install.json"
DOWNLOADS = ROOT + "/downloads"

ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


def log(message):
    print("[codeql-install] " + message, flush=True)


def fail(message):
    print("[codeql-install] ERROR: " + message, flush=True)
    sys.exit(2)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url, dest, attempts=4):
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "sast-agents-install"})
            with urllib.request.urlopen(request, timeout=120) as response, open(dest + ".part", "wb") as f:
                shutil.copyfileobj(response, f, 1 << 22)
            os.replace(dest + ".part", dest)
            return
        except Exception as exc:  # network errors vary by Python version
            log("download failed ({}/{}) {}: {}".format(attempt, attempts, url, exc))
            time.sleep(2 * attempt)
    fail("could not download " + url)


def run(command):
    """stdout only: CodeQL writes progress lines to stderr, which would break --format=json."""
    proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        print(proc.stdout.decode("utf-8", "replace").rstrip(), flush=True)
        print(proc.stderr.decode("utf-8", "replace").rstrip(), flush=True)
        fail("command failed with exit code {}: {}".format(proc.returncode, " ".join(command)))
    return proc.stdout.decode("utf-8", "replace")


def describe(pins):
    """What the installed CLI reports: version and the suites it can resolve."""
    version = json.loads(run([CLI, "version", "--format=json"]))
    if version.get("version") != pins["codeql_version"]:
        fail("codeql reports version {}, expected {}".format(version.get("version"), pins["codeql_version"]))
    packs = {}
    for pack, pack_version in sorted(pins.get("query_packs", {}).items()):
        pack_dir = os.path.join(CODEQL_HOME, "qlpacks", pack)
        if not os.path.isdir(os.path.join(pack_dir, pack_version)):
            found = sorted(os.listdir(pack_dir)) if os.path.isdir(pack_dir) else []
            fail("query pack {} {} is not in the bundle (found {})".format(pack, pack_version, found or "none"))
        packs[pack] = pack_version
    suites = {}
    for language, suite in sorted(pins["suites"].items()):
        resolved = json.loads(run([CLI, "resolve", "queries", "--format=json", suite]))
        if not resolved:
            fail("suite {} resolves to no queries".format(suite))
        suites[language] = len(resolved)
    return {"codeql_version": version["version"], "query_packs": packs, "suite_query_counts": suites}


def installed(pins):
    try:
        with open(RESULT_FILE) as f:
            previous = json.load(f)
    except (OSError, ValueError):
        return None
    if previous.get("pins") != pins or not os.access(CLI, os.X_OK):
        return None
    try:
        version = json.loads(subprocess.run([CLI, "version", "--format=json"], stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL).stdout.decode("utf-8", "replace"))
    except ValueError:
        return None
    return previous if version.get("version") == pins["codeql_version"] else None


def main():
    started = time.time()
    pins_path = sys.argv[1] if len(sys.argv) > 1 else ROOT + "/codeql-pins.json"
    with open(pins_path) as f:
        pins = json.load(f)

    previous = installed(pins)
    if previous is not None:
        log("already installed with these pins (pre-baked image or earlier run)")
        previous["preinstalled"] = True
        print("INSTALL_RESULT " + json.dumps(previous), flush=True)
        return

    machine = platform.machine().lower()
    arch = ARCH.get(machine)
    if arch is None or arch not in pins["bundles"]:
        fail("unsupported CPU architecture: " + machine)
    bundle_platform, expected = pins["bundles"][arch]

    os.makedirs(DOWNLOADS, exist_ok=True)
    archive = DOWNLOADS + "/codeql-bundle.tar.gz"
    url = pins["bundle_url"].format(tag=pins["bundle_tag"], platform=bundle_platform)
    log("downloading " + url)
    download(url, archive)
    actual = sha256_file(archive)
    if actual != expected:
        fail("bundle sha256 is {}, expected {}".format(actual, expected))

    shutil.rmtree(CODEQL_HOME, ignore_errors=True)
    log("extracting")
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            name = member.name
            if not (name == "codeql" or name.startswith("codeql/")) or ".." in name.split("/"):
                fail("unexpected path in bundle: " + name)
        # Python 3.12+ warns (3.14 refuses some links) without an explicit filter;
        # the paths were checked above, so the permissive 'tar' filter is enough.
        tar.extractall(ROOT, **({"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}))
    shutil.rmtree(DOWNLOADS, ignore_errors=True)

    info = describe(pins)
    result = dict(info, pins=pins, arch=arch, bundle_sha256=actual, seconds=round(time.time() - started, 1))
    with open(RESULT_FILE, "w") as f:
        json.dump(result, f)
    print("INSTALL_RESULT " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
