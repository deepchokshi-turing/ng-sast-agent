#!/usr/bin/env python3
"""Check the CodeQL bundle baked into the tools image against the pins.

Uploaded to the sandbox by ``CodeQLAgent.setup`` and run with the image's own
``python3``, next to ``pins.json`` (written from ``sast/codeql/pins.py``).
Standard library only, and written for any Python 3.6+.

Nothing is downloaded. The bundle is about a gigabyte and does not fit in
Harbor's 300 s setup limit, so a missing or different bundle is a failure that
says which image to use.

Checks: the CLI exists at ``<install_dir>/codeql`` (a real folder, not a
symlink), ``codeql version
--format=json`` reports the pinned version, the bundle's
``codeql/python-queries`` pack has the pinned version, and the pinned suite file
is there.

Exit status 0 and a last line ``INSTALL_RESULT {json}`` on success; non-zero
with an ``ERROR:`` line otherwise.
"""

import json
import os
import re
import subprocess
import sys
import time


def log(message):
    print("[install] " + message, flush=True)


def fail(message):
    print("[install] ERROR: " + message, flush=True)
    sys.exit(2)


def cli_version(binary):
    """The version ``codeql version --format=json`` reports."""
    try:
        proc = subprocess.run([binary, "version", "--format=json"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail("could not run {}: {}".format(binary, exc))
    if proc.returncode != 0:
        fail("{} version exited {}: {}".format(binary, proc.returncode,
                                               proc.stderr.decode("utf-8", "replace").strip()[-400:]))
    text = proc.stdout.decode("utf-8", "replace")
    try:
        return json.loads(text[text.index("{"):])["version"]
    except (ValueError, KeyError) as exc:
        fail("cannot read the CodeQL version from: {} ({})".format(text.strip()[:400], exc))


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


def main():
    started = time.time()
    pins_path = sys.argv[1] if len(sys.argv) > 1 else "pins.json"
    with open(pins_path) as f:
        pins = json.load(f)

    install_dir = pins["install_dir"]
    binary = os.path.join(install_dir, "codeql")
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        fail("CodeQL is not installed at {}. It is not downloaded at setup (too big for the 300 s limit): "
             "build the task image FROM the sast-tools image, which has the {} bundle there.".format(
                 binary, pins["bundle_tag"]))

    if os.path.islink(install_dir.rstrip("/")):
        # Seen with 2.27.1: through a symlinked bundle folder, database create
        # does not find the bundled query packs and tries to fetch them from
        # ghcr.io, which fails offline.
        fail("{} is a symlink; unpack the bundle there as a real folder".format(install_dir))

    version = cli_version(binary)
    log("codeql {} at {}".format(version, binary))
    if version != pins["codeql_version"]:
        fail("CodeQL at {} is version {}, expected {}".format(binary, version, pins["codeql_version"]))

    packs = pack_version(install_dir, pins["python_queries_pack"])
    if packs != [pins["python_queries_version"]]:
        fail("{} in the bundle is {}, expected exactly {}".format(
            pins["python_queries_pack"], ", ".join(packs) or "missing", pins["python_queries_version"]))

    suite = os.path.join(install_dir, pins["suite_path"])
    if not os.path.isfile(suite):
        fail("the query suite {} is missing".format(suite))

    result = {
        "pins": pins,
        "codeql_version": version,
        "python_queries_version": packs[0],
        "suite": suite,
        "preinstalled": True,
        "seconds": round(time.time() - started, 1),
    }
    print("INSTALL_RESULT " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
