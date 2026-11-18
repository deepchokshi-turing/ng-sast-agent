#!/usr/bin/env python3
"""Make the pinned security-audit skill, Claude Code and Node.js available.

``CloudflareAuditAgent.setup`` uploads this script with ``cf_pins.json`` and
the Claude review's installer (as ``ccsr_install.py``, whose Claude Code
download and checks are reused unchanged), and runs ``cf_install.py
<cf_pins.json>`` with the image's ``python3``. When a part at the pins'
``install_dir`` passes the checks below it is used as it is (a tools image
could bake one there; none does yet). Otherwise everything is downloaded into
``<work dir>/cloudflare-audit``.

A part holds:

- ``bin/claude``: the Claude Code native binary from npm, sha256 and npm
  sha512 integrity checked, ``claude --version`` must report the pinned version.
- ``node/bin/node``: the one file taken from the official Node.js tarball,
  whose sha256 must match; ``node --version`` must print the pinned version.
- ``skill/security-audit/``: the pinned files of cloudflare/security-audit-skill,
  each checked against its sha256.

``--build --target <dir>`` installs into ``<dir>`` (for a future tools image
build). Standard library only, Python 3.6+. Exit status 0 and a last line
``INSTALL_RESULT {json}`` on success, non-zero with an ``ERROR:`` line
otherwise.
"""

import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
try:
    import ccsr_install  # the Claude review's installer, uploaded next to this file
except ImportError:  # run from the repository (the tests)
    sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))
    from sast.claude_review import install as ccsr_install

InstallError = ccsr_install.InstallError
ROOT = os.environ.get("SAST_ROOT", "/opt/sast")
DEFAULT_BUDGET_SEC = 270
BUILD_BUDGET_SEC = 3600
ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
SKILL_DIR = os.path.join("skill", "security-audit")
NODE_PATH = os.path.join("node", "bin", "node")


def log(message):
    print("[install] " + message, flush=True)


def fail(message):
    print("[install] ERROR: " + message, flush=True)
    sys.exit(2)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- checks


def check_node(part, pins, home):
    node = os.path.join(part, NODE_PATH)
    if not os.path.isfile(node) or not os.access(node, os.X_OK):
        raise InstallError("no executable {}".format(node))
    try:
        proc = subprocess.run([node, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              env=ccsr_install.quiet_env(home), timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("cannot run {} --version: {}".format(node, exc))
    output = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode != 0 or output != "v" + pins["node_version"]:
        raise InstallError("{} --version gave {!r}, expected v{}".format(node, output[-100:], pins["node_version"]))
    return {"node": node, "node_version_output": output}


def check_skill(part, pins):
    base = os.path.join(part, SKILL_DIR)
    for rel, entry in sorted(pins["skill_files"].items()):
        path = os.path.join(base, rel)
        if not os.path.isfile(path) or os.path.islink(path):
            raise InstallError("skill file {} is missing".format(path))
        actual = ccsr_install.sha256_file(path)
        if actual != entry["sha256"]:
            raise InstallError("skill file {} has sha256 {}, expected {}".format(path, actual, entry["sha256"]))
    return {"skill_dir": base, "skill_commit": pins["skill_commit"], "skill_files": len(pins["skill_files"])}


def check_part(part, pins, home):
    """Everything the agent needs from a part, or InstallError."""
    result = {"part": part}
    result.update(ccsr_install.check_claude(part, pins, home))
    result.update(check_node(part, pins, home))
    result.update(check_skill(part, pins))
    try:
        with open(os.path.join(part, "install.json")) as f:
            result["install_json"] = json.load(f)
    except (OSError, ValueError):
        result["install_json"] = None
    return result


# ---------------------------------------------------------------- install


def install_node(part, pins, arch, deadline, fetch=None):
    entry = pins["node"].get(arch)
    if entry is None:
        raise InstallError("no Node.js tarball is pinned for this CPU ({})".format(arch))
    data = (fetch or ccsr_install.fetch)(entry["url"], deadline)
    if sha256_bytes(data) != entry["sha256"]:
        raise InstallError("{} has sha256 {}, expected {}".format(entry["url"], sha256_bytes(data), entry["sha256"]))
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            member = archive.getmember(entry["member"])
            if not member.isfile():
                raise InstallError("{} in {} is not a regular file".format(entry["member"], entry["url"]))
            source = archive.extractfile(member)
            target = os.path.join(part, NODE_PATH)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as out:
                shutil.copyfileobj(source, out, 1 << 20)
    except (KeyError, tarfile.TarError) as exc:
        raise InstallError("cannot unpack {} from {}: {}".format(entry["member"], entry["url"], exc))
    os.chmod(target, 0o755)
    log("Node.js {} for {} installed".format(pins["node_version"], arch))


def install_skill(part, pins, deadline, fetch=None):
    for rel, entry in sorted(pins["skill_files"].items()):
        data = (fetch or ccsr_install.fetch)(entry["url"], deadline)
        if sha256_bytes(data) != entry["sha256"]:
            raise InstallError("{} has sha256 {}, expected {}".format(entry["url"], sha256_bytes(data),
                                                                       entry["sha256"]))
        target = os.path.join(part, SKILL_DIR, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as out:
            out.write(data)
        os.chmod(target, 0o644)
    log("{} at {} installed ({} files)".format(pins["skill_repo"], pins["skill_commit"][:7],
                                               len(pins["skill_files"])))


def install(part, pins, home, deadline):
    arch = ARCH.get(platform.machine().lower(), platform.machine())
    name, _ = ccsr_install.libc()
    if name != "glibc":
        raise InstallError("the pinned Claude Code binary needs glibc Linux, this is {} on {}".format(name, arch))
    staging = part + ".partial"
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    ccsr_install.install_claude(staging, pins, arch, deadline)
    install_node(staging, pins, arch, deadline)
    install_skill(staging, pins, deadline)
    with open(os.path.join(staging, "install.json"), "w") as f:
        json.dump({"pins": pins, "arch": arch}, f, indent=1, sort_keys=True)
        f.write("\n")
    shutil.rmtree(part, ignore_errors=True)
    os.rename(staging, part)
    return check_part(part, pins, home)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("pins")
    parser.add_argument("--build", action="store_true", help="install into --target (tools image build)")
    parser.add_argument("--target", help="where to install (default: <work dir>/cloudflare-audit)")
    parser.add_argument("--budget-sec", type=float, default=DEFAULT_BUDGET_SEC)
    args = parser.parse_args(argv)
    started = time.monotonic()
    with open(args.pins) as f:
        pins = json.load(f)
    home = tempfile.mkdtemp(prefix="cloudflare-audit-home-")
    try:
        if args.build:
            result = install(args.target or pins["install_dir"], pins, home, started + BUILD_BUDGET_SEC)
            print("INSTALL_RESULT " + json.dumps(result), flush=True)
            return 0
        baked = pins["install_dir"]
        try:
            result = check_part(baked, pins, home)
            result["source"] = "image"
            log("using the part baked into the tools image at " + baked)
        except InstallError as exc:
            log("the baked part at {} cannot be used: {}".format(baked, exc))
            target = args.target or os.path.join(ROOT, "cloudflare-audit")
            if os.path.realpath(target) == os.path.realpath(baked):
                target = os.path.join(ROOT, "cloudflare-audit-local")
            log("installing into {} instead".format(target))
            result = install(target, pins, home, started + args.budget_sec)
            result["source"] = "setup"
            result["baked_problem"] = str(exc)
        result["image_manifest"] = ccsr_install.image_manifest("cloudflare-audit",
                                                               recompute=result["source"] == "image")
        result.update({"arch": platform.machine(), "libc": "-".join(ccsr_install.libc()),
                       "seconds": round(time.monotonic() - started, 1)})
        print("INSTALL_RESULT " + json.dumps(result), flush=True)
        return 0
    except InstallError as exc:
        fail(str(exc))
    finally:
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
