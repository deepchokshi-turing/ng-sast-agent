#!/usr/bin/env python3
"""Make the pinned datadog-saist binary available in the task sandbox.

``DatadogSaistAgent.setup`` uploads this script with the pins and runs
``install.py <pins.json>`` with the image's ``python3``. When a binary at the
pins' ``install_dir`` (a tools image could bake one there; none does yet)
passes the checks below it is used as it is. Otherwise the pinned release zip
is downloaded from github.com into ``<work dir>/datadog-saist``.

The zip must match its pinned sha256 before anything is extracted, the one
executable in it must match its own pinned sha256, and ``datadog-saist -h``
must run and list ``-detection-model`` (the binary has no version flag).

Standard library only. Exit status 0 and a last line ``INSTALL_RESULT {json}``
on success, non-zero with an ``ERROR:`` line otherwise.
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
import time
import urllib.request
import zipfile

ROOT = os.environ.get("SAST_ROOT", "/opt/sast")
DEFAULT_BUDGET_SEC = 270
READ_TIMEOUT_SEC = 60
ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
#: The probe inherits no provider key or other host settings.
ENV_ALLOW = frozenset(("PATH", "LANG", "TZ", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR"))


def log(message):
    print("[install] " + message, flush=True)


class InstallError(Exception):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def asset_for(pins, arch):
    entry = pins["assets"].get(arch)
    if entry is None:
        raise InstallError("no datadog-saist build is pinned for this CPU ({})".format(arch))
    return entry


def check_binary(part, pins, arch):
    path = os.path.join(part, "bin", pins["member"])
    if not os.path.isfile(path) or os.path.islink(path) or not os.access(path, os.X_OK):
        raise InstallError("no executable {}".format(path))
    expected = asset_for(pins, arch)["file_sha256"]
    actual = sha256_file(path)
    if actual != expected:
        raise InstallError("{} has sha256 {}, expected {}".format(path, actual, expected))
    env = {k: v for k, v in os.environ.items() if k in ENV_ALLOW}
    try:
        proc = subprocess.run([path, "-h"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("cannot run {} -h: {}".format(path, exc))
    output = proc.stdout.decode("utf-8", "replace")
    if "-detection-model" not in output:
        raise InstallError("{} -h gave no flag list (exit {}): {}".format(path, proc.returncode, output[-300:]))
    models = ""
    for line in output.splitlines():
        if "Available:" in line:
            models = line.split("Available:", 1)[1].strip()
            break
    return {"part": part, "binary": path, "binary_sha256": actual, "help_exit_code": proc.returncode,
            "models": models}


def fetch(url, deadline):
    last = None
    for attempt in range(3):
        left = deadline - time.monotonic()
        if left <= 0:
            raise InstallError("no time left to download {}".format(url))
        try:
            with urllib.request.urlopen(url, timeout=min(READ_TIMEOUT_SEC, max(5, left))) as response:
                chunks = []
                while True:
                    if time.monotonic() > deadline:
                        raise InstallError("downloading {} did not finish within the setup budget".format(url))
                    block = response.read(1 << 20)
                    if not block:
                        break
                    chunks.append(block)
                return b"".join(chunks)
        except InstallError:
            raise
        except OSError as exc:
            last = exc
            log("retrying {} after: {}".format(url, exc))
            time.sleep(2 * (attempt + 1))
    raise InstallError("could not download {}: {}".format(url, last))


def install(part, pins, arch, deadline):
    entry = asset_for(pins, arch)
    data = fetch(entry["url"], deadline)
    actual = hashlib.sha256(data).hexdigest()
    if actual != entry["sha256"]:
        raise InstallError("{} has sha256 {}, expected {}".format(entry["url"], actual, entry["sha256"]))
    staging = part + ".partial"
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(os.path.join(staging, "bin"))
    target = os.path.join(staging, "bin", pins["member"])
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        try:
            info = archive.getinfo(pins["member"])
        except KeyError:
            raise InstallError("{} holds no {}".format(entry["url"], pins["member"]))
        with archive.open(info) as source, open(target, "wb") as out:
            shutil.copyfileobj(source, out, 1 << 20)
    os.chmod(target, 0o755)
    with open(os.path.join(staging, "install.json"), "w") as f:
        json.dump({"version": pins["version"], "commit": pins["commit"], "arch": arch, "url": entry["url"],
                   "sha256": entry["sha256"], "file_sha256": entry["file_sha256"]}, f, indent=1, sort_keys=True)
    shutil.rmtree(part, ignore_errors=True)
    os.rename(staging, part)
    log("{} installed".format(os.path.basename(entry["url"])))
    return check_binary(part, pins, arch)


def image_manifest(tool, recompute):
    try:
        import sast_manifest
    except ImportError:
        return {"present": None, "verified": False, "status": "reader not uploaded"}
    try:
        return sast_manifest.check(tool, recompute=recompute)
    except Exception as exc:
        return {"present": None, "verified": False, "status": "error", "reason": str(exc)}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("pins")
    parser.add_argument("--target", help="where to install (default: <work dir>/datadog-saist)")
    parser.add_argument("--budget-sec", type=float, default=DEFAULT_BUDGET_SEC)
    args = parser.parse_args(argv)
    started = time.monotonic()
    with open(args.pins) as f:
        pins = json.load(f)
    arch = ARCH.get(platform.machine().lower(), platform.machine())
    try:
        if platform.system() != "Linux":
            raise InstallError("the pinned datadog-saist build is for Linux, this is {}".format(platform.system()))
        baked = pins["install_dir"]
        try:
            result = check_binary(baked, pins, arch)
            result["source"] = "image"
        except InstallError as exc:
            target = args.target or os.path.join(ROOT, "datadog-saist")
            if os.path.realpath(target) == os.path.realpath(baked):
                target = os.path.join(ROOT, "datadog-saist-local")
            log("the baked part at {} cannot be used ({}); installing into {}".format(baked, exc, target))
            result = install(target, pins, arch, started + args.budget_sec)
            result["source"] = "setup"
            result["baked_problem"] = str(exc)
        result["image_manifest"] = image_manifest("datadog-saist", recompute=result["source"] == "image")
        result.update({"version": pins["version"], "commit": pins["commit"], "arch": platform.machine(),
                       "seconds": round(time.monotonic() - started, 1)})
        print("INSTALL_RESULT " + json.dumps(result), flush=True)
        return 0
    except InstallError as exc:
        print("[install] ERROR: " + str(exc), flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
