#!/usr/bin/env python3
"""Make the pinned Codex CLI available in the task sandbox.

``CodexSecurityAgent.setup`` uploads this script with ``pins.json`` and runs
``install.py <pins.json>`` with the image's ``python3``. When a part at the
pins' ``install_dir`` (a tools image could bake one there; none does yet)
passes the checks below it is used as it is. Otherwise the pinned release
assets are downloaded from github.com into ``<work dir>/codex-security``.

A part holds three executables from the GitHub release of openai/codex
(see pins.py): ``bin/codex``, ``bin/codex-code-mode-host`` and
``bin/codex-resources/bwrap``. Each download must match its pinned sha256
before anything is extracted, each extracted file must match its own pinned
sha256, and ``codex --version`` must print ``codex-cli <pinned version>``.

``--build --target <dir>`` installs into ``<dir>`` (for a future tools image
build). Standard library only, written for any Python 3.6+. Exit status 0 and
a last line ``INSTALL_RESULT {json}`` on success, non-zero with an ``ERROR:``
line otherwise.
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
import urllib.request

ROOT = os.environ.get("SAST_ROOT", "/opt/sast")
DEFAULT_BUDGET_SEC = 270
BUILD_BUDGET_SEC = 3600
READ_TIMEOUT_SEC = 60
ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}

#: What the version probe inherits: no OPENAI_*, CODEX_* or other host settings.
ENV_ALLOW = frozenset((
    "PATH", "LANG", "LANGUAGE", "TZ", "TMPDIR", "TERM", "USER", "LOGNAME",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy",
    "no_proxy",
))


def log(message):
    print("[install] " + message, flush=True)


class InstallError(Exception):
    pass


def fail(message):
    print("[install] ERROR: " + message, flush=True)
    sys.exit(2)


def quiet_env(home):
    """An allow-listed environment with a throw-away HOME and CODEX_HOME."""
    env = {name: value for name, value in os.environ.items() if name in ENV_ALLOW or name.startswith("LC_")}
    env.update({"HOME": home, "CODEX_HOME": os.path.join(home, "codex-home")})
    return env


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def arch_assets(pins, arch):
    assets = pins["assets"].get(arch)
    if assets is None:
        raise InstallError("no Codex build is pinned for this CPU ({})".format(arch))
    return assets


# ---------------------------------------------------------------- checks


def check_files(part, assets):
    """Every pinned executable is there, executable, and has its pinned sha256."""
    found = {}
    for tool, entry in sorted(assets.items()):
        path = os.path.join(part, entry["path"])
        if not os.path.isfile(path) or os.path.islink(path) or not os.access(path, os.X_OK):
            raise InstallError("no executable {}".format(path))
        actual = sha256_file(path)
        if actual != entry["file_sha256"]:
            raise InstallError("{} has sha256 {}, expected {}".format(path, actual, entry["file_sha256"]))
        found[tool] = path
    return found


def check_version(codex, pins, home):
    try:
        os.makedirs(os.path.join(home, "codex-home"), exist_ok=True)
        proc = subprocess.run([codex, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=quiet_env(home), timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("cannot run {} --version: {}".format(codex, exc))
    output = proc.stdout.decode("utf-8", "replace").strip()
    expected = "codex-cli {}".format(pins["codex_version"])
    if proc.returncode != 0 or output != expected:
        raise InstallError("{} --version gave {!r} (exit {}), expected {!r}".format(
            codex, output[-300:], proc.returncode, expected))
    return output


def check_part(part, pins, arch, home):
    """Everything the agent needs from a part, or InstallError."""
    files = check_files(part, arch_assets(pins, arch))
    result = {"part": part, "codex": files["codex"], "code_mode_host": files["codex-code-mode-host"],
              "bwrap": files["bwrap"], "codex_version_output": check_version(files["codex"], pins, home)}
    try:
        with open(os.path.join(part, "install.json")) as f:
            result["install_json"] = json.load(f)
    except (OSError, ValueError):
        result["install_json"] = None
    return result


# ---------------------------------------------------------------- install


def fetch(url, deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise InstallError("no time left to download {}".format(url))
    last = None
    for attempt in range(3):
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


def install_asset(part, tool, entry, deadline):
    data = fetch(entry["url"], deadline)
    actual = hashlib.sha256(data).hexdigest()
    if actual != entry["sha256"]:
        raise InstallError("{} has sha256 {}, expected {}".format(entry["url"], actual, entry["sha256"]))
    target = os.path.join(part, entry["path"])
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        try:
            member = archive.getmember(entry["member"])
        except KeyError:
            raise InstallError("{} holds no {}".format(entry["url"], entry["member"]))
        if not member.isfile():
            raise InstallError("{} in {} is not a regular file".format(entry["member"], entry["url"]))
        source = archive.extractfile(member)
        with open(target, "wb") as out:
            shutil.copyfileobj(source, out, 1 << 20)
    os.chmod(target, 0o755)
    actual = sha256_file(target)
    if actual != entry["file_sha256"]:
        raise InstallError("{} from {} has sha256 {}, expected {}".format(target, entry["url"], actual,
                                                                         entry["file_sha256"]))
    log("{} {} installed".format(tool, os.path.basename(entry["url"])))


def install(part, pins, arch, home, deadline):
    assets = arch_assets(pins, arch)
    staging = part + ".partial"
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    for tool, entry in sorted(assets.items()):
        install_asset(staging, tool, entry, deadline)
    record = {"codex_version": pins["codex_version"], "release_tag": pins["release_tag"], "arch": arch,
              "assets": {tool: {"url": e["url"], "sha256": e["sha256"], "file_sha256": e["file_sha256"]}
                         for tool, e in assets.items()}}
    with open(os.path.join(staging, "install.json"), "w") as f:
        json.dump(record, f, indent=1, sort_keys=True)
        f.write("\n")
    shutil.rmtree(part, ignore_errors=True)
    os.rename(staging, part)
    return check_part(part, pins, arch, home)


def image_manifest(tool, recompute):
    """The tools image's MANIFEST.json entry (sast_manifest.py, uploaded next to
    this script). Never fails the install."""
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
    parser.add_argument("--build", action="store_true", help="install into --target (tools image build)")
    parser.add_argument("--target", help="where to install (default: <work dir>/codex-security)")
    parser.add_argument("--budget-sec", type=float, default=DEFAULT_BUDGET_SEC)
    args = parser.parse_args(argv)
    started = time.monotonic()
    deadline = started + args.budget_sec
    with open(args.pins) as f:
        pins = json.load(f)
    arch = ARCH.get(platform.machine().lower(), platform.machine())
    home = tempfile.mkdtemp(prefix="codex-security-home-")
    try:
        if platform.system() != "Linux":
            raise InstallError("the pinned Codex build is for Linux, this is {}".format(platform.system()))
        if args.build:
            target = args.target or pins["install_dir"]
            result = install(target, pins, arch, home, started + BUILD_BUDGET_SEC)
            print("INSTALL_RESULT " + json.dumps(result), flush=True)
            return 0
        baked = pins["install_dir"]
        try:
            result = check_part(baked, pins, arch, home)
            result["source"] = "image"
            log("using the part baked into the tools image at " + baked)
        except InstallError as exc:
            log("the baked part at {} cannot be used: {}".format(baked, exc))
            target = args.target or os.path.join(ROOT, "codex-security")
            if os.path.realpath(target) == os.path.realpath(baked):
                target = os.path.join(ROOT, "codex-security-local")
            log("installing into {} instead".format(target))
            result = install(target, pins, arch, home, deadline)
            result["source"] = "setup"
            result["baked_problem"] = str(exc)
        result["image_manifest"] = image_manifest("codex-security", recompute=result["source"] == "image")
        result.update({"arch": platform.machine(), "seconds": round(time.monotonic() - started, 1)})
        print("INSTALL_RESULT " + json.dumps(result), flush=True)
        return 0
    except InstallError as exc:
        fail(str(exc))
    finally:
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
