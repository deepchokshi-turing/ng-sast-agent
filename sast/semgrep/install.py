#!/usr/bin/env python3
"""Install Semgrep and its pinned rules inside a task sandbox.

Uploaded to the sandbox by ``SemgrepAgent.setup`` and run with the image's own
``python3``, next to ``pins.json`` (written from ``sast/semgrep/pins.py``).

The image's Python is used only to fetch ``uv``: Node and TypeScript images often
have a ``python3`` without pip, venv or ensurepip, and slim images have no curl.
``uv`` then brings its own CPython and installs Semgrep into ``/opt/sast/venv``,
so one path works on every image. Nothing is written under ``/app``.

Written for any Python 3.6+, because that is all we can assume about the image.
The install root is ``$SAST_ROOT`` (default ``/opt/sast``).

Exit status 0 and a last line ``INSTALL_RESULT {json}`` on success; non-zero
with an ``ERROR:`` line otherwise.
"""

import glob
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
BIN = ROOT + "/bin"
VENV = ROOT + "/venv"
RULES = ROOT + "/rules"
MERGED = ROOT + "/rules-merged"
DOWNLOADS = ROOT + "/downloads"
RESULT_FILE = ROOT + "/install.json"

ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
UV_URL = "https://github.com/astral-sh/uv/releases/download/{version}/uv-{arch}-unknown-linux-musl.tar.gz"
RULES_URL = "https://github.com/{repo}/archive/{commit}.tar.gz"


def log(message):
    print("[install] " + message, flush=True)


def fail(message):
    print("[install] ERROR: " + message, flush=True)
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
            with urllib.request.urlopen(request, timeout=60) as response, open(dest + ".part", "wb") as f:
                shutil.copyfileobj(response, f, 1 << 20)
            os.replace(dest + ".part", dest)
            return
        except Exception as exc:  # network errors vary by Python version
            log("download failed ({}/{}) {}: {}".format(attempt, attempts, url, exc))
            time.sleep(2 * attempt)
    fail("could not download " + url)


def check_libc():
    """Semgrep 1.179.0 ships manylinux_2_34 and musllinux wheels only."""
    if glob.glob("/lib/ld-musl-*.so.1"):
        return "musl"
    try:
        found = os.confstr("CS_GNU_LIBC_VERSION")  # e.g. "glibc 2.36"
    except (AttributeError, ValueError, OSError):
        found = None
    if not found:
        fail("cannot identify the C library; Semgrep needs glibc >= 2.34 or musl")
    version = found.split()[-1]
    major, minor = (int(part) for part in version.split(".")[:2])
    if (major, minor) < (2, 34):
        fail("{} is too old: Semgrep's wheels need glibc >= 2.34 (Debian 12, Ubuntu 22.04 or newer)".format(found))
    return found


def run(command, env=None):
    log("$ " + " ".join(command))
    proc = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = proc.stdout.decode("utf-8", "replace")
    if output.strip():
        print(output.rstrip(), flush=True)
    if proc.returncode != 0:
        fail("command failed with exit code {}: {}".format(proc.returncode, " ".join(command)))
    return output


def install_uv(pins, arch):
    expected = pins["uv_sha256"][arch]
    archive = DOWNLOADS + "/uv.tar.gz"
    download(UV_URL.format(version=pins["uv_version"], arch=arch), archive)
    actual = sha256_file(archive)
    if actual != expected:
        fail("uv archive sha256 is {}, expected {}".format(actual, expected))
    member_name = "uv-{}-unknown-linux-musl/uv".format(arch)
    with tarfile.open(archive, "r:gz") as tar:
        source = tar.extractfile(member_name)
        if source is None:
            fail("uv binary not found in the archive")
        with open(BIN + "/uv", "wb") as out:
            shutil.copyfileobj(source, out)
    os.chmod(BIN + "/uv", 0o755)
    return BIN + "/uv"


def uv_env():
    env = dict(os.environ)
    env.update({
        "UV_CACHE_DIR": ROOT + "/cache",
        "UV_PYTHON_INSTALL_DIR": ROOT + "/python",
        "UV_PYTHON_PREFERENCE": "only-managed",
        "UV_NO_CONFIG": "1",  # ignore any uv.toml / pyproject in the working directory
        "UV_LINK_MODE": "copy",
        "UV_NO_PROGRESS": "1",
    })
    return env


def select_rule_files(names, top, dirs):
    """Rule YAML files under ``dirs`` in a GitHub archive, minus test fixtures.

    Returns (member name, path relative to the rules root) pairs, sorted.
    """
    prefixes = tuple(top + d.strip("/") + "/" for d in dirs)
    chosen = []
    for name in names:
        if not name.startswith(prefixes):
            continue
        rel = name[len(top):]
        base = rel.rsplit("/", 1)[-1]
        if not base.endswith((".yaml", ".yml")) or ".test." in base:
            continue
        if rel.startswith("/") or ".." in rel.split("/"):
            fail("unsafe path in rules archive: " + name)
        chosen.append((name, rel))
    return sorted(chosen, key=lambda pair: pair[1])


def rules_digest(files):
    """sha256 over sorted "<relative path>\\0<sha256 of content>\\n" lines.

    Over the extracted content rather than the archive bytes: GitHub does not
    promise that an archive of one commit is byte-identical over time.
    """
    lines = sorted("{}\0{}\n".format(rel, hashlib.sha256(data).hexdigest()) for rel, data in files)
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def read_rules_archive(archive, dirs):
    """(relative path, bytes) for every selected rule file in the archive."""
    with tarfile.open(archive, "r:gz") as tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}
        tops = {name.split("/", 1)[0] + "/" for name in members}
        if len(tops) != 1:
            fail("unexpected rules archive layout")
        top = tops.pop()
        files = []
        for name, rel in select_rule_files(members, top, dirs):
            files.append((rel, tar.extractfile(members[name]).read()))
    return files


def install_rules(pins):
    archive = DOWNLOADS + "/rules.tar.gz"
    download(RULES_URL.format(repo=pins["rules_repo"], commit=pins["rules_commit"]), archive)
    files = read_rules_archive(archive, pins["rules_dirs"])
    digest = rules_digest(files)
    if digest != pins["rules_digest"] or len(files) != pins["rules_file_count"]:
        fail("rules content is {} ({} files), expected {} ({} files)".format(
            digest, len(files), pins["rules_digest"], pins["rules_file_count"]))
    shutil.rmtree(RULES, ignore_errors=True)
    for rel, data in files:
        path = os.path.join(RULES, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as out:
            out.write(data)
    return digest, len(files)


def merge_rules(pins):
    """One config file per rules folder (see merge_rules.py for why)."""
    output = run([VENV + "/bin/python", os.path.join(os.path.dirname(os.path.abspath(__file__)), "merge_rules.py"),
                  RULES, MERGED] + list(pins["rules_dirs"]))
    for line in reversed(output.splitlines()):
        if line.startswith("MERGED "):
            return json.loads(line[len("MERGED "):])
    fail("merging the rules printed no summary")


def semgrep_env():
    """Semgrep's entry point finds semgrep-core through PATH: put the venv first,
    so a Semgrep that the image already has is never picked up instead."""
    env = dict(os.environ)
    env.update({"HOME": ROOT + "/home", "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off",
                "PATH": VENV + "/bin:" + os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")})
    return env


def installed(pins):
    """The earlier install result if everything it promises is still on disk."""
    try:
        with open(RESULT_FILE) as f:
            previous = json.load(f)
    except (OSError, ValueError):
        return None
    if previous.get("pins") != pins:
        return None
    merged = [os.path.join(MERGED, d.replace("/", "_") + ".yaml") for d in pins["rules_dirs"]]
    if not os.path.exists(VENV + "/bin/semgrep") or not all(os.path.exists(m) for m in merged):
        return None
    proc = subprocess.run([VENV + "/bin/semgrep", "--version"], env=semgrep_env(),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = proc.stdout.decode("utf-8", "replace").strip().splitlines()
    if proc.returncode != 0 or not lines or lines[-1].strip() != pins["semgrep_version"]:
        return None
    return previous


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


def main():
    started = time.time()
    pins_path = sys.argv[1] if len(sys.argv) > 1 else ROOT + "/pins.json"
    with open(pins_path) as f:
        pins = json.load(f)

    # Before anything runs Semgrep, which could write bytecode into the venv.
    # About 400 MB and 7,400 files: 1.5 s to hash with a cold cache.
    manifest = image_manifest("semgrep", recompute=True)
    log("image manifest: " + manifest.get("status", "?"))
    previous = installed(pins)
    if previous is not None:
        log("already installed with these pins (pre-baked image or earlier run)")
        previous["preinstalled"] = True
        previous["image_manifest"] = manifest
        print("INSTALL_RESULT " + json.dumps(previous), flush=True)
        return

    machine = platform.machine().lower()
    arch = ARCH.get(machine)
    if arch is None:
        fail("unsupported CPU architecture: " + machine)
    libc = check_libc()
    log("python {} on {} ({})".format(platform.python_version(), arch, libc))

    for d in (BIN, DOWNLOADS, ROOT + "/home", ROOT + "/out"):
        os.makedirs(d, exist_ok=True)

    uv = install_uv(pins, arch)
    env = uv_env()
    run([uv, "venv", "--clear", "--python", pins["python_version"], VENV], env=env)
    run([uv, "pip", "install", "--python", VENV + "/bin/python",
         "--exclude-newer", pins["exclude_newer"],
         "semgrep==" + pins["semgrep_version"]], env=env)

    digest, count = install_rules(pins)
    merged = merge_rules(pins)

    version = run([VENV + "/bin/semgrep", "--version"], env=semgrep_env()).strip().splitlines()[-1].strip()
    if version != pins["semgrep_version"]:
        fail("semgrep reports version {}, expected {}".format(version, pins["semgrep_version"]))

    result = {
        "pins": pins,
        "arch": arch,
        "libc": libc,
        "semgrep_version": version,
        "rules_digest": digest,
        "rules_file_count": count,
        "rules_merged": merged,
        "rule_count": sum(merged.values()),
        "seconds": round(time.time() - started, 1),
    }
    with open(RESULT_FILE, "w") as f:
        json.dump(result, f)
    # Not in install.json: that file is part of the image the manifest covers.
    result["image_manifest"] = manifest
    # The venv is self-contained (UV_LINK_MODE=copy); the cache is hundreds of MB.
    shutil.rmtree(DOWNLOADS, ignore_errors=True)
    shutil.rmtree(ROOT + "/cache", ignore_errors=True)
    print("INSTALL_RESULT " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
