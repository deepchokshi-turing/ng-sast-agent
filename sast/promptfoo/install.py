#!/usr/bin/env python3
"""Make the pinned promptfoo, Node.js and git available in the sandbox.

One script for two places, like the Claude review installer:

- A tools image build may run ``install.py <pins.json> --build --target
  /opt/sast/promptfoo`` (not wired into tools/build_tools_image.sh yet: a
  follow-up). It downloads everything, checks every hash and writes
  ``install.json``.
- ``PromptfooCodeScanAgent.setup`` uploads it with ``pins.json``,
  ``package.json`` and ``package-lock.json`` and runs ``install.py
  <pins.json>`` with the sandbox's ``python3``. A baked part at
  ``install_dir`` that passes the checks below is used as it is. Otherwise the
  same steps install it into ``<work dir>/promptfoo`` (this needs the sandbox
  to reach nodejs.org, deb.debian.org or snapshot.debian.org, and
  registry.npmjs.org).

What a part holds and how it is checked:

- ``node/``: the official Node.js tarball for this CPU, whose sha256 must match
  the pin. ``node --version`` must print the pinned version.
- ``git/bin/git``: ``/usr/bin/git`` from the pinned Debian .deb, whose sha256
  must match. ``git --version`` must print the pinned version.
- ``app/``: ``package.json``, ``package-lock.json`` (both must match their
  pinned sha256) and ``node_modules``, installed the way ``npm ci
  --ignore-scripts`` would install that lock: every package tarball is
  downloaded from registry.npmjs.org (no other host is accepted), checked
  against the lock's sha512 ``integrity`` and unpacked at the lock's path. No
  install script runs, no version range is resolved, and a package the lock
  does not name is never fetched. A package limited to other platforms
  (``os``/``cpu``) is skipped only when the lock marks it optional.
  promptfoo's lock entry must carry the pinned integrity, and ``promptfoo
  --version`` must print the pinned version.

Standard library only, written for any Python 3.6+. Exit status 0 and a last
line ``INSTALL_RESULT {json}`` on success, non-zero with an ``ERROR:`` line
otherwise.
"""

import argparse
import base64
import concurrent.futures
import hashlib
import io
import json
import os
import platform
import shutil
import stat
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
DOWNLOAD_WORKERS = 8
ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
PROMPTFOO_ENTRY = os.path.join("app", "node_modules", "promptfoo", "dist", "src", "entrypoint.js")
MCP_ENTRY = os.path.join("app", "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js")
#: What the probes inherit: nothing from the host but the basics.
ENV_ALLOW = frozenset((
    "PATH", "LANG", "LANGUAGE", "TZ", "TMPDIR", "TERM",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
))


def log(message):
    print("[install] " + message, flush=True)


class InstallError(Exception):
    pass


def fail(message):
    print("[install] ERROR: " + message, flush=True)
    sys.exit(2)


def quiet_env(home):
    env = {name: value for name, value in os.environ.items() if name in ENV_ALLOW}
    env.update({"HOME": home, "PROMPTFOO_DISABLE_TELEMETRY": "1", "PROMPTFOO_DISABLE_UPDATE": "1",
                "PROMPTFOO_CONFIG_DIR": os.path.join(home, ".promptfoo"), "NO_COLOR": "1",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    return env


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text_file(path):
    """sha256 of a text file with LF line ends (a CRLF checkout hashes the same)."""
    with open(path, "rb") as f:
        return sha256_bytes(f.read().replace(b"\r\n", b"\n"))


def check_integrity(data, integrity):
    """Whether ``data`` matches an npm SSRI string (its strongest algorithm, as npm checks)."""
    entries = {}
    for item in (integrity or "").split():
        algo, _, digest = item.partition("-")
        if algo in ("sha512", "sha384", "sha256", "sha1") and digest:
            entries.setdefault(algo, []).append(digest)
    for algo in ("sha512", "sha384", "sha256", "sha1"):
        if algo in entries:
            actual = base64.b64encode(hashlib.new(algo, data).digest()).decode("ascii")
            return actual in entries[algo]
    return False


def probe(command, home, what):
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=quiet_env(home),
                              cwd=home, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("cannot run {}: {}".format(what, exc))
    output = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        raise InstallError("{} failed (exit {}): {}".format(what, proc.returncode, output[-600:]))
    return output


# ---------------------------------------------------------------- checks


def check_node(part, pins, home):
    node = os.path.join(part, "node", "bin", "node")
    if not os.path.isfile(node) or not os.access(node, os.X_OK):
        raise InstallError("no executable {}".format(node))
    output = probe([node, "--version"], home, node + " --version")
    if output.splitlines()[-1].strip() != "v" + pins["node_version"]:
        raise InstallError("{} --version gave {!r}, expected v{}".format(node, output[-100:], pins["node_version"]))
    return {"node": node, "node_version_output": output.splitlines()[-1].strip()}


def check_git(part, pins, home):
    git = os.path.join(part, "git", "bin", "git")
    if not os.path.isfile(git) or not os.access(git, os.X_OK):
        raise InstallError("no executable {}".format(git))
    output = probe([git, "--version"], home, git + " --version")
    if output.splitlines()[-1].strip() != "git version " + pins["git_version"]:
        raise InstallError("{} --version gave {!r}, expected git version {}".format(
            git, output[-100:], pins["git_version"]))
    return {"git": git, "git_version_output": output.splitlines()[-1].strip()}


def check_lock(app, pins):
    """The lock and package.json are the pinned ones, and the lock pins promptfoo as expected."""
    for name, key in (("package.json", "package_json_sha256"), ("package-lock.json", "package_lock_sha256")):
        path = os.path.join(app, name)
        if not os.path.isfile(path):
            raise InstallError("{} is missing".format(path))
        if sha256_text_file(path) != pins[key]:
            raise InstallError("{} does not match its pinned sha256".format(path))
    with open(os.path.join(app, "package-lock.json")) as f:
        lock = json.load(f)
    entry = (lock.get("packages") or {}).get("node_modules/promptfoo") or {}
    if entry.get("version") != pins["promptfoo_version"] or entry.get("integrity") != pins["promptfoo_integrity"]:
        raise InstallError("the lock does not pin promptfoo {} with the pinned integrity".format(
            pins["promptfoo_version"]))
    return lock


def check_app(part, pins, home, node):
    app = os.path.join(part, "app")
    check_lock(app, pins)
    for rel in (PROMPTFOO_ENTRY, MCP_ENTRY):
        if not os.path.isfile(os.path.join(part, rel)):
            raise InstallError("{} is missing".format(os.path.join(part, rel)))
    with open(os.path.join(app, "node_modules", "promptfoo", "package.json")) as f:
        installed = json.load(f).get("version")
    if installed != pins["promptfoo_version"]:
        raise InstallError("promptfoo {} is installed, expected {}".format(installed, pins["promptfoo_version"]))
    entry = os.path.join(part, PROMPTFOO_ENTRY)
    output = probe([node, entry, "--version"], home, "promptfoo --version")
    if output.splitlines()[-1].strip() != pins["promptfoo_version"]:
        raise InstallError("promptfoo --version gave {!r}, expected {}".format(output[-300:],
                                                                             pins["promptfoo_version"]))
    return {"promptfoo": entry, "mcp_filesystem": os.path.join(part, MCP_ENTRY),
            "promptfoo_version_output": output.splitlines()[-1].strip(), "app_dir": app}


def check_part(part, pins, home):
    """Everything the agent needs from a part, or InstallError."""
    result = {"part": part}
    result.update(check_node(part, pins, home))
    result.update(check_git(part, pins, home))
    result.update(check_app(part, pins, home, result["node"]))
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


def safe_target(base, name):
    """``base/name`` when it stays inside ``base``, else None."""
    if not name or name.startswith("/") or "\\" in name:
        return None
    target = os.path.normpath(os.path.join(base, name))
    if target != os.path.normpath(base) and not target.startswith(os.path.normpath(base) + os.sep):
        return None
    return target


def unpack(archive, base, strip, skipped, label):
    """Regular files and directories of ``archive`` under ``base``, the first
    ``strip`` path parts removed. Links, devices and unsafe paths are skipped."""
    for member in archive.getmembers():
        parts = [p for p in member.name.split("/") if p not in ("", ".")]
        if len(parts) <= strip:
            continue
        rel = "/".join(parts[strip:])
        target = safe_target(base, rel)
        if target is None or not (member.isfile() or member.isdir()):
            skipped.append("{}: {}".format(label, member.name))
            continue
        if member.isdir():
            os.makedirs(target, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        source = archive.extractfile(member)
        with open(target, "wb") as out:
            shutil.copyfileobj(source, out, 1 << 20)
        os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)


def install_node(part, pins, arch, deadline):
    entry = pins["node"].get(arch)
    if entry is None:
        raise InstallError("no Node.js tarball is pinned for this CPU ({})".format(arch))
    data = fetch(entry["url"], deadline)
    if sha256_bytes(data) != entry["sha256"]:
        raise InstallError("{} has sha256 {}, expected {}".format(entry["url"], sha256_bytes(data), entry["sha256"]))
    target = os.path.join(part, "node")
    skipped = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
        # The tarball's own links (bin/npm, bin/npx, bin/corepack) are not needed: node runs the entry point itself.
        unpack(archive, target, 1, skipped, "node")
    log("Node.js {} for {} installed ({} links skipped)".format(pins["node_version"], arch, len(skipped)))


def deb_member(data, prefix):
    """The body of the first ar member of a .deb whose name starts with ``prefix``."""
    if data[:8] != b"!<arch>\n":
        raise InstallError("not a Debian package (no ar header)")
    pos = 8
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        name = header[:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            raise InstallError("bad ar member header in the .deb")
        body = data[pos + 60:pos + 60 + size]
        if name.startswith(prefix):
            return name, body
        pos += 60 + size + (size % 2)
    raise InstallError("the .deb has no {} member".format(prefix))


def install_git(part, pins, arch, deadline):
    entry = pins["git"].get(arch)
    if entry is None:
        raise InstallError("no git package is pinned for this CPU ({})".format(arch))
    data, problems = None, []
    for url in entry["urls"]:
        try:
            candidate = fetch(url, deadline)
        except InstallError as exc:
            problems.append(str(exc))
            continue
        if sha256_bytes(candidate) == entry["sha256"]:
            data = candidate
            break
        problems.append("{} has sha256 {}, expected {}".format(url, sha256_bytes(candidate), entry["sha256"]))
    if data is None:
        raise InstallError("no usable {}: {}".format(entry["file"], "; ".join(problems)))
    name, body = deb_member(data, "data.tar")
    mode = {"data.tar.xz": "r:xz", "data.tar.gz": "r:gz", "data.tar": "r:"}.get(name)
    if mode is None:
        raise InstallError("unsupported .deb payload {}".format(name))
    with tarfile.open(fileobj=io.BytesIO(body), mode=mode) as archive:
        try:
            member = archive.getmember("./usr/bin/git")
        except KeyError:
            raise InstallError("{} has no ./usr/bin/git".format(entry["file"]))
        if not member.isfile():
            raise InstallError("./usr/bin/git in {} is not a regular file".format(entry["file"]))
        os.makedirs(os.path.join(part, "git", "bin"), exist_ok=True)
        target = os.path.join(part, "git", "bin", "git")
        with open(target, "wb") as out:
            shutil.copyfileobj(archive.extractfile(member), out, 1 << 20)
    os.chmod(target, 0o755)
    log("git {} for {} installed".format(pins["git_deb_version"], arch))


def lock_plan(lock, pins, arch):
    """(packages to fetch as [(lock path, resolved, integrity)], skipped as [(path, why)]).
    Raises InstallError for a lock the agent will not install."""
    cpu = pins["npm_cpu"].get(arch)
    plan, skipped = [], []
    packages = lock.get("packages") or {}
    if len(packages) - 1 != pins["package_lock_entries"]:
        raise InstallError("the lock has {} packages, the pin says {}".format(len(packages) - 1,
                                                                          pins["package_lock_entries"]))
    for path, entry in sorted(packages.items()):
        if not path:
            continue
        if not path.startswith("node_modules/") or safe_target("/x", path) is None:
            raise InstallError("unexpected lock path {!r}".format(path))
        if entry.get("link") or entry.get("inBundle"):
            raise InstallError("lock entry {} is a link or bundled, which this installer does not handle".format(path))
        oses, cpus = entry.get("os"), entry.get("cpu")
        if (oses and "linux" not in oses) or (cpus and cpu not in cpus):
            if not entry.get("optional"):
                raise InstallError("required package {} does not support linux/{}".format(path, cpu))
            skipped.append((path, "platform"))
            continue
        resolved, integrity = entry.get("resolved") or "", entry.get("integrity") or ""
        if not resolved.startswith(pins["npm_registry"]):
            raise InstallError("{} resolves outside {}: {!r}".format(path, pins["npm_registry"], resolved))
        if not integrity:
            raise InstallError("{} has no integrity in the lock".format(path))
        plan.append((path, resolved, integrity))
    return plan, skipped


def install_packages(app, lock, pins, arch, deadline):
    plan, skipped = lock_plan(lock, pins, arch)
    modules = os.path.join(app, "node_modules")
    links = []

    def one(item):
        path, url, integrity = item
        data = fetch(url, deadline)
        if not check_integrity(data, integrity):
            raise InstallError("{} does not match the lock's integrity".format(url))
        return path, data

    with concurrent.futures.ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as pool:
        for path, data in pool.map(one, plan):
            target = safe_target(app, path)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                unpack(archive, target, 1, links, path)
    if not os.path.isdir(modules):
        raise InstallError("no node_modules was written")
    log("{} npm packages installed, {} skipped for this platform, {} archive links skipped".format(
        len(plan), len(skipped), len(links)))
    return {"npm_packages": len(plan), "npm_skipped": [p for p, _ in skipped], "npm_links_skipped": links[:50]}


def install(part, pins, npm_dir, home, deadline):
    arch = ARCH.get(platform.machine().lower(), platform.machine())
    name, _ = platform.libc_ver()
    if name != "glibc":
        raise InstallError("the pinned Node.js, git and libsql binaries need glibc Linux, this is {} on {}".format(
            name or "unknown", arch))
    staging = part + ".partial"
    shutil.rmtree(staging, ignore_errors=True)
    app = os.path.join(staging, "app")
    os.makedirs(app)
    for file in ("package.json", "package-lock.json"):
        shutil.copyfile(os.path.join(npm_dir, file), os.path.join(app, file))
    lock = check_lock(app, pins)
    install_node(staging, pins, arch, deadline)
    install_git(staging, pins, arch, deadline)
    record = {"pins": pins, "arch": arch}
    record.update(install_packages(app, lock, pins, arch, deadline))
    with open(os.path.join(staging, "install.json"), "w") as f:
        json.dump(record, f, indent=1, sort_keys=True)
        f.write("\n")
    shutil.rmtree(part, ignore_errors=True)
    os.rename(staging, part)
    return check_part(part, pins, home)


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
    parser.add_argument("--target", help="where to install (default: <work dir>/promptfoo)")
    parser.add_argument("--npm-dir", help="the folder with package.json and package-lock.json (default: next to "
                                          "pins.json)")
    parser.add_argument("--budget-sec", type=float, default=DEFAULT_BUDGET_SEC)
    args = parser.parse_args(argv)
    started = time.monotonic()
    deadline = started + args.budget_sec
    with open(args.pins) as f:
        pins = json.load(f)
    npm_dir = args.npm_dir or os.path.dirname(os.path.abspath(args.pins))
    home = tempfile.mkdtemp(prefix="promptfoo-home-")
    try:
        if args.build:
            target = args.target or pins["install_dir"]
            result = install(target, pins, npm_dir, home, started + BUILD_BUDGET_SEC)
            print("INSTALL_RESULT " + json.dumps(result), flush=True)
            return 0
        baked = pins["install_dir"]
        try:
            result = check_part(baked, pins, home)
            result["source"] = "image"
            log("using the part baked into the tools image at " + baked)
        except InstallError as exc:
            log("the baked part at {} cannot be used: {}".format(baked, exc))
            target = args.target or os.path.join(ROOT, pins["local_dir_name"])
            if os.path.realpath(target) == os.path.realpath(baked):
                target = os.path.join(ROOT, pins["local_dir_name"] + "-local")
            log("installing into {} instead".format(target))
            result = install(target, pins, npm_dir, home, deadline)
            result["source"] = "setup"
            result["baked_problem"] = str(exc)
        result["image_manifest"] = image_manifest("promptfoo", recompute=result["source"] == "image")
        log("image manifest: " + str(result["image_manifest"].get("status")))
        result.update({"python": sys.executable, "arch": platform.machine(), "libc": "-".join(platform.libc_ver()),
                       "seconds": round(time.monotonic() - started, 1)})
        print("INSTALL_RESULT " + json.dumps(result), flush=True)
        return 0
    except InstallError as exc:
        fail(str(exc))
    finally:
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
