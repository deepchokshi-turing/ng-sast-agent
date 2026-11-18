#!/usr/bin/env python3
"""Make the pinned Claude Code security review available.

One script for two places, like the Semgrep installer:

- The tools image build runs ``install.py <pins.json> --build --target
  /opt/sast/claude-review --python <python> [--uv <uv>]``. It downloads
  everything, checks every hash, builds the venv and writes ``install.json``.
- ``ClaudeReviewAgent.setup`` uploads it with ``pins.json`` and
  ``requirements.lock`` and runs ``install.py <pins.json>`` with the image's
  ``python3``. When the baked part at ``install_dir`` passes the checks below it
  is used as it is. Otherwise the same steps as the build install it into
  ``<work dir>/claude-review`` (a fallback that needs the sandbox to reach
  registry.npmjs.org, raw.githubusercontent.com and pypi.org).

What a part holds and how it is checked:

- ``bin/claude``: the Claude Code native binary from the npm platform package
  for this CPU (glibc Linux x86_64 or aarch64), whose tarball must match the
  pinned sha256 and npm sha512 integrity. ``claude --version`` must report the
  pinned version.
- ``ccsr/``: the pinned upstream files, each checked against its sha256.
- ``venv/``: a venv with the hash-pinned requirements (``--require-hashes``),
  made with ``uv`` when one is at hand (the tools image has /opt/sast/bin/uv),
  else with ``python -m venv`` and pip. The venv's Python must import
  anthropic and requests at the pinned versions and the upstream package.

Standard library only, and written for any Python 3.6+. Exit status 0 and a
last line ``INSTALL_RESULT {json}`` on success, non-zero with an ``ERROR:``
line otherwise.
"""

import argparse
import base64
import glob
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
#: The image build has no setup limit, only this backstop.
BUILD_BUDGET_SEC = 3600
BUILD_PYTHON_PREFIX = "/opt/sast/python/"
READ_TIMEOUT_SEC = 60
ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
#: Pythons the fallback may build the venv from, best first.
PYTHON_CANDIDATES = ("/opt/sast/python/cpython-3.12*/bin/python3.12", "/opt/sast/python/cpython-3.1*/bin/python3.1*")
UV_CANDIDATES = ("/opt/sast/bin/uv",)
MIN_PYTHON = (3, 9)
#: Printed by the venv's Python: what it imports and from where.
PROBE = (
    "import json, sys; sys.path.insert(0, sys.argv[1]); import anthropic, requests; "
    "from claudecode import prompts, findings_filter, json_parser, claude_api_client; "
    "print(json.dumps({'python': sys.version.split()[0], 'anthropic': anthropic.__version__, "
    "'requests': requests.__version__}))"
)


def log(message):
    print("[install] " + message, flush=True)


class InstallError(Exception):
    pass


def fail(message):
    print("[install] ERROR: " + message, flush=True)
    sys.exit(2)


#: What the probes inherit (as driver.CLI_ENV_ALLOW): no ANTHROPIC_*, CLAUDE_* or other host settings.
ENV_ALLOW = frozenset((
    "PATH", "LANG", "LANGUAGE", "TZ", "TMPDIR", "TERM", "USER", "LOGNAME",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
))


def quiet_env(home):
    env = {name: value for name, value in os.environ.items() if name in ENV_ALLOW or name.startswith("LC_")}
    env.update({"HOME": home, "DISABLE_AUTOUPDATER": "1", "DISABLE_TELEMETRY": "1",
                "DISABLE_ERROR_REPORTING": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "PYTHONDONTWRITEBYTECODE": "1"})
    return env


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------- checks


def check_claude(part, pins, home):
    binary = os.path.join(part, "bin", "claude")
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        raise InstallError("no executable {}".format(binary))
    try:
        proc = subprocess.run([binary, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              env=quiet_env(home), timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("cannot run {} --version: {}".format(binary, exc))
    output = proc.stdout.decode("utf-8", "replace").strip()
    version = output.split()[0] if output else ""
    if proc.returncode != 0 or version != pins["claude_code_version"]:
        raise InstallError("{} --version gave {!r} (exit {}), expected {}".format(
            binary, output[-300:], proc.returncode, pins["claude_code_version"]))
    return {"claude": binary, "claude_version_output": output}


def check_ccsr(part, pins):
    base = os.path.join(part, "ccsr")
    for rel, expected in sorted(pins["ccsr_files"].items()):
        path = os.path.join(base, rel)
        if not os.path.isfile(path):
            raise InstallError("upstream file {} is missing".format(path))
        actual = sha256_file(path)
        if actual != expected:
            raise InstallError("upstream file {} has sha256 {}, expected {}".format(path, actual, expected))
    return {"ccsr_dir": base, "ccsr_commit": pins["ccsr_commit"], "ccsr_files": len(pins["ccsr_files"])}


def check_venv(part, pins, home):
    python = os.path.join(part, "venv", "bin", "python")
    if not os.path.exists(python):
        raise InstallError("no venv Python at {}".format(python))
    try:
        proc = subprocess.run([python, "-I", "-B", "-c", PROBE, os.path.join(part, "ccsr")],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=quiet_env(home), timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("cannot run {}: {}".format(python, exc))
    output = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        raise InstallError("the venv cannot import the review code: {}".format(output[-600:]))
    try:
        found = json.loads(output.splitlines()[-1])
    except (ValueError, IndexError):
        found = None
    if not isinstance(found, dict):
        raise InstallError("the venv probe printed no JSON result: {!r}".format(output[-300:]))
    for name, key in (("anthropic", "anthropic_version"), ("requests", "requests_version")):
        if found.get(name) != pins[key]:
            raise InstallError("the venv has {} {}, expected {}".format(name, found.get(name), pins[key]))
    found["venv_python"] = python
    return found


def check_part(part, pins, home):
    """Everything the agent needs from a part, or InstallError."""
    result = {"part": part}
    result.update(check_claude(part, pins, home))
    result.update(check_ccsr(part, pins))
    result.update(check_venv(part, pins, home))
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


def install_claude(part, pins, arch, deadline):
    entry = pins["claude_code_packages"].get(arch)
    if entry is None:
        raise InstallError("no Claude Code package is pinned for this CPU ({})".format(arch))
    data = fetch(entry["url"], deadline)
    actual = hashlib.sha256(data).hexdigest()
    if actual != entry["sha256"]:
        raise InstallError("{} has sha256 {}, expected {}".format(entry["url"], actual, entry["sha256"]))
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    if integrity != entry["integrity"]:
        raise InstallError("{} does not match its npm integrity".format(entry["url"]))
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember("package/claude")
        if not member.isfile():
            raise InstallError("package/claude in {} is not a regular file".format(entry["url"]))
        source = archive.extractfile(member)
        os.makedirs(os.path.join(part, "bin"), exist_ok=True)
        target = os.path.join(part, "bin", "claude")
        with open(target, "wb") as out:
            shutil.copyfileobj(source, out, 1 << 20)
    os.chmod(target, 0o755)
    log("Claude Code {} for {} installed".format(pins["claude_code_version"], arch))


def install_ccsr(part, pins, deadline):
    for rel, expected in sorted(pins["ccsr_files"].items()):
        url = pins["ccsr_raw_url"].format(path=rel)
        data = fetch(url, deadline)
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise InstallError("{} has sha256 {}, expected {}".format(url, actual, expected))
        target = os.path.join(part, "ccsr", rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as out:
            out.write(data)
        os.chmod(target, 0o644)
    log("{} at {} installed ({} files)".format(pins["ccsr_repo"], pins["ccsr_commit"][:7], len(pins["ccsr_files"])))


def python_version(python):
    try:
        out = subprocess.run([python, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60).stdout
        return tuple(int(x) for x in out.decode().strip().split("."))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def choose_python(explicit):
    candidates = [explicit] if explicit else []
    for pattern in PYTHON_CANDIDATES:
        candidates += sorted(glob.glob(pattern), reverse=True)
    for name in ("python3", "python"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in candidates:
        version = python_version(candidate)
        if version and version >= MIN_PYTHON:
            return candidate, version
    raise InstallError("no Python {}.{} or newer to build the venv from (tried {})".format(
        MIN_PYTHON[0], MIN_PYTHON[1], ", ".join(candidates) or "nothing"))


def choose_uv(explicit):
    for candidate in ([explicit] if explicit else []) + list(UV_CANDIDATES) + [shutil.which("uv") or ""]:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def run(command, env, deadline, what):
    left = deadline - time.monotonic()
    if left <= 5:
        raise InstallError("no time left for {}".format(what))
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=left)
    except subprocess.TimeoutExpired:
        raise InstallError("{} did not finish within the setup budget".format(what))
    output = proc.stdout.decode("utf-8", "replace")
    if proc.returncode != 0:
        raise InstallError("{} failed (exit {}): {}".format(what, proc.returncode, output[-1500:]))
    return output


def install_venv(part, requirements, python, uv, home, deadline):
    venv = os.path.join(part, "venv")
    env = quiet_env(home)
    cache = tempfile.mkdtemp(prefix="claude-review-cache-")
    try:
        if uv:
            env.update({"UV_CACHE_DIR": cache, "UV_LINK_MODE": "copy", "UV_PYTHON_DOWNLOADS": "never",
                        "UV_NO_CONFIG": "1"})
            run([uv, "venv", "--clear", "--python", python, venv], env, deadline, "uv venv")
            run([uv, "pip", "install", "--python", os.path.join(venv, "bin", "python"), "--require-hashes",
                 "--no-deps", "--only-binary", ":all:", "-r", requirements], env, deadline, "uv pip install")
        else:
            env.update({"PIP_NO_CACHE_DIR": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
            run([python, "-m", "venv", "--clear", venv], env, deadline, "python -m venv")
            run([os.path.join(venv, "bin", "python"), "-m", "pip", "install", "--require-hashes", "--no-deps",
                 "--only-binary", ":all:", "--no-compile", "-r", requirements], env, deadline, "pip install")
    finally:
        shutil.rmtree(cache, ignore_errors=True)
    log("venv built with {} from {}".format("uv" if uv else "pip", python))


def libc():
    name, version = platform.libc_ver()
    return name or "unknown", version


def install(part, pins, requirements, python, uv, home, deadline, python_prefix=None):
    arch = ARCH.get(platform.machine().lower(), platform.machine())
    name, _ = libc()
    if name != "glibc":
        raise InstallError("the pinned Claude Code binary needs glibc Linux, this is {} on {}".format(name, arch))
    if sha256_file(requirements) != pins["requirements_sha256"]:
        raise InstallError("{} does not match its pinned sha256".format(requirements))
    python, version = choose_python(python)
    if python_prefix and not os.path.realpath(python).startswith(python_prefix):
        # A venv points at its base Python, which must be in the image too.
        raise InstallError("the venv must be built from the CPython under {} (found {}): is the Semgrep part "
                           "there?".format(python_prefix, python))
    uv = choose_uv(uv)
    staging = part + ".partial"
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    install_claude(staging, pins, arch, deadline)
    install_ccsr(staging, pins, deadline)
    record = {"pins": pins, "arch": arch, "base_python": python, "base_python_version": ".".join(map(str, version)),
              "venv_tool": "uv" if uv else "pip"}
    with open(os.path.join(staging, "install.json"), "w") as f:
        json.dump(record, f, indent=1, sort_keys=True)
        f.write("\n")
    shutil.rmtree(part, ignore_errors=True)
    os.rename(staging, part)
    # A venv holds absolute paths, so it is built in its final place.
    install_venv(part, requirements, python, uv, home, deadline)
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
    parser.add_argument("--target", help="where to install (default: <work dir>/claude-review)")
    parser.add_argument("--requirements", help="requirements.lock (default: next to pins.json)")
    parser.add_argument("--python", help="the Python to build the venv from")
    parser.add_argument("--uv", help="uv to build the venv with")
    parser.add_argument("--budget-sec", type=float, default=DEFAULT_BUDGET_SEC)
    args = parser.parse_args(argv)
    started = time.monotonic()
    deadline = started + args.budget_sec
    with open(args.pins) as f:
        pins = json.load(f)
    requirements = args.requirements or os.path.join(os.path.dirname(os.path.abspath(args.pins)),
                                                     pins["requirements_file"])
    home = tempfile.mkdtemp(prefix="claude-review-home-")
    try:
        if args.build:
            target = args.target or pins["install_dir"]
            # Without an explicit --python the venv must come from /opt/sast/python,
            # which the image ships, never from the build stage's own Python.
            prefix = None if args.python else BUILD_PYTHON_PREFIX
            result = install(target, pins, requirements, args.python, args.uv, home, started + BUILD_BUDGET_SEC,
                             python_prefix=prefix)
            print("INSTALL_RESULT " + json.dumps(result), flush=True)
            return 0
        baked = pins["install_dir"]
        try:
            result = check_part(baked, pins, home)
            result["source"] = "image"
            log("using the part baked into the tools image at " + baked)
        except InstallError as exc:
            log("the baked part at {} cannot be used: {}".format(baked, exc))
            target = args.target or os.path.join(ROOT, "claude-review")
            if os.path.realpath(target) == os.path.realpath(baked):
                target = os.path.join(ROOT, "claude-review-local")
            log("installing into {} instead".format(target))
            result = install(target, pins, requirements, args.python, args.uv, home, deadline)
            result["source"] = "setup"
            result["baked_problem"] = str(exc)
        result["image_manifest"] = image_manifest("claude-review", recompute=result["source"] == "image")
        log("image manifest: " + str(result["image_manifest"].get("status")))
        result.update({"arch": platform.machine(), "libc": "-".join(libc()),
                       "seconds": round(time.monotonic() - started, 1)})
        print("INSTALL_RESULT " + json.dumps(result), flush=True)
        return 0
    except InstallError as exc:
        fail(str(exc))
    finally:
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
