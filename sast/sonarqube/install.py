#!/usr/bin/env python3
"""Check that sonar-scanner is in the sandbox and works.

Uploaded by ``SonarQubeAgent.setup`` next to ``pins.json`` and ``fetch.py``,
and run with the Python in ``/opt/sast`` when the image has one, else the
image's ``python3``. It downloads nothing: the scanner and its JRE are about
60 MB and come with the tools image ``sast-tools:0.4.0`` (see README.md).

Checks, in order: ``bin/sonar-scanner`` exists and is executable, the version
in the CLI jar's name matches the pin, and ``sonar-scanner -v``
runs, which proves the bundled JRE starts on this image. The Python it ran with
is reported, so the agent runs ``fetch.py`` with the same one.

Written for any Python 3.6+. Exit status 0 and a last line
``INSTALL_RESULT {json}`` on success, non-zero with an ``ERROR:`` line otherwise.
"""

import glob
import json
import os
import platform
import re
import subprocess
import sys
import time

ROOT = os.environ.get("SAST_ROOT", "/opt/sast")
JAR_VERSION = re.compile(r"sonar-scanner-cli-([0-9][0-9A-Za-z.\-]*)\.jar$")


def log(message):
    print("[install] " + message, flush=True)


def fail(message):
    print("[install] ERROR: " + message, flush=True)
    sys.exit(2)


def jar_version(home):
    """The CLI version from lib/sonar-scanner-cli-<version>.jar, or None."""
    for path in sorted(glob.glob(os.path.join(home, "lib", "sonar-scanner-cli-*.jar"))):
        match = JAR_VERSION.search(os.path.basename(path))
        if match:
            return match.group(1)
    return None


def run_version(executable):
    env = dict(os.environ)
    env["SONAR_USER_HOME"] = ROOT + "/home/.sonar"
    try:
        proc = subprocess.run([executable, "-v"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=180)
    except subprocess.TimeoutExpired:
        fail("'sonar-scanner -v' did not finish within 180 s")
    except OSError as exc:
        fail("cannot run {}: {}".format(executable, exc))
    output = proc.stdout.decode("utf-8", "replace").strip()
    if output:
        print(output, flush=True)
    if proc.returncode != 0:
        fail("'sonar-scanner -v' exited {}, so the bundled JRE may not run on this image".format(proc.returncode))
    return output


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
    home = os.environ.get("SONAR_SCANNER_HOME") or pins["install_dir"]
    executable = os.path.join(home, "bin", "sonar-scanner")

    if not os.path.isfile(executable):
        fail("sonar-scanner is not installed at {}. It is not downloaded at setup: build the task image "
             "with the tools image sast-tools:0.4.0 (COPY --from=sast-tools /opt/sast /opt/sast), "
             "see README.md".format(home))
    if not os.access(executable, os.X_OK):
        fail("{} is not executable".format(executable))

    version = jar_version(home)
    if version is None:
        fail("no lib/sonar-scanner-cli-<version>.jar under {}".format(home))
    pinned = pins.get("sonar_scanner_version")
    if not pinned:
        fail("no sonar-scanner version is pinned in pins.json")
    if version != pinned:
        fail("sonar-scanner is version {}, expected {}".format(version, pinned))

    # Hashing the scanner and its JRE (under 300 MB) takes a few seconds at most.
    manifest = image_manifest("sonar-scanner", recompute=True)
    log("image manifest: " + manifest.get("status", "?"))
    os.makedirs(ROOT + "/home/.sonar", exist_ok=True)
    output = run_version(executable)

    result = {
        "pins": pins,
        "scanner_home": home,
        "scanner_version": version,
        "scanner_pinned": bool(pinned),
        "scanner_v_output": [line for line in output.splitlines() if line.strip()][-6:],
        "python": sys.executable,
        "python_version": platform.python_version(),
        "arch": platform.machine(),
        "image_manifest": manifest,
        "seconds": round(time.time() - started, 1),
    }
    print("INSTALL_RESULT " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
