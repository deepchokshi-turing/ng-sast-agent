#!/usr/bin/env python3
"""Clean-environment check of each task's build_command, test_command and entrypoint (spec 5.2).

    python tools/check_clean_build.py <harbor-tasks dir> [--task NAME ...] [--jobs N] [--write]
                                      [--timeout SEC] [--tools-image IMG]

For every task folder it:

1. runs ``docker build`` on environment/ (with ``--build-arg
   SAST_TOOLS_IMAGE=<value>``, the value being ``--tools-image`` or else the
   ``ARG SAST_TOOLS_IMAGE=`` default in the Dockerfile). Base images must
   already be present locally; the build is run with ``--pull=false``.
2. reads ``[metadata] build_command``, ``test_command`` and ``entrypoint``
   from task.toml and runs each one in its own fresh container from that
   image (``docker run --rm --network none -w /app/repo <image> sh -c
   <command>``), with a timeout per command. /app/repo is where the
   Dockerfile copies repo/, so the repository-relative commands run from the
   repository root. When a command fails without network, it is run once
   more with the default network and ``network_needed`` records whether
   that made the difference.
3. runs each command a second time with the image's ``PYTHONPATH`` unset, to
   show whether the command works from the repository alone (recorded as
   ``passes_without_image_pythonpath``; informational, not part of the
   overall result).
4. removes the image (also when something fails).

It prints one line per task and exits 1 when any task fails. With
``--write`` it stores the result under ``qc.build_verified_clean_env`` in the
task's validation/provenance.json:

    {"date": ISO UTC, "image_id": sha256:..., "base_images": {...},
     "python_version": "3.12.x", "workdir": "/app/repo", "network": "none",
     "commands": {"build_command": {"command", "exit_code", "pass",
                  "network_needed", "passes_without_image_pythonpath",
                  "output_tail"}, ...},
     "pass": true/false}

It needs the docker CLI on PATH and nothing else; subprocess calls take list
arguments and use no host shell, so it runs the same way from PowerShell or
Git Bash. Uses only the standard library.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import tomllib
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

COMMANDS = ("build_command", "test_command", "entrypoint")
WORKDIR = "/app/repo"
DEFAULT_TIMEOUT_SEC = 120
BUILD_TIMEOUT_SEC = 1800
DOCKER_TIMEOUT_SEC = 300
TAIL_CHARS = 400
TOOLS_ARG_RE = re.compile(r"^\s*ARG\s+SAST_TOOLS_IMAGE\s*=\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
FROM_RE = re.compile(r"^\s*FROM\s+(\S+)", re.IGNORECASE | re.MULTILINE)
WORKDIR_RE = re.compile(r"^\s*WORKDIR\s+(\S+)", re.IGNORECASE | re.MULTILINE)
COPY_REPO_RE = re.compile(r"^\s*COPY\s+(?:--\S+\s+)*\.?/?repo/?\s+(\S+)", re.IGNORECASE | re.MULTILINE)


class DockerError(Exception):
    """A docker command failed."""


def docker(args: list[str], timeout: int = DOCKER_TIMEOUT_SEC) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except FileNotFoundError as exc:
        raise DockerError("the docker CLI is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerError(f"docker {args[0]} did not finish within {timeout} s") from exc


def tail(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").strip()
    return text[-TAIL_CHARS:]


def dockerfile_info(task: Path) -> dict:
    """Tools-image default, base images and the directory repo/ is copied to."""
    text = (task / "environment" / "Dockerfile").read_text(encoding="utf-8", errors="replace")
    m = TOOLS_ARG_RE.search(text)
    tools = m.group(1).strip("\"'") if m else None
    bases = [b.replace("${SAST_TOOLS_IMAGE}", tools or "${SAST_TOOLS_IMAGE}") for b in FROM_RE.findall(text)]
    copy = COPY_REPO_RE.search(text)
    workdirs = WORKDIR_RE.findall(text)
    repo_dir = copy.group(1).rstrip("/") if copy else None
    if repo_dir and not repo_dir.startswith("/") and workdirs:
        repo_dir = workdirs[-1].rstrip("/") + "/" + repo_dir
    return {"tools_image": tools, "base_images": bases, "repo_dir": repo_dir or WORKDIR}


def image_ref(name: str) -> str:
    """Image id plus repo digest of a local base image, without pulling."""
    proc = docker(["image", "inspect", "--format", "{{.Id}} {{json .RepoDigests}}", name])
    if proc.returncode != 0:
        return f"{name} (not present locally)"
    image_id, _, digests = proc.stdout.decode().strip().partition(" ")
    try:
        repo = json.loads(digests) or []
    except ValueError:
        repo = []
    return f"{name} id={image_id}" + (f" digest={repo[0]}" if repo else "")


def run_in_container(image: str, command: str, workdir: str, timeout: int, network: str,
                     unset_pythonpath: bool = False) -> tuple[int | None, str]:
    """(exit code, output tail) of ``sh -c command`` in a fresh container; None as exit code on timeout."""
    name = f"cleanbuild-{uuid.uuid4().hex[:12]}"
    script = ("unset PYTHONPATH; " if unset_pythonpath else "") + command
    args = ["run", "--rm", "--name", name, "--network", network, "-w", workdir, "--entrypoint", "sh", image,
            "-c", script]
    try:
        proc = docker(args, timeout=timeout)
    except DockerError as exc:
        docker(["rm", "-f", name])
        return None, str(exc)
    return proc.returncode, tail(proc.stdout)


def check_task(task: Path, tools_image: str | None, timeout: int) -> dict:
    info = dockerfile_info(task)
    meta = (tomllib.loads((task / "task.toml").read_text(encoding="utf-8")).get("metadata") or {})
    result: dict = {
        "date": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "image_id": None,
        "base_images": [image_ref(b) for b in info["base_images"]],
        "python_version": None,
        "workdir": info["repo_dir"],
        "network": "none",
        "commands": {},
        "pass": False,
    }
    image = None
    try:
        tag = f"cleanbuild-{task.name.lower()}:{uuid.uuid4().hex[:8]}"
        args = ["build", "--pull=false", "-t", tag]
        value = tools_image or info["tools_image"]
        if value:
            args += ["--build-arg", f"SAST_TOOLS_IMAGE={value}"]
        proc = docker(args + [str(task / "environment")], timeout=BUILD_TIMEOUT_SEC)
        if proc.returncode != 0:
            result["docker_build"] = {"exit_code": proc.returncode, "pass": False, "output_tail": tail(proc.stdout)}
            return result
        image = tag
        result["docker_build"] = {"exit_code": 0, "pass": True}
        result["image_id"] = docker(["image", "inspect", "--format", "{{.Id}}", tag]).stdout.decode().strip()
        code, out = run_in_container(image, "python -c 'import sys; print(sys.version.split()[0])'", "/", 60, "none")
        result["python_version"] = out.strip() if code == 0 else None
        ok = True
        for key in COMMANDS:
            command = meta.get(key)
            if not isinstance(command, str) or not command.strip():
                result["commands"][key] = {"command": command, "exit_code": None, "pass": False,
                                           "output_tail": f"task.toml has no metadata.{key}"}
                ok = False
                continue
            code, out = run_in_container(image, command, info["repo_dir"], timeout, "none")
            entry = {"command": command, "exit_code": code, "pass": code == 0, "network_needed": False}
            if code != 0:
                code2, out2 = run_in_container(image, command, info["repo_dir"], timeout, "bridge")
                entry["network_needed"] = code2 == 0
                entry["exit_code_with_network"] = code2
                if code2 == 0:
                    entry["pass"] = True
                    result["network"] = "needed"
            code3, _ = run_in_container(image, command, info["repo_dir"], timeout, "none", unset_pythonpath=True)
            entry["passes_without_image_pythonpath"] = code3 == 0
            entry["output_tail"] = out
            result["commands"][key] = entry
            ok = ok and entry["pass"]
        result["pass"] = ok
        return result
    except DockerError as exc:
        result["error"] = str(exc)
        return result
    finally:
        if image:
            docker(["rmi", "-f", image])


def write_provenance(task: Path, result: dict) -> None:
    prov = task / "validation" / "provenance.json"
    if not prov.is_file():
        return
    data = json.loads(prov.read_text(encoding="utf-8"))
    data.setdefault("qc", {})["build_verified_clean_env"] = result
    with prov.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def summary_line(name: str, r: dict) -> str:
    cells = []
    for key in COMMANDS:
        c = r["commands"].get(key)
        cells.append(f"{key.split('_')[0]}={'n/a' if c is None else ('pass' if c['pass'] else 'FAIL')}")
    extra = ""
    if not r.get("docker_build", {}).get("pass", False):
        extra = "  docker build FAILED"
    if r.get("error"):
        extra += f"  error: {r['error']}"
    if r.get("network") == "needed":
        extra += "  (network needed)"
    return f"{name}  {'pass' if r['pass'] else 'FAIL'}  {' '.join(cells)}  python={r.get('python_version')}{extra}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tasks", type=Path, help="the harbor-tasks directory")
    ap.add_argument("--task", action="append", default=[], metavar="NAME", help="only this task (repeatable)")
    ap.add_argument("--jobs", type=int, default=4, help="tasks checked in parallel (default 4)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SEC, help="seconds per command (default 120)")
    ap.add_argument("--tools-image", help="SAST_TOOLS_IMAGE build argument (default: the Dockerfile ARG default)")
    ap.add_argument("--write", action="store_true", help="store results in validation/provenance.json qc")
    args = ap.parse_args()
    tasks = sorted(d for d in args.tasks.iterdir()
                   if d.is_dir() and (d / "task.toml").is_file() and (d / "environment" / "Dockerfile").is_file())
    if args.task:
        unknown = sorted(set(args.task) - {t.name for t in tasks})
        if unknown:
            print(f"no such task under {args.tasks}: {', '.join(unknown)}")
            return 2
        tasks = [t for t in tasks if t.name in args.task]
    if not tasks:
        print(f"no task folders under {args.tasks}")
        return 1
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = dict(zip((t.name for t in tasks),
                           pool.map(lambda t: check_task(t, args.tools_image, args.timeout), tasks)))
    failed = 0
    for t in tasks:
        r = results[t.name]
        failed += not r["pass"]
        print(summary_line(t.name, r))
        if not r["pass"]:
            for key, c in r["commands"].items():
                if not c["pass"]:
                    print(f"    {key}: exit {c['exit_code']}: {c['output_tail']}")
            if not r.get("docker_build", {}).get("pass", False):
                print(f"    docker build: {r.get('docker_build', {}).get('output_tail', r.get('error'))}")
        if args.write:
            write_provenance(t, r)
    print(f"\nclean-environment build check: {len(tasks) - failed}/{len(tasks)} tasks pass")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
