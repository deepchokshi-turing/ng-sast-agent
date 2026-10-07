"""tools/leak_scan.py --image (audit R3): the built task image is checked, with
docker mocked at subprocess.run. The real run on two tasks is done by hand."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from tests.conftest import ROOT
from tests.test_report_and_leak_scan import make_twin

spec = importlib.util.spec_from_file_location("leak_scan", ROOT / "tools" / "leak_scan.py")
leak_scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(leak_scan)

TOOLS_DF = ("ARG SAST_TOOLS_IMAGE=sast-tools:0.4.0\nFROM ${SAST_TOOLS_IMAGE} AS sast-tools\n"
            "FROM python:3.12-slim\nCOPY --from=sast-tools /opt/sast /opt/sast\nCOPY repo/ /app/repo/\n")


def tar_of(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        dirs = {"app"} | {"app/" + "/".join(rel.split("/")[:i]) for rel in files for i in range(1, rel.count("/") + 1)}
        for d in sorted(dirs):
            info = tarfile.TarInfo(d)
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        for rel, data in files.items():
            info = tarfile.TarInfo(f"app/{rel}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("app/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "repo"
        tar.addfile(link)
    return buf.getvalue()


class FakeDocker:
    """Answers the docker calls leak_scan makes, and records them."""

    def __init__(self, files: dict[str, bytes], listed: list[str] | None = None, fail: str | None = None):
        self.files = files
        self.listed = sorted(files) if listed is None else listed
        self.fail = fail
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        assert isinstance(cmd, list) and "shell" not in kwargs, "list arguments and no shell"
        assert cmd[0] == "docker"
        self.calls.append(cmd)
        sub = cmd[1]
        if sub == self.fail:
            return subprocess.CompletedProcess(cmd, 1, b"", b"boom")
        out = {
            "build": b"sha256:feedface\n",
            "run": b"".join(f"/app/{rel}".encode() + b"\0" for rel in self.listed),
            "create": b"c0ffee\n",
            "cp": tar_of(self.files),
        }.get(sub, b"")
        return subprocess.CompletedProcess(cmd, 0, out, b"")

    def sub(self, name):
        return [c for c in self.calls if c[1] == name]


def clean_files(task: Path) -> dict[str, bytes]:
    repo = task / "environment" / "repo"
    return {f"repo/{p.relative_to(repo).as_posix()}": p.read_bytes() for p in sorted(repo.rglob("*")) if p.is_file()}


def setup_task(tmp_path, monkeypatch, extra=None, **kw):
    make_twin(tmp_path)
    task = tmp_path / "task_abc_positive"
    (task / "environment" / "Dockerfile").write_text(TOOLS_DF)
    (task / "solution").mkdir()
    (task / "solution" / "solve.sh").write_text("#!/bin/sh\ncp /solution/findings.sarif /app/output/ # answer\n")
    files = {**clean_files(task), **(extra(task) if extra else {})}
    fake = FakeDocker(files, **kw)
    monkeypatch.setattr(leak_scan.subprocess, "run", fake)
    return task, fake


def test_clean_image_passes_and_every_image_is_removed(tmp_path, monkeypatch):
    task, fake = setup_task(tmp_path, monkeypatch)
    problems, count = leak_scan.scan_image(task)
    assert problems == [] and count == 4
    build = fake.sub("build")[0]
    assert build[:3] == ["docker", "build", "-q"]
    assert "SAST_TOOLS_IMAGE=sast-tools:0.4.0" in build and build[-1] == str(task / "environment")
    assert fake.sub("run")[0] == ["docker", "run", "--rm", "--entrypoint", "sh", "sha256:feedface", "-c",
                                  "find /app -type f -print0"]
    assert fake.sub("cp")[0] == ["docker", "cp", "c0ffee:/app", "-"]
    assert fake.sub("rm")[0] == ["docker", "rm", "-f", "c0ffee"]
    assert fake.sub("rmi")[0] == ["docker", "rmi", "-f", "sha256:feedface"]


def test_tools_image_option_overrides_the_dockerfile_default(tmp_path, monkeypatch):
    task, fake = setup_task(tmp_path, monkeypatch)
    leak_scan.scan_image(task, "registry.example/sast-tools:0.4.0")
    assert "SAST_TOOLS_IMAGE=registry.example/sast-tools:0.4.0" in fake.sub("build")[0]


@pytest.mark.parametrize("extra, message", [
    (lambda t: {"tests/ground_truth.json": b"{}"}, "evaluator folder in the image: /app/tests/ground_truth.json"),
    (lambda t: {"solution/x.txt": b"x"}, "evaluator folder in the image: /app/solution/x.txt"),
    (lambda t: {"repo/notes/ground_truth_v2.json": b"[]"}, "evaluator file name in the image"),
    (lambda t: {"output/findings.sarif": b"{}"}, "evaluator file name in the image: /app/output/findings.sarif"),
    (lambda t: {"repo/data/copy.json": (t / "tests" / "ground_truth.json").read_bytes()},
     "/app/repo/data/copy.json has the same bytes as tests/ground_truth.json"),
    (lambda t: {"repo/run.txt": (t / "solution" / "solve.sh").read_bytes()},
     "has the same bytes as solution/solve.sh"),
    # Written by the build, so the source-tree check never saw it.
    (lambda t: {"repo/src/mini/gen.py": b"# the model picks any path and the notes tool\n"},
     "ground-truth text from findings[0].rationale appears in /app/repo/src/mini/gen.py"),
])
def test_leaks_in_the_image_fail(tmp_path, monkeypatch, extra, message):
    task, fake = setup_task(tmp_path, monkeypatch, extra=extra)
    problems, _ = leak_scan.scan_image(task)
    assert any(message in p for p in problems), problems
    assert fake.sub("rmi"), "the image is removed when a check fails"


def test_file_listed_but_not_copied_is_reported(tmp_path, monkeypatch):
    task, fake = setup_task(tmp_path, monkeypatch)
    fake.listed = fake.listed + ["repo/hidden.txt"]
    problems, _ = leak_scan.scan_image(task)
    assert any("not in the docker cp archive" in p and "/app/repo/hidden.txt" in p for p in problems)


def test_failed_build_is_a_problem_and_removes_nothing(tmp_path, monkeypatch):
    task, fake = setup_task(tmp_path, monkeypatch, fail="build")
    problems, count = leak_scan.scan_image(task)
    assert count == 0 and problems and "docker build exited 1: boom" in problems[0]
    assert not fake.sub("rmi") and not fake.sub("run")


def test_failed_copy_still_removes_container_and_image(tmp_path, monkeypatch):
    task, fake = setup_task(tmp_path, monkeypatch, fail="cp")
    problems, _ = leak_scan.scan_image(task)
    assert "docker cp exited 1" in problems[0]
    assert fake.sub("rm") and fake.sub("rmi")


def test_missing_docker_cli_is_reported(tmp_path, monkeypatch):
    make_twin(tmp_path)

    def no_docker(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(leak_scan.subprocess, "run", no_docker)
    problems, _ = leak_scan.scan_image(tmp_path / "task_abc_positive")
    assert problems == ["image check could not run: the docker CLI is not on PATH"]


def test_main_image_filters_tasks_and_sets_the_exit_code(tmp_path, monkeypatch, capsys):
    task, fake = setup_task(tmp_path, monkeypatch)
    assert leak_scan.main_image(tmp_path, ["task_abc_positive"], None) == 0
    out = capsys.readouterr().out
    assert "task_abc_positive  pass" in out and "task_abc_negative" not in out
    assert "image leak check: 1/1" in out and len(fake.sub("build")) == 1
    assert leak_scan.main_image(tmp_path, ["task_nope"], None) == 2
    fake.files["output/findings.sarif"] = json.dumps({"runs": []}).encode()
    assert leak_scan.main_image(tmp_path, ["task_abc_positive"], None) == 1


def test_image_mode_is_stdlib_and_shell_free():
    text = (ROOT / "tools" / "leak_scan.py").read_text()
    assert "shell=True" not in text and "os.system" not in text
    imports = {line.split()[1].split(".")[0] for line in text.splitlines() if line.startswith(("import ", "from "))}
    assert imports <= {"__future__", "argparse", "hashlib", "io", "json", "re", "subprocess", "sys", "tarfile",
                       "pathlib"}
