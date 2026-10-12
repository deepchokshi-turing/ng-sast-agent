"""scan.py, the sandbox runner, for real: the scope copy, the git change set,
how promptfoo is started (argv, environment, working directory), how its
failures are classified and that the key never reaches the result.

promptfoo itself is the scripted stand-in from tests/promptfoo_fakes.py; git
is the machine's own (these tests skip without one).
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from tests.promptfoo_fakes import KEY, SCAN, ScanRun, comment, header, response

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")

FILES = ["src/app/agent.py", "src/app/tools.py", "src/app/data.bin"]


def make_repo(tmp: Path) -> Path:
    repo = tmp / "repo"
    (repo / "src" / "app").mkdir(parents=True)
    (repo / "src" / "app" / "agent.py").write_text("import os\n\n\ndef run(cmd):\n    return eval(cmd)\n")
    # No final newline: still 3 lines.
    (repo / "src" / "app" / "tools.py").write_text("a = 1\nb = 2\nc = 3")
    (repo / "src" / "app" / "data.bin").write_bytes(b"\x00\x01binary")
    (repo / "src" / "app" / ".gitignore").write_text("*.py\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_agent.py").write_text("assert True\n")
    (repo / "solution").mkdir()
    (repo / "solution" / "solve.sh").write_text("echo answer\n")
    (repo / ".env").write_text("PROMPTFOO_API_KEY=from-dotenv\n")
    (repo / "security_manifest.json").write_text('{"task": "demo"}\n')
    return repo


def ok_script(comments=None):
    return [{"exit": 0, "response": response(comments if comments is not None else [comment("src/app/agent.py", 5)])}]


def test_happy_path_copies_the_scope_builds_the_change_and_runs_promptfoo(tmp_path, monkeypatch):
    monkeypatch.setenv("SOME_HOST_SECRET", "do-not-pass")
    repo = make_repo(tmp_path)
    run = ScanRun(tmp_path / "run", repo, FILES, script=ok_script())
    proc = run.run()
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith('SCAN_RESULT {"status": "ok", "error": null}')
    doc = run.document()
    assert doc["status"] == "ok" and "error" not in doc
    assert doc["response"]["comments"][0]["file"] == "src/app/agent.py"
    # The copy: the in-scope files and the manifest, nothing else (no tests/, solution/, .env).
    scope = Path(run.request["scope_dir"])
    copied = sorted(str(p.relative_to(scope)).replace(os.sep, "/") for p in scope.rglob("*")
                    if p.is_file() and ".git" not in p.relative_to(scope).parts)
    assert copied == ["security_manifest.json", "src/app/agent.py", "src/app/data.bin", "src/app/tools.py"]
    record = doc["scope_copy"]
    assert record["files"] == 4 and record["manifest"] and record["manifest_outside_roots"]
    assert record["binary"] == ["src/app/data.bin"] and record["in_promptfoo_denylist"] == ["src/app/data.bin"]
    assert doc["line_counts"] == {"src/app/agent.py": 5, "src/app/tools.py": 3, "security_manifest.json": 1}
    # The change set is the whole copy, even the files a .gitignore in it would hide.
    assert doc["git"]["base"] == "main" and doc["git"]["compare"] == "scan" and doc["git"]["files_changed"] == 4

    (call,) = run.calls()
    assert call["argv"] == [run.request["promptfoo"], "code-scans", "run", run.request["scope_dir"],
                                "--base", "main", "--compare", "scan", "-f", "json"]
    assert call["files"] == copied and call["git_dir"]
    # The key: in promptfoo's own environment only, never on its command line.
    assert call["env"]["PROMPTFOO_API_KEY"] == KEY
    assert all(KEY not in arg for arg in call["argv"])
    assert "SOME_HOST_SECRET" not in call["env"]
    assert call["env"]["PROMPTFOO_DISABLE_TELEMETRY"] == "1" and call["env"]["PROMPTFOO_DISABLE_UPDATE"] == "1"
    assert call["env"]["HOME"] == run.request["home"]
    assert call["env"]["PROMPTFOO_CONFIG_DIR"] == os.path.join(run.request["home"], ".promptfoo")
    # An empty private working directory: promptfoo loads .env from there.
    assert call["cwd"] == run.request["cwd"] and not call["cwd_has_env_file"]
    assert call["guidance"] is None
    assert doc["env_names"] == sorted(n for n in call["env"] if n in doc["env_names"])
    assert "PROMPTFOO_API_KEY" in doc["env_names"]
    # promptfoo's HOME (it may hold logs) and working directory are gone; the key is in no output.
    assert not Path(run.request["home"]).exists() and not Path(run.request["cwd"]).exists()
    assert KEY not in run.out.read_text() and KEY not in proc.stdout + proc.stderr


def test_options_reach_the_command_line(tmp_path):
    repo = make_repo(tmp_path)
    guidance = tmp_path / "guidance.txt"
    guidance.write_text("RULE=...\n")
    run = ScanRun(tmp_path / "run", repo, FILES, script=ok_script(), guidance_file=str(guidance),
                  min_severity="low", diffs_only=True)
    run.run()
    (call,) = run.calls()
    assert call["argv"][10:] == ["--min-severity", "low", "--diffs-only", "--guidance-file", str(guidance)]
    assert call["guidance"] == "RULE=...\n"


@pytest.mark.parametrize("step, code", [
    ({"exit": 1, "stderr": "Scan failed: Failed to connect to server: Authentication failed: Invalid API token\n"},
     "auth"),
    ({"exit": 1, "stderr": "Scan failed: Failed to connect to server: Authentication required. Provide OIDC token, "
                           "API key, or fork PR context.\n"}, "auth"),
    ({"exit": 1, "stderr": "Scan failed: Failed to connect to server: xhr poll error\n"}, "network"),
    ({"exit": 1, "stderr": "Scan failed: Connection timeout after 5000ms\n"}, "network"),
    ({"exit": 1, "stderr": "Scan failed: Server at capacity. Please retry.\n"}, "service"),
    ({"exit": 1, "stderr": "Scan failed: Failed to process diff: fatal: bad revision\n"}, "git"),
    ({"exit": 1, "stderr": "Scan failed: Filesystem MCP server exited before ready: code 1\n"}, "mcp"),
    ({"exit": 1, "stderr": "Scan failed: Cannot read properties of undefined (reading 'x')\n"}, "tool_failed"),
    ({"exit": 0, "stdout": "Scan complete, but no JSON here\n"}, "bad_output"),
    ({"exit": 0, "response": {"success": True, "comments": [], "review": "No files to scan"}}, "no_files"),
    ({"exit": 0, "response": {"success": False, "comments": [], "error": "Server at capacity"}}, "service"),
    ({"exit": 0, "response": {"success": False, "comments": [], "error": "model returned garbage"}}, "tool_failed"),
    ({"exit": 0, "response": {"success": True, "comments": [], "skipReason": "Fork PR scanning requires approval"}},
     "skipped"),
])
def test_failures_are_classified(tmp_path, step, code):
    run = ScanRun(tmp_path / "run", make_repo(tmp_path), FILES, script=[step])
    assert run.run().returncode == 0
    doc = run.document()
    assert doc["status"] == "error" and doc["error"]["code"] == code
    assert not Path(run.request["home"]).exists()


def test_an_empty_response_is_a_clean_scan(tmp_path):
    run = ScanRun(tmp_path / "run", make_repo(tmp_path), FILES, script=ok_script([]))
    run.run()
    doc = run.document()
    assert doc["status"] == "ok" and doc["response"]["comments"] == []


def test_the_key_echoed_by_promptfoo_is_scrubbed(tmp_path):
    step = {"exit": 1, "stderr": f"Scan failed: Authentication failed for key {KEY}\n"}
    run = ScanRun(tmp_path / "run", make_repo(tmp_path), FILES, script=[step])
    run.run()
    text = run.out.read_text()
    assert KEY not in text and "***" in text
    step = {"exit": 0, "response": response([comment("src/app/agent.py", 5, f"the key is {KEY}")])}
    run = ScanRun(tmp_path / "run2", make_repo(tmp_path / "r2"), FILES, script=[step])
    run.run()
    assert KEY not in run.out.read_text()
    assert run.document()["response"]["comments"][0]["finding"].endswith("the key is ***")


def test_no_key_file_or_an_empty_one(tmp_path):
    run = ScanRun(tmp_path / "run", make_repo(tmp_path), FILES, script=ok_script())
    run.keyfile.write_text("\n")
    run.run()
    assert run.document()["error"]["code"] == "no_key" and run.calls() == []
    run.keyfile.unlink()
    run.run()
    assert run.document()["error"]["code"] == "no_key"


def test_a_missing_git_is_a_git_error(tmp_path):
    run = ScanRun(tmp_path / "run", make_repo(tmp_path), FILES, script=ok_script(),
                  git=str(tmp_path / "no-such-git"))
    run.run()
    assert run.document()["error"]["code"] == "git" and run.calls() == []


def test_unsafe_and_missing_paths_are_not_copied(tmp_path):
    repo = make_repo(tmp_path)
    files = ["src/app/agent.py", "../outside.txt", "/etc/passwd", ".git/config", "src/app/missing.py"]
    (tmp_path / "outside.txt").write_text("secret\n")
    run = ScanRun(tmp_path / "run", repo, files, script=ok_script())
    run.run()
    record = run.document()["scope_copy"]
    assert record["files"] == 2
    assert sorted(record["skipped"]) == sorted(files[1:])
    (call,) = run.calls()
    assert call["files"] == ["security_manifest.json", "src/app/agent.py"]


def test_no_copied_file_is_an_error(tmp_path):
    repo = tmp_path / "empty"
    repo.mkdir()
    run = ScanRun(tmp_path / "run", repo, ["nothing.py"], script=ok_script())
    run.run()
    assert run.document()["error"]["code"] == "no_files" and run.calls() == []


def _load_scan_module():
    spec = importlib.util.spec_from_file_location("pf_scan_under_test", SCAN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_promptfoo_that_does_not_finish_is_stopped(tmp_path):
    scan = _load_scan_module()
    tool = tmp_path / "slow.py"
    tool.write_text("import time; time.sleep(60)\n")
    (tmp_path / "cwd").mkdir()
    request = {"node": sys.executable, "promptfoo": str(tool), "scope_dir": str(tmp_path), "git": sys.executable,
               "home": str(tmp_path / "home"), "cwd": str(tmp_path / "cwd")}
    code, _out, _err, took, timed_out = scan.run_promptfoo(request, KEY, 2)
    assert timed_out and took < 30


def test_parse_response_and_classify():
    scan = _load_scan_module()
    assert scan.parse_response('noise {"a": 1}\n{"success": true, "comments": []}\n') == {"success": True,
                                                                                         "comments": []}
    assert scan.parse_response("no json") is None
    assert scan.classify("Authentication failed: x") == "auth"
    assert scan.classify("anything else") == "tool_failed"
    assert scan.in_promptfoo_denylist("dist/app.py") and scan.in_promptfoo_denylist("a/poetry.lock")
    assert scan.in_promptfoo_denylist("src/app/data.bin") and not scan.in_promptfoo_denylist("src/build.py")
    assert scan.text_lines("a\nb\n") == ["a", "b"] and scan.text_lines("a\x0cb") == ["a\x0cb"]
    assert json.loads(json.dumps(scan.scrub_tree({"k": [f"x{KEY}y"]}, KEY))) == {"k": ["x***y"]}
