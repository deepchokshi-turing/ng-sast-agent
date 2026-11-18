"""driver.py confines the Claude CLI to the scope (audit A8): it runs in a copy
of only the in-scope files plus security_manifest.json, the real repository is
denied, finding paths stay repository-relative, and every tool call of the
stream-json is kept with the ones outside the scope flagged. The whole runs use
the scripted CLI of tests/claude_review_fakes.py; no API is called."""

from __future__ import annotations

import json
import os
import sys

import pytest

from sast.claude_review import driver
from tests.claude_review_fakes import KEY, DriverRun, NetCheckServer, finding, review, wrapper

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="driver.py runs in a Linux sandbox (process groups)")

IN_SCOPE = ["src/app/llm.py", "src/app/tools.py"]


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "src" / "app").mkdir(parents=True)
    (root / "src" / "app" / "tools.py").write_text("import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n")
    (root / "src" / "app" / "llm.py").write_text("PROMPT = 'hi'\nprint(PROMPT)\n")
    (root / "src" / "app" / "excluded.py").write_text("SECRET_NOTE = 1\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text("def test():\n    pass\n")
    (root / "README.md").write_text("# readme\n")
    (root / "security_manifest.json").write_text('{"intended_task": "x"}\n')
    return root


@pytest.fixture
def net():
    server = NetCheckServer()
    yield server.url
    server.close()


# ---------------------------------------------------------------- units


def test_scope_copy_holds_only_the_scope_and_the_manifest(tmp_path, repo):
    scope = tmp_path / "scope"
    (scope / "stale").mkdir(parents=True)
    record = driver.make_scope_copy(str(repo), IN_SCOPE, str(scope))
    copied = sorted(os.path.relpath(os.path.join(d, f), scope) for d, _, fs in os.walk(scope) for f in fs)
    assert copied == ["security_manifest.json", "src/app/llm.py", "src/app/tools.py"]
    assert (scope / "src" / "app" / "tools.py").read_text() == (repo / "src" / "app" / "tools.py").read_text()
    assert record["files"] == 3 and record["manifest"] and record["manifest_outside_roots"]


def test_scope_copy_skips_links_and_escapes(tmp_path, repo):
    (repo / "src" / "app" / "link.py").symlink_to(repo / "README.md")
    record = driver.make_scope_copy(str(repo), IN_SCOPE + ["src/app/link.py", "../outside.py"], str(tmp_path / "s"))
    assert record["skipped"] == ["src/app/link.py", "../outside.py"]
    assert not (tmp_path / "s" / "src" / "app" / "link.py").exists()


@pytest.mark.parametrize("value, why", [
    ("src/app/tools.py", None),
    ("security_manifest.json", None),
    ("src", None),                               # a folder on the way to an in-scope file
    (".", None),
    ("README.md", "not an in-scope file"),
    ("/app/repo/README.md", "outside the review directory"),
    ("../repo/tests/test_x.py", "outside the review directory"),
    ("SCOPE/src/app/llm.py", None),
])
def test_outside_scope(value, why):
    base = "/opt/sast/scope"
    value = value.replace("SCOPE", base)
    assert driver.outside_scope(value, base, set(IN_SCOPE) | {"security_manifest.json"}) == why


def test_tool_use_records_keep_only_names_and_paths_and_flag_the_outside():
    lines = [
        {"type": "system", "subtype": "init"},
        {"type": "assistant", "message": {"content": [
            {"type": "text", "text": "reading"},
            {"type": "tool_use", "name": "Read", "input": {"file_path": "/opt/sast/scope/src/app/llm.py", "limit": 5}},
            {"type": "tool_use", "name": "Grep", "input": {"pattern": f"key {KEY}", "path": "/etc", "output_mode": "x"}},
            {"type": "tool_use", "name": "Glob", "input": {"pattern": "/app/repo/**/*.py"}},
            {"type": "tool_use", "name": "Task", "input": {"prompt": "review the code", "description": "d"}},
        ]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "content": "PROMPT = 'hi'"}]}},
    ]
    stdout = "\n".join(json.dumps(line) for line in lines)
    records, flagged = driver.tool_use_records(stdout, "/opt/sast/scope", set(IN_SCOPE), KEY, 2)
    assert [r["tool"] for r in records] == ["Read", "Grep", "Glob", "Task"]
    assert records[0] == {"attempt": 2, "tool": "Read", "file_path": "/opt/sast/scope/src/app/llm.py"}
    assert records[1]["pattern"] == "key ***" and "output_mode" not in records[1]
    assert records[3] == {"attempt": 2, "tool": "Task"}   # no prompt text is kept
    assert [f["tool"] for f in flagged] == ["Grep", "Glob"]
    assert flagged[0]["outside_scope"] == "path outside the review directory"


def test_relativise_review_strips_the_scope_dir():
    reviewed = {"findings": [{"file": "/s/src/a.py", "line": 1, "path": [{"file": "/s/src/b.py", "line": 2}, "x"]},
                             {"file": "src/c.py", "line": 3}]}
    assert driver.relativise_review(reviewed, "/s") == 2
    assert reviewed["findings"][0]["file"] == "src/a.py" and reviewed["findings"][0]["path"][0]["file"] == "src/b.py"
    assert reviewed["findings"][1]["file"] == "src/c.py"


def test_cli_settings_deny_the_extra_folders():
    settings = driver.cli_settings("/opt/sast/secret/k", "/opt/sast/home/c", "api_key_helper", ("/app/repo",))
    assert "Read(//app/repo/**)" in settings["permissions"]["deny"]


# ---------------------------------------------------------------- whole runs


def _script(findings, tool_uses):
    return [{"exit": 0, "tool_uses": tool_uses, "wrapper": wrapper(review(findings, 2))}]


def test_the_cli_runs_in_the_scope_copy(tmp_path, repo, net):
    scope = tmp_path / "work" / "scope"
    findings = [finding(str(scope / "src" / "app" / "tools.py"), 5,
                        path=[{"file": str(scope / "src" / "app" / "tools.py"), "line": 4, "role": "sink"}]),
                finding("src/app/llm.py", 2, category="sensitive_data_logging")]
    uses = [{"name": "Read", "input": {"file_path": "security_manifest.json"}},
            {"name": "Read", "input": {"file_path": str(scope / "src" / "app" / "tools.py")}},
            {"name": "Read", "input": {"file_path": str(repo / "README.md")}},
            {"name": "Grep", "input": {"pattern": "subprocess", "path": "src"}}]
    run = DriverRun(tmp_path / "run", repo, IN_SCOPE, script=_script(findings, uses), net_url=net,
                    filter="hard_rules", scope_dir=str(scope))
    result = run.run()
    doc = run.document()
    assert result.returncode == 0, (result.stdout, result.stderr, doc.get("error"))
    (call,) = run.claude_calls()
    # The CLI saw the scope and the manifest, nothing else of the repository.
    assert call["cwd"] == str(scope)
    assert call["cwd_files"] == ["security_manifest.json", "src/app/llm.py", "src/app/tools.py"]
    assert f"Read(/{repo}/**)" in call["settings"]["permissions"]["deny"]
    assert doc["scope_copy"]["files"] == 3 and doc["scope_copy"]["manifest"] is True
    # Finding paths are the repository's own relative paths again.
    assert doc["paths_relativised"] == 2
    assert {f["file"] for f in doc["kept"]} <= set(IN_SCOPE)
    assert doc["review"]["findings"][0]["path"][0]["file"] == "src/app/tools.py"
    # Every tool call is kept; the read of the real repository is flagged.
    cli = doc["cli"]
    assert cli["tool_uses_count"] == 4 and [u["tool"] for u in cli["tool_uses"]] == ["Read", "Read", "Read", "Grep"]
    (flagged,) = cli["tool_uses_outside_scope"]
    assert flagged["file_path"] == str(repo / "README.md")
    assert flagged["outside_scope"] == "file_path outside the review directory"


def test_without_a_scope_dir_the_cli_runs_in_the_repository_and_out_of_scope_reads_are_flagged(tmp_path, repo, net):
    uses = [{"name": "Read", "input": {"file_path": "tests/test_x.py"}},
            {"name": "Read", "input": {"file_path": "src/app/tools.py"}}]
    run = DriverRun(tmp_path / "run", repo, IN_SCOPE, script=_script([], uses), net_url=net, filter="hard_rules")
    result = run.run()
    doc = run.document()
    assert result.returncode == 0, doc.get("error")
    (call,) = run.claude_calls()
    assert call["cwd"] == str(repo) and "scope_copy" not in doc
    assert [u["file_path"] for u in doc["cli"]["tool_uses_outside_scope"]] == ["tests/test_x.py"]


@pytest.mark.parametrize("scope", ["relative/scope", "REPO", "REPO/sub", "PARENT"])
def test_a_scope_dir_that_overlaps_the_repository_is_refused(tmp_path, repo, net, scope):
    scope = scope.replace("REPO", str(repo)).replace("PARENT", str(repo.parent))
    run = DriverRun(tmp_path / "run", repo, IN_SCOPE, script=_script([], []), net_url=net, filter="hard_rules",
                    scope_dir=scope)
    result = run.run()
    assert result.returncode == 3
    assert run.document()["error"]["code"] == "bad_request"
    assert (repo / "src" / "app" / "tools.py").exists()


def test_prompt_too_long_without_the_diff_is_its_own_code(tmp_path, repo, net):
    too_long = {"exit": 1, "wrapper": wrapper(None, subtype="success", is_error=True, result="Prompt is too long")}
    run = DriverRun(tmp_path / "run", repo, IN_SCOPE, script=[too_long], net_url=net, filter="hard_rules")
    run.run()
    assert run.document()["error"]["code"] == "prompt_too_long"
