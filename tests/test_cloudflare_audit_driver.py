"""sast/cloudflare_audit/driver.py run for real against a scripted ``claude``
CLI that plays the skill, a fake ``node`` and a local network-check server
(tests/cloudflare_audit_fakes.py). POSIX only: the fakes are executables with a
shebang. The pure helpers are tested everywhere."""

from __future__ import annotations

import json
import sys

import pytest

from sast.cloudflare_audit import driver
from tests.cloudflare_audit_fakes import (
    KEY, OAUTH_TOKEN, DriverRun, NetCheckServer, annotation, audit_files, confirmed, needs_validation)
from tests.conftest import SAMPLE_TASKS

POSIX = pytest.mark.skipif(sys.platform == "win32", reason="runs the scripted claude as an executable (POSIX only)")
REPO = SAMPLE_TASKS / "smoke_eval" / "environment" / "repo"
FILES = ["src/calc_agent/__init__.py", "src/calc_agent/agent.py", "src/calc_agent/llm.py",
         "src/calc_agent/maintenance.py"]


@pytest.fixture
def net():
    server = NetCheckServer()
    yield server.url
    server.close()


def run(tmp_path, net, script, **request):
    case = DriverRun(tmp_path, REPO, FILES, script=script, net_url=net, **request)
    proc = case.run()
    return case, proc, case.document()


# ---------------------------------------------------------------- pure helpers


def test_settings_allow_only_the_audit_folders_and_validators():
    settings = driver.cli_settings(scope_dir="/w/scope", out_root="/w/out-root", skill_dir="/w/home/sk",
                                   node="/w/node/bin/node", keyfile="/w/secret/tok", repo="/app/repo",
                                   private_dirs=("/w/out",), cli_auth="oauth")
    perms = settings["permissions"]
    assert perms["defaultMode"] == "dontAsk" and "apiKeyHelper" not in settings
    assert "Edit(//w/out-root/**)" in perms["allow"] and "Write(//w/out-root/**)" in perms["allow"]
    assert "Bash(node /w/home/sk/validate-findings.cjs:*)" in perms["allow"]
    assert not any(r.startswith(("Edit(", "Write(")) and "scope" in r for r in perms["allow"])
    assert {"Read(//app/repo/**)", "Read(//w/secret/**)", "Read(//w/out/**)", "Read(//proc/**)", "WebFetch",
            "WebSearch"} <= set(perms["deny"])
    assert "Bash(*/app*)" in perms["deny"] and "Bash(*-exec*)" in perms["deny"]
    assert "Bash(*CLAUDE_CODE*)" in perms["deny"] and "Bash(*${*)" in perms["deny"]
    helper = driver.cli_settings(scope_dir="/s", out_root="/o", skill_dir="/k", node="/n", keyfile="/w/secret/key",
                                 repo="/app/repo", private_dirs=(), cli_auth="api_key_helper")
    assert helper["apiKeyHelper"] == "cat /w/secret/key"


def test_argv_has_no_secret_and_the_fixed_flags():
    argv = driver.cli_argv("/c", "claude-opus-5-5", "/h/settings.json", ["/o", "/k"], 50, 9.5, "high")
    assert argv[:7] == ["/c", "--output-format", "stream-json", "--verbose", "--model", "claude-opus-5-5", "-p"]
    for flag in ("--permission-mode", "dontAsk", "--setting-sources", "user", "--strict-mcp-config",
                 "--no-session-persistence", "--add-dir", "/o", "/k", "--max-turns", "50", "--max-budget-usd", "9.5",
                 "--effort", "high"):
        assert flag in argv


@pytest.mark.parametrize("change,code", [({"model": "claude-other"}, "model_remapped"),
                                         ({"apiKeySource": "ANTHROPIC_API_KEY"}, "cli_auth"),
                                         ({"permissionMode": "auto"}, "cli_settings"),
                                         ({"tools": ["Task", "WebFetch"]}, "cli_settings"),
                                         ({"tools": ["Read", "Bash"]}, "no_subagents"),
                                         ({"skills": ["debug"]}, "skill_not_loaded")])
def test_check_init_refuses_anything_unexpected(change, code):
    init = {"model": "m", "apiKeySource": "none", "permissionMode": "dontAsk", "tools": ["Task", "Read"],
            "skills": ["security-audit"]}
    assert driver.check_init(init, "m", "oauth") is None
    init.update(change)
    assert driver.check_init(init, "m", "oauth")[0] == code


def test_tool_use_records_keep_paths_commands_and_flag_the_repository():
    lines = [json.dumps({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": "Read", "input": {"file_path": "/w/scope/src/a.py"}},
        {"type": "tool_use", "name": "Read", "input": {"file_path": "/app/repo/tests/t.py"}},
        {"type": "tool_use", "name": "Bash", "input": {"command": f"cat /app/repo/x {KEY}"}},
        {"type": "tool_use", "name": "Task", "input": {"subagent_type": "general", "prompt": "secret plan"}}]}})]
    records, flagged = driver.tool_use_records("\n".join(lines), ["/w/scope", "/w/out"], "/app/repo", KEY, 1)
    assert [r["tool"] for r in records] == ["Read", "Read", "Bash", "Task"]
    assert len(flagged) == 2 and KEY not in json.dumps(records) and "prompt" not in records[3]


def test_relativise_and_ledger_summary():
    findings = [confirmed(trace=[{"kind": "sink", "file": "/w/scope/src/a.py", "line": 1}])]
    ann = {"findings": [annotation(location={"file": "/w/scope/src/b.py", "start_line": 2})]}
    assert driver.relativise(findings, ann, "/w/scope") == 2
    assert findings[0]["trace"][0]["file"] == "src/a.py" and ann["findings"][0]["location"]["file"] == "src/b.py"
    assert driver.ledger_summary([{"status": "covered"}, {"status": "covered"}, "x"]) == {
        "units": 3, "by_state": {"covered": 2, "invalid": 1}}
    assert driver.ledger_summary({"no": "units"}) is None


def test_refused_tool_calls_are_marked():
    lines = [json.dumps({"type": "assistant", "message": {"content": [
                 {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "node x.cjs; echo $?"}},
                 {"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": "/w/scope/a.py"}}]}}),
             json.dumps({"type": "user", "message": {"content": [
                 {"type": "tool_result", "tool_use_id": "t1", "is_error": True,
                  "content": [{"type": "text", "text": "Permission to use Bash has been denied."}]},
                 {"type": "tool_result", "tool_use_id": "t2", "is_error": False, "content": "ok"}]}})]
    records, _ = driver.tool_use_records(chr(10).join(lines), ["/w/scope"], "/app/repo", KEY, 1)
    assert records[0]["refused"].startswith("Permission") and "refused" not in records[1]


# ---------------------------------------------------------------- the driver, for real


@POSIX
def test_a_complete_audit_is_read_validated_and_scrubbed(tmp_path, net):
    files = audit_files([confirmed(), needs_validation()], [annotation()], note=f"leaked {OAUTH_TOKEN}")
    case, proc, doc = run(tmp_path, net, [{"files": files, "tool_uses": [
        {"name": "Task", "input": {"subagent_type": "general", "description": "hunter"}},
        {"name": "Bash", "input": {"command": "cat /app/repo/tests/x.py"}}]}])
    assert proc.returncode == 0, doc.get("error")
    assert doc["status"] == "ok" and doc["run_status"] == "complete" and len(doc["findings"]) == 2
    assert doc["annotations"]["findings"][0]["fingerprint"] == "calc/eval"
    assert doc["validators"]["findings"]["passed"] is True and doc["validators"]["coverage_ledger"]["passed"] is True
    assert doc["ledger"] == {"units": 2, "by_state": {"covered": 1, "candidate": 1}}
    assert doc["report_md"].startswith("# Report") and doc["outputs"]["count"] >= 4
    assert doc["line_counts"]["src/calc_agent/agent.py"] > 0
    assert doc["cli"]["init"]["permissionMode"] == "dontAsk" and len(doc["cli"]["tool_uses_outside_scope"]) == 1
    text = case.out.read_text()
    assert OAUTH_TOKEN not in text and "***" in text
    (call,) = case.claude_calls()
    # The token reaches the CLI process's own environment only; the CLI runs in the scope copy.
    assert call["env_oauth_token"] == OAUTH_TOKEN and call["env_key"] is None
    assert "ANTHROPIC_BASE_URL" not in call["env_names"] and "CLAUDE_CODE_USE_BEDROCK" not in call["env_names"]
    assert OAUTH_TOKEN not in json.dumps(call["argv"]) and OAUTH_TOKEN not in json.dumps(call["settings"])
    assert call["cwd"] == str(tmp_path / "scope") and call["settings_mode"] == "0o600"
    assert "security_manifest.json" in call["cwd_files"] and not any(f.startswith("tests/") for f in call["cwd_files"])
    assert call["skills"] == ["SKILL.md", "validate-coverage-ledger.cjs", "validate-findings.cjs"]
    assert [c[1].endswith(".cjs") for c in case.node_calls()] == [True, True]


@POSIX
def test_api_key_goes_through_the_helper(tmp_path, net):
    case, proc, doc = run(tmp_path, net, [{"files": audit_files([], [])}], secret=KEY, auth="api_key")
    assert proc.returncode == 0, doc.get("error")
    (call,) = case.claude_calls()
    assert call["env_key"] is None and call["env_oauth_token"] is None
    assert call["settings"]["apiKeyHelper"].startswith("cat ")


@POSIX
@pytest.mark.parametrize("script,code", [
    ([{"files": audit_files([], [], run_status="incomplete", incomplete_reason="validation_budget_exhausted")}],
     "review_incomplete"),
    ([{"files": audit_files([], [], run_status="in_progress")}], "review_incomplete"),
    ([{}], "no_findings_file"),
    ([{"files": dict(audit_files([], []), **{"findings.json": "{not json"})}], "bad_findings"),
    ([{"files": dict(audit_files([], []), **{"findings.json": {"a": 1}})}], "bad_findings"),
    ([{"init": {"model": "claude-other"}}], "model_remapped"),
    ([{"init": {"skills": ["debug"]}}], "skill_not_loaded"),
    ([{"wrapper": {"subtype": "error_max_turns", "is_error": True}}], "cli_limit"),
    ([{"exit": 1, "wrapper": {"is_error": True, "subtype": "error_during_execution",
                              "result": "Invalid API key · Please run /login"}}], "cli_oauth_refused"),
    ([{"exit": 1, "wrapper": {"is_error": True, "subtype": "error_during_execution", "result": "boom"}}],
     "cli_failed"),
    ([{"no_init": True, "files": audit_files([], [])}], "cli_init_missing"),
])
def test_failures_have_their_codes(tmp_path, net, script, code):
    _, proc, doc = run(tmp_path, net, script)
    assert proc.returncode == 3 and doc["status"] == "error" and doc["error"]["code"] == code, doc.get("error")


@POSIX
def test_the_deadline_stops_a_slow_audit(tmp_path, net):
    _, proc, doc = run(tmp_path, net, [{"sleep": 30}], budget_sec=55, min_attempt_sec=1)
    assert doc["error"]["code"] in ("timeout", "deadline") and proc.returncode == 3


@POSIX
def test_a_tampered_skill_file_is_refused(tmp_path, net):
    case = DriverRun(tmp_path, REPO, FILES, script=[{}], net_url=net)
    (tmp_path / "skill-src" / "SKILL.md").write_text("changed")
    case.run()
    assert case.document()["error"]["code"] == "skill_missing" and case.claude_calls() == []


@POSIX
def test_a_scope_dir_inside_the_repository_is_refused(tmp_path, net):
    _, _, doc = run(tmp_path, net, [{}], scope_dir=str(REPO / "copy"))
    assert doc["error"]["code"] == "bad_request"
