"""sast/codex_security/driver.py: how it reads Codex's event stream, judges an
answer, flags commands, and whole runs against a scripted ``codex``
(tests/codex_security_fakes.py). The event-stream tests read real output of the
pinned Codex CLI (tests/fixtures/codex_security). No API is called and the key
is made up."""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from sast.codex_security import driver
from tests.codex_security_fakes import FIXTURES, KEY, DriverRun, answer, files_under, finding

POSIX = pytest.mark.skipif(sys.platform == "win32", reason="runs the scripted codex as an executable (POSIX only)")


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "src" / "app").mkdir(parents=True)
    (root / "src" / "app" / "tools.py").write_text("import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n")
    (root / "src" / "app" / "llm.py").write_text("PROMPT = 'hi'\nprint(PROMPT)")
    (root / "src" / "app" / "blob.bin").write_bytes(b"\x00\x01binary")
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text("SECRET_TEST = 1\n")
    (root / "security_manifest.json").write_text('{"task": "demo"}\n')
    return root


IN_SCOPE = ["src/app/blob.bin", "src/app/llm.py", "src/app/tools.py"]


# ---------------------------------------------------------------- the real event stream


def test_parse_events_reads_the_real_stream_of_codex_0_162_1():
    events = driver.parse_events((FIXTURES / "exec_ok_0.162.1.jsonl").read_text())
    assert events["thread_id"] == "01a13174-624a-7f22-89e0-573b0eaf7e98"
    assert events["turns_completed"] == 1 and events["turn_failed"] is None
    assert events["usage"] == {"input_tokens": 2000, "cached_input_tokens": 200, "cache_write_input_tokens": 0,
                               "output_tokens": 100, "reasoning_output_tokens": 20}
    assert json.loads(events["final_text"]) == {"findings": [{"title": "[P2] demo", "line": 2}]}
    (command,) = events["commands"]
    assert command["command"] == "/bin/bash -lc 'cat src/app.py'" and command["status"] == "completed"
    assert events["item_types"] == {"error": 1, "command_execution": 1, "agent_message": 1}
    # The WebSocket reconnect notices are errors in the stream but not a failure.
    assert len(events["errors"]) == 5 and events["non_json_lines"] == 0
    outcome, reason, value = driver.judge(0, events, None)
    assert outcome == "ok" and value["findings"][0]["line"] == 2


def test_a_refused_key_in_the_real_stream_is_fatal_and_its_masked_key_is_scrubbed():
    text = (FIXTURES / "exec_401_0.162.1.jsonl").read_text()
    events = driver.parse_events(text)
    assert events["final_text"] is None and "401 Unauthorized" in events["turn_failed"]
    outcome, code, message = driver.judge(1, events, None)
    assert (outcome, code) == ("fatal", "api_auth")
    assert "sk-fake-***STKEY" in message and "STKEY" not in driver.scrub(message, "")


@pytest.mark.parametrize("text, code", [
    ("unexpected status 401 Unauthorized: Incorrect API key provided", "api_auth"),
    ("You exceeded your current quota, please check your plan and billing details (insufficient_quota)", "quota"),
    ("The model `gpt-9` does not exist or you do not have access to it. (model_not_found)", "model_unavailable"),
    ("context_length_exceeded: input is too long", "prompt_too_long"),
    ("stream disconnected: error sending request for url (https://api.openai.com/v1/responses)", "network"),
    ("429 Too Many Requests: rate limit reached", "rate_limited"),
    ("an internal server error occurred", None),
])
def test_classify(text, code):
    assert driver.classify(text) == code


@pytest.mark.parametrize("code, events, last, outcome", [
    (None, {}, None, "timeout"),
    (0, {"final_text": "not json"}, None, "retry"),
    (0, {"final_text": json.dumps({"no_findings": []})}, None, "retry"),
    (0, {"final_text": json.dumps([1, 2])}, None, "retry"),
    (1, {"turn_failed": "server overloaded"}, None, "retry"),
    (1, {"turn_failed": "invalid_api_key"}, None, "fatal"),
    (2, {}, None, "retry"),
    # The -o file wins over the stream's last message.
    (0, {"final_text": "garbage"}, json.dumps({"findings": []}), "ok"),
])
def test_judge(code, events, last, outcome):
    base = {"final_text": None, "turn_failed": None, "errors": []}
    base.update(events)
    assert driver.judge(code, base, last)[0] == outcome


def test_command_records_keep_no_output_and_flag_private_paths():
    commands = [
        {"command": "/bin/bash -lc 'cat src/app.py'", "aggregated_output": "print(1)", "exit_code": 0,
         "status": "completed"},
        {"command": f"/bin/bash -lc 'cat /app/repo/tests/t.py; echo {KEY}'", "aggregated_output": "x",
         "exit_code": 0, "status": "completed"},
        {"command": "/bin/bash -lc 'cat /h/codex-home/auth.json'", "exit_code": 1, "status": "failed",
         "aggregated_output": "bwrap: No permissions to create a new namespace, likely because ..."},
    ]
    private = [("the repository", "/app/repo"), ("CODEX_HOME", "/h/codex-home")]
    records, flagged, sandbox_failures = driver.command_records(commands, private, KEY, 1)
    assert [r.get("outside_scope") for r in records] == [None, "names the repository", "names CODEX_HOME"]
    assert flagged == records[1:] and sandbox_failures == 1
    assert all("aggregated_output" not in r for r in records)
    assert KEY not in json.dumps(records) and "***" in records[1]["command"]


def test_check_review():
    assert driver.check_review(answer([], files_reviewed=2), 2) == {"files_reviewed": 2, "review_completed": True}
    with pytest.raises(driver.DriverError) as exc:
        driver.check_review(answer([], completed=False), 2)
    assert exc.value.code == "review_incomplete"
    with pytest.raises(driver.DriverError) as exc:
        driver.check_review(answer([], files_reviewed=0), 2)
    assert exc.value.code == "files_reviewed_zero"
    with pytest.raises(driver.DriverError) as exc:
        driver.check_review({"findings": ["text"], "analysis_summary": {}}, 2)
    assert exc.value.code == "bad_findings"


def test_relativise_makes_scope_paths_repository_relative():
    value = {"findings": [finding("/w/scope/src/a.py", 3, path=[{"file": "/w/scope/src/b.py", "line": 1},
                                                                 {"file": "src/c.py", "line": 2}]),
                          finding("/app/repo/src/d.py", 1)]}
    assert driver.relativise(value, "/w/scope") == 2
    assert value["findings"][0]["code_location"]["absolute_file_path"] == "src/a.py"
    assert [s["file"] for s in value["findings"][0]["path"]] == ["src/b.py", "src/c.py"]
    # Not under the copy: left for the agent's scope check.
    assert value["findings"][1]["code_location"]["absolute_file_path"] == "/app/repo/src/d.py"


def test_exec_argv_is_the_verified_command_line():
    argv = driver.exec_argv("/c/codex", "gpt-5.6-sol", "/p/schema.json", "/p/last.json", "/w/scope", "read-only")
    assert argv == ["/c/codex", "exec", "--strict-config", "--json", "--skip-git-repo-check", "--ephemeral",
                    "--ignore-rules", "--color", "never", "--output-schema", "/p/schema.json", "-o", "/p/last.json",
                    "-C", "/w/scope", "-m", "gpt-5.6-sol", "-"]
    container = driver.exec_argv("/c/codex", "m", "/s", "/l", "/w", "container")
    assert container[-2:] == ["--dangerously-bypass-approvals-and-sandbox", "-"]
    assert "--dangerously-bypass-approvals-and-sandbox" not in argv


def test_codex_environment_is_an_allow_list(monkeypatch):
    for name, value in {"OPENAI_API_KEY": "k", "CODEX_API_KEY": "k", "OPENAI_BASE_URL": "x", "CODEX_HOME": "/x",
                        "LANG": "C.UTF-8", "LC_ALL": "C", "HTTPS_PROXY": "http://p"}.items():
        monkeypatch.setenv(name, value)
    env = driver.codex_environment("/h", "/h/codex-home")
    assert env["HOME"] == "/h" and env["CODEX_HOME"] == "/h/codex-home"
    assert not any(n.startswith(("OPENAI_", "CODEX_API")) for n in env)
    assert env["LANG"] == "C.UTF-8" and env["HTTPS_PROXY"] == "http://p"


# ---------------------------------------------------------------- whole runs


def _final(*findings, files_reviewed=2):
    return answer(list(findings), files_reviewed=files_reviewed)


@POSIX
def test_whole_run_logs_in_from_stdin_and_reviews_the_scope_copy(tmp_path, repo):
    final = _final(finding(str(tmp_path / "scope" / "src/app/tools.py"), 5, cwe=["CWE-78"]))
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"runs": [{"final": final, "commands": [
        {"command": "/bin/bash -lc 'cat src/app/tools.py'"}]}]})
    proc = run.run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    doc = run.document()
    assert doc["status"] == "ok" and doc["codex_version"] == "codex-cli 0.162.1"
    assert doc["review"]["findings"][0]["code_location"]["absolute_file_path"] == "src/app/tools.py"
    assert doc["paths_relativised"] == 1 and doc["line_counts"] == {"src/app/llm.py": 2, "src/app/tools.py": 5}
    assert doc["not_text"] == [["src/app/blob.bin", "binary"]]
    assert doc["exec"]["usage"]["input_tokens"] == 1200 and doc["exec"]["thread_id"] == "thread-0"
    assert doc["exec"]["commands"][0]["command"] == "/bin/bash -lc 'cat src/app/tools.py'"
    assert doc["login"] == {"auth_file_mode": "0o600", "status": "api_key"}
    assert doc["sandbox_probe"]["ok"] is True and doc["network"] == "skipped"
    assert '"status": "ok"' in proc.stdout.splitlines()[-1]

    calls = run.calls()
    login = next(c for c in calls if c["argv"][1:] == ["login", "--with-api-key"])
    # The key reaches Codex on stdin only: never argv, never an environment variable.
    assert login["stdin"].strip() == KEY
    for call in calls:
        assert KEY not in json.dumps(call["argv"])
        assert all(KEY not in v for v in call["env"].values())
        assert not any(n in call["env"] for n in ("OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL"))
        assert call["env"]["CODEX_HOME"] == str(tmp_path / "home" / "codex-home")
    (exec_call,) = run.exec_calls()
    assert exec_call["auth_key"] == KEY and exec_call["stdin"] == "review the code"
    assert exec_call["config"] == 'model = "gpt-5.6-sol"\n'
    # Codex runs in the scope copy: the in-scope files and the manifest, nothing else.
    assert exec_call["cwd"] == str(tmp_path / "scope")
    assert exec_call["cwd_files"] == sorted(IN_SCOPE + ["security_manifest.json"])
    assert "-s" not in exec_call["argv"] and exec_call["argv"][-1] == "-"
    # Codex's home (auth.json) is gone afterwards, and no file holds the key.
    assert not (tmp_path / "home" / "codex-home").exists() and doc["codex_home_removed"] is True
    for path in files_under(tmp_path):
        # The key file itself, and the fake's own log of what it was given (stdin above).
        if path not in (run.keyfile, tmp_path / "codex.log"):
            assert KEY not in path.read_text(errors="replace"), path


@POSIX
def test_the_sandbox_probe_stops_a_review_that_could_read_nothing(tmp_path, repo):
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"sandbox_exit": 1, "runs": [{"final": _final()}]})
    assert run.run().returncode == 3
    doc = run.document()
    assert doc["error"]["code"] == "sandbox_unavailable" and "user namespaces" in doc["error"]["message"]
    assert run.exec_calls() == [] and not (tmp_path / "home" / "codex-home").exists()


@POSIX
def test_container_sandbox_skips_the_probe_and_bypasses_codex_sandbox(tmp_path, repo):
    run = DriverRun(tmp_path, repo, IN_SCOPE, sandbox="container",
                    script={"sandbox_exit": 1, "runs": [{"final": _final()}]})
    assert run.run().returncode == 0
    assert run.document()["sandbox_probe"] == "skipped: sandbox container"
    assert "--dangerously-bypass-approvals-and-sandbox" in run.exec_calls()[0]["argv"]


@POSIX
def test_every_command_failing_in_the_sandbox_is_an_error(tmp_path, repo):
    bwrap = {"command": "/bin/bash -lc 'cat x'", "status": "failed", "exit_code": 1,
             "output": "bwrap: No permissions to create a new namespace, likely because the kernel ..."}
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"runs": [{"final": _final(), "commands": [bwrap, bwrap]}]})
    assert run.run().returncode == 3
    assert run.document()["error"]["code"] == "sandbox_failed"


@POSIX
def test_an_unusable_answer_is_retried_then_reported(tmp_path, repo):
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"runs": [{"final_text": "I found nothing."},
                                                               {"final": _final()}]})
    assert run.run().returncode == 0
    attempts = run.document()["exec"]["attempts"]
    assert [a["outcome"] for a in attempts] == ["retry", "ok"]
    run2 = DriverRun(tmp_path / "b", repo, IN_SCOPE, script={"runs": [{"final_text": "nope"}]})
    assert run2.run().returncode == 3
    assert run2.document()["error"]["code"] == "bad_answer" and len(run2.exec_calls()) == 2


@POSIX
@pytest.mark.parametrize("step, code, calls", [
    ({"turn_failed": "unexpected status 401 Unauthorized: Incorrect API key provided: sk-proj-***EFGH"},
     "api_auth", 1),
    ({"turn_failed": "The model `x` does not exist or you do not have access to it."}, "model_unavailable", 1),
    ({"turn_failed": "server_error: try again"}, "cli_failed", 2),
    ({"exit": 101, "stdout": "thread 'main' panicked\n"}, "cli_crashed", 2),
    ({"final": {"findings": [], "analysis_summary": {"review_completed": False}}}, "review_incomplete", 1),
    ({"final": {"findings": [], "analysis_summary": {"files_reviewed": 0}}}, "files_reviewed_zero", 1),
])
def test_untrustworthy_reviews_are_errors(tmp_path, repo, step, code, calls):
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"runs": [step]})
    assert run.run().returncode == 3
    doc = run.document()
    assert doc["error"]["code"] == code and len(run.exec_calls()) == calls
    assert "EFGH" not in json.dumps(doc)  # the masked key is scrubbed too
    assert not (tmp_path / "home" / "codex-home").exists()


@POSIX
def test_a_failed_login_stops_before_the_review(tmp_path, repo):
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"login_exit": 1, "runs": [{"final": _final()}]})
    assert run.run().returncode == 3
    assert run.document()["error"]["code"] == "login_failed" and run.exec_calls() == []


@POSIX
def test_the_review_time_limit(tmp_path, repo):
    run = DriverRun(tmp_path, repo, IN_SCOPE, budget_sec=14, min_attempt_sec=1,
                    script={"runs": [{"sleep": 30, "final": _final()}]})
    assert run.run(timeout=60).returncode == 3
    assert run.document()["error"]["code"] == "timeout"


@POSIX
def test_missing_or_empty_key_file(tmp_path, repo):
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"runs": [{"final": _final()}]})
    run.keyfile.write_text("\n")
    assert run.run().returncode == 3 and run.document()["error"]["code"] == "no_key"
    run.keyfile.unlink()
    assert run.run().returncode == 3 and run.document()["error"]["code"] == "no_key"
    assert run.calls() == []


@POSIX
def test_the_result_file_is_private(tmp_path, repo):
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"runs": [{"final": _final()}]})
    run.run()
    assert stat.S_IMODE(os.stat(run.out).st_mode) == 0o600
