"""sast/datadog_saist/driver.py: the SARIF summary, error classification, and
whole runs against a scripted ``datadog-saist`` (tests/datadog_saist_fakes.py).
Two tests read real output of the pinned binary (tests/fixtures/datadog_saist:
a run whose key OpenAI refused; datadog-saist still exited 0). No API is called
and the key is made up."""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from sast.datadog_saist import driver
from tests.conftest import FIXTURES
from tests.datadog_saist_fakes import KEY, DriverRun, result, sarif

POSIX = pytest.mark.skipif(sys.platform == "win32", reason="runs the scripted binary as an executable (POSIX only)")
REAL = FIXTURES / "datadog_saist"


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


def test_the_real_sarif_of_a_refused_key_counts_every_scan_as_failed():
    summary = driver.scan_summary(json.loads((REAL / "real_401_run.sarif").read_text(encoding="utf-8")))
    assert summary["files_analysed"] == 13 and summary["scans_succeeded"] == 0 and summary["scans_failed"] == 12
    assert summary["input_tokens"] == 0 and summary["output_tokens"] == 0 and summary["results"] == 0
    assert ["src/crewai_codeint_mini/agent.py", "datadog/python-excessiveagency"] in summary["scan_failures"]


def test_the_real_stderr_of_a_refused_key_is_api_auth():
    assert driver.classify((REAL / "real_401_stderr.txt").read_text(encoding="utf-8")) == "api_auth"


@pytest.mark.parametrize("text, code", [
    ('POST "https://api.openai.com/v1/chat/completions": 429 Too Many Requests', "rate_limited"),
    ("insufficient_quota: You exceeded your current quota", "quota"),
    ("The model `gpt-5.2` does not exist or you do not have access to it", "model_unavailable"),
    ("dial tcp: lookup api.openai.com: no such host", "network"),
    ("Too many tokens in detection context", None),
])
def test_classify(text, code):
    assert driver.classify(text) == code


def test_tool_argv_is_the_verified_command_line():
    request = {"binary": "/b/datadog-saist", "detection_model": "openai-gpt5.2", "validation_model": "openai-gpt5-mini",
               "request_timeout_sec": 120, "file_concurrency": 4, "rules": "embedded", "skip_indexing": True}
    assert driver.tool_argv(request, "/s", "/p/r.sarif") == [
        "/b/datadog-saist", "--directory", "/s", "--output", "/p/r.sarif", "--detection-model", "openai-gpt5.2",
        "--validation-model", "openai-gpt5-mini", "--request-timeout-sec", "120", "--file-concurrency", "4",
        "--debug", "--local-prompts", "--skip-indexing"]


def test_masked_and_plain_keys_are_scrubbed():
    text = f"Incorrect API key provided: sk-proj-********ykcA and {KEY}"
    assert driver.scrub(text, KEY) == "Incorrect API key provided: *** and ***"


@POSIX
def test_whole_run_scans_the_scope_copy_with_the_key_only_in_the_tools_env(tmp_path, repo):
    doc = sarif([result("datadog/python-excessiveagency", "src/app/tools.py", 4)])
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"sarif": doc, "stderr": "INFO ok\n"})
    proc = run.run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    document = run.document()
    assert document["status"] == "ok"
    assert document["summary"]["results"] == 1 and document["summary"]["scans_succeeded"] == 1
    assert document["line_counts"] == {"src/app/llm.py": 2, "src/app/tools.py": 5}
    assert document["sarif"]["runs"][0]["results"][0]["ruleId"] == "datadog/python-excessiveagency"
    [call] = run.calls()
    assert call["cwd"] == str(tmp_path / "scope")
    assert sorted(call["cwd_files"]) == ["security_manifest.json", "src/app/blob.bin", "src/app/llm.py",
                                         "src/app/tools.py"]
    assert call["env"]["OPENAI_API_KEY"] == KEY
    assert not {"ANTHROPIC_API_KEY", "DD_API_KEY", "DD_SITE", "OPENAI_BASE_URL"} & set(call["env_names"])
    assert KEY not in json.dumps(call["argv"]) and "--debug" in call["argv"]
    assert call["env"]["HOME"].startswith(str(tmp_path / "private"))
    # The private folder (the tool's SARIF and HOME) is gone; the key is in no output.
    assert not (tmp_path / "private").exists() and document["private_dir_removed"] is True
    assert KEY not in run.out.read_text() and KEY not in proc.stdout
    assert stat.S_IMODE(os.stat(run.out).st_mode) == 0o600


@POSIX
def test_a_refused_key_with_exit_0_is_an_error(tmp_path, repo):
    stderr = (REAL / "real_401_stderr.txt").read_text(encoding="utf-8")
    doc = sarif([], artifacts={"src/app/tools.py": ([], ["datadog/python-cmdi"])}, tokens=(0, 0))
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"sarif": doc, "stderr": stderr, "echo_key": True})
    run.run()
    document = run.document()
    assert document["status"] == "error" and document["error"]["code"] == "api_auth"
    assert KEY not in run.out.read_text()


@POSIX
def test_some_failed_scans_without_a_fatal_error_are_kept_and_counted(tmp_path, repo):
    doc = sarif([], artifacts={"src/app/tools.py": (["datadog/python-cmdi"], ["datadog/python-xss"])})
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"sarif": doc, "stderr": "WARN max number of attempts exceeded"})
    run.run()
    document = run.document()
    assert document["status"] == "ok" and document["summary"]["scans_failed"] == 1
    assert document["failure_code"] is None


@POSIX
@pytest.mark.parametrize("script, code", [
    ({"exit": 1, "stderr": "error calling RunAnalysis: failed to make request: dial tcp"}, "rules_unavailable"),
    ({"exit": 1, "stderr": "panic: runtime error"}, "tool_crashed"),
    ({"exit": 0, "sarif": None}, "bad_output"),
    ({"exit": 0, "sarif": "{not json"}, "bad_output"),
    ({"exit": 0, "sarif": {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": [], "artifacts": []}]}},
     "tool_saw_nothing"),
])
def test_unusable_runs_are_reported(tmp_path, repo, script, code):
    run = DriverRun(tmp_path, repo, IN_SCOPE, script=script)
    run.run()
    assert run.document()["error"]["code"] == code


@POSIX
def test_the_deadline_stops_the_tool(tmp_path, repo):
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"sleep": 60, "sarif": sarif([])}, budget_sec=42)
    run.run()
    assert run.document()["error"]["code"] == "deadline"


@POSIX
def test_missing_or_empty_key_file(tmp_path, repo):
    run = DriverRun(tmp_path, repo, IN_SCOPE, script={"sarif": sarif([])}, secret="")
    run.run()
    assert run.document()["error"]["code"] == "no_key" and run.calls() == []
