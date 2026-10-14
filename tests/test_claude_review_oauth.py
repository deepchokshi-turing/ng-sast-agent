"""The Claude Code security review agent with a Claude subscription token
(CLAUDE_CODE_OAUTH_TOKEN, made with ``claude setup-token``).

Fakes only, as in the other claude_review tests: a fake sandbox for the agent,
and driver.py run for real with the scripted ``claude`` and the fake SDK. The
token here is made up. No real CLI runs and nothing is sent anywhere.
"""

from __future__ import annotations

import asyncio
import json
import sys

import pytest
from harbor.environments.base import ExecResult

from sast.base import ScannerAgent
from sast.claude_review import driver
from sast.claude_review.agent import ClaudeReviewAgent, choose_auth, filter_conflict
from sast.errors import ScannerError
from tests.claude_review_fakes import KEY, OAUTH_TOKEN, DriverRun, NetCheckServer, finding, review, wrapper
from tests.test_claude_review_agent import (
    CLEAN_ENV,
    KEY_DIR,
    MODEL,
    OUT,
    FakeSandbox,
    driver_document,
    run_agent,
)
from tests.test_claude_review_driver import IN_SCOPE as DRIVER_IN_SCOPE
from tests.test_claude_review_driver import parse_json_with_fallbacks
from tests.test_claude_review_driver import repo  # noqa: F401  (fixture)

TOKEN_FILE = f"{KEY_DIR}/claude-oauth-token"
SECRETS = (KEY, OAUTH_TOKEN)


def _clean(monkeypatch):
    for name in ("ANTHROPIC_API_KEY", *CLEAN_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def oauth_token(monkeypatch):
    """The host has a subscription token and no API key."""
    _clean(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", OAUTH_TOKEN)


@pytest.fixture
def both(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", OAUTH_TOKEN)


@pytest.fixture
def net():
    server = NetCheckServer()
    yield server.url
    server.close()


def oauth_init():
    """The init message Claude Code 2.1.296 prints with a subscription token: no API key in use."""
    return {"type": "system", "subtype": "init", "model": MODEL, "apiKeySource": "none", "tools": ["Read", "Grep"]}


def assert_secret_nowhere(tmp_path, sandbox, context, secret=OAUTH_TOKEN):
    """Neither credential in any exec command or env, log, metadata, artifact or sandbox file,
    no credential variable name in an exec env, and the credential file is gone."""
    for command, env, _ in sandbox.commands:
        for value in SECRETS:
            assert value not in command
            assert all(value not in v for v in (env or {}).values())
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in (env or {}) and "ANTHROPIC_API_KEY" not in (env or {})
    dumped = json.dumps(context.metadata, default=str)
    assert secret not in dumped
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret not in path.read_text(errors="replace"), path
    for name, data in sandbox.files.items():
        assert secret.encode() not in data, name
    assert not any(name.startswith(KEY_DIR) for name in sandbox.files)
    assert context.metadata["claude_review"]["key_file_removed"] is True


# ---------------------------------------------------------------- choosing the credential


@pytest.mark.parametrize("requested, env, mode, words", [
    ("auto", {"ANTHROPIC_API_KEY": KEY}, "api_key", "ANTHROPIC_API_KEY is set"),
    ("auto", {"CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN}, "oauth", "CLAUDE_CODE_OAUTH_TOKEN is set"),
    ("auto", {"ANTHROPIC_API_KEY": KEY, "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN}, "api_key", "both"),
    ("auto", {}, None, "neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN"),
    ("auto", {"ANTHROPIC_API_KEY": "  ", "CLAUDE_CODE_OAUTH_TOKEN": ""}, None, "neither"),
    ("api_key", {"ANTHROPIC_API_KEY": KEY, "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN}, "api_key", "auth=api_key"),
    ("api_key", {"CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN}, None, "needs ANTHROPIC_API_KEY"),
    ("oauth", {"ANTHROPIC_API_KEY": KEY, "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN}, "oauth", "auth=oauth"),
    ("oauth", {"ANTHROPIC_API_KEY": KEY}, None, "needs CLAUDE_CODE_OAUTH_TOKEN"),
])
def test_choose_auth(requested, env, mode, words):
    chosen, note = choose_auth(requested, env)
    assert chosen == mode and words in note
    assert all(value not in note for value in SECRETS)


def test_filter_conflict_only_for_claude_with_a_token():
    assert filter_conflict("oauth", "claude") and "API key" in filter_conflict("oauth", "claude")
    assert filter_conflict("oauth", "hard_rules") is None and filter_conflict("oauth", None) is None
    assert filter_conflict("api_key", "claude") is None


def test_preflight_auto_with_each_credential(monkeypatch):
    _clean(monkeypatch)
    with pytest.raises(ValueError, match="neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN"):
        ClaudeReviewAgent.preflight({"model": MODEL}, {})
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", OAUTH_TOKEN)
    ClaudeReviewAgent.preflight({"model": MODEL}, {})
    ClaudeReviewAgent.preflight({"model": MODEL, "filter": "hard_rules"}, {})
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    ClaudeReviewAgent.preflight({"model": MODEL, "filter": "claude"}, {})   # auto picks the key


def test_preflight_explicit_modes(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", OAUTH_TOKEN)
    with pytest.raises(ValueError, match="auth=api_key needs ANTHROPIC_API_KEY"):
        ClaudeReviewAgent.preflight({"auth": "api_key"}, {})
    ClaudeReviewAgent.preflight({"auth": "oauth"}, {})
    _clean(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    with pytest.raises(ValueError, match="auth=oauth needs CLAUDE_CODE_OAUTH_TOKEN"):
        ClaudeReviewAgent.preflight({"auth": "oauth"}, {})


def test_preflight_rejects_the_claude_filter_with_a_token(oauth_token, monkeypatch):
    with pytest.raises(ValueError, match="filter=claude needs an Anthropic API key"):
        ClaudeReviewAgent.preflight({"filter": "claude"}, {})
    monkeypatch.setenv("CLAUDE_REVIEW_FILTER", "claude")
    with pytest.raises(ValueError, match="filter=claude needs an Anthropic API key"):
        ClaudeReviewAgent.preflight({}, {})
    # Both credentials set, auth=oauth forced: still refused.
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    with pytest.raises(ValueError, match="filter=claude"):
        ClaudeReviewAgent.preflight({"auth": "oauth"}, {})


def test_auth_from_the_environment_loses_to_kwargs(both, monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_REVIEW_AUTH", "oauth")
    agent = ClaudeReviewAgent(logs_dir=tmp_path)
    assert agent.options.auth == "oauth" and agent.auth_mode() == "oauth" and agent.filter_mode() == "hard_rules"
    agent = ClaudeReviewAgent(logs_dir=tmp_path, auth="api_key")
    assert agent.auth_mode() == "api_key" and agent.filter_mode() == "claude"


def test_default_filter_follows_the_credential(tmp_path, monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    assert ClaudeReviewAgent(logs_dir=tmp_path).filter_mode() == "claude"
    assert ClaudeReviewAgent(logs_dir=tmp_path, filter="hard_rules").filter_mode() == "hard_rules"
    _clean(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", OAUTH_TOKEN)
    agent = ClaudeReviewAgent(logs_dir=tmp_path)
    assert agent.filter_mode() == "hard_rules" and agent.results_label() == "stock CLI + hard-rule filter"
    assert ClaudeReviewAgent(logs_dir=tmp_path, mode="scoped").results_label() == "scoped CLI + hard-rule filter"


# ---------------------------------------------------------------- the agent with a token


def test_oauth_run_keeps_the_token_in_a_file_and_out_of_everything(tmp_path, oauth_token):
    kept = [{**finding("src/calc_agent/agent.py", 8, category="eval_injection"),
             "_filter_metadata": {"confidence_score": 10, "justification": "Claude filtering disabled"}}]
    document = driver_document(kept, init=oauth_init())
    document["preflight"] = "skipped_oauth"
    sandbox = FakeSandbox(document=document, secret=OAUTH_TOKEN)
    agent, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok", meta.get("error")
    assert meta["auth"] == "oauth" and meta["filter_mode"] == "hard_rules" and meta["filter_model"] is None
    assert agent.to_agent_info().model_info.name == MODEL     # model reporting unchanged
    review_meta = meta["claude_review"]
    assert review_meta["auth"] == "oauth" and review_meta["auth_choice"].startswith("auth=auto")
    assert review_meta["filter_mode"] == "hard_rules" and review_meta["filter_mode_source"] == "default_for_oauth"
    assert review_meta["results_label"] == "stock CLI + hard-rule filter"
    assert review_meta["cli_auth"] == "oauth_env" and review_meta["preflight"] == "skipped_oauth"
    assert review_meta["cli_credential_source"] == "none"
    assert review_meta["key_file"] == TOKEN_FILE
    # The request names the mode and the filter, never the token.
    assert sandbox.request["auth"] == "oauth" and sandbox.request["filter"] == "hard_rules"
    assert OAUTH_TOKEN not in json.dumps(sandbox.request)
    # The token travels only in its own file, which is gone afterwards.
    assert sandbox.key_reads == [(TOKEN_FILE, True)]
    (command, _, _), = sandbox.commands_with("driver.py")
    assert f"--keyfile {TOKEN_FILE}" in command
    events = sandbox.events
    upload = events.index(("upload", f"{TOKEN_FILE}.upload"))
    driver_i = next(i for i, (kind, c) in enumerate(events) if kind == "exec" and "driver.py" in c)
    removed = events.index(("exec", f"rm -rf {KEY_DIR}"))
    assert upload < driver_i < removed
    sarif = json.loads(sandbox.files["/app/output/findings.sarif"])
    props = sarif["runs"][0]["tool"]["driver"]["properties"]
    assert props["filterMode"] == "hard_rules" and props["auth"] == "oauth"
    assert_secret_nowhere(tmp_path, sandbox, context)


def test_auto_with_both_prefers_the_key_and_says_so(tmp_path, both):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    review_meta = context.metadata["claude_review"]
    assert context.metadata["auth"] == "api_key" and review_meta["auth"] == "api_key"
    assert "both" in review_meta["auth_choice"] and review_meta["filter_mode"] == "claude"
    assert sandbox.request["auth"] == "api_key" and sandbox.key_reads == [(f"{KEY_DIR}/anthropic-key", True)]
    assert_secret_nowhere(tmp_path, sandbox, context, secret=KEY)
    assert_secret_nowhere(tmp_path, sandbox, context, secret=OAUTH_TOKEN)


def test_explicit_claude_filter_with_a_token_fails_before_anything_runs(tmp_path, oauth_token):
    sandbox = FakeSandbox(secret=OAUTH_TOKEN)
    _, context, go = run_agent(tmp_path, sandbox, filter="claude")
    with pytest.raises(ScannerError, match="filter=claude needs an Anthropic API key"):
        asyncio.run(go())
    assert not sandbox.commands_with("driver.py") and not any(n.startswith(KEY_DIR) for n in sandbox.files)


def test_refused_token_is_a_clear_error_without_the_token(tmp_path, oauth_token):
    message = f"Claude Code refused the subscription token (the CLI said 'invalid api key') {OAUTH_TOKEN}"
    document = driver_document(status="error", error={"code": "cli_oauth_refused", "message": message},
                               init=oauth_init())
    sandbox = FakeSandbox(document=document, driver_exit=3, secret=OAUTH_TOKEN,
                          driver_stderr=f"token {OAUTH_TOKEN}")
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="the subscription token was refused. Run `claude setup-token` again") as raised:
        asyncio.run(go())
    assert "[cli_oauth_refused]" in str(raised.value) and OAUTH_TOKEN not in str(raised.value)
    assert OAUTH_TOKEN not in context.metadata.get("error", "")
    assert b"***" in sandbox.files[OUT]
    assert_secret_nowhere(tmp_path, sandbox, context)


@pytest.mark.parametrize("failure, message", [
    ({"fail_upload": True}, "could not upload /opt/sast/secret/claude-oauth-token.upload"),
    ({"protect_exit": 1}, "could not protect the key file"),
    ({"prepare_exit": 1}, "could not prepare the key directory"),
    ({"driver_exit": 4, "write_document": False}, "without a readable result"),
])
def test_a_failure_with_a_token_removes_it(tmp_path, oauth_token, failure, message):
    sandbox = FakeSandbox(secret=OAUTH_TOKEN, driver_stderr=f"Traceback ... {OAUTH_TOKEN}", **failure)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=message) as raised:
        asyncio.run(go())
    assert OAUTH_TOKEN not in str(raised.value)
    assert_secret_nowhere(tmp_path, sandbox, context)


def test_a_timeout_with_a_token_is_a_tool_outcome_and_removes_it(tmp_path, oauth_token):
    sandbox = FakeSandbox(secret=OAUTH_TOKEN, driver_stderr=f"Traceback ... {OAUTH_TOKEN}", driver_exit=124,
                          write_document=False)
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    outcome = context.metadata["tool_outcome"]
    assert outcome["reason"] == "deadline" and "ran out of time" in outcome["message"]
    assert OAUTH_TOKEN not in outcome["message"]
    assert_secret_nowhere(tmp_path, sandbox, context)


def test_token_echoed_by_the_driver_is_scrubbed_everywhere(tmp_path, oauth_token):
    document = driver_document(echo_key=True, secret=OAUTH_TOKEN, init=oauth_init())
    sandbox = FakeSandbox(document=document, secret=OAUTH_TOKEN, driver_stdout=f"DRIVER_RESULT {{}}\nt {OAUTH_TOKEN}",
                          driver_stderr=f"leaked {OAUTH_TOKEN}")
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    log = (tmp_path / "command-1" / "stdout.txt").read_text()
    assert "leaked ***" in log and "t ***" in log
    assert b"the key was ***" in sandbox.files[OUT]
    assert_secret_nowhere(tmp_path, sandbox, context)


# ---------------------------------------------------------------- the driver with a token


def test_oauth_settings_have_no_api_key_helper():
    settings = driver.cli_settings("/opt/sast/secret/claude-oauth-token", "/opt/sast/home/claude-review", "oauth")
    assert "apiKeyHelper" not in settings
    assert "Read(//opt/sast/secret/**)" in settings["permissions"]["deny"]
    assert "Read(//proc/**)" in settings["permissions"]["deny"]      # the token is in the CLI's environment
    assert OAUTH_TOKEN not in json.dumps(settings)


def test_oauth_environment_adds_exactly_the_token(monkeypatch):
    for name in ("CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_MODEL"):
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "from-the-process")
    env = driver.cli_environment("/h", OAUTH_TOKEN, "oauth", "/opt/bin")
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == OAUTH_TOKEN
    assert not [n for n in env if n.startswith("ANTHROPIC_")]
    assert sorted(n for n in env if n.startswith("CLAUDE")) == ["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
                                                               "CLAUDE_CODE_OAUTH_TOKEN"]
    for cli_auth in ("api_key_helper", "env"):
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in driver.cli_environment("/h", KEY, cli_auth, "/opt/bin")


@pytest.mark.parametrize("source, ok", [
    ("none", True),
    ("apiKeyHelper", False),
    ("ANTHROPIC_API_KEY", False),
    ("/login managed key", False),
    (None, False),
])
def test_check_init_with_a_token(source, ok):
    init = {**oauth_init(), "apiKeySource": source}
    verdict = driver.check_init(init, MODEL, "oauth")
    if ok:
        assert verdict is None
    else:
        assert verdict[0] == "cli_auth" and "expected 'none'" in verdict[1]


def test_api_key_modes_still_reject_none():
    assert driver.check_init(oauth_init(), MODEL, "api_key_helper")[0] == "cli_auth"
    assert driver.check_init(oauth_init(), MODEL, "env")[0] == "cli_auth"


@pytest.mark.parametrize("text, marker", [
    ("Invalid API key · Please run /login", "invalid api key"),
    ("Failed to authenticate. API Error: 401 {\"type\":\"error\"}", "failed to authenticate"),
    ("OAuth token revoked · Please run /login", "please run /login"),
    ("all good", None),
])
def test_auth_failure_markers(text, marker):
    assert driver.auth_failure(text, "") == marker


def _stream(*messages):
    return "".join(json.dumps(m) + "\n" for m in messages)


#: The model's own text and a tool result quoting a repository file that holds the CLI's refusal phrases.
QUOTING = (
    {"type": "assistant", "message": {"content": [{"type": "text", "text": "The README says: Not logged in · "
                                                                            "Please run /login"}]}},
    {"type": "user", "message": {"content": [{"type": "tool_result", "content": "die('Invalid API key · Please "
                                                                                "run /login')"}]}},
)


@pytest.mark.parametrize("stdout, stderr, marker", [
    # A result that is not an error: the quotes are the repository's, not the CLI's.
    (_stream(*QUOTING, wrapper(result="Looks fine to me.")), "", None),
    (_stream(*QUOTING, wrapper(result="Invalid API key · Please run /login")), "", None),
    # An error result: its own text is the CLI's.
    (_stream(*QUOTING, wrapper(is_error=True, result="OAuth token revoked · Please run /login")), "",
     "please run /login"),
    # No result: the JSON messages are still not read, the CLI's plain lines are.
    (_stream(*QUOTING), "", None),
    (_stream(*QUOTING) + "Not logged in\n", "", "not logged in"),
    # stderr is always the CLI's own.
    (_stream(*QUOTING, wrapper(result="Looks fine to me.")), "Failed to authenticate. API Error: 401",
     "failed to authenticate"),
])
def test_auth_failure_reads_only_the_clis_own_words(stdout, stderr, marker):
    assert driver.auth_failure(stdout, stderr, parse_json_with_fallbacks) == marker


def test_exec_scrubs_the_output_before_it_cuts_it():
    """A killed command's error message keeps the last 600 characters of its
    output. A token straddling that cut leaves no partial copy."""
    output = "x" * 1000 + OAUTH_TOKEN + "y" * 590

    class Environment:
        async def exec(self, command, cwd=None, env=None, timeout_sec=None):
            return ExecResult(stdout=output, stderr="", return_code=124)

    with pytest.raises(ScannerError) as err:
        asyncio.run(ScannerAgent._exec(None, Environment(), "driver", timeout_sec=10, what="the review",
                                       scrub=lambda text: text.replace(OAUTH_TOKEN, "***")))
    assert OAUTH_TOKEN[-10:] not in str(err.value) and str(err.value).endswith("x" * 7 + "***" + "y" * 590)


def test_sdk_guard_refuses_to_make_a_client(monkeypatch):
    monkeypatch.setitem(sys.modules, "anthropic", None)    # restored after the test
    guard = driver.install_sdk_guard()
    assert sys.modules["anthropic"] is guard and guard.__version__ is None
    with pytest.raises(driver.SdkDisabled):
        guard.Anthropic(api_key=OAUTH_TOKEN)


def _oauth_run(tmp_path, repo, net, script=None, **request):
    request.setdefault("auth", "oauth")
    request.setdefault("filter", None)
    script = script or [{"exit": 0, "wrapper": wrapper(review([finding("src/app/tools.py", 5)]))}]
    return DriverRun(tmp_path / "run", repo, DRIVER_IN_SCOPE, script=script, net_url=net, secret=OAUTH_TOKEN,
                     **request)


#: Variables a host may leave in the driver's own environment. The driver must drop them all.
HOST_ENV = {"CLAUDE_CODE_OAUTH_TOKEN": "host-token-not-the-file", "ANTHROPIC_API_KEY": KEY}


def _assert_token_only_in_the_cli_env(run, result):
    for text in (run.out.read_text(), result.stdout, result.stderr):
        assert OAUTH_TOKEN not in text and KEY not in text
    for call in run.claude_calls():
        assert OAUTH_TOKEN not in json.dumps(call["argv"]) and OAUTH_TOKEN not in json.dumps(call["settings"])
        assert not call["env_has_key"] and call["helper_key"] is None
        assert call["env_oauth_token"] == OAUTH_TOKEN      # from the file, not the inherited variable


def test_whole_run_with_a_token(tmp_path, repo, net):  # noqa: F811
    run = _oauth_run(tmp_path, repo, net)
    result = run.run(extra_env=HOST_ENV)
    doc = run.document()
    assert result.returncode == 0, (result.stdout, result.stderr, doc.get("error"))
    assert doc["auth"] == "oauth" and doc["filter_mode"] == "hard_rules"
    assert doc["preflight"] == "skipped_oauth"
    assert doc["filter"]["mode"] == "hard_rules" and len(doc["kept"]) == 1
    assert doc["kept"][0]["_filter_metadata"]["justification"] == "Claude filtering disabled"
    assert "apiKeyHelper" not in doc["cli_settings"]
    assert doc["cli"]["init"]["apiKeySource"] == "none"
    assert "CLAUDE_CODE_OAUTH_TOKEN" in doc["environment_removed"] and "ANTHROPIC_API_KEY" in doc["environment_removed"]
    assert "CLAUDE_CODE_OAUTH_TOKEN" in doc["cli_environment"]        # the name only
    # The SDK is never imported and never called.
    assert not run.sdk_imported() and run.api_calls() == []
    assert doc["versions"]["anthropic"] is None
    (call,) = run.claude_calls()
    assert "CLAUDE_CODE_OAUTH_TOKEN" in call["env_names"]
    assert not [n for n in call["env_names"] if n.startswith("ANTHROPIC_")]
    _assert_token_only_in_the_cli_env(run, result)


def test_api_key_run_still_imports_the_sdk(tmp_path, repo, net):  # noqa: F811
    """The guard is for a token only: the API-key path is unchanged."""
    run = DriverRun(tmp_path / "run", repo, DRIVER_IN_SCOPE, net_url=net, filter="hard_rules",
                    script=[{"exit": 0, "wrapper": wrapper(review([]))}])
    assert run.run().returncode == 0
    assert run.sdk_imported() and run.document()["auth"] == "api_key"
    assert [c["ping"] for c in run.api_calls()] == [True]       # the preflight


def test_driver_refuses_the_claude_filter_with_a_token(tmp_path, repo, net):  # noqa: F811
    run = _oauth_run(tmp_path, repo, net, filter="claude")
    result = run.run()
    doc = run.document()
    assert result.returncode == 3 and doc["error"]["code"] == "oauth_filter"
    assert run.claude_calls() == [] and run.api_calls() == [] and not run.sdk_imported()


def test_refused_token_stops_at_once(tmp_path, repo, net):  # noqa: F811
    script = [{"exit": 1, "wrapper": wrapper(is_error=True, result=f"Invalid API key · Please run /login "
                                                                     f"({OAUTH_TOKEN})")}]
    run = _oauth_run(tmp_path, repo, net, script=script)
    result = run.run(extra_env=HOST_ENV)
    doc = run.document()
    assert result.returncode == 3 and doc["error"]["code"] == "cli_oauth_refused", doc["error"]
    assert "claude setup-token" in doc["error"]["message"]
    assert len(run.claude_calls()) == 1                       # not retried
    assert doc["cli"]["attempts"][0]["auth_failure"] == "invalid api key"
    _assert_token_only_in_the_cli_env(run, result)


def test_quoted_refusal_phrases_do_not_stop_a_token_run(tmp_path, repo, net):  # noqa: F811
    """The model quotes a repository file that says "Please run /login", and the
    attempt fails for another reason: the run retries instead of stopping as
    cli_oauth_refused."""
    first = _stream(*QUOTING, wrapper(result="I could not finish: Not logged in · Please run /login"))
    script = [{"exit": 0, "stdout": first}, {"exit": 0, "wrapper": wrapper(review([finding("src/app/tools.py", 5)]))}]
    run = _oauth_run(tmp_path, repo, net, script=script)
    result = run.run(timeout=60)
    doc = run.document()
    assert result.returncode == 0, doc.get("error")
    assert len(run.claude_calls()) == 2
    assert [a["outcome"] for a in doc["cli"]["attempts"]] == ["retry", "ok"]
    assert "auth_failure" not in doc["cli"]["attempts"][0]


def test_an_api_key_source_stops_a_token_run(tmp_path, repo, net):  # noqa: F811
    script = [{"exit": 0, "sleep": 60, "init": {"apiKeySource": "apiKeyHelper"}, "wrapper": wrapper(review([]))}]
    run = _oauth_run(tmp_path, repo, net, script=script)
    result = run.run(timeout=50)
    doc = run.document()
    assert result.returncode == 3 and doc["error"]["code"] == "cli_auth" and "expected 'none'" in doc["error"]["message"]
    assert len(run.claude_calls()) == 1
