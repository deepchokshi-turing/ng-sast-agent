"""ClaudeReviewAgent against a fake sandbox: options, model reporting, key
handling, the driver command, failures, mapping and the SARIF.

No model is called. The fake sandbox answers the driver command with a result
document in driver.py's format (its real behaviour is tested in
test_claude_review_driver.py), and lists files from the sample task
``smoke_eval``.
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
from pathlib import Path

import pytest
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

import sast
from sast import cwe_map
from sast.claude_review import category_map, pins
from sast.claude_review.agent import (
    FILTER_INSTRUCTIONS_FILE,
    KILL_AFTER_SEC,
    SCAN_INSTRUCTIONS_FILE,
    ClaudeReviewAgent,
)
from sast.errors import ScannerError
from tests.claude_review_fakes import KEY, finding, review, wrapper
from tests.conftest import SAMPLE_TASKS

WORK = "/opt/sast"
KEY_DIR = f"{WORK}/secret"
KEY_FILE = f"{KEY_DIR}/anthropic-key"
OUT = f"{WORK}/out/claude_review.json"
TASK = "smoke_eval"
REPO = SAMPLE_TASKS / TASK / "environment" / "repo"
#: The model most tests run with (any id works, the fakes never call a model).
MODEL = "claude-opus-5-5"
IN_SCOPE = ["src/calc_agent/__init__.py", "src/calc_agent/agent.py", "src/calc_agent/llm.py",
            "src/calc_agent/maintenance.py"]


def line_counts(files=IN_SCOPE):
    return {f: len((REPO / f).read_text().splitlines()) for f in files}


def driver_document(kept=None, *, status="ok", error=None, raw=None, excluded=None, echo_key=False, files=IN_SCOPE,
                    secret=KEY, init=None):
    kept = [] if kept is None else kept
    doc = {
        "driver_format": 1, "status": status, "seconds": 75.0,
        "claude_code_version": "2.1.296 (Claude Code)",
        "versions": {"python": "3.12.11", "anthropic": "0.79.0", "requests": "2.32.5"},
        "upstream_default_model": pins.UPSTREAM_DEFAULT_MODEL,
        "network": {"url": "https://api.anthropic.com/", "status": 404},
        "preflight": {pins.UPSTREAM_DEFAULT_MODEL: "ok"},
        "cli_argv": ["/opt/sast/claude-review/bin/claude", "--output-format", "json"],
        "cli_settings": {"apiKeyHelper": f"cat {KEY_FILE}", "permissions": {"deny": ["Bash"]}},
        "environment_removed": [],
        "pr": {"files": len(files), "in_diff": files, "skipped_generated": [], "skipped_binary": [], "missing": [],
               "line_counts": line_counts(files), "diff_bytes": 900, "diff_sha256": "ab"},
        "cli": {"attempts": [{"exit_code": 0, "seconds": 70.0, "outcome": "ok", "include_diff": True,
                              "wrapper": {"total_cost_usd": 0.42}}],
                "diff_omitted": False, "prompt_sha256": "cd", "prompt_bytes": 12000,
                "cli": {k: v for k, v in wrapper(review([])).items() if k != "review"},
                **({"init": init} if init is not None else {})},
        "review": review(raw if raw is not None else kept, files_reviewed=len(files)),
        "review_summary": {"files_reviewed": len(files), "review_completed": True},
        "filter": {"mode": "claude", "calls": [], "summary": {"total_findings": len(raw or kept)}},
        "kept": kept,
        "excluded": excluded or [],
        "api_usage": {pins.UPSTREAM_DEFAULT_MODEL: {"input_tokens": 300, "output_tokens": 20}},
        "api_calls": 3,
    }
    if error:
        doc["error"] = error
    if echo_key:
        doc["note"] = f"the key was {secret}"
    return doc


class FakeSandbox:
    """Just enough of BaseEnvironment: a dict file system and scripted exec."""

    def __init__(self, document=None, driver_exit=0, driver_stdout=None, prepare_exit=0, fail_upload=False,
                 protect_exit=0, driver_stderr="", write_document=True, secret=KEY):
        self.environment_dir = SAMPLE_TASKS / TASK / "environment"
        self.files: dict[str, bytes] = {}
        self.commands: list[tuple[str, dict | None, float | None]] = []
        self.events: list[tuple[str, str]] = []
        self.key_reads: list[tuple[str, bool]] = []
        self.document = driver_document() if document is None else document
        self.driver_exit = driver_exit
        self.driver_stdout = driver_stdout
        self.driver_stderr = driver_stderr
        self.prepare_exit = prepare_exit
        self.fail_upload = fail_upload
        self.protect_exit = protect_exit
        self.write_document = write_document
        self.request = None
        self.secret = secret

    def _remove_tree(self, path):
        for name in [n for n in self.files if n == path or n.startswith(path + "/")]:
            del self.files[name]

    def _find(self, command):
        args = shlex.split(command)
        roots = args[1:args.index("-name")]
        found = []
        for root in roots:
            base = REPO / root
            if base.is_file():
                found.append(root)
            elif base.is_dir():
                found += [str(p.relative_to(REPO)) for p in base.rglob("*") if p.is_file()]
        return ExecResult(stdout="\n".join(f"./{f}" if i % 2 else f for i, f in enumerate(found)) + "\n",
                          return_code=0)

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        self.commands.append((command, env, timeout_sec))
        self.events.append(("exec", command))
        if command.startswith("umask 077 && cat "):
            if self.protect_exit:
                return ExecResult(stdout="", stderr="Terminated", return_code=self.protect_exit)
            source, target = re.search(r"cat (\S+) > (\S+)", command).groups()
            self.files[target] = self.files.pop(source)
            return ExecResult(return_code=0)
        if re.fullmatch(r"rm -rf (\S+) && mkdir -p \S+ && chmod 700 \S+", command):
            self._remove_tree(command.split()[2])
            return ExecResult(return_code=self.prepare_exit)
        if re.fullmatch(r"rm -rf (\S+)", command):
            self._remove_tree(command.split()[2])
            return ExecResult(return_code=0)
        if command.startswith("find "):
            return self._find(command)
        if "install.py" in command:
            result = {"claude": "/opt/sast/claude-review/bin/claude", "ccsr_dir": "/opt/sast/claude-review/ccsr",
                      "venv_python": "/opt/sast/claude-review/venv/bin/python", "source": "image",
                      "claude_version_output": "2.1.296 (Claude Code)", "anthropic": "0.79.0"}
            return ExecResult(stdout="INSTALL_RESULT " + json.dumps(result), return_code=0)
        if "driver.py" in command:
            args = shlex.split(command.split(" && exec ", 1)[1])
            keyfile = args[args.index("--keyfile") + 1]
            self.key_reads.append((keyfile, self.files.get(keyfile, b"").strip() == self.secret.encode()))
            self.request = json.loads(self.files[args[args.index("--request") + 1]])
            if self.write_document:
                self.files[args[args.index("--out") + 1]] = json.dumps(self.document).encode()
            stdout = self.driver_stdout if self.driver_stdout is not None else "DRIVER_RESULT " + json.dumps(
                {"status": self.document.get("status")})
            return ExecResult(stdout=stdout, stderr=self.driver_stderr, return_code=self.driver_exit)
        if command.startswith("mkdir -p /opt/sast"):
            return ExecResult(stdout="writable\n", return_code=0)
        if command.startswith("if [ -e"):
            names = re.findall(r"if \[ -e (\S+) \]", command)
            return ExecResult(stdout="".join(f"OK {n}\n" for n in names if (REPO / n).exists()), return_code=0)
        if command.startswith("test -f") and " && cp " in command:
            source, target = re.match(r"test -f (\S+) && cp \S+ (\S+)", command).groups()
            if source not in self.files:
                return ExecResult(return_code=1)
            self.files[target] = self.files[source]
            return ExecResult(return_code=0)
        return ExecResult(stdout="", return_code=0)

    async def upload_file(self, source_path, target_path):
        self.events.append(("upload", str(target_path)))
        self.files[str(target_path)] = Path(source_path).read_bytes()
        if self.fail_upload and str(target_path).endswith(".upload"):
            raise RuntimeError("docker cp: context deadline exceeded")

    async def download_file(self, source_path, target_path):
        if source_path not in self.files:
            raise FileNotFoundError(source_path)
        Path(target_path).write_bytes(self.files[source_path])

    def commands_with(self, needle):
        return [(c, env, t) for c, env, t in self.commands if needle in c]


#: Host variables that would change a test's outcome, removed by the credential fixtures.
CLEAN_ENV = ("CLAUDE_REVIEW_MODEL", "CLAUDE_REVIEW_MODE", "CLAUDE_REVIEW_FILTER", "CLAUDE_REVIEW_MAX_TURNS",
             "CLAUDE_REVIEW_TIMEOUT_SEC", "CLAUDE_REVIEW_FILTER_MODEL", "CLAUDE_REVIEW_AUTH", "CLAUDE_CODE_OAUTH_TOKEN")


@pytest.fixture
def api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)


def run_agent(tmp_path, sandbox, **options):
    options.setdefault("model", MODEL)
    agent = ClaudeReviewAgent(logs_dir=tmp_path, model_name="openai/gpt-5", **options)
    context = AgentContext()

    async def go():
        await agent.setup(sandbox)
        await agent.run("instruction text", sandbox, context)

    return agent, context, go


def assert_key_nowhere(tmp_path, sandbox, context):
    """Not in any exec command or env, log, metadata, artifact or output, and the key file is gone."""
    for command, env, _ in sandbox.commands:
        assert KEY not in command
        assert "ANTHROPIC_API_KEY" not in (env or {})
        assert all(KEY not in value for value in (env or {}).values())
    assert KEY not in json.dumps(context.metadata, default=str)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert KEY not in path.read_text(errors="replace"), path
    for name, data in sandbox.files.items():
        assert KEY.encode() not in data, name
    assert not any(name.startswith(KEY_DIR) for name in sandbox.files)
    assert context.metadata["claude_review"]["key_file_removed"] is True


def sarif_of(sandbox):
    return json.loads(sandbox.files["/app/output/findings.sarif"])


# ---------------------------------------------------------------- happy path


def test_happy_path_maps_findings_and_keeps_the_key_in_a_file(tmp_path, api_key):
    kept = [
        {**finding("src/calc_agent/agent.py", 8, category="eval_injection"),
         "_filter_metadata": {"confidence_score": 9, "justification": "real"}},
        {**finding("src/calc_agent/maintenance.py", 8, category="Command Injection", severity="MEDIUM"),
         "_filter_metadata": {"confidence_score": 8, "justification": "real"}},
        # Not in the table: unmapped, counted, not reported.
        {**finding("src/calc_agent/llm.py", 2, category="business_logic_flaw", severity="LOW"),
         "_filter_metadata": {"confidence_score": 7, "justification": "x"}},
    ]
    sandbox = FakeSandbox(document=driver_document(kept))
    agent, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["status"] == "ok", meta.get("error")

    # The model it really uses, not Harbor's -m.
    assert meta["model"] == MODEL and meta["model_source"] == "option"
    assert meta["harbor_model_name_ignored"] == "openai/gpt-5" and "model_ignored" not in meta
    assert meta["mode"] == "stock" and meta["filter_mode"] == "claude"
    info = agent.to_agent_info()
    assert info.model_info.name == MODEL and info.model_info.provider == "anthropic"
    assert meta["agent_version"] == f"{sast.__version__}+claude-code-security-review-0c6a49f+claude-code-2.1.296"

    review_meta = meta["claude_review"]
    assert review_meta["upstream_commit"] == pins.CCSR_COMMIT
    assert review_meta["claude_code_version"] == "2.1.296 (Claude Code)"
    assert review_meta["total_cost_usd"] == 0.42 and review_meta["num_turns"] == 7 and review_meta["attempts"] == 1
    assert review_meta["model_usage"] and review_meta["api_usage"]
    assert review_meta["scan_instructions_sha256"] is None and review_meta["filter_instructions_sha256"] is None
    assert review_meta["findings_raw"] == 3 and review_meta["findings_kept"] == 3
    assert meta["category_map"] == category_map.VERSION
    assert meta["unmapped_by_category"] == {"business_logic_flaw": 1}
    assert meta["cwe_source"] == {"none": 1, "table": 2}

    results = sarif_of(sandbox)["runs"][0]["results"]
    assert [(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
             r["locations"][0]["physicalLocation"]["region"]["startLine"], r["level"]) for r in results] == [
        ("LLM03.EA.FUNCTIONALITY", "src/calc_agent/agent.py", 8, "error"),
        ("LLM03.EA.FUNCTIONALITY", "src/calc_agent/maintenance.py", 8, "warning"),
    ]
    first = results[0]
    assert first["properties"]["cwe"] == ["CWE-95"] and first["properties"]["toolRuleIds"] == ["ccsr/eval_injection"]
    assert "codeFlows" not in first
    tool = first["properties"]["toolProperties"]
    assert tool["category"] == "eval_injection" and tool["severity"] == "HIGH" and tool["cweSource"] == "table"
    assert tool["filterConfidence"] == "9"
    # Grader-read fields come only from the fixed heuristics, never from the model's prose.
    assert "controlStatus" not in first["properties"] and first["properties"]["heuristics"]["residualRisk"] == "high"
    driver = sarif_of(sandbox)["runs"][0]["tool"]["driver"]
    assert driver["name"] == "claude-code-security-review"
    assert driver["properties"]["model"] == MODEL and driver["properties"]["mode"] == "stock"
    assert driver["properties"]["cweMap"] == cwe_map.VERSION

    # The request names the in-scope files only (src minus tests and thirdparty).
    assert sandbox.request["files"] == IN_SCOPE
    assert sandbox.request["model"] == MODEL and sandbox.request["filter_model"] == MODEL
    assert sandbox.request["mode"] == "stock"
    assert sandbox.request["scan_instructions"] is None and KEY not in json.dumps(sandbox.request)

    # The key travels only in a file, which exists while the driver runs and is removed after.
    assert sandbox.key_reads == [(KEY_FILE, True)]
    events = sandbox.events
    prepare = events.index(("exec", f"rm -rf {KEY_DIR} && mkdir -p {KEY_DIR} && chmod 700 {KEY_DIR}"))
    upload = events.index(("upload", f"{KEY_FILE}.upload"))
    protect = next(i for i, (kind, c) in enumerate(events) if kind == "exec" and "chmod 600" in c)
    driver_i = next(i for i, (kind, c) in enumerate(events) if kind == "exec" and "driver.py" in c)
    removed = events.index(("exec", f"rm -rf {KEY_DIR}"))
    assert prepare < upload < protect < driver_i < removed
    assert_key_nowhere(tmp_path, sandbox, context)
    assert set(meta["artifacts_saved"]) == {"metadata.json", "findings.sarif", "install.log", "claude_review.json"}


def test_driver_command_and_time_limit(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, timeout_sec=1800)
    asyncio.run(go())
    (command, env, exec_limit), = sandbox.commands_with("driver.py")
    inner = command.split(" && exec ", 1)[1]
    args = shlex.split(inner)
    assert args[:3] == ["timeout", "-k", str(KILL_AFTER_SEC)]
    seconds = int(args[3])
    assert args[4:9] == ["/opt/sast/claude-review/venv/bin/python", "-I", "-B", f"{WORK}/driver.py", "--request"]
    assert args[10:] == ["--keyfile", KEY_FILE, "--out", OUT]
    assert exec_limit == seconds + KILL_AFTER_SEC + 5
    assert seconds <= 1800 - 60 and sandbox.request["budget_sec"] == seconds
    assert env == {"HOME": f"{WORK}/home/claude-review", "PYTHONDONTWRITEBYTECODE": "1",
                   "PATH": "/opt/sast/claude-review/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    assert context.metadata["scan_budget_sec"] == 1800
    # task.toml gives 900 s and Harbor's multiplier cannot be seen: a reminder, not a warning.
    review = context.metadata["claude_review"]
    assert "budget_warning" not in review and review["harbor_limit_needed_sec"] == 1800 + 120
    assert "--agent-timeout-multiplier" in review["budget_note"] and "at least 1920 s" in review["budget_note"]


def test_no_budget_note_when_the_budget_comes_from_task_toml(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert "budget_note" not in context.metadata["claude_review"]


def test_budget_note_rule():
    from sast.claude_review.agent import budget_note
    assert budget_note(780, False, 900) is None          # derived from task.toml
    assert budget_note(780, True, 900) is None           # explicit, and fits with the 120 s margin
    assert budget_note(2400, True, 900).startswith("timeout_sec=2400 is more than")
    assert budget_note(2400, True, None) is None         # no task limit: Harbor imposes none


# ---------------------------------------------------------------- options and model


def test_options_from_kwargs(tmp_path, api_key):
    sandbox = FakeSandbox()
    agent, context, go = run_agent(tmp_path, sandbox, model="anthropic/claude-sonnet-4-5", mode="scoped",
                                   max_turns="40", max_budget_usd="3.5", filter="hard_rules", cli_attempts="2")
    asyncio.run(go())
    request = sandbox.request
    assert request["model"] == "claude-sonnet-4-5" and request["mode"] == "scoped" and request["filter"] == "hard_rules"
    assert request["max_turns"] == 40 and request["max_budget_usd"] == 3.5 and request["cli_attempts"] == 2
    assert request["scan_instructions"] == SCAN_INSTRUCTIONS_FILE.read_text()
    assert request["filter_instructions"] == FILTER_INSTRUCTIONS_FILE.read_text()
    meta = context.metadata
    assert meta["model"] == "claude-sonnet-4-5" and meta["model_source"] == "option" and meta["filter_model"] is None
    review_meta = meta["claude_review"]
    assert review_meta["scan_instructions_sha256"] and review_meta["filter_instructions_sha256"]
    assert agent.to_agent_info().model_info.name == "claude-sonnet-4-5"


def test_options_from_the_environment_lose_to_kwargs(tmp_path, api_key, monkeypatch):
    monkeypatch.setenv("CLAUDE_REVIEW_MODEL", "claude-from-env")
    monkeypatch.setenv("CLAUDE_REVIEW_MODE", "scoped")
    monkeypatch.setenv("CLAUDE_REVIEW_MAX_TURNS", "25")
    agent = ClaudeReviewAgent(logs_dir=tmp_path)
    assert agent.review_model() == "claude-from-env" and agent.options.mode == "scoped" and agent.options.max_turns == 25
    agent = ClaudeReviewAgent(logs_dir=tmp_path, model="claude-from-kwarg", mode="stock")
    assert agent.review_model() == "claude-from-kwarg" and agent.options.mode == "stock"


@pytest.mark.parametrize("bad", [{"mode": "fancy"}, {"filter": "none"}, {"max_turns": "0"}, {"cli_auth": "argv"},
                                 {"auth": "subscription"},
                                 {"model": "two words"}, {"timeout_sec": "30"}])
def test_bad_options_are_refused(tmp_path, bad):
    with pytest.raises(ValueError):
        ClaudeReviewAgent(logs_dir=tmp_path, **bad)


def test_preflight_needs_the_key_on_the_host(monkeypatch):
    for name in ("ANTHROPIC_API_KEY", *CLEAN_ENV):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN is set on the host"):
        ClaudeReviewAgent.preflight({"model": MODEL}, {})
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    ClaudeReviewAgent.preflight({"mode": "scoped", "model": MODEL}, {})


def test_upstream_default_passes_preflight(monkeypatch):
    """No static refusal: whether a model id is served as itself is only known from the CLI's init message."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    for name in CLEAN_ENV:
        monkeypatch.delenv(name, raising=False)
    ClaudeReviewAgent.preflight({}, {})
    ClaudeReviewAgent.preflight({"model": "opus"}, {})
    assert not hasattr(pins, "CLI_MODEL_REMAPS")


def test_upstream_default_is_the_default_and_reaches_the_driver(tmp_path, api_key):
    sandbox = FakeSandbox()
    agent = ClaudeReviewAgent(logs_dir=tmp_path)
    assert agent.review_model() == pins.UPSTREAM_DEFAULT_MODEL
    context = AgentContext()

    async def go():
        await agent.setup(sandbox)
        await agent.run("x", sandbox, context)

    asyncio.run(go())
    assert sandbox.request["model"] == pins.UPSTREAM_DEFAULT_MODEL
    assert context.metadata["model"] == pins.UPSTREAM_DEFAULT_MODEL
    assert context.metadata["model_source"] == "upstream_default"


def test_model_from_the_environment(tmp_path, api_key, monkeypatch):
    monkeypatch.setenv("CLAUDE_REVIEW_MODEL", "claude-sonnet-x")
    assert ClaudeReviewAgent(logs_dir=tmp_path).review_model() == "claude-sonnet-x"


def test_a_remap_at_run_time_tells_how_to_choose_the_model(tmp_path, api_key):
    message = ("Claude Code would run the review on 'claude-opus-5-5', not on the requested "
               "'claude-opus-4-1-20250805'. Pass --ak model=<model id> (or set CLAUDE_REVIEW_MODEL) with a model "
               "your key can use, for example --ak model=claude-opus-5-5")
    document = driver_document(status="error", error={"code": "model_remapped", "message": message})
    sandbox = FakeSandbox(document=document, driver_exit=3)
    agent = ClaudeReviewAgent(logs_dir=tmp_path)
    context = AgentContext()

    async def go():
        await agent.setup(sandbox)
        await agent.run("x", sandbox, context)

    with pytest.raises(ScannerError, match=r"Choose the model with --ak model=<model id>") as raised:
        asyncio.run(go())
    assert "[model_remapped]" in str(raised.value) and "--ak model=claude-opus-5-5" in str(raised.value)
    assert_key_nowhere(tmp_path, sandbox, context)


def test_missing_key_fails_before_anything_runs(tmp_path, monkeypatch):
    for name in ("ANTHROPIC_API_KEY", *CLEAN_ENV):
        monkeypatch.delenv(name, raising=False)
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN is set on the host"):
        asyncio.run(go())
    assert context.metadata["status"] == "error"
    assert not sandbox.commands_with("driver.py") and "/app/output/findings.sarif" not in sandbox.files


# ---------------------------------------------------------------- key handling after failures


@pytest.mark.parametrize("failure, message", [
    ({"fail_upload": True}, "could not upload /opt/sast/secret/anthropic-key.upload"),
    ({"protect_exit": 124}, "protecting the key file ran out of time"),
    ({"protect_exit": 1}, "could not protect the key file"),
    ({"prepare_exit": 1}, "could not prepare the key directory"),
])
def test_a_failure_while_writing_the_key_leaves_nothing(tmp_path, api_key, failure, message):
    sandbox = FakeSandbox(**failure)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=message):
        asyncio.run(go())
    assert not sandbox.commands_with("driver.py")
    assert_key_nowhere(tmp_path, sandbox, context)


@pytest.mark.parametrize("code, words", [
    ("network", "cannot reach api.anthropic.com"),
    ("api_auth", "refused ANTHROPIC_API_KEY"),
    ("model_unavailable", "retired or misspelt"),
    ("cli_failed", "did not produce a usable review"),
    ("filter_call_failed", "per-finding filter call failed"),
    ("files_reviewed_zero", "reviewed no file"),
])
def test_driver_errors_become_scanner_errors_and_remove_the_key(tmp_path, api_key, code, words):
    document = driver_document(status="error", error={"code": code, "message": f"details of {code}"})
    sandbox = FakeSandbox(document=document, driver_exit=3)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match=words) as raised:
        asyncio.run(go())
    assert f"[{code}]" in str(raised.value) and f"details of {code}" in str(raised.value)
    assert context.metadata["claude_review"]["driver_error"]["code"] == code
    assert "/app/output/findings.sarif" not in sandbox.files
    assert_key_nowhere(tmp_path, sandbox, context)


def test_driver_timeout_is_an_error_and_removes_the_key(tmp_path, api_key):
    sandbox = FakeSandbox(driver_exit=124, write_document=False)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="ran out of time"):
        asyncio.run(go())
    assert_key_nowhere(tmp_path, sandbox, context)


def test_driver_without_output_is_an_error(tmp_path, api_key):
    sandbox = FakeSandbox(driver_exit=4, write_document=False, driver_stderr=f"Traceback ... {KEY}")
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="without a readable result") as raised:
        asyncio.run(go())
    assert KEY not in str(raised.value)
    assert_key_nowhere(tmp_path, sandbox, context)


def test_ok_status_with_a_non_zero_exit_is_still_an_error(tmp_path, api_key):
    sandbox = FakeSandbox(driver_exit=1)
    _, context, go = run_agent(tmp_path, sandbox)
    with pytest.raises(ScannerError, match="exit 1"):
        asyncio.run(go())


def test_key_echoed_by_the_driver_is_scrubbed_everywhere(tmp_path, api_key):
    sandbox = FakeSandbox(document=driver_document(echo_key=True), driver_stdout=f"DRIVER_RESULT {{}}\nkey {KEY}",
                          driver_stderr=f"leaked {KEY}")
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    log = (tmp_path / "command-1" / "stdout.txt").read_text()
    assert "leaked ***" in log and "key ***" in log
    assert b"the key was ***" in sandbox.files[OUT]
    assert_key_nowhere(tmp_path, sandbox, context)


def test_install_files_and_command_carry_no_secret(tmp_path, api_key):
    agent = ClaudeReviewAgent(logs_dir=tmp_path, model=MODEL)
    files = agent.install_files()
    assert set(files) == {"install.py", "driver.py", "pins.json", "requirements.lock"}
    assert all(KEY.encode() not in data for data in files.values())
    assert json.loads(files["pins.json"]) == pins.as_dict()
    assert KEY not in agent.install_command("/opt/sast")


def test_run_without_setup_is_an_error(tmp_path, api_key):
    agent = ClaudeReviewAgent(logs_dir=tmp_path, model=MODEL)
    context = AgentContext()
    with pytest.raises(ScannerError, match="setup"):
        asyncio.run(agent.run("x", FakeSandbox(), context))


# ---------------------------------------------------------------- scope and locations


def test_scope_options_change_the_files_sent(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, scan_roots="src,security_manifest.json", exclude="tests")
    asyncio.run(go())
    assert sandbox.request["files"] == ["security_manifest.json", *IN_SCOPE[:1], "src/calc_agent/agent.py",
                                        "src/calc_agent/llm.py", "src/calc_agent/maintenance.py",
                                        "src/calc_agent/thirdparty/legacy.py"]
    assert context.metadata["scan"]["files_in_scope"] == 6


def test_bad_locations_and_out_of_scope_findings_are_dropped_and_counted(tmp_path, api_key):
    kept = [
        finding("src/calc_agent/agent.py", 8, category="eval_injection"),
        finding("/app/repo/src/calc_agent/agent.py", "8", category="code_injection"),   # absolute path, str line
        finding("src/calc_agent/agent.py", 99, category="eval_injection"),              # past the end
        finding("src/calc_agent/agent.py", 0, category="eval_injection"),
        finding("src/calc_agent/agent.py", None, category="eval_injection"),
        finding("src/calc_agent/thirdparty/legacy.py", 3, category="eval_injection"),   # excluded path
        finding("tests/test_smoke.py", 1, category="eval_injection"),                   # excluded path
        finding("src/calc_agent/nope.py", 1, category="eval_injection"),                # no such file
    ]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    meta = context.metadata
    assert meta["dropped_bad_location_count"] == 4 and meta["dropped_out_of_scope_count"] == 2
    results = sarif_of(sandbox)["runs"][0]["results"]
    # The two good findings on line 8 are one result (same line, same family).
    assert len(results) == 1 and sorted(results[0]["properties"]["cwe"]) == ["CWE-94", "CWE-95"]


# ---------------------------------------------------------------- scoped CWEs


def test_scoped_mode_prefers_valid_model_cwes(tmp_path, api_key):
    kept = [
        finding("src/calc_agent/llm.py", 2, category="prompt_logging", cwe=["CWE-532", "CWE-200"]),
        finding("src/calc_agent/agent.py", 8, category="eval_injection", cwe=["CWE-99999", "nonsense"]),  # fallback
        finding("src/calc_agent/maintenance.py", 8, category="whatever", cwe=["CWE-78", "CWE-532"]),    # ambiguous
        finding("src/calc_agent/maintenance.py", 5, category="x", cwe=[78]),
    ]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, context, go = run_agent(tmp_path, sandbox, mode="scoped")
    asyncio.run(go())
    meta = context.metadata
    assert meta["cwe_source"] == {"model": 3, "table_fallback": 1}
    assert meta["cwes_rejected"] == ["CWE-99999", "nonsense"]
    assert meta["results_by_cwe_decision"]["ambiguous"] == 1
    assert meta["results_cwe_ambiguous"][0][2:] == ["src/calc_agent/maintenance.py", 8]
    rules = {(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
              r["locations"][0]["physicalLocation"]["region"]["startLine"]): (r["ruleId"], r["properties"]["cwe"])
             for r in sarif_of(sandbox)["runs"][0]["results"]}
    assert rules[("src/calc_agent/llm.py", 2)] == ("LLM02.SID.HIGH", ["CWE-532", "CWE-200"])
    assert rules[("src/calc_agent/agent.py", 8)] == ("LLM03.EA.FUNCTIONALITY", ["CWE-95"])
    assert rules[("src/calc_agent/maintenance.py", 5)] == ("LLM03.EA.FUNCTIONALITY", ["CWE-78"])
    assert len(rules) == 3


def test_stock_mode_ignores_model_cwes(tmp_path, api_key):
    kept = [finding("src/calc_agent/agent.py", 8, category="eval_injection", cwe=["CWE-532"])]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    (result,) = sarif_of(sandbox)["runs"][0]["results"]
    assert result["ruleId"] == "LLM03.EA.FUNCTIONALITY" and result["properties"]["cwe"] == ["CWE-95"]


# ---------------------------------------------------------------- scoped path, controls, recommendations


ASSESSED = {
    "path": [{"file": "src/calc_agent/agent.py", "line": 12, "role": "model_decision"},
             {"file": "./src/calc_agent/agent.py", "line": "8", "role": "SINK"}],
    "control_status": "None", "residual_risk": "high",
    "recommendation_ids": ["REC-NARROW-TYPED-TOOLS", "rec-policy-gate", "REC-NARROW-TYPED-TOOLS"],
}


def test_scoped_mode_writes_the_models_path_controls_and_recommendations(tmp_path, api_key):
    kept = [finding("src/calc_agent/agent.py", 8, category="eval_injection", cwe=["CWE-95"], **ASSESSED)]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, context, go = run_agent(tmp_path, sandbox, mode="scoped")
    asyncio.run(go())
    (result,) = sarif_of(sandbox)["runs"][0]["results"]
    steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [(s["location"]["physicalLocation"]["artifactLocation"]["uri"],
             s["location"]["physicalLocation"]["region"]["startLine"], s["properties"]["role"]) for s in steps] == [
        ("src/calc_agent/agent.py", 12, "model_decision"), ("src/calc_agent/agent.py", 8, "sink")]
    props = result["properties"]
    assert props["controlStatus"] == "none" and props["residualRisk"] == "high"
    assert props["recommendations"] == ["REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE"]
    assert "heuristics" in props
    assert context.metadata["assessed_fields"] == {"path": 1, "path_steps": 2, "control_status": 1,
                                                   "residual_risk": 1, "recommendations": 1}


def test_scoped_mode_drops_bad_steps_and_values(tmp_path, api_key):
    kept = [finding("src/calc_agent/agent.py", 8, category="eval_injection", cwe=["CWE-95"],
                    path=[{"file": "src/calc_agent/agent.py", "line": 999, "role": "sink"},
                          {"file": "tests/test_x.py", "line": 1, "role": "source"},
                          "not a step",
                          {"file": "src/calc_agent/agent.py", "line": 12, "role": "made_up"},
                          {"file": "src/calc_agent/agent.py", "line": 8, "role": "sink"}],
                    control_status="mostly", residual_risk="severe",
                    recommendation_ids=["REC-NOT-REAL", 7, "REC-POLICY-GATE"])]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, context, go = run_agent(tmp_path, sandbox, mode="scoped")
    asyncio.run(go())
    (result,) = sarif_of(sandbox)["runs"][0]["results"]
    steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
    # One role the profile does not know: the writer falls back to source/sink.
    assert [(s["location"]["physicalLocation"]["region"]["startLine"], s.get("properties", {}).get("role"))
            for s in steps] == [(12, "source"), (8, "sink")]
    props = result["properties"]
    assert "controlStatus" not in props and "residualRisk" not in props
    assert props["recommendations"] == ["REC-POLICY-GATE"]
    meta = context.metadata
    assert meta["path_steps_dropped_count"] == 3
    assert [d[0] for d in meta["path_steps_dropped"]] == ["line outside the file", "out of scope",
                                                         "step is not an object"]
    assert meta["assessed_values_rejected"] == ["mostly", "severe"]
    assert meta["recommendations_rejected"] == ["REC-NOT-REAL", "7"]


def test_scoped_mode_without_assessed_fields_scores_none(tmp_path, api_key):
    kept = [finding("src/calc_agent/agent.py", 8, category="eval_injection", cwe=["CWE-95"])]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, context, go = run_agent(tmp_path, sandbox, mode="scoped")
    asyncio.run(go())
    (result,) = sarif_of(sandbox)["runs"][0]["results"]
    assert "codeFlows" not in result
    assert not {"controlStatus", "residualRisk", "recommendations"} & set(result["properties"])
    assert context.metadata["assessed_fields"]["path"] == 0


def test_stock_mode_ignores_the_assessed_fields(tmp_path, api_key):
    kept = [finding("src/calc_agent/agent.py", 8, category="eval_injection", **ASSESSED)]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, _, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    (result,) = sarif_of(sandbox)["runs"][0]["results"]
    assert "codeFlows" not in result
    assert not {"controlStatus", "residualRisk", "recommendations"} & set(result["properties"])


def test_scoped_assessment_earns_path_controls_and_recommendations(tmp_path, api_key, grade_sarif):
    kept = [finding("src/calc_agent/agent.py", 8, category="eval_injection", cwe=["CWE-95"], **ASSESSED)]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, _, go = run_agent(tmp_path, sandbox, mode="scoped")
    asyncio.run(go())
    reward = grade_sarif(TASK, sarif_of(sandbox))
    assert reward["path"] == 1.0 and reward["controls"] == 1.0 and reward["recommendations"] == 1.0


def test_the_sarif_grades_like_any_scanner(tmp_path, api_key, grade_sarif):
    """The eval() finding on smoke_eval scores as the Semgrep one does: detection and classification."""
    kept = [finding("src/calc_agent/agent.py", 8, category="eval_injection")]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, _, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    reward = grade_sarif(TASK, sarif_of(sandbox))
    assert reward["reward"] > 0


def test_agent_imports_only_stdlib_and_harbor():
    import subprocess
    import sys
    from importlib import metadata

    from tests.conftest import ROOT
    from tests.test_imports import _closure

    code = ("import json, sys; import sast.claude_review.agent; "
            "print(json.dumps(sorted({m.split('.')[0] for m in sys.modules})))")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True, capture_output=True, text=True)
    allowed = _closure("harbor")
    providers = metadata.packages_distributions()
    offenders = []
    for module in set(json.loads(out.stdout)) - set(sys.stdlib_module_names) - {
            "sast", "harbor", "sitecustomize", "usercustomize"}:
        if module.startswith("_"):
            continue
        dists = {d.lower().replace("_", "-") for d in providers.get(module, [])}
        if not dists & allowed:
            offenders.append((module, sorted(dists)))
    assert offenders == []
    assert "anthropic" not in json.loads(out.stdout) and "claudecode" not in json.loads(out.stdout)


def test_record_survives_an_early_driver_error_with_scalar_fields():
    """A real oauth run stopped at check_init (model_remapped) before the filter ran.

    The driver's document then held no filter record, and a scalar in its place
    made _record crash with AttributeError instead of reporting the error.
    """
    from sast.claude_review.agent import ClaudeReviewAgent
    document = {"status": "error", "error": {"code": "model_remapped", "message": "x"},
                "filter": "hard_rules", "cli": "oops", "pr": None, "review": [],
                "request_options": {"filter": "hard_rules", "auth": "oauth"}}
    review: dict = {}
    ClaudeReviewAgent._record(document, review)
    assert review["filter_summary"] is None and review["filter_calls"] == 0
    assert review["attempts"] == 0 and review["pr"] == {} and review["findings_raw"] == 0
    assert review["request_options"]["auth"] == "oauth"
