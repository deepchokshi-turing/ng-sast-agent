import pytest

from sast import task_config
from sast.errors import ScannerError
from sast.semgrep.agent import SemgrepAgent
from tests.conftest import DEV_TASKS


def test_reads_the_reference_task():
    s = task_config.load(DEV_TASKS / "task_7f3a91" / "environment")
    assert s.scanner_roots == ("src", "config", "fixtures", "security_manifest.json", "pyproject.toml")
    assert s.excluded_paths == ("tests",)
    assert (s.cpus, s.memory_mb, s.agent_timeout_sec) == (1, 2048, 900.0)


def test_no_task_toml_means_defaults(tmp_path):
    s = task_config.load(tmp_path / "environment")
    assert s.source is None and s.scanner_roots == () and s.agent_timeout_sec is None
    assert task_config.load(None).notes


@pytest.mark.parametrize("roots", ['["/etc"]', '["../x"]', '["-rf"]', '"src"', '[""]'])
def test_unsafe_or_malformed_roots_are_refused(tmp_path, roots):
    (tmp_path / "task.toml").write_text(f"[metadata]\nscanner_roots = {roots}\n")
    with pytest.raises(ScannerError):
        task_config.load(tmp_path / "environment")


def test_options_split_strings_and_keep_unknown_keys(tmp_path):
    agent = SemgrepAgent(logs_dir=tmp_path, model_name="openai/gpt-5", scan_roots="src, lib",
                         exclude="tests", jobs="2", reasoning_effort="high", qc_pool="screen")
    assert agent.options.scan_roots == ["src", "lib"]
    assert agent.options.exclude == ["tests"]
    assert agent.options.jobs == 2
    assert agent.options.model_extra == {"qc_pool": "screen"}


def test_preflight_never_fails_a_job_on_an_unknown_key():
    SemgrepAgent.preflight({"something_new": "1"})


def test_preflight_still_rejects_a_bad_value():
    with pytest.raises(ValueError):
        SemgrepAgent.preflight({"jobs": "zero"})


def test_scan_budget_stops_before_harbors_timeout(tmp_path):
    agent = SemgrepAgent(logs_dir=tmp_path)
    assert agent._scan_budget(task_config.TaskSettings(agent_timeout_sec=900)) == 780
    assert agent._scan_budget(task_config.TaskSettings(agent_timeout_sec=100)) == 60
    assert agent._scan_budget(task_config.TaskSettings()) == 3600
    assert SemgrepAgent(logs_dir=tmp_path, scan_budget_sec=50)._scan_budget(task_config.TaskSettings()) == 50
