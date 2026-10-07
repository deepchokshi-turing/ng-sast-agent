import pytest

from sast.semgrep.normalise import cwes_of, normalise, repo_path
from tests.conftest import fixture_json


def test_eval_finding_from_real_semgrep_output():
    findings, counts = normalise(fixture_json("semgrep_1.179.0_smoke_eval.json"))
    by_rule = {f.tool_rule_id: f for f in findings}
    f = by_rule["python.lang.security.audit.eval-detected"]
    assert f.cwes == ("CWE-95",)
    assert (f.file, f.start_line, f.end_line) == ("src/calc_agent/agent.py", 8, 8)
    assert f.level in {"error", "warning", "note"}
    # The unrelated operator helper (shell=True), flagged by two rules.
    assert {x.file for x in findings} == {"src/calc_agent/agent.py", "src/calc_agent/maintenance.py"}
    assert counts["results_raw"] == 3 and counts["semgrep_errors"] == 0
    # The excluded thirdparty/ eval() and the build's .pyc files were not scanned.
    assert counts["files_scanned"] == 4


def test_only_security_category_is_kept():
    findings, counts = normalise(fixture_json("semgrep_1.179.0_task_7f3a91.json"))
    assert counts["results_by_category"] == {"best-practice": 1, "security": 1}
    assert [f.cwes for f in findings] == [("CWE-1236",)]


def test_no_results_is_fine_but_a_missing_list_is_not():
    findings, counts = normalise(fixture_json("semgrep_1.179.0_smoke_empty.json"))
    assert findings == [] and counts["results_raw"] == 0
    with pytest.raises(ValueError):
        normalise({"errors": []})


@pytest.mark.parametrize("raw, expected", [
    ("CWE-95: Eval Injection", ("CWE-95",)),
    (["CWE-89: SQL", "CWE-0089 dup", "cwe-200"], ("CWE-89", "CWE-200")),
    (None, ()),
    (42, ()),
])
def test_cwes_are_exact_ids_in_order(raw, expected):
    assert cwes_of({"cwe": raw}) == expected


@pytest.mark.parametrize("path, expected", [
    ("src/a.py", "src/a.py"),
    ("./src/a.py", "src/a.py"),
    ("/app/repo/src/a.py", "src/a.py"),
    ("src\\a.py", "src/a.py"),
])
def test_paths_are_repo_relative(path, expected):
    assert repo_path(path) == expected


def test_results_without_a_line_are_skipped():
    doc = {"results": [{"check_id": "x", "path": "a.py", "start": {}, "end": {},
                        "extra": {"metadata": {"category": "security", "cwe": "CWE-95"}}}]}
    findings, _ = normalise(doc)
    assert findings == []


# ---- dataflow traces (crafted fixture in Semgrep's documented JSON shape) -------

CRAFTED = "crafted_semgrep_dataflow_trace.json"


def crafted():
    findings, counts = normalise(fixture_json(CRAFTED))
    return {f.tool_rule_id: f for f in findings}, counts


def test_cliloc_source_intermediate_vars_and_call_sink_are_read():
    by_rule, counts = crafted()
    f = by_rule["crafted.taint.tenant-data-to-email"]
    assert f.has_trace
    assert (f.trace_source.file, f.trace_source.start_line, f.trace_source.content) == (
        "src/support_copilot/store.py", 21, "json.loads(path.read_text())")
    assert [(s.file, s.start_line, s.content) for s in f.trace_intermediate] == [
        ("src/support_copilot/store.py", 22, "tickets"), ("src/support_copilot/retrieval.py", 10, "rows")]
    # Every level of an interprocedural sink, outermost first.
    assert f.trace_sink_code == ("notify(rows)", "smtp.send_message(msg)")
    assert f.cwes == ("CWE-862", "CWE-200")
    assert counts["findings_with_dataflow_trace"] == 2


def test_clicall_source_is_the_innermost_location():
    by_rule, _ = crafted()
    src = by_rule["crafted.taint.pii-into-prompt"].trace_source
    assert (src.file, src.start_line, src.content) == ("src/support_copilot/users.py", 8, "USERS[uid]")


def test_no_trace_means_no_trace_fields():
    by_rule, _ = crafted()
    f = by_rule["crafted.pattern.eval"]
    assert not f.has_trace
    assert f.trace_source is None and f.trace_intermediate == () and f.trace_sink_code == ()
    assert "crafted.best-practice" not in by_rule


@pytest.mark.parametrize("trace", [
    "garbage", {}, {"taint_source": ["CliLoc", "bad"]}, {"taint_source": ["Unknown", []]},
    {"intermediate_vars": [{"location": {"path": "a.py", "start": {"line": 0}}}]},
    {"taint_source": ["CliCall", [None, [], None]]},
])
def test_malformed_traces_are_ignored_not_invented(trace):
    doc = {"results": [{"check_id": "x", "path": "a.py", "start": {"line": 3}, "end": {"line": 3},
                        "extra": {"severity": "ERROR", "dataflow_trace": trace,
                                  "metadata": {"category": "security", "cwe": "CWE-95"}}}]}
    (f,), _ = normalise(doc)
    assert not f.has_trace


@pytest.mark.parametrize("severity, impact, expected", [
    ("ERROR", "LOW", "high"),
    ("WARNING", "HIGH", "high"),
    ("WARNING", "MEDIUM", "medium"),
    ("INFO", "LOW", "low"),
    ("INFO", None, "low"),
    (None, None, "medium"),
])
def test_residual_risk_follows_severity_and_impact(severity, impact, expected):
    doc = {"results": [{"check_id": "x", "path": "a.py", "start": {"line": 3}, "end": {"line": 3},
                        "extra": {"severity": severity,
                                  "metadata": {"category": "security", "cwe": "CWE-95", "impact": impact}}}]}
    (f,), _ = normalise(doc)
    assert f.residual_risk == expected


def test_recorded_fixtures_have_no_trace():
    # Semgrep 1.179.0 without login printed no trace on the dev tasks.
    findings, counts = normalise(fixture_json("semgrep_1.179.0_smoke_eval.json"))
    assert counts["findings_with_dataflow_trace"] == 0 and not any(f.has_trace for f in findings)
    assert {f.residual_risk for f in findings} == {"high"}  # eval: impact HIGH; subprocess: ERROR
