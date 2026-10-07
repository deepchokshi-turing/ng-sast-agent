"""CodeQL SARIF -> findings -> task SARIF, on recorded real CodeQL output.

Every fixture here is unedited output of the CodeQL CLI 2.27.1 bundle
(python-queries 1.8.11, suite python-security-extended.qls), recorded with the
agent's own commands (``sast.codeql.agent.create_command`` and
``analyze_command``, scope from each task's task.toml, threads=1, ram=1536) on a
copy of the task's ``environment/repo`` at /app/repo. tests/fixtures/README.md
says when and on what each one was recorded.

The tasks' own graders, ground truth and task.toml are vendored under
tests/fixtures/tasks/, so nothing here reads a folder outside this repository
and nothing is skipped on a fresh clone.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sast import cwe_map, sarif, task_config
from sast.codeql.normalise import cwes_of, normalise, repo_path, residual_risk
from sast.findings import TraceStep
from sast.scope import in_scope
from tests.conftest import SAMPLE_TASKS, fixture_json

TWINS = [f"task_{i}_{role}" for i in ("3920a8", "4da5ab", "bd9abf", "dc4b7a") for role in ("positive", "negative")]
SAMPLES = ["task_7f3a91", "smoke_eval", "smoke_web_eval"]
RECORDED = [*SAMPLES, *TWINS]
LOCAL = ["task_3920a8_positive", "task_4da5ab_positive"]


def recorded(task: str) -> dict:
    return fixture_json(f"codeql_2.27.1_{task}.json")


def local(task: str) -> dict:
    return fixture_json(f"codeql_2.27.1_threat-model-local_{task}.json")


def task_dir(task: str) -> Path:
    return SAMPLE_TASKS / task


def agent_sarif(task: str, document: dict) -> tuple[dict, dict, list]:
    """What the agent would write: normalise, keep the task scope, build."""
    settings = task_config.load(task_dir(task) / "environment")
    roots = list(settings.scanner_roots) or ["."]
    findings, counts = normalise(document)
    kept = [f for f in findings if in_scope(f.file, roots, list(settings.excluded_paths))]
    doc, stats = sarif.build(kept, tool_name="codeql", tool_version="2.27.1")
    return doc, {**counts, **stats}, kept


def grade(task: str, doc: dict, tmp_path: Path) -> dict:
    (tmp_path / "findings.sarif").write_text(json.dumps(doc))
    subprocess.run(
        [sys.executable, str(task_dir(task) / "tests" / "grade.py"), "--sarif", str(tmp_path / "findings.sarif"),
         "--truth", str(task_dir(task) / "tests" / "ground_truth.json"), "--out", str(tmp_path / "verifier")],
        check=True, capture_output=True,
    )
    return json.loads((tmp_path / "verifier" / "reward.json").read_text())


# ---- provenance -------------------------------------------------------------------

@pytest.mark.parametrize("name", [f"codeql_2.27.1_{t}.json" for t in RECORDED]
                         + [f"codeql_2.27.1_threat-model-local_{t}.json" for t in LOCAL])
def test_fixtures_are_codeql_2_27_1_security_extended(name):
    run = fixture_json(name)["runs"][0]
    driver = run["tool"]["driver"]
    assert (driver["name"], driver["semanticVersion"]) == ("CodeQL", "2.27.1")
    packs = {e["name"]: e.get("semanticVersion") for e in run["tool"].get("extensions", [])}
    assert packs["codeql/python-queries"].split("+")[0] == "1.8.11"
    assert len(driver["rules"]) == 50  # python-security-extended in this bundle
    assert run["invocations"][0]["executionSuccessful"] is True


# ---- CWEs, levels, risk ---------------------------------------------------------------

def rules() -> dict:
    return {r["id"]: r for r in recorded("task_4da5ab_positive")["runs"][0]["tool"]["driver"]["rules"]}


@pytest.mark.parametrize("rule_id, expected", [
    ("py/path-injection", ("CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99")),
    ("py/command-line-injection", ("CWE-78", "CWE-88")),
    ("py/clear-text-logging-sensitive-data", ("CWE-312", "CWE-359", "CWE-532")),
    ("py/code-injection", ("CWE-94", "CWE-95", "CWE-116")),
    ("py/insecure-protocol", ("CWE-327",)),
    ("py/summary/lines-of-code", ()),
])
def test_cwes_come_from_the_rule_tags_in_order(rule_id, expected):
    assert cwes_of(rules()[rule_id]) == expected


@pytest.mark.parametrize("rule_id, expected", [
    ("py/unsafe-deserialization", "high"),          # 9.8
    ("py/insecure-temporary-file", "high"),          # 7.0
    ("py/http-response-splitting", "medium"),        # 6.1
    ("py/samesite-none-cookie", "medium"),           # 4.0
    ("py/summary/lines-of-code", "medium"),          # no security-severity
])
def test_residual_risk_from_security_severity(rule_id, expected):
    assert residual_risk(rules()[rule_id]) == expected


def test_residual_risk_low_band():
    assert residual_risk({"properties": {"security-severity": "3.9"}}) == "low"


def test_plain_problem_from_real_output():
    findings, counts = normalise(recorded("task_4da5ab_positive"))
    (f,) = findings
    assert f.tool_rule_id == "py/insecure-protocol" and f.cwes == ("CWE-327",)
    assert (f.file, f.start_line, f.end_line) == ("src/pydantic_ai_mini/_compat/httpx2.py", 146, 146)
    assert f.level == "warning"  # from the rule's defaultConfiguration; the result has no level
    assert f.residual_risk == "high" and f.trace == ()
    assert counts["results_raw"] == 1 and counts["results_with_trace"] == 0
    assert counts["codeql_rules_run"] == 50 and counts["codeql_error_notifications"] == 0


@pytest.mark.parametrize("task", RECORDED)
def test_every_recorded_result_lands_in_the_repo(task):
    findings, counts = normalise(recorded(task))
    assert counts["results_outside_repo"] == 0
    assert counts["results_cwe_ambiguous"] == []
    assert len(findings) == counts["results_raw"]
    assert sum(counts["results_by_cwe_decision"].values()) == counts["results_raw"]
    for f in findings:
        assert not f.file.startswith(("/", "./", "file:", "%")) and f.start_line >= 1


# ---- paths --------------------------------------------------------------------------

@pytest.mark.parametrize("artifact, bases, expected", [
    ({"uri": "src/a.py", "uriBaseId": "%SRCROOT%"}, {}, "src/a.py"),
    ({"uri": "src/a.py", "uriBaseId": "%SRCROOT%"}, {"%SRCROOT%": "file:///app/repo/"}, "src/a.py"),
    ({"uri": "file:///app/repo/src/a%20b.py"}, {}, "src/a b.py"),
    ({"uri": "/app/repo/src/a.py"}, {}, "src/a.py"),
    ({"uri": "file:///usr/lib/python3/os.py"}, {}, None),
    ({"uri": "../etc/passwd", "uriBaseId": "%SRCROOT%"}, {}, None),
    ({"uri": "x.py", "uriBaseId": "OTHER"}, {}, None),
])
def test_paths_are_relative_to_the_repo(artifact, bases, expected):
    assert repo_path(artifact, bases) == expected


# ---- scope ----------------------------------------------------------------------

def test_scope_filter_on_real_output():
    findings, _ = normalise(local("task_4da5ab_positive"))
    files = sorted({f.file for f in findings})
    assert files == ["src/pydantic_ai_mini/_compat/httpx2.py", "src/pydantic_ai_mini/app.py",
                     "src/pydantic_ai_mini/llm.py"]
    kept = [f for f in findings if in_scope(f.file, ["src"], ["src/pydantic_ai_mini/_compat", "tests"])]
    assert sorted({f.file for f in kept}) == files[1:]
    assert [f for f in findings if in_scope(f.file, ["config"], [])] == []


# ---- traces and codeFlows ------------------------------------------------------------

def test_trace_is_the_first_thread_flow():
    findings, counts = normalise(local("task_4da5ab_positive"))
    by_file = {f.file: f for f in findings}
    app = by_file["src/pydantic_ai_mini/app.py"]
    assert app.tool_rule_id == "py/path-injection" and app.cwes[0] == "CWE-22"
    assert app.trace == (
        TraceStep("src/pydantic_ai_mini/app.py", 19, 19),
        TraceStep("src/pydantic_ai_mini/app.py", 19, 19),
        TraceStep("src/pydantic_ai_mini/app.py", 19, 19),
        TraceStep("src/pydantic_ai_mini/app.py", 20, 20),
    )
    # The last step is the sink, which is the reported location.
    assert (app.trace[-1].file, app.trace[-1].start_line) == (app.file, app.start_line)
    assert counts["results_with_trace"] == 2 and counts["trace_steps_outside_repo"] == 0
    assert by_file["src/pydantic_ai_mini/_compat/httpx2.py"].trace == ()


@pytest.mark.parametrize("task", LOCAL)
def test_code_flows_are_the_real_codeql_path(task):
    document = local(task)
    findings, _ = normalise(document)
    doc, _ = sarif.build(findings, tool_name="codeql", tool_version="2.27.1")
    raw = {(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"]): r
           for r in document["runs"][0]["results"]}
    flows = [r for r in doc["runs"][0]["results"] if "codeFlows" in r]
    assert flows
    for result in flows:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
        ours = result["codeFlows"][0]["threadFlows"][0]["locations"]
        theirs = raw[(uri, line)]["codeFlows"][0]["threadFlows"][0]["locations"]
        assert [(l["location"]["physicalLocation"]["artifactLocation"]["uri"],
                 l["location"]["physicalLocation"]["region"]["startLine"]) for l in ours] == \
               [(l["location"]["physicalLocation"]["artifactLocation"]["uri"],
                 l["location"]["physicalLocation"]["region"]["startLine"]) for l in theirs]
        roles = [(l.get("properties") or {}).get("role") for l in ours]
        assert roles[0] == "source" and roles[-1] == "sink" and set(roles[1:-1]) <= {None}
    # A plain problem gets no made-up flow.
    for r in doc["runs"][0]["results"]:
        if "codeFlows" not in r:
            uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            line = r["locations"][0]["physicalLocation"]["region"]["startLine"]
            assert "codeFlows" not in raw.get((uri, line), {})


@pytest.mark.parametrize("task", RECORDED)
def test_heuristics_stay_under_their_own_key(task):
    findings, _ = normalise(recorded(task))
    doc, _ = sarif.build(findings, tool_name="codeql", tool_version="2.27.1")
    for r in doc["runs"][0]["results"]:
        assert set(r["properties"]) == {"cwe", "toolRuleIds", "heuristics"}
        assert set(r["properties"]["heuristics"]) == {"controlStatus", "residualRisk", "recommendations", "version"}


# ---- errors ---------------------------------------------------------------------

@pytest.mark.parametrize("document, message", [
    ({}, "no runs"),
    ({"runs": []}, "no runs"),
    ({"runs": [{}]}, "no results list"),
    ({"runs": [{"results": [], "invocations": [{"executionSuccessful": False}]}]}, "did not complete"),
])
def test_unusable_documents_are_errors(document, message):
    with pytest.raises(ValueError, match=message):
        normalise(document)


# ---- the task's own grader on the recorded output ------------------------------------

#: Rewards the recorded CodeQL output gets from each task's grade.py. Recorded,
#: not targets: nothing was tuned to change them.
EXPECTED = {
    "task_7f3a91": {"reward": 0.0, "tp": 0, "fp": 0, "fn": 1, "results": 0},
    "task_3920a8_positive": {"reward": 0.0, "tp": 0, "fp": 0, "fn": 2, "results": 0},
    "task_4da5ab_positive": {"reward": 0.0, "tp": 0, "fp": 0, "fn": 2, "results": 0},
    "task_dc4b7a_positive": {"reward": 0.0, "tp": 0, "fp": 0, "fn": 2, "results": 0},
    "task_bd9abf_positive": {"reward": 0.0, "tp": 0, "fp": 0, "fn": 1, "results": 0},
    # The eval() input is the model's reply, which CodeQL does not model as a source.
    "smoke_eval": {"reward": 0.0, "tp": 0, "fp": 0, "fn": 1, "results": 0},
    # CodeQL's py/code-injection with its own path from the HTTP request to eval():
    # detection 0.35 + classification 0.05 + path 0.30, no controls or recommendations.
    "smoke_web_eval": {"reward": 0.7, "tp": 1, "fp": 0, "fn": 0, "results": 1},
    # A clean twin with nothing reported passes.
    "task_3920a8_negative": {"reward": 1.0, "tp": 0, "fp": 0, "fn": 0, "results": 0},
    "task_4da5ab_negative": {"reward": 1.0, "tp": 0, "fp": 0, "fn": 0, "results": 0},
    "task_dc4b7a_negative": {"reward": 1.0, "tp": 0, "fp": 0, "fn": 0, "results": 0},
    "task_bd9abf_negative": {"reward": 1.0, "tp": 0, "fp": 0, "fn": 0, "results": 0},
}


@pytest.mark.parametrize("task", RECORDED)
def test_grading_the_recorded_output(task, tmp_path):
    doc, stats, _ = agent_sarif(task, recorded(task))
    score = grade(task, doc, tmp_path)
    want = EXPECTED[task]
    assert (score["reward"], score["tp"], score["fp"], score["fn"], stats["results_emitted"]) == (
        want["reward"], want["tp"], want["fp"], want["fn"], want["results"])


# ---- the tool's own path earns path credit (smoke_web_eval) ------------------------

def test_http_parameter_to_eval_is_found_with_codeqls_path():
    findings, counts = normalise(recorded("smoke_web_eval"))
    (f,) = findings
    assert f.tool_rule_id == "py/code-injection" and f.cwes[0] == "CWE-94"
    assert (f.file, f.start_line) == ("src/calc_service/server.py", 8)
    # From the request in do_GET (line 12) to the eval (line 8).
    assert f.trace[0].start_line == 12 and f.trace[-1].start_line == 8
    assert counts["results_with_trace"] == 1


def test_model_output_is_not_a_codeql_source():
    findings, counts = normalise(recorded("smoke_eval"))
    assert findings == [] and counts["results_raw"] == 0


def test_grader_gives_path_credit_only_for_a_real_path(tmp_path):
    """Adapted from PR #2: the same finding with and without CodeQL's codeFlows."""
    doc, _, _ = agent_sarif("smoke_web_eval", recorded("smoke_web_eval"))
    (tmp_path / "with").mkdir()
    score = grade("smoke_web_eval", doc, tmp_path / "with")
    assert (score["tp"], score["fp"], score["fn"], score["path"]) == (1, 0, 0, 1.0)
    assert score["reward"] == 0.7
    for result in doc["runs"][0]["results"]:
        result.pop("codeFlows")
    (tmp_path / "without").mkdir()
    assert grade("smoke_web_eval", doc, tmp_path / "without")["reward"] == 0.4


def test_twins_get_identical_codeql_results():
    for task in ("4da5ab", "bd9abf", "dc4b7a", "3920a8"):
        pos, _ = normalise(recorded(f"task_{task}_positive"))
        neg, _ = normalise(recorded(f"task_{task}_negative"))
        assert [(f.tool_rule_id, f.file, f.start_line) for f in pos] == \
               [(f.tool_rule_id, f.file, f.start_line) for f in neg]


# ---- cwe-map-4: CodeQL tags are an unordered set ---------------------------------------

def _retargeted(rule_id: str, tags: list[str] | None = None) -> dict:
    """The recorded 4da5ab result, pointed at another rule of the same real run.

    No query in python-security-extended fired with these rules on the dataset,
    so the result is the real py/insecure-protocol one and only its rule
    reference changes. With ``tags`` the rule's CWE tags are replaced too.
    """
    import copy
    document = copy.deepcopy(recorded("task_4da5ab_positive"))
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    index = next(i for i, r in enumerate(rules) if r["id"] == rule_id)
    if tags is not None:
        rules[index]["properties"]["tags"] = ["security"] + [f"external/cwe/cwe-{t}" for t in tags]
    (result,) = run["results"]
    result["ruleId"] = rule_id
    result["ruleIndex"] = index
    result["rule"] = {"id": rule_id, "index": index}
    return document


@pytest.mark.parametrize("rule_id, rule", [
    # Tags 312, 359, 532: cwe-map-3 took 312 (unmapped) and dropped these.
    ("py/clear-text-logging-sensitive-data", "LLM02.SID.HIGH"),
    ("py/clear-text-storage-sensitive-data", "LLM02.SID.HIGH"),
    ("py/path-injection", "LLM03.EA.FUNCTIONALITY"),
    ("py/code-injection", "LLM03.EA.FUNCTIONALITY"),
    ("py/stack-trace-exposure", "LLM02.SID.MEDIUM"),
    ("py/insecure-protocol", None),
])
def test_codeql_tags_are_decided_as_an_unordered_set(rule_id, rule):
    findings, counts = normalise(_retargeted(rule_id))
    (finding,) = findings
    assert sarif.emitted_rules(findings) == [rule]
    if rule is not None:
        assert counts["results_by_cwe_decision"]["mapped"] == 1
        assert cwe_map.rule_for(finding.cwes) is not None
    else:
        assert counts["results_by_cwe_decision"]["unmapped"] == 1


def test_a_rule_whose_tags_span_two_families_is_dropped_and_counted():
    findings, counts = normalise(_retargeted("py/path-injection", tags=["200", "22"]))
    assert findings == []
    assert counts["results_by_cwe_decision"] == {"none": 0, "unmapped": 0, "mapped": 0, "ambiguous": 1}
    assert counts["results_cwe_ambiguous"] == [
        ["py/path-injection", ["CWE-22", "CWE-200"], "src/pydantic_ai_mini/_compat/httpx2.py", 146]]


def test_tag_order_does_not_change_the_result():
    forward = normalise(_retargeted("py/path-injection", tags=["532", "312", "359"]))[0]
    backward = normalise(_retargeted("py/path-injection", tags=["359", "312", "532"]))[0]
    assert [f.cwes for f in forward] == [f.cwes for f in backward] == [("CWE-359", "CWE-532", "CWE-312")]
