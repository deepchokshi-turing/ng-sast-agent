"""The promptfoo normaliser and the scoped guidance: only the header is read,
every location is checked, and nothing is guessed from prose."""

from __future__ import annotations

from pathlib import Path

import pytest

from sast import cwe_map, heuristics
from sast.findings import PATH_ROLES
from sast.promptfoo import guidance
from sast.promptfoo.normalise import TOOL_RULE_ID, normalise, parse_header
from tests.conftest import SAMPLE_TASKS
from tests.promptfoo_fakes import comment, header

LINES = {"src/app/agent.py": 40, "src/app/tools.py": 12, "security_manifest.json": 5}
ROOTS, EXCLUDES = ["src", "security_manifest.json"], ["tests"]


def run(comments, mode="scoped", **kwargs):
    return normalise(comments, mode=mode, line_counts=LINES, roots=ROOTS, excludes=EXCLUDES, **kwargs)


# ---------------------------------------------------------------- the header


def test_parse_header_reads_fields_path_and_prose():
    text = header(path=["src/app/agent.py:12 model_decision", "src/app/tools.py:3-5 sink"]) + "\n\nThe prose.\nMore."
    fields, steps, prose, problem = parse_header(text)
    assert problem is None
    assert fields["RULE"] == "LLM03.EA.FUNCTIONALITY" and fields["CWE"] == "CWE-95" and fields["RECS"].startswith("REC-")
    assert steps == ["src/app/agent.py:12 model_decision", "src/app/tools.py:3-5 sink"]
    assert prose == "The prose.\nMore."


@pytest.mark.parametrize("text", [
    "```\nRULE=LLM02.SID.HIGH; CWE=CWE-532\n```\n\nprose",
    "**RULE=LLM02.SID.HIGH; CWE=CWE-532**\n\nprose",
    "`RULE=LLM02.SID.HIGH; CWE=CWE-532`\n\nprose",
    "\n\n  RULE=LLM02.SID.HIGH ;CWE=CWE-532 ;\n\nprose",
])
def test_parse_header_tolerates_a_fence_or_emphasis(text):
    fields, _steps, prose, problem = parse_header(text)
    assert problem is None and fields["RULE"] == "LLM02.SID.HIGH" and fields["CWE"] == "CWE-532"
    assert prose == "prose"


@pytest.mark.parametrize("text, problem", [
    ("The tool is dangerous. RULE=LLM02.SID.HIGH", "missing"),
    ("Some intro\nRULE=LLM02.SID.HIGH", "missing"),
    ("RULE=LLM02.SID.HIGH; RULE=LLM03.EA.AUTONOMY", "malformed"),
    ("RULE=LLM02.SID.HIGH; SEVERITY=high", "malformed"),
    ("RULE=LLM02.SID.HIGH; CWE CWE-532", "malformed"),
    ("", "missing"),
])
def test_parse_header_problems(text, problem):
    fields, steps, prose, got = parse_header(text)
    assert fields is None and steps == [] and got == problem and prose == text.strip()


# ---------------------------------------------------------------- normalise


def test_a_valid_scoped_finding_carries_every_field():
    head = header(rule="llm03.ea.functionality", cwe="CWE-95, cwe-94", control="Partial", risk="HIGH",
                  recs="REC-NARROW-TYPED-TOOLS, REC-POLICY-GATE, REC-NARROW-TYPED-TOOLS",
                  path=["- src/app/agent.py:12 model_decision", "src/app/tools.py:3-5 sink"])
    (finding,), counts = run([comment("src/app/tools.py", 5, start=3, head=head)])
    assert finding.task_rule == "LLM03.EA.FUNCTIONALITY" and finding.tool_rule_id == TOOL_RULE_ID
    assert finding.cwes == ("CWE-95", "CWE-94")
    assert (finding.file, finding.start_line, finding.end_line) == ("src/app/tools.py", 3, 5)
    assert finding.control_status == "partial" and finding.assessed_residual_risk == "high"
    assert finding.recommendations == ("REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE")
    assert [(s.file, s.start_line, s.end_line, s.role) for s in finding.trace] == [
        ("src/app/agent.py", 12, 12, "model_decision"), ("src/app/tools.py", 3, 5, "sink")]
    assert finding.message == "The tool evaluates model output."
    assert finding.level == "error" and finding.residual_risk == "high"
    assert dict(finding.extra)["severity"] == "high" and dict(finding.extra)["header"].startswith("RULE=")
    assert counts["headers"] == {"valid": 1, "missing": 0, "malformed": 0}
    assert counts["assessed_fields"] == {"cwe": 1, "path": 1, "path_steps": 2, "control_status": 1,
                                         "residual_risk": 1, "recommendations": 1}
    assert counts["dropped_no_task_rule_count"] == 0


def test_a_partial_header_scores_only_what_it_gives():
    (finding,), counts = run([comment("src/app/agent.py", 8, head="RULE=LLM03.EA.AUTONOMY")])
    assert finding.task_rule == "LLM03.EA.AUTONOMY" and finding.cwes == () and finding.trace == ()
    assert finding.control_status is None and finding.assessed_residual_risk is None and finding.recommendations == ()
    assert counts["assessed_fields"]["path"] == 0


def test_bad_values_are_dropped_and_counted():
    head = header(cwe="CWE-95,XSS,CWE-0", control="mostly", risk="extreme", recs="REC-MADE-UP,REC-POLICY-GATE",
                  path=["src/app/agent.py:12 model_decision", "src/app/agent.py:99 sink", "tests/t.py:1 source",
                        "outside.py:1 source", "src/app/agent.py:4 attacker", "just words"])
    (finding,), counts = run([comment("src/app/agent.py", 8, head=head)])
    assert finding.cwes == ("CWE-95",) and counts["cwes_rejected"] == ["XSS", "CWE-0"]
    assert finding.control_status is None and finding.assessed_residual_risk is None
    assert counts["assessed_values_rejected"] == ["CONTROL=mostly", "RISK=extreme"]
    assert finding.recommendations == ("REC-POLICY-GATE",) and counts["recommendations_rejected"] == ["REC-MADE-UP"]
    assert [(s.start_line, s.role) for s in finding.trace] == [(12, "model_decision"), (4, None)]
    assert counts["path_roles_rejected"] == ["attacker"]
    assert [row[0] for row in counts["path_steps_dropped"]] == [
        "line outside the file", "out of scope", "out of scope", "not <file>:<line> <role>"]


def test_no_valid_rule_no_finding():
    comments = [
        comment("src/app/agent.py", 8, head=header(rule="LLM09.MADE.UP")),
        comment("src/app/agent.py", 9, "No header, but the prose says LLM02.SID.HIGH and CWE-532."),
        comment("src/app/agent.py", 10, head="RULE=LLM02.SID.HIGH; RULE=LLM02.SID.HIGH"),
    ]
    findings, counts = run(comments)
    assert findings == []
    assert counts["dropped_no_task_rule_count"] == 3
    assert [row[4] for row in counts["dropped_no_task_rule"]] == ["RULE not a task ruleId", "no header", "no header"]
    assert counts["rule_ids_rejected"] == ["LLM09.MADE.UP"]
    assert counts["headers"] == {"valid": 1, "missing": 1, "malformed": 1}


def test_a_rule_outside_the_contract_is_rejected():
    findings, counts = run([comment("src/app/agent.py", 8, head=header(rule="LLM03.EA.AUTONOMY"))],
                           rule_ids=("LLM02.SID.HIGH", "LLM02.SID.MEDIUM"))
    assert findings == [] and counts["rule_ids_rejected"] == ["LLM03.EA.AUTONOMY"]


def test_stock_mode_emits_nothing_and_lists_everything():
    comments = [comment("src/app/agent.py", 8, head=header()), comment("src/app/tools.py", 2, severity="medium")]
    findings, counts = run(comments, mode="stock")
    assert findings == []
    assert counts["dropped_no_task_rule_count"] == 2
    assert {row[4] for row in counts["dropped_no_task_rule"]} == {"stock mode"}
    assert counts["tool_findings_count"] == 2 and counts["tool_findings"][1][:4] == ["src/app/tools.py", 2, 2, "medium"]
    assert counts["headers"]["missing"] == 2


@pytest.mark.parametrize("item, reason", [
    (comment(None, None), "no file"),
    (comment("src/app/agent.py", None), "no line"),
    (comment("src/app/agent.py", 41), "line outside the file"),
    (comment("src/app/agent.py", 5, start=9), "line outside the file"),
    (comment("src/app/agent.py", 0), "line outside the file"),
    (comment("src/app/notes.bin", 1), "not a text file of the scope"),
])
def test_bad_locations_are_dropped(item, reason):
    findings, counts = run([dict(item, finding=header() + "\n\nx")])
    assert findings == [] and counts["dropped_bad_location"][0][0] == reason


def test_out_of_scope_and_absolute_paths():
    comments = [comment("tests/test_agent.py", 1, head=header()), comment("/opt/sast/scope/src/app/agent.py", 8,
                                                                          head=header())]
    findings, counts = run(comments, scope_dir="/opt/sast/scope")
    assert counts["dropped_out_of_scope"] == [["tests/test_agent.py", 1]]
    assert [f.file for f in findings] == ["src/app/agent.py"]


def test_all_clear_comments_are_counted_not_reported():
    findings, counts = run([comment(None, None, "No issues found.", severity="none")])
    assert findings == [] and counts["comments_all_clear"] == 1 and counts["tool_findings_count"] == 0


@pytest.mark.parametrize("severity, level, risk", [("critical", "error", "high"), ("medium", "warning", "medium"),
                                                   ("low", "note", "low"), (None, "note", "medium")])
def test_levels(severity, level, risk):
    item = comment("src/app/agent.py", 8, head=header())
    item["severity"] = severity
    (finding,), _ = run([item])
    assert finding.level == level and finding.residual_risk == risk


# ---------------------------------------------------------------- the guidance


def test_guidance_comes_from_the_task_contract():
    instruction = (SAMPLE_TASKS / "smoke_eval" / "instruction.md").read_text()
    contract, source = guidance.contract_for(instruction)
    assert source == "task_instruction"
    text = guidance.guidance_text(contract)
    for rule in cwe_map.TASK_RULES:
        assert rule in text
    for rec in heuristics.CATALOGUE:
        assert f"- {rec}: " in text
    for role in PATH_ROLES:
        assert role in text
    assert "security_manifest.json" in text
    assert "RULE=<ruleId>; CWE=<CWE ids>; CONTROL=<control status>; RISK=<residual risk>; RECS=" in text
    # The example in the text parses as a valid header.
    example = text.split("Example:\n\n", 1)[1].split("\n\nRecommendation catalogue:", 1)[0]
    fields, steps, prose, problem = parse_header(example)
    assert problem is None and fields["RULE"] == "LLM03.EA.FUNCTIONALITY" and len(steps) == 2 and prose


def test_guidance_without_a_contract_uses_the_builtin_tables():
    contract, source = guidance.contract_for("Scan the repository.")
    assert source == "builtin" and [r for r, _ in contract.rules] == list(cwe_map.TASK_RULES)
    assert "REC-POLICY-GATE" in guidance.guidance_text(contract)


def test_every_dataset_style_instruction_parses():
    """The sample tasks with a contract all give one; the ruleIds are the profile's."""
    for path in sorted(Path(SAMPLE_TASKS).glob("*/instruction.md")):
        contract, source = guidance.contract_for(path.read_text())
        if source == "task_instruction":
            assert set(r for r, _ in contract.rules) <= set(cwe_map.TASK_RULES)
