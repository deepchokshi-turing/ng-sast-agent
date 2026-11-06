"""The skill's findings.json plus the side file -> Finding objects (sast/cloudflare_audit/normalise.py)."""

from __future__ import annotations

import json

from sast.cloudflare_audit.normalise import normalise
from tests.cloudflare_audit_fakes import annotation, confirmed, needs_validation, rejected, step_record

COUNTS = {"src/calc_agent/agent.py": 20, "src/calc_agent/maintenance.py": 12, "src/calc_agent/llm.py": 6,
          "tests/test_x.py": 5}
ROOTS, EXCLUDES = ["src"], ["tests"]


def run(records, annotations, mode="scoped", include=True):
    return normalise(records, annotations, mode=mode, include_needs_validation=include, line_counts=COUNTS,
                     roots=ROOTS, excludes=EXCLUDES)


ASSESSED = {"rule_id": "LLM03.EA.FUNCTIONALITY", "location": {"file": "src/calc_agent/agent.py", "start_line": 8,
                                                             "end_line": 9},
            "trace_roles": ["model_decision", "root_cause", "sink"], "control_status": "none",
            "residual_risk": "high", "recommendation_ids": ["REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE"]}


def test_scoped_record_uses_every_annotation_field_and_keeps_the_fix_verbatim():
    findings, counts = run([confirmed()], {"findings": [annotation(**ASSESSED)]})
    (f,) = findings
    assert (f.file, f.start_line, f.end_line, f.task_rule, f.cwes) == (
        "src/calc_agent/agent.py", 8, 9, "LLM03.EA.FUNCTIONALITY", ("CWE-95",))
    assert [(s.start_line, s.role) for s in f.trace] == [(12, "model_decision"), (10, "root_cause"), (8, "sink")]
    assert (f.control_status, f.assessed_residual_risk, f.recommendations) == (
        "none", "high", ("REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE"))
    assert f.level == "error" and f.residual_risk == "high"
    extra = dict(f.extra)
    assert extra["recommendation"] == "Parse arithmetic with ast and allow only numeric nodes."
    assert json.loads(extra["remediationCodeChanges"]) == [{"file_name": "src/calc_agent/agent.py",
                                                            "fixed_code": "safe_eval(expr)"}]
    assert extra["verdict"] == "confirmed" and extra["locationSource"] == "annotation"
    assert extra["traceKinds"] == "entrypoint,propagation,sink" and extra["exploitScenario"].startswith("a prompt")
    assert counts["rule_source"] == {"annotation": 1} and counts["location_source"] == {"annotation": 1}


def test_default_roles_and_location_come_from_the_trace_kinds():
    findings, counts = run([confirmed()], {"findings": [annotation()]}, mode="stock")
    (f,) = findings
    assert [s.role for s in f.trace] == ["source", None, "sink"]
    assert (f.file, f.start_line, f.task_rule, f.control_status, f.recommendations) == (
        "src/calc_agent/agent.py", 8, None, None, ())
    assert counts["location_source"] == {"trace_sink": 1}


def test_stock_mode_ignores_contract_fields():
    findings, _ = run([confirmed()], {"findings": [annotation(**ASSESSED)]}, mode="stock")
    (f,) = findings
    assert f.task_rule is None and f.control_status is None and [s.role for s in f.trace] == ["source", None, "sink"]


def test_verdicts_rejected_never_needs_validation_by_option():
    records = [confirmed(), needs_validation(), rejected()]
    ann = {"findings": [annotation(), annotation("calc/maint", cwe=["CWE-862"], rule_id="LLM03.EA.AUTONOMY")]}
    findings, counts = run(records, ann)
    assert [dict(f.extra)["verdict"] for f in findings] == ["confirmed", "needs_validation"]
    nv = findings[1]
    assert nv.task_rule == "LLM03.EA.AUTONOMY" and nv.level == "warning" and nv.residual_risk == "medium"
    assert json.loads(dict(nv.extra)["blockers"]) == ["needs a deployment fact"]
    assert counts["records_by_verdict"] == {"confirmed": 1, "needs_validation": 1, "rejected": 1}
    assert counts["records_skipped"] == {"rejected": 1}
    findings, counts = run(records, ann, include=False)
    assert len(findings) == 1 and counts["records_skipped"] == {"needs_validation": 1, "rejected": 1}


def test_two_annotations_for_one_fingerprint_give_two_findings():
    ann = {"findings": [annotation(**ASSESSED),
                        annotation(**dict(ASSESSED, rule_id="LLM02.SID.HIGH", cwe=["CWE-200"]))]}
    findings, _ = run([confirmed()], ann)
    assert sorted(f.task_rule for f in findings) == ["LLM02.SID.HIGH", "LLM03.EA.FUNCTIONALITY"]


def test_bad_steps_roles_values_and_ids_are_dropped_and_counted():
    trace = [step_record("entrypoint", "src/calc_agent/agent.py", 12), step_record("teleport", "x", 1),
             step_record("propagation", "src/calc_agent/agent.py", 999), step_record("sink", "src/calc_agent/agent.py", 8)]
    ann = annotation(rule_id="LLM09.MADE.UP", cwe=["CWE-95", "nope"], trace_roles=["sink", None, None, "sink"],
                     control_status="mostly", residual_risk="severe", recommendation_ids=["REC-NOT-REAL"],
                     location={"file": "tests/test_x.py", "start_line": 1})
    findings, counts = run([confirmed(trace=trace)], {"findings": [ann]})
    (f,) = findings
    assert [(s.start_line, s.role) for s in f.trace] == [(12, "source"), (8, "sink")]
    assert f.task_rule is None and f.cwes == ("CWE-95",)
    assert counts["path_steps_dropped_count"] == 2 and counts["trace_roles_rejected"] == ["entrypoint:sink"]
    assert counts["assessed_values_rejected"] == ["mostly", "severe"]
    assert counts["recommendations_rejected"] == ["REC-NOT-REAL"] and counts["cwes_rejected"] == ["nope"]
    assert counts["rule_ids_rejected"] == ["LLM09.MADE.UP"] and counts["dropped_out_of_scope_count"] == 1
    assert counts["location_source"] == {"trace_sink": 1}


def test_a_trace_that_loses_its_ends_is_dropped_whole_and_the_record_without_location_too():
    trace = [step_record("entrypoint", "src/calc_agent/agent.py", 12),
             step_record("sink", "src/calc_agent/agent.py", 500)]
    findings, counts = run([confirmed(trace=trace)], {"findings": [annotation()]})
    assert findings == [] and counts["traces_dropped_count"] == 1 and counts["dropped_bad_location_count"] == 1


def test_the_annotation_location_keeps_a_record_whose_trace_is_unusable():
    trace = [step_record("propagation", "src/calc_agent/agent.py", 10)]
    ann = annotation(**ASSESSED)
    findings, counts = run([confirmed(trace=trace)], {"findings": [ann]})
    (f,) = findings
    assert f.trace == () and f.start_line == 8 and counts["traces_dropped_count"] == 1


def test_without_annotations_nothing_is_guessed():
    findings, counts = run([confirmed()], None)
    (f,) = findings
    assert f.cwes == () and f.task_rule is None and f.control_status is None
    assert counts["annotations_missing"] is True and counts["records_without_annotation"] == ["calc/eval"]
    _, counts = run([confirmed()], {"findings": [annotation("someone/else")]})
    assert counts["annotations_orphaned"] == ["someone/else"]


def test_malformed_records_and_an_unusable_side_file_are_counted():
    findings, counts = run(["text", {"verdict": "confirmed"}, {"verdict": "maybe", "fingerprint": "a"}],
                           {"findings": "nope"})
    assert findings == [] and counts["dropped_records_count"] == 3 and counts["annotations_unusable"] is True


def test_end_line_out_of_the_file_is_replaced_by_the_start():
    ann = annotation(**dict(ASSESSED, location={"file": "src/calc_agent/agent.py", "start_line": 8,
                                                "end_line": 400}))
    (f,), counts = run([confirmed()], {"findings": [ann]})
    assert f.end_line == 8 and counts["end_line_replaced"] == 1
