import re
from pathlib import Path

from sast import cwe_map
from tests.conftest import SAMPLE_TASKS

TASK_RULE_IDS = {"LLM02.SID.HIGH", "LLM02.SID.MEDIUM", "LLM03.EA.FUNCTIONALITY",
                 "LLM03.EA.PERMISSIONS", "LLM03.EA.AUTONOMY"}


def test_every_entry_is_a_task_rule_id_with_a_reason():
    for cwe, (rule, why) in cwe_map.CWE_MAP.items():
        assert re.fullmatch(r"CWE-[1-9]\d*", cwe), cwe
        assert rule in TASK_RULE_IDS, (cwe, rule)
        assert rule in cwe_map.RULE_DESCRIPTIONS
        assert len(why) > 10, cwe


def test_rule_ids_are_the_ones_the_instruction_defines():
    instruction = (SAMPLE_TASKS / "task_7f3a91" / "instruction.md").read_text()
    for rule in {r for r, _ in cwe_map.CWE_MAP.values()}:
        assert f"`{rule}`" in instruction


def test_the_rules_primary_cwe_decides():
    assert cwe_map.rule_for(("CWE-95",)) == cwe_map.EA_FUNCTIONALITY
    assert cwe_map.rule_for(("CWE-89", "CWE-200")) == cwe_map.EA_FUNCTIONALITY
    assert cwe_map.rule_for(("CWE-200", "CWE-89")) == cwe_map.SID_HIGH
    # An out-of-scope primary weakness is not reported through a secondary CWE.
    assert cwe_map.rule_for(("CWE-79", "CWE-532")) is None


def test_unmapped_and_empty():
    assert cwe_map.rule_for(("CWE-1236",)) is None  # CSV formula injection: out of scope
    assert cwe_map.rule_for(()) is None


def test_secrets_in_code_and_weak_transport_are_not_disclosure_flows():
    # The instruction's LLM02 is data reaching model-visible state or crossing a
    # trust boundary; a hard-coded key or weak TLS is neither.
    for cwe in ("CWE-798", "CWE-319", "CWE-312", "CWE-522", "CWE-611", "CWE-922", "CWE-548"):
        assert cwe_map.rule_for((cwe,)) is None, cwe


def test_authorisation_on_data_is_disclosure():
    # The instruction's LLM02: data reaches model-visible state "without controls
    # that preserve its authorisation boundary".
    for cwe in ("CWE-285", "CWE-639", "CWE-862", "CWE-863"):
        assert cwe_map.rule_for((cwe,)) == cwe_map.SID_HIGH


def test_llm02_is_medium_unless_a_boundary_is_shown():
    assert cwe_map.task_rule(("CWE-200",)) == cwe_map.SID_MEDIUM
    assert cwe_map.task_rule(("CWE-862",)) == cwe_map.SID_MEDIUM
    for cwe in ("CWE-201", "CWE-532", "CWE-359"):
        assert cwe_map.task_rule((cwe,)) == cwe_map.SID_HIGH, cwe
    # 918 and 319 raise an LLM02 result as secondary CWEs, but never make one.
    assert cwe_map.task_rule(("CWE-200", "CWE-918")) == cwe_map.SID_HIGH
    assert cwe_map.task_rule(("CWE-200", "CWE-319")) == cwe_map.SID_HIGH
    assert cwe_map.task_rule(("CWE-918",)) == cwe_map.EA_FUNCTIONALITY
    assert cwe_map.task_rule(("CWE-319",)) is None
    # Other families ignore the boundary.
    assert cwe_map.task_rule(("CWE-95", "CWE-532")) == cwe_map.EA_FUNCTIONALITY
    assert cwe_map.task_rule(("CWE-250",)) == cwe_map.EA_PERMISSIONS
    assert cwe_map.VERSION == "cwe-map-3"
    assert cwe_map.SID_MEDIUM in cwe_map.RULE_DESCRIPTIONS
