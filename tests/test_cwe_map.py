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
    assert cwe_map.VERSION == "cwe-map-4"
    assert cwe_map.SID_MEDIUM in cwe_map.RULE_DESCRIPTIONS


# --- cwe-map-4: CWEs with no primary (CodeQL tags, SonarQube facet) ---------

import itertools
import random

import pytest


@pytest.mark.parametrize("cwes, decision, family, ordered", [
    ((), "none", None, ()),
    (("CWE-327",), "unmapped", None, ("CWE-327",)),
    (("CWE-327", "CWE-20"), "unmapped", None, ("CWE-20", "CWE-327")),
    # py/clear-text-logging-sensitive-data: 312 is unmapped and ignored.
    (("CWE-312", "CWE-359", "CWE-532"), "mapped", cwe_map.SID_HIGH, ("CWE-359", "CWE-532", "CWE-312")),
    # py/clear-text-storage-sensitive-data
    (("CWE-312", "CWE-315", "CWE-359"), "mapped", cwe_map.SID_HIGH, ("CWE-359", "CWE-312", "CWE-315")),
    # py/path-injection: 36 and 99 unmapped, the rest FUNCTIONALITY.
    (("CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99"), "mapped", cwe_map.EA_FUNCTIONALITY,
     ("CWE-22", "CWE-23", "CWE-73", "CWE-36", "CWE-99")),
    # py/code-injection
    (("CWE-94", "CWE-95", "CWE-116"), "mapped", cwe_map.EA_FUNCTIONALITY, ("CWE-94", "CWE-95", "CWE-116")),
    # python:S5332: 319 is unmapped, so 200 decides.
    (("CWE-319", "CWE-200"), "mapped", cwe_map.SID_HIGH, ("CWE-200", "CWE-319")),
    # Two families.
    (("CWE-200", "CWE-22"), "ambiguous", None, ("CWE-22", "CWE-200")),
    (("CWE-250", "CWE-78", "CWE-1"), "ambiguous", None, ("CWE-1", "CWE-78", "CWE-250")),
    # Duplicates collapse.
    (("CWE-95", "CWE-95"), "mapped", cwe_map.EA_FUNCTIONALITY, ("CWE-95",)),
])
def test_decide_unordered(cwes, decision, family, ordered):
    assert cwe_map.decide_unordered(cwes) == (decision, family, ordered)


def test_decide_unordered_reordered_tuple_gives_the_decided_rule():
    # sarif.py maps by the first CWE, and task_rule still sees every CWE.
    _, family, ordered = cwe_map.decide_unordered(("CWE-312", "CWE-359", "CWE-532"))
    assert cwe_map.rule_for(ordered) == family
    assert cwe_map.task_rule(ordered) == cwe_map.SID_HIGH
    _, _, ordered = cwe_map.decide_unordered(("CWE-319", "CWE-200"))
    assert cwe_map.task_rule(ordered) == cwe_map.SID_HIGH  # S5332: 319 is a boundary CWE
    _, _, ordered = cwe_map.decide_unordered(("CWE-209", "CWE-497"))  # py/stack-trace-exposure
    assert cwe_map.task_rule(ordered) == cwe_map.SID_MEDIUM
    for cwes in [("CWE-327", "CWE-20"), ("CWE-1",)]:
        _, _, ordered = cwe_map.decide_unordered(cwes)
        assert cwe_map.rule_for(ordered) is None


def test_decide_unordered_never_depends_on_input_order():
    table = sorted(cwe_map.CWE_MAP, key=lambda c: int(c.split("-")[1]))
    pool = table + ["CWE-20", "CWE-36", "CWE-99", "CWE-116", "CWE-312", "CWE-319", "CWE-327", "CWE-497"]
    rng = random.Random(40)
    sets = [tuple(rng.sample(pool, rng.randint(1, 5))) for _ in range(300)]
    sets += [("CWE-312", "CWE-359", "CWE-532"), ("CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99"),
             ("CWE-200", "CWE-22", "CWE-319"), ("CWE-250", "CWE-532", "CWE-20")]
    for cwes in sets:
        expected = cwe_map.decide_unordered(cwes)
        perms = itertools.permutations(cwes) if len(cwes) <= 5 else [cwes]
        for perm in perms:
            assert cwe_map.decide_unordered(perm) == expected, perm
            assert cwe_map.decide_unordered(list(perm) + [perm[0]]) == expected  # duplicates too
        decision, family, ordered = expected
        assert sorted(ordered) == sorted(set(cwes))
        if decision == "mapped":
            assert cwe_map.rule_for(ordered) == family


def test_decide_unordered_accepts_any_iterable():
    assert cwe_map.decide_unordered(iter(["CWE-95"]))[0] == "mapped"
    assert cwe_map.decide_unordered(None) == ("none", None, ())
    assert cwe_map.decide_unordered({"CWE-532", "CWE-312"})[1] == cwe_map.SID_HIGH
