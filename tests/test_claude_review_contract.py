"""The audit fixes in the Claude review agent: the scoped prompt built from the
task's output contract (A2), the filter exclusions it drops, any well-formed CWE
accepted in scoped mode (A9), and what the SARIF's ``runs[0].properties`` says
about dropped and re-mapped findings (F-B2). Tool calls and the scope copy (A8)
are in the metadata. No model is called."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import re

import pytest

from sast.claude_review import contract
from sast.claude_review.agent import FILTER_EXCLUSIONS_DROPPED, FILTER_INSTRUCTIONS_FILE, SCAN_INSTRUCTIONS_FILE
from tests.claude_review_fakes import finding
from tests.conftest import FIXTURES, ROOT, SAMPLE_TASKS
from tests.test_claude_review_agent import (  # noqa: F401  (api_key is a fixture)
    WORK,
    FakeSandbox,
    api_key,
    driver_document,
    run_agent,
    sarif_of,
)

CONTRACT_TEXT = (FIXTURES / "claude_review" / "contract_instruction.md").read_text(encoding="utf-8")
#: The published tasks next to this repository, when they are there (their ground truths are checked too).
HARBOR_TASKS = ROOT.parent / "harbor-tasks"


def _leak_scan():
    spec = importlib.util.spec_from_file_location("leak_scan", ROOT / "tools" / "leak_scan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------- parsing the contract


def test_the_contract_is_read_from_the_instruction():
    parsed = contract.parse(CONTRACT_TEXT)
    assert parsed is not None
    described = parsed.describe()
    assert described["rule_ids"] == ["LLM02.SID.MEDIUM", "LLM02.SID.HIGH", "LLM03.EA.FUNCTIONALITY",
                                     "LLM03.EA.PERMISSIONS", "LLM03.EA.AUTONOMY"]
    assert described["recommendation_ids"][0] == "REC-AUTHZ-BEFORE-RETRIEVAL" and len(described["recommendation_ids"]) == 13
    # In the instruction's own order.
    assert described["roles"] == ["source", "model_decision", "context_assembly", "model_consumption",
                                  "control_point", "root_cause", "sink"]
    assert described["control_statuses"] == ["none", "partial", "complete"]
    assert described["residual_risks"] == ["low", "medium", "high"]
    assert dict(parsed.rules)["LLM03.EA.PERMISSIONS"] == \
        "A tool's credential or authorisation scope exceeds what its operation requires"


def test_a_hard_wrapped_instruction_is_read_too():
    parsed = contract.parse((SAMPLE_TASKS / "smoke_eval" / "instruction.md").read_text(encoding="utf-8"))
    assert parsed is not None and len(parsed.rules) == 5 and len(parsed.recommendations) == 13
    assert parsed.roles[0] == "source" and parsed.roles[-1] == "sink" and len(parsed.roles) == 7


@pytest.mark.parametrize("text", [
    None, "",
    "This task is run by a security scanner agent. This file is a placeholder.",
    # Tables but no field vocabularies.
    "| `LLM02.SID.HIGH` | x |\n| `REC-POLICY-GATE` | y |\n",
])
def test_no_contract_gives_none(text):
    assert contract.parse(text) is None


def test_the_generated_text_has_the_upstream_format_and_every_part_of_the_contract():
    parsed = contract.parse(CONTRACT_TEXT)
    text = contract.scan_instructions(parsed)
    headers = re.findall(r"^\*\*(.+):\*\*$", text, re.MULTILINE)
    assert len(headers) == 3 and all(line.startswith(("**", "- ")) for line in text.splitlines() if line)
    # The fixed preamble: the manifest first, and the six fields.
    assert "security_manifest.json at the repository root first" in text
    for field in ('"rule_id"', '"cwe"', '"path"', '"control_status"', '"residual_risk"', '"recommendation_ids"'):
        assert f"- {field}:" in text
    # The vocabularies and tables come from the contract.
    for rule, definition in parsed.rules:
        assert f"- {rule}: {definition}" in text and f'"{rule}"' in text
    assert re.findall(r"^- (REC-[A-Z-]+):", text, re.MULTILINE) == [r for r, _ in parsed.recommendations]
    roles = re.search(r"a role, which is one of (.+)\.$", text, re.MULTILINE).group(1)
    assert re.findall(r'"([a-z_]+)"', roles) == list(parsed.roles)
    assert '"none", "partial" or "complete"' in text and '"low", "medium" or "high"' in text


def test_the_generated_text_leaks_no_label():
    """No six-word run shared with any ground truth (the sample tasks, and the published ones when present)."""
    leak_scan = _leak_scan()
    texts = [contract.scan_instructions(contract.parse(CONTRACT_TEXT)),
             contract.scan_instructions(contract.parse((SAMPLE_TASKS / "smoke_eval" / "instruction.md").read_text()))]
    truths = list(SAMPLE_TASKS.glob("*/tests/ground_truth.json"))
    if HARBOR_TASKS.is_dir():
        truths += list(HARBOR_TASKS.glob("*/tests/ground_truth.json"))
    assert truths
    for text in texts:
        ours = leak_scan.shingles(leak_scan.words(text), leak_scan.SHINGLE)
        for truth in truths:
            for _, value in leak_scan.truth_strings(json.loads(truth.read_text(encoding="utf-8"))):
                overlap = ours & leak_scan.shingles(leak_scan.words(value), leak_scan.SHINGLE)
                assert not overlap, (truth, value, overlap)
        for name in (p.name for p in SAMPLE_TASKS.iterdir()):
            assert name not in text


# ---------------------------------------------------------------- the agent uses it


def test_scoped_mode_builds_its_prompt_from_the_task_instruction(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, instruction=CONTRACT_TEXT, mode="scoped")
    asyncio.run(go())
    expected = contract.scan_instructions(contract.parse(CONTRACT_TEXT))
    assert sandbox.request["scan_instructions"] == expected
    assert sandbox.request["filter_instructions"] == FILTER_INSTRUCTIONS_FILE.read_text()
    review = context.metadata["claude_review"]
    assert review["scan_instructions_source"] == "task_instruction"
    assert review["scan_instructions_sha256"] == hashlib.sha256(expected.encode()).hexdigest()
    assert review["contract"]["rule_ids"][0] == "LLM02.SID.MEDIUM"
    assert all(v == [] for v in review["contract_ids_not_accepted"].values())
    # Disclosed: the scoped filter text leaves out two upstream hard exclusions.
    assert [e["upstream_number"] for e in review["filter_exclusions_dropped"]] == [7, 14]
    assert review["filter_exclusions_dropped_apply"] is True
    props = sarif_of(sandbox)["runs"][0]["properties"]["sastAgent"]
    assert props["scanInstructionsSource"] == "task_instruction" and props["filterExclusionsDropped"] == [7, 14]


def test_scoped_mode_falls_back_to_the_bundled_text_without_a_contract(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, instruction="This file is a placeholder.", mode="scoped",
                               filter="hard_rules")
    asyncio.run(go())
    assert sandbox.request["scan_instructions"] == SCAN_INSTRUCTIONS_FILE.read_text()
    review = context.metadata["claude_review"]
    assert review["scan_instructions_source"] == "bundled" and review["contract"] is None
    assert review["scan_instructions_sha256"] == hashlib.sha256(SCAN_INSTRUCTIONS_FILE.read_bytes()).hexdigest()
    # The hard-rule filter never reads the filter text.
    assert len(review["filter_exclusions_dropped"]) == 2 and review["filter_exclusions_dropped_apply"] is False


def test_stock_mode_uses_no_instructions_and_drops_no_exclusion(tmp_path, api_key):
    sandbox = FakeSandbox()
    _, context, go = run_agent(tmp_path, sandbox, instruction=CONTRACT_TEXT)
    asyncio.run(go())
    review = context.metadata["claude_review"]
    assert sandbox.request["scan_instructions"] is None
    assert review["scan_instructions_source"] is None and review["filter_exclusions_dropped"] == []


def test_the_dropped_exclusions_are_the_upstream_ones():
    source = (FIXTURES / "ccsr_0c6a49f" / "claudecode" / "claude_api_client.py").read_text()
    ours = FILTER_INSTRUCTIONS_FILE.read_text()
    for entry in FILTER_EXCLUSIONS_DROPPED:
        assert f"{entry['upstream_number']}. {entry['text']}" in source
        assert entry["text"] not in ours


# ---------------------------------------------------------------- A9: any well-formed CWE


def test_scoped_mode_accepts_any_well_formed_cwe(tmp_path, api_key):
    kept = [
        # CWE-1289 and CWE-184 were rejected by the old allow-list; the grader accepts them.
        finding("src/calc_agent/agent.py", 8, category="x", cwe=["CWE-1289", "cwe 184"], rule_id="LLM03.EA.FUNCTIONALITY"),
        finding("src/calc_agent/llm.py", 2, category="y", cwe=["CWE-0", "nonsense", "CWE-359"],
                rule_id="LLM02.SID.MEDIUM"),
    ]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, context, go = run_agent(tmp_path, sandbox, mode="scoped")
    asyncio.run(go())
    meta = context.metadata
    assert meta["cwes_rejected"] == ["CWE-0", "nonsense"] and meta["cwes_rejected_count"] == 2
    assert meta["cwe_source"] == {"model": 2}
    cwes = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: (r["ruleId"], r["properties"]["cwe"])
            for r in sarif_of(sandbox)["runs"][0]["results"]}
    assert cwes["src/calc_agent/agent.py"][0] == "LLM03.EA.FUNCTIONALITY"
    assert sorted(cwes["src/calc_agent/agent.py"][1]) == ["CWE-1289", "CWE-184"]
    assert cwes["src/calc_agent/llm.py"] == ("LLM02.SID.MEDIUM", ["CWE-359"])


# ---------------------------------------------------------------- F-B2: drops and re-mapping in the SARIF


def test_the_sarif_records_what_was_dropped_remapped_and_filtered(tmp_path, api_key):
    kept = [
        finding("src/calc_agent/agent.py", 8, category="eval_injection"),                        # re-mapped
        finding("src/calc_agent/llm.py", 2, category="authorization_bypass"),                    # re-mapped to SID
        finding("src/calc_agent/maintenance.py", 5, category="code_execution_sandbox_escape"),  # not in the map
        finding("tests/test_x.py", 1, category="eval_injection"),                                # out of scope
        finding("src/calc_agent/agent.py", 9999, category="eval_injection"),                     # bad location
    ]
    excluded = [{"finding": finding("src/calc_agent/llm.py", 3, category="open_redirect"), "filter_stage": "hard_rules",
                 "exclusion_reason": "Open redirect vulnerability (not high impact)"}]
    sandbox = FakeSandbox(document=driver_document(kept, excluded=excluded))
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    document = sarif_of(sandbox)
    results = document["runs"][0]["results"]
    assert len(results) == 2  # unchanged by the account below
    props = document["runs"][0]["properties"]["sastAgent"]
    dropped = props["dropped"]
    assert dropped["categoryNotInMap"] == {"count": 1, "items": [["code_execution_sandbox_escape", 1]]}
    assert dropped["unmappedCwe"]["count"] == 1
    assert dropped["unmappedCwe"]["items"][0][0] == "ccsr/code_execution_sandbox_escape"
    assert dropped["outOfScope"]["count"] == 1 and dropped["badLocation"]["count"] == 1
    remapped = {r["location"]: (r["category"], r["cweSource"], r["ruleId"]) for r in props["remapped"]["items"]}
    assert remapped["src/calc_agent/llm.py:2"] == ("authorization_bypass", "table", "LLM02.SID.MEDIUM")
    assert remapped["src/calc_agent/agent.py:8"][2] == "LLM03.EA.FUNCTIONALITY"
    (exclusion,) = props["upstreamFilterExclusions"]["items"]
    assert exclusion == {"stage": "hard_rules", "reason": "Open redirect vulnerability (not high impact)",
                         "category": "open_redirect", "location": "src/calc_agent/llm.py:3"}
    assert props["upstreamFilterExclusions"]["count"] == 1
    assert props["mode"] == "stock" and props["filterExclusionsDropped"] == []


def test_the_models_own_rule_is_not_counted_as_remapped(tmp_path, api_key):
    kept = [finding("src/calc_agent/agent.py", 8, category="x", cwe=["CWE-95"], rule_id="LLM03.EA.AUTONOMY")]
    sandbox = FakeSandbox(document=driver_document(kept))
    _, _, go = run_agent(tmp_path, sandbox, mode="scoped")
    asyncio.run(go())
    props = sarif_of(sandbox)["runs"][0]["properties"]["sastAgent"]
    assert props["remapped"] == {"count": 0, "items": []}


# ---------------------------------------------------------------- A8: scope copy and tool calls


def test_the_review_runs_in_a_scope_copy_and_its_tool_calls_are_kept(tmp_path, api_key):
    document = driver_document()
    document["scope_copy"] = {"dir": f"{WORK}/scope", "files": 4, "manifest": True}
    document["cli"].update({
        "tool_uses_count": 2,
        "tool_uses": [{"attempt": 1, "tool": "Read", "file_path": "security_manifest.json"},
                      {"attempt": 1, "tool": "Read", "file_path": "/app/repo/README.md",
                       "outside_scope": "file_path outside the review directory"}],
        "tool_uses_outside_scope": [{"attempt": 1, "tool": "Read", "file_path": "/app/repo/README.md",
                                     "outside_scope": "file_path outside the review directory"}],
    })
    sandbox = FakeSandbox(document=document)
    _, context, go = run_agent(tmp_path, sandbox)
    asyncio.run(go())
    assert sandbox.request["scope_dir"] == f"{WORK}/scope"
    review = context.metadata["claude_review"]
    assert review["scope_copy"]["files"] == 4
    assert review["tool_uses_count"] == 2 and len(review["tool_uses"]) == 2
    assert review["tool_uses_outside_scope_count"] == 1
    assert review["tool_uses_outside_scope"][0]["file_path"] == "/app/repo/README.md"
    # Every record is also in the kept driver result.
    assert "claude_review.json" in context.metadata["artifacts_saved"]
