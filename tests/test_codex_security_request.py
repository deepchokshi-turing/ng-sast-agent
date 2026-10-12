"""sast/codex_security/request.py: the prompts, the output schemas and the
config the agent sends. No model is called."""

from __future__ import annotations

import importlib.util
import json

import pytest

from sast import cwe_map, heuristics
from sast.claude_review import contract
from sast.codex_security import request
from sast.findings import CONTROL_STATUSES, PATH_ROLES, RISK_LEVELS
from tests.conftest import FIXTURES, ROOT, SAMPLE_TASKS

CONTRACT_TEXT = (FIXTURES / "claude_review" / "contract_instruction.md").read_text(encoding="utf-8")
HARBOR_TASKS = ROOT.parent / "harbor-tasks"


def _objects(schema):
    """Every object schema inside ``schema``."""
    if isinstance(schema, dict):
        if schema.get("type") == "object":
            yield schema
        for value in schema.values():
            yield from _objects(value)
    elif isinstance(schema, list):
        for value in schema:
            yield from _objects(value)


@pytest.mark.parametrize("mode", ["stock", "scoped"])
def test_schemas_follow_strict_structured_outputs(mode):
    schema = request.output_schema(mode, contract.parse(CONTRACT_TEXT) if mode == "scoped" else None)
    objects = list(_objects(schema))
    assert objects
    for obj in objects:
        assert obj["additionalProperties"] is False
        assert obj["required"] == list(obj["properties"])
    text = json.dumps(schema)
    # Only keywords the strict mode accepts everywhere: no pattern, minimum or format.
    assert not any(k in text for k in ('"pattern"', '"minimum"', '"maximum"', '"format"', '"oneOf"'))


def test_the_stock_schema_is_codex_review_shape_plus_category_and_cwe():
    finding = request.output_schema("stock")["properties"]["findings"]["items"]["properties"]
    assert list(finding) == ["title", "body", "confidence_score", "priority", "category", "cwe", "code_location"]
    location = finding["code_location"]["properties"]
    assert list(location) == ["absolute_file_path", "line_range"]
    assert list(location["line_range"]["properties"]) == ["start", "end"]


def test_the_scoped_schema_takes_its_vocabularies_from_the_contract():
    parsed = contract.parse(CONTRACT_TEXT)
    finding = request.output_schema("scoped", parsed)["properties"]["findings"]["items"]["properties"]
    assert finding["rule_id"]["enum"] == [r for r, _ in parsed.rules] + [None]
    assert finding["path"]["items"]["properties"]["role"]["enum"] == list(parsed.roles) + [None]
    assert finding["control_status"]["enum"] == list(parsed.control_statuses) + [None]
    assert finding["residual_risk"]["enum"] == list(parsed.residual_risks) + [None]
    assert finding["recommendation_ids"]["items"]["enum"] == [r for r, _ in parsed.recommendations]
    with pytest.raises(ValueError):
        request.output_schema("scoped", None)


def test_the_fallback_contract_is_what_the_normaliser_accepts():
    fallback = request.fallback_contract()
    assert [r for r, _ in fallback.rules] == list(cwe_map.TASK_RULES)
    assert [r for r, _ in fallback.recommendations] == list(heuristics.CATALOGUE)
    assert (fallback.roles, fallback.control_statuses, fallback.residual_risks) == (
        PATH_ROLES, CONTROL_STATUSES, RISK_LEVELS)


def test_the_scoped_prompt_is_the_stock_prompt_plus_the_contract():
    parsed = contract.parse(CONTRACT_TEXT)
    text = request.scoped_prompt(parsed)
    assert text.startswith(request.stock_prompt())
    assert "security_manifest.json" in text and "REC-POLICY-GATE" in text and '"rule_id"' in text
    # The Claude review's sentence about upstream's free-text field is not sent to Codex.
    assert request.UPSTREAM_ONLY_SENTENCE.strip() in contract.scan_instructions(parsed)
    assert request.UPSTREAM_ONLY_SENTENCE.strip() not in text


def test_the_stock_prompt_is_task_neutral():
    text = request.stock_prompt()
    assert "LLM0" not in text and "REC-" not in text and "security_manifest" not in text
    assert "absolute_file_path" in text and '"cwe"' in text and "review_completed" in text


def _leak_scan():
    spec = importlib.util.spec_from_file_location("leak_scan", ROOT / "tools" / "leak_scan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_prompts_leak_no_label():
    """No six-word run shared with any ground truth (the sample tasks, and the published ones when present)."""
    leak_scan = _leak_scan()
    texts = [request.stock_prompt(), request.scoped_prompt(contract.parse(CONTRACT_TEXT)),
             request.scoped_prompt(request.fallback_contract())]
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


def test_the_read_only_config_denies_the_private_paths():
    text = request.config_toml("gpt-5.6-sol", "read-only", None, deny=["/app/repo", "/opt/sast/secret-codex"])
    lines = text.splitlines()
    assert lines[0] == 'model = "gpt-5.6-sol"' and "model_reasoning_effort" not in text
    for line in ('approval_policy = "never"', 'web_search = "disabled"', "project_doc_max_bytes = 0",
                 "project_root_markers = []", 'cli_auth_credentials_store = "file"',
                 'default_permissions = "sast-review"', "[permissions.sast-review]", 'extends = ":read-only"',
                 "[permissions.sast-review.filesystem]", '"/app/repo" = "deny"', '"/opt/sast/secret-codex" = "deny"',
                 "[skills.bundled]", 'persistence = "none"'):
        assert line in lines, line
    assert "sandbox_mode" not in text and "mcp_servers" not in text
    for feature in request.FEATURES_OFF:
        assert f"{feature} = false" in lines


def test_the_container_config_turns_codex_sandbox_off_and_has_no_profile():
    text = request.config_toml("m", "container", "xhigh", deny=["/app/repo"])
    assert 'sandbox_mode = "danger-full-access"' in text and "permissions" not in text
    assert 'model_reasoning_effort = "xhigh"' in text
    with pytest.raises(ValueError):
        request.config_toml("m", "none")


def test_toml_strings_are_escaped():
    text = request.config_toml('we"ird\\model', "read-only", None, deny=['/a b/"c"'])
    assert 'model = "we\\"ird\\\\model"' in text and '"/a b/\\"c\\"" = "deny"' in text
