"""sast/pricing.py and the AI agents' usage_summary: tokens and cost reach Harbor's result fields."""

from __future__ import annotations

import pytest
from harbor.models.agent.context import AgentContext

from sast import pricing
from sast.claude_review.agent import ClaudeReviewAgent
from sast.codex_security.agent import CodexSecurityAgent

# Usage as a real Codex run on Daytona reported it (2026-10-14).
CODEX_USAGE = {"input_tokens": 100043, "cached_input_tokens": 70612, "cache_write_input_tokens": 29413,
               "output_tokens": 2718, "reasoning_output_tokens": 1296}


def test_openai_cost_splits_cached_and_cache_written_input():
    tokens, usd = pricing.openai_usage_cost("gpt-5.6-sol", CODEX_USAGE)
    assert tokens == {"input": 100043, "cache_read": 70612, "cache_write": 29413, "output": 2718}
    # 18 uncached x $4 + 70612 x $0.40 + 29413 x $5 + 2718 x $20, per 1M tokens
    assert usd == pytest.approx((18 * 4 + 70612 * 0.40 + 29413 * 4 * 1.25 + 2718 * 20) / 1e6)


def test_unknown_model_gives_no_estimate():
    assert pricing.openai_usage_cost("some-other-model", CODEX_USAGE)[1] is None
    assert pricing.cost("nope", 1, 1, 1, 1) is None


def test_codex_usage_reaches_the_context(tmp_path):
    agent = CodexSecurityAgent(logs_dir=tmp_path)
    meta = {"codex_security": {"model": "gpt-5.6-sol", "attempt_outcomes": [{"usage": CODEX_USAGE},
                                                                             {"usage": CODEX_USAGE}]}}
    context = AgentContext()
    agent._report_usage(context, meta)
    one = pricing.openai_usage_cost("gpt-5.6-sol", CODEX_USAGE)[1]
    assert context.n_input_tokens == 2 * 100043 and context.n_cache_tokens == 2 * 70612
    assert context.n_output_tokens == 2 * 2718 and context.cost_usd == pytest.approx(2 * one, abs=1e-6)
    assert "estimate" in meta["usage_summary"]["cost_source"]


def test_claude_cli_cost_plus_filter_estimate(tmp_path):
    agent = ClaudeReviewAgent(logs_dir=tmp_path)
    meta = {"claude_review": {
        "attempt_cost_usd": [0.10, 0.08],
        "model_usage": {"claude-opus-5-5": {"inputTokens": 2, "outputTokens": 2447, "cacheReadInputTokens": 10268,
                                            "cacheCreationInputTokens": 16331, "costUSD": 0.08}},
        "api_usage": {"claude-opus-5-5": {"input_tokens": 1000, "output_tokens": 100,
                                          "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}},
    }}
    context = AgentContext()
    agent._report_usage(context, meta)
    api = (1000 * 4 + 100 * 20) / 1e6
    assert context.cost_usd == pytest.approx(0.18 + api)
    assert context.n_input_tokens == 2 + 10268 + 16331 + 1000 and context.n_cache_tokens == 10268
    assert context.n_output_tokens == 2447 + 100


def test_no_usage_leaves_the_context_empty(tmp_path):
    context = AgentContext()
    CodexSecurityAgent(logs_dir=tmp_path)._report_usage(context, {"codex_security": {}})
    assert context.cost_usd is None and context.n_input_tokens is None


# ---- Harbor's -m -----------------------------------------------------------------------------------

@pytest.mark.parametrize("cls, model_name, option, expected, source", [
    (CodexSecurityAgent, "openai/gpt-5.6-terra", None, "gpt-5.6-terra", "harbor_model_name"),
    (CodexSecurityAgent, "gpt-5.6-luna", None, "gpt-5.6-luna", "harbor_model_name"),
    (CodexSecurityAgent, "anthropic/claude-opus-5-5", None, None, "default"),        # another provider: ignored
    (CodexSecurityAgent, "openai/gpt-5.6-terra", "gpt-5.6-sol", "gpt-5.6-sol", "option"),  # --ak model wins
    (ClaudeReviewAgent, "anthropic/claude-sonnet-5-5", None, "claude-sonnet-5-5", "harbor_model_name"),
    (ClaudeReviewAgent, "claude-haiku-5-5", None, "claude-haiku-5-5", "harbor_model_name"),
    (ClaudeReviewAgent, "openai/gpt-5.6-sol", None, None, "upstream_default"),
])
def test_harbor_m_is_used_only_for_the_tools_own_provider(tmp_path, cls, model_name, option, expected, source):
    kwargs = {"model": option} if option else {}
    agent = cls(logs_dir=tmp_path, model_name=model_name, **kwargs)
    assert agent.model_source() == source
    if expected:
        assert agent.review_model() == expected
    else:
        assert agent.review_model() not in (model_name, model_name.split("/")[-1])
