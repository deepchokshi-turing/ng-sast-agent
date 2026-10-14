"""List prices for the model APIs the AI agents call, to estimate a run's cost.

Used only where a tool reports tokens but no money: the Codex review (OpenAI
usage) and the Claude review's direct filter calls (Anthropic SDK usage). The
Claude Code CLI reports its own cost, which is used as is.

Prices are USD per million tokens, first-party list prices as of PRICES_AS_OF.
A model not in the table gives no estimate (None), never a guess. Update the
table when prices change; every estimate records PRICES_AS_OF next to it.
"""

from __future__ import annotations

from typing import Any

PRICES_AS_OF = "2026-10-14"

#: model -> (input, cached input read, output) USD per 1M tokens. Cache writes
#: cost CACHE_WRITE_FACTOR x input (5-minute writes on both APIs).
PRICES: dict[str, tuple[float, float, float]] = {
    # Anthropic (platform.claude.com pricing).
    "claude-fable-5-1": (10.00, 0.25, 50.00),
    "claude-opus-5-5": (4.00, 0.20, 20.00),
    "claude-sonnet-5-5": (2.00, 0.20, 10.00),
    "claude-haiku-5-5": (0.10, 0.01, 0.50),
    # OpenAI (developers.openai.com model page; promotional rate through 2026-11-21).
    "gpt-5.6-sol": (4.00, 0.40, 20.00),
}
CACHE_WRITE_FACTOR = 1.25

PER_TOKEN = 1_000_000


def _int(value: Any) -> int:
    return value if isinstance(value, int) and value > 0 else 0


def cost(model: str | None, uncached_input: int, cache_read: int, cache_write: int, output: int) -> float | None:
    """USD for one model's tokens, or None when the model has no price."""
    price = PRICES.get(str(model or ""))
    if price is None:
        return None
    inp, cached, out = price
    total = (_int(uncached_input) * inp + _int(cache_read) * cached
             + _int(cache_write) * inp * CACHE_WRITE_FACTOR + _int(output) * out)
    return round(total / PER_TOKEN, 6)


def anthropic_usage_cost(by_model: dict[str, dict[str, Any]] | None) -> tuple[dict[str, int], float | None]:
    """Token totals and estimated cost of Anthropic SDK usage, per model as the
    Claude review driver counts it ({model: {input_tokens, output_tokens,
    cache_creation_input_tokens, cache_read_input_tokens}}). Cost is None when
    any model with tokens has no price."""
    totals = {"input": 0, "cache_read": 0, "cache_write": 0, "output": 0}
    usd: float | None = 0.0
    for model, row in (by_model or {}).items():
        if not isinstance(row, dict):
            continue
        part = {"input": _int(row.get("input_tokens")), "cache_read": _int(row.get("cache_read_input_tokens")),
                "cache_write": _int(row.get("cache_creation_input_tokens")), "output": _int(row.get("output_tokens"))}
        for k, v in part.items():
            totals[k] += v
        if any(part.values()):
            c = cost(model, part["input"], part["cache_read"], part["cache_write"], part["output"])
            usd = None if c is None or usd is None else usd + c
    return totals, (round(usd, 6) if usd is not None else None)


def openai_usage_cost(model: str | None, usage: dict[str, Any] | None) -> tuple[dict[str, int], float | None]:
    """Token totals and estimated cost of one OpenAI usage record (Codex's
    turn usage: input_tokens includes the cached and cache-written tokens;
    output_tokens includes reasoning tokens)."""
    usage = usage if isinstance(usage, dict) else {}
    total_in = _int(usage.get("input_tokens"))
    cache_read = _int(usage.get("cached_input_tokens"))
    cache_write = _int(usage.get("cache_write_input_tokens"))
    output = _int(usage.get("output_tokens"))
    uncached = max(total_in - cache_read - cache_write, 0)
    totals = {"input": total_in, "cache_read": cache_read, "cache_write": cache_write, "output": output}
    if not (total_in or output):
        return totals, None
    return totals, cost(model, uncached, cache_read, cache_write, output)
