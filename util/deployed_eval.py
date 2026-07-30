# util/deployed_eval.py
"""Pure helpers for Lab 09 Stage 2 (deployed evaluation): cost math, timing
summaries, and the before->after payoff table. No I/O, no AWS calls: the
notebook orchestrates; these are the testable pieces."""

from __future__ import annotations
from statistics import mean, median

# TODO: Customize these to your models/region. USD per 1,000 tokens.
DEFAULT_RATES: dict[str, dict] = {
    "anthropic--claude-4.5-sonnet": {"input": 0.003, "output": 0.015},
    "amazon--nova-pro": {"input": 0.0008, "output": 0.0032},
    "amazon--nova-lite": {"input": 0.00006, "output": 0.00024},
}


def tokens_to_cost(input_tokens, output_tokens, model_id, rate_table=DEFAULT_RATES):
    """USD cost for one task, or None if data/model rate is missing."""
    if input_tokens is None or output_tokens is None:
        return None
    rate = rate_table.get(model_id)
    if not rate:
        return None
    return (input_tokens / 1000.0) * rate["input"] + (output_tokens / 1000.0) * rate["output"]


def summarize_timing(items):
    """Aggregate a list of {'latency_s': float, 'cold_start': bool} timing dicts."""
    latencies = [i["latency_s"] for i in items]
    if not latencies:
        return {"count": 0, "mean_s": None, "p50_s": None, "max_s": None, "cold_starts": 0}
    return {
        "count": len(latencies),
        "mean_s": mean(latencies),
        "p50_s": median(latencies),
        "max_s": max(latencies),
        "cold_starts": sum(1 for i in items if i.get("cold_start")),
    }


def render_scorecard(scorecard, metric_keys):
    """Printable single-column scorecard for one prod round. None -> '-'."""
    lines = [f"{'Metric':<24}{'Improved (prod)':>18}", "-" * 42]
    for k in metric_keys:
        lines.append(f"{k:<24}{_fmt(scorecard.get(k)):>18}")
    return "\n".join(lines)


def _fmt(v):
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)
