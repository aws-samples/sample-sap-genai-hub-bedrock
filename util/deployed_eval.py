# util/deployed_eval.py
"""Pure helpers for Lab 09 Stage 2 (deployed evaluation): timing summaries and
the scorecard table. No I/O, no AWS calls: the notebook orchestrates; these are
the testable pieces."""

from __future__ import annotations
from statistics import mean, median


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
