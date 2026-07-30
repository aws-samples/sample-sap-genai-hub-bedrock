# util/tests/test_deployed_eval.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from util.deployed_eval import (
    tokens_to_cost, DEFAULT_RATES, summarize_timing, render_scorecard,
)


def test_tokens_to_cost_basic():
    rates = {"m": {"input": 1.0, "output": 2.0}}  # USD per 1k
    # 1000 in @ $1/1k + 500 out @ $2/1k = 1.0 + 1.0 = 2.0
    assert tokens_to_cost(1000, 500, "m", rates) == 2.0


def test_tokens_to_cost_missing_data_returns_none():
    rates = {"m": {"input": 1.0, "output": 2.0}}
    assert tokens_to_cost(None, 500, "m", rates) is None
    assert tokens_to_cost(1000, None, "m", rates) is None


def test_tokens_to_cost_unknown_model_returns_none():
    assert tokens_to_cost(1000, 500, "unknown-model", {"m": {"input": 1.0, "output": 2.0}}) is None


def test_default_rates_present():
    assert "anthropic--claude-4.5-sonnet" in DEFAULT_RATES


def test_summarize_timing():
    items = [
        {"latency_s": 2.0, "cold_start": True},
        {"latency_s": 4.0, "cold_start": False},
        {"latency_s": 6.0, "cold_start": False},
    ]
    s = summarize_timing(items)
    assert s["count"] == 3
    assert s["mean_s"] == 4.0
    assert s["max_s"] == 6.0
    assert s["cold_starts"] == 1


def test_render_scorecard_basic():
    scorecard = {"Correctness": 1.0, "latency_s": 5.0, "cost_usd": 0.02}
    out = render_scorecard(scorecard, ["Correctness", "latency_s", "cost_usd"])
    assert "Correctness" in out and "1.00" in out and "5.00" in out


def test_render_scorecard_none_value():
    # A None metric must render as "-" on ITS OWN row, not be fabricated as $0.00. We target the
    # metric rows (not the separator line, which always contains dashes) to actually prove it.
    scorecard = {"Correctness": 1.0, "cost_usd": None}
    out = render_scorecard(scorecard, ["Correctness", "cost_usd"])
    cost_line = next(l for l in out.splitlines() if l.startswith("cost_usd"))
    correctness_line = next(l for l in out.splitlines() if l.startswith("Correctness"))
    assert cost_line.strip().endswith("-")  # None cost renders as a dash on its row
    assert "1.00" in correctness_line  # a real metric still renders its value


if __name__ == "__main__":
    import traceback
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failures += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    sys.exit(1 if failures else 0)
