# util/deployed_eval.py
"""Pure helpers for Lab 09 Stage 2 (deployed evaluation): timing summaries and
the scorecard table. No I/O, no AWS calls: the notebook orchestrates; these are
the testable pieces."""

from __future__ import annotations
from statistics import mean


def _metric_value(results, evaluator_id):
    """First numeric value for evaluator_id in a session's graded results, else None."""
    for r in results:
        if r.get("evaluatorId") == evaluator_id and isinstance(r.get("value"), (int, float)):
            return r["value"]
    return None


def render_overview(sessions, graded, columns):
    """Full Stage-2 outcome table: one row per scenario, one column per evaluator,
    plus prod-only latency, closing with a mean row.

    Unlike the old single-column scorecard (which averaged away everything but a
    handful of headline metrics), this surfaces *every* evaluator grade_sessions
    produced for *every* scenario, so nothing the deployed round measured is dropped.

    Args:
        sessions: per-scenario dicts with 'scenario_name', 'latency_s', 'cold_start'.
        graded:   {scenario_name: [result dicts]} from grade_sessions; each result
                  carries 'evaluatorId' and 'value'.
        columns:  ordered list of (header, evaluator_id) — the evaluator columns to show.

    None values render as '-'; a cold-start latency is flagged with '*'.
    """
    metric_headers = [h for h, _ in columns]
    all_headers = metric_headers + ["Latency"]
    name_w = max([len("Scenario")] + [len(s["scenario_name"]) for s in sessions])
    col_w = [max(len(h), 7) for h in all_headers]
    total_w = name_w + sum(w + 1 for w in col_w)

    def row(name, values):
        cells = [f"{name:<{name_w}}"] + [f"{v:>{w + 1}}" for v, w in zip(values, col_w)]
        return "".join(cells)

    lines = [row("Scenario", all_headers), "-" * total_w]

    metric_vals = {h: [] for h in metric_headers}
    latencies = []
    any_cold = False
    for s in sessions:
        results = graded.get(s["scenario_name"], [])
        cells = []
        for h, eid in columns:
            v = _metric_value(results, eid)
            if v is not None:
                metric_vals[h].append(v)
            cells.append(_fmt(v))
        lat = s.get("latency_s")
        if isinstance(lat, (int, float)):
            latencies.append(lat)
        cold = s.get("cold_start")
        any_cold = any_cold or bool(cold)
        cells.append(_fmt_latency(lat, cold))
        lines.append(row(s["scenario_name"], cells))

    lines.append("-" * total_w)
    mean_cells = [_fmt(mean(metric_vals[h]) if metric_vals[h] else None) for h in metric_headers]
    mean_cells.append(_fmt_latency(mean(latencies) if latencies else None, False))
    lines.append(row("mean", mean_cells))

    if any_cold:
        lines.append("* cold start")
    return "\n".join(lines)


def _fmt(v):
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)


def _fmt_latency(v, cold_start):
    if not isinstance(v, (int, float)):
        return "-"
    return f"{v:.1f}s{'*' if cold_start else ''}"
