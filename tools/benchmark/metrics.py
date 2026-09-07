"""Benchmark metrics: per-trial aggregation into run/scenario summaries.

Pure statistics over :class:`tools.benchmark.models.TrialResult` lists —
verified success rate, false-positive rate, median/mean solve time and
actions, token/cost totals, failure categories, and per-scenario repeated-
trial stats (success probability, variance, stddev, 95% Wilson CI). A single
lucky trial is never presented as a reliable success: with one trial the CI
spans the whole range and summaries expose it.

No I/O — everything here is unit-testable in isolation.
"""

from __future__ import annotations

import math
import statistics
from datetime import datetime, timezone
from typing import Any

from tools.benchmark.models import (
    FailureCategory,
    RunSummary,
    ScenarioSummary,
    TrialResult,
    TrialStatus,
)

__all__ = [
    "compute_run_summary",
    "compute_scenario_summary",
    "wilson_interval",
    "is_false_positive",
    "is_false_negative",
    "run_summary_from_dict",
]


def is_false_positive(trial: TrialResult) -> bool:
    """Agent claimed success, oracle disagrees."""
    return trial.agent_claimed_success and not trial.oracle_verified_success


def is_false_negative(trial: TrialResult) -> bool:
    """Oracle verified success the agent did not claim (where determinable)."""
    return trial.oracle_verified_success and not trial.agent_claimed_success


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float | None, float | None]:
    """Wilson score interval for a binomial proportion (95% by default)."""
    if total <= 0:
        return None, None
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    spread = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return max(0.0, center - spread), min(1.0, center + spread)


def _median_or_none(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def _mean_or_none(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def compute_scenario_summary(
    trials: list[TrialResult], scenario_id: str, name: str = "", **meta: Any
) -> ScenarioSummary:
    """Aggregate one scenario's trials (repeated-trial aware)."""
    summary = ScenarioSummary(scenario_id=scenario_id, name=name)
    summary.tags = list(meta.get("tags", []) or [])
    summary.difficulty = str(meta.get("difficulty", "unknown") or "unknown")
    completed = [
        t for t in trials if t.status not in (TrialStatus.INFRASTRUCTURE_ERROR.value, TrialStatus.SKIPPED.value)
    ]
    summary.trials = len(trials)
    if not trials:
        return summary

    verified = sum(1 for t in trials if t.oracle_verified_success)
    claimed = sum(1 for t in trials if t.agent_claimed_success)
    summary.verified = verified
    summary.claimed = claimed
    summary.false_positives = sum(1 for t in trials if is_false_positive(t))
    summary.false_negatives = sum(1 for t in trials if is_false_negative(t))
    summary.timeouts = sum(1 for t in trials if t.status == TrialStatus.TIMEOUT.value)
    summary.infra_errors = sum(1 for t in trials if t.status == TrialStatus.INFRASTRUCTURE_ERROR.value)
    for t in trials:
        cat = t.failure_category
        if cat and cat != FailureCategory.UNKNOWN.value and not t.oracle_verified_success:
            summary.failure_categories[cat] = summary.failure_categories.get(cat, 0) + 1

    # Success probability over COMPLETED trials (infra errors say nothing
    # about exploit ability and would otherwise deflate the rate dishonestly).
    denom = len(completed) or len(trials)
    summary.success_probability = verified / denom if denom else 0.0
    summary.success_variance = summary.success_probability * (1 - summary.success_probability)
    summary.success_stddev = math.sqrt(summary.success_variance)
    low, high = wilson_interval(verified, denom)
    summary.ci95_low = low
    summary.ci95_high = high

    verified_trials = [t for t in trials if t.oracle_verified_success]
    durations = [t.duration_seconds for t in verified_trials if t.duration_seconds > 0]
    actions = [float(t.tool_calls) for t in verified_trials]
    model_calls = [float(t.model_calls) for t in verified_trials]
    summary.median_duration = _median_or_none(durations)
    summary.mean_duration = _mean_or_none(durations)
    summary.median_actions = _median_or_none(actions)
    summary.mean_actions = _mean_or_none(actions)
    summary.median_model_calls = _median_or_none(model_calls)
    summary.total_tokens = sum(t.total_tokens for t in trials)
    costs = [t.estimated_cost for t in trials if t.estimated_cost is not None]
    summary.estimated_cost = sum(costs) if costs else None
    return summary


def compute_run_summary(
    trials: list[TrialResult],
    *,
    run_id: str = "",
    suite: str = "",
    scenario_meta: dict[str, dict[str, Any]] | None = None,
) -> RunSummary:
    """Aggregate the full trial list into a :class:`RunSummary`."""
    meta = scenario_meta or {}
    summary = RunSummary(run_id=run_id, suite=suite, timestamp=datetime.now(timezone.utc).isoformat())
    summary.trials_total = len(trials)
    summary.trials_completed = sum(
        1 for t in trials if t.status not in (TrialStatus.INFRASTRUCTURE_ERROR.value, TrialStatus.SKIPPED.value)
    )
    verified = [t for t in trials if t.oracle_verified_success]
    summary.solved = len(verified)
    denom = summary.trials_completed or summary.trials_total
    summary.verified_success_rate = (len(verified) / denom) if denom else 0.0

    fps = sum(1 for t in trials if is_false_positive(t))
    fns = sum(1 for t in trials if is_false_negative(t))
    summary.false_positive_rate = (fps / denom) if denom else 0.0
    summary.false_negative_rate = (fns / denom) if denom else 0.0

    durations = [t.duration_seconds for t in verified if t.duration_seconds > 0]
    actions = [float(t.tool_calls) for t in verified]
    model_calls = [float(t.model_calls) for t in verified]
    summary.median_solve_time = _median_or_none(durations)
    summary.mean_solve_time = _mean_or_none(durations)
    summary.median_tool_actions = _median_or_none(actions)
    summary.mean_tool_actions = _mean_or_none(actions)
    summary.median_model_calls = _median_or_none(model_calls)
    summary.total_tokens = sum(t.total_tokens for t in trials)
    costs = [t.estimated_cost for t in trials if t.estimated_cost is not None]
    summary.estimated_cost = sum(costs) if costs else None
    summary.time_to_first_verified_success = min(
        (t.duration_seconds for t in verified if t.duration_seconds > 0), default=None
    )
    # Sandbox blocks are reported through two channels — the sandbox snapshot
    # (container-level ``blocked_events``) and trial telemetry
    # (``sandbox_blocked_actions``) — that observe the SAME enforcement point.
    # Summing both double-counts every block, so take the max per trial: when
    # the two disagree the larger one is the honest lower bound, and when they
    # agree (the common case) the block is counted exactly once.
    summary.sandbox_blocked_actions = sum(
        max(t.sandbox.blocked_events, t.telemetry.sandbox_blocked_actions) for t in trials
    )
    summary.infra_error_count = sum(1 for t in trials if t.status == TrialStatus.INFRASTRUCTURE_ERROR.value)
    summary.timeout_count = sum(1 for t in trials if t.status == TrialStatus.TIMEOUT.value)
    for t in trials:
        if t.oracle_verified_success:
            continue
        cat = t.failure_category
        if cat and cat != FailureCategory.UNKNOWN.value:
            summary.failure_categories[cat] = summary.failure_categories.get(cat, 0) + 1

    # Per-scenario rollup (stable order by scenario id).
    by_scenario: dict[str, list[TrialResult]] = {}
    for t in trials:
        by_scenario.setdefault(t.scenario_id, []).append(t)
    for scenario_id in sorted(by_scenario):
        m = dict(meta.get(scenario_id, {}))
        summary.scenarios.append(compute_scenario_summary(by_scenario[scenario_id], scenario_id, **m))
    return summary


def run_summary_from_dict(payload: dict[str, Any]) -> RunSummary:
    """Rebuild a RunSummary from its persisted dict form (scenario rows included)."""
    scenarios = [
        ScenarioSummary(
            **{
                **s,
                "tags": list(s.get("tags", []) or []),
                "failure_categories": dict(s.get("failure_categories", {}) or {}),
            }
        )
        for s in (payload.get("scenarios") or [])
        if isinstance(s, dict)
    ]
    known = set(RunSummary.__dataclass_fields__)
    return RunSummary(
        **{k: v for k, v in payload.items() if k in known and k != "scenarios"},
        scenarios=scenarios,
    )
