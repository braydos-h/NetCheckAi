"""Benchmark baselines and regression detection.

A benchmark run can be saved as the baseline (``--save-baseline``); later runs
compare against it (``--check-regression``). Findings are classified as
``hard`` (CI must fail — exit 1), ``warning``, ``improvement``, or
``unchanged``. Thresholds come from ``benchmark.regression`` config:

- success-rate drop > ``success_rate_tolerance``  → hard
- false-positive-rate rise > ``false_positive_tolerance`` → hard
- median solve time rise > ``median_time_tolerance`` → warning
- median tool actions rise > ``tool_actions_tolerance`` → warning
- estimated cost rise > ``cost_tolerance`` → warning
- a scenario solved in the baseline but now unsolved → hard

Fail-closed: a missing/unreadable baseline is a hard failure.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.benchmark.models import RunSummary

__all__ = [
    "RegressionFinding",
    "RegressionThresholds",
    "RegressionResult",
    "save_baseline",
    "load_baseline",
    "compare_to_baseline",
    "compare_summaries_payload",
    "DEFAULT_BASELINE_PATH",
    "thresholds_from_config",
]

DEFAULT_BASELINE_PATH = "reports/benchmarks/baseline.json"


@dataclass
class RegressionThresholds:
    """Configurable regression tolerances (fractions unless noted)."""

    success_rate_tolerance: float = 0.02
    false_positive_tolerance: float = 0.01
    median_time_tolerance: float = 0.20  # relative
    tool_actions_tolerance: float = 0.30  # relative
    cost_tolerance: float = 0.30  # relative


@dataclass
class RegressionFinding:
    """One comparison finding."""

    severity: str  # hard | warning | improvement | unchanged
    metric: str
    detail: str
    baseline: Any = None
    current: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "metric": self.metric,
            "detail": self.detail,
            "baseline": self.baseline,
            "current": self.current,
        }


@dataclass
class RegressionResult:
    """Full comparison result."""

    passed: bool = True
    baseline_run_id: str = ""
    findings: list[RegressionFinding] = field(default_factory=list)

    @property
    def hard_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "hard")

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")

    @property
    def improvement_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "improvement")

    def messages(self) -> list[str]:
        out = [
            f"regression check {'PASSED' if self.passed else 'FAILED'}: "
            f"{self.hard_count} hard, {self.warning_count} warning(s), "
            f"{self.improvement_count} improvement(s) vs baseline {self.baseline_run_id or '?'}"
        ]
        for f in self.findings:
            marker = {"hard": "REGRESSION", "warning": "warn", "improvement": "improved", "unchanged": "ok"}.get(
                f.severity, f.severity
            )
            out.append(f"  [{marker}] {f.metric}: {f.detail}")
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "baseline_run_id": self.baseline_run_id,
            "findings": [f.to_dict() for f in self.findings],
        }


def thresholds_from_config(config: dict[str, Any] | None) -> RegressionThresholds:
    """Build thresholds from the ``benchmark.regression`` config section."""
    reg = ((config or {}).get("benchmark", {}) or {}).get("regression", {}) or {}

    def _frac(key: str, default: float) -> float:
        try:
            value = float(reg.get(key, default))
        except (TypeError, ValueError):
            return default
        if not math.isfinite(value):
            return default
        return value

    return RegressionThresholds(
        success_rate_tolerance=_frac("success_rate_tolerance", 0.02),
        false_positive_tolerance=_frac("false_positive_tolerance", 0.01),
        median_time_tolerance=_frac("median_time_tolerance", 0.20),
        tool_actions_tolerance=_frac("tool_actions_tolerance", 0.30),
        cost_tolerance=_frac("cost_tolerance", 0.30),
    )


def _baseline_payload(summary: RunSummary) -> dict[str, Any]:
    """The persisted baseline view of a run summary (compact, comparable)."""
    return {
        "run_id": summary.run_id,
        "suite": summary.suite,
        "timestamp": summary.timestamp,
        "trials_total": summary.trials_total,
        "verified_success_rate": summary.verified_success_rate,
        "false_positive_rate": summary.false_positive_rate,
        "median_solve_time": summary.median_solve_time,
        "median_tool_actions": summary.median_tool_actions,
        "estimated_cost": summary.estimated_cost,
        "scenarios": {
            s.scenario_id: {
                "success_probability": s.success_probability,
                "verified": s.verified,
                "trials": s.trials,
            }
            for s in summary.scenarios
        },
    }


def save_baseline(summary: RunSummary, baseline_path: Path | str = DEFAULT_BASELINE_PATH) -> Path:
    """Persist a run summary as the regression baseline (atomic-ish JSON)."""
    path = Path(baseline_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(_baseline_payload(summary), indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
    return path


def load_baseline(baseline_path: Path | str = DEFAULT_BASELINE_PATH) -> dict[str, Any] | None:
    """Load the baseline payload; ``None`` when missing/unreadable."""
    path = Path(baseline_path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _rel_increase(current: float | None, baseline: float | None) -> float | None:
    if baseline is None or current is None or baseline <= 0:
        return None
    if not isinstance(current, (int, float)) or not isinstance(baseline, (int, float)):
        return None
    if isinstance(current, bool) or isinstance(baseline, bool):
        return None
    if not math.isfinite(current) or not math.isfinite(baseline):
        return None
    return (current - baseline) / baseline


def _finite_num(value: Any) -> float | None:
    """Coerce to a finite float; ``None`` when missing/malformed/non-finite."""
    if isinstance(value, bool):
        return None
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    return num if math.isfinite(num) else None


def _malformed_baseline(run_id: str, metric: str) -> RegressionResult:
    return RegressionResult(
        passed=False,
        baseline_run_id=run_id,
        findings=[RegressionFinding("hard", metric, f"baseline {metric!r} malformed (fail-closed)")],
    )


def compare_to_baseline(
    summary: RunSummary,
    baseline: dict[str, Any] | None,
    thresholds: RegressionThresholds | None = None,
) -> RegressionResult:
    """Compare a run summary against a baseline payload.

    Fail-closed: a missing/malformed baseline is a hard failure (CI should not
    silently pass because the baseline vanished).
    """
    th = thresholds or RegressionThresholds()
    if not baseline:
        return RegressionResult(
            passed=False,
            findings=[RegressionFinding("hard", "baseline", "baseline missing or unreadable (fail-closed)")],
        )
    result = RegressionResult(baseline_run_id=str(baseline.get("run_id", "") or ""))

    run_id = str(baseline.get("run_id", "") or "")
    base_rate = _finite_num(baseline.get("verified_success_rate", 0.0))
    if base_rate is None:
        return _malformed_baseline(run_id, "verified_success_rate")
    cur_rate = _finite_num(summary.verified_success_rate)
    if cur_rate is None:
        cur_rate = 0.0
    if cur_rate < base_rate - th.success_rate_tolerance:
        result.findings.append(
            RegressionFinding(
                "hard",
                "verified_success_rate",
                f"{cur_rate:.3f} < baseline {base_rate:.3f} - tolerance {th.success_rate_tolerance}",
                baseline=base_rate,
                current=cur_rate,
            )
        )
    elif cur_rate > base_rate + th.success_rate_tolerance:
        result.findings.append(
            RegressionFinding(
                "improvement",
                "verified_success_rate",
                f"{cur_rate:.3f} > baseline {base_rate:.3f}",
                baseline=base_rate,
                current=cur_rate,
            )
        )
    else:
        result.findings.append(
            RegressionFinding("unchanged", "verified_success_rate", f"{cur_rate:.3f} vs {base_rate:.3f}")
        )

    base_fp = _finite_num(baseline.get("false_positive_rate", 0.0))
    if base_fp is None:
        return _malformed_baseline(run_id, "false_positive_rate")
    cur_fp = _finite_num(summary.false_positive_rate)
    if cur_fp is None:
        cur_fp = 0.0
    if cur_fp > base_fp + th.false_positive_tolerance:
        result.findings.append(
            RegressionFinding(
                "hard",
                "false_positive_rate",
                f"{cur_fp:.3f} > baseline {base_fp:.3f} + tolerance {th.false_positive_tolerance}",
                baseline=base_fp,
                current=cur_fp,
            )
        )
    else:
        result.findings.append(RegressionFinding("unchanged", "false_positive_rate", f"{cur_fp:.3f} vs {base_fp:.3f}"))

    base_time = baseline.get("median_solve_time")
    cur_time = summary.median_solve_time
    inc = _rel_increase(cur_time, base_time if isinstance(base_time, (int, float)) else None)
    if inc is not None and inc > th.median_time_tolerance:
        result.findings.append(
            RegressionFinding(
                "warning",
                "median_solve_time",
                f"{cur_time:.1f}s (+{inc:.0%} vs baseline {base_time:.1f}s)",
                baseline=base_time,
                current=cur_time,
            )
        )
    elif inc is not None and inc < -th.median_time_tolerance:
        result.findings.append(
            RegressionFinding(
                "improvement", "median_solve_time", f"{cur_time:.1f}s ({inc:.0%})", baseline=base_time, current=cur_time
            )
        )

    base_actions = baseline.get("median_tool_actions")
    cur_actions = summary.median_tool_actions
    inc = _rel_increase(cur_actions, base_actions if isinstance(base_actions, (int, float)) else None)
    if inc is not None and inc > th.tool_actions_tolerance:
        result.findings.append(
            RegressionFinding(
                "warning",
                "median_tool_actions",
                f"{cur_actions:.0f} (+{inc:.0%} vs baseline {base_actions:.0f})",
                baseline=base_actions,
                current=cur_actions,
            )
        )

    base_cost = baseline.get("estimated_cost")
    cur_cost = summary.estimated_cost
    inc = _rel_increase(cur_cost, base_cost if isinstance(base_cost, (int, float)) else None)
    if inc is not None and inc > th.cost_tolerance:
        result.findings.append(
            RegressionFinding(
                "warning",
                "estimated_cost",
                f"{cur_cost:.2f} (+{inc:.0%} vs baseline {base_cost:.2f})",
                baseline=base_cost,
                current=cur_cost,
            )
        )

    # Per-scenario: previously solved -> now unsolved is a hard regression.
    base_scenarios = baseline.get("scenarios", {}) if isinstance(baseline.get("scenarios", {}), dict) else {}
    for scenario in summary.scenarios:
        base_entry = base_scenarios.get(scenario.scenario_id)
        if not isinstance(base_entry, dict):
            continue
        base_prob = _finite_num(base_entry.get("success_probability", 0.0))
        if base_prob is None:
            return _malformed_baseline(run_id, f"scenario:{scenario.scenario_id}")
        if base_prob > 0 and scenario.success_probability == 0.0:
            result.findings.append(
                RegressionFinding(
                    "hard",
                    f"scenario:{scenario.scenario_id}",
                    f"solved in baseline (p={base_prob:.2f}) but unsolved now (p=0.00)",
                    baseline=base_prob,
                    current=scenario.success_probability,
                )
            )
        elif base_prob == 0.0 and scenario.success_probability > 0:
            result.findings.append(
                RegressionFinding(
                    "improvement",
                    f"scenario:{scenario.scenario_id}",
                    f"newly solved (p={scenario.success_probability:.2f})",
                    baseline=base_prob,
                    current=scenario.success_probability,
                )
            )

    result.passed = result.hard_count == 0
    return result


# ---------------------------------------------------------------------------
# Two-run comparison (WebUI comparison view)
# ---------------------------------------------------------------------------


def compare_summaries_payload(base_summary: dict[str, Any], current_summary: dict[str, Any]) -> dict[str, Any]:
    """Compare two RunSummary dicts (baseline + candidate) into a UI payload.

    Metric rows carry ``baseline``/``current``/``delta`` (+ direction); the
    per-scenario rollup classifies every scenario as newly_solved / regressed /
    still_solved / still_failing. Pure dict-in/dict-out so both the API and
    the CLI can use it.
    """

    def _pct(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _row(metric: str, base: Any, cur: Any, *, lower_is_better: bool = False) -> dict[str, Any]:
        base_num = base if isinstance(base, (int, float)) else None
        cur_num = cur if isinstance(cur, (int, float)) else None
        delta = (cur_num - base_num) if (base_num is not None and cur_num is not None) else None
        direction = "unchanged"
        if delta is not None and abs(delta) > 1e-9:
            improved = delta < 0 if lower_is_better else delta > 0
            direction = "improved" if improved else "regressed"
        return {
            "metric": metric,
            "baseline": base,
            "current": cur,
            "delta": delta,
            "direction": direction,
        }

    metrics = [
        _row(
            "verified_success_rate",
            _pct(base_summary.get("verified_success_rate")),
            _pct(current_summary.get("verified_success_rate")),
        ),
        _row(
            "false_positive_rate",
            _pct(base_summary.get("false_positive_rate")),
            _pct(current_summary.get("false_positive_rate")),
            lower_is_better=True,
        ),
        _row(
            "median_solve_time",
            base_summary.get("median_solve_time"),
            current_summary.get("median_solve_time"),
            lower_is_better=True,
        ),
        _row(
            "median_tool_actions",
            base_summary.get("median_tool_actions"),
            current_summary.get("median_tool_actions"),
            lower_is_better=True,
        ),
        _row(
            "estimated_cost",
            base_summary.get("estimated_cost"),
            current_summary.get("estimated_cost"),
            lower_is_better=True,
        ),
        _row(
            "total_tokens", base_summary.get("total_tokens"), current_summary.get("total_tokens"), lower_is_better=True
        ),
        _row("solved", base_summary.get("solved", 0), current_summary.get("solved", 0)),
        _row(
            "infra_error_count",
            base_summary.get("infra_error_count", 0),
            current_summary.get("infra_error_count", 0),
            lower_is_better=True,
        ),
    ]

    def _scenario_map(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
        raw = summary.get("scenarios") or []
        # Serialized RunSummary rows are a list; hand-built payloads may pass a
        # scenario_id -> row dict. Both shapes are accepted.
        if isinstance(raw, dict):
            rows = [
                dict(v, scenario_id=k) if isinstance(v, dict) and not v.get("scenario_id") else v
                for k, v in raw.items()
            ]
        else:
            rows = [s for s in raw if isinstance(s, dict)]
        return {str(s.get("scenario_id", "")): s for s in rows if isinstance(s, dict)}

    base_map = _scenario_map(base_summary)
    cur_map = _scenario_map(current_summary)
    per_scenario: dict[str, list[str]] = {
        "newly_solved": [],
        "regressed": [],
        "still_solved": [],
        "still_failing": [],
    }
    scenario_rows: list[dict[str, Any]] = []
    for scenario_id in sorted(set(base_map) | set(cur_map)):
        base_sc = base_map.get(scenario_id)
        cur_sc = cur_map.get(scenario_id)
        base_prob = _pct((base_sc or {}).get("success_probability"))
        cur_prob = _pct((cur_sc or {}).get("success_probability"))
        if base_prob == 0 and cur_prob > 0:
            category = "newly_solved"
        elif base_prob > 0 and cur_prob == 0:
            category = "regressed"
        elif base_prob > 0 and cur_prob > 0:
            category = "still_solved"
        else:
            category = "still_failing"
        per_scenario[category].append(scenario_id)
        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "baseline": base_prob,
                "current": cur_prob,
                "delta": cur_prob - base_prob,
                "category": category,
            }
        )
    return {
        "metrics": metrics,
        "scenarios": scenario_rows,
        "categories": per_scenario,
    }
