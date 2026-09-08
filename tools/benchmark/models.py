"""Typed data models for the BreachPilot benchmark suite.

Pure data + enums + JSON serialization. No I/O, no imports of heavy modules —
everything here is importable from any platform and unit-testable in isolation.

Design rules (docs/benchmarks.md):

- **Verified vs claimed are separate fields, always.** Ground truth comes only
  from the independent verifier (:mod:`tools.benchmark.verifier`), never from
  agent text, OutcomeJudge text, exit codes, or tool output.
- **Explicit unknowns.** When exact model/config/sandbox metadata cannot be
  obtained the field is recorded as ``"unknown"``/``None`` — never silently
  substituted — so a run's reproducibility is always honest.
- Deterministic ``to_dict`` output (stable key order via dataclass fields).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "TrialStatus",
    "FailureCategory",
    "ResetStrategy",
    "BenchmarkScenario",
    "FlagCheck",
    "TrialResult",
    "TrialTelemetry",
    "SandboxSnapshot",
    "TargetSnapshot",
    "RunEnvironment",
    "RunConfig",
    "ScenarioSummary",
    "RunSummary",
    "unknown",
]


def unknown(value: Any) -> str:
    """Normalize an optional metadata value to ``"unknown"`` when absent.

    The benchmark contract requires unknown metadata to be recorded as
    ``"unknown"`` rather than silently substituted with a placeholder.
    """
    text = str(value or "").strip()
    return text or "unknown"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TrialStatus(str, Enum):
    """Terminal outcome of one trial.

    ``INFRASTRUCTURE_ERROR`` is deliberately distinct from ``FAILED``: a
    sandbox/target-provision failure says nothing about exploitation ability
    and must not be reported as a failed-to-exploit trial.
    """

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    TIMEOUT = "TIMEOUT"
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"
    SKIPPED = "SKIPPED"


class FailureCategory(str, Enum):
    """Why a trial did not verify. Drives the "what do we build next" loop."""

    TARGET_PROVISION_FAILED = "TARGET_PROVISION_FAILED"
    SANDBOX_FAILED = "SANDBOX_FAILED"
    MODEL_FAILED = "MODEL_FAILED"
    TIMEOUT = "TIMEOUT"
    PLANNER_FAILURE = "PLANNER_FAILURE"
    TOOL_FAILURE = "TOOL_FAILURE"
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NO_EXPLOIT_PATH = "NO_EXPLOIT_PATH"
    AGENT_ABORTED = "AGENT_ABORTED"
    TARGET_RESET_FAILED = "TARGET_RESET_FAILED"
    #: Capability-shortfall classification: a trial whose scenario declares
    #: ``requires_capabilities`` the running build cannot provide (e.g.
    #: browser.* with no backend). Set by the runner's capability gate
    #: (step 0b) via tools/browser/capabilities.unmet_requirements.
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


class ResetStrategy(str, Enum):
    """How a scenario's target is restored between trials."""

    NONE = "none"  # static host, operator-managed
    RESTART = "restart"  # docker restart of the container
    RECREATE = "recreate"  # remove + re-run the image (fresh state)


# ---------------------------------------------------------------------------
# Scenario definition (benchmark-provider output)
# ---------------------------------------------------------------------------


@dataclass
class FlagCheck:
    """One declarative oracle check (reuses the eval_checks check-spec shape)."""

    flag_id: str
    description: str = ""
    check: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkScenario:
    """One benchmark scenario produced by a provider (XBEN is one provider).

    ``oracle`` is a declarative dict: ``{"flags": [FlagCheck-ish dicts],
    "host_owned_when": "any"|"all"|[ids]}`` — the same schema the graded eval
    uses, executed by the same independent executor
    (:func:`tools.eval_checks.default_check_executor`).
    """

    suite: str
    scenario_id: str
    name: str = ""
    description: str = ""
    target_type: str = "docker"  # docker | host
    target_image: str = ""
    target_host: str = "127.0.0.1"
    target_ports: list[int] = field(default_factory=list)
    goal: str = "initial_access"
    expected_flags: list[str] = field(default_factory=list)
    oracle: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    difficulty: str = "unknown"
    reset_strategy: str = ResetStrategy.RECREATE.value
    timeout_seconds: int = 1800
    source_manifest: str = ""  # path/URL of the definition, for reproducibility
    #: Capability names the scenario cannot run without (e.g.
    #: ``["browser.navigate", "browser.dom.inspect"]``). Scenarios declare
    #: requirements only — nothing here evaluates or launches them; the
    #: runner's capability gate detects the shortfall via
    #: ``tools.browser.capabilities.unmet_requirements`` and classifies such
    #: trials SKIPPED / CAPABILITY_UNAVAILABLE instead of running them.
    #: Default [] = same behavior as before.
    requires_capabilities: list[str] = field(default_factory=list)

    @property
    def benchmark_id(self) -> str:
        """Stable benchmark identifier (``<suite>/<scenario_id>``)."""
        return f"{self.suite}/{self.scenario_id}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Per-trial data
# ---------------------------------------------------------------------------


@dataclass
class SandboxSnapshot:
    """Sandbox facts recorded for reproducibility + violation counting."""

    enabled: bool = False
    required: bool = False
    image: str = "unknown"
    image_digest: str = "unknown"
    container_id: str = ""
    network_policy_fingerprint: str = ""
    authorized_destinations: list[str] = field(default_factory=list)
    blocked_events: int = 0
    failures: int = 0
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TargetSnapshot:
    """Target provisioning facts for one trial."""

    host: str = ""
    ports: list[int] = field(default_factory=list)
    image: str = "unknown"
    image_digest: str = "unknown"
    container_id: str = ""
    snapshot_id: str = ""
    reset_strategy: str = ResetStrategy.RECREATE.value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrialTelemetry:
    """Operational counters for one trial (model calls, tokens, cost)."""

    model_calls: int = 0
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    estimated_cost: float | None = None  # None = not computable (recorded honestly)
    tool_calls: int = 0
    tool_errors: int = 0
    sandbox_blocked_actions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrialResult:
    """Outcome of one scenario trial.

    ``agent_claimed_success`` and ``oracle_verified_success`` are independent:
    claimed-and-not-verified is a FALSE_POSITIVE trial; verified-but-not-claimed
    is a VERIFIED trial with ``false_negative=True`` (the agent undersold).
    """

    run_id: str = ""
    suite: str = ""
    scenario_id: str = ""
    trial_index: int = 0
    trial_id: str = ""
    status: str = TrialStatus.FAILED.value
    agent_claimed_success: bool = False
    oracle_verified_success: bool = False
    false_positive: bool = False
    false_negative: bool = False
    failure_category: str = FailureCategory.UNKNOWN.value
    failure_detail: str = ""
    started_at: str = ""
    ended_at: str = ""
    duration_seconds: float = 0.0
    model_calls: int = 0
    tool_calls: int = 0
    total_tokens: int = 0
    estimated_cost: float | None = None
    claimed_summary: str = ""
    flags: list[dict[str, Any]] = field(default_factory=list)
    flags_captured: int = 0
    flags_total: int = 0
    evidence_refs: list[str] = field(default_factory=list)
    audit_path: str = ""
    workspace: str = ""
    errors: list[str] = field(default_factory=list)
    sandbox: SandboxSnapshot = field(default_factory=SandboxSnapshot)
    target: TargetSnapshot = field(default_factory=TargetSnapshot)
    telemetry: TrialTelemetry = field(default_factory=TrialTelemetry)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


# ---------------------------------------------------------------------------
# Run-level data
# ---------------------------------------------------------------------------


@dataclass
class RunEnvironment:
    """Reproduction metadata captured at run start.

    Every field is honest-or-unknown: missing git/metadata becomes
    ``"unknown"``/``None``, never a fabricated value.
    """

    breachpilot_version: str = "unknown"
    git_sha: str = "unknown"
    git_dirty: bool | None = None  # None = unknown
    git_branch: str = "unknown"
    model_provider: str = "unknown"
    model_alias: str = "unknown"
    model_id: str = "unknown"
    model_version: str = "unknown"
    reasoning_config: dict[str, Any] = field(default_factory=dict)
    temperature: float | None = None
    config_hash: str = "unknown"
    benchmark_config_hash: str = "unknown"
    sandbox_image: str = "unknown"
    sandbox_image_digest: str = "unknown"
    sandbox_enabled: bool = False
    sandbox_required: bool = True
    target_images: dict[str, str] = field(default_factory=dict)  # scenario -> image
    platform: str = "unknown"
    python_version: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunConfig:
    """What the operator asked for (suite, filters, trials, model, ...)."""

    suite: str = ""
    scenario_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    trials: int = 1
    timeout_seconds: int = 1800
    model_alias: str = ""
    reasoning_profile: str = ""
    sandbox_required: bool = True
    save_baseline: bool = False
    check_regression: bool = False
    output_dir: str = "reports/benchmarks"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScenarioSummary:
    """Per-scenario aggregate across its trials."""

    scenario_id: str
    name: str = ""
    difficulty: str = "unknown"
    tags: list[str] = field(default_factory=list)
    trials: int = 0
    verified: int = 0
    claimed: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    timeouts: int = 0
    infra_errors: int = 0
    success_probability: float = 0.0
    success_variance: float = 0.0
    success_stddev: float = 0.0
    ci95_low: float | None = None
    ci95_high: float | None = None
    median_duration: float | None = None
    mean_duration: float | None = None
    median_actions: float | None = None
    mean_actions: float | None = None
    median_model_calls: float | None = None
    total_tokens: int = 0
    estimated_cost: float | None = None
    failure_categories: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunSummary:
    """Aggregate metrics for a whole benchmark run.

    Computed by :mod:`tools.benchmark.metrics` from the trial list.
    """

    run_id: str = ""
    suite: str = ""
    timestamp: str = ""
    trials_total: int = 0
    trials_completed: int = 0
    verified_success_rate: float = 0.0
    solved: int = 0  # verified trials
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    median_solve_time: float | None = None
    mean_solve_time: float | None = None
    median_tool_actions: float | None = None
    mean_tool_actions: float | None = None
    median_model_calls: float | None = None
    total_tokens: int = 0
    estimated_cost: float | None = None
    time_to_first_verified_success: float | None = None
    sandbox_blocked_actions: int = 0
    infra_error_count: int = 0
    timeout_count: int = 0
    failure_categories: dict[str, int] = field(default_factory=dict)
    scenarios: list[ScenarioSummary] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
