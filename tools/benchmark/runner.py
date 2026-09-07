"""BenchmarkRunner: orchestrates scenario trials end-to-end.

Flow per trial (docs/benchmarks.md §architecture):

    provider scenario
      -> provision/reset target          (tools.benchmark.targets)
      -> preflight port reachability     (fail fast when the lab is down)
      -> run BreachPilot mission         (tools.benchmark.agent_runner, sandboxed
                                          when sandbox.enabled — never a host fallback)
      -> independent verification        (tools.benchmark.verifier, eval_checks executors)
      -> classify + record metrics
      -> persist trial                   (tools.benchmark.storage)
      -> destroy/reset target

The runner is async-safe, supports cancellation, emits structured events, and
never lets one trial failure abort the suite. Ground truth comes exclusively
from the verifier; infra failures (provision/sandbox) are recorded as
INFRASTRUCTURE_ERROR, never as exploitation failures.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.benchmark.agent_runner import MissionRunner
from tools.benchmark.envinfo import collect_environment
from tools.benchmark.events import BenchmarkEventLogger
from tools.benchmark.metrics import compute_run_summary
from tools.benchmark.models import (
    FailureCategory,
    RunConfig,
    SandboxSnapshot,
    TargetSnapshot,
    TrialResult,
    TrialStatus,
)
from tools.benchmark.registry import get_provider
from tools.benchmark.regression import (
    compare_to_baseline,
    load_baseline,
    save_baseline,
    thresholds_from_config,
)
from tools.benchmark.replay import build_replay_manifest
from tools.benchmark.report import render_report_html, render_report_markdown
from tools.benchmark.storage import BenchmarkStorage
from tools.benchmark.targets import TargetManager, TargetProvisionError
from tools.benchmark.verifier import IndependentVerifier
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions

__all__ = ["BenchmarkRunner", "mint_run_id"]

_PROGRESS = Callable[[dict[str, Any]], None]


def mint_run_id() -> str:
    """Unique benchmark run id (filesystem-safe)."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + format(time.monotonic_ns() % 100000, "05d")


def _target_ports_reachable(host: str, ports: list[int], timeout: float = 1.0) -> bool:
    """True when at least one declared target port accepts TCP.

    Thin alias over :func:`tools.benchmark.targets.target_ports_reachable`
    (kept under this name for the runner preflight call-site and existing
    tests). See that function for the fail-fast rationale.
    """
    from tools.benchmark.targets import target_ports_reachable

    return target_ports_reachable(host, ports, timeout=timeout)


def _is_loopback_host(host: str) -> bool:
    """True for loopback targets (container-lo != host-lo under sandbox)."""
    try:
        from tools.validation_utils import is_local_target

        return bool(is_local_target(host))
    except Exception:  # noqa: BLE001 -- preflight is best-effort, never fatal
        return str(host or "").strip().lower() in ("127.0.0.1", "localhost", "::1")


def _loopback_mapping_enabled(config: dict[str, Any]) -> bool:
    """True when the dev-lab host-loopback mapping is explicitly opted in."""
    try:
        network = (config.get("sandbox") or {}).get("network") or {}
        return bool(network.get("map_host_loopback", False))
    except Exception:  # noqa: BLE001 -- preflight is best-effort, never fatal
        return False


class BenchmarkRunner:
    """Runs one benchmark suite execution (CLI or API share this path)."""

    def __init__(
        self,
        config: dict[str, Any],
        config_path: Path,
        *,
        storage: BenchmarkStorage | None = None,
        run_session: Any = None,
        target_manager: TargetManager | None = None,
        verifier_factory: Callable[[Any], IndependentVerifier] | None = None,
        model_alias: str = "",
    ) -> None:
        self.config = config
        self.config_path = Path(config_path)
        self.storage = storage or BenchmarkStorage(
            str(((config.get("benchmark", {}) or {}).get("output_dir", "")) or "reports/benchmarks")
        )
        self._run_session = run_session
        self._make_target_manager = (lambda: target_manager) if target_manager is not None else TargetManager
        self._verifier_factory = verifier_factory
        self.model_alias = model_alias or str((config.get("models", {}) or {}).get("default_alias", "") or "glm")

    # ------------------------------------------------------------------ main

    async def run(
        self,
        run_config: RunConfig,
        *,
        cancel: asyncio.Event | None = None,
        progress: _PROGRESS | None = None,
    ) -> dict[str, Any]:
        """Execute the configured suite. Returns a serializable run payload."""
        benchmark_cfg = self.config.get("benchmark", {}) or {}
        sandbox_cfg = self.config.get("sandbox", {}) or {}
        sandbox_enabled = bool(sandbox_cfg.get("enabled", False))
        sandbox_required = bool(run_config.sandbox_required)

        provider = get_provider(run_config.suite)
        scenarios = provider.load_scenarios(scenario_ids=run_config.scenario_ids or None, tags=run_config.tags or None)
        if not scenarios:
            return {"error": f"no scenarios matched for suite {run_config.suite!r}"}

        run_id = mint_run_id()
        environment = collect_environment(
            self.config,
            model_alias=self.model_alias,
            benchmark_config=benchmark_cfg,
            sandbox_enabled=sandbox_enabled,
            sandbox_required=sandbox_required,
        )
        environment.target_images = {s.scenario_id: (s.target_image or "unknown") for s in scenarios}

        run_dir = self.storage.init_run(
            run_config.suite, run_id, run_config, environment, [s.scenario_id for s in scenarios]
        )
        event_logger = BenchmarkEventLogger(path=run_dir / "events.jsonl", run_id=run_id, sink=progress)
        event_logger.log(
            "run_start",
            {
                "suite": run_config.suite,
                "scenarios": [s.scenario_id for s in scenarios],
                "trials": run_config.trials,
                "model_alias": self.model_alias,
                "sandbox_enabled": sandbox_enabled,
                "sandbox_required": sandbox_required,
            },
        )

        trials: list[TrialResult] = []
        sandbox_shortfall = sandbox_required and not sandbox_enabled
        if sandbox_shortfall:
            event_logger.log(
                "sandbox_unavailable",
                {
                    "detail": "sandbox_required=true but sandbox.enabled=false; "
                    "all trials marked INFRASTRUCTURE_ERROR (SANDBOX_FAILED). "
                    "There is no host-execution fallback."
                },
                level="error",
            )

        mission = MissionRunner(
            self.config, self.config_path, model_alias=self.model_alias, run_session=self._run_session
        )

        for scenario in scenarios:
            manager = self._make_target_manager()
            for trial_index in range(max(1, run_config.trials)):
                if cancel is not None and cancel.is_set():
                    event_logger.log("run_cancelled", {"reason": "operator cancel"}, level="warn")
                    break
                trial_id = f"{scenario.scenario_id}#t{trial_index + 1}"
                if progress is not None:
                    progress(
                        {
                            "type": "trial_start",
                            "run_id": run_id,
                            "scenario_id": scenario.scenario_id,
                            "trial": trial_index + 1,
                            "trials": run_config.trials,
                            "trial_id": trial_id,
                            "phase": "provision",
                        }
                    )
                trial = await self._run_trial(
                    scenario,
                    trial_index,
                    trial_id,
                    manager,
                    mission,
                    event_logger,
                    run_id=run_id,
                    run_dir=run_dir,
                    sandbox_required=sandbox_required,
                    sandbox_shortfall=sandbox_shortfall,
                    progress=progress,
                )
                trials.append(trial)
                self.storage.write_trial(run_config.suite, run_id, trial)
            manager.destroy_all()

        # Aggregate + persist.
        meta = {s.scenario_id: {"name": s.name, "difficulty": s.difficulty, "tags": s.tags} for s in scenarios}
        summary = compute_run_summary(trials, run_id=run_id, suite=run_config.suite, scenario_meta=meta)
        status = "cancelled" if (cancel is not None and cancel.is_set()) else "completed"
        manifest = build_replay_manifest(
            run_id, run_config.suite, run_config, environment, target_images=environment.target_images
        )
        self.storage.finalize_run(
            run_config.suite,
            run_id,
            status=status,
            trials=trials,
            summary=summary,
            config=run_config,
            environment=environment,
            scenario_ids=[s.scenario_id for s in scenarios],
            manifest=manifest,
        )

        # Public report from the persisted structured payload.
        stored_run = self.storage.load_run(run_config.suite, run_id) or {}
        stored_summary = self.storage.load_summary(run_config.suite, run_id)
        md_path, html_path = self.storage.write_report(
            run_config.suite,
            run_id,
            render_report_markdown(stored_run, stored_summary),
            render_report_html(stored_run, stored_summary),
        )

        # Baseline / regression.
        regression_payload: dict[str, Any] | None = None
        if run_config.save_baseline:
            baseline_path = Path(str(benchmark_cfg.get("baseline_path", "")) or self.storage.root / "baseline.json")
            save_baseline(summary, baseline_path)
            event_logger.log("baseline_saved", {"path": str(baseline_path)})
        if run_config.check_regression:
            baseline_path = Path(str(benchmark_cfg.get("baseline_path", "")) or self.storage.root / "baseline.json")
            result = compare_to_baseline(summary, load_baseline(baseline_path), thresholds_from_config(self.config))
            regression_payload = result.to_dict()
            event_logger.log("regression_check", regression_payload, level="info" if result.passed else "error")

        event_logger.log(
            "run_end",
            {
                "status": status,
                "solved": summary.solved,
                "trials_total": summary.trials_total,
                "verified_success_rate": summary.verified_success_rate,
                "false_positive_rate": summary.false_positive_rate,
            },
        )
        return {
            "run_id": run_id,
            "suite": run_config.suite,
            "status": status,
            "run_dir": str(run_dir),
            "report_markdown": str(md_path),
            "report_html": str(html_path),
            "summary": summary.to_dict(),
            "trials": [t.to_dict() for t in trials],
            "regression": regression_payload,
        }

    # ------------------------------------------------------------ one trial

    async def _run_trial(
        self,
        scenario: Any,
        trial_index: int,
        trial_id: str,
        manager: TargetManager,
        mission: MissionRunner,
        event_logger: BenchmarkEventLogger,
        *,
        run_id: str,
        run_dir: Path,
        sandbox_required: bool,
        sandbox_shortfall: bool,
        progress: _PROGRESS | None,
    ) -> TrialResult:
        trial = TrialResult(
            run_id=run_id,
            suite=scenario.suite,
            scenario_id=scenario.scenario_id,
            trial_index=trial_index,
            trial_id=trial_id,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        workspace = run_dir / "scenarios" / scenario.scenario_id / f"trial_{trial_index}_workspace"

        # 1. Provision (or reset) the target.
        try:
            if trial_index == 0:
                snapshot: TargetSnapshot = manager.provision(scenario)
            else:
                snapshot = manager.reset(scenario)
            trial.target = snapshot
        except TargetProvisionError as exc:
            trial.status = TrialStatus.INFRASTRUCTURE_ERROR.value
            trial.failure_category = FailureCategory.TARGET_PROVISION_FAILED.value
            trial.failure_detail = str(exc)[:500]
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            event_logger.log(
                "target_provision_failed",
                {"detail": trial.failure_detail},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
            return trial
        event_logger.log(
            "target_ready",
            {
                "host": snapshot.host,
                "ports": snapshot.ports,
                "image": snapshot.image,
                "container_id": snapshot.container_id,
            },
            trial_id=trial_id,
            scenario_id=scenario.scenario_id,
            target=snapshot.host,
        )

        # 1b. Preflight: a host-type lab target whose declared ports all
        # refuse is down (compose suite not up) -- fail fast instead of
        # running a doomed mission. No ports declared means nothing to probe.
        if snapshot.ports and not _target_ports_reachable(snapshot.host, snapshot.ports):
            trial.status = TrialStatus.INFRASTRUCTURE_ERROR.value
            trial.failure_category = FailureCategory.TARGET_PROVISION_FAILED.value
            trial.failure_detail = (
                f"target {snapshot.host} refused all declared ports {list(snapshot.ports)} -- "
                "is the lab suite up? (docker compose -f eval_targets/docker-compose.yml up -d)"
            )
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            event_logger.log(
                "target_provision_failed",
                {"detail": trial.failure_detail},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
            return trial

        # 1c. Loopback containment preflight: a sandboxed worker's loopback is
        # container-local, so a loopback lab target is unreachable by
        # construction unless the dev-lab mapping is opted in. Fail fast as
        # INFRASTRUCTURE_ERROR instead of burning the mission budget on 50
        # doomed recon rounds against container-lo.
        _sandbox_enabled = bool((self.config.get("sandbox") or {}).get("enabled", False))
        if (
            _is_loopback_host(snapshot.host)
            and not sandbox_shortfall
            and _sandbox_enabled
            and not _loopback_mapping_enabled(self.config)
        ):
            trial.status = TrialStatus.INFRASTRUCTURE_ERROR.value
            trial.failure_category = FailureCategory.SANDBOX_FAILED.value
            trial.failure_detail = (
                f"target {snapshot.host} is host loopback but the sandboxed worker cannot reach it "
                "(sandbox.network.map_host_loopback:false; container-lo != host-lo). Rerun the loopback lab "
                "with sandbox.enabled:false + benchmark.sandbox_required:false (explicit lab opt-out), or set "
                "sandbox.network.map_host_loopback:true for dev-lab localhost."
            )
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            event_logger.log(
                "target_provision_failed",
                {"detail": trial.failure_detail},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
            return trial

        # 2. Sandbox gate: required-but-unavailable is infrastructure failure.
        if sandbox_shortfall:
            trial.status = TrialStatus.INFRASTRUCTURE_ERROR.value
            trial.failure_category = FailureCategory.SANDBOX_FAILED.value
            trial.failure_detail = "sandbox required but disabled (no host-execution fallback)"
            trial.sandbox = SandboxSnapshot(required=True, enabled=False, last_error=trial.failure_detail)
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            return trial

        # 3. Run the mission.
        if progress is not None:
            progress(
                {
                    "type": "trial_phase",
                    "run_id": run_id,
                    "scenario_id": scenario.scenario_id,
                    "trial_id": trial_id,
                    "phase": "exploit",
                }
            )
        mission_result = await mission.run_mission(
            scenario,
            workspace=workspace,
            trial_id=trial_id,
            event_logger=event_logger,
            timeout_seconds=scenario.timeout_seconds,
        )
        trial.duration_seconds = mission_result.duration_seconds
        trial.model_calls = mission_result.telemetry.model_calls
        trial.tool_calls = mission_result.telemetry.tool_calls
        trial.total_tokens = mission_result.telemetry.total_tokens
        trial.estimated_cost = mission_result.telemetry.estimated_cost
        trial.claimed_summary = mission_result.claimed_summary
        trial.agent_claimed_success = mission_result.agent_claimed_success
        trial.audit_path = mission_result.audit_path
        trial.workspace = str(workspace)
        trial.errors = list(mission_result.errors)[:10]
        trial.sandbox = mission_result.sandbox
        trial.telemetry = mission_result.telemetry
        trial.evidence_refs = sorted({str(p) for p in [mission_result.audit_path, trial.workspace] if p})

        if mission_result.timed_out:
            trial.status = TrialStatus.TIMEOUT.value
            trial.failure_category = FailureCategory.TIMEOUT.value
            trial.failure_detail = f"mission exceeded {scenario.timeout_seconds}s"
            trial.ended_at = datetime.now(timezone.utc).isoformat()
            event_logger.log(
                "mission_timeout",
                {"timeout_seconds": scenario.timeout_seconds},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
            return trial

        # 4. Independent verification (fresh soft-fail MCP session for shell checks).
        if progress is not None:
            progress(
                {
                    "type": "trial_phase",
                    "run_id": run_id,
                    "scenario_id": scenario.scenario_id,
                    "trial_id": trial_id,
                    "phase": "verify",
                }
            )
        outcome = await self._verify(scenario, trial, event_logger)
        trial.flags = outcome.to_dict_list()
        trial.flags_captured = outcome.flags_captured
        trial.flags_total = outcome.flags_total
        trial.oracle_verified_success = outcome.verified
        event_logger.log(
            "oracle_result",
            {
                "verified": outcome.verified,
                "flags_captured": outcome.flags_captured,
                "flags_total": outcome.flags_total,
                "detail": outcome.detail[:800],
            },
            trial_id=trial_id,
            scenario_id=scenario.scenario_id,
        )

        # 5. Classify.
        trial.status, trial.failure_category, trial.failure_detail = self._classify(mission_result, outcome.verified)
        trial.false_positive = trial.agent_claimed_success and not trial.oracle_verified_success
        if trial.false_positive:
            # Claimed-vs-verified contrast is a first-class outcome: surfaced as
            # its own status + failure category, never averaged into FAILED.
            trial.status = TrialStatus.FALSE_POSITIVE.value
            trial.failure_category = FailureCategory.FALSE_POSITIVE.value
        trial.false_negative = trial.oracle_verified_success and not trial.agent_claimed_success
        trial.ended_at = datetime.now(timezone.utc).isoformat()
        return trial

    async def _verify(self, scenario: Any, trial: TrialResult, event_logger: BenchmarkEventLogger) -> Any:
        """Verify with a dedicated soft-fail session (never the agent's session)."""
        session = None
        cm = None
        loop = None
        try:
            from tools.mcp_session import open_exploit_mcp_session

            cm = open_exploit_mcp_session(
                transport="stdio",
                config_path=self.config_path,
                target_ip=scenario.target_host,
                exploit_port=int(self.config.get("mcp", {}).get("http_port", 8001) or 8001),
                soft_fail=True,
            )
            session = await cm.__aenter__()
            loop = asyncio.get_running_loop()
        except _EXC_GROUP_CATCH as exc:
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            event_logger.log(
                "verify_session_unavailable",
                {"detail": str(exc)[:300], "effect": "shell_command checks degrade to UNVERIFIED (fail-closed)"},
                trial_id=trial.trial_id,
                scenario_id=scenario.scenario_id,
                level="warn",
            )
        except Exception as exc:  # noqa: BLE001 -- verification must never abort the run
            event_logger.log(
                "verify_session_unavailable",
                {"detail": str(exc)[:300], "effect": "shell_command checks degrade to UNVERIFIED (fail-closed)"},
                trial_id=trial.trial_id,
                scenario_id=scenario.scenario_id,
                level="warn",
            )
        try:
            verifier = (
                self._verifier_factory(scenario)
                if self._verifier_factory is not None
                else IndependentVerifier(scenario, session=session, workspace=trial.workspace or None, loop=loop)
            )
            return await verifier.verify()
        finally:
            if cm is not None:
                try:
                    await cm.__aexit__(None, None, None)
                except _EXC_GROUP_CATCH as exc:
                    if _is_exception_group(exc):
                        _log_nested_exceptions(exc)
                except Exception:  # noqa: BLE001 -- teardown best-effort
                    pass

    @staticmethod
    def _classify(mission_result: Any, verified: bool) -> tuple[str, str, str]:
        """Map mission + verification outcome to (status, failure_category, detail)."""
        if verified:
            return TrialStatus.VERIFIED.value, FailureCategory.UNKNOWN.value, ""
        errors = mission_result.errors or []
        if any("model client build failed" in e for e in errors):
            return TrialStatus.FAILED.value, FailureCategory.MODEL_FAILED.value, errors[0][:300]
        if any("MCP" in e or "mcp" in e for e in errors) and mission_result.total_actions == 0:
            return TrialStatus.FAILED.value, FailureCategory.PLANNER_FAILURE.value, errors[0][:300]
        if mission_result.telemetry.tool_calls == 0 and mission_result.total_actions == 0:
            return (
                TrialStatus.FAILED.value,
                FailureCategory.PLANNER_FAILURE.value,
                mission_result.claimed_summary or errors[0][:300] if errors else "no actions taken",
            )
        if (
            mission_result.telemetry.tool_errors > 0
            and mission_result.telemetry.tool_errors >= mission_result.telemetry.tool_calls
        ):
            return (
                TrialStatus.FAILED.value,
                FailureCategory.TOOL_FAILURE.value,
                f"{mission_result.telemetry.tool_errors}/{mission_result.telemetry.tool_calls} tool calls failed",
            )
        return TrialStatus.FAILED.value, FailureCategory.NO_EXPLOIT_PATH.value, mission_result.claimed_summary[:300]
