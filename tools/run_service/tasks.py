"""AssessmentService: transport-neutral preparation and execution of runs.

Split from ``main.async_main`` so the CLI and the WebUI API daemon both drive
assessments through one code path. ``prepare`` resolves target/goal/settings
and returns a ``RunPreview`` (no I/O side effects beyond config reads);
``execute`` opens the MCP session, runs the agent loop, handles swarm, writes
reports, and returns a ``RunResult``.

The CLI supplies ``TerminalDecisionProvider`` / ``TerminalEventSink`` /
``TerminalApprovalProvider`` (backed by ``AttackUi``); the API supplies the
async adapters backed by persisted decisions + WebSocket events. The service
never calls ``AttackUi`` directly -- it emits events and requests decisions
through the provider/sink interfaces.
"""

from __future__ import annotations

import asyncio
import json
import time
import traceback
from pathlib import Path
from typing import Any

from tools.attack_ui import get_ui
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.exploit_agent import ExploitSettings
from tools.goal_engine import AttackGoal, GoalEngine
from tools.goal_suggester import ReconAssessment
from tools.run_service.models import (
    EVENT_ARTIFACT,
    EVENT_RECON,
    EVENT_SWARM,
    Decision,
    DecisionKind,
    RunRequest,
)
from tools.run_service.prepare import _config_cli_load, _read_swarm_snapshot, _request_to_args
from tools.run_service.providers import (
    CancellationToken,
    DecisionProvider,
    EventSink,
)
from tools.swarm_bridge import SwarmMcpBridge

ui = get_ui()


class TasksMixin:
    def _find_resume_match(self, reports_dir: Path, resume_key: str) -> Path | None:
        """Find a run subdir matching ``resume_key`` (name or session_id)."""
        for child in sorted(reports_dir.iterdir(), reverse=True):
            if not child.is_dir():
                continue
            if child.name == resume_key:
                return child
            for sj_name in ("session_state.json", "session.json"):
                sj = child / sj_name
                if sj.exists():
                    try:
                        if json.loads(sj.read_text(encoding="utf-8")).get("session_id") == resume_key:
                            return child
                    except (OSError, ValueError, KeyError):
                        continue
        return None

    async def _recon_first(
        self,
        *,
        request: RunRequest,
        config: dict[str, Any],
        config_path: Path,
        target_ip: str,
        original_target: str,
        resolved_ip: str | None,
        resolved_domain: str | None,
        reports_dir: Path,
        model_client: Any,
        model_alias: str,
        risk_profile: str,
        goal_engine: GoalEngine,
        decision_provider: DecisionProvider,
        event_sink: EventSink,
        cancellation: CancellationToken,
    ) -> tuple[ReconAssessment, AttackGoal]:
        """Recon-first: scan target, suggest goals, let operator pick."""
        ui.status("RECON-FIRST MODE: Scanning target before goal selection...")
        ui.divider()

        workspace = Path("exploit_workspace")
        workspace.mkdir(parents=True, exist_ok=True)

        http_port = int(config.get("mcp", {}).get("http_port", 8001))
        assessment: ReconAssessment | None = None
        try:
            async with self._c.open_session(
                transport="http",
                config_path=config_path,
                target_ip=target_ip,
                exploit_port=http_port,
                workspace=workspace,
                multi_model_enabled=bool(request.multi_model_consult),
                active_model_alias=model_alias,
                soft_fail=True,
                original_target=original_target if resolved_domain else None,
                resolved_ip=resolved_ip if resolved_domain else None,
            ) as recon_session:
                if recon_session is None:
                    ui.info("MCP recon unavailable — falling back to UNKNOWN OS verdict.")
                    assessment = ReconAssessment(
                        target_ip=target_ip, os_verdict="UNKNOWN", services=[], cve_findings=[]
                    )
                else:
                    assessment = await self._c.run_recon_assessment(
                        session=recon_session,
                        target_ip=target_ip,
                        reports_dir=reports_dir,
                    )
        except _EXC_GROUP_CATCH as exc:
            log_path = reports_dir / "recon_first_error.log"
            try:
                log_path.write_text(
                    "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)), encoding="utf-8"
                )
            except OSError:
                pass
            ui.warning(f"Recon-first session hit an unexpected error: {exc}")
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            assessment = ReconAssessment(target_ip=target_ip, os_verdict="UNKNOWN", services=[], cve_findings=[])
        if assessment is None:
            assessment = ReconAssessment(target_ip=target_ip, os_verdict="UNKNOWN", services=[], cve_findings=[])

        ui.display_recon_assessment(assessment)

        await event_sink.emit(EVENT_RECON, {"assessment": assessment.to_dict()})

        suggestions = goal_engine.suggest_goals(assessment, risk_profile)
        suggestions_path = reports_dir / "goal_suggestions.json"
        suggestions_path.write_text(json.dumps([s.to_dict() for s in suggestions], indent=2), encoding="utf-8")
        await event_sink.emit(EVENT_ARTIFACT, {"name": "goal_suggestions.json"})
        ui.info(f"Goal suggestions saved to: {suggestions_path}")
        ui.display_goal_suggestions(suggestions)

        await event_sink.emit(
            EVENT_GOAL_SUGGESTIONS := "goal_suggestions",
            {
                "suggestions": [s.to_dict() for s in suggestions],
            },
        )

        # Ask operator to pick a goal via decision provider.
        decision = Decision(
            id="",
            run_id="",
            kind=DecisionKind.GOAL_SELECT,
            prompt_text="Select a goal from the suggestions:",
            options=[s.to_dict() for s in suggestions],
        )
        answer = await decision_provider.request(decision)

        selected_sg = next((s for s in suggestions if s.name == answer), None)
        if selected_sg and getattr(selected_sg, "is_ai_generated", False):
            goal = goal_engine.get("custom", selected_sg.description, risk_profile=risk_profile)
            goal.name = selected_sg.name
        elif answer:
            goal = goal_engine.get(answer, risk_profile=risk_profile)
        else:
            goal = goal_engine.get("custom", "No goal selected", risk_profile=risk_profile)

        assessment_path = reports_dir / "recon_assessment.json"
        if assessment_path.exists():
            data = json.loads(assessment_path.read_text(encoding="utf-8"))
            data["chosen_goal"] = goal.name
            data["chosen_goal_description"] = goal.description
            assessment_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            await event_sink.emit(EVENT_ARTIFACT, {"name": "recon_assessment.json"})

        return assessment, goal

    async def _fast_recon(
        self,
        *,
        request: RunRequest,
        config: dict[str, Any],
        config_path: Path,
        target_ip: str,
        original_target: str,
        resolved_ip: str | None,
        resolved_domain: str | None,
        reports_dir: Path,
        model_client: Any,
        model_alias: str,
        risk_profile: str,
        goal_engine: GoalEngine,
        decision_provider: DecisionProvider,
        event_sink: EventSink,
        cancellation: CancellationToken,
    ) -> tuple[ReconAssessment, AttackGoal]:
        """Fast Mode: parallel recon preset, then auto goal + AI takeover.

        - Runs FastReconCoordinator (dependency-aware parallel tasks).
        - Persists fast_recon.json + recon_assessment.json (resume-aware).
        - Auto-selects goal if none supplied (highest-ranked compatible).
        - Emits fast_recon_* events + recon_assessment + goal_suggestions.
        - Tells the AI not to repeat completed recon (compact summary).

        Reuses the existing MCP session boundary: a short-lived recon session is
        opened for the preset, then a second session is opened for the agent.
        Reusing one session would save one boot cycle but requires brittle global
        state (the session holds target-locked env + tool schemas + policy); the
        current split keeps the boundary testable and cancellation-safe.
        """
        ui.status("FAST MODE: Running parallel recon preset before AI takeover...")
        ui.divider()

        workspace = Path("exploit_workspace")
        workspace.mkdir(parents=True, exist_ok=True)
        http_port = int(config.get("mcp", {}).get("http_port", 8001))

        # Resume: if a prior fast_recon.json is already on disk and recon is
        # valid, reuse it instead of rescanning (resume should continue with
        # persisted state). This is distinct from the short-lived cache.
        resume_assessment: ReconAssessment | None = None
        fast_json = reports_dir / "fast_recon.json"
        recon_json = reports_dir / "recon_assessment.json"
        if recon_json.exists():
            try:
                raw = json.loads(recon_json.read_text(encoding="utf-8"))
                resume_assessment = ReconAssessment.from_dict(raw)
                ui.info(f"FAST RECON RESUME: loaded assessment from {recon_json}")
            except Exception:
                resume_assessment = None

        if resume_assessment is not None and resume_assessment.services:
            assessment = resume_assessment
            # fabricate a minimal fast bundle for events
            await event_sink.emit(EVENT_RECON, {"assessment": assessment.to_dict()})
        else:
            # Run coordinator
            from tools.fast_recon import FastReconConfig, FastReconCoordinator

            fast_cfg = FastReconConfig.from_config(config)
            coordinator = FastReconCoordinator(
                config=fast_cfg,
                reports_dir=reports_dir,
                event_sink=event_sink,
                cancellation=cancellation,
            )
            assessment = None
            try:
                async with self._c.open_session(
                    transport="http",
                    config_path=config_path,
                    target_ip=target_ip,
                    exploit_port=http_port,
                    workspace=workspace,
                    multi_model_enabled=bool(request.multi_model_consult),
                    active_model_alias=model_alias,
                    soft_fail=True,
                    original_target=original_target if resolved_domain else None,
                    resolved_ip=resolved_ip if resolved_domain else None,
                ) as recon_session:
                    if recon_session is None:
                        ui.info("MCP recon unavailable — falling back to UNKNOWN assessment.")
                        assessment = ReconAssessment(
                            target_ip=target_ip, os_verdict="UNKNOWN", services=[], cve_findings=[]
                        )
                        # persist fallback so resume works
                        fast_bundle = {"target": target_ip, "recon_complete": False, "warnings": ["MCP unavailable"]}
                        (reports_dir / "fast_recon.json").write_text(
                            json.dumps(fast_bundle, indent=2), encoding="utf-8"
                        )
                        (reports_dir / "recon_assessment.json").write_text(
                            json.dumps(assessment.to_dict(), indent=2), encoding="utf-8"
                        )
                    else:
                        fast_result = await coordinator.run(recon_session, target_ip)
                        assessment = fast_result.assessment or ReconAssessment(
                            target_ip=target_ip,
                            os_verdict=fast_result.os.get("verdict", "UNKNOWN"),
                            services=fast_result.services,
                            cve_findings=fast_result.cves,
                        )
                        # log summary (compact, not raw)
                        if fast_result.summary_text:
                            ui.info("Fast Recon summary:\n" + fast_result.summary_text)
                        if fast_result.cache_hit:
                            ui.info(f"FAST RECON CACHE HIT: loaded assessment (age < {fast_cfg.cache_ttl_seconds}s)")
            except _EXC_GROUP_CATCH as exc:
                log_path = reports_dir / "recon_first_error.log"
                try:
                    log_path.write_text(
                        "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)), encoding="utf-8"
                    )
                except OSError:
                    pass
                ui.warning(f"Fast recon hit an unexpected error: {exc}")
                if _is_exception_group(exc):
                    _log_nested_exceptions(exc)
                assessment = ReconAssessment(target_ip=target_ip, os_verdict="UNKNOWN", services=[], cve_findings=[])
            if assessment is None:
                assessment = ReconAssessment(target_ip=target_ip, os_verdict="UNKNOWN", services=[], cve_findings=[])

            ui.display_recon_assessment(assessment)
            await event_sink.emit(EVENT_RECON, {"assessment": assessment.to_dict()})

        # Goal suggestion + auto-selection (no blocking dialog unless required).
        suggestions = goal_engine.suggest_goals(assessment, risk_profile)
        suggestions_path = reports_dir / "goal_suggestions.json"
        suggestions_path.write_text(json.dumps([s.to_dict() for s in suggestions], indent=2), encoding="utf-8")
        await event_sink.emit(EVENT_ARTIFACT, {"name": "goal_suggestions.json"})
        ui.display_goal_suggestions(suggestions)
        await event_sink.emit("goal_suggestions", {"suggestions": [s.to_dict() for s in suggestions]})

        # If operator supplied a goal, honour it. No blocking prompt.
        goal: AttackGoal | None = None
        if request.custom_goal.strip():
            goal = goal_engine.get("custom", request.custom_goal.strip(), risk_profile=risk_profile)
        elif request.goal_name.strip().lower() and goal_engine.is_preset(request.goal_name.strip().lower()):
            goal = goal_engine.get(request.goal_name.strip().lower(), risk_profile=risk_profile)
        else:
            # Auto-select highest-ranked compatible goal
            compatible = [s for s in suggestions if s.compatible]
            picked = compatible[0] if compatible else (suggestions[0] if suggestions else None)
            if picked:
                if getattr(picked, "is_ai_generated", False):
                    goal = goal_engine.get("custom", picked.description, risk_profile=risk_profile)
                    goal.name = picked.name
                else:
                    goal = goal_engine.get(picked.name, risk_profile=risk_profile)
                ui.info(
                    f"Fast Mode auto-selected goal: {goal.name} ({picked.exploit_likelihood}, rating {picked.success_rating})"
                )
                await event_sink.emit(
                    "fast_recon_goal_selected",
                    {
                        "goal": goal.name,
                        "description": goal.description,
                        "rating": picked.success_rating,
                        "likelihood": picked.exploit_likelihood,
                    },
                )
            else:
                goal = goal_engine.get(
                    "custom",
                    "Prioritize the highest-value authorized path based on completed recon. Do not repeat reconnaissance already performed.",
                    risk_profile=risk_profile,
                )
                await event_sink.emit("fast_recon_goal_selected", {"goal": goal.name, "description": goal.description})

        # Tag assessment with chosen goal for resume
        try:
            if recon_json.exists():
                data = json.loads(recon_json.read_text(encoding="utf-8"))
                data["chosen_goal"] = goal.name
                data["chosen_goal_description"] = goal.description
                recon_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass
        # Persist fast_recon artifact marker if not already
        if fast_json.exists():
            await event_sink.emit(EVENT_ARTIFACT, {"name": "fast_recon.json"})
        await event_sink.emit(EVENT_ARTIFACT, {"name": "recon_assessment.json"})

        # Tell next stage that recon is complete (model-facing hint)
        await event_sink.emit(
            "ai_takeover_started",
            {
                "recon_complete": True,
                "recon_strategy": "fast",
                "known_open_ports": assessment.open_ports if assessment else [],
                "known_services": assessment.services if assessment else [],
                "recon_artifact": str(recon_json),
                "compact_summary": (
                    fast_result.summary_text
                    if "fast_result" in locals() and hasattr(fast_result, "summary_text")
                    else ""
                ),
            },
        )
        ui.status(
            "Fast Recon complete — AI agent taking over with completed recon context (do not repeat discovery unless gap identified)."
        )
        return assessment, goal

    async def _setup_swarm(
        self,
        *,
        request: RunRequest,
        config: dict[str, Any],
        target_ip: str,
        goal: AttackGoal,
        mode: str,
        exploit_settings: ExploitSettings,
        model_client: Any,
        model_alias: str,
        swarm_bridge: SwarmMcpBridge,
        original_target: str,
        resolved_ip: str | None,
        resolved_domain: str | None,
        event_sink: EventSink,
        reports_dir: Path,
        progress_heartbeat: Any,
    ) -> tuple[Any, asyncio.Task[Any] | None, Path]:
        from agent_loop import AgentLoop

        exploit_cfg = config.get("exploit", {}) or {}
        from tools.run_service.models import is_agent_attack_mode as _swarm_is_attack

        _is_attack = _swarm_is_attack(mode)
        swarm_mission_config = {
            "program_name": f"Swarm: {target_ip}",
            "objective": goal.description or f"Swarm against {target_ip}",
            "risk_profile": "high_authorized_testing" if _is_attack else "standard_authorized",
            "allowed_assets": [str(target_ip)],
            "disallowed_assets": [],
            "forbidden_actions": ["denial_of_service", "social_engineering", "physical_attack"],
            "testing_modes": ["recon", "test", "exploit", "report"] if _is_attack else ["recon", "analysis", "report"],
            "rate_limits": {"default_requests_per_second": 2, "max_concurrent_requests": 3},
            "accounts": [],
            "use_swarm": True,
            "critic_enabled": bool(getattr(exploit_settings, "target_context", {}).get("critic_enabled", False)),
            "reflection_enabled": bool(
                getattr(exploit_settings, "target_context", {}).get("reflection_enabled", False)
            ),
            "adaptive_exploits_enabled": bool(getattr(exploit_settings, "adaptive_exploits_enabled", False)),
            "reflection_every_n_actions": 10,
            "attack_max_rounds": int(exploit_cfg.get("max_rounds", 30)),
            # §13/§23: the models + agent blocks ride along so the swarm
            # orchestrator can resolve models.roles.<role> clients (critic role)
            # and the campaign retry cap (agent.max_retries_per_task) applies
            # on the autonomous path. Both read defensively downstream.
            "models": (config or {}).get("models", {}),
            "agent": (config or {}).get("agent", {}),
            # P3-10: the swarm block rides along so SwarmOrchestrator reads
            # max_parallel_agents / per_phase_concurrency / exploit_parallel
            # from config on Flow A (previously constructor-only defaults).
            "swarm": (config or {}).get("swarm", {}),
        }
        swarm_workspace = reports_dir / "swarm_workspace"
        swarm_workspace.mkdir(parents=True, exist_ok=True)
        swarm_loop = AgentLoop(
            mission_config=swarm_mission_config,
            workspace_root=swarm_workspace,
            tool_executor=swarm_bridge.dispatch,
            console_ui=ui,
            state_dir=swarm_workspace,
            original_target=original_target if resolved_domain else "",
            resolved_ip=resolved_ip if resolved_domain else "",
        )
        try:
            swarm_loop.set_model_client(model_client, model_alias)
        except Exception as exc:  # noqa: BLE001
            ui.warning(f"swarm set_model_client failed: {exc}")

        def _track_progress(payload: dict[str, Any]) -> None:
            action = payload.get("action")
            progress_heartbeat.update(
                round=progress_heartbeat.round,
                action=int(action) if action is not None else progress_heartbeat.action,
                phase=str(payload.get("phase") or progress_heartbeat.phase),
            )

        async def _run_swarm() -> dict[str, Any]:
            try:
                if mode == "attack":
                    from tools.autonomous_orchestrator import observe_autonomous_progress

                    with observe_autonomous_progress(_track_progress):
                        return await swarm_loop.run_autonomous_campaign([target_ip])
                max_cycles = int(exploit_cfg.get("max_rounds", 30))
                return await asyncio.to_thread(swarm_loop.run, max_cycles)
            except _EXC_GROUP_CATCH as exc:
                ui.error(f"Swarm campaign error: {exc}")
                return {"error": str(exc)}

        swarm_task = asyncio.create_task(_run_swarm())
        ui.info(
            f"Swarm mode ENABLED (critic={request.critic}, reflection={request.reflection}, adaptive_exploits={request.adaptive_exploits})."
        )
        await event_sink.emit(EVENT_SWARM, {"status": "started", "workspace": str(swarm_workspace)})
        return swarm_loop, swarm_task, swarm_workspace

    async def _run_session(
        self,
        *,
        model_client: Any,
        model_alias: str,
        target_ip: str,
        mode: str,
        goal: AttackGoal,
        exploit_settings: ExploitSettings,
        config_path: Path,
        reports_dir: Path,
        assessment: ReconAssessment | None,
        approval_prompt: Any,
        approval_provider: Any,
        swarm_attach: Any,
        heartbeat: Any,
        original_target: str | None,
        resolved_ip: str | None,
        recon_first: bool,
        resume_state: tuple[Any, str, str] | None,
        event_sink: EventSink,
        cancellation: CancellationToken,
        checkpoint_hook: Any = None,
    ) -> dict[str, Any]:
        config = _config_cli_load(config_path)
        http_port = int(config.get("mcp", {}).get("http_port", 8001))

        result = await self._c.run_session(
            client=model_client,
            model=model_alias,
            target_ip=target_ip,
            mode=mode,
            goal=goal,
            exploit_settings=exploit_settings,
            config_path=config_path,
            mcp_transport="http",
            exploit_port=http_port,
            reports_dir=reports_dir,
            assessment=assessment if (recon_first or resume_state is not None) else None,
            approval_prompt=approval_prompt,
            approval_provider=approval_provider,
            swarm_attach=swarm_attach,
            heartbeat=heartbeat,
            original_target=original_target,
            resolved_ip=resolved_ip,
            event_sink=event_sink,
            checkpoint_hook=checkpoint_hook,
        )
        ui.divider()
        ui.success(f"Session complete. {result.get('total_actions', 0)} actions executed.")
        ui.status(f"Goal:    {goal.name}")
        ui.status(f"Target:  {target_ip}")
        ui.status(f"Mode:    {mode}")
        ui.status(f"Actions: {result.get('total_actions', 0)}")
        _outcome = result.get("outcome_summary")
        if _outcome:
            ui.status(f"Blocked/thrash: {_outcome}")
        _tel = getattr(result, "_telemetry", None)
        if isinstance(result, dict):
            _tel2 = result.get("_telemetry")
            if isinstance(_tel2, dict):
                _ctx_part = ""
                if _tel2.get("avg_ctx") is not None:
                    _ctx_part = (
                        f" (avg ctx {_tel2['avg_ctx']:.0f}%, max {_tel2['max_ctx']:.0f}%)"
                        if _tel2.get("max_ctx") is not None
                        else f" (avg ctx {_tel2['avg_ctx']:.0f}%)"
                    )
                ui.info(f"Model usage: {_tel2['total_tokens']:,} tokens across {_tel2['calls']} calls{_ctx_part}")
        final_skills = result.get("active_skills") or exploit_settings.target_context.get("active_skills", [])
        if final_skills:
            ui.skills(
                [
                    f"{item.get('name', 'unknown')} - {item.get('reason', 'selected')}"
                    for item in final_skills
                    if isinstance(item, dict)
                ]
            )
        ui.status("Artifacts written:")
        ui.info(f"  reports dir:        {reports_dir}")
        ui.info(f"  audit trail:        {result.get('audit_path', 'unknown')}")
        ui.info(f"  exploit workspace:  {result.get('workspace', 'unknown')}")
        if mode != "recon":
            ui.status(f"Review findings in: {reports_dir / 'session_summary.md'}")
        return result

    async def _wait_swarm(
        self,
        *,
        swarm_task: asyncio.Task[Any],
        swarm_bridge: SwarmMcpBridge,
        swarm_workspace: Path,
        config: dict[str, Any],
        request: RunRequest,
        result: dict[str, Any],
        event_sink: EventSink,
    ) -> dict[str, Any]:
        from tools.cli_exploit_settings import _compute_swarm_timeout

        swarm_start = time.monotonic()
        swarm_timeout = _compute_swarm_timeout(config, _request_to_args(request))
        swarm_result = None
        try:
            _last_progress = 0.0
            while not swarm_task.done():
                remaining = swarm_timeout - (time.monotonic() - swarm_start)
                if remaining <= 0:
                    raise asyncio.TimeoutError()
                try:
                    swarm_result = await asyncio.wait_for(asyncio.shield(swarm_task), timeout=min(2.0, remaining))
                    break
                except asyncio.TimeoutError:
                    elapsed = int(time.monotonic() - swarm_start)
                    if elapsed - _last_progress >= 15:
                        _last_progress = elapsed
                        snap = _read_swarm_snapshot(swarm_workspace)
                        detail = f" — {snap}" if snap else ""
                        ui.info(f"Swarm running {elapsed}s elapsed (timeout {int(swarm_timeout)}s){detail}")
                        await event_sink.emit(
                            EVENT_SWARM,
                            {"elapsed_seconds": elapsed, "timeout_seconds": int(swarm_timeout), "snapshot": snap},
                        )
                    continue
            if swarm_result is None and not swarm_task.cancelled():
                swarm_result = swarm_task.result()
            result["swarm_result"] = swarm_result
            elapsed = int(time.monotonic() - swarm_start)
            dispatched = getattr(swarm_bridge, "dispatched", 0)
            ui.info(
                f"Swarm campaign complete in {elapsed}s (dispatched {dispatched} tool call(s)): "
                f"{swarm_result.get('tasks_completed', 0)} completed, "
                f"{swarm_result.get('tasks_blocked', 0)} blocked, "
                f"{swarm_result.get('tasks_failed', 0)} failed, "
                f"{swarm_result.get('findings_report_ready', 0)} report-ready findings."
            )
        except asyncio.TimeoutError:
            ui.error(f"Swarm task timed out ({int(swarm_timeout)}s). Cancelling.")
            swarm_task.cancel()
            result["swarm_result"] = {"error": "timeout"}
        except _EXC_GROUP_CATCH as exc:
            ui.error(f"Swarm task error: {exc}")
            result["swarm_result"] = {"error": str(exc)}
        finally:
            if not swarm_task.done():
                swarm_task.cancel()
                try:
                    await swarm_task
                except asyncio.CancelledError:
                    pass
        return result
