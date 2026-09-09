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
import copy
import json
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.activity_log import ActivityLog
from tools.attack_ui import get_ui
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.goal_engine import AttackGoal
from tools.goal_suggester import ReconAssessment
from tools.mcp_session import _RunHeartbeat
from tools.model_telemetry import usage_log_path, workspace_root_from_sources
from tools.run_log import RunLog
from tools.run_service.models import (
    EVENT_ARTIFACT,
    EVENT_COMPLETION,
    EVENT_ERROR,
    EVENT_PROGRESS,
    EVENT_STATE,
    Decision,
    DecisionKind,
    RunPreview,
    RunRequest,
    RunResult,
    RunState,
)
from tools.run_service.prepare import (
    _build_campaign_result_from_records,
    _request_to_args,
    _TelemetryAccumulator,
)
from tools.run_service.providers import (
    CancellationToken,
    DecisionProvider,
    EventSink,
)
from tools.swarm_bridge import SwarmMcpBridge

ui = get_ui()


class ExecuteMixin:
    async def execute(
        self,
        request: RunRequest,
        preview: RunPreview,
        *,
        decision_provider: DecisionProvider,
        event_sink: EventSink,
        cancellation: CancellationToken,
        model_client: Any | None = None,
        config: dict[str, Any] | None = None,
        approval_provider: Any | None = None,
        session_attach: Callable[[Any, list[dict[str, Any]], Any], None] | None = None,
    ) -> RunResult:
        """Execute the assessment described by ``request`` / ``preview``.

        ``model_client`` may be None (the service builds a fresh router); when
        the CLI passes its already-built client it avoids a second router
        construction. ``config`` may be None (loaded from ``request.config_path``).
        """
        from tools import config_cli as _config_cli
        from tools.cli_exploit_settings import build_cli_exploit_settings
        from tools.resume_state import _load_resume_state
        from tools.skills_cli import (
            _apply_runtime_skill_selection,
            _build_runtime_skill_selection,
            apply_skills_cli_overrides,
        )

        config_path = request.config_path
        config = copy.deepcopy(config if config is not None else _config_cli.load_config(config_path))
        config = apply_skills_cli_overrides(config, _request_to_args(request))
        reports_dir = preview.reports_dir
        run_id = preview.run_id
        target_ip = preview.target_ip
        original_target = preview.original_target
        resolved_ip = preview.resolved_ip
        resolved_domain = preview.resolved_domain
        mode = preview.mode

        # Per-run run.log: tees all console output (ui.*, print) and every
        # logging record in this process into reports/<run_id>/run.log so
        # failures can be traced after the fact. See tools/run_log.py.
        RunLog.attach(reports_dir)

        await event_sink.emit(EVENT_STATE, {"state": RunState.RUNNING.value})

        # Per-run witness side task (advisory audit-stream watcher). When
        # ``witness.enabled`` is truthy the run spawns a WitnessAgent poll
        # loop alongside the session: it tails the per-run audit trails
        # (reports/<run_id>/activity.jsonl now; the per-attempt
        # exploit_audit.jsonl is registered from the session result in the
        # teardown below) and flags anomalies to the witness log + event
        # sink. Advisory ONLY: the witness never gates the run, and its
        # failure never propagates into the run's result path. See
        # tools/swarm/agents/witness_agent.py.
        witness_agent: Any | None = None
        witness_task: asyncio.Task[None] | None = None
        if bool((config.get("witness", {}) or {}).get("enabled", False)):
            witness_agent, witness_task = self._start_witness(
                config=config,
                reports_dir=reports_dir,
                event_sink=event_sink,
            )

        # Write session_state.json for --resume.
        try:
            (reports_dir / "session_state.json").write_text(
                json.dumps({"session_id": run_id, "started_at": datetime.now(timezone.utc).isoformat()}, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass

        # Build/refresh model client if not supplied.
        if model_client is None:
            _long_cfg = config.get("long_session", {}) or {}
            _ls_active = bool(request.long_session or _long_cfg.get("enabled", False))
            _req_timeout = (
                float(_long_cfg["request_timeout_seconds"])
                if (_ls_active and _long_cfg.get("request_timeout_seconds"))
                else None
            )
            router = self._build_router_for_config(config, _req_timeout)
            model_alias = self._resolve_model_alias(config, request)
            self._ensure_client_registered(router, config, model_alias, _req_timeout)
            model_client = router.get_client(model_alias)
        else:
            model_alias = self._resolve_model_alias(config, request)

        # Resolve goal (recon-first / interactive / preset / custom).
        goal_engine = self._c.goal_engine_cls()
        from tools.run_service.models import is_agent_attack_mode as _is_attack_mode2

        risk_profile = "high_authorized_testing" if _is_attack_mode2(mode) else "standard_authorized"
        assessment: ReconAssessment | None = None

        # Resume state.
        _resume_state: tuple[ReconAssessment, str, str] | None = None
        if request.resume_source:
            match = self._find_resume_match(request.reports_dir, request.resume_source)
            if match is not None:
                _resume_state = _load_resume_state(match, _request_to_args(request))
                if _resume_state is not None:
                    assessment = _resume_state[0]

        # Determine recon-first.
        recon_first = request.recon_first
        if recon_first is None:
            recon_first = not request.goal_name and not request.custom_goal
        if _resume_state is not None:
            recon_first = False

        # Fast mode: always runs parallel recon then auto-selects goal if none supplied.
        if mode == "fast" and _resume_state is None:
            assessment, goal = await self._fast_recon(
                request=request,
                config=config,
                config_path=config_path,
                target_ip=target_ip,
                original_target=original_target,
                resolved_ip=resolved_ip,
                resolved_domain=resolved_domain,
                reports_dir=reports_dir,
                model_client=model_client,
                model_alias=model_alias,
                risk_profile=risk_profile,
                goal_engine=goal_engine,
                decision_provider=decision_provider,
                event_sink=event_sink,
                cancellation=cancellation,
            )
            # Fast recon implies recon_first semantics for downstream context.
            recon_first = True
        elif recon_first:
            assessment, goal = await self._recon_first(
                request=request,
                config=config,
                config_path=config_path,
                target_ip=target_ip,
                original_target=original_target,
                resolved_ip=resolved_ip,
                resolved_domain=resolved_domain,
                reports_dir=reports_dir,
                model_client=model_client,
                model_alias=model_alias,
                risk_profile=risk_profile,
                goal_engine=goal_engine,
                decision_provider=decision_provider,
                event_sink=event_sink,
                cancellation=cancellation,
            )
        elif request.custom_goal.strip():
            goal = goal_engine.get("custom", request.custom_goal.strip(), risk_profile=risk_profile)
        elif request.goal_name.strip().lower() and goal_engine.is_preset(request.goal_name.strip().lower()):
            goal = goal_engine.get(request.goal_name.strip().lower(), risk_profile=risk_profile)
        else:
            # Interactive goal selection via decision provider.
            presets = goal_engine.list_presets()
            decision = Decision(
                id="",
                run_id=run_id,
                kind=DecisionKind.GOAL_SELECT,
                prompt_text="Select mission goal:",
                options=[{"name": k, "description": d} for k, d in presets]
                + [{"name": "custom", "description": "Type your own goal"}],
            )
            answer = await decision_provider.request(decision)
            if answer == "custom":
                custom_decision = Decision(
                    id="",
                    run_id=run_id,
                    kind=DecisionKind.GOAL_SELECT,
                    prompt_text="Describe your custom goal:",
                )
                custom_text = await decision_provider.request(custom_decision)
                goal = goal_engine.get("custom", custom_text or "No custom goal provided.", risk_profile=risk_profile)
            else:
                goal = goal_engine.get(answer, risk_profile=risk_profile)

        # Resume goal override.
        if _resume_state is not None:
            _rg_name, _rg_desc = _resume_state[1], _resume_state[2]
            if _rg_name:
                _rg_risk = "high_authorized_testing" if _is_attack_mode2(mode) else "standard_authorized"
                goal = goal_engine.get(_rg_name, _rg_desc, risk_profile=_rg_risk)

        # Build exploit settings.
        multi_model_consult = request.multi_model_consult
        if multi_model_consult is None:
            multi_model_consult = bool((config.get("multi_model", {}) or {}).get("enabled", False))
        exploit_settings = build_cli_exploit_settings(
            mode=mode,
            target_ip=target_ip,
            goal=goal,
            config=config,
            adaptive_exploits=request.adaptive_exploits,
            swarm=request.swarm,
            critic=request.critic,
            reflection=request.reflection,
            multi_model_enabled=bool(multi_model_consult),
            observer_mode=request.observer_mode,
            ultrathink=request.ultrathink,
            debug=request.debug,
            long_session=request.long_session,
        )
        skill_selection = _build_runtime_skill_selection(
            config=config,
            goal=goal,
            mode=mode,
            assessment=assessment if (recon_first or _resume_state is not None) else None,
            is_domain=bool(resolved_domain),
        )
        _apply_runtime_skill_selection(exploit_settings, skill_selection, config=config, goal=goal, mode=mode)

        # The primary agent and the autonomous swarm advance independently.
        # Keep separate holders so the ticker can report the live worker rather
        # than overwriting one source's phase/action state with the other's.
        _heartbeat = _RunHeartbeat()
        _swarm_heartbeat = _RunHeartbeat()

        # Swarm bridge + loop setup.
        swarm_bridge = SwarmMcpBridge()
        swarm_loop: Any = None
        swarm_task: asyncio.Task[Any] | None = None
        swarm_workspace: Path | None = None
        if request.swarm:
            swarm_loop, swarm_task, swarm_workspace = await self._setup_swarm(
                request=request,
                config=config,
                target_ip=target_ip,
                goal=goal,
                mode=mode,
                exploit_settings=exploit_settings,
                model_client=model_client,
                model_alias=model_alias,
                swarm_bridge=swarm_bridge,
                original_target=original_target,
                resolved_ip=resolved_ip,
                resolved_domain=resolved_domain,
                event_sink=event_sink,
                reports_dir=reports_dir,
                progress_heartbeat=_swarm_heartbeat,
            )

        # Activity log.
        activity = ActivityLog(reports_dir, plain=request.plain)
        activity.log("info", f"Session started: {mode} against {target_ip} with goal {goal.name}")

        # Telemetry snapshot (incremental — only new bytes are re-read).
        _telemetry_acc = _TelemetryAccumulator(usage_log_path(workspace_root_from_sources()))

        async def _ticker() -> None:
            start = time.monotonic()
            while True:
                await asyncio.sleep(15.0)
                if cancellation.cancelled:
                    return
                m, s = divmod(int(time.monotonic() - start), 60)
                _live_tel = _telemetry_acc.snapshot() or {}
                swarm_active = swarm_task is not None and not swarm_task.done() and _swarm_heartbeat.phase != "starting"
                live = _swarm_heartbeat if swarm_active else _heartbeat
                source = "swarm" if swarm_active else "agent"
                progress = {
                    "elapsed_seconds": int(time.monotonic() - start),
                    "actions": live.action,
                    "phase": live.phase,
                    "source": source,
                    "telemetry": _live_tel,
                }
                if not swarm_active:
                    progress["round"] = live.round
                await event_sink.emit(EVENT_PROGRESS, progress)
                if swarm_active:
                    ui.info(f"Swarm still running... {m}:{s:02d} elapsed ({live.action} actions, {live.phase})")
                else:
                    ui.info(
                        f"Exploit agent still running... {m}:{s:02d} elapsed "
                        f"(round {live.round}, {live.action} actions, {live.phase})"
                    )

        ticker_task = asyncio.create_task(_ticker())

        result: dict[str, Any] = {}
        # Mid-run operator checkpoint (Flow A). The loop calls this hook at the
        # verified-access / no-path milestones; the closure builds a
        # CAMPAIGN_NEXT_STEP Decision from the CheckpointContext, asks the
        # operator via the transport-neutral DecisionProvider (CLI questionary
        # or API persisted decision + WebUI), and returns a CheckpointOutcome.
        # ``_goal_box`` is a one-element mutable container so a goal transition
        # selected at the checkpoint is visible to the post-session summary +
        # RunResult (a bare rebind of the ``goal`` local would be lost). Only
        # attack mode surfaces checkpoints; recon mode is read-only propose.
        _goal_box: list[AttackGoal] = [goal]
        _objective_transitions: list[dict[str, Any]] = []
        from tools.run_service.models import is_agent_attack_mode as _ckpt_attack

        _checkpoint_enabled = _ckpt_attack(mode)

        async def _checkpoint_hook(ctx: Any) -> Any:
            """Build a CAMPAIGN_NEXT_STEP Decision from ``ctx`` and ask the operator."""
            from tools.exploit_agent.runner import CheckpointOutcome

            if not _checkpoint_enabled:
                return None
            kind = str(getattr(ctx, "kind", "") or "")
            evidence = getattr(ctx, "evidence", {}) or {}
            # Build the human-readable evidence summary the operator sees.
            if kind == "access":
                _shell = evidence.get("shell_type", "")
                _priv = evidence.get("privilege_level", "")
                _outcome = evidence.get("outcome", "compromise")
                prompt_lines = [
                    "VERIFIED ACCESS OBTAINED",
                    f"Target: {target_ip}",
                    f"Outcome: {_outcome}",
                ]
                if _shell:
                    prompt_lines.append(f"Shell type: {_shell}")
                if _priv:
                    prompt_lines.append(f"Privilege level: {_priv}")
                prompt_lines.append(f"Outcome summary: {evidence.get('outcome_summary', '')}")
                # Access-kind actions: privesc, another goal, finish, cancel.
                _presets = goal_engine.list_presets()
                _goal_opts = [{"name": k, "description": d} for k, d in _presets] + [
                    {"name": "custom", "description": "Type your own goal"},
                ]
                options = [
                    {"action": "privesc", "label": "Escalate privileges on this target"},
                    {
                        "action": "another_goal",
                        "label": "Continue with another goal on this target",
                        "goals": _goal_opts,
                    },
                    {"action": "finish", "label": "Finish and generate the report"},
                    {"action": "cancel", "label": "Cancel the run"},
                ]
            else:  # no_path
                prompt_lines = [
                    "NO VERIFIED ACCESS YET",
                    f"Target: {target_ip}",
                    f"Services detected: {evidence.get('services_detected', 0)}",
                    f"Versions identified: {evidence.get('versions_identified', 0)}",
                    f"Blocked/thrash summary: {evidence.get('blocked_summary', '')}",
                    "Research/service enumeration/vulnerability research completed; no verified foothold obtained.",
                ]
                _presets = goal_engine.list_presets()
                _goal_opts = [{"name": k, "description": d} for k, d in _presets] + [
                    {"name": "custom", "description": "Type your own goal"},
                ]
                options = [
                    {"action": "continue", "label": "Continue assessing this target with a different approach"},
                    {
                        "action": "change_goal",
                        "label": "Select a different mission goal for this target",
                        "goals": _goal_opts,
                    },
                    {"action": "finish", "label": "Finish and generate the report"},
                    {"action": "cancel", "label": "Cancel the run"},
                ]
            decision = Decision(
                id="",
                run_id=run_id,
                kind=DecisionKind.CAMPAIGN_NEXT_STEP,
                prompt_text="\n".join(prompt_lines),
                options=options,
            )
            try:
                answer = await decision_provider.request(decision)
            except (EOFError, KeyboardInterrupt):
                return CheckpointOutcome(action="finish")
            if not answer:
                return CheckpointOutcome(action="finish")
            # Answer encoding: "<action>" or "<action>:<goal_name>" for
            # change_goal/another_goal, or "<action>:custom:<custom_text>".
            _parts = answer.split(":", 2)
            _action = _parts[0]
            _new_goal_name = _parts[1] if len(_parts) > 1 else ""
            _custom_text = _parts[2] if len(_parts) > 2 else ""
            # Resolve a new objective if the operator picked a goal change.
            _objective_text = ""
            _from_goal = _goal_box[0].name
            if _action in ("change_goal", "another_goal", "privesc"):
                if _action == "privesc":
                    _new_goal = goal_engine.get(
                        "privesc", "Escalate privileges on the compromised target.", risk_profile=risk_profile
                    )
                elif _new_goal_name == "custom" and _custom_text:
                    _new_goal = goal_engine.get("custom", _custom_text, risk_profile=risk_profile)
                elif _new_goal_name and goal_engine.is_preset(_new_goal_name):
                    _new_goal = goal_engine.get(_new_goal_name, risk_profile=risk_profile)
                else:
                    # No/unknown goal name -- keep the current objective but
                    # still inject a continue-style replanning instruction.
                    _new_goal = _goal_box[0]
                _goal_box[0] = _new_goal
                _objective_transitions.append(
                    {
                        "from": _from_goal,
                        "to": _new_goal.name,
                        "at_checkpoint": kind,
                    }
                )
                _objective_text = (
                    f"NEW OBJECTIVE: {_new_goal.name} — {_new_goal.description}. "
                    f"Continue against {target_ip}. Use your existing recon context; "
                    "do not repeat failed actions; try a different approach."
                )
            return CheckpointOutcome(action=_action, objective_text=_objective_text)

        try:
            # Swarm attach callback.
            def _swarm_attach(
                session: Any,
                schemas: list[dict[str, Any]],
                policy: Any,
                config: dict[str, Any] | None = None,
            ) -> None:
                if session_attach is not None:
                    session_attach(session, schemas, policy)
                if not request.swarm:
                    return
                main_loop = asyncio.get_running_loop()
                # Snapshot/rollback (design §snapshots): pass the loaded app
                # config so the bridge's snapshot-before-destructive funnel is
                # armed. None (legacy/tests) keeps the hook inert.
                swarm_bridge.attach(session, schemas, policy, loop=main_loop, config=config)
                if swarm_loop is not None:
                    ctx = getattr(getattr(swarm_loop, "_swarm", None), "_context", None)
                    if isinstance(ctx, dict):
                        ctx["mcp_session"] = session
                        ctx["exploit_tools_schemas"] = schemas
                        ctx["main_loop"] = main_loop

            # Run the exploit session.
            try:
                result = await self._run_session(
                    model_client=model_client,
                    model_alias=model_alias,
                    target_ip=target_ip,
                    mode=mode,
                    goal=goal,
                    exploit_settings=exploit_settings,
                    config_path=config_path,
                    reports_dir=reports_dir,
                    assessment=assessment,
                    approval_prompt=None,
                    approval_provider=approval_provider,
                    swarm_attach=_swarm_attach if (request.swarm or session_attach is not None) else None,
                    heartbeat=_heartbeat,
                    original_target=original_target if resolved_domain else None,
                    resolved_ip=resolved_ip if resolved_domain else None,
                    recon_first=recon_first,
                    resume_state=_resume_state,
                    event_sink=event_sink,
                    cancellation=cancellation,
                    checkpoint_hook=_checkpoint_hook,
                )
            finally:
                if session_attach is not None:
                    session_attach(None, [], None)

            # Keep the progress ticker alive while the parallel swarm finishes;
            # cancelling it before this wait left the API with frozen status.
            if swarm_task is not None and swarm_workspace is not None:
                result = await self._wait_swarm(
                    swarm_task=swarm_task,
                    swarm_bridge=swarm_bridge,
                    swarm_workspace=swarm_workspace,
                    config=config,
                    request=request,
                    result=result,
                    event_sink=event_sink,
                    reports_dir=reports_dir,
                )
        except _EXC_GROUP_CATCH as exc:
            log_path = reports_dir / "session_error.log"
            try:
                log_path.write_text(
                    "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                    encoding="utf-8",
                )
            except OSError:
                pass
            ui.error(f"Exploitation session failed unexpectedly: {exc}")
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            await event_sink.emit(EVENT_ERROR, {"message": str(exc), "log_path": str(log_path)})
            # Deep Run Logs: the session "errored out" — mirror the crash
            # into errors.jsonl so the fixer-agent gets kind/class/traceback,
            # not just the one-line message above. Fail-open, never gates.
            try:
                from tools.run_service.tasks import _emit_service_deep_error

                await _emit_service_deep_error(
                    event_sink,
                    reports_dir,
                    exc,
                    {"phase": "attack", "response_excerpt": str(log_path)},
                    kind="tool_error",
                )
            except _EXC_GROUP_CATCH:
                pass
            return RunResult(
                run_id=run_id,
                target_ip=target_ip,
                mode=mode,
                goal_name=goal.name,
                goal_description=goal.description,
                error=str(exc),
                reports_dir=str(reports_dir),
            )
        finally:
            # Witness teardown. Runs on BOTH the success and error paths (the
            # except clause above returns through this finally). Order
            # matters: before cancelling the poll task, register the exploit
            # audit trail exposed by the session result and do one final scan
            # so the tail the poll interval did not cover is still read. The
            # whole block is best-effort — a broken witness must never raise
            # into the result path.
            if witness_agent is not None:
                try:
                    _wit_audit = str(result.get("audit_path", "") or "") if isinstance(result, dict) else ""
                    if _wit_audit and witness_agent.add_audit_path(_wit_audit):
                        witness_agent.scan_once()
                except (AttributeError, TypeError, RuntimeError, *_EXC_GROUP_CATCH):
                    pass
                try:
                    witness_agent.stop()
                except (AttributeError, TypeError, RuntimeError, *_EXC_GROUP_CATCH):
                    pass
            if witness_task is not None:
                witness_task.cancel()
                try:
                    await asyncio.wait_for(witness_task, timeout=0.5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
            ticker_task.cancel()
            try:
                await asyncio.wait_for(ticker_task, timeout=0.1)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
            RunLog.detach()
            # Deep Run Logs: flush the activity buffer so the run's final
            # <10 audit rows survive (success AND error paths share this
            # finally). Best-effort — a logging failure must not break teardown.
            try:
                activity.stop()
            except Exception:  # noqa: BLE001 -- teardown only, never gates
                pass

        # Telemetry.
        _tel = _telemetry_acc.snapshot()
        if _tel:
            result.setdefault("_telemetry", _tel)

        # Safety review (recon mode).
        safety_review_data: dict[str, Any] | None = None
        if mode == "recon":
            try:
                review = await self._c.run_safety_review(model_client, model_alias, result, target_ip, goal)
                ui.display_safety_review(review)
                safety_review_data = {
                    "safe_to_proceed": review.safe_to_proceed,
                    "concerns": getattr(review, "concerns", []),
                    "recommendations": getattr(review, "recommendations", []),
                }
            except _EXC_GROUP_CATCH as exc:
                ui.error(f"Safety review failed: {exc}")

        # Write session summary + run.json.
        summary_path = reports_dir / "session_summary.md"
        summary_lines = [
            f"# Session Summary — {target_ip}",
            "",
            f"- **Date**: {datetime.now(timezone.utc).isoformat()}",
            f"- **Target**: {target_ip}",
            f"- **Mode**: {mode}",
            f"- **Goal**: {goal.name}",
            f"- **Goal Description**: {goal.description}",
            f"- **Actions Executed**: {result.get('total_actions', 0)}",
            f"- **Workspace**: {result.get('workspace', 'unknown')}",
            f"- **Audit trail**: {result.get('audit_path', 'unknown')}",
        ]
        if _tel:
            _ctx = ""
            if _tel["avg_ctx"] is not None:
                _ctx = f", avg ctx {_tel['avg_ctx']:.0f}%"
            summary_lines.append(
                f"- **Model usage**: {_tel['total_tokens']:,} tokens across {_tel['calls']} calls{_ctx}"
            )
        _summary_skills = result.get("active_skills") or []
        if _summary_skills:
            _skill_names = ", ".join(str(s.get("name", "unknown")) for s in _summary_skills if isinstance(s, dict))
            summary_lines.append(f"- **Active skills**: {_skill_names}")
        _summary_outcome = result.get("outcome_summary")
        if _summary_outcome:
            summary_lines.append(f"- **Blocked/thrash summary**: {_summary_outcome}")
        if _objective_transitions:
            summary_lines.append("- **Objective transitions (operator-selected at checkpoints)**:")
            for _tr in _objective_transitions:
                summary_lines.append(
                    f"  - {_tr.get('from', '?')} → {_tr.get('to', '?')} (at {_tr.get('at_checkpoint', '?')} checkpoint)"
                )
        _sw = result.get("swarm_result")
        if isinstance(_sw, dict) and _sw.get("tasks_completed") is not None:
            summary_lines.extend(
                [
                    "",
                    "## Swarm",
                    "",
                    f"- **Completed**: {_sw.get('tasks_completed', 0)}",
                    f"- **Blocked**: {_sw.get('tasks_blocked', 0)}",
                    f"- **Failed**: {_sw.get('tasks_failed', 0)}",
                    f"- **Report-ready findings**: {_sw.get('findings_report_ready', 0)}",
                ]
            )
        summary_lines.extend(
            ["", "## Results", "", "See the exploit workspace for full logs, scripts, and audit trails.", ""]
        )
        summary_path.write_text("\n".join(summary_lines), encoding="utf-8")

        run_json_path = reports_dir / "run.json"
        if isinstance(result, dict):
            try:
                run_json_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
            except OSError as exc:
                ui.warning(f"Could not write run.json: {exc}")

        # Flow A enhanced report (Phase B1). Flow A's run_exploit_agent does
        # not run an AutonomousOrchestrator campaign, so EnhancedReportGenerator
        # was Flow B-only. Build a minimal campaign_result["states"] from the
        # audit records: each completed exit_code==0 record is a successful
        # action; failed/blocked records populate failed_attempts. This feeds
        # ExploitationChain + TechnicalFinding so the WebUI can render the
        # attack graph. Best-effort — never fatal to the run.
        try:
            campaign_result = _build_campaign_result_from_records(result, target_ip)
            if campaign_result is not None:
                from tools.enhanced_reporting import EnhancedReportGenerator

                generator = EnhancedReportGenerator(
                    db=None,
                    mission_id=run_id,
                    workspace=reports_dir,
                )
                paths = generator.generate_full_report(campaign_result, output_format="all")
                # Stable names so the WebUI can fetch /artifacts/enhanced/enhanced_report.{json,md,html}
                for key, stable_name in (
                    ("json", "enhanced_report.json"),
                    ("markdown", "enhanced_report.md"),
                    ("html", "enhanced_report.html"),
                ):
                    src = paths.get(key)
                    if src is not None and src.exists():
                        stable = reports_dir / "enhanced" / stable_name
                        stable.write_bytes(src.read_bytes())
        except Exception as exc:  # noqa: BLE001 -- reporting is best-effort
            ui.warning(f"Could not write enhanced report: {exc}")

        await event_sink.emit(
            EVENT_ARTIFACT,
            {
                "name": "session_summary.md",
                "reports_dir": str(reports_dir),
                "session_summary": str(summary_path),
                "run_json": str(run_json_path),
                "audit_path": result.get("audit_path", ""),
                "workspace": result.get("workspace", ""),
            },
        )

        await event_sink.emit(
            EVENT_COMPLETION,
            {
                "total_actions": result.get("total_actions", 0),
                "goal": goal.name,
                "target": target_ip,
                "mode": mode,
            },
        )

        # Apply a goal transition selected at a mid-run checkpoint: the
        # _goal_box closure variable holds the latest objective, which may
        # differ from the ``goal`` resolved at execute start.
        _final_goal = _goal_box[0]
        # Operator cancelled at a checkpoint -> surface as cancelled, not
        # completed/failed. The loop sets ``cancelled_by_operator`` in its
        # result dict; RunManager._execute_run reads RunResult.cancelled.
        _cancelled_by_operator = bool(result.get("cancelled_by_operator", False))

        _final_run_result = RunResult(
            run_id=run_id,
            target_ip=target_ip,
            mode=mode,
            goal_name=_final_goal.name,
            goal_description=_final_goal.description,
            total_actions=result.get("total_actions", 0),
            workspace=result.get("workspace", ""),
            audit_path=result.get("audit_path", ""),
            records=result.get("records", []),
            messages=result.get("messages", []),
            error=result.get("error", ""),
            swarm_result=result.get("swarm_result"),
            active_skills=result.get("active_skills", []),
            outcome_summary=result.get("outcome_summary", ""),
            telemetry=_tel,
            safety_review=safety_review_data,
            reports_dir=str(reports_dir),
            summary_path=str(summary_path),
            run_json_path=str(run_json_path),
            cancelled=_cancelled_by_operator,
            objective_transitions=list(_objective_transitions),
        )
        RunLog.detach()
        return _final_run_result

    # ------------------------------------------------------------------
    # Witness side task (advisory; never gates the run)
    # ------------------------------------------------------------------

    def _start_witness(
        self,
        config: dict[str, Any],
        reports_dir: Path,
        event_sink: EventSink,
    ) -> tuple[Any | None, asyncio.Task[None] | None]:
        """Start the advisory witness watcher for this run.

        Constructs the agent through the ``Callables.witness_agent_factory``
        seam (tests stub it there) and spawns a side task that polls
        ``scan_once()`` every ``witness.poll_interval_seconds``. Returns
        ``(None, None)`` — current behavior, byte-identical — when
        ``witness.enabled`` is false or the agent cannot be constructed.

        The witness's ``event_callback`` is a SYNC callable but
        ``event_sink.emit`` is a coroutine, so escalation bridges through the
        running loop captured here (``loop.create_task(event_sink.emit(...))``
        from inside the sync callback). A broken sink must never kill the
        witness, and the witness must never break the run — hence the guards.
        """
        witness_cfg = config.get("witness", {}) or {}
        if not bool(witness_cfg.get("enabled", False)):
            return None, None
        loop = asyncio.get_running_loop()
        escalate = bool(witness_cfg.get("escalate_to_event_broker", True))

        def _on_witness_flag(event: str, payload: dict[str, Any]) -> None:
            try:
                loop.create_task(event_sink.emit(event, payload))
            except (RuntimeError, *_EXC_GROUP_CATCH):
                pass

        try:
            interval = float(witness_cfg.get("poll_interval_seconds", 5.0) or 5.0)
        except (TypeError, ValueError):
            interval = 5.0

        try:
            agent = self._c.witness_agent_factory(
                config,
                audit_paths=[reports_dir / "activity.jsonl"],
                event_callback=_on_witness_flag if escalate else None,
            )
        except (TypeError, ValueError, RuntimeError, *_EXC_GROUP_CATCH) as exc:
            ui.warning(f"Witness watcher unavailable (advisory, run continues): {exc}")
            return None, None

        async def _witness_poll() -> None:
            while True:
                await asyncio.sleep(interval)
                try:
                    agent.scan_once()
                except _EXC_GROUP_CATCH:
                    pass

        return agent, asyncio.create_task(_witness_poll())
