"""Campaign executor — AttackModuleExecutor.

Canonical source for AttackModuleExecutor.
Moved from tools.autonomous_orchestrator to break the god file.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import time
from typing import Any, Callable

from tools.attack_modules import AttackModule, ModuleContext, ModuleResult, _module_target_signature
from tools.attack_planner import StepContext
from tools.attack_ui import get_ui
from tools.exceptions import _EXC_GROUP_CATCH
from tools.failure_taxonomy import classify_failure
from tools.logging_setup import get_logger

from tools.campaign.state import (
    AggressionLevel,
    AttackPhase,
    AttackState,
    AttackTask,
    TaskStatus,
    _report_autonomous_progress,
)

logger = get_logger()
ui = get_ui()


def _result_evidence(result: Any) -> list[str]:
    """Pull human-readable evidence strings out of a module result dict."""
    if not isinstance(result, dict):
        return [str(result)[:500]] if result else ["no evidence returned"]
    out: list[str] = []
    ev = result.get("evidence")
    if isinstance(ev, list):
        out.extend(str(e)[:500] for e in ev)
    for key in ("note", "status"):
        val = result.get(key)
        if val:
            out.append(str(val)[:500])
    return out[:10] or ["no evidence returned"]


class AttackModuleExecutor:
    """Executes attack modules with scope checking, evidence capture, and retry logic."""

    def __init__(
        self,
        scope_gate: Any | None = None,
        risk_controller: Any | None = None,
        evidence_store: Any | None = None,
        *,
        blackboard: dict[str, Any] | None = None,
        mission_config: dict[str, Any] | None = None,
        model_client: Any = None,
        critic_agent: Any = None,
        reflection_agent: Any = None,
        tool_executor: Callable[[str, dict[str, Any]], str] | None = None,
        opsec_manager: Any | None = None,
        semantic_memory: Any | None = None,
        experience_store: Any | None = None,
    ) -> None:
        self._scope_gate = scope_gate
        self._risk_controller = risk_controller
        self._evidence_store = evidence_store
        # Phase 1: Bayesian ExperienceStore for the orchestrator's module-run
        # learning loop. Distinct from ``_evidence_store`` (the per-attempt
        # evidence capture). When wired (AutonomousOrchestrator passes its
        # self._experience_store through), execute() records each module run
        # outcome so find_modules on the next campaign reflects orchestrator
        # history. None (legacy callers, most tests) -> best-effort skip.
        self._experience_store = experience_store
        # Phase 6.2: optional OpsecManager. When wired (AutonomousOrchestrator
        # builds one from the ``opsec`` config block), execute() awaits
        # ``acquire_pacing(task.aggression.value)`` before each module run so
        # AggressionLevel.STEALTH becomes load-bearing (max jitter + min-gap +
        # rate bucket). Unwired / disabled profile -> pacing_delay is 0.0 and
        # acquire_pacing is a no-op, so legacy callers and tests are unchanged.
        self._opsec = opsec_manager
        # D1: optional SemanticMemoryManager. When wired (AutonomousOrchestrator
        # builds one from the ``orchestrator.semantic_memory`` config flag),
        # execute() calls store_lesson on a confirmed win so the campaign
        # learns across missions. No-op when None (the default opt-in state).
        self._semantic_memory = semantic_memory
        # Phase 2.1: the optional tool_executor lets execute() actually DISPATCH
        # a module's suggested_command / generated script and capture the real
        # output, instead of treating the module's dict as dead data. When wired
        # (AutonomousOrchestrator passes its own _tool_executor through), a
        # script/suggested_command is run, the output is classified via
        # ``classify_exploit_result``, and ``shell_type`` / ``privilege_level``
        # are only set when a real compromise marker (meterpreter / uid=0 / NT
        # AUTHORITY\SYSTEM) appears -- so ``access_achieved`` and the downstream
        # privesc/lateral phases only fire on a verified foothold. Unwired
        # (legacy callers, most tests) -> behaves exactly as before: module
        # dicts pass through unchanged.
        self._tool_executor: Callable[[str, dict[str, Any]], str] | None = tool_executor
        # Swarm integration (Tier 0 item 0.6b): the autonomous attack path
        # previously ran modules with only inline scope/risk checks and NO
        # multi-layer critic, NO reflection, and NO shared blackboard -- so the
        # most aggressive path bypassed all the swarm's multi-layer reasoning.
        # When wired (agent_loop passes the swarm's LIVE blackboard + fresh
        # CriticAgent/ReflectionAgent), execute() runs a critic pre-check (deny
        # blocks, modify mutates), records module outcomes to the shared
        # blackboard (so the critic's repeat-failure detection fires), and runs
        # a reflection post-check that publishes patterns/strategy-shifts.
        # Unwired (legacy callers, most tests) -> behaves exactly as before:
        # every helper below is a no-op when its agent/blackboard is absent.
        self._blackboard: dict[str, Any] = blackboard if blackboard is not None else {}
        self._mission_config: dict[str, Any] = mission_config or {}
        self._model_client = model_client
        self._critic = critic_agent
        self._reflection = reflection_agent
        self._action_count = 0
        # Snapshot/rollback (design §snapshots): lazily-built in
        # _snapshot_before_destructive; None until a destructive dispatch
        # first needs it (opt-in — snapshots.enabled defaults false).
        self._snapshot_mgr: Any | None = None

    async def execute(
        self,
        task: AttackTask,
        state: AttackState,
    ) -> dict[str, Any]:
        """Execute an attack module with full lifecycle management."""
        task.status = TaskStatus.RUNNING
        task.started_at = time.monotonic()
        self._action_count += 1
        action_num = self._action_count

        logger.info(f"Executing {task.module_name} against {task.target} (attempt {task.retry_count + 1})")
        # Surface each module dispatch to the operator so a long campaign shows
        # which attack module is running against which target in which phase.
        ui.action_status(
            action_num=action_num,
            tool=task.module_name,
            target=task.target,
            phase=task.phase.value,
        )
        _report_autonomous_progress(
            action=action_num,
            attempt=task.retry_count + 1,
            phase=task.phase.value,
            target=task.target,
            tool=task.module_name,
        )
        state.add_timeline_event(
            "module_execution",
            f"Executing {task.module_name} against {task.target}",
            {"attempt": task.retry_count + 1, "aggression": task.aggression.value},
        )

        # Scope check — fail closed: with no gate wired there is no authorized
        # attack step, so block rather than run ungated (NEVER add a host
        # fallback or permissive path here).
        if self._scope_gate is None:
            task.status = TaskStatus.BLOCKED
            task.error = "Scope blocked: no scope gate wired (fail-closed)"
            state.add_timeline_event("blocked", task.error)
            return {"success": False, "error": task.error, "blocked": True}
        scope_result = self._scope_gate.check_scope(
            asset=task.target,
            action_type=task.phase.value,
            tool_name=task.module_name,
            risk_level="high" if task.aggression == AggressionLevel.MAXIMUM else "medium",
        )
        if not scope_result.allowed:
            task.status = TaskStatus.BLOCKED
            task.error = f"Scope blocked: {scope_result.reason}"
            state.add_timeline_event("blocked", task.error)
            return {"success": False, "error": task.error, "blocked": True}

        # Risk check
        if self._risk_controller:
            if not self._risk_controller.can_proceed():
                task.status = TaskStatus.BLOCKED
                task.error = "Risk budget exhausted"
                return {"success": False, "error": task.error, "blocked": True}

        # Critic pre-check (Tier 0 item 0.6b): defense-in-depth on top of the
        # inline scope/risk checks above. When a CriticAgent is wired, it adds
        # forbidden-action, risk-profile, repeat-failure, and (optionally) LLM
        # reasoning. A "deny" blocks the run before any module code runs; a
        # "modify" mutates the task (aggression/risk downgrade, require_mutation
        # flag) and the run proceeds with the mutated task. Returns None when no
        # critic is wired (legacy path: only the inline checks above apply).
        critic_decision = await asyncio.to_thread(self._run_critic, task)
        if critic_decision is not None:
            decision = critic_decision.get("decision", "approve")
            if decision == "deny":
                task.status = TaskStatus.BLOCKED
                task.error = f"Critic denied: {critic_decision.get('reasoning', '')}"
                state.add_timeline_event("critic_deny", task.error)
                self._record_failure_on_blackboard(task.module_name)
                return {
                    "success": False,
                    "error": task.error,
                    "blocked": True,
                    "critic": critic_decision,
                }
            if decision == "modify":
                self._apply_critic_modifications(task, critic_decision.get("modifications", {}))
                state.add_timeline_event(
                    "critic_modify",
                    f"Critic modified {task.module_name}: {critic_decision.get('reasoning', '')}",
                )

        # Get module
        # shim-aware lookup: tests patch tools.autonomous_orchestrator.get_module
        try:
            import tools.autonomous_orchestrator as _ao_shim  # type: ignore[import]

            _get_module = getattr(_ao_shim, "get_module", None)
        except Exception:
            _get_module = None
        if _get_module is None:
            from tools.attack_modules import get_module as _get_module  # type: ignore[import]
        module = _get_module(task.module_name)
        if not module:
            task.status = TaskStatus.FAILED
            task.error = f"Module {task.module_name} not found"
            state.record_failure(task.module_name, task.error)
            self._record_failure_on_blackboard(task.module_name)
            return {"success": False, "error": task.error}

        # Build context -- carry version + CPE so the module's
        # generate_dynamic_script records the correct service:version:os
        # signature for the ExperienceStore (audit: version was dropped here
        # too, so historical confidence never applied).
        # Phase 1/2: also thread the recovered credentials, the task's
        # parameters (e.g. {"exploit": ...} for ValidateFinding, callback_host
        # for persistence), and the mission config so post-exploit modules
        # (LateralMovement, ValidateFinding, persistence) can read them.
        ctx = ModuleContext(
            target_ip=task.target,
            target_os=state.recon_result.os_family if state.recon_result else None,
            services=[
                {
                    "service": s.service,
                    "port": f"{s.port}/{s.protocol}",
                    "version": s.version,
                    "cpe": list(s.cpe),
                    "banner": s.banner,
                }
                for s in (state.recon_result.services if state.recon_result else [])
            ],
            credentials=list(state.credentials_found),
            parameters=dict(task.parameters),
            config=self._mission_config,
            # Capability-upgrade (§12): thread live attack state so modules
            # can reason about prerequisites (foothold/privilege/sessions)
            # and prior evidence without raw logs. Additive; the defaults in
            # ModuleContext keep every other construction site byte-identical.
            access_achieved=state.access_achieved,
            privilege_level=state.privilege_level,
            sessions=([{"shell": state.shell_type}] if state.access_achieved and state.shell_type else []),
            phase=state.current_phase.value,
            evidence_refs=list(state.loot)[-10:],
        )

        # Phase 6.2: OPSEC pacing. Await the profile's pacing delay (jittered,
        # aggression-scaled) + optional rate bucket before the module runs. A
        # disabled profile or unwired manager makes this a no-op. Wrapped so an
        # OPSEC hiccup can never block an authorized attack step.
        #
        # Phase 6.2+ (target-aware OPSEC): resolve the effective manager against
        # THIS task's target so the operator-intent toggle bites per action --
        # local/private target -> disabled profile -> pacing no-op (the operator
        # owns the box, let the AI move freely); public target -> configured
        # posture (pacing/UA-rotation/quiet-commands ON). Resolving per-task
        # (rather than once at campaign start) keeps pivot targets correct:
        # ``OpsecManager.resolve_for_target`` returns ``self`` for a public
        # target (zero overhead) and a disabled manager for a local one. The
        # ``getattr`` guard keeps legacy/test fakes without the method working.
        if self._opsec is not None:
            try:
                mgr = self._opsec
                resolver = getattr(self._opsec, "resolve_for_target", None)
                if resolver is not None and task.target:
                    mgr = resolver(task.target)
                await mgr.acquire_pacing(task.aggression.value)
            except Exception as exc:  # noqa: BLE001 -- pacing is best-effort
                logger.debug(f"OPSEC pacing skipped for {task.module_name}: {exc}")

        # Execute with timeout
        try:
            timeout = task.parameters.get("timeout", 300)
            module_run = asyncio.to_thread(module.run, ctx)
            try:
                result = await asyncio.wait_for(module_run, timeout=timeout)
            except asyncio.TimeoutError:
                if inspect.iscoroutine(module_run):
                    module_run.close()
                raise

            # Phase 2.1: adapt the module's dict return into a typed
            # ModuleResult, then -- when a tool_executor is wired -- actually
            # DISPATCH any runnable artifact (suggested_command or generated
            # script) and classify the real output. Previously the module's
            # suggested_command / script keys were dead data on Path B (counted
            # as succeeded but never executed), so ``access_achieved`` was never
            # set and the downstream privesc / lateral phases never fired. Now a
            # real shell marker (meterpreter / uid=0 / NT AUTHORITY\SYSTEM) in
            # the dispatch output sets ``shell_type`` / ``privilege_level``, and
            # ``record_success`` flips ``access_achieved`` only on that verified
            # signal. Info-stub modules (status=info with no runnable script)
            # skip dispatch and stay info-stubs, so they never falsely set
            # access_achieved. Unwired (no tool_executor) -> the module's own
            # dict passes through unchanged, preserving legacy behavior.
            mresult = ModuleResult.to_result(result)
            dispatch_failure = False
            if self._tool_executor is not None and mresult.status not in ("info",):
                dispatch_out = await self._dispatch_module_artifact(module, mresult, ctx, task, state)
                if dispatch_out is not None:
                    output, classification = dispatch_out
                    # Merge real-output evidence onto the typed result.
                    if classification.get("evidence"):
                        mresult.evidence.extend(classification["evidence"])
                    outcome = str(classification.get("outcome", "unknown")).lower()
                    if outcome == "compromise":
                        # Verified shell -- set the keys record_success reads.
                        if classification.get("shell_type"):
                            mresult.shell_type = str(classification["shell_type"])
                        if classification.get("privilege_level"):
                            mresult.privilege_level = str(classification["privilege_level"])
                        state.add_timeline_event(
                            "compromise_verified",
                            f"{task.module_name} produced verified shell "
                            f"({mresult.shell_type or 'shell'}) against {task.target}",
                            {"outcome": outcome, "evidence": classification.get("evidence", [])},
                        )
                    elif outcome == "cred_dump":
                        # Credentials marker -- record as a credential string so
                        # record_success picks it up via result["credentials"].
                        mresult.credentials_found.append(
                            f"dump:{task.module_name}:{classification.get('evidence', ['creds'])[0]}"
                        )
                        state.add_timeline_event(
                            "cred_dump_verified",
                            f"{task.module_name} produced a credential dump against {task.target}",
                            {"evidence": classification.get("evidence", [])},
                        )
                    elif outcome == "failure":
                        # The dispatched artifact ran but explicitly failed -- do
                        # NOT count this as a succeeded module. The script may
                        # have been generated (status=script_generated) but the
                        # actual exploit failed, so mark it failed for retry.
                        dispatch_failure = True
                        if not mresult.note:
                            mresult.note = "Dispatched artifact reported failure markers"
                        state.add_timeline_event(
                            "dispatch_failure",
                            f"{task.module_name} dispatch output signalled failure",
                            {"evidence": classification.get("evidence", [])},
                        )
                    # 'partial' / 'unknown' -> ran but no verified compromise;
                    # leave shell_type empty so access_achieved stays False.

            # Convert the (possibly enriched) ModuleResult back to the dict shape
            # the renderer / record_success / task.result expect. Pass-through
            # extra keys are preserved by to_dict().
            result = mresult.to_dict()

            # Phase 1: feed this module run into the ExperienceStore so the
            # Bayesian learning loop reflects orchestrator history, not just
            # the exploit-agent loop. Best-effort -- a None store (legacy
            # callers) or a module with no target signature (no target_services)
            # is silently skipped. Maps info -> partial (neutral), real
            # compromise -> success, failure -> failure. This is the missing
            # wiring that makes find_modules on the next campaign prefer
            # proven modules and demote known-bad ones.
            if self._experience_store is not None:
                try:
                    sig = _module_target_signature(module, ctx)
                    if sig is not None:
                        self._experience_store.record_module_outcome(
                            target_signature=sig,
                            module_name=module.name,
                            status_str=str(result.get("status", "")),
                            metadata={"target": task.target, "phase": state.current_phase.value},
                        )
                except Exception:  # noqa: BLE001 -- learning loop is best-effort
                    logger.debug(f"ExperienceStore record skipped for {module.name}")

            # Process result
            task.result = result
            # A module that ran but did not achieve exploitation is NOT a success:
            # the retry/mutation loop (_execute_task_batch), lateral recursion
            # (_attack_target), and reflection (_run_reflection) all key off
            # result["success"] / task.status, so a ran-but-failed module must
            # report success=False and TaskStatus.FAILED -- otherwise failed
            # modules are counted as completed and never retried.
            # Phase 1: stop counting status="info" as _succeeded. Info-stub
            # modules produce no runnable artifact and no compromise signal --
            # counting them as success was a silent false-positive that left
            # ValidateFinding/LateralMovement "succeeding" without ever
            # dispatching (the dispatcher at line 659 correctly skips info
            # status, but _succeeded then counted them as wins). Now only
            # success/exploited/script_generated count as succeeded; info
            # modules are recorded as failures so the retry loop can re-queue
            # them with a dispatchable status (the module recipe must emit
            # script/suggested_command to actually win).
            _succeeded = result.get("status") in ("success", "exploited", "script_generated") and not dispatch_failure
            task.status = TaskStatus.COMPLETED if _succeeded else TaskStatus.FAILED
            task.completed_at = time.monotonic()

            if _succeeded:
                state.record_success(task.module_name, result)
                state.add_timeline_event(
                    "success",
                    f"{task.module_name} succeeded against {task.target}",
                    {"result_type": result.get("status")},
                )
                logger.info(f"Module {task.module_name} succeeded against {task.target}")
                self._record_success_on_blackboard(task.module_name)
                # D1: persist a cross-mission lesson on a confirmed win so the
                # campaign learns across missions, not just within the exploit
                # loop. Best-effort — store_lesson skips + logs when Ollama is
                # down, and a None manager makes this a no-op. Distinct
                # action_type keeps this from polluting the operational
                # exploit-action confidence rows in the ExperienceStore.
                await asyncio.to_thread(self._record_lesson_on_success, task, state, result)
            else:
                task.error = result.get("note", "Module did not achieve exploitation")
                state.record_failure(task.module_name, task.error)
                state.add_timeline_event("failure", f"{task.module_name} did not achieve exploitation")
                self._record_failure_on_blackboard(task.module_name)

            # Reflection post-check (Tier 0 item 0.6b): feed this attempt into the
            # ReflectionAgent. The agent updates the shared blackboard itself
            # (last_reflection / strategy_shift / failed_modules); it is
            # heuristic-only when no model_client is wired, so per-module cost is
            # low. Advisory -- exceptions are swallowed so reflection can't stall
            # the campaign. No-op when no reflection agent is wired.
            await asyncio.to_thread(
                self._run_reflection,
                task,
                state,
                {"success": _succeeded, "result": result},
            )

            return {"success": _succeeded, "result": result}

        except asyncio.TimeoutError:
            task.status = TaskStatus.FAILED
            task.error = f"Timeout after {timeout}s"
            state.record_failure(task.module_name, task.error)
            state.add_timeline_event("timeout", task.error)
            logger.warning(f"Module {task.module_name} timed out against {task.target}")
            self._record_failure_on_blackboard(task.module_name)
            return {"success": False, "error": task.error, "timeout": True}

        except Exception as exc:
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            state.record_failure(task.module_name, task.error)
            state.add_timeline_event("error", f"Exception in {task.module_name}: {task.error}")
            logger.exception(f"Module {task.module_name} failed against {task.target}")
            self._record_failure_on_blackboard(task.module_name)
            return {"success": False, "error": task.error}

    async def execute_plan_step(self, step: StepContext) -> dict[str, Any]:
        """Run ONE planner step with no cross-step memory (FSM executor role).

        Takes only a StepContext (target/tool/arguments/expected evidence) --
        never a plan, battle log, or history. Builds an ephemeral AttackTask /
        AttackState, runs it through execute(), and folds the outcome into
        ``{"success", "evidence", "failure_class"}`` for
        ``tools.attack_planner.record_step_result``. Scope gating stays inside
        execute() (fail-closed); a scope block maps to ``scope_blocked``.
        """
        task = AttackTask(
            task_id=f"FSM-{self._action_count + 1:05d}",
            phase=self._campaign_phase_for(step.phase),
            module_name=step.tool,
            target=step.target_ip,
            parameters=dict(step.arguments),
        )
        state = AttackState(target=step.target_ip)
        try:
            raw = await self.execute(task, state)
        except _EXC_GROUP_CATCH as exc:
            err = f"{type(exc).__name__}: {exc}"[:2000]
            task.failure_class = classify_failure(err).value
            return {
                "success": False,
                "evidence": [err],
                "failure_class": task.failure_class,
                "tool": step.tool,
                "target_ip": step.target_ip,
            }
        if raw.get("success"):
            task.failure_class = ""
            return {
                "success": True,
                "evidence": _result_evidence(raw.get("result")),
                "failure_class": "",
                "tool": step.tool,
                "target_ip": step.target_ip,
            }
        err = str(raw.get("error") or "unknown failure")[:2000]
        # Fail-closed scope blocks are scope_blocked even when the message
        # misses the taxonomy regexes (never retry a blocked step blindly).
        task.failure_class = "scope_blocked" if raw.get("blocked") else classify_failure(err).value
        return {
            "success": False,
            "evidence": [err],
            "failure_class": task.failure_class,
            "tool": step.tool,
            "target_ip": step.target_ip,
        }

    @staticmethod
    def _campaign_phase_for(planner_phase: str) -> AttackPhase:
        """Map a planner phase value to the campaign enum (never raises)."""
        try:
            # ponytail: lazy import -- planner_adapter pulls the
            # autonomous_orchestrator shim, which re-exports this module.
            from tools.intelligence.adapters.planner_adapter import AttackPhaseBridge

            mapped = AttackPhaseBridge.to_orchestrator(planner_phase)
        except _EXC_GROUP_CATCH:
            mapped = None
        return mapped if mapped is not None else AttackPhase.RECONNAISSANCE

    # ── Phase 2.1 dispatch helper ───────────────────────────────────────────

    async def _dispatch_module_artifact(
        self,
        module: AttackModule,
        mresult: ModuleResult,
        ctx: ModuleContext,
        task: AttackTask,
        state: AttackState,
    ) -> tuple[str, dict[str, Any]] | None:
        """Dispatch a module's runnable artifact through ``self._tool_executor``.

        Resolves the artifact to a shell command in priority order:

        1. ``mresult.suggested_command`` -- a ready-to-run shell command
           (e.g. ``sqlmap -u ...``). Used as-is.
        2. ``mresult.script`` (or ``module.generate_python_script(ctx)``) -- a
           Python script string. Written to
           ``<workspace>/modules/<module>_<ip>.py`` and dispatched as
           ``python <path> <target_ip>``.

        Returns ``(output_text, classification_dict)`` on dispatch, or ``None``
        when there is nothing runnable (no command, no script) or the
        tool_executor raises (best-effort: the exception is recorded as a
        timeline event and we return ``None`` so the caller treats the module
        as a non-verified run, NOT a hard failure -- the script itself may be
        valid and just need a manual operator run).

        The classification comes from ``classify_exploit_result`` (Phase 1.1),
        imported lazily so a missing dep never breaks the executor. The
        classifier is conservative: only strong shell / uid=0 / Meterpreter /
        NT AUTHORITY\\SYSTEM markers yield ``compromise``.
        """
        executor = self._tool_executor
        if executor is None:
            return None

        # 1. suggested_command wins -- it's already a complete shell invocation.
        command = mresult.suggested_command or ""
        if not command:
            # 2. Fall back to the module's generated Python script.
            script_text = mresult.script
            if not script_text:
                try:
                    script_text = module.generate_python_script(ctx) or ""
                except Exception:
                    script_text = ""
            if script_text:
                try:
                    modules_dir = ctx.workspace / "modules"
                    modules_dir.mkdir(parents=True, exist_ok=True)
                    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{module.name}_{ctx.target_ip}.py")
                    script_path = modules_dir / safe_name
                    script_path.write_text(script_text, encoding="utf-8")
                    command = f"python {script_path} {ctx.target_ip}"
                except Exception as exc:  # noqa: BLE001 -- best-effort
                    state.add_timeline_event(
                        "dispatch_write_err",
                        f"Failed to write script for {module.name}: {exc}",
                    )
                    return None

        if not command:
            return None

        # ── Snapshot before destructive dispatch (design §snapshots) ────────
        # Fail-open and additive: when snapshots are enabled AND the artifact
        # command is destructive, take an infrastructure snapshot first so the
        # Path-B funnel (no-MCP module dispatch) gets the same rollback story
        # as the MCP loop. A failure only logs — never blocks the dispatch.
        await self._snapshot_before_destructive(task, state, command)

        # ── Fail-closed target lock before dispatch ─────────────────────────
        # No scope gate, a missed/failed scope check, or an off-allowlist
        # command blocks the dispatch (fail closed; NEVER a host-execution
        # fallback). A failure classification makes the caller mark FAILED.
        block_reason = self._dispatch_block_reason(command, task)
        if block_reason is not None:
            state.add_timeline_event(
                "dispatch_blocked",
                f"{module.name} dispatch blocked: {block_reason}",
                {"command": command[:200]},
            )
            return "", {"outcome": "failure", "shell_type": "", "privilege_level": "", "evidence": [block_reason]}

        try:
            output = await asyncio.to_thread(executor, command, {"target": task.target})
        except Exception as exc:  # noqa: BLE001 -- best-effort dispatch
            state.add_timeline_event(
                "dispatch_err",
                f"{module.name} dispatch raised: {exc}",
                {"command": command[:200]},
            )
            return None

        output_text = str(output or "")
        state.add_timeline_event(
            "module_dispatch",
            f"Dispatched {module.name} artifact ({len(output_text)} bytes output)",
            {"command": command[:200], "output_len": len(output_text)},
        )

        # Conservative classification (Phase 1.1). Lazy import -- the dep lives
        # in tools/exploit_agent which is always present in the runtime, but the
        # import is deferred so a stale/missing module never breaks the
        # executor's hot path.
        try:
            from tools.exploit_agent.outcome_classify import classify_exploit_result

            classification = classify_exploit_result(output_text)
        except Exception:
            classification = {"outcome": "unknown", "shell_type": "", "privilege_level": "", "evidence": []}

        return output_text, classification

    def _dispatch_block_reason(self, command: str, task: AttackTask) -> str | None:
        """Fail-closed gate for artifact dispatch (None = proceed).

        Blocks when no scope gate is wired, the scope check misses/fails, or
        the existing ``_target_lock_block`` flags an off-allowlist destination.
        """
        if self._scope_gate is None:
            return "no scope gate wired (fail-closed)"
        try:
            scope_result = self._scope_gate.check_scope(
                asset=task.target,
                action_type=task.phase.value,
                tool_name=task.module_name,
                risk_level="high" if task.aggression == AggressionLevel.MAXIMUM else "medium",
            )
        except Exception as exc:  # noqa: BLE001 -- a broken gate blocks, never passes
            return f"scope check raised: {exc}"
        if not scope_result.allowed:
            return f"Scope blocked: {scope_result.reason}"
        try:
            from tools.mcp_tools.terminal import _target_lock_block

            return _target_lock_block(command, self._mission_config)
        except Exception as exc:  # noqa: BLE001 -- a broken lock blocks, never passes
            return f"target-lock check raised: {exc}"

    async def _snapshot_before_destructive(
        self,
        task: AttackTask,
        state: AttackState,
        command: str,
    ) -> None:
        """Take an auto-snapshot before a destructive Path-B dispatch (fail-open).

        Mirrors the exploit-loop hook: gated on ``snapshots.enabled`` +
        ``snapshots.auto_before_destructive`` + a destructive command (via
        ``tools.snapshots.should_snapshot`` — module names are not in the tool
        category map, so Path-B reduces to destructive-command detection, the
        conservative choice). The manager is built lazily and cached; any
        failure is a timeline event only.
        """
        try:
            from tools.snapshots import SnapshotManager, should_snapshot

            if not should_snapshot(task.module_name, command, self._mission_config):
                return
            if getattr(self, "_snapshot_mgr", None) is None:
                workspace = str(self._mission_config.get("workspace", ".") or ".")
                self._snapshot_mgr = SnapshotManager(
                    self._mission_config,
                    index_dir=workspace,
                )
            mgr = self._snapshot_mgr
            label = f"pre-{task.module_name}-{task.retry_count + 1}"
            ref = await asyncio.to_thread(mgr.before_destructive, task.target, label)
            if ref is not None:
                state.add_timeline_event(
                    "snapshot_taken",
                    f"Snapshot {ref.snapshot_id} ({ref.provider}) before {task.module_name}",
                    {"snapshot_id": ref.snapshot_id, "provider": ref.provider, "label": ref.label},
                )
        except Exception as exc:  # noqa: BLE001 -- fail-open by contract
            state.add_timeline_event(
                "snapshot_err",
                f"Snapshot before {task.module_name} failed (continuing): {exc}",
            )

    # ── Swarm integration helpers (Tier 0 item 0.6b) ───────────────────────
    #
    # Every helper is a no-op when its agent/blackboard is absent, so legacy
    # callers and the existing test suite (which construct the executor with
    # only a scope_gate/risk_controller) are unchanged. They activate only when
    # agent_loop wires the swarm context into the autonomous orchestrator.

    def _run_critic(self, task: AttackTask) -> dict[str, Any] | None:
        """Run the CriticAgent pre-check.

        Returns None when no critic is wired (legacy path: only the inline
        scope/risk checks above apply). A returned dict carries
        decision/reasoning/modifications. The critic performs its OWN
        scope/risk checks, so this is defense-in-depth, not a substitute for
        the inline checks. A critic EXCEPTION denies (fail closed): unlike the
        inline checks it is the last reasoning layer before module code runs,
        so a crashed critic must not silently green-light the run.
        """
        if self._critic is None:
            return None
        proposed = {
            "target": task.target,
            "phase": task.phase.value,
            "tool": task.module_name,
            "module_name": task.module_name,
            "risk_level": "high" if task.aggression == AggressionLevel.MAXIMUM else "medium",
            "aggression": task.aggression.value,
        }
        context = {
            "scope_gate": self._scope_gate,
            "risk_controller": self._risk_controller,
            "mission": self._mission_config,
            "model_client": self._model_client,
            "blackboard": self._blackboard,
        }
        try:
            result = self._critic.run(
                {"task_id": task.task_id, "proposed_action": proposed},
                context,
            )
            if result and result.output:
                return dict(result.output)
        except Exception as exc:  # fail closed -- see docstring
            logger.warning(
                "Critic pre-check raised for %s (denying): %r",
                task.module_name,
                exc,
            )
            return {"decision": "deny", "reasoning": f"critic error (fail-closed): {exc}"}
        return None

    def _apply_critic_modifications(self, task: AttackTask, modifications: dict[str, Any]) -> None:
        """Apply a critic 'modify' decision to the task in place.

        Honors risk-level downgrades (mapped back to an aggression level) and a
        ``require_mutation`` flag (recorded for the retry engine / mutator).
        Unknown modifications are ignored -- the run proceeds with the mutated
        task rather than being blocked, since the critic only downgrades risk.
        """
        if not modifications:
            return
        risk_level = modifications.get("risk_level")
        if risk_level == "medium" and task.aggression == AggressionLevel.MAXIMUM:
            task.aggression = AggressionLevel.AGGRESSIVE
            task.parameters["critic_risk_downgrade"] = "high->medium"
        elif risk_level == "low" and task.aggression in (
            AggressionLevel.MAXIMUM,
            AggressionLevel.AGGRESSIVE,
        ):
            task.aggression = AggressionLevel.NORMAL
            task.parameters["critic_risk_downgrade"] = "->low"
        if modifications.get("require_mutation"):
            task.parameters["critic_require_mutation"] = True
        logger.info("Critic modify applied to %s: %s", task.module_name, modifications)

    def _record_failure_on_blackboard(self, module_name: str) -> None:
        """Record a module failure on the shared blackboard.

        Feeds the CriticAgent's repeat-failure detection (Layer 4) so a
        re-attempt of the same failing module on the autonomous path is flagged
        for modification. No-op when no blackboard is wired (empty dict).

        Uses ``Blackboard.append_to`` (atomic, dedupe via extend_list) so the
        write is safe even if the swarm ``route()`` loop is concurrently
        touching ``failed_modules`` via the reflection agent — the legacy
        ``bb.setdefault(...)`` + in-place ``.append`` mutated the list outside
        any lock and raced under the shared-blackboard model.
        """
        bb = self._blackboard
        if not bb:
            return
        # extend_list with dedupe=True gives the "append if absent" semantics
        # the old setdefault+append had, atomically.
        if hasattr(bb, "extend_list"):
            bb.extend_list("failed_modules", [module_name])
        else:  # legacy plain-dict fallback (defensive)
            failed = bb.setdefault("failed_modules", [])
            if module_name not in failed:
                failed.append(module_name)

    def _record_success_on_blackboard(self, module_name: str) -> None:
        """Record a module success on the shared blackboard.

        Clears the module from the repeat-failure list (so the critic stops
        flagging it) and notes it as successful. No-op when no blackboard wired.

        Atomic via ``Blackboard.remove_from_list`` / ``append_to`` so the
        failed→successful transition is safe against a concurrent reflection
        agent merge.
        """
        bb = self._blackboard
        if not bb:
            return
        if hasattr(bb, "remove_from_list"):
            bb.remove_from_list("failed_modules", module_name)
            bb.append_to("successful_modules", module_name)
        else:  # legacy plain-dict fallback (defensive)
            failed = bb.get("failed_modules")
            if failed and module_name in failed:
                failed.remove(module_name)
            worked = bb.setdefault("successful_modules", [])
            if module_name not in worked:
                worked.append(module_name)

    def _run_reflection(self, task: AttackTask, state: AttackState, result: dict[str, Any]) -> None:
        """Run the ReflectionAgent post-check.

        The agent updates the shared blackboard itself (``last_reflection``,
        ``strategy_shift``, and a merged ``failed_modules``). It is
        heuristic-only when no model_client is wired, so per-module cost is low.
        Advisory -- exceptions are swallowed so reflection can't stall the
        campaign. No-op when no reflection agent is wired.
        """
        if self._reflection is None:
            return
        inner = result.get("result") if isinstance(result, dict) else None
        status = inner.get("status", "") if isinstance(inner, dict) else ""
        success = bool(result.get("success")) and status in (
            "success",
            "exploited",
            "script_generated",
            "info",
        )
        battle_entry = {
            "tool": task.module_name,
            "target": task.target,
            "success": success,
            "summary": str(status),
            "error": result.get("error", ""),
        }
        try:
            self._reflection.run(
                {
                    "task_id": task.task_id,
                    "battle_log": [battle_entry],
                    "session_state": state.to_dict(),
                },
                {
                    "memory": None,
                    "model_client": self._model_client,
                    "blackboard": self._blackboard,
                },
            )
        except Exception as exc:  # advisory -- never stall the campaign
            logger.warning(
                "Reflection post-check raised for %s (continuing): %r",
                task.module_name,
                exc,
            )

    def _record_lesson_on_success(
        self,
        task: AttackTask,
        state: AttackState,
        result: dict[str, Any],
    ) -> None:
        """Persist a cross-mission lesson on a confirmed win.

        Advisory/best-effort — never raises, never blocks the campaign. No-op
        when no SemanticMemoryManager is wired (the default). Uses a DISTINCT
        ``action_type='orchestrator:module_success'`` so these rows are
        isolated from the exploit-loop lessons ('reflection:exploit_loop') and
        the swarm reflection lessons ('reflection:strategy_shift') —
        downstream recall sees all three families, but the Bayesian
        ExperienceStore (operational exploit-action confidence) is untouched.
        """
        if self._semantic_memory is None:
            return
        # ponytail: cap text length to keep the embedding + DB row bounded;
        # store_lesson already truncates to 8000 chars, this is a tighter cap.
        note = str(result.get("note") or result.get("status") or "succeeded")[:300]
        text = f"{task.target} {task.module_name} ({task.phase.value}) succeeded: {note}"
        try:
            self._semantic_memory.store_lesson(
                target_signature=task.target,
                action_type="orchestrator:module_success",
                outcome="success",
                text=text,
                confidence=0.75,
                metadata={
                    "module": task.module_name,
                    "phase": task.phase.value,
                    "aggression": task.aggression.value,
                    "shell_type": result.get("shell_type", ""),
                    "privilege_level": result.get("privilege_level", ""),
                    "source": "autonomous_orchestrator",
                },
            )
        except Exception as exc:  # noqa: BLE001 -- never break the campaign on a lesson write
            logger.debug("store_lesson skipped for %s: %r", task.module_name, exc)
