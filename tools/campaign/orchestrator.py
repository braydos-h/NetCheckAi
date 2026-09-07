"""Campaign orchestrator — AutonomousOrchestrator core.

Canonical source for AutonomousOrchestrator.
Moved from tools.autonomous_orchestrator to break the god file.
Phase handlers live in tools.campaign.phases and are bound after class definition
to preserve ``self._phase_*`` call sites.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any, Callable

from tools.logging_setup import get_logger
from tools.recon_pipeline import ReconConfig, ReconPipeline

from tools.campaign import batch as _batch
from tools.campaign import phases as _phases
from tools.campaign import preflight as _preflight
from tools.campaign import service_tasks as _service_tasks
from tools.campaign import state_store as _state_store
from tools.campaign.executor import AttackModuleExecutor
from tools.campaign.state import (
    AggressionLevel,
    AttackState,
    AttackTask,
)
from tools.kernel.orchestration import MAX_MODULE_FAILURES

logger = get_logger()

# ---------------------------------------------------------------------------
# Autonomous orchestrator
# ---------------------------------------------------------------------------


class AutonomousOrchestrator:
    """Main autonomous attack orchestrator.

    Usage::
        orchestrator = AutonomousOrchestrator(mission_config, workspace, tool_executor)
        results = await orchestrator.run_autonomous_campaign(targets=["10.0.0.50"])
    """

    # ponytail: campaign-level cap on per-module retries. The per-task
    # max_retries bound (default 3) only governs a single AttackTask; the
    # aggression-escalation loop (_phase_exploitation:1622-1626) re-queues
    # failed modules with a fresh retry_count=0 each time, so without a
    # campaign-level budget a structural-failure module (e.g. Log4jRCE
    # against a non-vulnerable target) gets retried indefinitely until the
    # aggression ceiling is hit. Drop a module from the retry set once it
    # has failed this many times total in state.failed_attempts[mod].
    _max_module_failures: int = MAX_MODULE_FAILURES
    # Prerequisite-kind patterns — canonical table lives in tools/campaign/batch.py.
    _PREREQ_KIND_PATTERNS = _batch._PREREQ_KIND_PATTERNS

    def __init__(
        self,
        mission_config: dict[str, Any],
        workspace_root: Path,
        tool_executor: Callable[[str, dict[str, Any]], str] | None = None,
        *,
        recon_config: ReconConfig | None = None,
        scope_gate: Any | None = None,
        risk_controller: Any | None = None,
        evidence_store: Any | None = None,
        blackboard: dict[str, Any] | None = None,
        model_client: Any = None,
        critic_agent: Any = None,
        reflection_agent: Any = None,
        experience_store: Any | None = None,
        semantic_memory: Any | None = None,
    ) -> None:
        self._workspace = workspace_root
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._mission = mission_config
        self._tool_executor = tool_executor
        self._recon_config = recon_config or ReconConfig()
        self._recon = ReconPipeline(self._recon_config)
        # Evidence-aware module ranking: the dormant ExperienceStore at
        # tools/attack_modules/registry.py:205-328 already supports Bayesian
        # confidence boosting/demotion, but the autonomous path never passed
        # it (the audit flagged this -- ranked modules always got neutral 0.5).
        # Build a shared default-backed store when the caller doesn't supply one.
        self._experience_store = experience_store
        if self._experience_store is None:
            try:
                from db import get_default_db
                from tools.experience_store import ExperienceStore

                self._experience_store = ExperienceStore(get_default_db())
            except Exception:  # noqa: BLE001 -- ranking degrades to static-only
                self._experience_store = None
        # D1: semantic memory consumer. The exploit-agent loop and swarm
        # reflection already write cross-mission lessons via
        # SemanticMemoryManager.store_lesson; the orchestrator is the missing
        # campaign-level consumer so a multi-phase campaign learns across
        # missions, not just within the exploit loop. Read-only consumer —
        # store_lesson writes to the lessons table; no execution authority.
        # Built from config when not supplied (mirrors agent_loop.py:172-182
        # and tools/exploit_agent/runner/_impl.py). Gated by
        # ``orchestrator.semantic_memory`` (default false) so the wiring is
        # opt-in per the "new attack-path capabilities must be opt-in" rule.
        self._semantic_memory = semantic_memory
        if self._semantic_memory is None and bool(mission_config.get("semantic_memory", False)):
            try:
                from db import get_default_db
                from tools.providers.embeddings import (
                    NullEmbeddingProvider as _NullEmbeddings,
                    build_embedding_provider as _build_embeddings,
                )
                from tools.semantic_memory import SemanticMemoryManager

                # Embeddings provider owns the endpoint (``embeddings.provider``);
                # ``none`` degrades to keyword storage with zero requests.
                _embedding_provider = _build_embeddings(mission_config)
                if not isinstance(_embedding_provider, _NullEmbeddings):
                    self._semantic_memory = SemanticMemoryManager(
                        db=get_default_db(),
                        embedding_provider=_embedding_provider,
                    )
            except Exception as exc:  # noqa: BLE001 -- cross-mission learning degrades to no-op
                logger.debug("SemanticMemoryManager wiring skipped: %r", exc)
                self._semantic_memory = None
        # Phase 6.2: build an OpsecManager from the ``opsec`` config block
        # (merged into mission_config by the campaign call sites). Tolerant of
        # its absence -> disabled profile -> pacing no-op. Also published as the
        # process-global UA source so HTTP egress rotates UAs when ua_rotation
        # is on. Wrapped so an OPSEC build failure can never block orchestration.
        #
        # Phase 6.2+ (target-aware OPSEC): the manager passed to the executor is
        # the BASE (unresolved) manager -- ``AttackModuleExecutor.execute``
        # resolves it per task.target so each action gets the right posture
        # (local/private -> OPSEC off, public -> OPSEC on). The process-global
        # UA source is published resolved against the campaign's PRIMARY target
        # so egress UA rotation follows the same local/public rule. The primary
        # target is read from mission_config["target"] (set by the MCP campaign
        # tools) or the EXPLOIT_TARGET env (set by mcp_session at boot).
        try:
            from tools.opsec import OpsecManager
            from tools.opsec import configure as _opsec_configure

            self._opsec = OpsecManager.from_config(mission_config or {})
            _primary_target = (mission_config or {}).get("target") or os.environ.get("EXPLOIT_TARGET", "")
            _ua_profile = self._opsec.profile
            if _primary_target:
                _ua_profile = self._opsec.resolve_for_target(_primary_target).profile
            _opsec_configure(_ua_profile)
        except Exception:  # noqa: BLE001 -- OPSEC is best-effort
            self._opsec = None
        # Pass the swarm context through so the autonomous path runs the
        # critic pre-check / reflection post-check / shared blackboard
        # (Tier 0 item 0.6b). Unwired -> AttackModuleExecutor behaves as before.
        self._executor = AttackModuleExecutor(
            scope_gate,
            risk_controller,
            evidence_store,
            blackboard=blackboard,
            mission_config=mission_config,
            model_client=model_client,
            critic_agent=critic_agent,
            reflection_agent=reflection_agent,
            tool_executor=tool_executor,
            opsec_manager=self._opsec,
            semantic_memory=self._semantic_memory,
            experience_store=self._experience_store,
        )

        self._states: dict[str, AttackState] = {}
        self._tasks: dict[str, AttackTask] = {}
        self._task_counter = 0
        self._running = True
        # §23: agent.max_retries_per_task overrides the per-module failure cap
        # when the merged mission_config carries the agent block (the MCP
        # campaign call sites and the swarm bridge both merge it now). Absent
        # block -> the class default of 3 is preserved (byte-identical).
        _agent_cfg = (mission_config or {}).get("agent") or {}
        try:
            self._max_module_failures = max(1, int(_agent_cfg.get("max_retries_per_task", self._max_module_failures)))
        except (TypeError, ValueError):
            pass
        self._max_cycles = mission_config.get("max_cycles", 100)
        self._max_aggression = AggressionLevel(mission_config.get("max_aggression", "maximum"))
        # Capability-upgrade (§9): dynamic-composition counters. When a module
        # fails with PREREQUISITE_MISSING, a producer module is scheduled for
        # the missing artifact. Bounded: one prereq task per failing task (via
        # the per-batch ``prereq_scheduled`` set) plus this campaign-level cap
        # so a structural-missing chain cannot balloon the task queue. The cap
        # rides on the existing per-module failure budget so no new knob is
        # introduced.
        self._prereq_tasks_added = 0
        self._prereq_recovery_cap = max(1, int(self._max_module_failures))
        # Pivot-depth cap (Tier 0 item 0.6a): the lateral-movement phase recurses
        # into each discovered pivot target via _attack_target, which previously
        # had NO depth bound -- unbounded pivoting is a safety hole. Depth 0 is
        # the operator's original target; each successful pivot increments it.
        #
        # DEFAULT IS 0 (single-IP lock): per CLAUDE.md the engine is "still
        # target-locked to a single IP (AI cannot pivot to other hosts)". With
        # depth 0, ``_phase_lateral_movement`` discovers pivot targets but
        # ``_depth + 1 < 0`` is always False, so it logs the cap and never
        # recurses into them. An operator who has written authorization covering
        # the reachable hosts may opt in to bounded pivoting by setting
        # ``max_pivot_depth: N`` in mission.yaml/config.
        self._max_pivot_depth = int(mission_config.get("max_pivot_depth", 0))

        # Phase 2 opt-in capabilities (default OFF — new attack-path capabilities
        # must be opt-in per CLAUDE.md). These flow in from config.yaml's
        # ``autonomous`` block via the mission_config dict the call sites build
        # (see tools/mcp_tools/attack_modules.py start_autonomous_campaign /
        # run_campaign_step, which merge config["autonomous"] into mission_config).
        # ``persistence_phase`` enables the PERSISTENCE phase handler (2.2);
        # ``checkpoint_every`` makes run_autonomous_campaign save
        # attack_states.json every N completed targets (2.3, 0 = off);
        # ``adaptive_replan`` enables per-target multi-round replan + vuln
        # chaining (2.4). All default off so the default single-pass
        # _attack_target behavior is unchanged.
        self._persistence_enabled = bool(mission_config.get("persistence_phase", False))
        self._checkpoint_every = max(0, int(mission_config.get("checkpoint_every", 0) or 0))
        self._adaptive_replan = bool(mission_config.get("adaptive_replan", False))
        # ponytail: opt-in per-target parallelism (default 1 = serial,
        # byte-identical). Set ``max_parallel_targets: N`` to attack N
        # targets concurrently under a semaphore.
        try:
            self._max_parallel_targets = max(1, int(mission_config.get("max_parallel_targets", 1) or 1))
        except (TypeError, ValueError):
            self._max_parallel_targets = 1
        # Kill-chain state machine (design §killchain). Opt-in (default off):
        # when enabled, _attack_target prefers verified kill-chain edges over
        # free-form module planning and falls back on the first unverified
        # edge. The machine lives in tools/killchain/ and commits transitions
        # only after independent verification.
        _kc_cfg = (mission_config or {}).get("killchain", {}) or {}
        self._killchain_enabled = bool(_kc_cfg.get("enabled", False))
        self._killchain_goal_state = str(_kc_cfg.get("goal_state", "shell_as_root"))
        self._killchain_machine: Any | None = None
        # Phase 3: advisory local_exploit_suggester follow-up after the privesc
        # batch. Passed through as ``msf_auto_les`` (or nested ``msf`` dict) by
        # the campaign call sites. Default off. When on AND access was
        # achieved, a single LocalExploitSuggester info-task runs -- it only
        # SUGGESTS the MSF recipe (Path B has no MSF session id, so it never
        # fabricates one).
        self._auto_local_exploit_suggester = bool(
            mission_config.get("msf_auto_les", False)
            or ((mission_config.get("msf") or {}).get("auto_local_exploit_suggester", False))
        )

        # Phase 5: campaign-entry preflight (dedup + non-routable filter +
        # scope-gate pre-check). All opt-in / default-off so a single-IP
        # campaign is byte-identical to before. ``dedup_targets`` collapses
        # duplicate IPs / CIDR overlap / hosts resolving to the same IP;
        # ``skip_non_routable`` drops RFC1918/link-local/reserved addresses
        # that are not the operator's own host (those are handled by the
        # local-takeover playbook).
        self._dedup_targets = bool(mission_config.get("dedup_targets", False))
        self._skip_non_routable = bool(mission_config.get("skip_non_routable", False))

        # Phase 5: hard-target cutoff. After this many adaptive rounds with
        # zero novel candidate modules AND zero access achieved, give up on
        # the target instead of burning the remaining ``max_cycles`` budget.
        # 0 = off (current behavior).
        self._hard_target_max_rounds = max(0, int(mission_config.get("hard_target_max_rounds", 0) or 0))

        # Domain targeting: the operator's original --target (domain or IP) and
        # the resolved IP for a domain target. Threaded in from
        # run_autonomous_campaign(original_target=..., resolved_ip=...) so the
        # Path-B subdomain expansion in _phase_reconnaissance actually fires
        # (it's gated on state.original_target). Defaults to "" so IP-only
        # campaigns are unaffected.
        self._original_target = ""
        self._resolved_ip = ""

    def _new_task_id(self) -> str:
        self._task_counter += 1
        return f"ATK-{self._task_counter:05d}"

    def get_state(self, target: str) -> AttackState:
        if target not in self._states:
            state = AttackState(target=target)
            # Thread the domain-targeting context into the freshly-created
            # AttackState so _phase_reconnaissance's subdomain-expansion branch
            # (gated on state.original_target) is reachable on Path B.
            if self._original_target and not state.original_target:
                state.original_target = self._original_target
            if self._resolved_ip and not state.resolved_ip:
                state.resolved_ip = self._resolved_ip
            self._states[target] = state
        return self._states[target]

    # ── Main campaign runner ─────────────────────────────────────────────

    async def run_autonomous_campaign(
        self,
        targets: list[str],
        *,
        resume: bool = False,
        original_target: str = "",
        resolved_ip: str = "",
    ) -> dict[str, Any]:
        """Run a full autonomous attack campaign against multiple targets.

        Tier 1.3: when ``resume`` is True, load previously-saved attack state
        from ``attack_states.json`` in the workspace BEFORE attacking. The
        recovered per-target ``AttackState`` (recon_result, successful_exploits,
        failed_attempts, current_phase, credentials, access) means each target
        skips recon it already finished and doesn't re-fire modules that
        already succeeded/failed. A missing/empty state file degrades
        gracefully to a fresh start (see ``load_state``).

        Domain targeting: pass ``original_target`` (the operator's domain
        --target) and ``resolved_ip`` so the Path-B subdomain-expansion branch
        in _phase_reconnaissance fires. When both are "" (the default), an
        IP-only campaign runs unchanged.
        """
        # Stash on the instance so get_state() can thread them into freshly-
        # created AttackState objects (get_state has no kwargs of its own).
        if original_target:
            self._original_target = original_target
        if resolved_ip:
            self._resolved_ip = resolved_ip
        logger.info(f"Starting autonomous campaign against {len(targets)} targets")
        campaign_start = time.monotonic()

        if resume:
            state_path = self._workspace / "attack_states.json"
            loaded = self.load_state(state_path)
            if loaded:
                logger.info("Resume: prior attack state loaded")
            else:
                logger.info("Resume requested but no usable state found — fresh start")

        results: dict[str, Any] = {}
        completed = 0

        # Phase 5: campaign-entry preflight. Resolve/dedupe/scope-check the
        # target list BEFORE spending a single scan on it. A duplicate IP, a
        # non-routable address, or an out-of-scope host would otherwise each
        # get a full Nmap -p- scan + exploitation campaign. All three filters
        # are opt-in (default off) so a single-IP campaign is byte-identical.
        targets = self._preflight_targets(targets)

        # ponytail: bounded per-target fan-out. max_parallel_targets=1 (default)
        # keeps the original serial loop verbatim — including checkpoint
        # interleaving (a checkpoint at completed==2 captures exactly 2
        # targets' states). N>1 runs targets concurrently under a semaphore;
        # checkpoints then fire as results complete (a checkpoint may capture
        # more states than its count — inherent to concurrent completion).
        async def _run_guarded(target: str) -> tuple[str, dict[str, Any]]:
            # Phase 2.3: crash-bounded per-target dispatch. A single target's
            # unexpected exception must NOT abort the whole campaign -- record
            # the failure and continue so the operator still gets results for
            # the remaining targets (and a checkpoint preserves progress).
            try:
                return target, await self._attack_target(target)
            except Exception as exc:  # noqa: BLE001 -- crash-bounded: one target shouldn't kill the campaign
                logger.exception(f"Crash-bounded: _attack_target({target}) raised {exc}")
                state = self.get_state(target)
                state.add_timeline_event("target_crash", f"Target {target} aborted: {exc}", {"error": str(exc)})
                return target, {"status": "crashed", "error": str(exc), "state": state.to_dict()}

        def _checkpoint() -> None:
            # Phase 2.3: periodic checkpoint. Every ``checkpoint_every``
            # completed targets (opt-in, 0 = off), persist attack_states.json
            # so a crashed run resumes with real progress. Best-effort — a
            # checkpoint failure never aborts the campaign.
            if self._checkpoint_every > 0 and completed % self._checkpoint_every == 0:
                try:
                    self.save_state()
                    logger.info(f"[CHECKPOINT] Saved attack state after {completed} target(s)")
                except Exception as exc:  # noqa: BLE001 -- checkpoint failure is non-fatal
                    logger.warning(f"[CHECKPOINT] Save failed (non-fatal): {exc}")

        if self._max_parallel_targets <= 1:
            for target in targets:
                if not self._running:
                    break
                _, result = await _run_guarded(target)
                results[target] = result
                completed += 1
                _checkpoint()
        else:
            _sema = asyncio.Semaphore(self._max_parallel_targets)

            async def _run_one(target: str) -> tuple[str, dict[str, Any]]:
                async with _sema:
                    if not self._running:
                        return target, {"status": "aborted", "error": "campaign stopped"}
                    return await _run_guarded(target)

            for target, result in await asyncio.gather(*(_run_one(t) for t in targets)):
                results[target] = result
                completed += 1
                _checkpoint()

        campaign_duration = time.monotonic() - campaign_start
        logger.info(f"Campaign complete in {campaign_duration:.1f}s")

        return {
            "targets": targets,
            "results": results,
            "duration": campaign_duration,
            "total_tasks": len(self._tasks),
            "successful_exploits": sum(len(s.successful_exploits) for s in self._states.values()),
            "states": {t: s.to_dict() for t, s in self._states.items()},
        }

    async def _attack_target(self, target: str, *, _depth: int = 0) -> dict[str, Any]:
        """Run full attack lifecycle against a single target (see tools/campaign/phases.py)."""
        return await _phases._attack_target(self, target, _depth=_depth)

    # ── Task batches + prerequisite recovery (see tools/campaign/batch.py) ──

    async def _execute_task_batch(self, tasks: list[AttackTask], state: AttackState) -> None:
        """Execute a batch of tasks with concurrency control (see tools/campaign/batch.py)."""
        return await _batch._execute_task_batch(self, tasks, state)

    def _prereq_artifact_kinds(self, error: str) -> list[str]:
        """Candidate artifact kinds for a PREREQUISITE_MISSING error (see tools/campaign/batch.py)."""
        return _batch._prereq_artifact_kinds(self, error)

    def _maybe_schedule_prereq(
        self,
        task: AttackTask,
        state: AttackState,
        error: str,
    ) -> AttackTask | None:
        """Schedule a producer module for a missing prerequisite (see tools/campaign/batch.py)."""
        return _batch._maybe_schedule_prereq(self, task, state, error)

    async def _retry_failed_modules(self, state: AttackState) -> None:
        """Retry failed modules with escalated aggression (see tools/campaign/batch.py)."""
        return await _batch._retry_failed_modules(self, state)

    # ── Service-specific tasks (see tools/campaign/service_tasks.py) ──

    def _create_service_specific_tasks(self, state: AttackState) -> list[AttackTask]:
        """Create additional tasks based on discovered services (see tools/campaign/service_tasks.py)."""
        return _service_tasks._create_service_specific_tasks(self, state)

    # ── Campaign-entry preflight (see tools/campaign/preflight.py) ──

    def _preflight_targets(self, targets: list[str]) -> list[str]:
        """Resolve, de-duplicate, scope-check and filter targets (see tools/campaign/preflight.py)."""
        return _preflight._preflight_targets(self, targets)

    # ── Persistence (see tools/campaign/state_store.py) ──

    def save_state(self, path: Path | None = None) -> Path:
        """Save all attack states to disk (see tools/campaign/state_store.py)."""
        return _state_store.save_state(self, path)

    def load_state(self, path: Path) -> bool:
        """Load attack states from disk (see tools/campaign/state_store.py)."""
        return _state_store.load_state(self, path)

    def stop(self) -> None:
        """Gracefully stop the orchestrator (see tools/campaign/state_store.py)."""
        return _state_store.stop(self)


# Bind phase handlers (preserve self._phase_* call sites without inheritance)
AutonomousOrchestrator._phase_local_takeover = _phases._phase_local_takeover  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_reconnaissance = _phases._phase_reconnaissance  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_exploitation = _phases._phase_exploitation  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_privilege_escalation = _phases._phase_privilege_escalation  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_lateral_movement = _phases._phase_lateral_movement  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_validation = _phases._phase_validation  # type: ignore[attr-defined]
AutonomousOrchestrator._extract_persistence_marker = _phases._extract_persistence_marker  # type: ignore[attr-defined]
AutonomousOrchestrator._module_context = _phases._module_context  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_persistence = _phases._phase_persistence  # type: ignore[attr-defined]
AutonomousOrchestrator._run_adaptive_rounds = _phases._run_adaptive_rounds  # type: ignore[attr-defined]
AutonomousOrchestrator._schedule_vuln_chain = _phases._schedule_vuln_chain  # type: ignore[attr-defined]
AutonomousOrchestrator._get_killchain_machine = _phases._get_killchain_machine  # type: ignore[attr-defined]
AutonomousOrchestrator._phase_killchain = _phases._phase_killchain  # type: ignore[attr-defined]
