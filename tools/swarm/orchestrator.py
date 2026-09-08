"""Swarm Orchestrator — routes tasks to specialist agents and merges results.

V2: Shared blackboard for inter-agent state, parallel dispatch with semaphore,
critic pre-check with blackboard awareness, and reflection-driven strategy adaptation.
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

from tools.kernel.orchestration import safe_emit
from tools.swarm import milestones as _milestones
from tools.swarm import negotiation as _negotiation
from tools.swarm import reflection_run as _reflection_run
from tools.swarm import state_store as _state_store
from tools.swarm.agents.critic_agent import CriticAgent
from tools.swarm.agents.exploit_agent import ExploitAgent
from tools.swarm.agents.post_exploit_agent import PostExploitAgent
from tools.swarm.agents.recon_agent import ReconAgent
from tools.swarm.agents.reflection_agent import ReflectionAgent
from tools.swarm.agents.vuln_agent import VulnAgent
from tools.swarm.base import Agent, AgentResult, AgentStatus
from tools.swarm.blackboard import Blackboard

# Mapping from task phase/type to default agent class
_DEFAULT_AGENT_MAP: dict[str, type[Agent]] = {
    "recon": ReconAgent,
    "analysis": VulnAgent,
    "test": VulnAgent,
    "validate": ExploitAgent,
    "exploit": ExploitAgent,
    "post_exploit": PostExploitAgent,
    "report": ReflectionAgent,
}


def _swarm_config(config: Any) -> dict[str, Any]:
    """Defensive ``swarm`` config-block read (never raises, {} when absent).

    P3-10 seam: parallel flags (``max_parallel_agents``,
    ``per_phase_concurrency``, ``exploit_parallel``, ``parallel_enabled``)
    resolve through here so constructor ``None`` defaults pick up a flipped
    config.yaml. Explicit constructor args always win over this.
    """
    try:
        if not isinstance(config, dict):
            return {}
        swarm_cfg = config.get("swarm", {})
        return dict(swarm_cfg) if isinstance(swarm_cfg, dict) else {}
    except Exception:  # ponytail: bare except intentional — malformed config means defaults
        return {}


class SwarmOrchestrator:
    """Routes tasks to registered agents and aggregates their results.

    V2 improvements:
    - Shared blackboard for inter-agent state communication
    - Critic pre-check with blackboard awareness (repeat failure detection)
    - Parallel dispatch with semaphore-based concurrency
    - Reflection-driven strategy adaptation
    - Battle log accumulation for reflection agent
    """

    # Negotiable critic keys — canonical set lives in tools/swarm/negotiation.py.
    _NEGOTIABLE_KEYS = _negotiation._NEGOTIABLE_KEYS

    def __init__(
        self,
        context: dict[str, Any],
        *,
        agent_registry: dict[str, type[Agent]] | None = None,
        max_parallel: int | None = None,
        critic_enabled: bool = True,
        reflection_enabled: bool = True,
        event_callback: Callable[[str, dict[str, Any]], None] | None = None,
        state_path: Path | str | None = None,
        # Phase 3: ``exploit_parallel`` controls whether exploit/post_exploit
        # tasks parallelize in ``route_parallel``. False (default) = recon-
        # first policy (only recon + analysis parallelize). True = exploits
        # also run in parallel (higher IDS/crash risk; opt in via
        # ``swarm.exploit_parallel: true`` in config.yaml).
        exploit_parallel: bool | None = None,
        # Bounded critic↔exploit negotiation rounds. 0 = legacy one-shot
        # behavior (critic's ``modify`` is applied once, then the task runs).
        # N>0 = after applying a ``modify``, the modified task is re-reviewed
        # by the critic up to N times until it returns ``approve``/``deny``,
        # a scope-expanding modification is proposed (rejected + logged), or
        # the same modification repeats twice in a row (deadlock break). The
        # negotiation is about *how* to execute a planned action (risk level,
        # tool swap, mutation flag, rate limiting), never *what* target/scope
        # to hit — the allowlist lock is untouched. See ``_negotiate``.
        negotiation_rounds: int = 0,
    ) -> None:
        self._context = context
        self._agent_registry = agent_registry or dict(_DEFAULT_AGENT_MAP)
        # P3-10: parallel flags resolve explicit-arg → config → schema
        # default. ``None`` (the new default) means "read
        # ``swarm.max_parallel_agents`` / ``swarm.exploit_parallel`` /
        # ``swarm.per_phase_concurrency`` from context config"; an explicit
        # arg always wins (tests + legacy/agent_loop.py pass theirs
        # directly). Previously the flags were constructor-only, so a
        # flipped config.yaml never reached the orchestrator on Flow A.
        _swarm_cfg = _swarm_config(context.get("config"))
        self._max_parallel = (
            max(1, int(max_parallel))
            if max_parallel is not None
            else max(1, int(_swarm_cfg.get("max_parallel_agents", 3) or 3))
        )
        self._per_phase_concurrency = max(
            1, int(_swarm_cfg.get("per_phase_concurrency", self._max_parallel) or self._max_parallel)
        )
        self._critic_enabled = critic_enabled
        self._reflection_enabled = reflection_enabled
        self._event_callback = event_callback
        self._exploit_parallel = (
            bool(exploit_parallel) if exploit_parallel is not None else bool(_swarm_cfg.get("exploit_parallel", False))
        )
        self._negotiation_rounds = max(0, int(negotiation_rounds))
        self._state_path: Path | None = Path(state_path) if state_path else None
        self._agents: dict[str, Agent] = {}
        self._results: list[AgentResult] = []
        self._battle_log: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        # §13: models.roles resolution runs lazily on first critic dispatch
        # (the router build is lazy + cached, so deferring keeps construction
        # cheap and avoids import weight on paths that never dispatch a critic).
        self._role_clients_resolved = False

        # Phase 3: per-(target, phase) milestone events. A dependent task
        # (e.g. a vuln task waiting on recon for the same target) awaits the
        # event before its agent runs, so cross-phase parallelism can't start
        # the recon→vuln→exploit chain out of order. Same-phase, different-
        # target tasks don't wait on each other (parallel recon on N hosts is
        # the win). ``threading.Event`` (not asyncio.Event) because agents run
        # in run_in_executor worker threads under route_parallel; the
        # await_milestone helper hops to the main loop to wait.
        self._milestone_events: dict[tuple[str, str], threading.Event] = {}

        # In-memory growth caps. ``_results`` and ``_battle_log`` are only read
        # for their length and a recent tail (see _persist_state's
        # ``battle_log[-200:]`` and _distill_episode_summary's win-count roll-up),
        # so bounding them reclaims the memory a long multi-cycle campaign would
        # otherwise leak without losing any consumed data. The full per-task
        # outcome is already persisted to swarm_state.json on every event.
        self._max_results = 500
        self._max_battle_log = 500
        # ponytail: persist throttle. _persist_state does a full json.dumps +
        # mkdir + atomic replace; at 200 cycles x several events per cycle the
        # disk writes dominate the orchestrator's own CPU. Throttled to at most
        # one write per interval; route_parallel forces a final write so resume
        # never loses the batch tail.
        self._state_persist_interval = 5.0
        self._last_persist = 0.0

        # ── Shared blackboard for inter-agent state ──
        # ``Blackboard`` (tools/swarm/blackboard.py) is a dict subclass with
        # atomic append_to/extend_list and per-target namespacing. Subclassing
        # dict means every existing ``bb["k"]`` / ``bb.get("k")`` read site in
        # the 6 agents keeps working unchanged (reads hit the __global__
        # bucket, the legacy flat-dict view); only write sites are migrated to
        # the atomic methods so parallel dispatch in route_parallel no longer
        # races on the get-then-set list appends the old plain dict allowed.
        self._blackboard: Blackboard = Blackboard(
            {
                "recon_complete": False,
                "vuln_research_complete": False,
                "access_achieved": False,
                "discovered_services": [],
                "vulnerability_hypotheses": [],
                "compromised_hosts": [],
                "credentials_found": [],
                "pivot_targets": [],
                "loot": [],
                "failed_modules": [],
                "attack_surface_score": 0,
                "strategy_shift": "",
            }
        )

        # Inject blackboard into context so all agents can access it. Agents
        # read it as a dict (bb["k"] / bb.get) and write via the atomic API
        # (bb.set_scalar / bb.append_to / bb.extend_list).
        self._context["blackboard"] = self._blackboard

        # ── Runtime skill selection for advisory phase hints ──
        # Build one mission-level SkillSelection and stash it on the shared
        # context so each specialist agent can derive phase-relevant hints.
        # Advisory only; never grants execution authority. Best-effort: a
        # missing/empty config or disabled skills yields an empty selection
        # and agents no-op.
        try:
            from tools.skill_pipeline import build_skill_selection_for_swarm

            self._context.setdefault("skill_selection", build_skill_selection_for_swarm(self._context))
        except Exception:
            self._context.setdefault("skill_selection", None)

    # ── Public API ──────────────────────────────────────────────────────

    def route(self, task: dict[str, Any]) -> AgentResult:
        """Route a single task to the appropriate agent (sequential).

        Includes critic pre-check with blackboard awareness.

        Phase 3: the ``self._lock`` (an ``RLock``) now guards ONLY the
        orchestrator's own mutable state (``_agents``, ``_results``,
        ``_battle_log``, ``_milestone_events``) — NOT ``agent.run()`` /
        ``critic.run()``. Those run outside the lock so ``route_parallel`` can
        dispatch multiple agents concurrently (the lock is reentrant for the
        ``_spawn`` / ``_results.append`` / ``_battle_log.append`` /
        ``_mark_milestone`` calls that happen before/after the unlocked
        ``agent.run``). This is hazard #1 from the route_parallel warning,
        fixed. Hazards #2-#5 are fixed by Phase 1 (Blackboard), Phase 2
        (per-attempt workspaces), and the milestone gating below.
        """
        phase = task.get("phase", "recon")
        agent_cls = self._agent_registry.get(phase)
        if agent_cls is None:
            return AgentResult(
                agent_type="unknown",
                status=AgentStatus.FAILED,
                task_id=task.get("task_id", task.get("id", "")),
                error=f"No agent registered for phase '{phase}'.",
            )

        task_id = task.get("task_id", task.get("id", ""))
        target = task.get("target", "")
        with self._lock:
            agent = self._spawn(agent_cls, task_id=task_id)

        # ── Critic pre-check (with blackboard awareness) ──
        # Runs UNLOCKED — critic.run() reads the blackboard (atomic via
        # Blackboard.get) and may call an LLM; holding the orchestrator lock
        # across that would serialize all parallel agents.
        if self._critic_enabled and phase not in ("recon", "report"):
            self._ensure_role_clients()
            critic_cls = self._agent_registry.get("critic", CriticAgent)
            critic = critic_cls()
            outcome = self._negotiate(critic, task, task_id, target, agent)
            if outcome is not None:
                # ``deny`` short-circuits the route — the blocked result is
                # already recorded and persisted by ``_negotiate``.
                return outcome

        # ── Execute agent ──
        # Runs UNLOCKED so parallel agents (route_parallel) actually run
        # concurrently. All blackboard writes inside agent.run go through the
        # atomic Blackboard API (Phase 1); per-attempt workspaces (Phase 2)
        # isolate filesystem writes. The orchestrator's own state
        # (_results, _battle_log, _agents) is touched only in the locked
        # blocks below.
        # ponytail: fault isolation at the single choke point — a raising
        # agent becomes a FAILED result, so one bad agent can't kill the batch;
        # milestone marking + persist below still run.
        try:
            result = agent.run(task, self._context)
        except Exception as exc:  # noqa: BLE001 -- isolation, never propagate
            result = AgentResult(
                agent_type=agent.agent_type,
                status=AgentStatus.FAILED,
                task_id=task_id,
                error=f"agent.run raised: {exc}",
            )
        agent._set_status(result.status)

        with self._lock:
            self._results.append(result)
        self._emit(
            f"agent_{result.status.value}",
            {
                "agent_id": agent.agent_id,
                "agent_type": agent.agent_type,
                "task_id": task_id,
                "status": result.status.value,
                "execution_time": result.execution_time,
                "summary": str(result.output)[:200] if result.output else result.error,
                "findings_count": len(result.findings),
                "new_tasks_count": len(result.new_tasks),
            },
        )

        # ── Update battle log with richer context ──
        with self._lock:
            self._battle_log.append(
                {
                    "task_id": task_id,
                    "tool": task.get("tool", task.get("phase", "")),
                    "target": target,
                    "success": result.status == AgentStatus.COMPLETE,
                    "summary": str(result.output)[:500],
                    "error": result.error,
                    "findings": result.findings,
                    "new_tasks": result.new_tasks,
                }
            )
            self._trim_history()

        # ── Blackboard milestone events ──
        if result.output:
            for key in ("access_achieved", "compromised_hosts", "credentials_found", "loot"):
                value = result.output.get(key) if isinstance(result.output, dict) else None
                if value:
                    # Bug #18 (preserved): the old ``setdefault(key, value)``
                    # on a list value was a no-op once the key existed — the
                    # first task's list stuck and every later task's list was
                    # silently dropped. We now merge list values
                    # (order-preserving dedupe) and keep first-write
                    # semantics for scalars. The Blackboard API makes this
                    # atomic (lock-protected get-then-set) so the same merge
                    # is safe under route_parallel's unlocked agent.run.
                    if isinstance(value, list):
                        self._blackboard.extend_list(key, value)
                    else:
                        # First-write-wins for scalars: only set if absent.
                        if key not in self._blackboard:
                            self._blackboard.set_scalar(key, value)
                    if key == "access_achieved" and value:
                        self._blackboard.set_scalar("access_achieved", True)
                    self._emit(
                        "blackboard_updated",
                        {"key": key, "value": value, "task_id": task_id, "agent_type": agent.agent_type},
                    )

        # ── Phase milestone ──
        # Mark this (target, phase) complete so any dependent task waiting in
        # route_parallel can proceed. ``recon``→``analysis``/``exploit`` chain
        # depends on this; ``post_exploit`` depends on ``exploit``. Done in a
        # finally-style block so a failed agent still unblocks dependents (a
        # failed recon shouldn't wedge the whole campaign forever).
        self._mark_milestone(target, phase)

        # Forced: task completion (results + blackboard deltas) is the
        # resume-meaningful event. Spawn/block/reflect persists stay throttled.
        self._persist_state(force=True)

        # ── Auto-reflect after exploitation phases ──
        if self._reflection_enabled and phase in ("exploit", "post_exploit"):
            self.reflect(self._battle_log, {"target_ip": target})

        return result

    async def route_parallel(self, tasks: list[dict[str, Any]]) -> list[AgentResult]:
        """Route multiple tasks in parallel with a concurrency limit.

        Phase 3: re-enabled. The 5 hazards from the old warning are fixed:

        1. **``route()`` RLock no longer serializes agent.run** — the lock now
           guards only ``_spawn``/``_results.append``/``_battle_log.append``/
           ``_mark_milestone`` (short, metadata-only critical sections);
           ``agent.run()`` and ``critic.run()`` run unlocked.
        2. **Blackboard is thread-safe + per-target namespaced** (Phase 1) —
           same-phase tasks on different targets write to isolated buckets;
           atomic ``extend_list``/``append_to`` make list merges race-free.
        3. **List read-modify-writes are atomic** (Phase 1) — all 4 named
           races (compromised_hosts, credentials_found, loot, failed_modules)
           go through ``Blackboard.append_to``/``extend_list``.
        4. **Precondition gating** (Phase 3) — a task with ``depends_on`` set
           to ``(target, phase)`` awaits the milestone event before running,
           so a vuln task won't start until its target's recon is done. Same-
           phase, different-target tasks run concurrently (parallel recon on
           N hosts is the win).
        5. **Per-attempt UUID workspaces** (Phase 2) — parallel exploit/post-
           exploit agents get isolated ``<ip>/<attempt_uuid>/`` dirs so they
           don't collide on exploit_script.py / loot.jsonl.

        Recon-first policy: by default only ``recon`` and ``analysis`` phases
        parallelize here. ``exploit``/``post_exploit`` stay sequential (run
        via the plain ``route()`` path) unless the caller passes them through
        here explicitly (e.g. a future ``swarm.exploit_parallel: true`` config
        flips the policy). This matches the operator's recon-first rollout
        choice — parallel recon (multi-host scan) + vuln research (multi-
        service CVE lookup) first; parallel exploits (higher IDS/crash risk)
        stay sequential until explicitly opted in.
        """
        # Recon-first filter: only parallelize the safe read-only phases here
        # by default. ``self._exploit_parallel`` (from config.yaml
        # ``swarm.exploit_parallel``) flips the policy so exploit/post_exploit
        # also parallelize. A task can also opt in individually via
        # ``force_parallel`` (used by the Phase 4 spawn_subagent tool when the
        # main AI explicitly delegates a parallel exploit batch).
        if self._exploit_parallel:
            _parallel_phases = ("recon", "analysis", "exploit", "post_exploit")
        else:
            _parallel_phases = ("recon", "analysis")
        parallel_tasks: list[dict[str, Any]] = []
        sequential_tasks: list[dict[str, Any]] = []
        for t in tasks:
            phase = t.get("phase", "recon")
            if phase in _parallel_phases or t.get("force_parallel"):
                parallel_tasks.append(t)
            else:
                sequential_tasks.append(t)

        # P3-10: ``swarm.per_phase_concurrency`` sizes the same-phase
        # semaphore (schema default 3); ``max_parallel`` stays the
        # constructor-level ceiling for backward compatibility. Explicit
        # constructor args and config both flow through __init__.
        semaphore = asyncio.Semaphore(max(1, min(self._per_phase_concurrency, self._max_parallel)))

        async def _run_one(task: dict[str, Any]) -> AgentResult:
            # Precondition gating: wait for the dependency milestone before
            # starting the agent. ``depends_on`` is a (target, phase) tuple
            # serialized as a 2-list (JSON-friendly). Same-target deps block;
            # different-target same-phase tasks don't wait on each other (so
            # parallel recon on N hosts runs concurrently).
            depends_on = task.get("depends_on")
            if depends_on and isinstance(depends_on, (list, tuple)) and len(depends_on) == 2:
                dep_target, dep_phase = depends_on
                # Block in this worker thread (only this task waits, not the
                # whole loop). 10-min ceiling so a stuck dependency can't
                # wedge the campaign forever.
                self._await_milestone(dep_target, dep_phase, timeout=600.0)
            async with semaphore:
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, self.route, task)

        parallel_results: list[AgentResult] = []
        if parallel_tasks:
            # ponytail: return_exceptions=True + map strays to FAILED, so one
            # raising worker can't cancel the batch (fault isolation).
            raw: list[Any] = list(await asyncio.gather(*[_run_one(t) for t in parallel_tasks], return_exceptions=True))
            for t, r in zip(parallel_tasks, raw):
                if isinstance(r, AgentResult):
                    parallel_results.append(r)
                elif isinstance(r, BaseException):
                    parallel_results.append(
                        AgentResult(
                            agent_type="unknown",
                            status=AgentStatus.FAILED,
                            task_id=t.get("task_id", t.get("id", "")),
                            error=f"route_parallel worker raised: {r!r}",
                        )
                    )

        # Sequential tasks (exploit/post_exploit in recon-first mode) run
        # via route() one at a time, after the parallel batch finishes, so a
        # vuln result feeds the next exploit cycle cleanly. Each still runs in
        # the executor (not blocking the event loop) but awaits one-by-one so
        # the serial safety semantics are unchanged.
        sequential_results: list[AgentResult] = []
        for t in sequential_tasks:
            sequential_results.append(await _run_one(t))

        # Preserve input order: return results in the same order as ``tasks``.
        # gather preserves order for parallel_tasks; the sequential loop
        # preserves order for sequential_tasks; we interleave by matching
        # task_id back to the original input position.
        # ponytail: empty/duplicate task_ids mint a fresh id — never overwrite
        # an earlier result under the same key.
        result_by_task_id: dict[str, AgentResult] = {}
        for r in parallel_results + sequential_results:
            key = r.task_id or f"orphan-{uuid.uuid4().hex[:8]}"
            while key in result_by_task_id:
                key = f"{r.task_id or 'orphan'}-{uuid.uuid4().hex[:4]}"
            result_by_task_id[key] = r
        try:
            ordered: list[AgentResult] = []
            for t in tasks:
                tid = t.get("task_id", t.get("id", ""))
                r = result_by_task_id.get(tid)
                if r is not None:
                    ordered.append(r)
            # Any task that didn't produce a result (shouldn't happen) falls back
            # to a failed placeholder so the caller gets exactly len(tasks) items.
            while len(ordered) < len(tasks):
                ordered.append(
                    AgentResult(
                        agent_type="unknown",
                        status=AgentStatus.FAILED,
                        task_id="",
                        error="route_parallel: no result produced for task",
                    )
                )
            return ordered
        finally:
            # Batch-end forced write: throttled per-task persists above may have
            # skipped the tail; resume must see the completed batch. In finally
            # so it runs even when ordering above raises.
            self._persist_state(force=True)

    def reflect(self, battle_log: list[dict[str, Any]], session_state: dict[str, Any]) -> AgentResult:
        """Run the reflection agent on the current phase results (see tools/swarm/reflection_run.py)."""
        return _reflection_run.reflect(self, battle_log, session_state)

    def get_blackboard(self) -> dict[str, Any]:
        """Return a snapshot of the global (legacy flat-dict) blackboard state.

        Read-only consumers (diagnostics, the resume JSON's
        ``last_reflection``/``strategy_shift`` echoes) get the flat view they
        always had. Per-target namespaced state is NOT included here — use
        ``self._blackboard.snapshot()`` for the full namespaced picture, or
        ``self._blackboard.get_target(ip)`` for one host.
        """
        return self._blackboard.flat()

    def share_blackboard(self) -> "Blackboard":
        """Return the LIVE shared blackboard (not a copy).

        Used by the autonomous orchestrator (Tier 0 item 0.6b) so the autonomous
        attack path and the swarm ``route()`` loop share one source of truth --
        ``AttackModuleExecutor`` records module failures / reflection output
        into this Blackboard and the swarm's ``CriticAgent`` reads them back.
        The autonomous campaign and the swarm ``route()`` loop are alternative
        execution paths within a run (never concurrent), so a shared mutable
        reference is safe here; callers must use the atomic ``set_scalar`` /
        ``append_to`` / ``extend_list`` methods (not bare ``bb[k] = v``) so the
        internal lock protects writes. ``get_blackboard()`` remains the snapshot
        API for read-only persistence and diagnostics consumers.
        """
        return self._blackboard

    @property
    def model_client(self) -> Any:
        """The LLM client shared with swarm agents (None until set_model_client)."""
        return self._context.get("model_client")

    # ── Event emission + state persistence ───────────────────────────────

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event to the registered callback, swallowing errors."""
        safe_emit(self._event_callback, event_type, data)

    # ── Critic negotiation (canonical code in tools/swarm/negotiation.py) ──

    def _ensure_role_clients(self) -> None:
        """Resolve ``models.roles`` clients lazily (see tools/swarm/negotiation.py)."""
        return _negotiation._ensure_role_clients(self)

    def _negotiate(
        self,
        critic: Agent,
        task: dict[str, Any],
        task_id: str,
        target: str,
        agent: Agent,
    ) -> AgentResult | None:
        """Bounded critic↔exploit negotiation (see tools/swarm/negotiation.py)."""
        return _negotiation._negotiate(self, critic, task, task_id, target, agent)

    def _negotiation_loop(
        self,
        critic: Agent,
        task: dict[str, Any],
        task_id: str,
        target: str,
        agent: Agent,
        first_modifications: dict[str, Any],
    ) -> AgentResult | None:
        """Bounded re-review loop (see tools/swarm/negotiation.py)."""
        return _negotiation._negotiation_loop(self, critic, task, task_id, target, agent, first_modifications)

    def _filter_modifications(
        self,
        modifications: dict[str, Any],
        task_id: str,
        target: str,
        *,
        round_idx: int,
    ) -> dict[str, Any]:
        """Keep only negotiable critic keys (see tools/swarm/negotiation.py)."""
        return _negotiation._filter_modifications(self, modifications, task_id, target, round_idx=round_idx)

    def _modifications_hash(self, modifications: dict[str, Any]) -> str:
        """Stable hash of a modifications dict (see tools/swarm/negotiation.py)."""
        return _negotiation._modifications_hash(self, modifications)

    def _record_block(
        self,
        critic: Agent,
        task: dict[str, Any],
        task_id: str,
        target: str,
        agent: Agent,
        reasoning: str,
    ) -> AgentResult:
        """Record a critic ``deny`` (see tools/swarm/negotiation.py)."""
        return _negotiation._record_block(self, critic, task, task_id, target, agent, reasoning)

    # ── Milestones (canonical code in tools/swarm/milestones.py) ──

    def _mark_milestone(self, target: str, phase: str) -> None:
        """Mark ``(target, phase)`` complete (see tools/swarm/milestones.py)."""
        return _milestones._mark_milestone(self, target, phase)

    def is_milestone_set(self, target: str, phase: str) -> bool:
        """Check whether ``(target, phase)`` completed (see tools/swarm/milestones.py)."""
        return _milestones.is_milestone_set(self, target, phase)

    def _await_milestone(self, target: str, phase: str, timeout: float | None = None) -> bool:
        """Block until ``(target, phase)`` completes (see tools/swarm/milestones.py)."""
        return _milestones._await_milestone(self, target, phase, timeout)

    # ── State persistence (canonical code in tools/swarm/state_store.py) ──

    def _trim_history(self) -> None:
        """Bound ``_results`` and ``_battle_log`` (see tools/swarm/state_store.py)."""
        return _state_store._trim_history(self)

    def _persist_state(self, *, force: bool = False) -> None:
        """Persist a swarm-state snapshot (see tools/swarm/state_store.py)."""
        return _state_store._persist_state(self, force=force)

    def load_state(self, path: Path | str | None = None) -> bool:
        """Restore the blackboard from swarm_state.json (see tools/swarm/state_store.py)."""
        return _state_store.load_state(self, path)

    # ── Internal ────────────────────────────────────────────────────────

    def _spawn(self, agent_cls: type[Agent], task_id: str = "") -> Agent:
        """Instantiate a fresh agent instance."""
        agent = agent_cls()
        agent._task_id = task_id  # type: ignore[attr-defined]
        self._agents[agent.agent_id] = agent
        agent._set_status(AgentStatus.RUNNING)
        self._emit(
            "agent_started",
            {
                "agent_id": agent.agent_id,
                "agent_type": agent.agent_type,
                "task_id": task_id,
            },
        )
        self._persist_state()
        return agent
