"""Critic negotiation — bounded critic↔exploit review loop.

Extracted from ``SwarmOrchestrator`` (see ``tools/swarm/orchestrator.py``) to
keep the orchestrator under 500 lines. The functions below are bound onto
``SwarmOrchestrator`` after its definition, so ``self._negotiate`` call sites
and tests keep working unchanged. Each takes the orchestrator instance as an
untyped first arg so the body stays verbatim.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tools.swarm.base import Agent, AgentResult, AgentStatus

# Keys the critic is allowed to modify during a negotiation. A ``modify``
# proposing a change to any key NOT in this set is treated as a scope
# expansion attempt and rejected (the modification is dropped, the
# negotiation stops, and the original task runs). The negotiation is about
# *how* to execute a planned action — never *what* target/scope to hit.
# ``target``/``phase``/``scope``/``allowed_tools``/``asset_type`` define
# WHAT the action touches, so they are off the table. The allowlist lock is
# untouched by this allowlist: it is enforced separately at the MCP tool
# layer regardless of what the critic proposes.
_NEGOTIABLE_KEYS: frozenset[str] = frozenset(
    {
        "risk_level",
        "require_mutation",
        "alternative_tool",
        "rate_limit_seconds",
        "delay_seconds",
        "timeout_seconds",
        "max_retries",
        "mutation_strategy",
    }
)


# Role -> shared-context key. ``critic`` is the original §13 call site;
# additional roles fan out through the same stash + ``or``-fallback contract
# (each agent prefers its role client, falls back to the shared client).
_ROLE_CONTEXT_KEYS: tuple[tuple[str, str], ...] = (
    ("critic", "critic_model_client"),
    ("planner", "planner_model_client"),
    ("summarizer", "summarizer_model_client"),
)


def _ensure_role_clients(self) -> None:
    """Resolve ``models.roles`` clients once, lazily (capability-upgrade §13).

    Stashes ``<role>_model_client`` in the shared context when a role maps
    to a different model than the shared default client, so role agents'
    LLM calls route to the configured role model. The mission_config's
    ``models`` block (merged by the run-service task builder / AgentLoop
    callers) is the source; resolution is best-effort — any failure leaves
    the context untouched and agents keep using the shared client, exactly
    the pre-role-routing behavior.
    """
    if self._role_clients_resolved:
        return
    self._role_clients_resolved = True
    try:
        cfg = self._context.get("config")
        if not isinstance(cfg, dict) or not cfg.get("models"):
            return
        from tools.mcp_tools.registry import _get_model_router

        router = _get_model_router(cfg)
        if router is None:
            return
        shared = self._context.get("model_client")
        for role, key in _ROLE_CONTEXT_KEYS:
            try:
                client = router.get_client_for_role(role, config=cfg)
            except Exception:  # noqa: BLE001 — one bad role never blocks the others
                continue
            if client is not None and client is not shared:
                self._context[key] = client
    except Exception:  # noqa: BLE001 — role routing must never break dispatch
        pass


def _negotiate(
    self,
    critic: Agent,
    task: dict[str, Any],
    task_id: str,
    target: str,
    agent: Agent,
) -> AgentResult | None:
    """Run the bounded critic↔exploit negotiation and return a blocked
    result on ``deny``, or ``None`` to let the route proceed.

    Behavior by ``self._negotiation_rounds``:

    - ``0`` (default, legacy one-shot): critic reviews once. ``deny``
      blocks; ``modify`` is applied once and the task runs (no re-review).
      Byte-for-byte the pre-negotiation behavior.
    - ``N>0``: critic reviews; on ``modify`` the modifications are applied
      and the critic re-reviews the modified task, up to ``N`` rounds. The
      loop stops early on: ``approve`` (task runs), ``deny`` (blocked), a
      scope-expanding modification (rejected + logged, original task runs),
      or a repeated modification (deadlock — original task runs).

    The negotiation never changes the target/scope: any modification
    touching a key outside ``_NEGOTIABLE_KEYS`` is dropped and the loop
    terminates with the pre-modification task. The allowlist lock is not
    consulted here (it lives at the MCP tool layer); this guard only
    prevents the critic from expanding WHAT the action touches.

    Runs UNLOCKED — ``critic.run`` may call an LLM. All orchestrator state
    mutations (``_results``/``_battle_log``) on the deny path happen under
    ``self._lock``.
    """
    critic_task = {
        "task_id": f"critic-{task_id}",
        "proposed_action": task,
    }
    critic_result = critic.run(critic_task, self._context)
    decision = critic_result.output.get("decision", "approve") if critic_result.output else "approve"
    reasoning = critic_result.output.get("reasoning", "") if critic_result.output else ""

    self._emit(
        "critic_decision",
        {"task_id": task_id, "target": target, "decision": decision, "reasoning": reasoning, "round": 0},
    )

    if decision == "deny":
        return self._record_block(critic, task, task_id, target, agent, reasoning)

    if decision == "modify":
        modifications = critic_result.output.get("modifications", {}) or {}
        # Legacy one-shot path: apply once, no re-review.
        if self._negotiation_rounds <= 0:
            safe = self._filter_modifications(modifications, task_id, target, round_idx=0)
            task.update(safe)
            return None
        # Bounded loop: re-review the modified task up to N rounds.
        return self._negotiation_loop(critic, task, task_id, target, agent, modifications)

    return None


def _negotiation_loop(
    self,
    critic: Agent,
    task: dict[str, Any],
    task_id: str,
    target: str,
    agent: Agent,
    first_modifications: dict[str, Any],
) -> AgentResult | None:
    """Bounded re-review loop. ``first_modifications`` is the round-0
    ``modify`` output already extracted by ``_negotiate``."""
    # Track a hash of each round's proposed modifications so a repeated
    # proposal (same bytes twice in a row) breaks the loop as a deadlock.
    # ponytail: SHA256 of the JSON-sorted modifications dict — O(1) per
    # round, detects the exact-repeat case. A smarter detector would diff
    # semantic content; upgrade if a critic oscillates between two
    # different but equivalent modifications.
    last_hash = self._modifications_hash(first_modifications)
    # Apply the round-0 modifications (filtered for scope safety).
    safe = self._filter_modifications(first_modifications, task_id, target, round_idx=0)
    task.update(safe)

    for round_idx in range(1, self._negotiation_rounds + 1):
        critic_task = {"task_id": f"critic-{task_id}", "proposed_action": task}
        critic_result = critic.run(critic_task, self._context)
        decision = critic_result.output.get("decision", "approve") if critic_result.output else "approve"
        reasoning = critic_result.output.get("reasoning", "") if critic_result.output else ""

        self._emit(
            "critic_decision",
            {
                "task_id": task_id,
                "target": target,
                "decision": decision,
                "reasoning": reasoning,
                "round": round_idx,
            },
        )

        if decision == "deny":
            return self._record_block(critic, task, task_id, target, agent, reasoning)
        if decision == "approve":
            return None
        # decision == "modify": check for scope expansion + deadlock.
        modifications = critic_result.output.get("modifications", {}) or {}
        cur_hash = self._modifications_hash(modifications)
        # If every proposed key is out-of-scope, the critic tried to expand
        # scope — reject, stop negotiating, run the pre-modification task.
        if not self._filter_modifications(modifications, task_id, target, round_idx=round_idx):
            self._emit(
                "negotiation_scope_rejected",
                {"task_id": task_id, "target": target, "round": round_idx, "modifications": modifications},
            )
            return None
        # Deadlock: same modification repeated twice in a row.
        if cur_hash == last_hash:
            self._emit(
                "negotiation_deadlock",
                {"task_id": task_id, "target": target, "round": round_idx},
            )
            return None
        last_hash = cur_hash
        safe = self._filter_modifications(modifications, task_id, target, round_idx=round_idx)
        task.update(safe)

    # Rounds exhausted without consensus: fall back to the current task
    # state (the last accepted modifications) + log. The task runs with
    # whatever modifications were applied in the final accepted round.
    self._emit(
        "negotiation_exhausted",
        {"task_id": task_id, "target": target, "rounds": self._negotiation_rounds},
    )
    return None


def _filter_modifications(
    self,
    modifications: dict[str, Any],
    task_id: str,
    target: str,
    *,
    round_idx: int,
) -> dict[str, Any]:
    """Return only the keys in ``_NEGOTIABLE_KEYS``. Out-of-scope keys are
    dropped silently (the caller emits a ``negotiation_scope_rejected``
    event when the WHOLE modification is empty after filtering)."""
    if not isinstance(modifications, dict):
        return {}
    safe: dict[str, Any] = {}
    rejected: list[str] = []
    for key, value in modifications.items():
        if key in self._NEGOTIABLE_KEYS:
            safe[key] = value
        else:
            rejected.append(key)
    if rejected:
        self._emit(
            "negotiation_keys_rejected",
            {"task_id": task_id, "target": target, "round": round_idx, "keys": rejected},
        )
    return safe


def _modifications_hash(self, modifications: dict[str, Any]) -> str:
    """Stable hash of a modifications dict for deadlock detection."""
    try:
        return hashlib.sha256(json.dumps(modifications, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    except (TypeError, ValueError):
        return ""


def _record_block(
    self,
    critic: Agent,
    task: dict[str, Any],
    task_id: str,
    target: str,
    agent: Agent,
    reasoning: str,
) -> AgentResult:
    """Record a critic ``deny`` as a blocked result + battle-log entry."""
    with self._lock:
        blocked_result = AgentResult(
            agent_type=agent.agent_type,
            status=AgentStatus.BLOCKED,
            task_id=task_id,
            error=f"Critic blocked: {reasoning}",
        )
        agent._set_status(AgentStatus.BLOCKED)
        self._results.append(blocked_result)
        self._battle_log.append(
            {
                "task_id": task_id,
                "tool": task.get("tool", task.get("phase", "")),
                "target": target,
                "success": False,
                "error": f"Critic blocked: {reasoning}",
            }
        )
        self._trim_history()
    self._emit(
        "agent_blocked",
        {
            "agent_id": agent.agent_id,
            "agent_type": agent.agent_type,
            "task_id": task_id,
            "reason": f"Critic blocked: {reasoning}",
        },
    )
    self._persist_state()
    return blocked_result
