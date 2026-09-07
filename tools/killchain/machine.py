"""Kill-chain state machine (design §killchain).

The LLM *proposes*; the machine *verifies*. ``KillChainMachine`` is the only
writer of ``attack_state`` metadata on graph nodes, and it writes a new state
ONLY after the edge's ``verify`` check specs pass through the shared
Feature-1 verifier (:func:`tools.eval_harness.verify_flag_check`). There is
deliberately **no unverified-transition code path** in this module —
``killchain.require_verification`` in config only toggles REPORTING verbosity;
the machine never accepts a request to skip verification (the config flag is
not consulted for enforcement, only for output detail).

Playbook steps run through the normal MCP tool layer (injected
``tool_executor`` or a live MCP ``session.call_tool``) so the target-IP
allowlist lock and the JSONL audit trail apply unchanged — the machine adds
no bypass of its own.
"""

from __future__ import annotations

import time
from collections import deque
from pathlib import Path
from typing import Any, Awaitable, Callable

from tools.exceptions import (
    _EXC_GROUP_CATCH,
    _is_exception_group,
    _log_nested_exceptions,
)
from tools.intelligence.graph.types import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeStatus,
    NodeType,
)
from tools.killchain.edges import EDGES, STUB_EDGES, resolve_placeholders
from tools.killchain.states import AttackState

ToolExecutor = Callable[[str, dict[str, Any]], Awaitable[str]]

DEFAULT_GOAL_STATE = AttackState.SHELL_AS_ROOT.value


class KillChainMachine:
    """Verified-only kill-chain transition machine.

    Args:
        graph_store: an :class:`AttackGraphStore` (or a duck-typed stand-in
            with ``upsert_node`` / ``get_node_by_value``).
        workspace: per-target workspace directory (evidence excerpts).
        config: full app config dict (reads the ``killchain`` block).
        session: live MCP client session. Used only when ``tool_executor`` is
            not provided.
        tool_executor: ``async (tool_name, args) -> str``. Takes precedence
            over ``session``; this is the seam tests inject fakes into.
        check_executor: sync ``(check_spec) -> (passed, detail)`` from
            :func:`tools.eval_checks.default_check_executor`. Lazily built
            with the machine's session/workspace when omitted.
        run_dir: run directory for decision-log events.
        decision_log_enabled: caller-supplied gate (the loop's
            ``agent.decision_log_enabled`` read).
        now_fn: injectable clock (tests).
    """

    def __init__(
        self,
        *,
        graph_store: Any,
        workspace: str | Path = "",
        config: dict[str, Any] | None = None,
        session: Any = None,
        tool_executor: ToolExecutor | None = None,
        check_executor: Callable[[dict[str, Any]], tuple[bool, str]] | None = None,
        run_dir: str | Path = "",
        decision_log_enabled: bool = True,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self.graph_store = graph_store
        self.workspace = Path(workspace) if workspace else None
        self.config = config or {}
        self.session = session
        self.tool_executor = tool_executor
        self.check_executor = check_executor
        self.run_dir = Path(run_dir) if run_dir else None
        self.decision_log_enabled = decision_log_enabled
        self._now_fn = now_fn or time.time
        kc_cfg = (self.config.get("killchain", {}) or {}) if isinstance(self.config, dict) else {}
        self.goal_state = str(kc_cfg.get("goal_state") or DEFAULT_GOAL_STATE)
        # require_verification only toggles reporting verbosity. Verification
        # is unconditional; a request to skip it is structurally impossible.
        self.verbose_reporting = bool(kc_cfg.get("require_verification", True))

    # -- scope / node helpers ------------------------------------------------

    def _scope(self, target: str) -> str:
        return f"target:{target}"

    def _host_node(self, target: str) -> GraphNode:
        """Current host node for ``target`` (fresh node if never seen)."""
        existing = self.graph_store.get_node_by_value(NodeType.HOST, target, self._scope(target))
        if existing is not None:
            return existing
        return GraphNode(
            node_id=f"host:{target}",
            node_type=NodeType.HOST,
            value=target,
            scope=self._scope(target),
            status=NodeStatus.UNKNOWN,
            source="killchain",
        )

    # -- tool execution ------------------------------------------------------

    async def _run_tool(self, tool_name: str, args: dict[str, Any]) -> str:
        """Run one playbook step through the MCP tool layer."""
        if self.tool_executor is not None:
            try:
                return await self.tool_executor(tool_name, args)
            except _EXC_GROUP_CATCH as exc:  # pragma: no cover - defensive
                if _is_exception_group(exc):
                    _log_nested_exceptions(exc, prefix="killchain.tool_executor")
                raise
        if self.session is not None:
            try:
                result = await self.session.call_tool(tool_name, args)
            except _EXC_GROUP_CATCH as exc:
                if _is_exception_group(exc):
                    _log_nested_exceptions(exc, prefix="killchain.session.call_tool")
                raise
            return _content_text(result)
        raise NotImplementedError("no tool executor wired: pass tool_executor or session")

    # -- verification --------------------------------------------------------

    def _executor(self) -> Callable[[dict[str, Any]], tuple[bool, str]]:
        if self.check_executor is not None:
            return self.check_executor
        from tools.eval_checks import default_check_executor

        return default_check_executor(session=self.session, workspace=str(self.workspace) if self.workspace else None)

    # -- transitions ---------------------------------------------------------

    def can_transition(self, from_state: str, to_state: str) -> bool:
        """True when a registered (non-stub) edge connects the two states."""
        try:
            src = AttackState.parse(from_state)
            dst = AttackState.parse(to_state)
        except ValueError:
            return False
        return any(
            e
            for e in EDGES.values()
            if e["from_state"] == src.value and e["to_state"] == dst.value and e["edge_id"] not in STUB_EDGES
        )

    def _resolve_edge(self, from_state: str, to_state: str, edge_id: str | None) -> tuple[Any | None, str]:
        """Resolve the edge to run. Returns (edge, error)."""
        try:
            src = AttackState.parse(from_state)
            dst = AttackState.parse(to_state)
        except ValueError as exc:
            return None, str(exc)
        candidates = [
            e
            for e in EDGES.values()
            if e["from_state"] == src.value and e["to_state"] == dst.value and e["edge_id"] not in STUB_EDGES
        ]
        if edge_id:
            candidates = [e for e in candidates if e["edge_id"] == edge_id]
            if not candidates:
                return None, f"edge {edge_id!r} does not connect {src.value} -> {dst.value}"
        if not candidates:
            return None, f"no registered edge connects {src.value} -> {dst.value}"
        return candidates[0], ""

    async def attempt_transition(
        self,
        target: str,
        from_state: str,
        to_state: str,
        edge_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Propose → execute playbook → verify → (only then) commit state.

        Returns a result dict: ``{"success", "edge_id", "from_state",
        "to_state", "steps": [...], "checks": [...], "error"}``.
        On verification failure the graph is untouched.
        """
        started = self._now_fn()
        edge, error = self._resolve_edge(from_state, to_state, edge_id)
        if edge is None:
            return {"success": False, "error": error, "blocked": True, "from_state": from_state, "to_state": to_state}

        ctx: dict[str, Any] = {**(context or {}), "target_ip": target}
        steps: list[dict[str, Any]] = []
        for step in edge["playbook"]:
            tool_name = str(step.get("tool", ""))
            args = {k: resolve_placeholders(v, ctx) for k, v in (step.get("args") or {}).items()}
            try:
                output = await self._run_tool(tool_name, args)
            except _EXC_GROUP_CATCH as exc:
                # _EXC_GROUP_CATCH, not bare Exception: anyio task groups raise
                # BaseExceptionGroup (not an Exception subclass) on MCP
                # subprocess death — missing it crashed killchain_attempt.
                _log_nested_exceptions(exc)
                steps.append({"tool": tool_name, "args": args, "error": str(exc)})
                return {
                    "success": False,
                    "edge_id": edge["edge_id"],
                    "from_state": from_state,
                    "to_state": to_state,
                    "steps": steps,
                    "error": f"playbook step {tool_name!r} failed: {exc}",
                }
            steps.append({"tool": tool_name, "args": args, "output": str(output)[:2000]})

        checks: list[dict[str, Any]] = []
        from tools.eval_harness import verify_flag_check

        executor = self._executor()
        all_passed = True
        for spec in edge["verify"]:
            resolved_spec = _resolve_check_spec(spec, ctx)
            try:
                result = await asyncio_to_thread(verify_flag_check, resolved_spec, executor)
            except _EXC_GROUP_CATCH as exc:
                # Same MCP-death group hazard as the playbook steps above.
                _log_nested_exceptions(exc)
                checks.append({"flag_id": str(spec.get("id", "")), "passed": False, "detail": f"check error: {exc}"})
                all_passed = False
                continue
            checks.append({"flag_id": result.flag_id, "passed": result.passed, "detail": result.detail})
            if not result.passed:
                all_passed = False
        if not all_passed:
            self._log_decision(target, edge, success=False, duration_s=self._now_fn() - started, checks=checks)
            return {
                "success": False,
                "edge_id": edge["edge_id"],
                "from_state": from_state,
                "to_state": to_state,
                "steps": steps,
                "checks": checks,
                "error": "verification failed — state unchanged",
            }

        evidence_ref = self._commit(target, edge, from_state, to_state, checks)
        self._log_decision(target, edge, success=True, duration_s=self._now_fn() - started, checks=checks)
        return {
            "success": True,
            "edge_id": edge["edge_id"],
            "from_state": from_state,
            "to_state": to_state,
            "steps": steps,
            "checks": checks,
            "evidence_ref": evidence_ref,
        }

    # -- commit ---------------------------------------------------------------

    def _commit(
        self,
        target: str,
        edge: dict[str, Any],
        from_state: str,
        to_state: str,
        checks: list[dict[str, Any]],
    ) -> str:
        """Verified-success commit: attack_state merge + evidence node + edge."""
        scope = self._scope(target)
        ts = f"{self._now_fn():.3f}"

        host = self._host_node(target)
        host_id = self.graph_store.upsert_node(
            GraphNode(
                node_id=host.node_id or f"host:{target}",
                node_type=NodeType.HOST,
                value=target,
                scope=scope,
                properties={
                    "attack_state": AttackState.parse(to_state).value,
                    "attack_state_previous": from_state,
                    "attack_state_edge": edge["edge_id"],
                    "attack_state_at": ts,
                },
                status=NodeStatus.CONFIRMED,
                source="killchain",
            )
        )

        evidence_value = f"killchain:{edge['edge_id']}:{ts}"
        evidence_node = GraphNode(
            node_id=f"ev:killchain:{edge['edge_id']}:{ts}",
            node_type=NodeType.EVIDENCE,
            value=evidence_value,
            scope=scope,
            properties={
                "evidence_type": edge.get("evidence_type", ""),
                "edge_id": edge["edge_id"],
                "from_state": from_state,
                "to_state": to_state,
                "checks": checks,
            },
            status=NodeStatus.CONFIRMED,
            confidence=0.9,
            source="killchain",
        )
        evidence_id = self.graph_store.upsert_node(evidence_node)
        try:
            self.graph_store.upsert_edge(
                GraphEdge(
                    edge_id=f"e:{evidence_id}",
                    source_node_id=evidence_id,
                    target_node_id=host_id,
                    edge_type=EdgeType.OBSERVED_ON,
                    scope=scope,
                    properties={"edge_id": edge["edge_id"]},
                    source="killchain",
                )
            )
        except ValueError:
            # Duck-typed test stores may not implement edges; state commit stands.
            pass
        return f"ev:{evidence_value}"

    def _log_decision(
        self,
        target: str,
        edge: dict[str, Any],
        *,
        success: bool,
        duration_s: float,
        checks: list[dict[str, Any]],
    ) -> None:
        if not self.decision_log_enabled or self.run_dir is None:
            return
        try:
            from tools.decision_log import log_decision

            log_decision(
                self.run_dir,
                task_id=f"killchain:{edge['edge_id']}",
                target=target,
                capability="killchain",
                reason=f"edge {edge['edge_id']} {edge['from_state']} -> {edge['to_state']}",
                model_role="killchain_machine",
                duration_s=duration_s,
                outcome="verified_transition" if success else "verification_failed",
                failure_class="" if success else "verify_failed",
                success=success,
                evidence_refs=[f"check:{c.get('flag_id', '')}:{'pass' if c.get('passed') else 'fail'}" for c in checks],
            )
        except Exception:  # noqa: BLE001 - decision logging must never break the loop
            pass

    # -- reads ----------------------------------------------------------------

    def status(self, target: str) -> dict[str, Any]:
        """Current kill-chain state for ``target`` (default ``discovered``)."""
        node = self.graph_store.get_node_by_value(NodeType.HOST, target, self._scope(target))
        raw = (
            node.properties.get("attack_state", "") if node and node.properties else ""
        ) or AttackState.DISCOVERED.value
        current = AttackState.parse(raw).value
        return {
            "target": target,
            "state": current,
            "applicable_edges": [e["edge_id"] for e in edges_from_safe(current)],
            "goal_state": self.goal_state,
            "path_to_goal": self.plan(target, self.goal_state),
        }

    def plan(self, target: str, goal_state: str = "") -> list[str]:
        """BFS shortest edge-id path from the target's current state to the goal."""
        try:
            goal = AttackState.parse(goal_state or self.goal_state).value
        except ValueError:
            return []
        node = self.graph_store.get_node_by_value(NodeType.HOST, target, self._scope(target))
        raw = (
            node.properties.get("attack_state", "") if node and node.properties else ""
        ) or AttackState.DISCOVERED.value
        try:
            start = AttackState.parse(raw).value
        except ValueError:
            return []
        if start == goal:
            return []
        # BFS over the edge registry (BloodHound shortest-path, but generic).
        queue: deque[tuple[str, list[str]]] = deque([(start, [])])
        visited = {start}
        while queue:
            state, path = queue.popleft()
            for edge in EDGES.values():
                if edge["from_state"] != state:
                    continue
                nxt = edge["to_state"]
                if nxt in visited:
                    continue
                new_path = path + [edge["edge_id"]]
                if nxt == goal:
                    return new_path
                visited.add(nxt)
                queue.append((nxt, new_path))
        return []


def _resolve_check_spec(spec: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    """Resolve ``{placeholder}`` tokens in a verify check spec.

    Handles both shapes ``verify_flag_check`` accepts: a bare check spec and
    a nested ``{"id", "description", "check": {...}}`` entry.
    """
    resolved = {k: resolve_placeholders(v, ctx) for k, v in spec.items()}
    inner = resolved.get("check")
    if isinstance(inner, dict):
        resolved["check"] = {k: resolve_placeholders(v, ctx) for k, v in inner.items()}
    return resolved


def edges_from_safe(state: str) -> list[dict[str, Any]]:
    """``edges.edges_from`` that never raises on an unparseable state."""
    from tools.killchain.edges import edges_from

    try:
        return edges_from(state)
    except ValueError:
        return []


async def asyncio_to_thread(fn: Callable[..., Any], /, *args: Any) -> Any:
    """Local alias so the module does not depend on the stdlib name spelling."""
    import asyncio

    return await asyncio.to_thread(fn, *args)


def _content_text(result: Any) -> str:
    """Best-effort text extraction from an MCP CallToolResult."""
    try:
        parts = getattr(result, "content", None) or []
        texts = [getattr(p, "text", "") for p in parts]
        return "\n".join(t for t in texts if t)
    except Exception:  # noqa: BLE001
        return str(result)
