"""Kill-chain MCP tool registration.

Three tools that expose the kill-chain state machine (tools/killchain/) to
the agent:

  - ``killchain_status``  read-only snapshot: current state per target,
                          applicable edges, shortest path to the goal state
  - ``killchain_attempt`` propose a transition — the LLM proposes, the
                          machine executes the edge playbook through the
                          normal MCP tool layer and VERIFIES via the shared
                          Feature-1 check specs; only verified success moves
                          the state. The LLM cannot bypass verification.
  - ``killchain_plan``    read-only BFS shortest path to a goal state

Opt-in: registered only when ``killchain.enabled`` is true in config
(default false). Playbook steps run through the SAME registered tool
functions the agent calls (in-process dispatch via FastMCP introspection),
so the target-IP allowlist lock and the JSONL audit trail apply unchanged.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.killchain import KillChainMachine, all_edges, get_edge
from tools.killchain.states import AttackState
from tools.mcp_tools.registry import ToolContext
from tools.validation_utils import validate_target_or_ip


def _in_process_tool_executor(mcp: Any):
    """Build the machine's tool executor: dispatch to registered tool fns.

    Uses the same decorated functions the agent invokes over MCP
    (FastMCP's ``_tool_manager._tools[name].fn``), so every playbook step
    re-applies the target-IP allowlist and writes audit rows. Falls back to
    a stub ``mcp.tools`` dict for in-process test harnesses.
    """

    def _resolve(name: str) -> Any | None:
        tm = getattr(mcp, "_tool_manager", None)
        tools = getattr(tm, "_tools", None) if tm is not None else None
        if tools:
            entry = tools.get(name)
            if entry is not None:
                return getattr(entry, "fn", entry)
        simple = getattr(mcp, "tools", None)
        if isinstance(simple, dict):
            return simple.get(name)
        return None

    async def _executor(tool_name: str, args: dict[str, Any]) -> str:
        fn = _resolve(tool_name)
        if fn is None:
            raise NotImplementedError(f"tool {tool_name!r} is not registered on this MCP server")
        if asyncio.iscoroutinefunction(fn):
            return str(await fn(**args))
        return str(await asyncio.to_thread(fn, **args))

    return _executor


def _in_process_shell_session(mcp: Any) -> Any:
    """Sync ``(tool_name, args) -> str`` session for ``shell_command`` verifies.

    Routes ``run_exploit_terminal`` through the same in-process dispatch as
    playbooks, so verify probes honor the allowlist + audit trail. Dispatch
    failures raise (``eval_checks`` degrades them to UNVERIFIED, never a pass).
    Safe from any thread: hops to a fresh loop when the caller sits in one.
    """
    _dispatch = _in_process_tool_executor(mcp)

    def _call(tool_name: str, args: dict[str, Any]) -> str:
        coro = _dispatch(tool_name, args)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return str(asyncio.run(coro))
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return str(pool.submit(asyncio.run, coro).result())

    return _call


def register_killchain_tools(mcp: Any, *, ctx: ToolContext) -> None:
    config = ctx.config
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist
    workspace = ctx.workspace
    kc_cfg = (config or {}).get("killchain", {}) or {}
    if not bool(kc_cfg.get("enabled", False)):
        return

    graph_db = Path(str(kc_cfg.get("graph_db") or (workspace / "killchain_graph.db")))
    graph_db.parent.mkdir(parents=True, exist_ok=True)
    from tools.eval_checks import default_check_executor
    from tools.intelligence.graph.store import AttackGraphStore

    store = AttackGraphStore(graph_db, scope="")
    machine = KillChainMachine(
        graph_store=store,
        workspace=workspace,
        config=config,
        tool_executor=_in_process_tool_executor(mcp),
        check_executor=default_check_executor(session=_in_process_shell_session(mcp), workspace=workspace),
        run_dir=workspace,
        decision_log_enabled=bool(((config or {}).get("agent", {}) or {}).get("decision_log_enabled", True)),
    )

    def _format_edge(edge_id: str) -> str:
        edge = get_edge(edge_id)
        if edge is None:
            return edge_id
        return f"{edge_id} ({edge['from_state']} -> {edge['to_state']})"

    # ------------------------------------------------------------------
    # 1. killchain_status -- read-only
    # ------------------------------------------------------------------
    @mcp.tool()
    @audit_tool
    def killchain_status(target: str) -> str:
        """Read-only kill-chain snapshot for a target: current state, applicable edges, and the shortest verified-edge path to the configured goal state. No target touch -- reads the kill-chain graph only."""
        if not target or not target.strip():
            return "BLOCKED: target is required."
        try:
            snap = machine.status(target.strip())
        except Exception as exc:  # noqa: BLE001  # ponytail: bare except intentional
            return f"ERROR: killchain_status failed: {exc}"
        lines = [
            "KILLCHAIN_STATUS:",
            f"TARGET: {snap['target']}",
            f"STATE: {snap['state']}",
            f"GOAL: {snap['goal_state']}",
            f"APPLICABLE_EDGES: {', '.join(snap['applicable_edges']) or '(none)'}",
            f"PATH_TO_GOAL: {' -> '.join(snap['path_to_goal']) or '(no registered path)'}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 2. killchain_attempt -- target-touching, verified-only
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def killchain_attempt(
        target: str, from_state: str, to_state: str, edge_id: str = "", context_json: str = ""
    ) -> str:
        """Attempt a verified kill-chain transition (e.g. creds_in_hand -> shell_as_user). The machine runs the edge's playbook through the normal MCP tool layer (allowlist + audit apply) and then independently verifies success via check probes; the state is ONLY updated when verification passes. You can propose but cannot bypass verification.

        Args:
            target: The target IP or hostname (must be allowlisted).
            from_state: Current attack state (e.g. ``creds_in_hand``).
            to_state: Desired attack state (e.g. ``shell_as_user``).
            edge_id: Optional tiebreaker when several edges connect the states.
            context_json: Optional JSON object with playbook placeholders
                (``user``, ``password``, ``port``, ...).
        """
        if not target or not target.strip():
            return "BLOCKED: target is required."
        if not validate_target_or_ip(target.strip()):
            return f"BLOCKED: {target.strip()!r} is not a valid target IP or hostname."
        # P3-11 pack gate: destructive kill-chain playbooks require the
        # snapshot safety net. Fail fast with guidance (never run
        # net-less); read-only killchain_status/plan are unaffected.
        from tools.snapshots import autonomy_pack_guidance as _pack_guidance

        _guidance = _pack_guidance(config)
        if _guidance:
            return _guidance
        import json as _json

        context: dict[str, Any] = {}
        if context_json and context_json.strip():
            try:
                parsed = _json.loads(context_json)
                if not isinstance(parsed, dict):
                    return "BLOCKED: context_json must be a JSON object."
                context = parsed
            except _json.JSONDecodeError as exc:
                return f"BLOCKED: context_json is not valid JSON ({exc})."
        try:
            coro = machine.attempt_transition(
                target.strip(), from_state, to_state, edge_id=edge_id or None, context=context
            )
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                result = asyncio.run(coro)
            else:
                # Already inside a loop (in-process test harnesses): hop to a
                # worker thread so the machine gets its own clean loop.
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    result = pool.submit(asyncio.run, coro).result()
        except NotImplementedError as exc:
            return f"ERROR: killchain_attempt unavailable: {exc}"
        except Exception as exc:  # noqa: BLE001  # ponytail: bare except intentional
            return f"ERROR: killchain_attempt failed: {exc}"

        header = "KILLCHAIN_TRANSITION:" if result.get("success") else "KILLCHAIN_FAILED:"
        lines = [
            header,
            f"TARGET: {target.strip()}",
            f"EDGE: {result.get('edge_id', '(none)')}",
            f"TRANSITION: {result.get('from_state', from_state)} -> {result.get('to_state', to_state)}",
        ]
        if result.get("blocked"):
            lines.append(f"BLOCKED: {result.get('error', '')}")
        if result.get("error"):
            lines.append(f"ERROR: {result['error']}")
        checks = result.get("checks") or []
        if checks:
            lines.append("VERIFICATION:")
            for check in checks:
                lines.append(
                    f"  [{'PASS' if check.get('passed') else 'FAIL'}] {check.get('flag_id', '')}: {check.get('detail', '')}"
                )
        if result.get("success") and result.get("evidence_ref"):
            lines.append(f"EVIDENCE: {result['evidence_ref']}")
        if not result.get("success"):
            lines.append("STATE UNCHANGED (verification failed or transition rejected).")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 3. killchain_plan -- read-only BFS
    # ------------------------------------------------------------------
    @mcp.tool()
    @audit_tool
    def killchain_plan(target: str, goal_state: str = "") -> str:
        """Compute the shortest kill-chain path (BFS over verified edges) from the target's current state to a goal state. Read-only planning -- executes nothing. ``goal_state`` defaults to the configured ``killchain.goal_state`` (fallback ``shell_as_root``)."""
        if not target or not target.strip():
            return "BLOCKED: target is required."
        goal = goal_state.strip() or str(machine.goal_state)
        try:
            AttackState.parse(goal)
        except ValueError as exc:
            return f"BLOCKED: {exc}"
        try:
            path = machine.plan(target.strip(), goal)
            snap = machine.status(target.strip())
        except Exception as exc:  # noqa: BLE001  # ponytail: bare except intentional
            return f"ERROR: killchain_plan failed: {exc}"
        lines = [
            "KILLCHAIN_PLAN:",
            f"TARGET: {snap['target']}",
            f"CURRENT_STATE: {snap['state']}",
            f"GOAL_STATE: {goal}",
            "PATH:",
        ]
        if path:
            lines.extend(f"  {i + 1}. {_format_edge(eid)}" for i, eid in enumerate(path))
        else:
            lines.append("  (no registered edge path — free-form module planning applies)")
        lines.append(f"REGISTERED_EDGES: {len(all_edges())} (stubs excluded)")
        return "\n".join(lines)


__all__ = ["register_killchain_tools"]
