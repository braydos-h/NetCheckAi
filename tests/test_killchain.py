"""Tests for the kill-chain state machine (design §killchain).

Covers:
- ``AttackState`` parsing (tolerant + strict).
- Edge registry accessors + placeholder resolution.
- ``KillChainMachine`` transition matrix: verified success commits state +
  evidence + decision log; failed verification changes nothing; unknown
  transitions are rejected; ``can_transition`` truth table; BFS planning.
- Graph persistence round-trip through a real ``AttackGraphStore`` file.
- The killchain MCP family (registered against a stub FastMCP): status /
  attempt / plan, allowlist blocking, and disabled-family registration.
- Orchestrator kill-chain preference: edge path attempted before free-form
  planning, fallback on unverified edge.
- End-to-end scripted chain (discovered -> ... -> shell_as_user) with zero
  free-form commands.

All mocked — no subprocess/network/model calls.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------


class _StubMCP:
    """Minimal FastMCP stand-in: records decorated tool functions by name."""

    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, *args: Any, **kwargs: Any) -> Any:
        def decorator(fn: Any) -> Any:
            self.tools[fn.__name__] = fn
            return fn

        return decorator

    _tool_manager: Any = None


def _build_ctx(
    tmp_path: Path,
    *,
    enabled: bool = True,
    require_allowlist_flag: bool = True,
    allowed: tuple[str, ...] = ("10.0.0.50",),
    snapshots_enabled: bool = True,
) -> Any:
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.mcp_shared import make_audit_tool, make_require_allowlist
    from tools.mcp_tools.registry import ToolContext
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "killchain": {"enabled": enabled, "goal_state": "shell_as_root", "require_verification": True},
        # P3-11 pack gate: destructive killchain_attempt requires the
        # snapshot net; the harness enables it so attempt tests exercise
        # the gated-on path (the gated-off path has its own test below).
        "snapshots": {"enabled": snapshots_enabled},
        "exploit": {
            "require_explicit_allowlist": require_allowlist_flag,
            "allowed_targets": list(allowed),
        },
        "agent": {"decision_log_enabled": True},
    }
    return ToolContext(
        workspace=tmp_path,
        config=config,
        search=ExploitSearch(ExploitSearchSettings()),
        nvd=NVDClient(CVESearchSettings()),
        researcher=WebResearcher(WebResearcherSettings()),
        audit_tool=make_audit_tool(tmp_path),
        require_allowlist=make_require_allowlist(tmp_path, config),
    )


class FakeToolExecutor:
    """Async (tool_name, args) -> str fake; scripted per tool name."""

    def __init__(self, outputs: dict[str, str] | None = None, fail_tools: set[str] | None = None) -> None:
        self.outputs = outputs or {}
        self.fail_tools = fail_tools or set()
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, tool_name: str, args: dict[str, Any]) -> str:
        self.calls.append((tool_name, args))
        if tool_name in self.fail_tools:
            raise RuntimeError(f"tool {tool_name} exploded")
        return self.outputs.get(tool_name, "OUTPUT: ok")


class FakeCheckExecutor:
    """Sync (check) -> (passed, detail) fake; scripted by flag id."""

    def __init__(self, results: dict[str, bool] | None = None, default: bool = True) -> None:
        self.results = results or {}
        self.default = default
        self.seen: list[dict[str, Any]] = []

    def __call__(self, check: dict[str, Any]) -> tuple[bool, str]:
        self.seen.append(check)
        flag_id = str(check.get("id", ""))
        passed = self.results.get(flag_id, self.default)
        return passed, f"fake check {flag_id} -> {passed}"


def _run_coro(coro: Any) -> Any:
    """Run a coroutine from sync test code and from inside a running loop."""
    import concurrent.futures

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _machine(tmp_path: Path, *, tool_executor: Any = None, check_executor: Any = None, run_dir: bool = True) -> Any:
    from tools.intelligence.graph.store import AttackGraphStore
    from tools.killchain import KillChainMachine

    return KillChainMachine(
        graph_store=AttackGraphStore(":memory:"),
        workspace=tmp_path,
        config={"killchain": {"enabled": True, "goal_state": "shell_as_root", "require_verification": True}},
        tool_executor=tool_executor if tool_executor is not None else FakeToolExecutor(),
        check_executor=check_executor if check_executor is not None else FakeCheckExecutor(),
        run_dir=tmp_path if run_dir else None,
    )


# ---------------------------------------------------------------------------
# States + edges
# ---------------------------------------------------------------------------


def test_state_parse_tolerant() -> None:
    from tools.killchain import AttackState

    assert AttackState.parse("SHELL_AS_ROOT") is AttackState.SHELL_AS_ROOT
    assert AttackState.parse("root") is AttackState.SHELL_AS_ROOT
    assert AttackState.parse("creds") is AttackState.CREDS_IN_HAND
    with pytest.raises(ValueError):
        AttackState.parse("not-a-state")


def test_edge_registry_accessors() -> None:
    from tools.killchain import all_edges, edges_from, get_edge

    edge = get_edge("cred_ssh_login")
    assert edge is not None
    assert edge["from_state"] == "creds_in_hand"
    assert edge["to_state"] == "shell_as_user"
    from_states = {e["from_state"] for e in edges_from("creds_in_hand")}
    assert from_states == {"creds_in_hand"}
    # no stubs ship: every registered edge has a working verify story
    assert "kerberoast_to_da" in {e["edge_id"] for e in all_edges()}
    assert "kerberoast_to_da" in {e["edge_id"] for e in all_edges(include_stubs=True)}
    assert "domain_login_validate" in {e["edge_id"] for e in all_edges()}
    # unparseable states are tolerant
    assert edges_from("bogus") == []


def test_placeholder_resolution() -> None:
    from tools.killchain import resolve_placeholders

    ctx = {"target_ip": "10.0.0.50", "user": "root", "password": "hunter2"}
    assert resolve_placeholders("ssh {user}@{target_ip}", ctx) == "ssh root@10.0.0.50"
    # missing placeholder survives (visible failure, not silent)
    assert resolve_placeholders("p {port}", ctx) == "p {port}"
    # non-str values pass through untouched
    assert resolve_placeholders(7, ctx) == 7


# ---------------------------------------------------------------------------
# Machine: transition matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verified_transition_commits_state_evidence_and_decision_log(tmp_path: Path) -> None:
    machine = _machine(tmp_path, tool_executor=FakeToolExecutor(), check_executor=FakeCheckExecutor())
    result = await machine.attempt_transition(
        "10.0.0.50",
        "creds_in_hand",
        "shell_as_user",
        edge_id="cred_ssh_login",
        context={"user": "root", "password": "pw"},
    )
    assert result["success"] is True
    assert result["edge_id"] == "cred_ssh_login"
    # state committed on the graph
    snap = machine.status("10.0.0.50")
    assert snap["state"] == "shell_as_user"
    # evidence node written + linked (evidence_ref is "ev:<evidence value>")
    from tools.intelligence.graph.types import NodeType

    node = machine.graph_store.get_node_by_value(NodeType.EVIDENCE, result["evidence_ref"][3:], "target:10.0.0.50")
    assert node is not None
    assert node.properties["edge_id"] == "cred_ssh_login"
    # decision-log event written
    log = (tmp_path / "decision_log.jsonl").read_text(encoding="utf-8")
    records = [json.loads(line) for line in log.splitlines() if line.strip()]
    assert any(r["success"] and r["capability"] == "killchain" for r in records)
    # playbook ran through the injected executor (allowlist/audit live there)
    assert machine.tool_executor.calls, "playbook must run through the tool executor"


@pytest.mark.asyncio
async def test_failed_verification_leaves_state_unchanged(tmp_path: Path) -> None:
    machine = _machine(tmp_path, check_executor=FakeCheckExecutor({"ssh_uid_probe": False}))
    result = await machine.attempt_transition("10.0.0.50", "creds_in_hand", "shell_as_user")
    assert result["success"] is False
    assert result["error"] == "verification failed — state unchanged"
    assert machine.status("10.0.0.50")["state"] == "discovered"
    # a failure decision event is still logged (observability)
    log = (tmp_path / "decision_log.jsonl").read_text(encoding="utf-8")
    records = [json.loads(line) for line in log.splitlines() if line.strip()]
    assert any(not r["success"] and r["failure_class"] == "verify_failed" for r in records)


@pytest.mark.asyncio
async def test_invalid_transition_rejected(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    result = await machine.attempt_transition("10.0.0.50", "discovered", "da")
    assert result["success"] is False
    assert result.get("blocked") is True
    assert "no registered edge" in result["error"]
    # unknown state names are rejected too
    result2 = await machine.attempt_transition("10.0.0.50", "warp", "da")
    assert result2["success"] is False


@pytest.mark.asyncio
async def test_playbook_tool_failure_is_reported_not_committed(tmp_path: Path) -> None:
    machine = _machine(tmp_path, tool_executor=FakeToolExecutor(fail_tools={"run_exploit_terminal"}))
    result = await machine.attempt_transition("10.0.0.50", "creds_in_hand", "shell_as_user")
    assert result["success"] is False
    assert "failed" in result["error"]
    assert machine.status("10.0.0.50")["state"] == "discovered"


def test_can_transition_truth_table(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    assert machine.can_transition("creds_in_hand", "shell_as_user") is True
    assert machine.can_transition("discovered", "da") is False
    assert machine.can_transition("bogus", "reachable") is False
    # domain path is live: creds -> domain_creds -> da
    assert machine.can_transition("creds_in_hand", "domain_creds") is True
    assert machine.can_transition("domain_creds", "da") is True
    # privesc path is live: user shell -> root shell (default goal reachable)
    assert machine.can_transition("shell_as_user", "shell_as_root") is True


def test_bfs_plan_shortest_path(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    # from a seeded creds_in_hand state the path to shell_as_user is one edge
    from tools.intelligence.graph.types import GraphNode, NodeType

    machine.graph_store.upsert_node(
        GraphNode(
            node_id="h",
            node_type=NodeType.HOST,
            value="10.0.0.50",
            scope="target:10.0.0.50",
            properties={"attack_state": "creds_in_hand"},
        )
    )
    assert machine.plan("10.0.0.50", "shell_as_user") == ["cred_ssh_login"]
    # already at goal -> empty plan
    assert machine.plan("10.0.0.50", "creds_in_hand") == []
    # unknown goal -> no path
    assert machine.plan("10.0.0.50", "warp") == []
    # default goal is reachable from a user shell via the privesc edge
    machine.graph_store.upsert_node(
        GraphNode(
            node_id="h2",
            node_type=NodeType.HOST,
            value="10.0.0.51",
            scope="target:10.0.0.51",
            properties={"attack_state": "shell_as_user"},
        )
    )
    assert machine.plan("10.0.0.51", "shell_as_root") == ["privesc_sudo_to_root"]


@pytest.mark.asyncio
async def test_privesc_edge_verifies_end_to_end(tmp_path: Path) -> None:
    """shell_as_user -> shell_as_root commits only on a uid=0( verify."""
    machine = _machine(tmp_path, tool_executor=FakeToolExecutor(), check_executor=FakeCheckExecutor())
    result = await machine.attempt_transition("10.0.0.50", "shell_as_user", "shell_as_root")
    assert result["success"] is True
    assert result["edge_id"] == "privesc_sudo_to_root"
    assert machine.status("10.0.0.50")["state"] == "shell_as_root"


# ---------------------------------------------------------------------------
# Graph persistence round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_graph_state_survives_machine_reconstruction(tmp_path: Path) -> None:
    from tools.intelligence.graph.store import AttackGraphStore
    from tools.killchain import KillChainMachine

    db = tmp_path / "g.db"
    store = AttackGraphStore(db)
    first = KillChainMachine(
        graph_store=store,
        workspace=tmp_path,
        config={"killchain": {"enabled": True}},
        tool_executor=FakeToolExecutor(),
        check_executor=FakeCheckExecutor(),
    )
    await first.attempt_transition("10.0.0.77", "creds_in_hand", "shell_as_user")
    store.close()

    second = KillChainMachine(
        graph_store=AttackGraphStore(db),
        workspace=tmp_path,
        config={"killchain": {"enabled": True}},
    )
    assert second.status("10.0.0.77")["state"] == "shell_as_user"


# ---------------------------------------------------------------------------
# MCP family
# ---------------------------------------------------------------------------


def test_family_not_registered_when_disabled(tmp_path: Path) -> None:
    from tools.mcp_tools.killchain import register_killchain_tools

    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=_build_ctx(tmp_path, enabled=False))
    assert not mcp.tools


def test_family_registers_three_tools(tmp_path: Path) -> None:
    from tools.mcp_tools.killchain import register_killchain_tools

    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=_build_ctx(tmp_path))
    assert set(mcp.tools) == {"killchain_status", "killchain_attempt", "killchain_plan"}


def test_killchain_status_block(tmp_path: Path) -> None:
    from tools.mcp_tools.killchain import register_killchain_tools

    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=_build_ctx(tmp_path))
    out = mcp.tools["killchain_status"](target="10.0.0.50")
    assert out.startswith("KILLCHAIN_STATUS:")
    assert "STATE: discovered" in out


def test_killchain_status_blocked_on_empty_target(tmp_path: Path) -> None:
    from tools.mcp_tools.killchain import register_killchain_tools

    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=_build_ctx(tmp_path))
    assert mcp.tools["killchain_status"](target="").startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_killchain_attempt_success_flow(tmp_path: Path) -> None:
    from tools.mcp_tools.killchain import register_killchain_tools

    ctx = _build_ctx(tmp_path)
    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=ctx)
    # Seed the graph at creds_in_hand and make the family's in-process
    # dispatch succeed: the ssh probe (a shell_command) runs against the
    # registered run_exploit_terminal fn, so give the fake check executor a
    # pass; the machine is built inside the registrar, so drive it via the
    # tool with a pre-seeded store: easiest is to seed through the same
    # graph db file the family created.
    db = tmp_path / "killchain_graph.db"
    from tools.intelligence.graph.store import AttackGraphStore
    from tools.intelligence.graph.types import GraphNode, NodeType

    store = AttackGraphStore(db)
    store.upsert_node(
        GraphNode(
            node_id="h",
            node_type=NodeType.HOST,
            value="10.0.0.50",
            scope="target:10.0.0.50",
            properties={"attack_state": "creds_in_hand"},
        )
    )
    store.close()
    # The family machine verifies with default_check_executor (no session ->
    # shell_command checks return UNVERIFIED False), so the transition fails
    # verification by design here; assert the KILLCHAIN_FAILED contract.
    out = mcp.tools["killchain_attempt"](
        target="10.0.0.50",
        from_state="creds_in_hand",
        to_state="shell_as_user",
        context_json=json.dumps({"user": "root", "password": "pw"}),
    )
    assert out.startswith("KILLCHAIN_FAILED:")
    assert "STATE UNCHANGED" in out


def test_killchain_attempt_blocked_when_not_allowlisted(tmp_path: Path) -> None:
    from tools.mcp_tools.killchain import register_killchain_tools

    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=_build_ctx(tmp_path))
    out = mcp.tools["killchain_attempt"](target="10.9.9.9", from_state="creds_in_hand", to_state="shell_as_user")
    assert out.startswith("BLOCKED:")


def test_killchain_attempt_bad_context_json(tmp_path: Path) -> None:
    from tools.mcp_tools.killchain import register_killchain_tools

    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=_build_ctx(tmp_path))
    out = mcp.tools["killchain_attempt"](
        target="10.0.0.50", from_state="creds_in_hand", to_state="shell_as_user", context_json="{not json"
    )
    assert out.startswith("BLOCKED:")


def test_killchain_attempt_fails_fast_without_snapshots(tmp_path: Path) -> None:
    """P3-11 pack gate: killchain on + snapshots off fails fast with
    guidance — no playbook runs net-less. Read-only status/plan unaffected."""
    from tools.mcp_tools.killchain import register_killchain_tools

    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=_build_ctx(tmp_path, snapshots_enabled=False))
    out = mcp.tools["killchain_attempt"](
        target="10.0.0.50", from_state="creds_in_hand", to_state="shell_as_user"
    )
    assert out.startswith("BLOCKED:")
    assert "snapshots.enabled" in out
    assert "killchain.enabled" in out


def test_killchain_plan_block(tmp_path: Path) -> None:
    from tools.mcp_tools.killchain import register_killchain_tools

    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=_build_ctx(tmp_path))
    out = mcp.tools["killchain_plan"](target="10.0.0.50", goal_state="shell_as_user")
    assert out.startswith("KILLCHAIN_PLAN:")
    assert "no registered edge path" in out or "PATH:" in out
    bad = mcp.tools["killchain_plan"](target="10.0.0.50", goal_state="warp")
    assert bad.startswith("BLOCKED:")


# ---------------------------------------------------------------------------
# Orchestrator preference behavior
# ---------------------------------------------------------------------------


class _FakeOrchestrator:
    """Minimal duck-typed orchestrator for the killchain phase handlers.

    The phase handlers are plain functions bound onto AutonomousOrchestrator
    after import; bind them onto the fake the same way so the tests exercise
    the real handler bodies.
    """

    def __init__(self, tmp_path: Path, *, enabled: bool, executor: Any) -> None:
        from tools.campaign.state import AttackState as CampaignState

        self._mission = {"killchain": {"enabled": enabled, "goal_state": "shell_as_user"}, "agent": {}}
        self._workspace = tmp_path
        self._tool_executor = executor
        self._killchain_enabled = enabled
        self._killchain_goal_state = "shell_as_user"
        self._killchain_machine = None
        self.state = CampaignState(target="10.0.0.50")


from tools.campaign.phases import _get_killchain_machine, _phase_killchain

_FakeOrchestrator._get_killchain_machine = _get_killchain_machine  # type: ignore[attr-defined]
_FakeOrchestrator._phase_killchain = _phase_killchain  # type: ignore[attr-defined]


def test_orchestrator_edge_path_attempted_and_verified(tmp_path: Path) -> None:
    import asyncio

    orch = _FakeOrchestrator(tmp_path, enabled=True, executor=lambda name, args: "OUTPUT: ok")
    # seed current state at creds_in_hand on the machine's graph
    machine = orch._get_killchain_machine(orch.state)
    assert machine is not None
    from tools.intelligence.graph.types import GraphNode, NodeType

    machine.graph_store.upsert_node(
        GraphNode(
            node_id="h",
            node_type=NodeType.HOST,
            value="10.0.0.50",
            scope="target:10.0.0.50",
            properties={"attack_state": "creds_in_hand"},
        )
    )
    # The machine's check executor defaults to eval_checks' default executor
    # (no session -> UNVERIFIED False), so the edge cannot verify here; the
    # orchestrator must fall back (return False) and leave free-form planning
    # in charge.
    advanced = asyncio.run(_phase_killchain(orch, orch.state))
    assert advanced is False
    assert any(e.get("event_type") == "killchain_plan" for e in orch.state.timeline)
    assert any(e.get("event_type") == "killchain_edge_failed" for e in orch.state.timeline)


def test_orchestrator_falls_back_when_disabled(tmp_path: Path) -> None:
    import asyncio

    orch = _FakeOrchestrator(tmp_path, enabled=False, executor=lambda name, args: "OUTPUT: ok")
    assert asyncio.run(orch._phase_killchain(orch.state)) is False
    assert not any(str(e.get("event_type", "")).startswith("killchain") for e in orch.state.timeline)


# ---------------------------------------------------------------------------
# End-to-end scripted chain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_to_end_scripted_chain(tmp_path: Path) -> None:
    """discovered -> reachable -> service_access -> creds_in_hand -> shell_as_user
    driven purely by verified kill-chain transitions (fake executor + checks)."""
    from tools.intelligence.graph.store import AttackGraphStore
    from tools.killchain import KillChainMachine

    executor = FakeToolExecutor()
    checks = FakeCheckExecutor()  # every probe passes
    machine = KillChainMachine(
        graph_store=AttackGraphStore(":memory:"),
        workspace=tmp_path,
        config={"killchain": {"enabled": True, "goal_state": "shell_as_user"}},
        tool_executor=executor,
        check_executor=checks,
        run_dir=tmp_path,
    )
    # full chain from discovered: BFS plan covers the registered baseline edges
    plan = machine.plan("10.0.0.50", "shell_as_user")
    assert plan, "baseline edges must connect discovered to shell_as_user"
    ctx: dict[str, Any] = {"user": "admin", "password": "password", "port": "80"}
    for from_state, to_state, edge_id in _plan_pairs(plan):
        result = await machine.attempt_transition("10.0.0.50", from_state, to_state, edge_id=edge_id, context=ctx)
        assert result["success"], result
    assert machine.status("10.0.0.50")["state"] == "shell_as_user"
    # zero free-form commands outside the edge playbooks: every executor call
    # belongs to a registered playbook tool
    from tools.killchain import all_edges

    playbook_tools = {step["tool"] for e in all_edges() for step in e["playbook"]}
    assert all(name in playbook_tools for name, _ in executor.calls)


def _plan_pairs(plan: list[str]) -> list[tuple[str, str, str]]:
    from tools.killchain import get_edge

    return [(e["from_state"], e["to_state"], e["edge_id"]) for e in (get_edge(eid) for eid in plan) if e is not None]


# ---------------------------------------------------------------------------
# Domain path: creds_in_hand -> domain_creds -> da
# ---------------------------------------------------------------------------


def test_bfs_plan_reaches_da_from_creds(tmp_path: Path) -> None:
    machine = _machine(tmp_path)
    from tools.intelligence.graph.types import GraphNode, NodeType

    machine.graph_store.upsert_node(
        GraphNode(
            node_id="h",
            node_type=NodeType.HOST,
            value="10.0.0.50",
            scope="target:10.0.0.50",
            properties={"attack_state": "creds_in_hand"},
        )
    )
    assert machine.plan("10.0.0.50", "da") == ["domain_login_validate", "kerberoast_to_da"]


@pytest.mark.asyncio
async def test_domain_path_verifies_end_to_end(tmp_path: Path) -> None:
    """creds -> domain_creds -> da driven purely by verified transitions."""
    executor = FakeToolExecutor(
        outputs={
            "lateral_exec": "LATERAL_EXEC_RESULT: completed\nOUTPUT:\nCORP\\admin",
            "kerberoast": "KERBEROAST_RESULT: completed\nTICKETS_SIZE: 1234 bytes",
        }
    )
    machine = _machine(tmp_path, tool_executor=executor, check_executor=FakeCheckExecutor())
    ctx: dict[str, Any] = {"user": "admin", "password": "pw", "domain": "CORP"}
    first = await machine.attempt_transition("10.0.0.50", "creds_in_hand", "domain_creds", context=ctx)
    assert first["success"], first
    assert first["edge_id"] == "domain_login_validate"
    second = await machine.attempt_transition(
        "10.0.0.50", "domain_creds", "da", edge_id="kerberoast_to_da", context=ctx
    )
    assert second["success"], second
    assert machine.status("10.0.0.50")["state"] == "da"
    tools_called = [name for name, _ in executor.calls]
    assert tools_called == ["lateral_exec", "kerberoast"]
    # placeholders resolved from context (no visible {token} leaks into calls)
    assert executor.calls[1][1]["domain"] == "CORP"


def test_killchain_attempt_succeeds_when_shell_probe_passes(tmp_path: Path) -> None:
    """MCP wiring: shell_command verifies run through in-process dispatch."""
    from tools.intelligence.graph.store import AttackGraphStore
    from tools.intelligence.graph.types import GraphNode, NodeType
    from tools.mcp_tools.killchain import register_killchain_tools

    mcp = _StubMCP()
    register_killchain_tools(mcp, ctx=_build_ctx(tmp_path))
    mcp.tools["run_exploit_terminal"] = lambda command: f"OUTPUT:\nuid=0(root) via {command}"
    db = tmp_path / "killchain_graph.db"
    store = AttackGraphStore(db)
    store.upsert_node(
        GraphNode(
            node_id="h",
            node_type=NodeType.HOST,
            value="10.0.0.50",
            scope="target:10.0.0.50",
            properties={"attack_state": "creds_in_hand"},
        )
    )
    store.close()
    out = mcp.tools["killchain_attempt"](
        target="10.0.0.50",
        from_state="creds_in_hand",
        to_state="shell_as_user",
        context_json=json.dumps({"user": "root", "password": "pw"}),
    )
    assert out.startswith("KILLCHAIN_TRANSITION:")
    assert "EVIDENCE:" in out


def test_killchain_context_parses_credential_shapes() -> None:
    from types import SimpleNamespace

    from tools.campaign.phases import _killchain_context

    assert _killchain_context(SimpleNamespace(credentials_found=[])) == {
        "user": "",
        "password": "",
        "domain": "",
        "port": "",
    }
    state = SimpleNamespace(
        credentials_found=[{"username": "admin", "password": "pw", "domain": "CORP"}],
    )
    assert _killchain_context(state) == {"user": "admin", "password": "pw", "domain": "CORP", "port": ""}
    flat = SimpleNamespace(credentials_found=["user=svc password=s3cr3t"])
    assert _killchain_context(flat)["user"] == "svc"
    assert _killchain_context(flat)["password"] == "s3cr3t"
    # unusable entries are skipped, freshest usable wins
    mixed = SimpleNamespace(
        credentials_found=[{"username": "old", "password": "x"}, {"username": "", "password": ""}],
    )
    assert _killchain_context(mixed)["user"] == "old"


@pytest.mark.asyncio
async def test_playbook_mcp_death_group_returns_failure_dict(tmp_path: Path) -> None:
    """An anyio BaseExceptionGroup from a dead MCP subprocess (NOT an
    Exception subclass) must be caught by _EXC_GROUP_CATCH and returned as
    the documented failure dict — never raised out of killchain_attempt."""

    class _GroupExecutor:
        calls: list[tuple[str, dict[str, Any]]] = []

        async def __call__(self, tool_name: str, args: dict[str, Any]) -> str:
            self.calls.append((tool_name, args))
            raise BaseExceptionGroup("mcp subprocess died", [RuntimeError("boom")])

    machine = _machine(tmp_path, tool_executor=_GroupExecutor())
    result = await machine.attempt_transition("10.0.0.50", "creds_in_hand", "shell_as_user")
    assert result["success"] is False
    assert result["edge_id"] == "cred_ssh_login"
    assert result["from_state"] == "creds_in_hand"
    assert result["to_state"] == "shell_as_user"
    assert result["steps"] and "error" in result["steps"][0]
    assert "failed" in result["error"]
    assert machine.status("10.0.0.50")["state"] == "discovered"
