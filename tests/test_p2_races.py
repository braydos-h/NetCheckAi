"""P2 regression: deterministic race coverage — audit chain, decisions, bridge.

Read-only against source — no source edits here. Every test synchronizes
with ``asyncio.Event`` / ``threading.Barrier`` / ``asyncio.gather``; there
is deliberately no ``time.sleep`` anywhere in this file.

1. Audit chain: ``ExploitPolicy.record()`` links via ``prev_hash`` under
   ``_audit_lock`` (``policy.py``), so N concurrent ``record()`` calls under
   ``asyncio.gather`` must still verify end-to-end.
2. Decision broker: ``resolve()`` is synchronous (no await points, so true
   interleaving inside it is impossible); the concurrency seam is the
   persistence lock. Exactly one answer wins; the loser sees the winner's
   row; ``RunManager.answer_decision`` maps the second answer to 404.
3. Swarm bridge: parallel ``dispatch`` calls share the single MCP session;
   the event loop + ``run_coroutine_threadsafe`` hop fan results back out
   without cross-talk. The bridge holds no lock by design — serialization
   is the loop's single thread.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from tools.api.decision_broker import DecisionBroker
from tools.api.errors import APIError
from tools.api.event_broker import EventBrokerRegistry
from tools.api.persistence import ApiPersistence
from tools.api.run_manager import RunHandle, RunManager
from tools.exploit_agent.policy import (
    ExploitPermission,
    ExploitPolicy,
    ExploitSettings,
    verify_audit_chain,
)
from tools.run_service.models import Decision, DecisionKind
from tools.swarm_bridge import SwarmMcpBridge


def _mcp_result(text: str) -> Any:
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])


# ── 1. Audit chain under gather ──────────────────────────────────────────────


async def test_audit_chain_valid_under_concurrent_append(tmp_path):
    workspace = tmp_path / "ws"
    settings = ExploitSettings(
        permission=ExploitPermission.FULL_ACCESS,
        target_ip="10.0.0.50",
        attack_mode=True,
    )
    policy = ExploitPolicy(settings, workspace)
    await asyncio.gather(
        *[policy.record(action=f"tool-{i}", command=f"cmd {i}", approved=True, status="completed") for i in range(8)]
    )
    assert len(policy._records) == 8
    ok, reason = verify_audit_chain(workspace / "exploit_audit.jsonl")
    assert ok is True, reason


# ── 2. Decision double-decide ────────────────────────────────────────────────


async def _broker_with_decision(tmp_path, *, run_id="run1"):
    persistence = ApiPersistence(tmp_path / "reports")
    persistence.create_run(run_id=run_id, request={}, preview={}, state="awaiting_input")
    broker = DecisionBroker(run_id, persistence)
    decision = Decision(
        id="d1",
        run_id="",
        kind=DecisionKind.TOOL_APPROVAL,
        prompt_text="Allow?",
        required_text="ALLOW 10.0.0.50",
    )
    did = await broker.create(decision)
    return persistence, broker, did


async def test_broker_double_resolve_exactly_one_winner(tmp_path):
    _, broker, did = await _broker_with_decision(tmp_path)
    assert broker.resolve(did, "ALLOW 10.0.0.50") is True
    assert broker.resolve(did, "ALLOW 10.0.0.50") is False  # already answered: loser


def test_persistence_concurrent_double_answer_single_winner(tmp_path):
    """Two threads answering at once (``threading.Barrier`` release, no
    sleeps): the persistence lock serializes; one answer persists and both
    callers observe the same winning row."""
    persistence, _, did = asyncio.run(_broker_with_decision(tmp_path))
    barrier = threading.Barrier(2)
    seen: dict[int, tuple[str, str]] = {}

    def _worker(i: int) -> None:
        barrier.wait()  # simultaneous release — no sleeps
        row = persistence.answer_decision(did, f"ans-{i}")
        assert row is not None
        seen[i] = (row["status"], row["answer"])

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert seen[0][0] == "answered" and seen[1][0] == "answered"
    assert seen[0] == seen[1]  # single winner: both callers see the same row
    assert seen[0][1] in {"ans-0", "ans-1"}


async def test_run_manager_second_answer_is_404(tmp_path):
    """End-to-end through ``RunManager.answer_decision``: first answer wins,
    second raises ``decision_not_found`` 404 (never 500, never a double
    state transition)."""
    persistence = ApiPersistence(tmp_path / "reports")
    registry = EventBrokerRegistry(tmp_path / "reports")
    manager = RunManager(
        persistence,
        registry,
        config={},
        config_path=tmp_path / "config.yaml",
    )
    try:
        persistence.create_run(run_id="r1", request={}, preview={}, state="awaiting_input")
        handle = RunHandle("r1")
        # Stub the event broker: the contract under test is the 404 mapping,
        # not the WS fan-out (which needs a live loop + JSONL broker).
        handle.event_broker = MagicMock()
        handle.event_broker.emit = AsyncMock(return_value={})
        handle.decision_broker = DecisionBroker("r1", persistence)
        manager._active["r1"] = handle
        decision = Decision(
            id="d1",
            run_id="",
            kind=DecisionKind.TOOL_APPROVAL,
            prompt_text="Allow?",
            required_text="ALLOW 10.0.0.50",
        )
        did = await handle.decision_broker.create(decision)
        first = await manager.answer_decision("r1", did, "ALLOW 10.0.0.50")
        assert first == {"decision_id": did, "status": "answered"}
        with pytest.raises(APIError) as exc_info:
            await manager.answer_decision("r1", did, "ALLOW 10.0.0.50")
        assert exc_info.value.status_code == 404
    finally:
        registry.close_all()


# ── 3. Swarm bridge parallel dispatch ────────────────────────────────────────


async def test_parallel_dispatch_shares_single_session_without_crosstalk():
    """N dispatches in flight at once (event-gated overlap, no sleeps) share
    the ONE attached session; each caller gets exactly its own result."""
    bridge = SwarmMcpBridge()
    policy = MagicMock()
    policy.approve_action = AsyncMock(return_value=True)
    session = MagicMock()
    arrived: list[int] = []
    release = asyncio.Event()
    count = 4

    async def _gated_call_tool(name: str, arguments: dict[str, Any]) -> Any:
        arrived.append(arguments["tag"])
        if len(arrived) == count:
            release.set()
        await asyncio.wait_for(release.wait(), timeout=10.0)  # hang guard, not sync
        return _mcp_result(f"resp-{arguments['tag']}")

    session.call_tool = AsyncMock(side_effect=_gated_call_tool)
    bridge.attach(session, [], policy, loop=asyncio.get_running_loop())

    results = await asyncio.gather(
        *[asyncio.to_thread(bridge.dispatch, "run_exploit_terminal", {"command": "echo", "tag": i}) for i in range(count)]
    )
    assert results == [f"resp-{i}" for i in range(count)]  # gather order == caller order
    assert bridge.dispatched == count
    assert session.call_tool.await_count == count
    assert sorted(arrived) == [0, 1, 2, 3]
