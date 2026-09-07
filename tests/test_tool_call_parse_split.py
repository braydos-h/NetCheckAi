"""Regression tests for the split transport/parse try in the agent loop.

The tool-call dispatch in ``tools/exploit_agent/runner/_impl.py`` used to wrap both
``session.call_tool(...)`` (MCP transport) and the result-parsing lines in a
single ``try``. That conflated transport failures with parse failures and was
the historical home of the ``cannot access local variable 'result'`` crash.
The split surfaces parse errors as ``INTERNAL_PARSE_ERROR:`` tool-role
messages (without triggering the BLOCKED/UNAVAILABLE accounting) while
transport errors keep the existing ``ERROR:`` + retry/block behaviour.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_policy(tmp_path):
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=10,
        attack_max_commands=10,
    )
    return ExploitPolicy(settings, tmp_path)


def _tool_call_msg(name="check_os", args=None):
    return {
        "message": {
            "content": "probing",
            "tool_calls": [{"function": {"name": name, "arguments": args or {"target_ip": "10.0.0.1"}}}],
        }
    }


@pytest.mark.asyncio
async def test_call_tool_transport_error_no_unbound_local(tmp_path) -> None:
    """A transport-level ``call_tool`` exception must not raise
    ``UnboundLocalError`` and must surface as an ``ERROR:`` tool message."""
    from tools.exploit_agent import run_exploit_agent

    policy = _make_policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = lambda *a, **k: _tool_call_msg()
    session = AsyncMock()
    session.call_tool.side_effect = RuntimeError("transport boom")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "stopped"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "check_os"}}],
            policy=policy,
            target_ip="10.0.0.1",
        )

    # Reaching here at all proves no UnboundLocalError escaped the loop.
    tool_msgs = [m for m in result["messages"] if m.get("role") == "tool"]
    assert any(str(m.get("content", "")).startswith("ERROR:") for m in tool_msgs), (
        f"expected an ERROR: tool message, got {tool_msgs!r}"
    )
    # The blocked-outcome threshold (3 consecutive) stops the session.
    assert session.call_tool.call_count == 3


@pytest.mark.asyncio
async def test_parse_error_surfaces_as_internal_parse_error(tmp_path) -> None:
    """A result that cannot be parsed must surface as
    ``INTERNAL_PARSE_ERROR:`` and must NOT trigger the blocked-tool
    accounting (no ``Repeated blocked or unavailable`` terminal prompt)."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

    # Keep the turn count small: parse errors do not call record_blocked, so
    # the loop runs until max rounds.
    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=3,
        attack_max_commands=3,
    )
    policy = ExploitPolicy(settings, tmp_path)
    client = MagicMock()
    client.chat.side_effect = lambda *a, **k: _tool_call_msg()
    session = AsyncMock()

    class _UnparseableResult:
        @property
        def content(self):
            raise ValueError("malformed content payload")

    # Accessing ``.content`` raises inside the parse try -> INTERNAL_PARSE_ERROR.
    session.call_tool.return_value = _UnparseableResult()

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "check_os"}}],
            policy=policy,
            target_ip="10.0.0.1",
        )

    tool_msgs = [m for m in result["messages"] if m.get("role") == "tool"]
    parse_msgs = [m for m in tool_msgs if str(m.get("content", "")).startswith("INTERNAL_PARSE_ERROR:")]
    assert parse_msgs, f"expected an INTERNAL_PARSE_ERROR tool message, got {tool_msgs!r}"
    # None of the tool messages should be a transport-style ERROR:
    assert not any(str(m.get("content", "")).startswith("ERROR:") for m in tool_msgs)

    # record_blocked must NOT have fired -> no terminal-constraint prompt.
    all_feedback = "\n".join(str(m.get("content", "")) for m in result["messages"])
    assert "Repeated blocked or unavailable tool outcomes" not in all_feedback
