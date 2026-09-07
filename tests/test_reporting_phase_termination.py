"""Regression tests for the reporting-phase termination fix (Flow A).

Defect: ``_PhaseTracker.MIN_ACTIONS["reporting"] == 1`` but no tool maps to the
``reporting`` phase in the runner's tool->phase map, so ``can_terminate()`` could
never return True in production -- every natural-termination attempt was pushed
back until round/command budget exhaustion and the no-path operator checkpoint
was unreachable for non-compromise runs.

Fix: the no-tool summary turn (which the system prompt designates as the
EXPLOIT_RESULT reporting block) credits the reporting phase exactly once, and
only when it is the ONLY unmet phase, so push-back still fires while recon /
service-enumeration / vuln-research minima are unmet.

Pattern mirrors tests/test_campaign_checkpoint.py / tests/test_reliability_bugs.py:
MagicMock client, AsyncMock session, patched ``_stream_ollama``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PUSHBACK_MARKER = "phase minima are not yet met"


def _tool_call_msg(name="run_exploit_terminal", args=None):
    return {
        "message": {
            "content": "running tool",
            "tool_calls": [{"function": {"name": name, "arguments": args or {"command": "x"}}}],
        }
    }


def _done_msg():
    return {"message": {"content": "done", "tool_calls": []}}


def _tool_result(text: str):
    return MagicMock(content=[MagicMock(text=text)])


def _tool(name: str):
    return {"type": "function", "function": {"name": name}}


_MINIMA_TOOLS = [
    _tool("check_os"),
    _tool("run_exploit_terminal"),
    _tool("search_cve_intel"),
    _tool("list_workspace"),
]


def _settings(tmp_path, **overrides):
    from tools.exploit_agent import ExploitPermission, ExploitSettings

    base = dict(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=10,
        attack_max_commands=50,
        outcome_judgment_flow_a=False,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    base.update(overrides)
    return ExploitSettings(**base)


def _policy(tmp_path, **overrides):
    from tools.exploit_agent import ExploitPolicy

    return ExploitPolicy(_settings(tmp_path, **overrides), tmp_path)


def _user_messages(result):
    return [str(m.get("content", "")) for m in result["messages"] if m.get("role") == "user"]


# ── Natural termination after minima are met ───────────────────────────────────


@pytest.mark.asyncio
async def test_full_access_non_compromise_run_terminates_naturally(tmp_path):
    """FULL_ACCESS, no compromise: 2 recon + 1 service_enum + 1 vuln_research
    tool calls, then a no-tool summary turn → the run terminates naturally at
    the summary turn (no push-back loop, no budget exhaustion)."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("check_os"),
        _tool_call_msg("check_os"),
        _tool_call_msg("run_exploit_terminal"),
        _tool_call_msg("search_cve_intel"),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("ok\nno vulnerabilities found")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "final summary"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=_MINIMA_TOOLS,
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
        )

    # The loop broke on the summary turn: 4 tool rounds + 1 done round. If the
    # reporting minimum were still unsatisfiable it would have pushed back
    # until attack_max_rounds (10 chat calls) instead.
    assert result["total_actions"] == 4
    assert client.chat.call_count == 5
    assert not any(PUSHBACK_MARKER in m for m in _user_messages(result))


@pytest.mark.asyncio
async def test_premature_termination_still_blocked_when_minima_unmet(tmp_path):
    """One recon action then repeated no-tool turns: the push-back must keep
    firing (and the summary turn must NOT credit reporting early), so the
    run only exits via round budget -- never a natural termination."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path, attack_max_rounds=4)
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("check_os"),
        _done_msg(),
        _done_msg(),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("OS_VERDICT: LINUX\nexit_code=0")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "final summary"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=_MINIMA_TOOLS,
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
        )

    pushbacks = [m for m in _user_messages(result) if PUSHBACK_MARKER in m]
    assert pushbacks, "expected at least one phase-minimum push-back message"
    # recon=1 < 2 → the loop kept pushing back every remaining round instead
    # of terminating on the first done.
    assert len(pushbacks) >= 2
    assert result["total_actions"] == 1
    assert client.chat.call_count == 4


# ── Existing termination paths unchanged ───────────────────────────────────────


@pytest.mark.asyncio
async def test_compromise_still_terminates_via_goal_complete_bypass(tmp_path):
    """A verified compromise terminates on the next no-tool turn even though
    the recon/enum/research minima are unmet (goal_complete bypass)."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path, attack_max_rounds=50)
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("run_exploit_terminal"),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("meterpreter session 1 opened\nuid=0(root)")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "final summary"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=_MINIMA_TOOLS,
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
        )

    assert "compromises: 1" in result["outcome_summary"]
    assert result["total_actions"] == 1
    assert client.chat.call_count == 2
    assert not any(PUSHBACK_MARKER in m for m in _user_messages(result))


# ── No-path operator checkpoint reachable without monkeypatching ───────────────


class _RecordingHook:
    def __init__(self, outcome):
        self.calls = []
        self._outcome = outcome

    async def __call__(self, ctx):
        self.calls.append(ctx)
        return self._outcome


@pytest.mark.asyncio
async def test_no_path_checkpoint_fires_without_can_terminate_monkeypatch(tmp_path):
    """Non-compromise run that met the other minima reaches the no-path
    operator checkpoint naturally (no can_terminate patching)."""
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    hook = _RecordingHook(CheckpointOutcome(action="finish"))
    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("check_os"),
        _tool_call_msg("check_os"),
        _tool_call_msg("run_exploit_terminal"),
        _tool_call_msg("search_cve_intel"),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("ok\nno vulnerabilities found")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=_MINIMA_TOOLS,
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    assert len(hook.calls) == 1
    assert hook.calls[0].kind == "no_path"
    assert result["cancelled_by_operator"] is False


# ── Unmapped tools must not satisfy the reporting minimum ──────────────────────


@pytest.mark.asyncio
async def test_unmapped_tool_call_does_not_increment_reporting(tmp_path):
    """A tool the phase map does not name falls into the recon (else) branch --
    it must never be counted as 'reporting'. The summary turn is the only
    source of the reporting credit, visible in the checkpoint evidence."""
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    hook = _RecordingHook(CheckpointOutcome(action="finish"))
    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("check_os"),
        _tool_call_msg("check_os"),
        _tool_call_msg("run_exploit_terminal"),
        # Unmapped by the phase map (else branch → recon), NOT reporting.
        _tool_call_msg("list_workspace"),
        _tool_call_msg("search_cve_intel"),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("ok\nno vulnerabilities found")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=_MINIMA_TOOLS,
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    assert len(hook.calls) == 1
    assert hook.calls[0].kind == "no_path"
    counts = hook.calls[0].evidence["phase_counts"]
    # 2 check_os + the unmapped tool all landed in recon...
    assert counts["recon"] == 3
    # ...and reporting was credited exactly once, by the summary turn alone.
    assert counts["reporting"] == 1
    assert result["total_actions"] == 5
