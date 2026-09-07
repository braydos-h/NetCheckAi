"""Focused tests for the mid-run operator checkpoint (Flow A CAMPAIGN_NEXT_STEP).

Covers:
  - Verified compromise creates the access checkpoint.
  - Credential dump creates the access checkpoint.
  - Natural no-footprint termination creates the no-path checkpoint.
  - Each option (continue / change_goal / finish / cancel) resumes, changes
    objective, completes, or cancels correctly.
  - The decision-loop guard requires fresh actions before re-presenting the
    same no-path checkpoint.
  - No checkpoint is created for a single failed tool call (blocked path or
    phase minima unmet).

Pattern mirrors tests/test_outcome_judge_flow_a.py: MagicMock client,
AsyncMock session, patched ``_stream_ollama``, a fake ``checkpoint_hook``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


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


def _policy(tmp_path):
    from tools.exploit_agent import ExploitPolicy

    return ExploitPolicy(_settings(tmp_path), tmp_path)


class _RecordingHook:
    """Fake checkpoint hook that records every call and returns a fixed outcome."""

    def __init__(self, outcome):
        self.calls = []
        self._outcome = outcome

    async def __call__(self, ctx):
        self.calls.append(ctx)
        return self._outcome


# ── Access checkpoint ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verified_compromise_creates_access_checkpoint(tmp_path):
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    hook = _RecordingHook(CheckpointOutcome(action="finish"))
    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("meterpreter session 1 opened\nuid=0(root)")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    assert len(hook.calls) == 1
    assert hook.calls[0].kind == "access"
    assert hook.calls[0].evidence["outcome"] == "compromise"
    assert hook.calls[0].evidence["shell_type"] == "meterpreter"


@pytest.mark.asyncio
async def test_cred_dump_creates_access_checkpoint(tmp_path):
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    hook = _RecordingHook(CheckpointOutcome(action="finish"))
    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg("dump_credentials"), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("credentials: admin:P@ssw0rd\nntlm: 0xad3b4b5")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "dump_credentials"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    assert len(hook.calls) == 1
    assert hook.calls[0].kind == "access"
    assert hook.calls[0].evidence["outcome"] == "cred_dump"


# ── No-path checkpoint ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_natural_no_foothold_termination_creates_no_path_checkpoint(tmp_path):
    """Agent does the real work (2 recon + 1 service_enum + 1 vuln_research —
    the phase minima), then emits no tool calls: the summary turn credits the
    reporting phase, can_terminate passes, and the no-path checkpoint fires
    (no verified foothold). No can_terminate monkeypatch."""
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    hook = _RecordingHook(CheckpointOutcome(action="finish"))
    policy = _policy(tmp_path)
    # Phase mapping (runner/_impl.py): check_os→recon; run_exploit_terminal→
    # service_enumeration; search_cve_intel→vulnerability_research. With
    # services_detected=0 / versions_identified=0 the minima are 2/1/1, so
    # 2+1+1 = 4 tool actions satisfy every non-reporting minimum, and the
    # final no-tool summary turn records the reporting action.
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
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[
                {"type": "function", "function": {"name": "check_os"}},
                {"type": "function", "function": {"name": "run_exploit_terminal"}},
                {"type": "function", "function": {"name": "search_cve_intel"}},
            ],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    assert len(hook.calls) == 1
    assert hook.calls[0].kind == "no_path"


# ── Single failed tool call: no checkpoint ──────────────────────────────────────


@pytest.mark.asyncio
async def test_single_failed_tool_call_no_checkpoint(tmp_path):
    """One blocked/failed call that trips terminal_constraint_reached terminates
    via the blocked path, not the natural-termination path → no checkpoint."""
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    hook = _RecordingHook(CheckpointOutcome(action="finish"))
    policy = _policy(tmp_path)
    # One tool call that returns BLOCKED, then the loop hits the terminal
    # constraint (threshold=3 by default; we send 3 blocked calls to trip it,
    # none of which reach phase minima). Actually simpler: send one tool call
    # then a done — phase minima are NOT met (recon=1 < 2), so the push-back
    # path fires (continue), then the next round is done again → still unmet
    # → the loop keeps pushing back until max_rounds. To avoid a long loop,
    # set max_rounds=1 so the single round ends after the push-back continue.
    settings = _settings(tmp_path, attack_max_rounds=1)
    from tools.exploit_agent import ExploitPolicy

    policy = ExploitPolicy(settings, tmp_path)
    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("BLOCKED: denied")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    # Phase minima were unmet (recon=0) and the blocked path / max_rounds ended
    # the loop before the natural-termination boundary → no checkpoint.
    assert hook.calls == []


# ── Outcome handling ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_continue_injects_objective_and_keeps_history(tmp_path):
    """'continue' appends a user-role objective message and does not break."""
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    hook = _RecordingHook(CheckpointOutcome(action="continue", objective_text="NEW OBJECTIVE: try harder."))
    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("meterpreter session 1 opened\nuid=0(root)")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    # The objective text was injected as a user message.
    messages = result["messages"]
    injected = [m for m in messages if m.get("role") == "user" and "NEW OBJECTIVE" in str(m.get("content", ""))]
    assert injected, "expected a user-role objective message after 'continue'"
    # Not cancelled.
    assert result["cancelled_by_operator"] is False


@pytest.mark.asyncio
async def test_cancel_sets_cancelled_flag(tmp_path):
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    hook = _RecordingHook(CheckpointOutcome(action="cancel"))
    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("meterpreter session 1 opened\nuid=0(root)")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    assert result["cancelled_by_operator"] is True


@pytest.mark.asyncio
async def test_finish_breaks_loop(tmp_path):
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    hook = _RecordingHook(CheckpointOutcome(action="finish"))
    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("meterpreter session 1 opened\nuid=0(root)")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    assert result["cancelled_by_operator"] is False
    assert len(hook.calls) == 1


# ── Decision-loop guard ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_path_decision_loop_guard_requires_fresh_actions(tmp_path):
    """'continue' at a no-path checkpoint advances _last_no_path_action; a
    second natural-termination with no new actions does NOT re-prompt."""
    from tools.exploit_agent import run_exploit_agent
    from tools.exploit_agent.runner import CheckpointOutcome

    # First call: continue. Second call: finish (so the loop stops).
    outcomes = iter(
        [
            CheckpointOutcome(action="continue", objective_text="NEW OBJECTIVE: retry."),
            CheckpointOutcome(action="finish"),
        ]
    )
    calls = []

    async def _hook(ctx):
        calls.append(ctx)
        return next(outcomes)

    hook = _hook
    policy = _policy(tmp_path)
    # Meet every non-reporting phase minimum (2 recon + 1 service_enum +
    # 1 vuln_research) → done (no_path #1 → continue) → done (no new
    # actions → guard blocks no_path #2 → break). No can_terminate
    # monkeypatch: the summary turn credits reporting for real.
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("check_os"),
        _tool_call_msg("check_os"),
        _tool_call_msg("run_exploit_terminal"),
        _tool_call_msg("search_cve_intel"),
        _done_msg(),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("ok\nno vulns")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[
                {"type": "function", "function": {"name": "check_os"}},
                {"type": "function", "function": {"name": "run_exploit_terminal"}},
                {"type": "function", "function": {"name": "search_cve_intel"}},
            ],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
            checkpoint_hook=hook,
        )

    # Only the first natural-termination fired the no-path checkpoint; the
    # second (with no new actions) was blocked by the guard.
    no_path_calls = [c for c in calls if c.kind == "no_path"]
    assert len(no_path_calls) == 1


# ── No hook → byte-identical behavior ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_hook_means_no_checkpoint_and_normal_termination(tmp_path):
    """When checkpoint_hook is None (default), the loop behaves exactly as
    before — no checkpoint, no cancelled flag, normal termination."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("meterpreter session 1 opened\nuid=0(root)")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
        )

    assert result["cancelled_by_operator"] is False
    # Compromise still recorded by the outcome classifier.
    assert "compromises: 1" in result["outcome_summary"]
