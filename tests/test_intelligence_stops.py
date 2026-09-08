"""Regression tests for the intelligence-layer stopping criteria (agent-intelligence).

Covers:
1. Goal threading: run_exploit_agent(goal=...) lands the goal text in the
   built system prompt AND the initial user message. Default None = no block.
2. Repeated identical exploit failures trip the terminal constraint (same
   tool+target+action-class, N=threshold) with a 'repeated identical action'
   reason -- a scripted model repeating one failing exploit must stop, not
   loop to max_rounds.
3. A peer consult is advisory, NOT success: the failure count survives the
   consult (cooldown only), and consults are capped per run.
4. Recoverable schema-validation thrash (K consecutive) becomes terminal.
5. Target-format validation in tool_catalog rejects garbage before dispatch.
6. Executor + adapter route through outcome_truth (strict): 'root cause'
   prose, HTML '>', 'no hashes recovered' must NOT yield access_achieved /
   CONFIRMED.
7. Distinct attempt ids per loop iteration (judge ref != shared empty ref).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.exploit_agent.tool_calls import _ToolOutcomeTracker


def _tool(name: str):
    return {"type": "function", "function": {"name": name}}


def _tool_call_msg(name="run_exploit_terminal", args=None):
    return {
        "message": {
            "content": "running tool",
            "tool_calls": [{"function": {"name": name, "arguments": args or {"command": "x"}}}],
        }
    }


def _done_msg(content="EXPLOIT_RESULT: failed\nSUMMARY: nothing worked"):
    return {"message": {"content": content, "tool_calls": []}}


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


def _policy(tmp_path, **overrides):
    from tools.exploit_agent import ExploitPolicy

    return ExploitPolicy(_settings(tmp_path, **overrides), tmp_path)


# ── 1. Goal threading ─────────────────────────────────────────────────────


def test_goal_text_appears_in_built_prompt():
    from tools.exploit_agent import build_exploit_system_prompt
    from tools.goal_engine import GoalEngine

    goal = GoalEngine().get("initial_access", risk_profile="standard_authorized")
    prompt = build_exploit_system_prompt(
        attacker_os="Linux",
        target_ip="10.0.0.50",
        goal_context=goal.system_prompt_addition(),
    )
    assert "INITIAL_ACCESS" in prompt
    assert goal.description.split()[0] in prompt


def test_goal_default_absent():
    from tools.exploit_agent import build_exploit_system_prompt

    prompt = build_exploit_system_prompt(attacker_os="Linux", target_ip="10.0.0.50")
    assert "PRIMARY MISSION" not in prompt


@pytest.mark.asyncio
async def test_run_agent_threads_goal_into_messages(tmp_path):
    from tools.exploit_agent import run_exploit_agent
    from tools.goal_engine import GoalEngine

    goal = GoalEngine().get("initial_access", risk_profile="standard_authorized")
    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [_done_msg()]
    session = AsyncMock()

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "final"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[_tool("check_os")],
            policy=policy,
            target_ip="10.0.0.50",
            goal=goal,
            config={"outcome_judgment": {"flow_a": False}},
        )
    system = next(m for m in result["messages"] if m.get("role") == "system")
    assert "INITIAL_ACCESS" in str(system.get("content", ""))
    first_user = next(m for m in result["messages"] if m.get("role") == "user")
    assert "MISSION GOAL" in str(first_user.get("content", ""))
    assert "INITIAL_ACCESS" in str(first_user.get("content", ""))


# ── 2. Repeated identical failures stop ───────────────────────────────────


def test_repeated_identical_failures_trip_constraint():
    t = _ToolOutcomeTracker(threshold=3)
    args = {"command": "nmap -sV 10.0.0.50", "target_ip": "10.0.0.50"}
    assert t.record_repeated_failure("run_exploit_terminal", args, "exit 1") is False
    assert t.record_repeated_failure("run_exploit_terminal", args, "exit 1") is False
    assert t.record_repeated_failure("run_exploit_terminal", args, "exit 1") is True
    assert t.terminal_constraint_reached is True
    assert t.last_constraint == "repeated_failures"
    assert "repeated identical" in t.last_reason


def test_argument_tweaks_still_count_as_identical():
    # Same tool+target+first-token, different flags -> same coarse key.
    t = _ToolOutcomeTracker(threshold=3)
    base = {"target_ip": "10.0.0.50"}
    t.record_repeated_failure("run_exploit_terminal", {**base, "command": "nmap -sV 10.0.0.50"}, "e1")
    t.record_repeated_failure("run_exploit_terminal", {**base, "command": "nmap -sV -Pn 10.0.0.50"}, "e2")
    assert t.record_repeated_failure("run_exploit_terminal", {**base, "command": "nmap -A 10.0.0.50"}, "e3") is True


def test_different_targets_do_not_collide():
    t = _ToolOutcomeTracker(threshold=3)
    t.record_repeated_failure("run_exploit_terminal", {"command": "id", "target_ip": "10.0.0.50"}, "e")
    t.record_repeated_failure("run_exploit_terminal", {"command": "id", "target_ip": "10.0.0.51"}, "e")
    assert t.terminal_constraint_reached is False


@pytest.mark.asyncio
async def test_scripted_model_repeating_failing_exploit_stops(tmp_path):
    """A model that emits the SAME failing exploit every round must stop via
    the repeated-identical-action constraint, well before max_rounds."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    client = MagicMock()
    # Same failing exploit 10 times; max_rounds=10 -- must stop at 3.
    client.chat.side_effect = [
        _tool_call_msg("run_exploit_terminal", {"command": "exploit 10.0.0.50", "target_ip": "10.0.0.50"})
    ] * 10
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("exploit failed\nexit_code=1")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "stopping summary"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[_tool("run_exploit_terminal")],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
        )
    assert result["total_actions"] == 3
    assert "repeated_failures" in result["outcome_summary"]


# ── 3. Consult is advisory, capped ────────────────────────────────────────


def test_consult_keeps_failure_count_and_caps():
    t = _ToolOutcomeTracker(threshold=3)
    for _ in range(3):
        t.record_exploit_failure()
    assert t.should_consult_peers(3) is True
    t.note_peer_consult()
    # Failure count survives; cooldown blocks an immediate re-consult.
    assert t.consecutive_exploit_failures == 3
    assert t.should_consult_peers(3) is False
    # Threshold NEW failures re-arm it.
    for _ in range(3):
        t.record_exploit_failure()
    assert t.should_consult_peers(3) is True
    t.note_peer_consult()
    for _ in range(3):
        t.record_exploit_failure()
    t.note_peer_consult()
    assert t.peer_consults == 3
    for _ in range(9):
        t.record_exploit_failure()
    # Cap hit: never again, no matter how many failures pile up.
    assert t.should_consult_peers(3) is False


# ── 4. Recoverable thrash is terminal ─────────────────────────────────────


def test_recoverable_thrash_trips_constraint():
    t = _ToolOutcomeTracker()
    for _ in range(4):
        assert t.record_recoverable() is False
    assert t.record_recoverable() is True
    assert t.terminal_constraint_reached is True
    assert t.last_constraint == "recoverable_thrash"


def test_dispatched_tool_resets_recoverable_count():
    t = _ToolOutcomeTracker()
    for _ in range(4):
        t.record_recoverable()
    t.record_success()
    assert t.consecutive_recoverable == 0
    assert t.terminal_constraint_reached is False


@pytest.mark.asyncio
async def test_loop_stops_on_persistent_malformed_calls(tmp_path):
    """A model emitting only malformed calls must stop after K recoverable
    failures instead of looping to max_rounds."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path, attack_max_rounds=20)
    client = MagicMock()
    # Missing required 'command' every round -- recoverable, forever.
    client.chat.side_effect = [
        {
            "message": {
                "content": "trying",
                "tool_calls": [{"function": {"name": "run_exploit_terminal", "arguments": {}}}],
            }
        }
    ] * 20
    session = AsyncMock()
    schema = {
        "type": "function",
        "function": {
            "name": "run_exploit_terminal",
            "parameters": {"required": ["command"], "properties": {"command": {"type": "string"}}},
        },
    }

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "stopping summary"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[schema],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
        )
    assert result["total_actions"] == 0
    assert "recoverable_thrash" in result["outcome_summary"]


# ── 5. Target-format validation ───────────────────────────────────────────


def _target_schema(name="quick_scan", param="target_ip"):
    return {
        "type": "function",
        "function": {
            "name": name,
            "parameters": {"required": [param], "properties": {param: {"type": "string"}}},
        },
    }


def test_garbage_target_rejected():
    from tools.exploit_agent.tool_catalog import validate_tool_call

    schema = [_target_schema()]
    err = validate_tool_call("quick_scan", {"target_ip": "not a host !!!"}, schema)
    assert err is not None
    assert "target_ip" in err


def test_valid_targets_pass():
    from tools.exploit_agent.tool_catalog import validate_tool_call

    schema = [_target_schema()]
    assert validate_tool_call("quick_scan", {"target_ip": "10.0.0.50"}, schema) is None
    assert validate_tool_call("quick_scan", {"target_ip": "example.com"}, schema) is None
    assert validate_tool_call("quick_scan", {"target_ip": "10.0.0.0/24"}, schema) is None


def test_non_target_params_untouched():
    from tools.exploit_agent.tool_catalog import validate_tool_call

    schema = [
        {
            "type": "function",
            "function": {
                "name": "run_exploit_terminal",
                "parameters": {"required": ["command"], "properties": {"command": {"type": "string"}}},
            },
        }
    ]
    # A free-text command is not a target param -- never format-checked.
    assert validate_tool_call("run_exploit_terminal", {"command": "not a host !!!"}, schema) is None


def test_consult_hidden_when_multi_model_off():
    from tools.exploit_agent.tool_catalog import select_tools_for_phase

    tools = [_tool("check_os"), _tool("consult_peer_models"), _tool("quick_scan")]
    mcp_names = {"check_os", "consult_peer_models", "quick_scan"}
    on = select_tools_for_phase(tools, "recon", available_mcp_names=mcp_names, multi_model_enabled=True)
    assert "consult_peer_models" in {t["function"]["name"] for t in on}
    off = select_tools_for_phase(tools, "recon", available_mcp_names=mcp_names, multi_model_enabled=False)
    assert "consult_peer_models" not in {t["function"]["name"] for t in off}
    # check_os stays visible either way.
    assert "check_os" in {t["function"]["name"] for t in off}


def test_install_tools_advertised():
    from tools.exploit_agent.tool_catalog import select_tools_for_phase

    tools = [_tool("check_os"), _tool("apt_install"), _tool("pip_install")]
    names = {t["function"]["name"] for t in select_tools_for_phase(tools, "recon")}
    assert "apt_install" in names
    assert "pip_install" in names


# ── 6. Strict compromise classification ───────────────────────────────────


def test_legacy_loose_markers_not_compromise_strict():
    from tools.exploit_agent.outcome_truth import classify_exploit_outcome

    assert classify_exploit_outcome("Investigating the root cause of the failure")["outcome"] != "compromise"
    assert classify_exploit_outcome("<html><body>hello</body></html>")["outcome"] != "compromise"
    r = classify_exploit_outcome("0 hashes recovered\nhashes were not found")
    assert r["outcome"] != "compromise"
    assert r["outcome"] != "cred_dump"
    assert classify_exploit_outcome("meterpreter session 1 opened")["outcome"] == "compromise"


@pytest.mark.asyncio
async def test_executor_dispatch_uses_strict_classifier(tmp_path):
    """_dispatch_module_artifact must not report compromise for loose prose."""
    import asyncio

    from tools.campaign.executor import AttackModuleExecutor
    from tools.campaign.state import AttackState

    try:
        from scope_gate import ScopeGate
    except ImportError:
        pytest.skip("scope_gate unavailable")

    gate = ScopeGate(
        None,
        "",
        allowed_assets=["10.0.0.50"],
        disallowed_assets=[],
        forbidden_actions=[],
        risk_profile="high_authorized_testing",
    )
    ex = AttackModuleExecutor(
        scope_gate=gate, tool_executor=lambda cmd, ctx: "root cause analysis done\nno hashes recovered"
    )

    class _M:
        name = "probe"
        suggested_command = "probe 10.0.0.50"

        def generate_python_script(self, ctx):
            return ""

    class _R:
        suggested_command = "probe 10.0.0.50"
        script = ""

        def __getattr__(self, item):
            return "" if item != "evidence" else []

    class _Ctx:
        target_ip = "10.0.0.50"
        workspace = tmp_path

        def __getattr__(self, item):
            return None

    class _Task:
        target = "10.0.0.50"
        module_name = "probe"

        def __getattr__(self, item):
            return None

    out = await ex._dispatch_module_artifact(_M(), _R(), _Ctx(), _Task(), AttackState(target="10.0.0.50"))
    assert out is not None
    _, classification = out
    assert str(classification.get("outcome", "")).lower() != "compromise"


@pytest.mark.asyncio
async def test_adapter_fallback_never_confirms_on_loose_text(tmp_path):
    """build_observation with no action_result (legacy fallback) must not
    CONFIRM on bare 'meterpreter' prose."""
    from types import SimpleNamespace

    from tools.exploit_agent.outcome_adapter import build_observation, judge_outcome

    try:
        from outcome_judge import OutcomeJudge
    except ImportError:
        pytest.skip("outcome_judge unavailable")

    rec = SimpleNamespace(action="run_exploit_terminal", attempt_id="abc123", detail="d", exit_code=0)
    obs = build_observation(
        result_text="we saw meterpreter in the logs",
        exploit_record=rec,
        plan_step_hypothesis="exploit ssh",
        target_ip="10.0.0.50",
    )
    assert obs is not None
    assert str(obs["classification"].get("outcome", "")).lower() != "compromise"
    verdict = await judge_outcome(obs, OutcomeJudge(), task_id="t1")
    if verdict is not None:
        status, _ = verdict
        assert getattr(status, "value", str(status)) != "confirmed"


# ── 7. Distinct attempt ids ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_attempt_ids_distinct_per_iteration(tmp_path):
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("check_os", {}),
        _tool_call_msg("check_os", {}),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("Linux ok")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "final"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[_tool("check_os")],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
        )
    ids = [r.get("attempt_id", "") for r in result["records"] if r.get("action") == "check_os"]
    assert len(ids) == 2
    assert all(ids)
    assert len(set(ids)) == 2


# ── Medium slices ─────────────────────────────────────────────────────────


def test_failure_substring_not_mislabeled():
    from tools.exploit_agent.context import _looks_like_failure

    assert _looks_like_failure("scan done: 0 errors, 3 ports open") is False
    assert _looks_like_failure("no failures found") is False
    assert _looks_like_failure("exit_code: 1 -- connection refused") is True
    assert _looks_like_failure("Traceback: something broke") is True


def test_verdict_mismatch_flagged():
    from tools.exploit_agent.runner._impl import _check_final_verdict
    from tools.exploit_agent.tool_calls import _ToolOutcomeTracker

    t = _ToolOutcomeTracker()
    msgs = [{"role": "assistant", "content": "EXPLOIT_RESULT: compromise\nSUMMARY: pwned"}]
    mismatch = _check_final_verdict(msgs, t)
    assert "VERDICT_MISMATCH" in mismatch
    t.record_compromise(shell_type="sh", privilege_level="root")
    assert _check_final_verdict(msgs, t) == ""
