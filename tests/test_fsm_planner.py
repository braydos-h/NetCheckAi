"""FSM / planner-executor split (tools/attack_planner + campaign executor).

(a) happy path: planner -> memoryless step context -> executor -> record ->
    FSM advances RECON -> ENUMERATE.
(b) stuck-loop breaker: 3x same failure_class -> step blocked + replan;
    permanent classes block immediately; a changed class resets the streak.
(c) isolation: the step context and the planner context never carry full
    history (no result_summary / battle-log leak).
Legacy plan JSON (pre-split keys) still loads unchanged.
"""

from __future__ import annotations

import inspect
from unittest.mock import MagicMock

from tools.attack_planner import (
    AttackPhase,
    AttackPlan,
    AttackStep,
    ExecutorResult,
    fsm_advance,
    fsm_can_transition,
    fsm_settings,
    planner_context,
    record_step_result,
    step_context_for,
)
from tools.campaign.executor import AttackModuleExecutor

_TARGET = "127.0.0.1"


def _allowing_scope_gate() -> MagicMock:
    gate = MagicMock()
    gate.check_scope.return_value = MagicMock(allowed=True, reason="ok")
    return gate


def _recon_plan() -> AttackPlan:
    plan = AttackPlan(target_ip=_TARGET)
    plan.add_step(
        AttackStep(
            phase="recon",
            tool="APIFuzzer",  # offline-safe stub: returns script_generated, no network
            reason="probe api surface",
            target_ip=_TARGET,
            expected_evidence=["open ports"],
        )
    )
    return plan


# (a) planner -> executor -> FSM happy path advances the phase ---------------
async def test_happy_path_advances_phase() -> None:
    plan = _recon_plan()
    assert plan.current_phase == AttackPhase.RECON

    ctx = step_context_for(plan, 0)
    assert (ctx.target_ip, ctx.tool) == (_TARGET, "APIFuzzer")

    raw = await AttackModuleExecutor(_allowing_scope_gate()).execute_plan_step(ctx)
    assert raw["success"] is True
    assert raw["failure_class"] == ""

    assert record_step_result(plan, 0, raw) == "done"
    assert fsm_advance(plan) == AttackPhase.ENUMERATE
    assert plan.current_phase == AttackPhase.ENUMERATE


def test_fsm_guard_rejects_phase_jumps() -> None:
    plan = _recon_plan()
    assert fsm_can_transition("recon", "enumerate")
    assert not fsm_can_transition("recon", "loot")
    try:
        fsm_advance(plan, AttackPhase.LOOT)
    except ValueError as exc:
        assert "Illegal FSM transition" in str(exc)
    else:
        raise AssertionError("recon -> loot must raise")
    assert plan.current_phase == AttackPhase.RECON  # rejected jump changes nothing


# (b) stuck-loop breaker ------------------------------------------------------
def test_three_same_failures_block_step_and_force_replan() -> None:
    plan = _recon_plan()
    bad = {"success": False, "evidence": ["timed out after 30s"], "failure_class": "timeout"}
    assert record_step_result(plan, 0, bad) == "retry"
    plan.reset_step(0)  # planner-sanctioned retry, never blind
    assert record_step_result(plan, 0, bad) == "retry"
    plan.reset_step(0)
    assert record_step_result(plan, 0, bad, max_retries=3) == "replan"
    assert plan.steps[0].status == "blocked"
    assert plan.ready_steps() == []  # a blocked step never resurfaces as ready


def test_permanent_failure_blocks_immediately() -> None:
    plan = _recon_plan()
    out = record_step_result(
        plan, 0, {"success": False, "evidence": ["BLOCKED: off allowlist"], "failure_class": "scope_blocked"}
    )
    assert out == "replan"
    assert plan.steps[0].status == "blocked"


def test_changed_failure_class_resets_streak() -> None:
    plan = _recon_plan()
    assert record_step_result(plan, 0, {"success": False, "evidence": ["x"], "failure_class": "auth_failed"}) == "retry"
    plan.reset_step(0)
    # Different class -> fresh streak, not a third strike.
    assert record_step_result(plan, 0, {"success": False, "evidence": ["y"], "failure_class": "timeout"}) == "retry"
    assert plan.steps[0].status == "failed"


def test_executor_result_dataclass_path() -> None:
    plan = _recon_plan()
    assert record_step_result(plan, 0, ExecutorResult(success=True, evidence=["ok"])) == "done"
    assert plan.steps[0].completed and plan.steps[0].success


# (c) executor receives only its step context ---------------------------------
def test_step_and_planner_contexts_carry_no_history() -> None:
    plan = _recon_plan()
    plan.mark_step_done(0, True, "MARKER-RESULT-SUMMARY-SECRET full battle history must not leak")
    plan.add_step(AttackStep(phase="enumerate", tool="APIFuzzer", reason="next", target_ip=_TARGET))

    ctx = step_context_for(plan, 1)
    assert "MARKER-RESULT-SUMMARY-SECRET" not in repr(ctx.to_dict())
    assert "MARKER-RESULT-SUMMARY-SECRET" not in planner_context(plan)
    # Structural: the memoryless runner takes the step and nothing else.
    assert list(inspect.signature(AttackModuleExecutor.execute_plan_step).parameters) == ["self", "step"]


async def test_scope_blocked_step_maps_to_scope_blocked() -> None:
    gate = MagicMock()
    gate.check_scope.return_value = MagicMock(allowed=False, reason="Out of scope")
    plan = _recon_plan()
    raw = await AttackModuleExecutor(gate).execute_plan_step(step_context_for(plan, 0))
    assert raw["success"] is False
    assert raw["failure_class"] == "scope_blocked"
    assert record_step_result(plan, 0, raw) == "replan"


def test_fsm_settings_defaults_and_overrides() -> None:
    assert fsm_settings({}) == (False, 3)
    assert fsm_settings(None) == (False, 3)
    assert fsm_settings({"fsm": {"enabled": True, "max_retries_per_step": 5}}) == (True, 5)


def test_legacy_plan_json_loads_unchanged() -> None:
    data = {
        "target_ip": _TARGET,
        "current_phase_index": 0,
        "phases": ["recon", "enumerate", "exploit", "escalate", "loot", "pivot", "done"],
        "steps": [
            {
                "phase": "recon",
                "tool": "check_os",
                "reason": "r",
                "target_ip": _TARGET,
                "arguments": {},
                "depends_on": [],
                "completed": False,
                "success": None,
                "result_summary": "",
            }
        ],
    }
    plan = AttackPlan.from_json(data)
    assert plan.steps[0].failure_streak == 0
    assert plan.steps[0].status == "pending"
    assert plan.to_json()["steps"][0]["failure_streak"] == 0
