"""Task-graph + failure-recovery simulation harness (capability upgrade §18).

These are NOT unit tests of a single function -- they script end-to-end
mini-scenarios over the *stable foundation* (``AttackPlan`` DAG semantics,
``failure_taxonomy`` classification/recovery, ``assessment_state`` hypothesis
lifecycle, ``find_producers`` composition) to prove the AI's new
observe -> hypothesize -> plan -> execute -> interpret -> update -> recover
loop holds together without a live target or model.

Everything here is deterministic Python: no network, no Ollama, no MCP
session. Mock modules stand in for real ``AttackModule`` subclasses so the
simulation does not depend on the module-metadata sweep landing first.
"""

from __future__ import annotations

import json

import pytest

from tools.assessment_state import AssessmentStateStore
from tools.attack_planner import AttackPlan, AttackStep
from tools.failure_taxonomy import (
    FailureClass,
    RecoveryAction,
    classify_failure,
    is_permanent,
    is_retryable,
    recovery_for,
    recovery_hint,
)


def _step(tool="check_os", *, phase="recon", depends_on=None, priority=50, hypothesis=""):
    return AttackStep(
        phase=phase,
        tool=tool,
        reason="sim",
        target_ip="10.0.0.50",
        depends_on=list(depends_on or []),
        priority=priority,
        hypothesis=hypothesis,
    )


def _plan(steps):
    plan = AttackPlan(target_ip="10.0.0.50")
    for s in steps:
        plan.add_step(s)
    return plan


# ──────────────────────────────────────────────────────────────────────────
# Scenario 1: linear dependency chain executes in order
# ──────────────────────────────────────────────────────────────────────────
def test_linear_chain_unlocks_in_order():
    plan = _plan([_step("a"), _step("b", depends_on=[0]), _step("c", depends_on=[1])])

    assert [i for i, _ in plan.ready_steps()] == [0]
    plan.mark_step_done(0, True, "a ok")
    assert [i for i, _ in plan.ready_steps()] == [1]
    plan.mark_step_done(1, True, "b ok")
    assert [i for i, _ in plan.ready_steps()] == [2]
    plan.mark_step_done(2, True, "c ok")
    assert plan.ready_steps() == []
    assert all(s.completed and s.success for s in plan.steps)


# ──────────────────────────────────────────────────────────────────────────
# Scenario 2: parallel fan-out -- all dependents ready together, priority orders
# ──────────────────────────────────────────────────────────────────────────
def test_parallel_fanout_priority_ordering():
    plan = _plan(
        [
            _step("root"),
            _step("low", depends_on=[0], priority=10),
            _step("high", depends_on=[0], priority=90),
            _step("mid", depends_on=[0], priority=50),
        ]
    )
    assert [i for i, _ in plan.ready_steps()] == [0]
    plan.mark_step_done(0, True, "root ok")

    ready = [i for i, _ in plan.ready_steps()]
    # Descending priority, stable insertion order on ties.
    assert ready == [2, 3, 1]


# ──────────────────────────────────────────────────────────────────────────
# Scenario 3: retryable failure -> reset -> retry succeeds (no deadlock)
# ──────────────────────────────────────────────────────────────────────────
def test_retryable_failure_reset_and_retry():
    plan = _plan([_step("exploit"), _step("loot", depends_on=[0])])

    # First attempt times out -- retryable, so the step stays open-ish.
    fc = classify_failure("ERROR: connection timed out after 30s")
    assert fc is FailureClass.TIMEOUT
    assert is_retryable(fc) and not is_permanent(fc)
    plan.fail_step(0, fc.value, "timeout on first attempt")
    assert plan.steps[0].status == "failed"
    assert plan.steps[0].attempt_count == 1
    # A failed (not completed) step does not unlock dependents and is not "ready".
    assert plan.ready_steps() == []

    # Recovery: reset and retry with params succeeds.
    plan.reset_step(0)
    assert plan.steps[0].status == "pending"
    assert [i for i, _ in plan.ready_steps()] == [0]
    plan.mark_step_done(0, True, "exploit ok with --timeout 90")
    assert [i for i, _ in plan.ready_steps()] == [1]


# ──────────────────────────────────────────────────────────────────────────
# Scenario 4: permanent failure (scope_blocked) -> no retry -> cancel + block downstream
# ──────────────────────────────────────────────────────────────────────────
def test_permanent_failure_cancels_and_blocks_downstream():
    plan = _plan(
        [
            _step("scan_oob"),
            _step("pivot", depends_on=[0]),
        ]
    )
    fc = classify_failure("BLOCKED: target 10.0.0.99 not in the explicit allowlist")
    assert fc is FailureClass.SCOPE_BLOCKED
    assert is_permanent(fc) and not is_retryable(fc)
    assert recovery_for(fc) is RecoveryAction.STOP

    plan.fail_step(0, fc.value, "out of scope")
    # Permanent -> operator/planner cancels rather than retry.
    plan.cancel_step(0, "scope violation; never retry")
    assert plan.steps[0].status == "cancelled"

    # Downstream step is now blocked (dep is dead) then should be cancelled too.
    blocked = plan.blocked_steps()
    assert blocked and blocked[0][0] == 1
    plan.cancel_step(1, "prerequisite cancelled")
    assert plan.steps[1].status == "cancelled"
    assert plan.ready_steps() == []


# ──────────────────────────────────────────────────────────────────────────
# Scenario 5: prerequisite_missing -> find_producers -> schedule producer step
# ──────────────────────────────────────────────────────────────────────────
class _MockModule:
    """Minimal stand-in for AttackModule for composition discovery."""

    def __init__(self, name, produces, requires=None):
        self.name = name
        self.produces = list(produces)
        self.requires = list(requires or [])


def test_prerequisite_missing_schedules_producer(monkeypatch):
    # Simulate the registry: two modules, one consumes "credentials", one produces it.
    producer = _MockModule("cred_spray", produces=["credentials"])
    consumer = _MockModule("pass_hash", produces=["hash_artifact"], requires=["credentials"])

    import tools.attack_modules.registry as registry

    monkeypatch.setattr(registry, "list_modules", lambda: [producer, consumer])
    # find_producers reads m.produces off whatever list_modules returns.
    candidates = registry.find_producers("credentials")
    assert [m.name for m in candidates] == ["cred_spray"]

    # A consumer run fails with PREREQUISITE_MISSING.
    fc = classify_failure("requires a credential to proceed; no valid credentials found")
    assert fc is FailureClass.PREREQUISITE_MISSING
    assert recovery_for(fc) is RecoveryAction.CREATE_PREREQUISITE

    # Planner appends a producer task to satisfy the prerequisite.
    plan = _plan([_step("pass_hash")])
    plan.fail_step(0, fc.value, "no credentials")
    producer_step = _step("cred_spray", phase="exploit")
    producer_step.created_from = "recovery:prerequisite"
    producer_idx = plan.add_step(producer_step)
    plan.reset_step(0)  # reopen the consumer once prereq is scheduled
    plan.steps[0].depends_on.append(producer_idx)

    # Producer is ready immediately; consumer waits for it.
    ready = [i for i, _ in plan.ready_steps()]
    assert producer_idx in ready
    assert 0 not in ready
    plan.mark_step_done(producer_idx, True, "got creds")
    assert [i for i, _ in plan.ready_steps()] == [0]


# ──────────────────────────────────────────────────────────────────────────
# Scenario 6: blocked steps are reported with a reason
# ──────────────────────────────────────────────────────────────────────────
def test_blocked_steps_report_dead_dependency():
    plan = _plan([_step("a"), _step("b", depends_on=[0]), _step("c", depends_on=[1])])
    plan.cancel_step(0, "obsolete")
    blocked = plan.blocked_steps()
    # b is directly blocked by cancelled a; c is still open (b not dead yet).
    blocked_idx = [i for i, _, _ in blocked]
    assert 1 in blocked_idx
    assert 2 not in blocked_idx
    assert "0" in blocked[0][2]


# ──────────────────────────────────────────────────────────────────────────
# Scenario 7: failure-classification matrix (deterministic taxonomy)
# ──────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "text,expected",
    [
        ("BLOCKED: 10.0.0.99 not in allowlist", FailureClass.SCOPE_BLOCKED),
        ("VULN_NOT_CONFIRMED: patched version detected", FailureClass.FALSE_POSITIVE),
        ("insufficient evidence to confirm", FailureClass.INSUFFICIENT_EVIDENCE),
        ("connection refused: no route to host", FailureClass.TARGET_UNREACHABLE),
        ("readtimeout after 30s", FailureClass.TIMEOUT),
        ("STATUS_LOGON_FAILURE invalid credentials", FailureClass.AUTH_FAILED),
        ("requires a foothold to run; no active session", FailureClass.PREREQUISITE_MISSING),
        ("sqlmap: command not found / not installed", FailureClass.TOOL_UNAVAILABLE),
        ("Traceback (most recent call last): SyntaxError", FailureClass.MALFORMED_CODE),
        ("invalid argument: unexpected keyword 'foo'", FailureClass.SCHEMA_ERROR),
        ("RemoteProtocolError: server disconnected", FailureClass.TRANSPORT_ERROR),
        ("unsupported target: does not apply", FailureClass.UNSUPPORTED_TARGET),
        ("", FailureClass.UNKNOWN),
        ("some weird unrecognized thingamajig", FailureClass.UNEXPECTED_OUTPUT),
    ],
)
def test_classification_matrix(text, expected):
    assert classify_failure(text) is expected


def test_recovery_actions_consistency():
    # STOP classes are permanent + not retryable; RETRY/REPAIR/CREATE classes are retryable-or-actionable.
    for fc in (FailureClass.SCOPE_BLOCKED, FailureClass.FALSE_POSITIVE):
        assert is_permanent(fc) and not is_retryable(fc)
    for fc in (FailureClass.TIMEOUT, FailureClass.TRANSPORT_ERROR, FailureClass.MALFORMED_CODE):
        assert is_retryable(fc) and not is_permanent(fc)
    # PREREQUISITE_MISSING drives composition, not a blind retry.
    assert recovery_for(FailureClass.PREREQUISITE_MISSING) is RecoveryAction.CREATE_PREREQUISITE
    assert recovery_hint(FailureClass.PREREQUISITE_MISSING)


# ──────────────────────────────────────────────────────────────────────────
# Scenario 8: hypothesis lifecycle drives step status
# ──────────────────────────────────────────────────────────────────────────
def test_hypothesis_lifecycle(tmp_path):
    store = AssessmentStateStore(tmp_path)
    state = store.load("10.0.0.50")
    state.goal = "backdoor"
    h = state.add_hypothesis(
        "Log4j RCE exposed on port 8080", confidence=0.7, expected_evidence=["shell"], created_from="planner"
    )

    # A step is tied to the hypothesis.
    plan = _plan([_step("log4j", phase="exploit", hypothesis=h.id)])
    assert plan.steps[0].hypothesis == h.id

    # Hypothesis confirmed -> step succeeds.
    assert state.set_hypothesis_status(h.id, "confirmed", "WEBSHELL_CONFIRMED")
    assert state.find_hypothesis(h.id).status == "confirmed"
    plan.mark_step_done(0, True, "shell obtained")

    # A second hypothesis is refuted -> its step should be cancelled.
    h2 = state.add_hypothesis("SMBGhost reachable", confidence=0.4, created_from="recon")
    plan.add_step(_step("smbghost", phase="exploit", hypothesis=h2.id))
    state.set_hypothesis_status(h2.id, "refuted", "VULN_NOT_CONFIRMED")
    plan.cancel_step(1, f"hypothesis {h2.id} refuted")
    assert plan.steps[1].status == "cancelled"

    # Persist the mutated state, then reload.
    store.save(state)
    reloaded = AssessmentStateStore(tmp_path).load("10.0.0.50")
    statuses = {x.id: x.status for x in reloaded.hypotheses}
    assert statuses[h.id] == "confirmed" and statuses[h2.id] == "refuted"


# ──────────────────────────────────────────────────────────────────────────
# Scenario 9: graph_summary + aggregate_state compact snapshot
# ──────────────────────────────────────────────────────────────────────────
def test_graph_summary_and_aggregate_state(tmp_path):
    plan = _plan(
        [
            _step("a"),
            _step("b", depends_on=[0], priority=80),
            _step("c", depends_on=[1]),
        ]
    )
    plan.mark_step_done(0, True, "a ok")
    plan.fail_step(1, FailureClass.TIMEOUT.value, "timeout")

    summary = plan.graph_summary()
    assert "TASK GRAPH: 3 steps" in summary
    assert "ready" in summary and "blocked" in summary
    assert "[1] failed/b" in summary  # failed step surfaced

    # Persist plan where aggregate_state expects it.
    from tools.attack_planner import AttackPlanner

    planner = AttackPlanner(tmp_path)
    planner.save_plan(plan)

    # Seed an audit trail record for the target (compact refs, not secrets).
    (tmp_path / "exploit_audit.jsonl").write_text(
        json.dumps(
            {
                "target_ip": "10.0.0.50",
                "tool_name": "run_exploit_terminal",
                "status": "completed",
                "attempt_id": "att-1",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    snap = __import__("tools.assessment_state", fromlist=["aggregate_state"]).aggregate_state(
        "10.0.0.50", tmp_path, config={}
    )
    assert snap["target"] == "10.0.0.50"
    # Plan summary reflects the DAG state we built.
    assert snap["plan"]["total_steps"] == 3
    assert snap["plan"]["completed"] == 1
    assert snap["plan"]["failed"] == [1]
    # Audit rollup carries compact refs, never raw command/args.
    assert snap["activity"]["tool_calls"] == 1
    ref = snap["activity"]["recent"][0]
    assert "exploit_audit:10.0.0.50:att-1" in ref
    assert "command" not in ref  # no raw command leakage


# ──────────────────────────────────────────────────────────────────────────
# Scenario: next_step selects the single highest-priority ready step
# ──────────────────────────────────────────────────────────────────────────
def test_next_step_selects_highest_priority_ready():
    plan = _plan(
        [
            _step("root"),
            _step("low", depends_on=[0], priority=10),
            _step("high", depends_on=[0], priority=90),
        ]
    )
    # Before root completes only root is selectable.
    assert plan.next_step()[0] == 0
    plan.mark_step_done(0, True, "root ok")
    # Highest-priority ready step wins; ties fall back to insertion order.
    assert plan.next_step()[0] == 2
    plan.mark_step_done(2, True, "high ok")
    assert plan.next_step()[0] == 1
    plan.mark_step_done(1, True, "low ok")
    # Nothing ready (all done) — and a blocked graph also yields None.
    assert plan.next_step() is None

    blocked = _plan([_step("a"), _step("b", depends_on=[0])])
    blocked.fail_step(0, FailureClass.SCOPE_BLOCKED.value, "denied")
    assert blocked.next_step() is None

    # Selection survives a JSON round-trip (loop persists plans between runs).
    revived = AttackPlan.from_json(plan.to_json())
    assert revived.next_step() is None
    revived2 = AttackPlan.from_json(blocked.to_json())
    assert revived2.next_step() is None
