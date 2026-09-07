"""Capability-upgrade (§5/§9/§12): failure-classified retries + prerequisite-
driven composition + richer ModuleContext for the autonomous orchestrator.

These tests pin three additive behaviors in ``tools/autonomous_orchestrator``:

* ``RetryEngine.should_retry`` classifies via ``tools.failure_taxonomy`` and
  refuses to retry permanent classes (scope_blocked / false_positive).
* A failure classified ``PREREQUISITE_MISSING`` schedules a producer module
  looked up via ``find_producers`` (dynamic composition, bounded).
* The two ModuleContext builders thread live attack state (access_achieved,
  privilege_level, sessions, phase, evidence_refs) so modules see it.

Modules are mocked; no live targets. The orchestrator/executor are built with
minimal args (every collaborator defaults off) like the existing suite.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from tools.attack_modules import ModuleContext
from tools.autonomous_orchestrator import (
    AttackModuleExecutor,
    AttackPhase,
    AttackState,
    AttackTask,
    AutonomousOrchestrator,
    RetryEngine,
)


def _mission_config(tmp_path: Path) -> dict[str, Any]:
    return {
        "allowed_assets": ["10.0.0.50"],
        "disallowed_assets": [],
        "forbidden_actions": ["denial_of_service"],
        "risk_profile": "high_authorized_testing",
        "max_cycles": 10,
        "max_aggression": "maximum",
        "workspace": str(tmp_path),
    }


# ── RetryEngine: failure-taxonomy classification ────────────────────────────


class TestRetryEngineTaxonomy:
    def test_scope_blocked_is_not_retried(self) -> None:
        # classify_failure -> SCOPE_BLOCKED -> is_permanent -> no retry.
        assert RetryEngine.should_retry("SSHBruteForce", "blocked by scope", 0, 3) is False

    def test_false_positive_is_not_retried(self) -> None:
        # VULN_NOT_CONFIRMED -> FALSE_POSITIVE -> is_permanent -> no retry.
        assert RetryEngine.should_retry("Log4jRCE", "VULN_NOT_CONFIRMED: not vulnerable", 0, 3) is False

    def test_timeout_is_retried(self) -> None:
        assert RetryEngine.should_retry("SSHBruteForce", "connection timed out", 0, 3) is True

    def test_transient_error_is_retried(self) -> None:
        assert RetryEngine.should_retry("SSHBruteForce", "connection reset by peer", 0, 3) is True

    def test_max_attempts_still_wins(self) -> None:
        # A retryable class still respects the attempt budget.
        assert RetryEngine.should_retry("SSHBruteForce", "timeout", 3, 3) is False

    def test_legacy_substring_blacklist_preserved(self) -> None:
        # "permission denied" classifies as AUTH_FAILED (NOT permanent per the
        # taxonomy), so the legacy substring blacklist must still catch it.
        assert RetryEngine.should_retry("SSHBruteForce", "permission denied", 0, 3) is False
        assert RetryEngine.should_retry("SSHBruteForce", "Tool not found", 0, 3) is False


# ── Prerequisite-driven composition (§9) ────────────────────────────────────


class _FakeModule:
    """Stand-in for an AttackModule returned by a mocked find_producers."""

    def __init__(self, name: str) -> None:
        self.name = name


def test_prereq_missing_schedules_producer_task(tmp_path: Path, monkeypatch) -> None:
    """A PREREQUISITE_MISSING failure schedules a find_producers-based task.

    The executor is faked so the failing module returns a missing-credential
    error; ``find_producers`` is mocked to return a credential-producing
    module. The batch must register a recovery task in ``self._tasks`` with
    ``created_from="recovery:prerequisite"`` and run it inline.
    """
    orch = AutonomousOrchestrator(_mission_config(tmp_path), tmp_path / "ws")

    executed: list[str] = []

    class _FailingExecutor:
        async def execute(self, task: AttackTask, state: AttackState) -> dict[str, Any]:
            executed.append(task.module_name)
            if task.created_from == "recovery:prerequisite":
                # The recovery module succeeds so the inner run_task returns.
                return {"success": True, "status": "success"}
            # The original failure: a missing-credential signal.
            return {"success": False, "error": "requires a credential to proceed"}

    orch._executor = _FailingExecutor()  # type: ignore[assignment]

    # Mock find_producers at the module namespace (the established patch seam).
    monkeypatch.setattr(
        "tools.autonomous_orchestrator.find_producers",
        lambda kind: [_FakeModule("SSHBruteForce")] if kind == "credentials" else [],
    )

    state = AttackState(target="10.0.0.50")
    task = AttackTask(
        task_id="ATK-ORIG",
        phase=AttackPhase.EXPLOITATION,
        module_name="LateralMovement",
        target="10.0.0.50",
    )
    orch._tasks[task.task_id] = task

    import asyncio

    asyncio.run(orch._execute_task_batch([task], state))

    # The recovery task was registered with the provenance tag.
    prereq_tasks = [t for t in orch._tasks.values() if t.created_from == "recovery:prerequisite"]
    assert len(prereq_tasks) == 1, f"expected one prereq task, got {len(prereq_tasks)}"
    assert prereq_tasks[0].module_name == "SSHBruteForce"
    # The producer module was actually executed (inline run_task).
    assert "SSHBruteForce" in executed
    # Counter incremented and bounded.
    assert orch._prereq_tasks_added == 1


def test_prereq_not_scheduled_for_non_missing_failure(tmp_path: Path, monkeypatch) -> None:
    """A non-PREREQUISITE_MISSING failure does not schedule a producer task."""
    orch = AutonomousOrchestrator(_mission_config(tmp_path), tmp_path / "ws")

    class _FailingExecutor:
        async def execute(self, task: AttackTask, state: AttackState) -> dict[str, Any]:
            return {"success": False, "error": "connection timed out"}

    orch._executor = _FailingExecutor()  # type: ignore[assignment]

    called: list[str] = []
    monkeypatch.setattr(
        "tools.autonomous_orchestrator.find_producers",
        lambda kind: called.append(kind) or [],
    )

    state = AttackState(target="10.0.0.50")
    task = AttackTask(
        task_id="ATK-TO",
        phase=AttackPhase.EXPLOITATION,
        module_name="SSHBruteForce",
        target="10.0.0.50",
        max_retries=0,  # avoid retry loop
    )
    import asyncio

    asyncio.run(orch._execute_task_batch([task], state))

    assert called == [], "find_producers must not be consulted for a timeout failure"
    assert not any(t.created_from == "recovery:prerequisite" for t in orch._tasks.values())


def test_prereq_scheduling_is_bounded(tmp_path: Path, monkeypatch) -> None:
    """The campaign-level cap stops scheduling after _prereq_recovery_cap hits."""
    cfg = _mission_config(tmp_path)
    orch = AutonomousOrchestrator(cfg, tmp_path / "ws")
    # Force a tiny cap by simulating it is already exhausted.
    orch._prereq_recovery_cap = 1
    orch._prereq_tasks_added = 1

    class _FailingExecutor:
        async def execute(self, task: AttackTask, state: AttackState) -> dict[str, Any]:
            return {"success": False, "error": "missing credential"}

    orch._executor = _FailingExecutor()  # type: ignore[assignment]

    monkeypatch.setattr(
        "tools.autonomous_orchestrator.find_producers",
        lambda kind: [_FakeModule("SSHBruteForce")],
    )

    state = AttackState(target="10.0.0.50")
    task = AttackTask(
        task_id="ATK-CAP",
        phase=AttackPhase.EXPLOITATION,
        module_name="LateralMovement",
        target="10.0.0.50",
        max_retries=0,
    )
    import asyncio

    asyncio.run(orch._execute_task_batch([task], state))

    assert not any(t.created_from == "recovery:prerequisite" for t in orch._tasks.values())


def test_maybe_schedule_prereq_unit(tmp_path: Path, monkeypatch) -> None:
    """Direct unit: returns the producer task and registers it; None otherwise."""
    orch = AutonomousOrchestrator(_mission_config(tmp_path), tmp_path / "ws")
    state = AttackState(target="10.0.0.50")
    task = AttackTask(
        task_id="ATK-UNIT",
        phase=AttackPhase.EXPLOITATION,
        module_name="LateralMovement",
        target="10.0.0.50",
    )
    monkeypatch.setattr(
        "tools.autonomous_orchestrator.find_producers",
        lambda kind: [_FakeModule("CredentialSpray")] if kind == "credentials" else [],
    )
    out = orch._maybe_schedule_prereq(task, state, "requires a credential")
    assert out is not None
    assert out.module_name == "CredentialSpray"
    assert out.created_from == "recovery:prerequisite"
    assert out.task_id in orch._tasks

    # Non-missing failure -> None.
    assert orch._maybe_schedule_prereq(task, state, "connection timed out") is None


# ── Richer ModuleContext (§12) ───────────────────────────────────────────────


def test_execute_threads_access_state_into_context(tmp_path: Path, monkeypatch) -> None:
    """AttackModuleExecutor.execute threads access_achieved/privilege_level/
    phase/sessions/evidence_refs into the ModuleContext it builds.

    A fake module captures the ctx so the test can assert the fields landed.
    """
    # Fail-closed hardening blocks ungated execution before any context is
    # built, so wire an allowing gate (same pattern as test_agent_loop.py).
    gate = MagicMock()
    gate.check_scope.return_value = MagicMock(allowed=True, requires_human_approval=False)
    executor = AttackModuleExecutor(gate)

    captured: dict[str, Any] = {}

    class _CapturingModule:
        name = "SSHBruteForce"

        def run(self, ctx: ModuleContext) -> dict[str, Any]:
            captured["access_achieved"] = ctx.access_achieved
            captured["privilege_level"] = ctx.privilege_level
            captured["phase"] = ctx.phase
            captured["sessions"] = ctx.sessions
            captured["evidence_refs"] = ctx.evidence_refs
            captured["parameters"] = ctx.parameters
            return {"status": "info"}

    # get_module is the established patch seam (orch_mod.get_module).
    import tools.autonomous_orchestrator as orch_mod

    monkeypatch.setattr(orch_mod, "get_module", lambda name: _CapturingModule())

    state = AttackState(target="10.0.0.50")
    state.access_achieved = True
    state.privilege_level = "root"
    state.shell_type = "reverse"
    state.current_phase = AttackPhase.PRIVILEGE_ESCALATION
    state.loot = ["/tmp/loot1.txt", "/tmp/loot2.txt"]

    task = AttackTask(
        task_id="ATK-CTX",
        phase=AttackPhase.PRIVILEGE_ESCALATION,
        module_name="SSHBruteForce",
        target="10.0.0.50",
        parameters={"port": 22},
    )
    import asyncio

    asyncio.run(executor.execute(task, state))

    assert captured["access_achieved"] is True
    assert captured["privilege_level"] == "root"
    assert captured["phase"] == "privesc"
    assert captured["sessions"] == [{"shell": "reverse"}]
    assert captured["evidence_refs"] == ["/tmp/loot1.txt", "/tmp/loot2.txt"]
    assert captured["parameters"] == {"port": 22}


def test_module_context_builder_threads_state_and_parameters(tmp_path: Path) -> None:
    """AutonomousOrchestrator._module_context threads live state + (optional)
    task parameters into the ModuleContext (additive, byte-identical when no
    task is supplied)."""
    orch = AutonomousOrchestrator(_mission_config(tmp_path), tmp_path / "ws")
    state = AttackState(target="10.0.0.50")
    state.access_achieved = True
    state.privilege_level = "admin"
    state.shell_type = "bind"
    state.current_phase = AttackPhase.LATERAL_MOVEMENT
    state.loot = ["/tmp/proof.txt"]

    # No task -> parameters stays {} (legacy byte-identical), but the live
    # state fields still propagate.
    ctx = orch._module_context(state)
    assert ctx.access_achieved is True
    assert ctx.privilege_level == "admin"
    assert ctx.phase == "lateral"
    assert ctx.sessions == [{"shell": "bind"}]
    assert ctx.evidence_refs == ["/tmp/proof.txt"]
    assert ctx.parameters == {}

    # With a task -> parameters propagate.
    task = AttackTask(
        task_id="ATK-P",
        phase=AttackPhase.LATERAL_MOVEMENT,
        module_name="LateralMovement",
        target="10.0.0.50",
        parameters={"cb": "10.0.0.99"},
    )
    ctx2 = orch._module_context(state, task)
    assert ctx2.parameters == {"cb": "10.0.0.99"}
    assert ctx2.access_achieved is True
