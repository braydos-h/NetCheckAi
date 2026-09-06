"""Attack planner for autonomous AI-driven penetration testing.

Provides:
- AttackPhase enum: RECON, ENUMERATE, EXPLOIT, ESCALATE, LOOT, PIVOT, DONE
- AttackPlan: JSON-serializable plan with ordered phases and tool selections
- AttackPlanner: drives the AI to create/adapt plans based on results
- Plan execution helpers that feed context back to the LLM
"""

from __future__ import annotations

import enum
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.failure_taxonomy import is_permanent


class AttackPhase(str, enum.Enum):
    RECON = "recon"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    ESCALATE = "escalate"
    LOOT = "loot"
    PIVOT = "pivot"
    DONE = "done"


@dataclass
class AttackStep:
    phase: str
    tool: str
    reason: str
    target_ip: str
    arguments: dict[str, Any] = field(default_factory=dict)
    depends_on: list[int] = field(default_factory=list)
    completed: bool = False
    success: bool | None = None
    result_summary: str = ""
    # Capability-upgrade / task-graph fields (all defaulted; old plan JSON
    # loads unchanged and to_json stays additive-only):
    hypothesis: str = ""
    priority: int = 50  # 0-100; higher runs first among ready steps
    status: str = "pending"  # pending|running|done|failed|blocked|cancelled
    attempt_count: int = 0
    failure_class: str = ""  # tools/failure_taxonomy.FailureClass value
    failure_streak: int = 0  # consecutive failures with the same failure_class (stuck-loop breaker)
    failure_reason: str = ""
    capability: str = ""  # module/tool capability name when known
    expected_evidence: list[str] = field(default_factory=list)
    confidence: float | None = None
    created_from: str = ""  # planner|recovery:prerequisite|operator|replan|...


@dataclass
class AttackPlan:
    target_ip: str
    target_os: str | None = None
    target_cves: list[str] = field(default_factory=list)
    service_context: str = ""
    phases: list[AttackPhase] = field(
        default_factory=lambda: [
            AttackPhase.RECON,
            AttackPhase.ENUMERATE,
            AttackPhase.EXPLOIT,
            AttackPhase.ESCALATE,
            AttackPhase.LOOT,
            AttackPhase.PIVOT,
            AttackPhase.DONE,
        ]
    )
    steps: list[AttackStep] = field(default_factory=list)
    current_phase_index: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    attack_mode: bool = False

    @property
    def current_phase(self) -> AttackPhase:
        if self.current_phase_index < len(self.phases):
            return self.phases[self.current_phase_index]
        return AttackPhase.DONE

    def next_phase(self) -> None:
        if self.current_phase_index < len(self.phases) - 1:
            self.current_phase_index += 1
        self.updated_at = time.time()

    def add_step(self, step: AttackStep) -> int:
        self.steps.append(step)
        self.updated_at = time.time()
        return len(self.steps) - 1

    def mark_step_done(self, index: int, success: bool, summary: str) -> None:
        if 0 <= index < len(self.steps):
            self.steps[index].completed = True
            self.steps[index].success = success
            self.steps[index].result_summary = summary[:2000]
            self.steps[index].status = "done"
        self.updated_at = time.time()

    def is_complete(self) -> bool:
        return self.current_phase_index >= len(self.phases) - 1

    # --- Task-graph (DAG) operations -------------------------------------
    # depends_on edges already serialized; these are the scheduling semantics
    # that were missing. All methods are pure-Python, no model calls.

    _OPEN_STATUSES = ("pending", "running")

    def _dep_satisfied(self, index: int) -> bool:
        """A dependency is satisfied only when it completed AND succeeded."""
        if not (0 <= index < len(self.steps)):
            return True  # dangling dep reference: don't deadlock the graph
        dep = self.steps[index]
        return dep.completed and dep.success is True

    def _dep_dead(self, index: int) -> bool:
        """A dependency is dead when it can never satisfy (failed permanently
        or cancelled)."""
        if not (0 <= index < len(self.steps)):
            return False
        dep = self.steps[index]
        return dep.status == "cancelled" or (dep.completed and dep.success is False)

    def ready_steps(self) -> list[tuple[int, AttackStep]]:
        """Executable steps now: open status, all depends_on succeeded.

        Ordered by priority (desc) then insertion order so the scheduler and
        the LLM see a deterministic next-action list.
        """
        ready = [
            (i, s)
            for i, s in enumerate(self.steps)
            if s.status in self._OPEN_STATUSES and not s.completed and all(self._dep_satisfied(d) for d in s.depends_on)
        ]
        ready.sort(key=lambda t: (-t[1].priority, t[0]))
        return ready

    def blocked_steps(self) -> list[tuple[int, AttackStep, str]]:
        """Open steps whose dependencies can never satisfy, with reason."""
        out: list[tuple[int, AttackStep, str]] = []
        for i, s in enumerate(self.steps):
            if s.status not in self._OPEN_STATUSES or s.completed:
                continue
            dead = [d for d in s.depends_on if self._dep_dead(d)]
            if dead:
                out.append((i, s, f"dependency step(s) {dead} failed or cancelled"))
        return out

    def fail_step(self, index: int, failure_class: str = "", reason: str = "") -> None:
        """Record a failed attempt without completing the step (retryable)."""
        if 0 <= index < len(self.steps):
            s = self.steps[index]
            s.attempt_count += 1
            s.status = "failed"
            s.failure_class = failure_class
            s.failure_reason = reason[:500]
        self.updated_at = time.time()

    def reset_step(self, index: int) -> None:
        """Re-open a failed step for another attempt (e.g. after recovery)."""
        if 0 <= index < len(self.steps):
            s = self.steps[index]
            if s.status in ("failed", "blocked") and not s.completed:
                s.status = "pending"
        self.updated_at = time.time()

    def cancel_step(self, index: int, reason: str = "") -> None:
        """Mark a step obsolete (e.g. its hypothesis was refuted elsewhere)."""
        if 0 <= index < len(self.steps):
            s = self.steps[index]
            if not s.completed:
                s.status = "cancelled"
                s.failure_reason = reason[:500]
        self.updated_at = time.time()

    def graph_summary(self, max_steps: int = 40) -> str:
        """Compact DAG view for prompts/state tools: ready/blocked counts +
        per-step one-liners. Raw results stay in artifacts."""
        lines = [
            f"TASK GRAPH: {len(self.steps)} steps "
            f"({len(self.ready_steps())} ready, {len(self.blocked_steps())} blocked)"
        ]
        for i, s in enumerate(self.steps[:max_steps]):
            dep = f" <-{s.depends_on}" if s.depends_on else ""
            hyp = f" hyp={s.hypothesis[:60]!r}" if s.hypothesis else ""
            lines.append(f"  [{i}] {s.status}/{s.tool}{dep}{hyp}")
        if len(self.steps) > max_steps:
            lines.append(f"  ... (+{len(self.steps) - max_steps} more)")
        return "\n".join(lines)

    def to_json(self) -> dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "target_os": self.target_os,
            "target_cves": self.target_cves,
            "service_context": self.service_context,
            "phases": [p.value for p in self.phases],
            "current_phase": self.current_phase.value,
            "current_phase_index": self.current_phase_index,
            "steps": [
                {
                    "phase": s.phase,
                    "tool": s.tool,
                    "reason": s.reason,
                    "target_ip": s.target_ip,
                    "arguments": s.arguments,
                    "depends_on": s.depends_on,
                    "completed": s.completed,
                    "success": s.success,
                    "result_summary": s.result_summary,
                    # Capability-upgrade fields (additive keys; old readers
                    # ignore them, new readers get the DAG state):
                    "hypothesis": s.hypothesis,
                    "priority": s.priority,
                    "status": s.status,
                    "attempt_count": s.attempt_count,
                    "failure_class": s.failure_class,
                    "failure_streak": s.failure_streak,
                    "failure_reason": s.failure_reason,
                    "capability": s.capability,
                    "expected_evidence": s.expected_evidence,
                    "confidence": s.confidence,
                    "created_from": s.created_from,
                }
                for s in self.steps
            ],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "attack_mode": self.attack_mode,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> AttackPlan:
        plan = cls(
            target_ip=data.get("target_ip", ""),
            target_os=data.get("target_os"),
            target_cves=data.get("target_cves", []),
            service_context=data.get("service_context", ""),
            current_phase_index=data.get("current_phase_index", 0),
            phases=[AttackPhase(p) for p in data.get("phases", [])],
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            attack_mode=data.get("attack_mode", False),
        )
        for s in data.get("steps", []):
            step = AttackStep(
                phase=s.get("phase", ""),
                tool=s.get("tool", ""),
                reason=s.get("reason", ""),
                target_ip=s.get("target_ip", ""),
                arguments=s.get("arguments", {}),
                depends_on=s.get("depends_on", []),
                completed=s.get("completed", False),
                success=s.get("success"),
                result_summary=s.get("result_summary", ""),
                hypothesis=s.get("hypothesis", ""),
                priority=s.get("priority", 50),
                status=s.get("status", "done" if s.get("completed") else "pending"),
                attempt_count=s.get("attempt_count", 0),
                failure_class=s.get("failure_class", ""),
                failure_streak=s.get("failure_streak", 0),
                failure_reason=s.get("failure_reason", ""),
                capability=s.get("capability", ""),
                expected_evidence=s.get("expected_evidence", []),
                confidence=s.get("confidence"),
                created_from=s.get("created_from", ""),
            )
            plan.steps.append(step)
        return plan

    def generate_battle_log(self) -> str:
        """Compact summary of everything tried so far for context compression."""
        lines = [
            f"Target: {self.target_ip}",
            f"Current Phase: {self.current_phase.value}",
            f"Total Steps: {len(self.steps)}",
            f"Completed Steps: {sum(1 for s in self.steps if s.completed)}",
            f"Successful Steps: {sum(1 for s in self.steps if s.completed and s.success)}",
        ]
        for i, s in enumerate(self.steps):
            status = "✓" if s.completed and s.success else "✗" if s.completed else "○"
            lines.append(f"  [{i}] {status} {s.phase}/{s.tool}: {s.reason[:80]}")
            if s.completed:
                lines.append(f"       Result: {s.result_summary[:120]}")
        return "\n".join(lines)


# --- FSM + planner-executor split -------------------------------------------
# The campaign loop used to let one LLM call own planning AND execution with
# the full battle history in context. The split below separates the roles:
#
# - planner (persistent): owns the single AttackPlan via add_step /
#   mark_step_done / record_step_result. It only ever sees planner_context()
#   (current phase + ready/blocked summary, never raw step output).
# - executor (memoryless): takes ONE StepContext, runs it via
#   AttackModuleExecutor.execute_plan_step, returns an ExecutorResult. It
#   cannot see sibling steps or history by construction (the step is its
#   only input).
# - FSM guard: the RECON -> ... -> DONE chain with explicit allowed
#   transitions, plus a stuck-loop breaker (same failure_class N times in a
#   row -> step blocked, caller must replan instead of retrying blindly).

# ponytail: linear chain + DONE escape + one-step back-edge for replan
# regression. Anything else (e.g. a recon->loot jump) is a planner bug and
# fails loudly in fsm_advance.
FSM_TRANSITIONS: dict[str, list[str]] = {
    "recon": ["enumerate", "done"],
    "enumerate": ["exploit", "recon", "done"],
    "exploit": ["escalate", "enumerate", "done"],
    "escalate": ["loot", "exploit", "done"],
    "loot": ["pivot", "escalate", "done"],
    "pivot": ["done", "recon"],
    "done": [],
}


def fsm_can_transition(frm: str, to: str) -> bool:
    """True when the FSM guard allows a phase move (never raises)."""
    return str(to) in FSM_TRANSITIONS.get(str(frm), [])


def _fsm_next(plan: AttackPlan) -> AttackPhase:
    nxt_idx = plan.current_phase_index + 1
    if 0 <= nxt_idx < len(plan.phases):
        return plan.phases[nxt_idx]
    return AttackPhase.DONE


def fsm_advance(plan: AttackPlan, target: AttackPhase | str | None = None) -> AttackPhase:
    """Move the plan through the FSM guard to the next (or ``target``) phase.

    Raises ValueError on an illegal jump so a planner bug fails loudly
    instead of silently skipping phases.
    """
    cur = plan.current_phase
    nxt = AttackPhase(target) if target is not None else _fsm_next(plan)
    if nxt == cur:
        return cur
    if not fsm_can_transition(cur.value, nxt.value):
        raise ValueError(f"Illegal FSM transition {cur.value} -> {nxt.value}")
    try:
        plan.current_phase_index = plan.phases.index(nxt)
    except ValueError:
        plan.next_phase()  # custom phase list without nxt: single-step fallback
    plan.updated_at = time.time()
    return plan.current_phase


def planner_context(plan: AttackPlan, max_steps: int = 20) -> str:
    """State-scoped planner view: current phase + ready/blocked summary.

    Deliberately excludes per-step results and history (no result_summary,
    no battle log) so planner context stays bounded and one step's raw
    output cannot leak into the next plan via the planner.
    """
    ready = plan.ready_steps()
    blocked = plan.blocked_steps()
    lines = [
        f"TARGET: {plan.target_ip}",
        f"CURRENT PHASE: {plan.current_phase.value}",
        f"STEPS: {len(plan.steps)} total, {len(ready)} ready, {len(blocked)} blocked, "
        f"{sum(1 for s in plan.steps if s.completed)} completed",
        "READY:",
    ]
    for i, s in ready[:max_steps]:
        ev = f" evidence={s.expected_evidence}" if s.expected_evidence else ""
        lines.append(f"  [{i}] {s.phase}/{s.tool}: {s.reason[:120]}{ev}")
    lines.append("BLOCKED:")
    for i, s, why in blocked[:max_steps]:
        lines.append(f"  [{i}] {s.phase}/{s.tool}: {why}")
    return "\n".join(lines)


@dataclass
class StepContext:
    """Memoryless executor input: ONE step plus the minimum to run it.

    No plan reference, no history, no sibling steps -- serializing this can
    never contain another step's output.
    """

    target_ip: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    expected_evidence: list[str] = field(default_factory=list)
    phase: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "expected_evidence": list(self.expected_evidence),
            "phase": self.phase,
            "reason": self.reason,
        }


@dataclass
class ExecutorResult:
    """Memoryless executor output, folded into the plan via record_step_result."""

    success: bool
    evidence: list[str] = field(default_factory=list)
    failure_class: str = ""
    tool: str = ""
    target_ip: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "evidence": list(self.evidence),
            "failure_class": self.failure_class,
            "tool": self.tool,
            "target_ip": self.target_ip,
        }


def step_context_for(plan: AttackPlan, index: int) -> StepContext:
    """Build the memoryless input for one ready step (planner-side read)."""
    s = plan.steps[index]
    return StepContext(
        target_ip=s.target_ip or plan.target_ip,
        tool=s.tool,
        arguments=dict(s.arguments),
        expected_evidence=list(s.expected_evidence),
        phase=s.phase,
        reason=s.reason,
    )


def record_step_result(
    plan: AttackPlan,
    index: int,
    result: ExecutorResult | dict[str, Any],
    *,
    max_retries: int = 3,
) -> str:
    """Fold ONE memoryless executor result into the plan (planner-side write).

    The ONLY writer path for executor outcomes: returns "done" (step
    succeeded), "retry" (failed, may be reset for another attempt), or
    "replan" (step blocked -- same failure_class hit the retry budget, or the
    class is permanent -- the planner must author a NEW step, never blindly
    retry this one).
    """
    if isinstance(result, dict):
        success = bool(result.get("success"))
        evidence = [str(e)[:500] for e in (result.get("evidence") or [])][:10]
        failure_class = str(result.get("failure_class") or "")
    else:
        success = result.success
        evidence = [str(e)[:500] for e in result.evidence][:10]
        failure_class = result.failure_class
    step = plan.steps[index]
    if success:
        plan.mark_step_done(index, True, "; ".join(evidence)[:2000] or f"{step.tool} succeeded")
        step.failure_streak = 0
        return "done"
    if not failure_class:
        failure_class = "unknown"
    if is_permanent(failure_class):
        # ponytail: scope/false-positive failures never burn the retry budget.
        plan.fail_step(index, failure_class, "; ".join(evidence)[:500])
        step.status = "blocked"
        return "replan"
    streak = step.failure_streak + 1 if failure_class == step.failure_class else 1
    plan.fail_step(index, failure_class, "; ".join(evidence)[:500] or f"{step.tool} failed ({failure_class})")
    step.failure_streak = streak
    if streak >= max(1, max_retries):
        step.status = "blocked"  # stuck-loop breaker: same failure N times
        return "replan"
    return "retry"


def fsm_settings(config: dict[str, Any] | None = None) -> tuple[bool, int]:
    """Read the ``fsm`` config block (never raises; defaults off / 3 retries)."""
    block = (config or {}).get("fsm")
    if not isinstance(block, dict):
        return False, 3
    try:
        max_retries = max(1, int(block.get("max_retries_per_step", 3)))
    except (TypeError, ValueError):
        max_retries = 3
    return bool(block.get("enabled", False)), max_retries


def build_planning_prompt(
    phase: AttackPhase,
    target_ip: str,
    target_os: str | None,
    known_cves: list[str],
    service_context: str,
    attacker_os: str,
    previous_result: str = "",
    battle_log: str = "",
) -> str:
    """Build a prompt that asks the AI to generate an attack plan for the current phase."""
    base = f"""You are an autonomous penetration testing AI. You are in **{phase.value.upper()}** phase.

TARGET: {target_ip}
TARGET OS: {target_os or "Unknown"}
KNOWN CVEs: {", ".join(known_cves) if known_cves else "None"}
SERVICE CONTEXT: {service_context}
ATTACKER OS: {attacker_os}

{previous_result}

BATTLE LOG (history of attempts):
{battle_log}

Your task: Generate the NEXT attack steps for this phase.
Return ONLY a JSON list of steps, like:
[
  {{
    "phase": "{phase.value}",
    "tool": "check_os",
    "reason": "Need to confirm target OS before choosing exploit",
    "target_ip": "{target_ip}",
    "arguments": {{"target_ip": "{target_ip}"}},
    "depends_on": []
  }},
  ...
]

Rules:
- Each step must use a valid tool name from your available MCP tools.
- "depends_on" lists indices of previous steps that must succeed before this step.
- Keep each reason concise (under 200 chars).
- If the phase should be skipped, return an empty list and explain why in your reasoning.
- After generating the plan, execute it step-by-step.
"""
    return base


def build_replanning_prompt(
    plan: AttackPlan,
    last_result: str,
    attacker_os: str,
) -> str:
    """Prompt the AI to update its plan after a tool result."""
    phase = plan.current_phase
    base = f"""You are in **{phase.value.upper()}** phase against {plan.target_ip}.

SERVICE CONTEXT: {plan.service_context}
ATTACKER OS: {attacker_os}

BATTLE LOG:
{plan.generate_battle_log()}

LAST RESULT:
{last_result[:2000]}

Adaptive instructions:
- If the last step succeeded, consider escalating or moving to the next phase.
- If it failed, try an alternative approach within the same phase.
- If you gained access (shell, RCE, command execution), automatically transition to POST-EXPLOITATION (escalate, loot, pivot).
- Do NOT repeat failed steps verbatim.
- If target OS is now known and differs from assumptions, update your tool choices.

What is your next move? Return a JSON step OR a phase transition command:
{{
  "action": "step" | "next_phase" | "done",
  "step": {{"phase": "...", "tool": "...", "reason": "...", "target_ip": "...", "arguments": {{}}, "depends_on": []}},
  "explanation": "..."
}}
"""
    return base


def parse_plan_json(text: str) -> list[AttackStep]:
    """Extract JSON list of attack steps from AI response text (with markdown fence stripping)."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = data.get("steps", [])
    if not isinstance(data, list):
        return []
    steps: list[AttackStep] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        steps.append(
            AttackStep(
                phase=item.get("phase", ""),
                tool=item.get("tool", ""),
                reason=item.get("reason", ""),
                target_ip=item.get("target_ip", ""),
                arguments=item.get("arguments", {}),
                depends_on=item.get("depends_on", []),
            )
        )
    return steps


def parse_replan_json(text: str) -> tuple[str, AttackStep | None, str]:
    """Parse replanning response: returns (action, step_or_none, explanation)."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "step", None, "Parse error; continuing with heuristic step"
    action = data.get("action", "step")
    explanation = data.get("explanation", "")
    step_data = data.get("step")
    step = None
    if isinstance(step_data, dict):
        step = AttackStep(
            phase=step_data.get("phase", ""),
            tool=step_data.get("tool", ""),
            reason=step_data.get("reason", ""),
            target_ip=step_data.get("target_ip", ""),
            arguments=step_data.get("arguments", {}),
            depends_on=step_data.get("depends_on", []),
        )
    return action, step, explanation


class AttackPlanner:
    """Manages plan lifecycle: creation, execution, adaptive replanning, persistence."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._plans: dict[str, AttackPlan] = {}
        self._plan_path = workspace / "plans"
        self._plan_path.mkdir(parents=True, exist_ok=True)

    def create_plan(
        self,
        target_ip: str,
        *,
        target_os: str | None = None,
        known_cves: list[str] | None = None,
        service_context: str = "",
        attack_mode: bool = False,
    ) -> AttackPlan:
        plan = AttackPlan(
            target_ip=target_ip,
            target_os=target_os,
            target_cves=known_cves or [],
            service_context=service_context,
            attack_mode=attack_mode,
        )
        self._plans[target_ip] = plan
        return plan

    def get_plan(self, target_ip: str) -> AttackPlan | None:
        return self._plans.get(target_ip)

    def save_plan(self, plan: AttackPlan) -> None:
        path = self._plan_path / f"{plan.target_ip.replace('.', '_')}_plan.json"
        path.write_text(json.dumps(plan.to_json(), indent=2, default=str), encoding="utf-8")

    def load_plan(self, target_ip: str) -> AttackPlan | None:
        path = self._plan_path / f"{target_ip.replace('.', '_')}_plan.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            plan = AttackPlan.from_json(data)
            self._plans[target_ip] = plan
            return plan
        except (json.JSONDecodeError, KeyError):
            return None

    def has_active_plan(self, target_ip: str) -> bool:
        plan = self.get_plan(target_ip) or self.load_plan(target_ip)
        if plan is None:
            return False
        return not plan.is_complete()

    def all_plans_summary(self) -> str:
        lines = ["ACTIVE PLANS:"]
        for ip, plan in self._plans.items():
            status = "DONE" if plan.is_complete() else plan.current_phase.value.upper()
            lines.append(
                f"  {ip}: {status} ({len(plan.steps)} steps, {sum(1 for s in plan.steps if s.completed and s.success)} success)"
            )
        return "\n".join(lines)
