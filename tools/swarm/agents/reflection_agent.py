"""Reflection Agent — post-phase meta-cognitive reviewer.

Deep reflection specialist with:
- Pattern analysis across the full battle log
- Root cause identification for failures (tool mismatch, protocol error, firewall, patched)
- Strategy shift recommendations with confidence
- Semantic memory storage for cross-mission learning
- Blackboard-driven strategy adaptation
"""

from __future__ import annotations

import json
import time
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH
from tools.failure_taxonomy import FailureClass
from tools.kernel.orchestration import MAX_MODULE_FAILURES
from tools.swarm.base import Agent, AgentResult, AgentStatus
from tools.swarm.bb_compat import bb_extend, bb_remove, bb_set

# Structured failure taxonomy -> reflection prompt label. The reflection
# system prompt already names the nine root-cause categories (TOOL_MISMATCH,
# PROTOCOL_ERROR, ...); this maps a known ``FailureClass`` from a battle-log
# entry onto the prompt's vocabulary so the LLM reflection can name a
# structured class when one is already known instead of re-deriving it from
# error text. Unmapped classes fall through to None (the prompt's free-text
# categorization still applies). Augments — does NOT replace — the prompt
# taxonomy.
_FAILURE_CLASS_TO_REFLECTION_LABEL: dict[FailureClass, str] = {
    FailureClass.TARGET_UNREACHABLE: "NETWORK_ISSUE",
    FailureClass.TIMEOUT: "NETWORK_ISSUE",
    FailureClass.TRANSPORT_ERROR: "NETWORK_ISSUE",
    FailureClass.UNSUPPORTED_TARGET: "TOOL_MISMATCH",
    FailureClass.MALFORMED_CODE: "TOOL_MISMATCH",
    FailureClass.UNEXPECTED_OUTPUT: "TOOL_MISMATCH",
    FailureClass.PREREQUISITE_MISSING: "AUTH_REQUIRED",
    FailureClass.AUTH_FAILED: "AUTH_REQUIRED",
    FailureClass.TOOL_UNAVAILABLE: "TOOL_MISSING",
    FailureClass.SCOPE_BLOCKED: "FIREWALL_BLOCK",
    FailureClass.SCHEMA_ERROR: "PROTOCOL_ERROR",
    FailureClass.FALSE_POSITIVE: "PATCHED",
    FailureClass.INSUFFICIENT_EVIDENCE: "TOOL_MISMATCH",
}


def _coerce_fc(fc: Any) -> FailureClass | None:
    """Coerce a battle-log ``failure_class`` value (str | FailureClass) to a
    FailureClass, or None when it doesn't resolve to a known member."""
    if isinstance(fc, FailureClass):
        return fc
    try:
        return FailureClass(str(fc))
    except ValueError:
        return None


def _known_failure_classes(battle_log: list[dict[str, Any]]) -> list[str]:
    """Return 'tool: LABEL (FailureClass.X)' lines for failures that carry a
    structured ``failure_class`` the reflection prompt can name. Empty when no
    entry has one (legacy/unknown failures keep the free-text path)."""
    lines: list[str] = []
    for e in battle_log:
        if e.get("success"):
            continue
        fc = e.get("failure_class")
        if not fc:
            continue
        resolved = _coerce_fc(fc)
        if resolved is None:
            continue
        label = _FAILURE_CLASS_TO_REFLECTION_LABEL.get(resolved)
        if not label:
            continue
        lines.append(f"{e.get('tool', 'unknown')}: {label} (FailureClass.{resolved.value})")
    return lines


_REFLECTION_SYSTEM_PROMPT = """You are a STRATEGIC REFLECTION agent in an autonomous penetration testing swarm.

YOUR MISSION: Analyze the battle log after each phase and recommend strategy improvements.

ANALYSIS DIMENSIONS:
1. WHAT WORKED: Which tools/techniques succeeded? Why?
2. WHAT FAILED: Which failed? Root cause? (tool mismatch, protocol error, firewall, patched, wrong target)
3. PATTERNS: Are we repeating failures? Are we missing obvious attack vectors?
4. STRATEGY SHIFT: Should we pivot? Escalate aggression? Try a different service? Expand recon?

OUTPUT:
- what_worked: list of successful actions with rationale
- what_failed: list of failures with root cause analysis
- patterns_identified: recurring patterns (good and bad)
- new_hypothesis: revised hypothesis based on evidence
- recommended_strategy_shift: concrete next action
- confidence: 0.0-1.0 in the recommendation

DEEP REFLECTION METHODOLOGY:
1. SUCCESS ANALYSIS:
   - For each successful action, identify WHY it worked:
     - Correct tool for the service/protocol
     - Accurate version detection led to right CVE match
     - Default/weak credentials were present
     - Service was misconfigured (e.g., anonymous access enabled)
     - Payload was well-crafted for the target OS
   - Extract reusable patterns: "X tool works well against Y service on Z OS"
2. FAILURE ROOT CAUSE:
   - Categorize each failure:
     TOOL_MISMATCH: Wrong tool for the job (e.g., using SMB exploit on HTTP port)
     PROTOCOL_ERROR: Tool doesn't speak the right protocol version
     FIREWALL_BLOCK: Connection refused or filtered — target is protected
     PATCHED: Vulnerability exists but has been patched
     WRONG_VERSION: Exploit targets different version than what's running
     AUTH_REQUIRED: Service requires credentials we don't have
     NETWORK_ISSUE: Timeout, DNS failure, routing problem
     TOOL_MISSING: Required tool not installed in environment
     RATE_LIMITED: Target is throttling or blocking our requests
   - Count failures by category to identify systemic issues
3. PATTERN RECOGNITION:
   - Time-based: Are failures increasing over time? (target may be adapting/blocking)
   - Tool-based: Does one tool consistently fail? (may be incompatible or buggy)
   - Service-based: Are all failures on one service? (may be well-hardened)
   - Phase-based: Are we stuck in one phase too long? (need to advance or pivot)
   - Success clustering: Do successes cluster around certain techniques?
4. STRATEGY RECOMMENDATIONS:
   - ACCELERATE: >70% success rate → increase aggression, try more ambitious exploits
   - CONTINUE: 30-70% success rate → stay the course, minor adjustments
   - PIVOT_SERVICE: <30% success on current service → switch to next highest-priority service
   - EXPAND_RECON: <10% success overall → go back to reconnaissance, we're missing something
   - CREDENTIAL_ATTACK: Auth failures dominant → focus on credential harvesting/brute force
   - TOOL_INSTALL: Tool missing errors → run apt_install/pip_install to build arsenal
   - SLOW_DOWN: Rate limiting detected → add delays, reduce concurrency
5. CROSS-MISSION LEARNING:
   - Store successful patterns in semantic memory for future missions
   - Tag reflections with: target OS, services found, tools used, techniques applied
   - Build a knowledge base of "what works against what"

RULES:
- Be brutally honest — if we're wasting time, say so
- If all exploits failed, recommend going back to recon
- If one service is clearly vulnerable, recommend focusing all effort there
- Store reflections in semantic memory for future missions
- Provide specific, actionable recommendations, not vague advice
- Include confidence scores to help the orchestrator weigh your advice
- Consider the mission's time budget — don't recommend slow approaches near deadline
"""


class ReflectionAgent(Agent):
    """Agent that reflects on completed phases to improve future strategy.

    Deep reflection with pattern analysis, root cause identification,
    strategy shift recommendations, and semantic memory storage.
    """

    SYSTEM_PROMPT = _REFLECTION_SYSTEM_PROMPT

    def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        self._set_status(AgentStatus.RUNNING)
        start = time.monotonic()

        task_id = task.get("task_id", task.get("id", ""))
        battle_log = task.get("battle_log", [])
        session_state = task.get("session_state", {})
        memory = context.get("memory")
        # §13: prefer the role-routed summarizer client (models.roles.summarizer,
        # resolved by SwarmOrchestrator._ensure_role_clients) over the shared
        # default client. Unset -> shared client, unchanged behavior.
        model_client = context.get("summarizer_model_client") or context.get("model_client")
        blackboard = context.get("blackboard", {})
        # Tier 1.1: cross-mission learning handles. May be None (semantic memory
        # off); guarded below so a down Ollama degrades to a no-op, never raises.
        semantic_memory = context.get("semantic_memory")

        output: dict[str, Any] = {
            "what_worked": [],
            "what_failed": [],
            "patterns_identified": [],
            "why": "",
            "new_hypothesis": "",
            "recommended_strategy_shift": "",
            "confidence": 0.5,
        }
        error = ""
        memory_updates: list[dict[str, Any]] = []

        try:
            # ── Heuristic baseline ──
            successes = [e for e in battle_log if e.get("success")]
            failures = [e for e in battle_log if not e.get("success")]

            output["what_worked"] = [
                f"{e.get('tool', 'unknown')} on {e.get('target', '')}: {e.get('summary', '')[:100]}"
                for e in successes[:5]
            ]
            output["what_failed"] = [
                f"{e.get('tool', 'unknown')} on {e.get('target', '')}: {e.get('error', 'no error')[:100]}"
                for e in failures[:5]
            ]

            # ── Pattern detection ──
            patterns = []

            # Repeated tool failures
            failure_tools: dict[str, int] = {}
            for e in failures:
                tool = e.get("tool", "unknown")
                failure_tools[tool] = failure_tools.get(tool, 0) + 1
            for tool, count in failure_tools.items():
                if count >= MAX_MODULE_FAILURES:
                    patterns.append(f"Tool '{tool}' failed {count} times — likely incompatible or blocked.")

            # Connection refused pattern
            refused_count = sum(1 for e in failures if "refused" in str(e.get("error", "")).lower())
            if refused_count >= MAX_MODULE_FAILURES:
                patterns.append(
                    f"Connection refused {refused_count} times — target may have firewall or service is down."
                )

            # Timeout pattern
            timeout_count = sum(1 for e in failures if "timeout" in str(e.get("error", "")).lower())
            if timeout_count >= MAX_MODULE_FAILURES:
                patterns.append(f"Timeout on {timeout_count} attempts — target may be slow, firewalled, or blocking.")

            # Success pattern
            if successes:
                success_tools = {}
                for e in successes:
                    tool = e.get("tool", "unknown")
                    success_tools[tool] = success_tools.get(tool, 0) + 1
                best_tool = max(success_tools, key=success_tools.get)
                patterns.append(
                    f"Tool '{best_tool}' most successful ({success_tools[best_tool]} times) — prioritize this approach."
                )

            output["patterns_identified"] = patterns

            # ── Root cause analysis ──
            if failure_tools:
                most_failed = max(failure_tools, key=failure_tools.get)
                output["why"] = (
                    f"Primary failure: '{most_failed}' failed {failure_tools[most_failed]} times. "
                    f"Likely causes: tool not installed, protocol mismatch, firewall blocking, or service not vulnerable."
                )
            else:
                output["why"] = "No failures observed — strategy is working."

            # ── Hypothesis update ──
            partial = [e for e in battle_log if e.get("partial_success")]
            if partial:
                output["new_hypothesis"] = (
                    f"Partial success with {partial[0].get('tool')} suggests "
                    "target may be vulnerable with adjusted parameters."
                )
            elif successes:
                output["new_hypothesis"] = (
                    f"Confirmed {len(successes)} successful vectors; target likely vulnerable to similar techniques."
                )
            else:
                output["new_hypothesis"] = (
                    "No confirmed vectors yet; consider alternative service paths or expanded recon."
                )

            # ── Strategy shift ──
            if len(failures) > len(successes) * 3:
                output["recommended_strategy_shift"] = (
                    "MAJOR PIVOT: Current approach failing. Return to reconnaissance and re-evaluate attack surface."
                )
                output["confidence"] = 0.9
            elif len(failures) > len(successes) * 2:
                output["recommended_strategy_shift"] = (
                    "PIVOT: Try different service or attack vector. Current path has low success rate."
                )
                output["confidence"] = 0.7
            elif successes and not failures:
                output["recommended_strategy_shift"] = (
                    "ACCELERATE: High confidence in current vectors. Increase aggression and expand exploitation."
                )
                output["confidence"] = 0.9
            elif not successes and not failures:
                output["recommended_strategy_shift"] = "PROCEED: No data yet. Continue with planned approach."
                output["confidence"] = 0.5
            else:
                output["recommended_strategy_shift"] = (
                    "MIXED: Continue with caution. Validate each finding before escalation."
                )
                output["confidence"] = 0.6

            # ── LLM-driven deep reflection ──
            if model_client:
                llm_reflection = self._llm_reflect(
                    model_client,
                    battle_log,
                    session_state,
                    blackboard,
                    skill_selection=context.get("skill_selection"),
                )
                if llm_reflection:
                    for key in ("why", "new_hypothesis", "recommended_strategy_shift", "patterns_identified"):
                        if llm_reflection.get(key):
                            output[key] = llm_reflection[key]
                    if llm_reflection.get("confidence"):
                        output["confidence"] = llm_reflection["confidence"]

            # ── Update blackboard ──
            # Atomic writes via the Blackboard API (bb_compat bridges the
            # plain-dict test/legacy path). The ``failed_modules`` merge below
            # was a named list read-modify-write race in the route_parallel
            # warning (``bb[k] = list(set(bb.get(k,[]) + [...]))`` — get-then-set,
            # not atomic). ``bb_extend`` (dedupe=True) makes it atomic;
            # ``bb_remove`` makes the "clear succeeded modules" filter-then-set
            # atomic too.
            bb_set(blackboard, "last_reflection", output)
            bb_set(blackboard, "strategy_shift", output["recommended_strategy_shift"])
            if failures:
                # Dedupe-failures: the old code did list(set(bb + new)) which
                # lost ordering; bb_extend keeps insertion order while deduping.
                bb_extend(blackboard, "failed_modules", [e.get("tool", "unknown") for e in failures])
            # Clear modules that just succeeded. Without this the swarm path,
            # unlike the autonomous path's _record_success_on_blackboard, leaves
            # a recovered module in failed_modules forever -- so CriticAgent's
            # repeat-failure check (critic_agent.py:147-152) keeps flagging it
            # for require_mutation even after it later succeeds. Mirror the
            # autonomous semantics: remove from failed, note as successful.
            if successes:
                success_tools = {e.get("tool", "unknown") for e in successes}
                for tool in success_tools:
                    bb_remove(blackboard, "failed_modules", tool)
                bb_extend(blackboard, "successful_modules", list(success_tools))

            # ── Store in semantic memory ──
            memory_updates.append(
                {
                    "target": session_state.get("target_ip", ""),
                    "memory_type": "reflection",
                    "content": json.dumps(output),
                    "tags": ["reflection", "strategy", "learning"],
                }
            )

            # ── Tier 1.1: persist the reflection as a cross-mission lesson ──
            # The lessons-table write (real embedding) lets future engagements
            # recall this strategy shift via find_similar_lessons. Only the
            # semantic write — reflections are not exploit outcomes, so they do
            # NOT feed the Bayesian ExperienceStore (that would pollute exploit
            # action-confidence with non-exploit 'partial' rows). No-op when
            # semantic memory is off; store_lesson skips + logs when Ollama is
            # down. Reached via both Flow B (swarm.reflect) and Flow A
            # (autonomous_orchestrator) reflection paths.
            shift = output.get("recommended_strategy_shift", "")
            if semantic_memory is not None and shift:
                target = session_state.get("target_ip", "") or task.get("target", "") or "unknown"
                try:
                    semantic_memory.store_lesson(
                        target_signature=target,
                        action_type="reflection:strategy_shift",
                        outcome="partial",
                        text=f"{target} reflection -> {shift[:300]}",
                        confidence=float(output.get("confidence", 0.5)),
                        metadata={"task_id": task_id, "shift": shift[:500]},
                    )
                except Exception:
                    pass  # pragma: no cover — never break reflection on a lesson write

            # ── Tier 2.1: record per-skill phase-end outcomes for feedback ──
            # The reflection agent reviews the full active skill set, so it is
            # the natural place to judge whether the methodology that informed
            # this phase helped. A phase with at least as many successes as
            # failures records a success for each active skill; a
            # failure-dominated phase records a failure. Advisory and
            # boost-only downstream (the selector never excludes on this); no
            # store / no selection -> no-op. Never raises.
            skill_selection = context.get("skill_selection")
            if skill_selection:
                experience = context.get("experience")
                if experience is not None:
                    from tools.skill_feedback import record_skill_outcome

                    phase_success = len(successes) >= max(1, len(failures))
                    for skill in getattr(skill_selection, "skills", ()) or ():
                        try:
                            record_skill_outcome(
                                experience,
                                skill.name,
                                success=phase_success,
                                metadata={"task_id": task_id, "target": target},
                            )
                        except Exception:
                            pass  # pragma: no cover — never break reflection

            self._set_status(AgentStatus.COMPLETE)
        except _EXC_GROUP_CATCH as exc:
            error = str(exc)
            self._set_status(AgentStatus.FAILED)

        return AgentResult(
            agent_type=self.agent_type,
            status=self.status,
            task_id=task_id,
            output=output,
            error=error,
            execution_time=time.monotonic() - start,
            memory_updates=memory_updates,
        )

    def _llm_reflect(
        self,
        client: Any,
        battle_log: list[dict[str, Any]],
        session_state: dict[str, Any],
        blackboard: dict[str, Any],
        skill_selection: Any = None,
    ) -> dict[str, Any] | None:
        """Use LLM for deeper strategic reflection.

        Sends the rich ``_REFLECTION_SYSTEM_PROMPT`` as the system message so
        the specialist framing (root-cause categories, strategy thresholds,
        cross-mission learning) is live. Returns ``None`` on failure so the
        deterministic reflection is kept; the failure is logged.
        """
        try:
            log_summary = json.dumps(battle_log[-15:], indent=2)
            current_phase = session_state.get("current_phase", "unknown")
            remaining_budget = session_state.get("commands_remaining", "unknown")
            # Surface any structured failure classes already classified upstream
            # (ModuleResult.failure_class / decision log) so the LLM names the
            # known category instead of re-deriving it from error text. Empty
            # when no entry carries one — the prompt's free-text categorization
            # still applies.
            known_classes = _known_failure_classes(battle_log)
            known_block = (
                "KNOWN STRUCTURED FAILURE CLASSES (already classified — reuse these labels):\n"
                + "\n".join(f"- {line}" for line in known_classes)
                + "\n"
                if known_classes
                else ""
            )
            prompt = f"""You are a senior penetration testing strategist analyzing recent actions.

CURRENT PHASE: {current_phase}
REMAINING COMMAND BUDGET: {remaining_budget}

{known_block}BATTLE LOG (last 15 actions):
{log_summary}

CURRENT STATE:
- Target: {session_state.get("target_ip", "unknown")}
- Access achieved: {blackboard.get("access_achieved", False)}
- Attack surface score: {blackboard.get("attack_surface_score", "N/A")}
- Prior strategy shift: {blackboard.get("strategy_shift", "none")}

Analyze:
1. What patterns do you see in successes and failures?
2. What is the ROOT CAUSE of failures (not just symptoms)? Categorize: TOOL_MISMATCH, PROTOCOL_ERROR, FIREWALL_BLOCK, PATCHED, WRONG_VERSION, AUTH_REQUIRED, NETWORK_ISSUE, TOOL_MISSING, RATE_LIMITED.
3. What should we do DIFFERENTLY? (reference the strategy thresholds: ACCELERATE >70% success, CONTINUE 30-70%, PIVOT_SERVICE <30%, EXPAND_RECON <10%)
4. What is the single highest-impact next action? Keep the remaining budget in mind.

Return JSON only (no markdown fences):
{{
  "patterns_identified": ["pattern 1", "pattern 2"],
  "why": "root cause analysis",
  "new_hypothesis": "revised hypothesis",
  "recommended_strategy_shift": "concrete next action",
  "confidence": 0.0
}}
Notes:
- "confidence" MUST be a number between 0.0 and 1.0 (not the string "0.0-1.0").
- Keep the shift concrete and actionable; vague advice is not useful."""

            # Advisory skill hints (reflection reviews the full active set).
            from tools.skill_pipeline import append_phase_skill_hints

            prompt = append_phase_skill_hints(prompt, skill_selection, "reflection")

            resp = client.chat(
                messages=[
                    {"role": "system", "content": _REFLECTION_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                tools=None,
                stream=False,
            )
            message = resp.get("message", {}) if isinstance(resp, dict) else getattr(resp, "message", None)
            if isinstance(message, dict):
                text = message.get("content", "")
            else:
                text = getattr(message, "content", resp if isinstance(resp, str) else "")
            text = str(text or "").strip()
            if not text:
                return None
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except Exception as exc:
            # Log so a persistent LLM failure is debuggable instead of silently
            # degrading to heuristic-only reflection on every call.
            print(f"[ReflectionAgent] LLM reflection failed: {exc}")
            return None
