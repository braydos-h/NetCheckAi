"""Attack planning MCP tools (split from god file)."""

from __future__ import annotations

from typing import Any

from tools.attack_planner import (
    AttackPlanner,
    build_planning_prompt,
    build_replanning_prompt,
    parse_plan_json,
    parse_replan_json,
)
from tools.mcp_tools.registry import ToolContext, _get_model_client, _platform_system
from tools.validation_utils import validate_target_or_ip


def register_planning_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def create_attack_plan(target_ip: str, target_os: str = "", known_cves: str = "") -> str:
        """Create a structured attack plan for a target IP.

        Uses the model router (if available) to generate intelligent attack phases and steps.
        The plan follows the standard kill chain: RECON → ENUMERATE → EXPLOIT → ESCALATE →
        LOOT → PIVOT → DONE. The plan is saved as JSON for later retrieval and adaptation.

        Args:
            target_ip: IPv4 address of the target host.
            target_os: Optional OS hint (e.g., 'linux', 'windows').
            known_cves: Optional comma-separated CVE IDs known to affect the target.

        Returns:
            Plan summary: plan ID, phases, number of steps, and current phase.

        Example:
            create_attack_plan("192.168.1.100", "linux", "CVE-2024-6387,CVE-2021-44228")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        try:
            cve_list = [c.strip() for c in known_cves.split(",") if c.strip()] if known_cves else []
            plans_dir = workspace / "plans"
            plans_dir.mkdir(parents=True, exist_ok=True)

            planner = AttackPlanner(workspace)
            plan = planner.create_plan(
                target_ip=target_ip,
                target_os=target_os if target_os else None,
                known_cves=cve_list,
                attack_mode=True,
            )

            # Try to use the model router to generate intelligent steps
            # (§13 planner role: routes to models.roles.planner when set).
            client, model_name = _get_model_client(config, role="planner")
            if client is not None:
                try:
                    prompt = build_planning_prompt(
                        phase=plan.current_phase,
                        target_ip=target_ip,
                        target_os=target_os if target_os else None,
                        known_cves=cve_list,
                        service_context=plan.service_context,
                        attacker_os=_platform_system(),
                    )
                    response = client.chat(
                        model_name,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    content = (
                        response.get("message", {}).get("content", "") if isinstance(response, dict) else str(response)
                    )
                    steps = parse_plan_json(content)
                    for step in steps:
                        plan.add_step(step)
                except Exception:  # ponytail: bare except intentional
                    pass  # Fall through to save plan without AI-generated steps

            planner.save_plan(plan)

            lines = [
                f"ATTACK_PLAN_CREATED: {target_ip}",
                f"PLAN_ID: {target_ip.replace('.', '_')}_plan.json",
                f"TARGET_OS: {target_os or 'Unknown'}",
                f"KNOWN_CVES: {', '.join(cve_list) if cve_list else 'None'}",
                f"PHASES: {' → '.join(p.value for p in plan.phases)}",
                f"CURRENT_PHASE: {plan.current_phase.value}",
                f"TOTAL_STEPS: {len(plan.steps)}",
                f"SAVED_TO: {plans_dir / (target_ip.replace('.', '_') + '_plan.json')}",
            ]
            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: Plan creation failed — {exc}"

    @mcp.tool()
    @require_allowlist()
    def get_current_plan(target_ip: str) -> str:
        """Retrieve the current attack plan for a target IP.

        Loads the saved plan JSON from the workspace and returns a summary including
        current phase, completed/failed steps, and the battle log.

        Args:
            target_ip: IPv4 address of the target host.

        Returns:
            Plan summary or 'NO_PLAN_FOUND' if no plan exists for this target.

        Example:
            get_current_plan("192.168.1.100")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        try:
            planner = AttackPlanner(workspace)
            plan = planner.load_plan(target_ip)
            if plan is None:
                return f"NO_PLAN_FOUND: No attack plan exists for {target_ip}. Use create_attack_plan first."

            lines = [
                f"ATTACK_PLAN: {target_ip}",
                f"CURRENT_PHASE: {plan.current_phase.value}",
                f"PHASES: {' → '.join(p.value for p in plan.phases)}",
                f"TOTAL_STEPS: {len(plan.steps)}",
                f"COMPLETED: {sum(1 for s in plan.steps if s.completed)}",
                f"SUCCESSFUL: {sum(1 for s in plan.steps if s.completed and s.success)}",
                f"FAILED: {sum(1 for s in plan.steps if s.completed and s.success is False)}",
                f"IS_COMPLETE: {plan.is_complete()}",
                "",
                plan.generate_battle_log(),
            ]
            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: Plan retrieval failed — {exc}"

    @mcp.tool()
    @require_allowlist()
    def replan(target_ip: str, failure_reason: str) -> str:
        """Adapt the current attack plan based on a failure or new information.

        Loads the existing plan, uses the replanning prompt to generate an updated
        strategy, and saves the adapted plan. This enables the AI to pivot when
        an attack vector fails.

        Args:
            target_ip: IPv4 address of the target host.
            failure_reason: Description of what failed and why (e.g., 'SSH brute force
                           blocked by rate limiting', 'target appears to be Windows not Linux').

        Returns:
            Updated plan summary with new phase/step information.

        Example:
            replan("192.168.1.100", "Log4j probe returned no response — service may be patched")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        try:
            planner = AttackPlanner(workspace)
            plan = planner.load_plan(target_ip)
            if plan is None:
                return f"NO_PLAN_FOUND: No attack plan exists for {target_ip}. Use create_attack_plan first."

            # §13 planner role (see create_attack_plan above).
            client, model_name = _get_model_client(config, role="planner")
            if client is not None:
                try:
                    prompt = build_replanning_prompt(
                        plan=plan,
                        last_result=failure_reason,
                        attacker_os=_platform_system(),
                    )
                    response = client.chat(
                        model_name,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    content = (
                        response.get("message", {}).get("content", "") if isinstance(response, dict) else str(response)
                    )
                    action, step, explanation = parse_replan_json(content)

                    if action == "next_phase":
                        plan.next_phase()
                    elif action == "done":
                        plan.current_phase_index = len(plan.phases) - 1
                    elif step is not None:
                        plan.add_step(step)
                except Exception:  # ponytail: bare except intentional
                    # Fallback: just advance to next phase
                    plan.next_phase()

            planner.save_plan(plan)

            lines = [
                f"REPLAN_RESULT: {target_ip}",
                f"FAILURE_REASON: {failure_reason[:200]}",
                f"NEW_PHASE: {plan.current_phase.value}",
                f"TOTAL_STEPS: {len(plan.steps)}",
                "",
                plan.generate_battle_log(),
            ]
            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: Replan failed — {exc}"

    # ───────────────────────────────────────────────────────────────────────
    # 3. Attack Modules & Pre-Packaged Exploits (tools.attack_modules)
    # ───────────────────────────────────────────────────────────────────────
