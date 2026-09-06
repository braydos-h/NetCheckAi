"""AI-facing assessment-state / capability-discovery MCP tools (design §8, §16).

Read-mostly tools that give the model ONE compact view of run state (hypotheses,
plan graph, recon, credentials, audit rollup) and let it discover which
capabilities (modules / tools / skills) fit the current target. Two tools also
WRITE LLM-controlled state (``record_hypothesis`` writes the assessment store,
``update_task`` mutates the attack plan); both re-validate the target against
the allowlist before writing -- the ``run_campaign_step`` precedent -- because
the store file path is derived from the target string.

Gates:
- target-touching readers/writers use ``@require_allowlist()`` (target-IP lock +
  audit trail); the writers add an explicit ``_check_allowlist`` re-validation
  inside the body (defense in depth, since the path is LLM-influenced).
- target-free discovery tools (``query_capabilities`` / ``get_capability_details``)
  use ``@audit_tool`` (no target, local read of the module/skill registry).
"""

from __future__ import annotations

import json
from typing import Any

from tools.attack_modules import get_module
from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.mcp_tools.registry import ToolContext, _positive_int, _skills_config, _truncate_text


# ponytail: sync introspection of FastMCP's tool registry. ``mcp.list_tools()``
# is async ( unusable from these sync tool handlers; ``_tool_manager._tools``
# is a plain dict name->Tool with ``.name``/``.description`` we can read
# without an event loop. Attribute path is stable across the pinned MCP SDK.
def _registered_tool_names(mcp: Any) -> list[str]:
    try:
        tools = getattr(getattr(mcp, "_tool_manager", None), "_tools", None)
    except _EXC_GROUP_CATCH as exc:  # noqa: BLE001 -- introspection is best-effort
        _log_nested_exceptions(exc)
        return []
    if not isinstance(tools, dict):
        return []
    return sorted(tools.keys())


def _check_allowlist_explicit(target_ip: str, config: dict[str, Any] | None) -> tuple[bool, str]:
    """Re-validate target against the allowlist from inside a tool body."""
    from tools.mcp_shared import _check_allowlist

    return _check_allowlist(target_ip, config)


def _format_state_block(snap: dict[str, Any]) -> str:
    """Render aggregate_state's dict as a compact ASSESSMENT_STATE: block."""
    lines = ["ASSESSMENT_STATE:"]
    lines.append(f"TARGET: {snap.get('target', '')}")
    lines.append(f"GOAL: {snap.get('goal', '') or '(unset)'}")
    lines.append(f"PHASE: {snap.get('phase', '') or '(unset)'}")

    plan = snap.get("plan")
    if plan:
        lines.append(
            f"PLAN: phase={plan.get('current_phase', '')} "
            f"steps={plan.get('total_steps', 0)} done={plan.get('completed', 0)} "
            f"ok={plan.get('successful', 0)} ready={plan.get('ready', [])} "
            f"blocked={plan.get('blocked', [])} failed={plan.get('failed', [])}"
        )
    else:
        lines.append("PLAN: (none)")

    recon = snap.get("recon")
    if recon:
        services = recon.get("services", [])
        svc_summary = ", ".join(f"{s.get('service', '')}:{s.get('port', '')}" for s in services[:15])
        lines.append(
            f"RECON: os={recon.get('os', '') or '?'} "
            f"services={recon.get('service_count', 0)} cves={len(recon.get('cves', []))}"
        )
        if svc_summary:
            lines.append(f"  SERVICES: {svc_summary}")
        if recon.get("cves"):
            lines.append(f"  CVES: {', '.join(recon['cves'][:15])}")
    else:
        lines.append("RECON: (none)")

    hyps = snap.get("hypotheses", [])
    lines.append(f"HYPOTHESES: {len([h for h in hyps if h.get('status') == 'open'])} open / {len(hyps)} total")
    for h in hyps[:20]:
        lines.append(
            f"  [{h.get('id', '')}] {h.get('status', '')} "
            f"({float(h.get('confidence', 0)):.2f}) {h.get('statement', '')[:80]}"
        )

    lines.append(f"CREDENTIALS_AVAILABLE: {snap.get('credentials_available', 0)}")

    activity = snap.get("activity", {}) or {}
    lines.append(f"ACTIVITY: tool_calls={activity.get('tool_calls', 0)} blocked={activity.get('blocked', 0)}")
    by_tool = activity.get("by_tool", {}) or {}
    if by_tool:
        top = sorted(by_tool.items(), key=lambda kv: kv[1], reverse=True)[:10]
        lines.append("  BY_TOOL: " + ", ".join(f"{k or '(unnamed)'}={v}" for k, v in top))
    recent = activity.get("recent", []) or []
    if recent:
        lines.append("  RECENT:")
        for ref in recent[-15:]:
            lines.append(f"    {ref}")
    return "\n".join(lines)


def register_assessment_state_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    # §16/§23: agent.* gates. Defaults preserve today's behavior — the tools
    # register when the agent block (or the keys) are absent, because
    # config_cli.load_config merges NO defaults, so read defensively.
    # state_tools_enabled gates the whole family; task_graph_enabled gates
    # only the plan-mutating update_task tool.
    _agent_cfg = (config or {}).get("agent") or {}
    # capability_discovery_enabled gates the two read-only discovery tools.
    _cap_discovery = bool(_agent_cfg.get("capability_discovery_enabled", True))
    if not bool(_agent_cfg.get("state_tools_enabled", True)):
        return

    @mcp.tool()
    @require_allowlist()
    def get_assessment_state(target_ip: str) -> str:
        """Return a compact snapshot of assessment state for one target: goal, phase, hypotheses, attack-plan DAG summary, newest recon result (services/CVEs), credential count, and an audit-trail rollup. Read-only; target must be in the allowlist. Raw tool output stays in workspace artifacts -- this carries counts, names, and stable references only."""
        from tools.assessment_state import aggregate_state

        try:
            snap = aggregate_state(target_ip, workspace, config)
        except _EXC_GROUP_CATCH as exc:  # noqa: BLE001 -- snapshot never raises
            _log_nested_exceptions(exc)
            return f"ERROR: aggregate_state failed: {exc}"
        return _format_state_block(snap)

    if _cap_discovery:

        @mcp.tool()
        @audit_tool
        def query_capabilities(scope: str = "modules", service: str = "") -> str:
            """Discover available capabilities without touching the target. scope=modules lists all registered attack modules via capability_record() (filter by service substring against module.target_services when service is set). scope=tools lists registered MCP tool names. scope=skills best-effort lists runtime skills from the skill registry. Advisory only -- never executes anything. Returns a CAPABILITIES: block."""
            scope_lc = (scope or "modules").strip().lower()
            if scope_lc == "modules":
                from tools.attack_modules import list_modules

                svc_filter = (service or "").strip().lower()
                lines = ["CAPABILITIES: scope=modules"]
                count = 0
                for mod in list_modules():
                    if svc_filter and svc_filter not in {s.lower() for s in mod.target_services}:
                        continue
                    rec = mod.capability_record()
                    req = ",".join(rec.get("requires", [])) or "-"
                    prod = ",".join(rec.get("produces", [])) or "-"
                    lines.append(
                        f"- {rec['name']} | phase={rec.get('phase_hint', '') or '?'} "
                        f"cost={rec.get('cost', '')} ro={rec.get('read_only', False)} "
                        f"requires={req} produces={prod}"
                    )
                    count += 1
                if svc_filter and count == 0:
                    lines.append(f"(no modules target service {service!r})")
                lines.append(f"TOTAL: {count}")
                return "\n".join(lines)
            if scope_lc == "tools":
                names = _registered_tool_names(mcp)
                lines = ["CAPABILITIES: scope=tools"]
                if names:
                    lines.append(f"COUNT: {len(names)}")
                    for n in names:
                        lines.append(f"- {n}")
                else:
                    lines.append(
                        "NOTE: tools scope lists registered MCP tool names; in-process registry not introspectable here."
                    )
                return "\n".join(lines)
            if scope_lc == "skills":
                lines = ["CAPABILITIES: scope=skills"]
                try:
                    from tools.skill_registry_cache import get_registry

                    registry = get_registry({"skills": _skills_config(config)})
                    skills = registry.list_skills()
                    lines.append(f"COUNT: {len(skills)}")
                    for skill in skills[:50]:
                        tags = ",".join(skill.metadata.tags[:6]) or "-"
                        desc = _truncate_text(skill.metadata.description, 120).replace("\n", " ")
                        lines.append(f"- {skill.name} | tags={tags} | {desc}")
                    if registry.errors:
                        lines.append(f"WARNINGS: {len(registry.errors)} skill file(s) failed to load.")
                except _EXC_GROUP_CATCH as exc:  # noqa: BLE001 -- skills listing is best-effort
                    _log_nested_exceptions(exc)
                    lines.append(f"NOTE: skill registry unavailable: {exc}")
                return "\n".join(lines)
            return f"BLOCKED: unknown scope {scope!r} (use modules|tools|skills)."

        @mcp.tool()
        @audit_tool
        def get_capability_details(name: str, scope: str = "modules") -> str:
            """Get the full capability record for one named module, tool, or skill, plus (for modules) an applicability explanation against a minimal empty-services context so the model can see why it would/wouldn't rank. Advisory only. Returns a CAPABILITY_DETAILS: block."""
            scope_lc = (scope or "modules").strip().lower()
            if scope_lc == "modules":
                mod = get_module(name)
                if mod is None:
                    return f"CAPABILITY_DETAILS: module not found: {name!r}"
                from tools.attack_modules import ModuleContext

                rec = mod.capability_record()
                ctx_min = ModuleContext(target_ip="")
                report = mod.applicability_explain(ctx_min)
                lines = ["CAPABILITY_DETAILS: scope=modules"]
                for k, v in rec.items():
                    lines.append(f"{k.upper()}: {v}")
                lines.append(f"APPLICABILITY_SCORE: {report.score}")
                if report.reasons:
                    lines.append("REASONS:")
                    for r in report.reasons:
                        lines.append(f"  - {r}")
                if report.penalties:
                    lines.append("PENALTIES:")
                    for p in report.penalties:
                        lines.append(f"  - {p}")
                return "\n".join(lines)
            if scope_lc == "skills":
                try:
                    from tools.skill_registry_cache import get_registry

                    registry = get_registry({"skills": _skills_config(config)})
                    skill = registry.get(name)
                except Exception as exc:  # noqa: BLE001 -- best-effort lookup  # ponytail: bare except intentional
                    return f"CAPABILITY_DETAILS: skill registry unavailable: {exc}"
                if skill is None:
                    return f"CAPABILITY_DETAILS: skill not found: {name!r}"
                m = skill.metadata
                lines = ["CAPABILITY_DETAILS: scope=skills"]
                lines.append(f"NAME: {skill.name}")
                lines.append(f"DESCRIPTION: {_truncate_text(m.description, 300)}")
                lines.append(f"DOMAIN: {m.domain} SUBDOMAIN: {m.subdomain}")
                lines.append(f"TAGS: {', '.join(m.tags)}")
                lines.append(f"VERSION: {m.version} MAYBE: {m.maybe}")
                if m.nist_csf:
                    lines.append(f"NIST_CSF: {', '.join(m.nist_csf)}")
                if m.mitre_attack:
                    lines.append(f"MITRE_ATTACK: {', '.join(m.mitre_attack)}")
                lines.append(f"PATH: {m.path}")
                return "\n".join(lines)
            if scope_lc == "tools":
                # ponytail: query_capabilities lists scope=tools, so details must
                # accept it too -- otherwise the agent hits BLOCKED and loops.
                try:
                    tools = getattr(getattr(mcp, "_tool_manager", None), "_tools", None)
                except _EXC_GROUP_CATCH as exc:  # noqa: BLE001 -- introspection is best-effort
                    _log_nested_exceptions(exc)
                    tools = None
                if isinstance(tools, dict) and name in tools:
                    tool = tools[name]
                    desc = str(getattr(tool, "description", "") or "").replace("\n", " ")
                    lines = ["CAPABILITY_DETAILS: scope=tools"]
                    lines.append(f"NAME: {name}")
                    lines.append(f"DESCRIPTION: {_truncate_text(desc, 500)}")
                    return "\n".join(lines)
                return (
                    f"CAPABILITY_DETAILS: tool not found: {name!r}. "
                    "Use query_capabilities(scope='tools') to list registered MCP tool names."
                )
            return f"BLOCKED: unknown scope {scope!r} (use modules|tools|skills)."

    @mcp.tool()
    @require_allowlist()
    def get_evidence(target_ip: str, limit: int = 25, tool: str = "") -> str:
        """Read recent exploit_audit.jsonl entries for one target and return compact evidence refs (exploit_audit:<target>:<attempt_id> with tool/status/duration only -- raw command/args are never emitted, they may contain secrets). target must be in the allowlist. Returns an EVIDENCE: block."""

        max_items = max(1, min(_positive_int(limit, 25), 200))
        tool_filter = (tool or "").strip().lower()
        audit = workspace / "exploit_audit.jsonl"
        lines = ["EVIDENCE:"]
        rows: list[str] = []
        if audit.exists():
            try:
                with audit.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if str(rec.get("target_ip", "")) != target_ip:
                            continue
                        if rec.get("status") == "started":
                            continue
                        tname = str(rec.get("tool_name", ""))
                        if tool_filter and tool_filter != tname.lower():
                            continue
                        attempt = rec.get("attempt_id", "")
                        status = rec.get("status", "")
                        duration = rec.get("duration_s")
                        if duration is None:
                            duration = rec.get("duration")
                        dur_str = f"{duration}" if duration is not None else "-"
                        rows.append(
                            f"exploit_audit:{target_ip}:{attempt} tool={tname} status={status} duration={dur_str}"
                        )
            except OSError as exc:
                return f"ERROR: could not read audit trail: {exc}"
        lines.append(f"COUNT: {len(rows)}")
        for row in rows[-max_items:]:
            lines.append(f"- {row}")
        if not rows:
            lines.append("(no audit entries for this target)")
        return "\n".join(lines)

    @mcp.tool()
    @require_allowlist()
    def record_hypothesis(
        target_ip: str,
        statement: str,
        confidence: float = 0.5,
        expected_evidence: str = "",
        created_from: str = "",
    ) -> str:
        """Record one tracked hypothesis about the target into the assessment state store (<workspace>/plans/<target>_assessment.json). target must be in the allowlist (re-validated before writing -- the path is LLM-influenced). Returns a HYPOTHESIS_RECORDED: block with the assigned id."""
        allowed, reason = _check_allowlist_explicit(target_ip, config)
        if not allowed:
            return f"BLOCKED: {reason}"
        if not statement or not statement.strip():
            return "BLOCKED: statement is required."
        from tools.assessment_state import AssessmentStateStore

        store = AssessmentStateStore(workspace)
        state = store.load(target_ip)
        ev = [e.strip() for e in (expected_evidence or "").splitlines() if e.strip()]
        hyp = state.add_hypothesis(
            statement,
            confidence=confidence,
            expected_evidence=ev,
            created_from=created_from,
        )
        store.save(state)
        return (
            f"HYPOTHESIS_RECORDED:\n"
            f"ID: {hyp.id}\n"
            f"TARGET: {target_ip}\n"
            f"CONFIDENCE: {hyp.confidence:.2f}\n"
            f"STATUS: {hyp.status}"
        )

    if not bool(_agent_cfg.get("task_graph_enabled", True)):
        return

    @mcp.tool()
    @require_allowlist()
    def update_task(
        target_ip: str,
        step_index: int,
        action: str = "complete",
        success: bool = True,
        summary: str = "",
        failure_class: str = "",
        reason: str = "",
    ) -> str:
        """Mutate one step of the attack plan for one target: complete/fail/cancel/reset. Loads <workspace>/plans/<ip>_plan.json via AttackPlanner, dispatches to mark_step_done/fail_step/cancel_step/reset_step, and saves. target must be in the allowlist (re-validated before writing). Returns a TASK_UPDATED: block, or NO_PLAN_FOUND when no plan exists for the target."""
        allowed, reason_msg = _check_allowlist_explicit(target_ip, config)
        if not allowed:
            return f"BLOCKED: {reason_msg}"
        from tools.attack_planner import AttackPlanner

        planner = AttackPlanner(workspace)
        plan = planner.load_plan(target_ip)
        if plan is None:
            return "NO_PLAN_FOUND"
        if not isinstance(step_index, int) or step_index < 0 or step_index >= len(plan.steps):
            return f"BLOCKED: step_index {step_index} out of range (0..{len(plan.steps) - 1})."
        act = (action or "complete").strip().lower()
        if act == "complete":
            plan.mark_step_done(step_index, bool(success), summary)
            result = f"step {step_index} -> done success={bool(success)}"
        elif act == "fail":
            plan.fail_step(step_index, failure_class=failure_class, reason=reason)
            result = f"step {step_index} -> failed class={failure_class or '(none)'}"
        elif act == "cancel":
            plan.cancel_step(step_index, reason=reason)
            result = f"step {step_index} -> cancelled"
        elif act == "reset":
            plan.reset_step(step_index)
            result = f"step {step_index} -> reset"
        else:
            return f"BLOCKED: unknown action {action!r} (use complete|fail|cancel|reset)."
        planner.save_plan(plan)
        return f"TASK_UPDATED:\nTARGET: {target_ip}\nSTEP: {step_index}\nACTION: {act}\n{result}"
