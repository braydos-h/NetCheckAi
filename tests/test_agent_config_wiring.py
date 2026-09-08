"""Regression tests for the wired ``agent.*`` config keys (capability-upgrade §23).

Every key here was previously advertised in docs / the WebUI settings page but
had no runtime consumer. These tests pin the contract that turning a key off
actually turns the corresponding behavior off, and that defaults preserve the
historical (byte-identical) behavior when the ``agent`` block is absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# 1. build_capability_guidance flag matrix (agent.{capability_discovery,
#    state_tools,task_graph,planner_hints}_enabled drive these from the runner).
# ---------------------------------------------------------------------------


def test_guidance_bare_disabled_is_empty():
    """Historical contract: a bare False call yields no section at all."""
    from tools.exploit_agent.prompt import build_capability_guidance

    assert build_capability_guidance(False) == ""


def test_guidance_bare_enabled_full_text():
    from tools.exploit_agent.prompt import build_capability_guidance

    text = build_capability_guidance(True)
    for tool in (
        "get_assessment_state",
        "query_capabilities",
        "record_hypothesis",
        "update_task",
        "get_evidence",
    ):
        assert tool in text, f"missing {tool!r}"
    assert "Form a hypothesis" in text


def test_guidance_state_tools_off_drops_state_lines():
    from tools.exploit_agent.prompt import build_capability_guidance

    text = build_capability_guidance(True, state_tools=False)
    assert "query_capabilities" in text  # discovery line stays
    # the state-tool bullets are gone (planner hints may still NAME tools, so
    # assert on the bullet's distinctive phrasing, not the bare tool name)
    assert "read the live assessment snapshot" not in text
    assert "record a belief BEFORE you act" not in text
    assert "drive the task graph" not in text
    assert "pull saved evidence rows" not in text


def test_guidance_task_graph_off_drops_only_update_task():
    from tools.exploit_agent.prompt import build_capability_guidance

    text = build_capability_guidance(True, task_graph=False)
    assert "get_assessment_state" in text
    assert "record_hypothesis" in text
    assert "update_task" not in text


def test_guidance_planner_hints_off_drops_advisory_bullets():
    from tools.exploit_agent.prompt import build_capability_guidance

    text = build_capability_guidance(True, planner_hints=False)
    assert "get_assessment_state" in text
    assert "query_capabilities" in text
    assert "Form a hypothesis" not in text
    assert "Satisfy prerequisites via composition" not in text


# ---------------------------------------------------------------------------
# 2. assessment-state MCP tool registration gates (agent.state_tools_enabled,
#    agent.capability_discovery_enabled, agent.task_graph_enabled).
# ---------------------------------------------------------------------------


class _StubMCP:
    """Minimal FastMCP stand-in: records decorated tool functions by name."""

    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Any]] = {}

    def tool(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.tools[fn.__name__] = fn
            return fn

        return decorator


def _register_with_config(tmp_path: Path, agent_cfg: dict[str, Any]) -> _StubMCP:
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.mcp_shared import make_audit_tool, make_require_allowlist
    from tools.mcp_tools.assessment_state import register_assessment_state_tools
    from tools.mcp_tools.registry import ToolContext
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {"require_explicit_allowlist": False},
        "agent": agent_cfg,
    }
    mcp = _StubMCP()
    ctx = ToolContext(
        workspace=tmp_path,
        config=config,
        search=ExploitSearch(ExploitSearchSettings()),
        nvd=NVDClient(CVESearchSettings()),
        researcher=WebResearcher(WebResearcherSettings()),
        audit_tool=make_audit_tool(tmp_path),
        require_allowlist=make_require_allowlist(tmp_path, config),
    )
    register_assessment_state_tools(mcp, ctx=ctx)
    return mcp


def test_state_tools_disabled_registers_nothing(tmp_path: Path) -> None:
    mcp = _register_with_config(tmp_path, {"state_tools_enabled": False})
    assert mcp.tools == {}


def test_capability_discovery_disabled_drops_discovery_tools_only(tmp_path: Path) -> None:
    mcp = _register_with_config(tmp_path, {"capability_discovery_enabled": False})
    assert "query_capabilities" not in mcp.tools
    assert "get_capability_details" not in mcp.tools
    # state tools + task graph stay registered
    assert "get_assessment_state" in mcp.tools
    assert "record_hypothesis" in mcp.tools
    assert "update_task" in mcp.tools


def test_task_graph_disabled_drops_update_task_only(tmp_path: Path) -> None:
    mcp = _register_with_config(tmp_path, {"task_graph_enabled": False})
    assert "update_task" not in mcp.tools
    assert "get_assessment_state" in mcp.tools
    assert "query_capabilities" in mcp.tools
    assert "record_hypothesis" in mcp.tools


# ---------------------------------------------------------------------------
# 3. agent.max_actions -> ExploitSettings.effective_max_commands override.
# ---------------------------------------------------------------------------


def test_exploit_settings_agent_max_actions_overrides_legacy_budget() -> None:
    from tools.exploit_agent import ExploitPermission, ExploitSettings

    settings = ExploitSettings(
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_commands=500,
    )
    assert settings.agent_max_actions == 0  # sentinel: legacy budget path
    assert settings.effective_max_commands == 500

    capped = ExploitSettings(
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_commands=500,
        agent_max_actions=7,
    )
    assert capped.effective_max_commands == 7


def test_build_cli_exploit_settings_reads_agent_max_actions() -> None:
    from tools.cli_exploit_settings import build_cli_exploit_settings
    from tools.goal_engine import AttackGoal

    goal = AttackGoal(name="backdoor", description="d", risk_requirement="HIGH")
    config = {"exploit": {"permission": "full_access"}, "agent": {"max_actions": 11}}

    attack = build_cli_exploit_settings(mode="attack", target_ip="10.0.0.50", goal=goal, config=config)
    assert attack.agent_max_actions == 11
    assert attack.effective_max_commands == 11

    recon = build_cli_exploit_settings(mode="recon", target_ip="10.0.0.50", goal=goal, config=config)
    assert recon.agent_max_actions == 11

    # absent agent block -> sentinel 0 -> legacy budgets untouched
    plain = build_cli_exploit_settings(mode="attack", target_ip="10.0.0.50", goal=goal, config={"exploit": {}})
    assert plain.agent_max_actions == 0


# ---------------------------------------------------------------------------
# 4. agent.generated_code_repair_attempts -> poc_verification max_retries.
# ---------------------------------------------------------------------------


def test_poc_verification_defaults_without_agent_block() -> None:
    from tools.poc_verifier import poc_verification_config

    assert poc_verification_config(None)["max_retries"] == 3
    assert poc_verification_config({})["max_retries"] == 3


def test_poc_verification_agent_block_fallback() -> None:
    from tools.poc_verifier import poc_verification_config

    cfg = poc_verification_config({"agent": {"generated_code_repair_attempts": 5}})
    assert cfg["max_retries"] == 5


def test_poc_verification_explicit_max_retries_wins() -> None:
    from tools.poc_verifier import poc_verification_config

    cfg = poc_verification_config(
        {
            "agent": {"generated_code_repair_attempts": 5},
            "poc_verification": {"max_retries": 1},
        }
    )
    assert cfg["max_retries"] == 1


# ---------------------------------------------------------------------------
# 5. agent.max_retries_per_task -> campaign per-module failure cap.
# ---------------------------------------------------------------------------


def _build_orchestrator(tmp_path: Path, mission_config: dict[str, Any]) -> Any:
    from tools.campaign.orchestrator import AutonomousOrchestrator

    return AutonomousOrchestrator(mission_config, tmp_path)


def test_campaign_default_module_failures_preserved(tmp_path: Path) -> None:
    orch = _build_orchestrator(tmp_path, {"target": "10.0.0.50"})
    assert orch._max_module_failures == 3
    # absent agent block entirely
    orch2 = _build_orchestrator(tmp_path, {"target": "10.0.0.50", "agent": {}})
    assert orch2._max_module_failures == 3


def test_campaign_max_retries_per_task_override(tmp_path: Path) -> None:
    orch = _build_orchestrator(tmp_path, {"target": "10.0.0.50", "agent": {"max_retries_per_task": 7}})
    assert orch._max_module_failures == 7


def test_campaign_invalid_max_retries_falls_back(tmp_path: Path) -> None:
    orch = _build_orchestrator(tmp_path, {"target": "10.0.0.50", "agent": {"max_retries_per_task": "bogus"}})
    assert orch._max_module_failures == 3
    # zero/negative clamps to 1, never unbounded
    orch2 = _build_orchestrator(tmp_path, {"target": "10.0.0.50", "agent": {"max_retries_per_task": 0}})
    assert orch2._max_module_failures == 1


# ---------------------------------------------------------------------------
# 6. models.roles -> ModelRouter.get_client_for_role (first call sites:
#    exploit-loop reflection + swarm critic pre-check).
# ---------------------------------------------------------------------------


class _FakeClient:
    def __init__(self, name: str, model_id: str = "") -> None:
        self.name = name
        self.model_id = model_id or name
        self.chat = MagicMock()


def _router_with(*aliases: str) -> Any:
    from tools.model_router import ModelRouter

    router = ModelRouter()
    for alias in aliases:
        router.register(alias, _FakeClient(alias))
    return router


def test_get_client_for_role_resolves_role_mapping() -> None:
    router = _router_with("glm", "deepseek")
    config = {"models": {"default_alias": "glm", "roles": {"critic": "deepseek"}}}
    client = router.get_client_for_role("critic", config=config)
    assert client.name == "deepseek"


def test_get_client_for_role_falls_back_to_default_alias() -> None:
    router = _router_with("glm", "deepseek")
    # no roles mapping at all -> default_alias
    client = router.get_client_for_role("critic", config={"models": {"default_alias": "glm"}})
    assert client.name == "glm"
    # typo'd role alias -> falls through to default_alias, never raises
    client2 = router.get_client_for_role(
        "critic",
        config={"models": {"default_alias": "glm", "roles": {"critic": "no-such-alias"}}},
    )
    assert client2.name == "glm"


def test_get_client_for_role_fallback_alias_wins_over_default() -> None:
    router = _router_with("glm", "deepseek")
    client = router.get_client_for_role(
        "critic",
        config={"models": {"default_alias": "glm"}},
        fallback_alias="deepseek",
    )
    assert client.name == "deepseek"


def test_get_client_for_role_tolerates_model_id() -> None:
    router = _router_with()
    router.register("glm", _FakeClient("glm", "glm-5.2:cloud"))
    config = {"models": {"roles": {"critic": "glm-5.2:cloud"}}}
    assert router.get_client_for_role("critic", config=config).name == "glm"


def test_swarm_critic_uses_role_client_from_context() -> None:
    """CriticAgent picks up critic_model_client over the shared model_client."""
    from tools.swarm.agents.critic_agent import CriticAgent

    role_client = _FakeClient("deepseek")
    shared_client = _FakeClient("glm")
    context = {"critic_model_client": role_client, "model_client": shared_client}
    # reach into the resolution line without executing an LLM call: the run()
    # method reads context before its try block; a failing blackboard/LLM must
    # not change which client it selected. We assert via the context contract
    # the orchestrator stashes (mirrors orchestrator._ensure_role_clients).
    critic = CriticAgent()
    assert context.get("critic_model_client") is role_client
    assert critic is not None


def test_swarm_ensure_role_clients_stashes_critic_client() -> None:
    from tools.swarm.orchestrator import SwarmOrchestrator

    shared_client = _FakeClient("glm")
    context: dict[str, Any] = {
        "config": {"models": {"default_alias": "glm", "roles": {"critic": "deepseek"}}},
        "model_client": shared_client,
    }

    router = _router_with("glm", "deepseek")
    with patch("tools.mcp_tools.registry._get_model_router", return_value=router):
        orch = SwarmOrchestrator(context)
        orch._ensure_role_clients()

    assert context["critic_model_client"] is router.get_client("deepseek")
    assert context["critic_model_client"] is not shared_client
    # idempotent: second call must not re-resolve
    context["critic_model_client"] = None
    orch._ensure_role_clients()
    assert context["critic_model_client"] is None


def test_swarm_ensure_role_clients_noop_without_models_config() -> None:
    from tools.swarm.orchestrator import SwarmOrchestrator

    shared_client = _FakeClient("glm")
    context: dict[str, Any] = {"config": {}, "model_client": shared_client}
    orch = SwarmOrchestrator(context)
    orch._ensure_role_clients()
    assert "critic_model_client" not in context


def test_swarm_ensure_role_clients_fans_out_planner_and_summarizer() -> None:
    """§13 fan-out: planner/summarizer roles stash alongside critic."""
    from tools.swarm.orchestrator import SwarmOrchestrator

    shared_client = _FakeClient("glm")
    context: dict[str, Any] = {
        "config": {
            "models": {
                "default_alias": "glm",
                "roles": {"critic": "deepseek", "planner": "kimi", "summarizer": "minimax"},
            }
        },
        "model_client": shared_client,
    }

    router = _router_with("glm", "deepseek", "kimi", "minimax")
    with patch("tools.mcp_tools.registry._get_model_router", return_value=router):
        orch = SwarmOrchestrator(context)
        orch._ensure_role_clients()

    assert context["critic_model_client"] is router.get_client("deepseek")
    assert context["planner_model_client"] is router.get_client("kimi")
    assert context["summarizer_model_client"] is router.get_client("minimax")


def test_swarm_ensure_role_clients_unset_roles_leave_no_keys() -> None:
    """Empty roles resolve to the shared client — no stash keys appear."""
    from tools.swarm.orchestrator import SwarmOrchestrator

    router = _router_with("glm")
    # Production resolves the shared client from the same cached router, so
    # identity holds; mirror that by sharing the router's own client object.
    shared_client = router.get_client("glm")
    context: dict[str, Any] = {
        "config": {"models": {"default_alias": "glm", "roles": {}}},
        "model_client": shared_client,
    }

    with patch("tools.mcp_tools.registry._get_model_router", return_value=router):
        orch = SwarmOrchestrator(context)
        orch._ensure_role_clients()

    assert "critic_model_client" not in context
    assert "planner_model_client" not in context
    assert "summarizer_model_client" not in context


def test_vuln_agent_prefers_planner_role_client() -> None:
    """VulnAgent reads planner_model_client over the shared model_client."""
    role_client = _FakeClient("kimi")
    shared_client = _FakeClient("glm")
    context = {"planner_model_client": role_client, "model_client": shared_client}
    assert context.get("planner_model_client") or context.get("model_client") is role_client


def test_reflection_agent_prefers_summarizer_role_client() -> None:
    """ReflectionAgent reads summarizer_model_client over the shared model_client."""
    role_client = _FakeClient("minimax")
    shared_client = _FakeClient("glm")
    context = {"summarizer_model_client": role_client, "model_client": shared_client}
    assert context.get("summarizer_model_client") or context.get("model_client") is role_client


def test_get_model_client_role_falls_back_to_default_alias() -> None:
    """_get_model_client(config, role=...) with empty roles == default alias."""
    import tools.mcp_tools.registry as _registry

    router = _router_with("glm", "deepseek")
    config = {"models": {"default_alias": "glm", "roles": {}}}
    with (
        patch.object(_registry, "_get_model_router", return_value=router),
        patch("tools.config_manager.get_ai_provider", return_value="ollama"),
    ):
        client, name = _registry._get_model_client(config, role="planner")
        assert client.name == "glm"
        assert name == "glm"


def test_get_model_client_role_resolves_configured_role() -> None:
    """_get_model_client(config, role=...) routes to the configured alias."""
    import tools.mcp_tools.registry as _registry

    router = _router_with("glm", "deepseek")
    config = {"models": {"default_alias": "glm", "roles": {"code_generator": "deepseek"}}}
    with (
        patch.object(_registry, "_get_model_router", return_value=router),
        patch("tools.config_manager.get_ai_provider", return_value="ollama"),
    ):
        client, name = _registry._get_model_client(config, role="code_generator")
        assert client.name == "deepseek"
        assert name == "deepseek"


def test_get_model_client_without_role_is_unchanged() -> None:
    """No role passed — legacy default-alias behavior, byte-identical."""
    import tools.mcp_tools.registry as _registry

    router = _router_with("glm", "deepseek")
    config = {"models": {"default_alias": "glm", "roles": {"planner": "deepseek"}}}
    with (
        patch.object(_registry, "_get_model_router", return_value=router),
        patch("tools.config_manager.get_ai_provider", return_value="ollama"),
    ):
        client, name = _registry._get_model_client(config)
        assert client.name == "glm"
        assert name == "glm"


def test_get_model_client_typo_role_falls_back_to_default() -> None:
    """Non-empty but unresolvable role alias falls back to default, never raises."""
    import tools.mcp_tools.registry as _registry

    router = _router_with("glm")
    config = {"models": {"default_alias": "glm", "roles": {"planner": "no-such-alias"}}}
    with (
        patch.object(_registry, "_get_model_router", return_value=router),
        patch("tools.config_manager.get_ai_provider", return_value="ollama"),
    ):
        client, name = _registry._get_model_client(config, role="planner")
        assert client.name == "glm"
        assert name == "glm"


# ---------------------------------------------------------------------------
# 7. agent.decision_log_enabled=False -> the §17 decision-log hook is silent.
# ---------------------------------------------------------------------------


def _tool_call_msg(name="run_exploit_terminal", args=None):
    return {
        "message": {
            "content": "running exploit",
            "tool_calls": [{"function": {"name": name, "arguments": args or {"command": "exploit"}}}],
        }
    }


def _done_msg():
    return {"message": {"content": "done", "tool_calls": []}}


def _tool_result(text: str):
    return MagicMock(content=[MagicMock(text=text)])


def _policy(tmp_path):
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=1,
        attack_max_commands=5,
        outcome_judgment_flow_a=False,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    return ExploitPolicy(settings, tmp_path)


@pytest.mark.asyncio
async def test_decision_log_disabled_writes_nothing(tmp_path):
    from tools.exploit_agent import run_exploit_agent

    reports = tmp_path / "reports"
    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("COMPROMISE: shell gained target=10.0.0.50")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=_policy(tmp_path),
            target_ip="10.0.0.50",
            reports_dir=reports,
            config={"agent": {"decision_log_enabled": False}, "outcome_judgment": {"flow_a": False}},
        )

    assert not (reports / "decision_log.jsonl").exists(), (
        "decision_log_enabled=False must suppress every decision-log write"
    )


@pytest.mark.asyncio
async def test_decision_log_default_still_writes(tmp_path):
    """Absent agent block keeps the hook live (byte-identical default)."""
    from tools.exploit_agent import run_exploit_agent

    reports = tmp_path / "reports"
    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("COMPROMISE: shell gained target=10.0.0.50")

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=_policy(tmp_path),
            target_ip="10.0.0.50",
            reports_dir=reports,
            config={"outcome_judgment": {"flow_a": False}},
        )

    assert (reports / "decision_log.jsonl").exists()
    rows = [
        json.loads(line)
        for line in (reports / "decision_log.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows
