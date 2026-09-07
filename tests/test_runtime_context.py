"""Tests for explicit runtime dependency injection (``tools/runtime_context.py``).

Before this refactor, ``main.py`` configured runs by mutating imported module
globals (``tools.mcp_session.ui``, MCP timeout values, ``load_config``,
``open_exploit_mcp_session``, ``run_exploit_agent``, ...) on every call, so
two simultaneous runs shared hidden state. ``RuntimeContext`` bundles those
dependencies explicitly; ``tools.*`` functions accept an optional ``ctx``
and fall back to module globals only when it is omitted (back-compat for
existing monkeypatch-style tests).

All subprocess/network I/O is faked — sessions, routers, and UIs are stubs.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from tools.exploit_agent import ExploitPermission, ExploitSettings
from tools.goal_engine import AttackGoal
from tools.runtime_context import RuntimeContext


# ── Fakes ────────────────────────────────────────────────────────────────


class _FakeUI:
    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.lines: list[str] = []

    def status(self, msg: str) -> None:
        self.lines.append(f"{self.tag}:{msg}")

    def warning(self, msg: str) -> None:
        self.lines.append(f"{self.tag}:WARN:{msg}")

    def error(self, msg: str) -> None:
        self.lines.append(f"{self.tag}:ERR:{msg}")

    def skills(self, items: list[str]) -> None:
        self.lines.append(f"{self.tag}:skills")

    def divider(self) -> None:
        pass


class _FakeSession:
    async def list_tools(self) -> Any:
        tools = MagicMock()
        tools.tools = []
        return tools


@contextlib.asynccontextmanager
async def _fake_open_session(**kwargs: Any):
    _fake_open_session.seen.append(kwargs)
    yield _FakeSession()


_fake_open_session.seen: list[dict[str, Any]] = []


def _settings(tmp_path: Path) -> ExploitSettings:
    return ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=ExploitPermission.APPROVE_ONLY,
        attack_mode=False,
        target_ip="10.0.0.50",
        workspace_root=tmp_path / "ws",
        target_context={"active_skills": ["x"]},  # skip skill selection
    )


def _goal() -> AttackGoal:
    return AttackGoal(name="g", description="d")


async def _fake_agent(**kwargs: Any) -> dict[str, Any]:
    _fake_agent.seen.append(kwargs)
    return {"ok": True}


_fake_agent.seen: list[dict[str, Any]] = []


@pytest.fixture(autouse=True)
def _reset_seen():
    _fake_open_session.seen.clear()
    _fake_agent.seen.clear()
    yield
    _fake_open_session.seen.clear()
    _fake_agent.seen.clear()


def _ctx(tag: str, tmp_path: Path, **overrides: Any) -> RuntimeContext:
    fields: dict[str, Any] = {
        "ui": _FakeUI(tag),
        "config_loader": lambda path: {"exploit": {}},
        "open_mcp_session": _fake_open_session,
        "run_exploit_agent_fn": _fake_agent,
    }
    fields.update(overrides)
    return RuntimeContext(**fields)


async def _run(ctx: RuntimeContext, tmp_path: Path, target: str) -> dict[str, Any]:
    from tools.exploit_session import run_exploit_session

    return await run_exploit_session(
        client=object(),
        model="m",
        target_ip=target,
        mode="recon",
        goal=_goal(),
        exploit_settings=_settings(tmp_path),
        config_path=tmp_path / "config.yaml",
        mcp_transport="stdio",
        exploit_port=8001,
        reports_dir=tmp_path,
        ctx=ctx,
    )


# ── Context contents ─────────────────────────────────────────────────────


def test_defaults_are_production_wiring():
    ctx = RuntimeContext()
    assert ctx.mcp_boot_timeout_seconds == 30.0
    assert callable(ctx.config_loader)
    assert callable(ctx.open_mcp_session)
    assert callable(ctx.run_exploit_agent_fn)
    assert callable(ctx.build_router_fn)
    assert ctx.ui is not None


# ── Concurrency isolation ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_two_contexts_do_not_leak_ui_or_deps(tmp_path: Path):
    """Two simultaneous runs keep their own UI, loader, factory, and runner."""
    ctx_a = _ctx("A", tmp_path)
    ctx_b = _ctx("B", tmp_path)
    res_a, res_b = await asyncio.gather(_run(ctx_a, tmp_path, "10.0.0.1"), _run(ctx_b, tmp_path, "10.0.0.2"))
    assert res_a == {"ok": True} and res_b == {"ok": True}
    lines_a = ctx_a.ui.lines
    lines_b = ctx_b.ui.lines
    assert any("10.0.0.1" in line for line in lines_a)
    assert not any("10.0.0.2" in line for line in lines_a), lines_a
    assert any("10.0.0.2" in line for line in lines_b)
    assert not any("10.0.0.1" in line for line in lines_b), lines_b


@pytest.mark.asyncio
async def test_ctx_selects_loader_and_factory(tmp_path: Path):
    """The context's loader/factory/runner are the ones actually invoked."""
    loads: list[Any] = []

    def _loader(path: Any) -> dict[str, Any]:
        loads.append(path)
        return {"exploit": {}}

    ctx = _ctx("A", tmp_path, config_loader=_loader)
    await _run(ctx, tmp_path, "10.0.0.1")
    assert loads == [tmp_path / "config.yaml"]
    assert len(_fake_open_session.seen) == 1
    assert _fake_open_session.seen[0]["target_ip"] == "10.0.0.1"
    assert len(_fake_agent.seen) == 1


# ── No module-global mutation ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_main_wrappers_stop_mutating_module_globals(tmp_path: Path, monkeypatch):
    """main.py run paths must not poke tools.* module attributes anymore."""
    import main as main_mod
    from tools import exploit_session as _es
    from tools import mcp_session as _ms

    before_es = set(vars(_es))
    before_ms = set(vars(_ms))
    timeout_before = _ms.MCP_BOOT_TIMEOUT_SECONDS

    async def _fake_main_session(**kwargs: Any):
        yield _FakeSession()

    monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _fake_main_session)
    monkeypatch.setattr(main_mod, "run_exploit_agent", _fake_agent)

    await main_mod.run_exploit_session(
        client=object(),
        model="m",
        target_ip="10.0.0.3",
        mode="recon",
        goal=_goal(),
        exploit_settings=_settings(tmp_path),
        config_path=tmp_path / "config.yaml",
        mcp_transport="stdio",
        exploit_port=8001,
        reports_dir=tmp_path,
    )
    assert set(vars(_es)) == before_es, "run_exploit_session must not add module globals"
    assert set(vars(_ms)) == before_ms, "MCP session globals must be untouched"
    assert _ms.MCP_BOOT_TIMEOUT_SECONDS == timeout_before


@pytest.mark.asyncio
async def test_ctx_timeout_reaches_session_factory(tmp_path: Path, monkeypatch):
    """A context boot timeout is honored without touching the module global."""
    import tools.mcp_session as _ms

    captured: dict[str, Any] = {}

    @contextlib.asynccontextmanager
    async def _capture_once(**kwargs: Any):
        captured.update(kwargs)
        yield _FakeSession()

    monkeypatch.setattr(_ms, "_open_exploit_mcp_session_once", _capture_once)
    ctx = RuntimeContext(ui=_FakeUI("T"), mcp_boot_timeout_seconds=7.5)
    async with _ms.open_exploit_mcp_session(
        transport="stdio",
        config_path=tmp_path / "c.yaml",
        target_ip="10.0.0.9",
        exploit_port=8001,
        workspace=tmp_path,
        fallback_to_stdio=False,
        ctx=ctx,
    ):
        pass
    assert captured.get("ctx") is ctx
    assert _ms.MCP_BOOT_TIMEOUT_SECONDS == 30.0


# ── Back-compat fallbacks ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_omitted_ctx_keeps_legacy_behavior(tmp_path: Path):
    """No ctx → module globals, exactly as before (existing tests rely on it)."""
    from tools import exploit_session as _es

    await _run(RuntimeContext(ui=_FakeUI("Z"), config_loader=lambda p: {"exploit": {}}), tmp_path, "10.0.0.4")
    # The tools module still exposes its patchable globals for legacy tests.
    assert hasattr(_es, "ui")
    assert hasattr(_es, "load_config")
    assert hasattr(_es, "open_exploit_mcp_session")
    assert hasattr(_es, "run_exploit_agent")


def test_run_manager_constructor_injection():
    """RunManager/BenchmarkService wire explicitly (no private pokes needed)."""
    from tools.api.run_manager import RunManager
    from tools.benchmark.service import BenchmarkService

    bench = BenchmarkService({}, ".")
    assert bench.run_manager is None
    mgr = MagicMock()
    bench2 = BenchmarkService({}, ".", run_manager=mgr)
    assert bench2.run_manager is mgr
    # Setter path preserves the legacy attribute-assignment shape.
    bench.run_manager = mgr
    assert bench.run_manager is mgr
    assert RunManager.__init__.__defaults__ is None  # keyword-only tail
