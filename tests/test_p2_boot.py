"""P2 regression: MCP boot contract — groups, soft_fail, cancellation.

Drives the REAL ``tools.mcp_session.open_exploit_mcp_session`` (stdio path)
with the subprocess/session layer mocked at the proven seam (function-local
``from mcp import ClientSession`` / ``from mcp.client.stdio import
stdio_client`` patched on the source modules — the same seam
``test_recon_first_session.py::TestMcpBootTimeout`` uses). No processes
spawned, no network, no sleeps.

Contract under test (``tools/mcp_session.py:409``):
- a ``BaseExceptionGroup`` from a dead stdio task group is caught via
  ``_EXC_GROUP_CATCH`` (a bare ``except Exception`` would MISS it — the group
  is not an ``Exception`` subclass);
- ``soft_fail=True`` degrades to a ``None`` session with ``[WARN]``;
- ``CancelledError`` is never swallowed, even with ``soft_fail=True``.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any

import pytest

import tools.mcp_session as ms
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group

_TARGET = "10.0.0.50"


class _OkSession:
    """Minimal live session: initialize succeeds instantly."""

    async def initialize(self) -> None:
        return None

    async def __aenter__(self) -> "_OkSession":
        return self

    async def __aexit__(self, *exc_info: Any) -> bool:
        return False


@contextlib.asynccontextmanager
async def _ok_stdio(_params: Any):
    yield ("read", "write")


def _patch_stdio(monkeypatch, *, stdio_factory=_ok_stdio, session_factory=None):
    import mcp
    import mcp.client.stdio as mcp_stdio

    monkeypatch.setattr(mcp_stdio, "stdio_client", stdio_factory)
    monkeypatch.setattr(mcp, "ClientSession", session_factory or (lambda _r, _w: _OkSession()))


def _drive(tmp_path, **kwargs):
    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="stdio",
            config_path=Path("config.yaml"),
            target_ip=_TARGET,
            exploit_port=8001,
            workspace=tmp_path,
            **kwargs,
        ) as session:
            return session

    return _run


# ── The catch contract itself ────────────────────────────────────────────────


def test_group_is_not_an_exception_but_is_in_exc_group_catch():
    """Pin the reason the helper exists: a task-group death group carrying a
    non-``Exception`` (cancellation / keyboard interrupt / subprocess kill)
    is a true ``BaseExceptionGroup`` — a bare ``except Exception`` MISSES it
    while ``_EXC_GROUP_CATCH`` gets it.

    (An all-``Exception`` group auto-narrows to ``ExceptionGroup``, an
    ``Exception`` subclass, so the probe must mix in a ``BaseException`` to
    exercise the real miss path.)"""
    group = BaseExceptionGroup("stdio task group died", [ConnectionError("epipe"), KeyboardInterrupt("intr")])
    assert not isinstance(group, Exception)
    assert _is_exception_group(group) is True

    caught = False
    try:
        raise group
    except _EXC_GROUP_CATCH:
        caught = True
    assert caught is True

    missed_by_bare_except = False
    try:
        raise group
    except Exception:
        missed_by_bare_except = True
    except BaseException:
        pass
    assert missed_by_bare_except is False


# ── Dead stdio_client task group ─────────────────────────────────────────────


def test_stdio_entry_group_soft_fail_yields_none(monkeypatch, capsys, tmp_path):
    """Group raised on ``stdio_client`` entry (subprocess death) with
    ``soft_fail=True`` degrades to ``None`` — caught, warned, never hung."""

    @contextlib.asynccontextmanager
    async def _dead_stdio(_params):
        raise BaseExceptionGroup("stdio task group died", [ConnectionError("epipe")])
        yield  # pragma: no cover - unreachable

    _patch_stdio(monkeypatch, stdio_factory=_dead_stdio)
    session = asyncio.run(_drive(tmp_path, soft_fail=True)())
    assert session is None
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "[WARN]" in combined
    assert "[ERROR]" not in combined


def test_stdio_entry_group_hard_fail_reraises(monkeypatch, tmp_path):
    """Without ``soft_fail`` the group propagates (bare ``raise``) — soft-fail
    is opt-in, never a silent swallow."""

    @contextlib.asynccontextmanager
    async def _dead_stdio(_params):
        raise BaseExceptionGroup("stdio task group died", [ConnectionError("epipe")])
        yield  # pragma: no cover - unreachable

    _patch_stdio(monkeypatch, stdio_factory=_dead_stdio)
    with pytest.raises(BaseExceptionGroup):
        asyncio.run(_drive(tmp_path, soft_fail=False)())


def test_initialize_group_soft_fail_yields_none(monkeypatch, capsys, tmp_path):
    """Group from ``session.initialize()`` (server dies mid-handshake) takes
    the same soft-fail path — it unwinds through the fake CMs into the outer
    ``except _EXC_GROUP_CATCH``."""

    class _DyingSession(_OkSession):
        async def initialize(self) -> None:
            raise BaseExceptionGroup("init died", [RuntimeError("server crash mid-handshake")])

    _patch_stdio(monkeypatch, session_factory=lambda _r, _w: _DyingSession())
    session = asyncio.run(_drive(tmp_path, soft_fail=True)())
    assert session is None
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "[WARN]" in combined
    assert "[ERROR]" not in combined


# ── Body failures: soft swallows, hard wraps ─────────────────────────────────


def test_body_group_soft_fail_exits_cleanly(monkeypatch, tmp_path):
    """A group escaping a mid-recon tool call with ``soft_fail=True`` is
    logged and swallowed so recon-first can degrade."""

    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="stdio",
            config_path=Path("config.yaml"),
            target_ip=_TARGET,
            exploit_port=8001,
            workspace=tmp_path,
            soft_fail=True,
        ):
            raise BaseExceptionGroup("stdio died mid-call", [ConnectionError("epipe")])

    _patch_stdio(monkeypatch)
    asyncio.run(_run())  # must not raise


def test_body_group_hard_fail_wraps(monkeypatch, tmp_path):
    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="stdio",
            config_path=Path("config.yaml"),
            target_ip=_TARGET,
            exploit_port=8001,
            workspace=tmp_path,
            soft_fail=False,
        ):
            raise BaseExceptionGroup("stdio died mid-call", [ConnectionError("epipe")])

    _patch_stdio(monkeypatch)
    with pytest.raises(RuntimeError, match="MCP session closed due to error"):
        asyncio.run(_run())


# ── Cancellation is never swallowed ──────────────────────────────────────────


async def test_soft_fail_never_swallows_cancellation(monkeypatch, tmp_path):
    """Cancelling a task suspended inside the session body must surface
    ``CancelledError`` even with ``soft_fail=True`` — ``_EXC_GROUP_CATCH``
    covers ``Exception`` + ``BaseExceptionGroup`` only, and ``CancelledError``
    derives from neither."""
    _patch_stdio(monkeypatch)
    entered = asyncio.Event()

    async def _run():
        async with ms.open_exploit_mcp_session(
            transport="stdio",
            config_path=Path("config.yaml"),
            target_ip=_TARGET,
            exploit_port=8001,
            workspace=tmp_path,
            soft_fail=True,
        ):
            entered.set()
            await asyncio.Event().wait()  # suspend until cancelled; no timers

    task = asyncio.create_task(_run())
    await asyncio.wait_for(entered.wait(), timeout=10.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
