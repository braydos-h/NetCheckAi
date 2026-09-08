"""Shared fixtures — ponytail: replace copy-paste Mock(spec=...) across 249 tests.

These three fixtures cover the most duplicated mocks (grep "Mock(spec=" shows
>80 sites for MCP session / Ollama client / Nmap). New tests should use them
instead of hand-rolling Mocks. Existing tests are migrated incrementally — the
fixtures are opt-in, never breaking.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from tools.api.event_broker import _reset_plugin_dispatcher


def pytest_xdist_auto_num_workers(config):  # type: ignore[no-untyped-def]
    """Cap ``-n auto`` workers to the CI value (``-n 2``).

    CI's blessed invocation is ``-n 2 -m "not integration and not live_llm"``;
    bare local runs must not exceed it. Override via
    PYTEST_XDIST_AUTO_NUM_WORKERS.
    """
    env = os.environ.get("PYTEST_XDIST_AUTO_NUM_WORKERS")
    if env:
        try:
            return int(env)
        except ValueError:
            pass
    return 2


@pytest.fixture(autouse=True)
def _reset_event_broker_dispatcher():
    """Ensure the global plugin dispatcher never leaks across tests/loops.

    The dispatcher holds an asyncio.Queue bound to the loop that created it.
    Without a per-test reset, a test that emits events leaves a queue/worker
    set bound to its loop; the next test's loop then hits
    'Queue bound to a different event loop' and the worker enters an infinite
    crash-log loop (see _worker_loop). Resetting synchronously before and
    after each test guarantees fresh state regardless of asyncio_mode=auto.
    """
    _reset_plugin_dispatcher()
    yield
    _reset_plugin_dispatcher()


# Track and close TestClient portals leaked by tests that forget ``client.close()``.
# Each TestClient spawns an anyio portal thread (``anyio.from_thread``) that
# survives until ``close()``. With ~2500+ tests that create a client, leaking
# 1 portal per test exhausts threads and causes the 40 s timeout hang at ~70 %.
import threading as _threading
import weakref as _weakref

_tracked_clients: _weakref.WeakSet = _weakref.WeakSet()  # type: ignore[var-annotated]


@pytest.fixture(autouse=True)
def _close_leaked_test_clients(monkeypatch):
    """Auto-close any TestClient created during the test (even if test forgets)."""
    try:
        from fastapi.testclient import TestClient as _FastAPIClient
        from starlette.testclient import TestClient as _StarletteClient
    except Exception:  # pragma: no cover - import should succeed
        yield
        return

    orig_fastapi_init = _FastAPIClient.__init__  # type: ignore[attr-defined]
    orig_starlette_init = _StarletteClient.__init__  # type: ignore[attr-defined]

    def _fastapi_tracked_init(self, *a, **kw):  # type: ignore[no-untyped-def]
        orig_fastapi_init(self, *a, **kw)
        _tracked_clients.add(self)

    def _starlette_tracked_init(self, *a, **kw):  # type: ignore[no-untyped-def]
        orig_starlette_init(self, *a, **kw)
        _tracked_clients.add(self)

    monkeypatch.setattr(_FastAPIClient, "__init__", _fastapi_tracked_init)
    monkeypatch.setattr(_StarletteClient, "__init__", _starlette_tracked_init)
    yield
    for c in list(_tracked_clients):
        try:
            c.close()  # type: ignore[attr-defined]
        except Exception:
            pass
    _tracked_clients.clear()


@pytest.fixture(autouse=True)
def _patch_anyio_portal_join_timeout(monkeypatch):
    """Prevent TestClient per-request portals from hanging on background tasks.

    ``RunManager.create_run`` spawns a ``prep_task`` on the request's portal
    loop; that task outlives the request. ``anyio.from_thread.start_blocking_portal``
    does ``thread.join()`` without timeout, so the portal hangs until the
    prep_task finishes. Patch ``Thread.join`` to use a bounded 2 s timeout
    when no explicit timeout is given – this is safe for tests and prevents
    the 40 s per-test hang at ~76 %.
    """
    orig_join = _threading.Thread.join

    def _patched_join(self, timeout=None):  # type: ignore[no-untyped-def]
        if timeout is None:
            timeout = 2.0
        return orig_join(self, timeout=timeout)

    monkeypatch.setattr(_threading.Thread, "join", _patched_join)
    yield


# Track RunManager instances so their background preparation tasks do not leak
# across tests. Each ``create_run`` spawns a ``prep_task``/``task`` that
# outlives the test if not awaited/shut down, accumulating pending tasks
# that block loop teardown (hang at 76 %).
import asyncio as _asyncio

_tracked_managers: list = []  # type: ignore[var-annotated]


@pytest.fixture(autouse=True)
async def _shutdown_leaked_run_managers(monkeypatch):
    """Ensure RunManager background tasks are cancelled after each test."""
    try:
        from tools.api.run_manager import RunManager as _RM
    except Exception:  # pragma: no cover
        yield
        return

    orig_init = _RM.__init__  # type: ignore[attr-defined]

    def _tracked_init(self, *a, **kw):  # type: ignore[no-untyped-def]
        orig_init(self, *a, **kw)
        _tracked_managers.append(self)

    monkeypatch.setattr(_RM, "__init__", _tracked_init)
    yield
    for m in list(_tracked_managers):
        try:
            # Only attempt shutdown if we still have a running loop; otherwise
            # the manager's tasks are already orphaned on a closed loop and
            # awaiting would raise "Event loop is closed".
            try:
                loop = _asyncio.get_running_loop()
            except RuntimeError:
                continue
            if loop.is_closed():
                continue
            try:
                await _asyncio.wait_for(m.shutdown(), timeout=2.0)
            except (_asyncio.TimeoutError, RuntimeError):
                pass
            except Exception:
                pass
        except Exception:
            pass
    _tracked_managers.clear()


@pytest.fixture
def mock_mcp_session():
    """Mocked MCP ClientSession (stdio_client/streamable_http_client)."""
    session = AsyncMock()
    session.initialize = AsyncMock(return_value=None)
    session.list_tools = AsyncMock(return_value=[])
    session.call_tool = AsyncMock(return_value=Mock(content=[Mock(text="ok")], isError=False))
    return session


@pytest.fixture
def mock_ollama():
    """Mocked Ollama client (model_router.build_router → get_client → chat)."""
    client = Mock()
    client.chat = Mock(return_value={"message": {"content": "ok"}})
    client.generate = Mock(return_value={"response": "ok"})
    router = Mock()
    router.get_client.return_value = client
    return router


@pytest.fixture
def mock_nmap(tmp_path):
    """Mocked nmap subprocess output + recon_pipeline helpers."""
    nmap_mock = Mock()
    nmap_mock.run = Mock(return_value=Mock(stdout="<nmaprun/>", stderr="", returncode=0))
    return nmap_mock
