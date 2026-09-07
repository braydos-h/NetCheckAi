"""Explicit runtime dependencies for assessment runs (incremental DI).

``main.py`` historically configured runs by mutating imported module globals
(``tools.mcp_session.ui``, ``tools.exploit_session.run_exploit_agent``, MCP
timeout values, ...) on every call. That hidden coupling breaks concurrent
runs: two simultaneous sessions interleave their pokes and each proceeds
with the other's UI/timeouts/dependencies.

``RuntimeContext`` is the incremental way out, following the established
``Callables`` precedent (``tools/run_service/prepare.py``): a plain bundle
of runtime dependencies with production defaults, constructed explicitly by
the caller and threaded through optional ``ctx`` parameters. The module
globals remain as back-compat fallbacks (existing monkeypatch-style tests
keep working), but production paths pass a context and never mutate them.

Fields:

- ``ui`` — terminal UI (defaults to the process ``get_ui()`` singleton).
- ``config_loader`` — ``load_config(path)`` callable.
- ``mcp_boot_timeout_seconds`` — MCP session boot cap.
- ``open_mcp_session`` — MCP session factory (async context manager).
- ``run_exploit_agent_fn`` — exploit-agent runner coroutine function.
- ``build_router_fn`` — model-router builder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


def _default_ui() -> Any:
    from tools.attack_ui import get_ui

    return get_ui()


def _default_config_loader(path: Path | str) -> dict[str, Any]:
    from tools.kernel.config import load_config

    return load_config(Path(path))


def _default_open_mcp_session(**kwargs: Any) -> Any:
    from tools.mcp_session import open_exploit_mcp_session

    return open_exploit_mcp_session(**kwargs)


async def _default_run_exploit_agent(**kwargs: Any) -> dict[str, Any]:
    from tools.exploit_agent import run_exploit_agent

    return await run_exploit_agent(**kwargs)


def _default_build_router(*args: Any, **kwargs: Any) -> Any:
    from tools.model_router import build_router

    return build_router(*args, **kwargs)


@dataclass
class RuntimeContext:
    """Runtime dependencies for one assessment run. See module docstring."""

    ui: Any = field(default_factory=_default_ui)
    config_loader: Callable[..., dict[str, Any]] = field(default=_default_config_loader)
    mcp_boot_timeout_seconds: float = 30.0
    open_mcp_session: Callable[..., Any] = field(default=_default_open_mcp_session)
    run_exploit_agent_fn: Callable[..., Any] = field(default=_default_run_exploit_agent)
    build_router_fn: Callable[..., Any] = field(default=_default_build_router)

    def load_config(self, path: Path | str) -> dict[str, Any]:
        """Load config through this context's loader."""
        return self.config_loader(path)
