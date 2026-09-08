"""Shared dependencies and helpers for exploit MCP tool registration."""
# BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot

from __future__ import annotations

import os
import platform
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from db import get_default_db
from tools.config_manager import CONFIG_SCHEMA
from tools.cve_lookup import NVDClient
from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.exploit_search import ExploitSearch
from tools.kernel.allowlist import _extract_scanner_targets
from tools.kernel.workspace import read_workspace
from tools.mcp_shared import (
    _attempt_dir,
    make_audit_tool,
    make_require_allowlist,
)
from tools.mcp_shared import (
    _run_with_pgrp_timeout as _shared_run_with_pgrp_timeout,
)
from tools.web_researcher import WebResearcher

_ORIGINAL_SUBPROCESS_RUN = subprocess.run


def _platform_system() -> str:
    if os.name == "nt":
        return "Windows"
    try:
        return platform.system()
    except Exception:  # ponytail: bare except intentional
        return "Linux"


@dataclass(frozen=True)
class ToolContext:
    workspace: Path
    config: dict[str, Any] | None
    search: ExploitSearch
    nvd: NVDClient
    researcher: WebResearcher
    audit_tool: Any
    require_allowlist: Any
    # Disposable execution sandbox (tools/sandbox/) — None when disabled
    # (documented legacy host-execution mode). Optional at the END so positional
    # construction and test FakeCtx duck-typing keep working.
    sandbox: Any | None = None
    # Non-empty when the server degraded to legacy host-execution via the
    # boot-time native fallback (sandbox enabled, Docker unusable,
    # sandbox.fallback_native=true as explicit opt-in): tools embed this in results so the agent
    # (and the audit trail) knows execution is UNCONTAINED. "" otherwise.
    sandbox_notice: str = ""


def _run_with_pgrp_timeout(*args: Any, **kwargs: Any) -> Any:
    """Compatibility-aware wrapper around the shared subprocess timeout helper.

    Some older tests monkeypatch ``mcp_exploit_server._run_with_pgrp_timeout``.
    Tool modules call this wrapper so that patch point still controls execution.
    """
    server_mod = sys.modules.get("mcp_exploit_server")
    override = getattr(server_mod, "_run_with_pgrp_timeout", None) if server_mod else None
    if override is not None and override is not _run_with_pgrp_timeout:
        return override(*args, **kwargs)
    if subprocess.run is not _ORIGINAL_SUBPROCESS_RUN:
        proc = subprocess.run(
            args[0] if args else kwargs.get("args"),
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
            cwd=kwargs.get("cwd"),
            env=kwargs.get("env"),
            input=kwargs.get("input_text"),
            timeout=args[1] if len(args) > 1 else kwargs.get("timeout"),
            text=kwargs.get("text"),
            encoding=kwargs.get("encoding"),
        )
        return proc.returncode, proc.stdout, proc.stderr
    return _shared_run_with_pgrp_timeout(*args, **kwargs)


_model_router_cache: Any = None
_model_router_init_attempted: bool = False
_model_router_lock = threading.Lock()

_consultation_count: int = 0
_consultation_lock = threading.Lock()


def _get_model_router_impl(config: dict[str, Any] | None) -> Any | None:
    """Lazily build and cache a ModelRouter from config. Returns None on failure."""
    global _model_router_cache, _model_router_init_attempted
    with _model_router_lock:
        if _model_router_init_attempted:
            return _model_router_cache
        _model_router_init_attempted = True
        try:
            from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config
            from tools.model_router import build_router

            registry = (config or {}).get("models", {}).get("registry", {})
            host = (config or {}).get("ollama", {}).get("host", "http://localhost:11434")
            provider = get_ai_provider(config)
            kwargs: dict[str, Any] = {"host": str(host)}
            if registry:
                kwargs["registry"] = registry
            if provider == "chatgpt":
                kwargs["provider"] = "chatgpt"
                kwargs["chatgpt_config"] = get_chatgpt_config(config)
                kwargs["config"] = config
            elif provider == "opencode_go":
                kwargs["provider"] = "opencode_go"
                kwargs["opencode_go_config"] = get_opencode_go_config(config)
                kwargs["config"] = config
            _model_router_cache = build_router(**kwargs)
            return _model_router_cache
        except ImportError:
            return None
        except Exception:  # ponytail: bare except intentional
            return None


def _get_model_router(config: dict[str, Any] | None) -> Any | None:
    """Compatibility-aware model-router lookup for moved peer-model tools."""
    server_mod = sys.modules.get("mcp_exploit_server")
    override = getattr(server_mod, "_get_model_router", None) if server_mod else None
    if override is not None and override is not _get_model_router:
        return override(config)
    return _get_model_router_impl(config)


def _get_model_client(config: dict[str, Any] | None, role: str = "") -> tuple[Any | None, str]:
    """Return (client, model_name) from the router (provider-aware).

    ``role`` (capability-upgrade §13) resolves via
    ``get_client_for_role(role)`` — a configured ``models.roles.<role>``
    routes that call to a different model, empty/unresolvable roles fall
    back to the default alias, so callers without a role are byte-identical
    to before. ``ModelClient.chat()`` ignores positional model args (its own
    model is baked in), but callers still pass the returned name through.
    """
    from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config

    router = _get_model_router(config)
    if router is None:
        return None, ""
    provider = get_ai_provider(config)
    if provider == "chatgpt":
        default_alias = str(get_chatgpt_config(config).get("default_model") or "gpt-5.2")
    elif provider == "opencode_go":
        default_alias = str(get_opencode_go_config(config).get("default_model") or "muse-spark-1.2-contributor")
    else:
        default_alias = str((config or {}).get("models", {}).get("default_alias", "glm") or "glm")
    try:
        if role:
            try:
                client = router.get_client_for_role(role, config=config, fallback_alias=default_alias)
                return client, str(getattr(client, "name", "") or default_alias)
            except Exception:  # ponytail: bare except intentional — role failure falls back below
                pass
        client = router.get_client(default_alias)
        return client, default_alias
    except Exception:  # ponytail: bare except intentional
        return None, ""


def _resolve_consult_aliases(config: dict[str, Any] | None) -> list[str]:
    """Return the peer aliases the active model may consult.

    Intersection of ``multi_model.consult_aliases`` with the actually-registered
    ``models.registry`` aliases, minus the active ``default_alias`` (a model never
    consults itself). Preserves the order given in ``consult_aliases``.
    """
    cfg = config or {}
    mm = cfg.get("multi_model", {}) or {}
    requested = [
        str(a) for a in (mm.get("consult_aliases") or ["kimi", "deepseek", "deepseek_flash", "glm", "minimax"])
    ]
    registry = cfg.get("models", {}).get("registry", {}) or {}
    active = os.environ.get("AI_NMAP_ACTIVE_MODEL_ALIAS") or cfg.get("models", {}).get("default_alias", "glm")
    available = set(registry.keys())
    return [a for a in requested if a in available and a != active]


def _env_bool(value: str | None) -> bool | None:
    """Parse a boolean environment override, returning None when unset/unknown."""
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def _multi_model_enabled(config: dict[str, Any] | None) -> bool:
    """Return the effective peer-consult setting, honoring per-run env override."""
    override = _env_bool(os.environ.get("AI_NMAP_MULTI_MODEL_ENABLED"))
    if override is not None:
        return override
    return bool(((config or {}).get("multi_model", {}) or {}).get("enabled", False))


def _positive_int(value: Any, default: int) -> int:
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return default
    return ivalue if ivalue > 0 else default


def _chat_content(response: Any) -> str:
    """Extract assistant text from an Ollama response-like object."""
    if isinstance(response, dict):
        message = response.get("message", {}) or {}
        if isinstance(message, dict):
            return str(message.get("content", "") or "")
        return str(getattr(message, "content", "") or "")
    message = getattr(response, "message", None)
    if isinstance(message, dict):
        return str(message.get("content", "") or "")
    if message is not None:
        return str(getattr(message, "content", "") or "")
    return str(response or "")


def _truncate_text(value: str, max_chars: int) -> str:
    text = str(value or "")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[truncated]"


def tool_slug(value: Any, default: str = "unknown", limit: int = 40) -> str:
    """Filesystem/id-safe slug (empty -> ``default``).

    Single source for the ``_slug`` helper previously duplicated in
    ``web_scan.py`` and ``hitl.py`` (different signatures, same intent).
    """
    import re as _re

    text = _re.sub(r"[^A-Za-z0-9]+", "-", str(value or "").strip()).strip("-")
    return (text or default)[:limit].strip("-") or default


def parse_extra_options(options: str) -> tuple[list[str], str | None]:
    """Split free-form ``options`` into argv tokens (no shell).

    Returns ``(argv, error)`` -- ``error`` is None on success (empty options
    yields ``([], None)``). Rejects shell metacharacters with one shared
    regex so ``web_scan`` / ``payloads`` / ``metasploit`` stop drifting
    (``<|>`` vs ``<|> |\\\\`` variants).
    """
    import re as _re
    import shlex as _shlex

    opts = (options or "").strip()
    if not opts:
        return [], None
    if _re.search(r"[;|&$`()]|<|>|\n", opts):
        return [], "BLOCKED: options contains forbidden shell metacharacters."
    try:
        return _shlex.split(opts), None
    except ValueError:
        return [], "BLOCKED: options string could not be parsed (unbalanced quotes)."


def run_argv_captured(
    argv: list[str],
    timeout: int,
    *,
    max_chars: int = 4000,
) -> tuple[str, int | None, str, float]:
    """Run ``argv`` via ``_run_with_pgrp_timeout``; return (status, rc, output, elapsed).

    Shared replacement for the copy-pasted ``try: _run_with_pgrp_timeout /
    TimeoutExpired / broad-except`` blocks in ``cracking.py``,
    ``payloads.py``, ``web_scan.py``, ``credentials.py`` and ``ad.py``.
    Output is truncated to ``max_chars`` (tail) to bound result blocks.
    """
    import time as _time

    start = _time.monotonic()
    try:
        returncode, out, err = _run_with_pgrp_timeout(
            argv,
            timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output = ((out or "") + "\n" + (err or ""))[-max_chars:]
        return ("completed" if returncode == 0 else "failed"), returncode, output, _time.monotonic() - start
    except subprocess.TimeoutExpired:
        elapsed = _time.monotonic() - start
        name = argv[0] if argv else "command"
        return "timed_out", None, f"{name} timed out after {timeout}s", elapsed
    except _EXC_GROUP_CATCH as exc:
        _log_nested_exceptions(exc)
        return "error", None, str(exc), _time.monotonic() - start


def _skills_config(config: dict[str, Any] | None) -> dict[str, Any]:
    base = dict(CONFIG_SCHEMA.get("skills", {}) or {})
    overlay = (config or {}).get("skills", {}) or {}
    if isinstance(overlay, dict):
        base.update(overlay)
    return base


def _runtime_skills_enabled(config: dict[str, Any] | None) -> bool:
    cfg = _skills_config(config)
    return bool(cfg.get("enabled", True) and cfg.get("allow_model_lookup", True))


def _ensure_workspace_dirs(workspace: Path) -> None:
    """Create standard subdirectories under the workspace."""
    for sub in ["plans", "exploits", "modules", "campaigns"]:
        (workspace / sub).mkdir(parents=True, exist_ok=True)


# Ponytail: single-source registry for MCP tool families.
# Each ``tools/mcp_tools/<family>.py`` defines ``register_<family>_tools(mcp, ctx)``.
# The old 2-place wiring (decorator + manual list in mcp_exploit_server.py) is
# collapsed to 1: ``mcp_exploit_server._discover_tool_registrars()`` walks the
# ``tools.mcp_tools`` package at import time and collects every
# ``register_*_tools`` callable. Adding a new family now requires only one file
# edit — create ``tools/mcp_tools/foo.py`` with ``register_foo_tools``; no edit
# to ``mcp_exploit_server.py`` or ``registry.py``.
_TOOL_REGISTRARS: list[Any] = []  # populated by _discover_tool_registrars on first use


def register_tool_family(fn: Any) -> Any:
    """Decorator for explicit registration (alternative to auto-discovery).

    Usage::

        @register_tool_family
        def register_foo_tools(mcp, ctx): ...

    The decorator appends ``fn`` to ``_TOOL_REGISTRARS`` and returns it
    unchanged. ``mcp_exploit_server.create_mcp_server`` also auto-discovers
    ``register_*_tools`` via package walk, so this decorator is optional —
    the single source is the function name, not the list.
    """
    if fn not in _TOOL_REGISTRARS:
        _TOOL_REGISTRARS.append(fn)
    return fn


def _discover_tool_registrars() -> list[Any]:
    """Auto-discover ``register_*_tools`` callables in ``tools.mcp_tools``.

    Walks top-level family modules AND every subpackage (``modules/``,
    ``terminal/``, ...) through one uniform branch: each module or
    ``<subpkg>.<module>`` contributing a callable named ``register_*_tools``.
    Re-walks on every call -- no stale cache (a newly added family is picked
    up without a restart); ``sys.modules`` makes the re-import cheap and
    already-seen callables are never duplicated. Explicit
    ``@register_tool_family`` entries are merged in.
    """
    import importlib
    import pkgutil

    try:
        import tools.mcp_tools as _pkg
    except ImportError:
        return list(_TOOL_REGISTRARS)

    def _collect(mod: Any) -> None:
        for attr in dir(mod):
            if attr.startswith("register_") and attr.endswith("_tools"):
                fn = getattr(mod, attr, None)
                if callable(fn) and fn not in _TOOL_REGISTRARS:
                    _TOOL_REGISTRARS.append(fn)

    for _, modname, ispkg in pkgutil.iter_modules(_pkg.__path__):
        if modname == "registry":
            continue
        try:
            mod = importlib.import_module(f"tools.mcp_tools.{modname}")
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            continue
        if not ispkg:
            _collect(mod)
            continue
        # Package itself may define the registrar (e.g. terminal/__init__.py
        # aggregates execute + privilege + package submodules).
        _collect(mod)
        try:
            submodules = list(pkgutil.iter_modules(mod.__path__))
        except AttributeError:
            continue
        for _, subname, sub_is_pkg in submodules:
            if sub_is_pkg:
                continue
            try:
                sub = importlib.import_module(f"tools.mcp_tools.{modname}.{subname}")
            except _EXC_GROUP_CATCH as exc:
                _log_nested_exceptions(exc)
                continue
            _collect(sub)
    return list(_TOOL_REGISTRARS)


def _validate_mcp_tool_decorators(_files: list[Any] | None = None) -> list[str]:
    """Static check: every ``@mcp.tool`` in ``tools/mcp_tools/*.py`` must have audit allowlist.

    Parses each ``tools/mcp_tools/<family>.py`` file with ``ast`` and verifies
    that every function/method decorated with ``mcp.tool`` also has
    ``@audit_tool`` or ``@require_allowlist`` (including ``ctx.audit_tool``,
    ``ctx.require_allowlist``, ``make_audit_tool`` variants). Returns a list of
    error messages (empty = all good). Used by ``collect_tools()`` to fail CI.
    ``_files`` overrides the scanned set (hermetic unit tests only).
    """
    import ast
    import pathlib

    errors: list[str] = []
    pkg_dir = pathlib.Path(__file__).parent
    # Check top-level, modules subpackage, and terminal subpackage (split god-file)
    files = (
        list(_files)
        if _files is not None
        else list(pkg_dir.glob("*.py"))
        + list((pkg_dir / "modules").glob("*.py"))
        + list((pkg_dir / "terminal").glob("*.py"))
    )
    for py in files:
        if py.name == "registry.py" or py.name == "__init__.py":
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        except Exception as exc:  # ponytail: bare except intentional
            errors.append(f"{py.name}: failed to parse: {exc}")
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decos = getattr(node, "decorator_list", [])
            if not decos:
                continue
            # need to detect @mcp.tool() among decorators
            has_mcp_tool = False
            has_audit = False
            broken_deco = False
            for d in decos:
                try:
                    src = ast.unparse(d)
                except _EXC_GROUP_CATCH as exc:
                    _log_nested_exceptions(exc)
                    broken_deco = True
                    continue
                low = src.lower()
                if "mcp.tool" in low or ".tool(" in low:
                    has_mcp_tool = True
                if "audit_tool" in low or "require_allowlist" in low:
                    has_audit = True
            if broken_deco:
                errors.append(f"{py.name}:{node.lineno} {node.name} has an unparseable decorator (fail closed)")
            elif has_mcp_tool and not has_audit:
                errors.append(
                    f"{py.name}:{node.lineno} {node.name} has @mcp.tool but lacks @audit_tool/@require_allowlist"
                )
    return errors


def collect_tools() -> list[Any]:
    """Single-source MCP tool collection with decorator validation (Phase 3).

    Discovers every ``register_*_tools`` in ``tools.mcp_tools.*`` (like
    ``_discover_tool_registrars``) and validates that every ``@mcp.tool``
    inside those modules carries ``@audit_tool`` or ``@require_allowlist``.
    Raises ``RuntimeError`` listing offenders so CI fails if a tool lacks the
    audit/allowlist gate. ``mcp_exploit_server.py`` should call this instead of
    a manual list.
    """
    registrars = _discover_tool_registrars()
    errs = _validate_mcp_tool_decorators()
    if errs:
        raise RuntimeError("MCP tool decorator check failed:\n" + "\n".join(errs))
    return registrars


# -- Kernel re-exports (Phase 3) --
# read_workspace now lives in tools.kernel.workspace; re-export for backwards compat
# (from tools.mcp_tools.registry import read_workspace still works).
# See tools/kernel/workspace.py


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# -- Kernel re-exports (Phase 3) --
# _extract_scanner_targets + helpers now live in tools.kernel.allowlist;
# re-export for backwards compat (from tools.mcp_tools.registry import _extract_scanner_targets still works).
# See tools/kernel/allowlist.py

# -- Public surface: ToolContext + discovery/validation + the small set of
# helpers other modules import explicitly (terminal/*, mcp_exploit_server,
# swarm, tests). Family modules import everything else from its true origin;
# the old ~70-symbol star re-export is gone.
__all__ = [
    "ToolContext",
    "_TOOL_REGISTRARS",
    "_attempt_dir",
    "_discover_tool_registrars",
    "_ensure_workspace_dirs",
    "_extract_scanner_targets",
    "_get_model_router",
    "_run_with_pgrp_timeout",
    "_validate_mcp_tool_decorators",
    "collect_tools",
    "get_default_db",
    "make_audit_tool",
    "make_require_allowlist",
    "parse_extra_options",
    "read_workspace",
    "register_tool_family",
    "run_argv_captured",
    "tool_slug",
]
