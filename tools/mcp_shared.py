"""Shared configuration helpers for both MCP servers.

Centralizes the duplicated config-loading and builder logic that previously
lived in both ``mcp_server.py`` and ``mcp_exploit_server.py``.
"""
# BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot

from __future__ import annotations

import os
import signal
import subprocess
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import cast

from tools.cve_lookup import CVESearchSettings, NVDClient
from tools.exploit_search import ExploitSearch, ExploitSearchSettings
from tools.kernel.allowlist import (
    _MSF_LHOST_RE,
    _MSF_PIVOT_RE,
    _MSF_RHOSTS_RE,
    _allowed_target_list,
    _check_allowlist,
    _env_widening_note,
    _extract_msf_lhosts,
    _extract_msf_option_hosts,
    _extract_msf_rhosts,
    _extract_scanner_targets,
    add_discovered_target,
    allowlist_env_audit_extra,
    check_targets_allowlist,
)
from tools.kernel.audit import (
    _BLOCKED_RESULT_MARKERS,
    _REDACTED,
    _SECRET_ARG_NAMES,
    _WHOLESALE_REDACT_FIELDS,
    _audit_log,
    _extract_audit_target,
    _mask_secret_content,
    _redact_args,
    _redact_nested,
    _result_is_blocked,
    make_audit_tool,
    make_require_allowlist,
)
from tools.kernel.config import load_config  # re-export for back-compat
from tools.kernel.discovered import (
    clear_discovered,
    get_discovered_host,
    is_pair_authorized,
    record_discovered_host,
    resolved_ips_for_host,
)
from tools.kernel.discovered import (
    snapshot as discovered_snapshot,
)
from tools.kernel.workspace import (
    _attempt_dir,
    _find_file,
    _is_inside_workspace,
    _resolve_workspace_file,
    read_workspace,
)
from tools.reliability import RateLimiter
from tools.web_researcher import (
    OllamaResearchSettings,
    SerpAPIResearchSettings,
    WebResearcher,
    WebResearcherSettings,
)

__all__ = [  # re-exports for backwards compat (F401 suppression via __all__)
    "_MSF_LHOST_RE",
    "_MSF_PIVOT_RE",
    "_MSF_RHOSTS_RE",
    "_REDACTED",
    "_SECRET_ARG_NAMES",
    "_WHOLESALE_REDACT_FIELDS",
    "_BLOCKED_RESULT_MARKERS",
    "_allowed_target_list",
    "_attempt_dir",
    "_audit_log",
    "_check_allowlist",
    "_env_widening_note",
    "_extract_audit_target",
    "_extract_msf_lhosts",
    "_extract_msf_option_hosts",
    "_extract_msf_rhosts",
    "_extract_scanner_targets",
    "_find_file",
    "_is_inside_workspace",
    "_mask_secret_content",
    "allowlist_env_audit_extra",
    "_redact_args",
    "_redact_nested",
    "_resolve_workspace_file",
    "_result_is_blocked",
    "add_discovered_target",
    "check_targets_allowlist",
    "clear_discovered",
    "discovered_snapshot",
    "get_discovered_host",
    "is_pair_authorized",
    "record_discovered_host",
    "resolved_ips_for_host",
    "make_audit_tool",
    "load_config",
    "make_require_allowlist",
    "read_workspace",
]

# Tier 1.8: process-wide shared NVD rate budget. Keyed by the configured
# per-minute rate so that concurrent MCP requests -- each of which calls
# build_cve_search() and would otherwise get its OWN NVDClient with its own
# per-instance 6s throttle -- instead share ONE token bucket, keeping the
# whole process within NVD's rate limit (not just each client instance).
# Module-level so the limiter survives across requests in a long-running
# HTTP-transport server. Loop-agnostic (threading.Lock based) so it is safe
# regardless of which event loop a caller runs in.
_SHARED_NVD_LIMITERS: dict[float, RateLimiter] = {}


def _shared_nvd_limiter(per_minute: float) -> RateLimiter:
    """Return the process-wide shared NVD RateLimiter for ``per_minute``,
    creating + caching it on first use."""
    lim = _SHARED_NVD_LIMITERS.get(per_minute)
    if lim is None:
        lim = RateLimiter.from_per_minute(per_minute, burst=1)
        _SHARED_NVD_LIMITERS[per_minute] = lim
    return lim


def _cfg_int(cfg: Mapping[str, object], key: str, default: int) -> int:
    v = cfg.get(key, default)
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        try:
            return int(v.strip())
        except ValueError:
            return default
    return default


def _cfg_float(cfg: Mapping[str, object], key: str, default: float) -> float:
    v = cfg.get(key, default)
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return default
    return default


def _cfg_str(cfg: Mapping[str, object], key: str, default: str) -> str:
    v = cfg.get(key, default)
    return str(v) if isinstance(v, (str, int, float, bytes)) else default


def _cfg_bool(cfg: Mapping[str, object], key: str, default: bool) -> bool:
    v = cfg.get(key, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(v, int):
        return bool(v)
    return default


def build_search(config: Mapping[str, object]) -> ExploitSearch:
    """Build an ``ExploitSearch`` from the ``exploit``/``search`` config blocks."""
    exploit_cfg_raw = config.get("exploit", {})
    exploit_cfg: Mapping[str, object] = exploit_cfg_raw if isinstance(exploit_cfg_raw, Mapping) else {}
    research_cfg_raw = config.get("research", {})
    research_cfg: Mapping[str, object] = research_cfg_raw if isinstance(research_cfg_raw, Mapping) else {}
    search_cfg_raw = config.get("search", {})
    search_cfg: Mapping[str, object] = search_cfg_raw if isinstance(search_cfg_raw, Mapping) else {}
    serpapi_cfg_raw = research_cfg.get("serpapi", {})
    serpapi_cfg: Mapping[str, object] = serpapi_cfg_raw if isinstance(serpapi_cfg_raw, Mapping) else {}

    def web_cfg(key: str, default: object) -> object:
        return serpapi_cfg.get(key, search_cfg.get(key, default))

    settings = ExploitSearchSettings(
        enabled=_cfg_bool(exploit_cfg, "enabled", False),
        searchsploit_path=_cfg_str(exploit_cfg, "searchsploit_path", "searchsploit"),
        web_endpoint=str(web_cfg("endpoint", "https://serpapi.com/search.json")),
        web_engine=str(web_cfg("engine", "duckduckgo")),
        web_region=str(web_cfg("region", "us-en")),
        web_api_key_env=str(web_cfg("api_key_env", "SERPAPI_API_KEY")),
        web_timeout_seconds=_cfg_int(research_cfg, "timeout_seconds", _cfg_int(search_cfg, "timeout_seconds", 20)),
        web_max_results=_cfg_int(research_cfg, "max_results", _cfg_int(search_cfg, "max_results", 5)),
        cache_ttl_seconds=_cfg_float(exploit_cfg, "cache_ttl_seconds", 3600.0),
        cache_max_entries=_cfg_int(exploit_cfg, "cache_max_entries", 50),
        max_query_chars=_cfg_int(exploit_cfg, "max_query_chars", 200),
    )
    return ExploitSearch(settings)


def build_cve_search(config: Mapping[str, object]) -> NVDClient:
    """Build an NVD client from the ``cve_lookup`` config block.

    Tier 1.8: also wires a process-wide shared ``RateLimiter`` (built from
    ``cve_lookup.search_rate_limit_per_minute``, default 10/min = the ~6s NVD
    gap) so concurrent MCP requests share one NVD budget instead of each
    NVDClient hammering at its own per-instance gap. ``rate_limit_seconds``
    remains the per-instance FALLBACK used only when no shared limiter is
    passed (e.g. vuln_agent constructing NVDClient directly)."""
    cve_cfg_raw = config.get("cve_lookup", {})
    cve_cfg: Mapping[str, object] = cve_cfg_raw if isinstance(cve_cfg_raw, Mapping) else {}
    settings = CVESearchSettings(
        enabled=_cfg_bool(cve_cfg, "enabled", True),
        timeout_seconds=_cfg_int(cve_cfg, "timeout_seconds", 30),
        max_results=_cfg_int(cve_cfg, "max_results", 5),
        cache_ttl_seconds=_cfg_int(cve_cfg, "cache_ttl_seconds", 3600),
        cache_max_entries=_cfg_int(cve_cfg, "cache_max_entries", 100),
        rate_limit_seconds=_cfg_float(cve_cfg, "rate_limit_seconds", 6.0),
        api_key_env=_cfg_str(cve_cfg, "api_key_env", "NVD_API_KEY"),
        circuit_failure_threshold=_cfg_int(cve_cfg, "circuit_failure_threshold", 5),
        circuit_recovery_timeout=_cfg_float(cve_cfg, "circuit_recovery_timeout", 60.0),
        epss_enabled=_cfg_bool(cve_cfg, "epss_enabled", False),
        kev_enabled=_cfg_bool(cve_cfg, "kev_enabled", False),
        kev_cache_ttl_seconds=_cfg_int(cve_cfg, "kev_cache_ttl_seconds", 86400),
        kev_cache_path=_cfg_str(cve_cfg, "kev_cache_path", ""),
    )
    search_per_minute = _cfg_float(cve_cfg, "search_rate_limit_per_minute", 10.0)
    limiter = _shared_nvd_limiter(search_per_minute) if search_per_minute > 0 else None
    return NVDClient(settings, rate_limiter=limiter)


def build_researcher(config: Mapping[str, object]) -> WebResearcher:
    """Build a web researcher from the ``research`` config block."""
    research_cfg_raw = config.get("research", {})
    research_cfg: Mapping[str, object] = research_cfg_raw if isinstance(research_cfg_raw, Mapping) else {}
    ollama_cfg_raw = research_cfg.get("ollama", {})
    ollama_cfg: Mapping[str, object] = ollama_cfg_raw if isinstance(ollama_cfg_raw, Mapping) else {}
    serpapi_cfg_raw = research_cfg.get("serpapi", {})
    serpapi_cfg: Mapping[str, object] = serpapi_cfg_raw if isinstance(serpapi_cfg_raw, Mapping) else {}

    def list_cfg(key: str, default: list[str]) -> list[str]:
        value = research_cfg.get(key, default)
        return value if isinstance(value, list) else default

    settings = WebResearcherSettings(
        enabled=_cfg_bool(research_cfg, "enabled", True),
        provider=_cfg_str(research_cfg, "provider", "ollama"),
        fallback_provider=_cfg_str(research_cfg, "fallback_provider", "serpapi"),
        timeout_seconds=_cfg_int(research_cfg, "timeout_seconds", 15),
        max_results=_cfg_int(research_cfg, "max_results", 8),
        max_fetch_depth=_cfg_int(research_cfg, "max_fetch_depth", 5),
        max_content_chars=_cfg_int(research_cfg, "max_content_chars", 12000),
        cache_ttl_seconds=_cfg_float(research_cfg, "cache_ttl_seconds", 1800.0),
        cache_max_entries=_cfg_int(research_cfg, "cache_max_entries", 250),
        min_source_quality=_cfg_str(research_cfg, "min_source_quality", "medium"),
        allow_local_fetch=_cfg_bool(research_cfg, "allow_local_fetch", False),
        allowed_domains=list_cfg("allowed_domains", []),
        blocked_domains=list_cfg(
            "blocked_domains",
            [
                "doubleclick.net",
                "googleadservices.com",
                "googlesyndication.com",
                "facebook.com",
                "twitter.com",
                "instagram.com",
                "tiktok.com",
            ],
        ),
        ollama=OllamaResearchSettings(
            api_key_env=_cfg_str(ollama_cfg, "api_key_env", "OLLAMA_API_KEY"),
            max_results=_cfg_int(ollama_cfg, "max_results", _cfg_int(research_cfg, "max_results", 8)),
            use_web_search=_cfg_bool(ollama_cfg, "use_web_search", True),
            use_web_fetch=_cfg_bool(ollama_cfg, "use_web_fetch", True),
        ),
        serpapi=SerpAPIResearchSettings(
            api_key_env=_cfg_str(serpapi_cfg, "api_key_env", "SERPAPI_API_KEY"),
            endpoint=_cfg_str(serpapi_cfg, "endpoint", "https://serpapi.com/search.json"),
            engine=_cfg_str(serpapi_cfg, "engine", "duckduckgo"),
            region=_cfg_str(serpapi_cfg, "region", "us-en"),
        ),
    )
    return WebResearcher(settings)


# -- Kernel re-exports (Phase 2) --
# Workspace / allowlist / audit pure functions now live in tools.kernel.*
# (workspace.py / allowlist.py / audit.py). This module re-exports
# them for backwards compat — from tools.mcp_shared import _is_inside_workspace
# and make_audit_tool continue to work. New code should import from
# tools.kernel.* directly. Verbatim moves, no behavior change.
# See tools/kernel/__init__.py and docs/architecture.md ADR-001.

# ── Subprocess helper with process-group timeout kill ────────────────────────
#
# Reused by every shell-wrapper / ``subprocess.run(..., timeout=...)`` site in
# the exploit MCP server (M2 / M15 / M18 / H1-H2 / H5 / M5). On POSIX it opens the
# child in its own session (``start_new_session=True``) so a timeout can reap the
# *whole* process group with ``os.killpg(SIGKILL)`` -- shell-spawned children die
# with the parent instead of surviving the kill. On Windows process groups are
# unavailable, so it falls back to ``proc.kill()``.
#
# Re-raises ``subprocess.TimeoutExpired`` (rather than returning a structured
# result) so existing call sites that wrap ``subprocess.run(..., timeout=...)``
# in ``try/except subprocess.TimeoutExpired`` keep working unchanged.


def _run_with_pgrp_timeout(
    args: Sequence[str] | str,
    timeout: float | None,
    stdout: int | None = None,
    stderr: int | None = None,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | bytes | None = None,
    **popen_kwargs: object,
) -> tuple[int, str | bytes | None, str | bytes | None]:
    """Run ``args`` with a hard ``timeout``, reaping the process group on timeout.

    On POSIX the child is started in a new session (``start_new_session=True``)
    so that on timeout the entire group is killed via
    ``os.killpg(os.getpgid(pid), SIGKILL)`` (guarded against
    ``ProcessLookupError`` / ``PermissionError`` with a ``proc.kill()`` fallback).
    On Windows (``os.name == "nt"``) ``start_new_session`` is a no-op and the
    timeout path uses ``proc.kill()`` (``os.killpg`` / ``SIGKILL`` are not
    available).

    ``stdout`` / ``stderr`` / ``cwd`` / ``env`` / ``input_text`` are forwarded to
    ``subprocess.Popen``; remaining ``popen_kwargs`` are passed through (e.g.
    ``text=True``, ``encoding="utf-8"``). When ``input_text`` is a ``str`` it is
    encoded to bytes for ``Popen.communicate(input=...)``.

    Returns ``(returncode, stdout, stderr)``. When text mode is requested (via
    ``text=True`` / ``universal_newlines=True`` / ``encoding=``) the captured
    streams are decoded to ``str``; otherwise they are ``bytes`` (or whatever the
    caller-supplied ``stdout``/``stderr`` sink yields, e.g. ``None`` when the
    caller passes ``subprocess.DEVNULL``).

    Re-raises ``subprocess.TimeoutExpired`` on timeout so callers can catch it,
    matching the existing ``subprocess.run(..., timeout=...)`` call-site pattern.
    """

    text_mode = bool(
        popen_kwargs.get("text") or popen_kwargs.get("universal_newlines") or popen_kwargs.get("encoding") is not None
    )
    proc = subprocess.Popen(  # type: ignore[call-overload,misc]
        args,
        start_new_session=(os.name != "nt"),
        stdout=stdout,
        stderr=stderr,
        cwd=cwd,
        env=env,
        **popen_kwargs,  # type: ignore[arg-type]
    )
    input_bytes = None
    if input_text is not None:
        input_bytes = input_text.encode() if isinstance(input_text, str) else input_text
    try:
        out, err = proc.communicate(input=input_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Kill the whole process group on POSIX so shell-spawned children die
        # with the parent; on Windows fall back to killing the immediate proc.
        if os.name == "nt":
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        else:
            try:
                killpg = getattr(os, "killpg", None)
                getpgid = getattr(os, "getpgid", None)
                sigkill = getattr(signal, "SIGKILL", 9)
                if killpg is not None and getpgid is not None:
                    killpg(getpgid(proc.pid), sigkill)  # type: ignore[operator]
                else:
                    proc.kill()
            except (ProcessLookupError, PermissionError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
        try:
            proc.wait()
        except Exception:
            pass
        raise
    returncode = proc.returncode
    if text_mode:
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
    return returncode, out, err


# ── HTTP transport hardening (loopback gate + optional shared-secret auth) ──
#
# CLAUDE.md documents that the MCP HTTP transport "refuses to bind to non-
# loopback interfaces unless ``--allow-public-bind`` AND
# ``MCP_ALLOW_PUBLIC_BIND=1`` are both set", and that there is no auth on the
# streamable-http endpoint. The loopback gate previously existed only in
# mcp_exploit_server.py (and the documented override flag did not exist at
# all); mcp_server.py (defensive) had no gate. These helpers give both servers
# the same gate + an optional ``MCP_HTTP_TOKEN`` bearer-token check so a
# public bind is not unauthenticated.

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def assert_loopback_bind(host: str, allow_public_bind: bool = False) -> None:
    """Raise ``ValueError`` if ``host`` is non-loopback and the public-bind
    override is not satisfied. The override requires BOTH the caller passing
    ``allow_public_bind=True`` (the ``--allow-public-bind`` CLI flag) AND the
    ``MCP_ALLOW_PUBLIC_BIND`` env var set to a truthy value -- a two-person
    rule so a stray flag or env var alone never exposes the server."""
    if host in _LOOPBACK_HOSTS:
        return
    env = os.environ.get("MCP_ALLOW_PUBLIC_BIND", "").strip().lower()
    env_set = env in {"1", "true", "yes", "on"}
    if allow_public_bind and env_set:
        return
    raise ValueError(
        f"Refusing to bind MCP HTTP transport to non-loopback host {host!r}. "
        f"Binding a public interface exposes the MCP tools to the network. "
        f"To allow, pass --allow-public-bind AND set MCP_ALLOW_PUBLIC_BIND=1."
    )


def _wrap_http_auth(app: Callable[..., Awaitable[None]], token: str) -> Callable[..., Awaitable[None]]:
    """Wrap an ASGI app to require ``Authorization: Bearer <token>``.

    Pure-ASGI (no Starlette import) so it works with the streamable-http app
    from FastMCP. When the ``MCP_HTTP_TOKEN`` env var is unset, callers should
    not wrap -- the server is loopback-only by default. Comparison uses
    ``hmac.compare_digest`` to avoid timing side channels.
    """
    import hmac

    expected = f"Bearer {token}".encode("utf-8")

    async def auth_app(
        scope: Mapping[str, object],
        receive: Callable[[], Awaitable[Mapping[str, object]]],
        send: Callable[[Mapping[str, object]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            return await app(scope, receive, send)
        raw_headers = scope.get("headers", [])
        headers: dict[bytes, bytes] = {}
        if isinstance(raw_headers, list):
            for k, v in raw_headers:  # type: ignore[misc]
                if isinstance(k, bytes) and isinstance(v, bytes):
                    headers[k.lower()] = v
        if hmac.compare_digest(headers.get(b"authorization", b""), expected):
            return await app(scope, receive, send)
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"www-authenticate", b'Bearer realm="mcp"'),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"Unauthorized: MCP_HTTP_TOKEN required"})

    return auth_app


def run_mcp_http_server(mcp: object, host: str, port: int, *, allow_public_bind: bool = False) -> None:
    """Run a FastMCP server over streamable-http with loopback + optional auth.

    Centralizes the HTTP serving for both MCP servers so the loopback gate,
    the ``--allow-public-bind`` override, and the ``MCP_HTTP_TOKEN`` bearer
    auth live in one place. Uses ``mcp.streamable_http_app()`` + ``uvicorn.run``
    (the current SDK path) instead of the legacy ``server.run(transport="http")``.
    """
    assert_loopback_bind(host, allow_public_bind=allow_public_bind)
    try:
        import uvicorn

        app = cast(Callable[[], Callable[..., Awaitable[None]]], getattr(mcp, "streamable_http_app"))()
    except ImportError as exc:
        raise RuntimeError(
            "HTTP MCP transport needs uvicorn and starlette. Run: python -m pip install -r requirements.txt"
        ) from exc
    token = os.environ.get("MCP_HTTP_TOKEN", "").strip()
    if token:
        app = _wrap_http_auth(app, token)
    uvicorn.run(app, host=host, port=port, log_level="info")
