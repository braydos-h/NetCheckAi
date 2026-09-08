"""Browser-native web agent MCP tools (Playwright backend, sandboxed).

Read-only Phase 1 surface: start/navigate/observe/page-state/network/storage/
screenshot/discover/close, plus the mutating Phase 2 surface (``browser_submit``,
``browser_replay``) behind the explicit lab opt-in
``browser.allow_mutating_actions`` (``browser_execute_js`` shares the gate).

Containment: every target-touching tool carries ``@require_allowlist`` (the
target-IP lock) and funnels Chromium execution through ``BrowserManager`` +
a launcher resolved per call — ``SandboxPlaywrightLauncher`` (one Chromium op
per docker exec inside the worker netns) when the sandbox is enabled, the
in-process launcher only for the documented ``sandbox.enabled: false``
opt-out. When the sandbox is enabled but unusable the tools return
``SANDBOX_*`` blocks and NEVER fall back to host execution.

Conditional registration (the killchain/snapshots precedent): nothing
registers unless ``browser.enabled`` + ``backend: playwright`` + the runtime
is actually available (host SDK or a configured sandbox worker).
"""

from __future__ import annotations

import asyncio
import json
import threading
import urllib.parse
from pathlib import Path
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.mcp_shared import check_targets_allowlist
from tools.mcp_tools.registry import ToolContext
from tools.mcp_tools.sandbox_exec import sandbox_error_block
from tools.validation_utils import validate_target_or_ip

_MANAGERS: dict[str, Any] = {}
_BACKENDS: dict[str, Any] = {}
# Launchers are cached per workspace alongside managers/backends: engine
# tokens (Chromium pages, worker cookie jars) live in launcher instances, so
# re-resolving per call would orphan every session after the call that
# created it. Only successful resolutions are cached — a SANDBOX_* block is
# returned uncached so the next call re-probes sandbox health.
_LAUNCHERS: dict[str, Any] = {}

_browser_loop: asyncio.AbstractEventLoop | None = None
_browser_thread: threading.Thread | None = None
_browser_loop_guard = threading.Lock()


def _get_browser_loop() -> asyncio.AbstractEventLoop:
    """One private event loop for every browser coroutine (host-mode fix).

    Playwright connections bind to the loop that created them; an
    ``asyncio.run(...)``-per-tool pattern gives every call a fresh loop, so any
    op after ``browser_start`` dies with ``'NoneType' object has no attribute
    'send'``. Every browser coroutine hops onto this single daemon-thread loop
    instead (the swarm_bridge / exploit_agent precedent). A dead loop thread
    (stopped/closed loop) is replaced, never reused.
    """
    global _browser_loop, _browser_thread
    with _browser_loop_guard:
        thread_dead = _browser_thread is not None and not _browser_thread.is_alive()
        if _browser_loop is None or _browser_loop.is_closed() or thread_dead:
            _browser_loop = asyncio.new_event_loop()
            _browser_thread = threading.Thread(target=_browser_loop.run_forever, name="browser-loop", daemon=True)
            _browser_thread.start()
        return _browser_loop


def _run(awaitable: Any) -> Any:
    """Block the calling (MCP worker) thread until the browser coroutine finishes."""
    return asyncio.run_coroutine_threadsafe(awaitable, _get_browser_loop()).result()


def _browser_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    return (config or {}).get("browser", {}) or {}


def _get_stack(ctx: Any) -> tuple[Any, Any, Any, str]:
    """Resolve (manager, backend, launcher, block) for one tool call.

    ``block`` non-empty means the tool must return it verbatim (fail closed).
    Managers/backends/launchers are cached per workspace so sessions survive
    across calls; a failed sandbox resolution is never cached, so the next
    call re-probes instead of sticking on a stale block.
    """
    from tools.browser.capabilities import get_backend, register_playwright_backend
    from tools.browser.manager import BrowserManager
    from tools.browser.playwright_backend import PlaywrightBackend
    from tools.browser.sandbox_launcher import resolve_browser_launcher

    config = ctx.config
    key = str(getattr(ctx, "workspace", "default") or "default")
    launcher = _LAUNCHERS.get(key)
    if launcher is None:
        launcher, block = resolve_browser_launcher(ctx, config)
        if block:
            return None, None, None, block
        _LAUNCHERS[key] = launcher
    backend = _BACKENDS.get(key)
    if backend is None:
        register_playwright_backend(config)
        backend = get_backend("playwright")
        if backend is None:  # pragma: no cover — registration only fails without the module
            backend = PlaywrightBackend(config)
        _BACKENDS[key] = backend
    backend.launcher = launcher
    manager = _MANAGERS.get(key)
    if manager is None:
        manager = BrowserManager(config, backend=backend)
        _MANAGERS[key] = manager
    else:
        manager.attach_backend(backend)
    return manager, backend, launcher, ""


def _session_for(manager: Any, session_id: str, target: str) -> tuple[Any, str]:
    """Fetch a session and cross-check its target lock (BLOCKED on mismatch)."""
    from tools.browser.errors import BrowserSessionNotFound

    if not (session_id or "").strip():
        return None, "BLOCKED: session_id is required."
    try:
        session = manager.get_session(session_id.strip())
    except BrowserSessionNotFound:
        return None, f"ERROR: unknown browser session {session_id!r}."
    if target and session.target_ip and session.target_ip != target:
        return None, (
            f"BLOCKED: browser session {session_id!r} is locked to target {session.target_ip} (not {target})."
        )
    return session, ""


def _url_host_allowed(url: str, config: Any) -> str:
    """Return a BLOCKED reason when the URL's host is outside the allowlist."""
    try:
        host = urllib.parse.urlparse((url or "").strip()).hostname or ""
    except Exception:  # noqa: BLE001 — unparsable URL is a denial, not a crash  # ponytail: bare except intentional
        return f"BLOCKED: could not parse URL {url!r}."
    if not host:
        return f"BLOCKED: URL {url!r} has no host."
    allowed, reason = check_targets_allowlist([host], config)
    if not allowed:
        return f"BLOCKED: {reason}"
    return ""


def _browser_error_text(exc: BaseException, *, tool_name: str = "") -> str:
    """Render a typed browser failure as a model-readable result string."""
    from tools.browser.errors import BrowserBackendError, browser_error_from_exception
    from tools.sandbox.exceptions import SandboxError

    if isinstance(exc, SandboxError):
        return sandbox_error_block(exc, tool_name=tool_name or "browser")
    if isinstance(exc, BrowserBackendError):
        code, message = browser_error_from_exception(exc)
        prefix = "BLOCKED" if code in ("scope_blocked", "tool_unavailable") else "ERROR"
        lines = [f"{prefix}: {message}", f"FAILURE_CLASS: {code}"]
        if tool_name:
            lines.append(f"TOOL: {tool_name}")
        return "\n".join(lines)
    text = f"ERROR: browser operation failed: {exc}"
    if tool_name:
        text += f"\nTOOL: {tool_name}"
    return text


def _browser_result_error(result: Any, tool_name: str) -> str:
    """Render an unsuccessful BrowserResult as a model-readable result string."""
    err = getattr(result, "error", None)
    message = str(getattr(err, "message", "") or "browser operation failed")
    failure = getattr(err, "failure_class", None)
    code = str(getattr(failure, "value", "") or "unknown")
    prefix = "BLOCKED" if code in ("scope_blocked", "tool_unavailable") else "ERROR"
    return f"{prefix}: {message}\nFAILURE_CLASS: {code}\nTOOL: {tool_name}"


def _artifact_path(ctx: Any, session_id: str, name: str) -> str:
    workspace = getattr(ctx, "workspace", None)
    if workspace is None:
        return name
    return str(Path(workspace) / "browser" / session_id / name)


def register_browser_tools(mcp: Any, *, ctx: ToolContext) -> None:
    config = ctx.config
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist
    browser_cfg = _browser_cfg(config)
    if not bool(browser_cfg.get("enabled", False)):
        return
    if str(browser_cfg.get("backend", "none") or "none") != "playwright":
        return
    from tools.browser.capabilities import browser_runtime_available, register_playwright_backend

    register_playwright_backend(config)
    if not browser_runtime_available(config):
        return

    # ------------------------------------------------------------------
    # 1. browser_start
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_start(target: str, run_id: str = "", headless: bool = True) -> str:
        """Start a sandboxed Chromium session locked to the target. Returns SESSION_STARTED with the session id for browser_navigate/browser_observe/..."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        manager, _backend, launcher, block = _get_stack(ctx)
        if block:
            return block
        if getattr(launcher, "kind", "") == "sandbox_worker" and not headless:
            return "BLOCKED: headed Chromium needs a display; the sandbox worker is headless-only."
        try:
            session = _run(manager.start_session_async(target_ip=target, run_id=run_id, headless=headless))
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_start")
        return (
            f"SESSION_STARTED: {session.session_id}\n"
            f"TARGET: {session.target_ip}\nSTATE: {session.state.value}\nBACKEND: {session.backend_id}"
        )

    # ------------------------------------------------------------------
    # 2. browser_navigate
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_navigate(target: str, session_id: str, url: str, timeout_seconds: float = 30) -> str:
        """Navigate a browser session to a URL (redirect/SPA aware). The URL host must be allowlisted. Returns the final URL + status."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        if not (url or "").strip():
            return "BLOCKED: url is required."
        denied = _url_host_allowed(url, config)
        if denied:
            return denied
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            result = _run(
                manager.run_op(
                    _session.session_id,
                    "navigate",
                    run_id=_session.run_id,
                    url=url.strip(),
                    timeout_seconds=timeout_seconds,
                )
            )
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_navigate")
        meta = result.metadata or {}
        chain = meta.get("redirect_chain") or [url]
        lines = [
            f"NAVIGATED: {meta.get('final_url', url)}",
            f"STATUS: {meta.get('status_code')}",
            f"REDIRECTS: {' -> '.join(str(c) for c in chain)}",
        ]
        if meta.get("blocked_popups"):
            lines.append(f"BLOCKED_POPUPS: {meta['blocked_popups']}")
        lines.append("NEXT: browser_observe to harvest the page.")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 3. browser_observe
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_observe(
        target: str, session_id: str, include_forms: bool = True, include_endpoints: bool = True
    ) -> str:
        """Harvest a compact page snapshot: title/URL/DOM summary/forms/endpoints/scripts/framework indicators. Bounded; never raw HTML."""
        from tools.browser.models import _mask_body

        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            observation = _run(
                manager.run_op(
                    _session.session_id,
                    "observe",
                    run_id=_session.run_id,
                    include_forms=include_forms,
                    include_endpoints=include_endpoints,
                )
            )
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_observe")
        payload = dict(observation.payload or {})
        lines = [
            f"OBSERVED: {payload.get('final_url', '')}",
            f"TITLE: {payload.get('title', '')}",
            f"STATUS: {payload.get('status_code')}",
            f"DOM: {_mask_body(str(payload.get('dom_summary', '') or ''))}",
        ]
        forms = payload.get("forms") or []
        lines.append(f"FORMS: {len(forms)}")
        for form in forms[:10]:
            fields = ", ".join(str(i.get("name", "")) for i in (form.get("inputs") or [])[:8])
            lines.append(f"  - {form.get('method', 'get').upper()} {form.get('action', '')} [{fields}]")
        endpoints = payload.get("endpoints") or []
        lines.append(f"ENDPOINTS: {len(endpoints)}")
        for endpoint in endpoints[:20]:
            lines.append(f"  - {endpoint.get('method', '')} {endpoint.get('url', '')}")
        if payload.get("graphql_endpoints"):
            lines.append(f"GRAPHQL: {', '.join(str(g) for g in payload['graphql_endpoints'][:10])}")
        if payload.get("scripts"):
            lines.append(f"SCRIPTS: {len(payload['scripts'])}")
        if payload.get("indicators"):
            lines.append(f"INDICATORS: {', '.join(str(i) for i in payload['indicators'])}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 4. browser_page_state
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_page_state(target: str, session_id: str) -> str:
        """Lightweight page-state snapshot (URL/title/forms/endpoints) without a full observation drain."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            state = _run(manager.run_op(_session.session_id, "get_page_state", run_id=_session.run_id))
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_page_state")
        return (
            f"PAGE: {state.final_url or state.url}\n"
            f"TITLE: {state.title}\nSTATUS: {state.status_code}\n"
            f"FORMS: {len(state.forms)}  ENDPOINTS: {len(state.endpoints)}  "
            f"SCRIPTS: {len(state.scripts)}  INDICATORS: {', '.join(state.indicators)}"
        )

    # ------------------------------------------------------------------
    # 5. browser_network_events
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_network_events(target: str, session_id: str, limit: int = 100, after_id: str = "") -> str:
        """Captured request/response records (headers/body samples redacted). Paginate with limit/after_id."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            events = _run(
                manager.run_op(
                    _session.session_id,
                    "get_network_events",
                    run_id=_session.run_id,
                    limit=limit,
                    after_id=after_id,
                )
            )
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_network_events")
        lines = [f"NETWORK_EVENTS: {len(events)}"]
        for event in events[-50:]:
            red = event.to_redacted_dict()
            lines.append(
                f"  - [{red['event_id']}] {red['direction']} {red['method']} {red['url']} "
                f"status={red['status_code']} sha256={str(red['body_sha256'])[:12]}"
            )
        if events:
            lines.append(f"LAST_ID: {events[-1].event_id}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 6. browser_storage
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_storage(target: str, session_id: str, origin: str = "") -> str:
        """Cookies + localStorage/sessionStorage for the origin. Values are redacted; persist useful ones via cred_store_add explicitly."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            snapshot = _run(manager.run_op(_session.session_id, "get_storage", run_id=_session.run_id, origin=origin))
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_storage")
        redacted = snapshot.to_dict()
        lines = [f"STORAGE: origin={redacted['origin']} entries={len(redacted['entries'])}"]
        for entry in redacted["entries"][:30]:
            lines.append(f"  - {entry.get('key', '')} = {entry.get('value', '')}")
        lines.append("NOTE: values redacted. Persist useful credentials via cred_store_add (intentional harvest only).")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 7. browser_screenshot
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_screenshot(target: str, session_id: str) -> str:
        """Capture a viewport screenshot as a hashed artifact under the workspace."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        import uuid as _uuid

        artifact_path = _artifact_path(ctx, _session.session_id, f"screenshot-{_uuid.uuid4().hex[:8]}.png")
        try:
            artifact = _run(
                manager.run_op(
                    _session.session_id, "capture_screenshot", run_id=_session.run_id, artifact_path=artifact_path
                )
            )
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_screenshot")
        return (
            f"SCREENSHOT: {artifact.path}\nSHA256: {artifact.sha256}\nBYTES: {artifact.size_bytes}\n"
            f"EVIDENCE_REF: browser_artifact:{artifact.artifact_id}"
        )

    # ------------------------------------------------------------------
    # 8. browser_execute_js
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_execute_js(target: str, session_id: str, expression: str) -> str:
        """Execute JavaScript in the page and capture a bounded, redacted preview. Requires browser.allow_mutating_actions (lab opt-in)."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        if not bool(_browser_cfg(config).get("allow_mutating_actions", False)):
            return (
                "BLOCKED: browser_execute_js requires the explicit lab opt-in "
                "browser.allow_mutating_actions: true (arbitrary JS can mutate target state)."
            )
        if not (expression or "").strip():
            return "BLOCKED: expression is required."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            from tools.browser.models import BrowserAction, BrowserActionKind

            action = BrowserAction(
                action_id=f"a-{_session.session_id[-8:]}-js",
                session_id=_session.session_id,
                kind=BrowserActionKind.EXECUTE_JS,
                parameters={"expression": expression},
                run_id=_session.run_id,
                target_ip=target,
            )
            result = _run(manager.run_op(_session.session_id, "execute_action", run_id=_session.run_id, action=action))
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_execute_js")
        if not result.success:
            return _browser_error_text(
                Exception((result.error.message if result.error else "javascript failed")),  # noqa: BLE001
                tool_name="browser_execute_js",
            )
        meta = result.metadata or {}
        return f"JS_RESULT: {meta.get('return_preview', '')}\nTRUNCATED: {meta.get('truncated', False)}"

    # ------------------------------------------------------------------
    # 9/10. discovery
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_discover_forms(target: str, session_id: str) -> str:
        """Discover forms + fields on the live page (metadata fingerprints, no submission)."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            from tools.browser.models import BrowserAction, BrowserActionKind

            action = BrowserAction(
                action_id=f"a-{_session.session_id[-8:]}-df",
                session_id=_session.session_id,
                kind=BrowserActionKind.DISCOVER_FORMS,
                run_id=_session.run_id,
                target_ip=target,
            )
            result = _run(manager.run_op(_session.session_id, "execute_action", run_id=_session.run_id, action=action))
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_discover_forms")
        forms = (result.metadata or {}).get("forms") or []
        lines = [f"FORMS: {len(forms)}"]
        for form in forms[:20]:
            fields = ", ".join(str(i.get("name", "")) for i in (form.get("inputs") or [])[:10])
            lines.append(f"  - {form.get('method', 'get').upper()} {form.get('action', '')} [{fields}]")
        return "\n".join(lines)

    @mcp.tool()
    @require_allowlist("target")
    def browser_discover_endpoints(target: str, session_id: str) -> str:
        """Discover REST/GraphQL endpoints from captured traffic + script refs."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            from tools.browser.models import BrowserAction, BrowserActionKind

            action = BrowserAction(
                action_id=f"a-{_session.session_id[-8:]}-de",
                session_id=_session.session_id,
                kind=BrowserActionKind.DISCOVER_ENDPOINTS,
                run_id=_session.run_id,
                target_ip=target,
            )
            result = _run(manager.run_op(_session.session_id, "execute_action", run_id=_session.run_id, action=action))
        except Exception as exc:  # noqa: BLE001 — fail closed with a readable result  # ponytail: bare except intentional
            return _browser_error_text(exc, tool_name="browser_discover_endpoints")
        meta = result.metadata or {}
        endpoints = meta.get("endpoints") or []
        lines = [f"ENDPOINTS: {len(endpoints)}"]
        for endpoint in endpoints[:30]:
            lines.append(f"  - {endpoint.get('method', '')} {endpoint.get('url', '')}")
        if meta.get("graphql_endpoints"):
            lines.append(f"GRAPHQL: {', '.join(str(g) for g in meta['graphql_endpoints'][:10])}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 11. browser_close
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_close(target: str, session_id: str) -> str:
        """Hard-close a browser session (idempotent; releases worker resources)."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            awaitable = manager.close_session_async(_session.session_id, run_id=_session.run_id)
            _run(awaitable)
        except _EXC_GROUP_CATCH as exc:  # noqa: BLE001 — close never fails the run
            _log_nested_exceptions(exc)
            return _browser_error_text(exc, tool_name="browser_close")
        return f"SESSION_CLOSED: {_session.session_id}"

    # ------------------------------------------------------------------
    # 12. browser_submit (mutating: explicit lab opt-in)
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_submit(
        target: str, session_id: str, form_index: int = 0, field_values: dict[str, str] | None = None
    ) -> str:
        """Fill one live-page form by field name and submit it. The form's action host must be allowlisted. Requires browser.allow_mutating_actions."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        if not bool(_browser_cfg(config).get("allow_mutating_actions", False)):
            return (
                "BLOCKED: browser_submit requires the explicit lab opt-in "
                "browser.allow_mutating_actions: true (form submission mutates target state)."
            )
        if field_values is not None and not isinstance(field_values, dict):
            return "BLOCKED: field_values must be a {name: value} mapping."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        try:
            from tools.browser.models import BrowserAction, BrowserActionKind

            discover = BrowserAction(
                action_id=f"a-{_session.session_id[-8:]}-df",
                session_id=_session.session_id,
                kind=BrowserActionKind.DISCOVER_FORMS,
                run_id=_session.run_id,
                target_ip=target,
            )
            found = _run(manager.run_op(_session.session_id, "execute_action", run_id=_session.run_id, action=discover))
        except _EXC_GROUP_CATCH as exc:  # noqa: BLE001 — fail closed with a readable result
            _log_nested_exceptions(exc)
            return _browser_error_text(exc, tool_name="browser_submit")
        forms = (found.metadata or {}).get("forms") or []
        try:
            index = int(form_index)
        except (TypeError, ValueError):
            return f"BLOCKED: form_index must be an integer, got {form_index!r}."
        if index < 0 or index >= len(forms):
            return (
                f"BLOCKED: form index {index} out of range ({len(forms)} forms discovered). "
                "Discover forms via browser_discover_forms first."
            )
        page_url = str((found.metadata or {}).get("url", "") or "")
        action_url = urllib.parse.urljoin(page_url, str(forms[index].get("action", "") or ""))
        denied = _url_host_allowed(action_url, config)
        if denied:
            return denied
        try:
            from tools.browser.models import BrowserAction, BrowserActionKind

            submit = BrowserAction(
                action_id=f"a-{_session.session_id[-8:]}-sub",
                session_id=_session.session_id,
                kind=BrowserActionKind.SUBMIT_FORM,
                parameters={"form_index": index, "field_values": dict(field_values or {})},
                run_id=_session.run_id,
                target_ip=target,
            )
            result = _run(manager.run_op(_session.session_id, "execute_action", run_id=_session.run_id, action=submit))
        except _EXC_GROUP_CATCH as exc:  # noqa: BLE001 — fail closed with a readable result
            _log_nested_exceptions(exc)
            return _browser_error_text(exc, tool_name="browser_submit")
        if not result.success:
            return _browser_result_error(result, "browser_submit")
        meta = result.metadata or {}
        return (
            f"SUBMITTED: {meta.get('final_url', '')}\n"
            f"STATUS: {meta.get('status_code')}\n"
            f"FORM: {str(meta.get('form_method', '')).upper()} {meta.get('form_action', '')}\n"
            f"FILLED: {meta.get('filled_fields', 0)} fields\n"
            f"NETWORK_EVENTS: {meta.get('captured_events', 0)} captured\n"
            "NEXT: browser_observe to harvest the result page."
        )

    # ------------------------------------------------------------------
    # 13. browser_replay (mutating: explicit lab opt-in)
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("target")
    def browser_replay(
        target: str,
        session_id: str,
        url: str = "",
        event_id: str = "",
        method: str = "",
        headers_json: str = "",
        body: str = "",
    ) -> str:
        """Replay one HTTP request through the session (captured event_id as base, explicit url/method/headers/body override). The final URL host must be allowlisted. Requires browser.allow_mutating_actions."""
        if not validate_target_or_ip(target):
            return "BLOCKED: invalid target (IP or domain)."
        if not bool(_browser_cfg(config).get("allow_mutating_actions", False)):
            return (
                "BLOCKED: browser_replay requires the explicit lab opt-in "
                "browser.allow_mutating_actions: true (request replay mutates target state)."
            )
        try:
            extra_headers = json.loads(headers_json) if (headers_json or "").strip() else {}
        except (json.JSONDecodeError, TypeError, ValueError):
            return "BLOCKED: headers_json must be a JSON object."
        if not isinstance(extra_headers, dict):
            return "BLOCKED: headers_json must be a JSON object."
        manager, _backend, _launcher, block = _get_stack(ctx)
        if block:
            return block
        _session, problem = _session_for(manager, session_id, target)
        if problem:
            return problem
        base_url, base_method, base_headers = "", "", {}
        if (event_id or "").strip():
            try:
                events = _run(
                    manager.run_op(
                        _session.session_id, "get_network_events", run_id=_session.run_id, limit=500, after_id=""
                    )
                )
            except _EXC_GROUP_CATCH as exc:  # noqa: BLE001 — fail closed with a readable result
                _log_nested_exceptions(exc)
                return _browser_error_text(exc, tool_name="browser_replay")
            match = next((e for e in (events or []) if e.event_id == event_id.strip()), None)
            if match is None:
                return (
                    f"ERROR: unknown network event {event_id.strip()!r} for this session. "
                    "List events via browser_network_events first."
                )
            if not bool(getattr(match, "replayable", False)):
                return (
                    f"BLOCKED: network event {event_id.strip()!r} is not replayable "
                    "(non-HTTP(S) scheme or unparsable URL — only http/https events replay)."
                )
            base_url = match.url
            base_method = match.method or "GET"
            base_headers = dict(match.request_headers or {})
        final_url = (url or "").strip() or base_url
        if not final_url:
            return "BLOCKED: url or a captured event_id is required."
        denied = _url_host_allowed(final_url, config)
        if denied:
            return denied
        headers = dict(base_headers)
        headers.update({str(k): str(v) for k, v in extra_headers.items()})
        try:
            from tools.browser.models import BrowserAction, BrowserActionKind

            replay = BrowserAction(
                action_id=f"a-{_session.session_id[-8:]}-rep",
                session_id=_session.session_id,
                kind=BrowserActionKind.REPLAY_REQUEST,
                parameters={
                    "url": final_url,
                    "method": (method or "").strip() or base_method or "GET",
                    "headers": headers,
                    "body": body or "",
                },
                run_id=_session.run_id,
                target_ip=target,
            )
            result = _run(manager.run_op(_session.session_id, "execute_action", run_id=_session.run_id, action=replay))
        except _EXC_GROUP_CATCH as exc:  # noqa: BLE001 — fail closed with a readable result
            _log_nested_exceptions(exc)
            return _browser_error_text(exc, tool_name="browser_replay")
        if not result.success:
            return _browser_result_error(result, "browser_replay")
        meta = result.metadata or {}
        return (
            f"REPLAYED: {meta.get('method', '')} {meta.get('url', '')}\n"
            f"STATUS: {meta.get('status_code')}\n"
            f"SHA256: {meta.get('body_sha256', '')}\n"
            f"PREVIEW: {meta.get('body_preview', '')}\n"
            f"TRUNCATED: {meta.get('truncated', False)}"
        )


__all__ = ["register_browser_tools"]
