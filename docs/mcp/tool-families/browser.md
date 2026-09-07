---
title: "Tool Family: browser"
sources:
  - tools/mcp_tools/browser.py
  - tools/browser/manager.py
  - tools/browser/capabilities.py
  - tools/browser/playwright_backend.py
  - tools/browser/sandbox_launcher.py
  - tools/browser/errors.py
  - tools/browser/models.py
  - tools/mcp_shared.py
  - tools/validation_utils.py
tests:
  - tests/test_browser_mcp_tools.py
  - tests/test_browser_manager.py
  - tests/test_browser_capabilities.py
  - tests/test_browser_sandbox_family.py
subsystem: mcp
---

# Tool Family: browser

Sandboxed Chromium web agent (Playwright backend) for authorized testing of web targets the operator owns or has explicit written authorization to assess. Phase 1 surface is read-only (start/navigate/observe/page-state/network/storage/screenshot/discover/close); the Phase 2 mutating surface (`browser_submit`, `browser_replay`, `browser_execute_js`) sits behind the explicit lab opt-in `browser.allow_mutating_actions`.

- **Registration source:** `register_browser_tools(mcp, *, ctx)` in `tools/mcp_tools/browser.py:185` — discovered via `collect_tools()` / `register_*_tools` naming; no edit to `mcp_exploit_server.py` needed.
- **Enablement gate (all three must hold, `browser.py:190-198`):** `browser.enabled` is true, `browser.backend` is `"playwright"`, and `browser_runtime_available(config)` is true (host SDK or a configured sandbox worker). Otherwise nothing registers — the killchain/snapshots conditional-registration precedent.
- **Containment:** every target-touching tool carries `@require_allowlist("target")`; Chromium execution funnels through `BrowserManager` plus a per-call launcher — `SandboxPlaywrightLauncher` (one Chromium op per docker exec inside the worker netns) when the sandbox is enabled, the in-process launcher only for the documented `sandbox.enabled: false` opt-out. When the sandbox is enabled but unusable the tools return `SANDBOX_*` blocks and never fall back to host execution.

```yaml
# config.yaml (browser block, lines 299-317)
browser:
  enabled: true
  backend: playwright
  headless: true
  max_sessions: 2
  session_timeout_seconds: 300
  navigation_timeout_seconds: 30
  capture_screenshots: true
  capture_network: true
  capture_console: false
  persist_storage: false
  allow_mutating_actions: false
```

## Tools Exported (13)

Gate column notes the decorator plus any extra in-body gate. Implementation note: `ctx.audit_tool` is fetched at `browser.py:187` but `@audit_tool` is not applied to any tool in this module — the per-tool gate is `@require_allowlist("target")` alone.

| Tool | Purpose | Key inputs | Gate | Common failures |
|------|---------|------------|------|-----------------|
| `browser_start` | Start a sandboxed Chromium session locked to the target; returns `SESSION_STARTED` with the session id | `target: str`, `run_id: str = ""`, `headless: bool = True` | `@require_allowlist("target")` | `BLOCKED: invalid target`; `BLOCKED: headed Chromium needs a display` (sandbox worker is headless-only) |
| `browser_navigate` | Navigate a session to a URL (redirect/SPA aware); URL host must be allowlisted | `target`, `session_id`, `url`, `timeout_seconds: float = 30` | `@require_allowlist("target")` + `_url_host_allowed` | `BLOCKED: url is required`; `BLOCKED` when URL host is outside the allowlist; session-lock mismatch |
| `browser_observe` | Compact page snapshot: title/URL/DOM summary/forms/endpoints/scripts/framework indicators; bounded, never raw HTML | `target`, `session_id`, `include_forms: bool = True`, `include_endpoints: bool = True` | `@require_allowlist("target")` | `ERROR: unknown browser session`; session-lock mismatch |
| `browser_page_state` | Lightweight page-state snapshot (URL/title/forms/endpoints) without a full observation drain | `target`, `session_id` | `@require_allowlist("target")` | Same session failures as `browser_observe` |
| `browser_network_events` | Captured request/response records (headers/body samples redacted); paginate with `limit`/`after_id` | `target`, `session_id`, `limit: int = 100`, `after_id: str = ""` | `@require_allowlist("target")` | Same session failures; unknown `after_id` yields an empty page, not an error |
| `browser_storage` | Cookies + localStorage/sessionStorage for the origin; values redacted | `target`, `session_id`, `origin: str = ""` | `@require_allowlist("target")` | Same session failures |
| `browser_screenshot` | Viewport screenshot as a hashed artifact under the workspace | `target`, `session_id` | `@require_allowlist("target")` | Same session failures; sandbox/artifact write errors surface as `SANDBOX_*`/`ERROR` |
| `browser_execute_js` | Execute JavaScript in the page; bounded, redacted preview | `target`, `session_id`, `expression: str` | `@require_allowlist("target")` + `allow_mutating_actions` opt-in | `BLOCKED: browser_execute_js requires ... browser.allow_mutating_actions: true`; `BLOCKED: expression is required` |
| `browser_discover_forms` | Discover forms + fields on the live page (metadata fingerprints, no submission) | `target`, `session_id` | `@require_allowlist("target")` | Same session failures |
| `browser_discover_endpoints` | Discover REST/GraphQL endpoints from captured traffic + script refs | `target`, `session_id` | `@require_allowlist("target")` | Same session failures |
| `browser_close` | Hard-close a session (idempotent; releases worker resources) | `target`, `session_id` | `@require_allowlist("target")` | Close never fails the run — exceptions are logged via `_log_nested_exceptions` and rendered, not raised |
| `browser_submit` | Fill one live-page form by field name and submit it | `target`, `session_id`, `form_index: int = 0`, `field_values: dict[str, str] \| None = None` | `@require_allowlist("target")` + `allow_mutating_actions` opt-in + form-action host allowlist | Mutating opt-in `BLOCKED`; `BLOCKED: field_values must be a {name: value} mapping`; `BLOCKED: form index N out of range`; `BLOCKED` when the form action host is outside the allowlist |
| `browser_replay` | Replay one HTTP request through the session (captured `event_id` as base, explicit url/method/headers/body override) | `target`, `session_id`, `url: str = ""`, `event_id: str = ""`, `method: str = ""`, `headers_json: str = ""`, `body: str = ""` | `@require_allowlist("target")` + `allow_mutating_actions` opt-in + final-URL host allowlist | Mutating opt-in `BLOCKED`; `BLOCKED: headers_json must be a JSON object`; `BLOCKED: url or a captured event_id is required`; `ERROR: unknown network event` |

### Result shape — common

```text
SESSION_STARTED: <session_id>
TARGET: 127.0.0.1
STATE: <state>
BACKEND: <backend_id>
```

- Every `target` is validated with `validate_target_or_ip` → `BLOCKED: invalid target (IP or domain).`
- Every `session_id` goes through `_session_for` (`browser.py:117-131`): empty id → `BLOCKED: session_id is required.`; unknown id → `ERROR: unknown browser session ...`; target mismatch → `BLOCKED: browser session ... is locked to target ...`.
- Typed failures render via `_browser_error_text` / `_browser_result_error` as `BLOCKED|ERROR: <message>` plus `FAILURE_CLASS: <code>` and `TOOL: <tool_name>` lines; `scope_blocked` / `tool_unavailable` map to the `BLOCKED` prefix.
- Observation results are bounded: last 50 network events shown, first 10 forms / 20 endpoints in `browser_observe`, first 30 storage entries, DOM masked via `_mask_body`.

## Session model

- **Per-workspace caching:** managers, backends, and launchers are cached in `_MANAGERS` / `_BACKENDS` / `_LAUNCHERS` keyed by `ctx.workspace` (`browser.py:36-43`), so sessions survive across tool calls. Only successful launcher resolutions are cached — a `SANDBOX_*` block is returned uncached so the next call re-probes sandbox health.
- **Single event loop:** all browser coroutines run on one private daemon-thread loop (`_get_browser_loop`, `browser.py:50-67`; the swarm_bridge / exploit_agent precedent) because Playwright connections bind to the loop that created them — an `asyncio.run`-per-call pattern would break every op after `browser_start`. A dead loop thread is replaced, never reused; `_run` blocks the calling MCP worker thread on the coroutine result.
- **Session target lock:** each session is locked to its start target (`session.target_ip`); every later tool re-checks `target` against the lock and returns `BLOCKED` on mismatch, independent of the decorator-level allowlist.
- **Screenshots:** written to `<workspace>/browser/<session_id>/screenshot-<8 hex>.png` (`_artifact_path`, `browser.py:178-182`) and returned as `SCREENSHOT` / `SHA256` / `BYTES` / `EVIDENCE_REF: browser_artifact:<id>`.

## Safety notes

Authorized testing only — every tool is target-locked twice (decorator allowlist on `target`, plus the session lock and, for navigate/submit/replay, a URL-host allowlist check on the exact host touched).

- **Read vs mutate split:** observation and discovery tools never change target state. `browser_execute_js`, `browser_submit`, and `browser_replay` each hard-require `browser.allow_mutating_actions: true` (default false) and say so in their `BLOCKED` text — arbitrary JS, form submission, and request replay can mutate the target.
- **Redaction by default:** network headers/body samples render redacted with only a body `sha256` prefix; storage values render redacted with a pointer to persist useful credentials explicitly via `cred_store_add`; DOM output is masked via `_mask_body`.
- **Fail closed:** sandbox-unusable returns `SANDBOX_*` blocks with no host-execution fallback; unparsable URLs are denials (`BLOCKED: could not parse URL`), not crashes; replay defaults the method to the captured event's method or `GET`, and submit re-discovers forms live so a stale `form_index` is a `BLOCKED` range error rather than a blind submit.
- **Loopback-only examples:** use `http://127.0.0.1/` or `http://localhost/` targets (e.g. `browser_navigate` with `url` `http://127.0.0.1/login`) — never real third-party hosts.

## Related documentation

- [MCP security](../security.md) — allowlist / target-lock model
- [MCP registration](../registration.md) — decorator and discovery contract
- [Browser agent design](../../browser-agent-design.md) —end-to-end agent behavior
- [Sandbox](../../sandbox.md) — disposable execution worker and fail-closed rule
- [Safety model](../../safety-model.md) — authorized-testing posture

## Source map

- `tools/mcp_tools/browser.py` — `register_browser_tools`, all 13 tools, `_get_stack`, `_session_for`, `_url_host_allowed`, error renderers
- `config.yaml` — `browser.*` settings (lines 299-317)
- `tools/browser/manager.py` — `BrowserManager` session lifecycle (imported by `_get_stack`)
- `tools/browser/capabilities.py` — `register_playwright_backend`, `browser_runtime_available`, `get_backend`
- `tools/browser/playwright_backend.py` — `PlaywrightBackend` engine
- `tools/browser/sandbox_launcher.py` — `resolve_browser_launcher` (sandbox worker vs in-process)
- `tools/browser/errors.py` — `BrowserSessionNotFound`, `BrowserBackendError`, `browser_error_from_exception`
- `tools/browser/models.py` — `BrowserAction`, `BrowserActionKind`, `_mask_body`
- `tools/mcp_shared.py` — `check_targets_allowlist`
- `tools/validation_utils.py` — `validate_target_or_ip`
- `tools/exceptions.py` — `_EXC_GROUP_CATCH`, `_log_nested_exceptions`
- `tools/mcp_tools/registry.py` — `ToolContext` (`audit_tool`, `require_allowlist`)
- `tools/mcp_tools/sandbox_exec.py` — `sandbox_error_block`
- `tools/sandbox/exceptions.py` — `SandboxError`
