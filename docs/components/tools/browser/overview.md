---
title: Browser — Overview
package: tools/browser
files: [manager.py, interfaces.py, models.py, capabilities.py, errors.py]
---

# Browser — Overview (`tools/browser/`)

Fail-closed browser session ownership: `BrowserManager` owns lifecycle and metadata, `BrowserBackend` is the only engine seam, `models.py` is the shared vocabulary. With the stock config (`browser.enabled: false`, `backend: none`) every path fails closed — nothing launches, nothing pretends a browser exists.

## Package map

| File | LOC | Role |
|---|---|---|
| `manager.py` | 417 | `BrowserManager` — session registry + lifecycle validator + async execution funnel |
| `interfaces.py` | 136 | `BrowserBackend` ABC — the only seam browser control may cross |
| `models.py` | 928 | Pure-data domain models, enums, transition map, redaction |
| `capabilities.py` | 243 | `browser.*` capability vocabulary + availability rule + backend registry |
| `errors.py` | 141 | Typed fail-closed exception hierarchy |
| `playwright_backend.py`, `sandbox_launcher.py`, `_pw_probe.py` | — | Playwright engine + sandboxed launcher + probes (Implementation note: not read for this pass; see `docs/browser-agent-design.md` for the contract they implement) |

## Architecture

```
agent ──► tools/mcp_tools/browser.py ──► BrowserManager ──► BrowserBackend ──► Chromium
  (@require_allowlist        (transitions +          (engine adapter,
   target lock)               ownership guards)       never policy)
```

- The manager MAY validate transitions, allocate ids, hold metadata, track ownership by run id, and drive the async funnel. It MUST NOT launch browsers, open sockets, visit URLs, or run JS — every capability delegates to the injected backend (`manager.py:15-25`).
- The backend never touches the allowlist; the MCP layer calling the funnel is target-locked and sandboxed (`interfaces.py:46-51`).
- Stock builds have no backend injected, so `available()` is never true and every action raises `BrowserBackendUnavailable`.

## `manager.py` — `BrowserManager`

```python
def __init__(self, config: dict[str, Any] | None = None, *, backend: BrowserBackend | None = None) -> None
```

| Symbol | Kind | Description |
|---|---|---|
| `config` / `backend` / `backend_id` | property | Effective `browser` block; injected backend; configured backend id (`"none"` default) |
| `attach_backend(backend)` | def | (Re)attach engine backend; sessions survive the swap |
| `available()` | def | `backend is not None and enabled` — never true for stock builds |
| `availability()` | def | Secret-free `{enabled, backend, available, max_sessions, session_timeout_seconds}` report block |
| `get_session(session_id)` | def | Registry lookup; raises `BrowserSessionNotFound` |
| `sessions_metadata()` / `sessions_for_run(run_id)` | def | Serialized registry snapshots via `BrowserSession.to_dict()` |
| `start_session(*, target_ip, run_id="", original_target="", metadata=None)` | def | Availability + target + `max_sessions` checks, then allocates a `PENDING` record (fails closed otherwise) |
| `transition(session_id, new_state)` | def | Validate + apply one lifecycle transition |
| `mark_ready` / `mark_failed` | def | Shorthands to `READY` / `FAILED` |
| `stop_session(session_id)` | def | To `STOPPING` (idempotent on terminal states) |
| `close_session(session_id)` | def | Terminal close via `STOPPING → CLOSED` |
| `delegate_to_backend(...)` | def | Deprecated sync shim — always raises; new code must `await run_op(...)` |
| `start_session_async(*, target_ip, run_id="", original_target="", metadata=None, headless=True)` | async | Allocate `PENDING → STARTING`, drive `backend.start_session(...)` under `session_timeout_seconds`, merge record, `mark_ready`; any failure marks `FAILED` |
| `run_op(session_id, op, *, run_id="", timeout_seconds=None, **kwargs)` | async | Ownership + state guard, `READY/SUSPENDED → ACTIVE → READY` around one backend coroutine; `transport_error` marks `FAILED`, timeouts return to `READY` |
| `close_session_async(session_id, *, run_id="")` | async | Best-effort backend `stop_session` + `close`, then metadata `STOPPING → CLOSED` |
| `close_all_for_run(run_id)` | async | Deterministic per-run cleanup sweep |
| `idle_sessions(*, now=None)` / `reap_idle()` | def/async | Ids idle beyond `session_timeout_seconds`; opportunistic close on session start |

`op` names a `BrowserBackend` coroutine (`navigate`, `observe`, `execute_action`, `capture_screenshot`, `get_network_events`, `get_storage`, `get_page_state`). Per-session `asyncio.Lock` serializes ops; `_sync_last_url` best-effort mirrors the live URL onto the record.

## `interfaces.py` — `BrowserBackend`

```python
class BrowserBackend(ABC):
    backend_id: str = ""
    display_name: str = ""
    capabilities: tuple[str, ...] = ()

    def is_configured(self, config: dict[str, Any] | None) -> bool: ...
    def health(self, config: dict[str, Any] | None) -> dict[str, Any]: ...
    async def start_session(self, *, target, run_id="", session_id="", headless=True, metadata=None) -> BrowserSession: ...
    async def stop_session(self, session_id: str) -> BrowserResult: ...
    async def navigate(self, session_id: str, url: str, *, timeout_seconds=None) -> BrowserResult: ...
    async def observe(self, session_id: str, *, include_forms=True, include_endpoints=True) -> BrowserObservation: ...
    async def execute_action(self, session_id: str, action: BrowserAction) -> BrowserResult: ...
    async def capture_screenshot(self, session_id: str, *, artifact_path="") -> BrowserArtifact: ...
    async def get_network_events(self, session_id: str, *, limit=100, after_id="") -> list[BrowserNetworkEvent]: ...
    async def get_storage(self, session_id: str, *, origin="") -> BrowserStorageSnapshot: ...
    async def get_page_state(self, session_id: str) -> BrowserPageState: ...
    async def close(self, session_id: str) -> BrowserResult: ...
```

All operations are `@abstractmethod` (no executable defaults); only metadata probes (`is_configured`/`health`) have bodies. Methods return `models.*` types only — no Playwright/Selenium/CDP object may leak across the seam.

## `models.py` — vocabulary

| Symbol | Kind | Description |
|---|---|---|
| `BrowserSessionState` | enum | `pending → starting → ready ↔ active`, `suspended`, `stopping → closed/failed` (terminal) |
| `_ALLOWED_SESSION_TRANSITIONS` | map | Explicit transition table; enforced by `validate_session_transition(current, new)` (raises `BrowserTransitionError`) |
| `BrowserActionKind` | enum | 12 kinds: `navigate/observe/execute_js/screenshot/get_network_events/get_storage/discover_forms/discover_endpoints/replay_request/submit_form/wait/close` (mutating kinds additionally gated by `browser.allow_mutating_actions`) |
| `BrowserObservationKind` | enum | 9 kinds: `page_state/dom/forms/endpoints/network/storage/console/screenshot/scripts` |
| `BrowserFailureClass` | enum | Overlaps reuse exact global `FailureClass` strings; `failure_class()` maps to the global taxonomy (`None` = browser-only) |
| `BrowserSession` | dataclass | Metadata only, never a live handle; `to_dict`/`from_dict` round-trip |
| `BrowserAction` | dataclass | `action_id/session_id/kind/parameters/run_id/target_ip` — the audit+evidence anchor |
| `BrowserResult` | dataclass | `success/failure_class/retryable/confidence/produced_artifacts/evidence_refs/follow_ups/error/metadata` |
| `BrowserError` | dataclass | Serializable failure payload (NOT the exception; exceptions live in `errors.py`) |
| `BrowserObservation` | dataclass | `to_dict` (full), `to_redacted_dict` (payload masked when `sensitive`), `to_audit_dict` (payload dropped — keys digest + counts only) |
| `BrowserPageState` | dataclass | Planning surface: url/final_url, forms, endpoints, scripts, indicators, `graphql_endpoints`; never raw HTML |
| `BrowserNetworkEvent` | dataclass | Headers/digests/timing + truncated `body_sample`; `to_redacted_dict` masks secret headers wholesale |
| `BrowserCookie` / `BrowserStorageSnapshot` | dataclass | Values redacted by default; raw only via explicit `to_dict(redact=False)` credential-store path |
| `BrowserArtifact` | dataclass | Persisted artifact with sha256; `evidence_type` maps to legacy EvidenceStore buckets |
| `new_session_id(seq)` | def | `bs-<seq>-<rand12>` non-guessable id |
| `redact_value(value)` | def | Structural masking over kernel `tools.kernel.audit` content table + browser key vocabulary |

Serialization is deterministic (hand-rolled field-order dicts) and tolerant on read (unknown enums → safe defaults).

## `capabilities.py` — declared ≠ available

10 stable `browser.*` names (`navigate`, `dom.inspect`, `javascript.execute`, `network.observe`, `network.replay`, `storage.read`, `form.inspect`, `form.submit`, `screenshot`, `endpoint.discover`), each with `description` + `read_only` planner hint.

```
available = browser.enabled AND backend != "none"
            AND backend in BACKEND_REGISTRY
            AND (BACKEND_REGISTRY[backend].is_configured(...) OR sandbox worker configured)
```

| Symbol | Kind | Description |
|---|---|---|
| `BROWSER_CAPABILITIES` | dict | Name → `BrowserCapability` declaration-ordered vocabulary |
| `BACKEND_REGISTRY` | dict | Registered backends; empty until `register_playwright_backend(config)` runs at call time (never import) |
| `browser_runtime_available(config)` | def | The single availability rule above |
| `browser_capabilities(config)` | def | Machine-readable `{name, description, read_only, available}` records |
| `browser_available(config)` | def | Whether ANY browser op can run |
| `unmet_requirements(required, config)` | def | Benchmark `requires_capabilities` classification (unknown names always unmet) |

## `errors.py` — failure taxonomy

`BrowserBackendError` (base, `.code`) → `BrowserBackendUnavailable` (`tool_unavailable`), `BrowserBackendNotImplemented`, `BrowserTransitionError` (`invalid_transition`), `BrowserSessionNotFound` (`session_not_found`), `BrowserTimeout` (`timeout`), `BrowserNavigationFailed` (`navigation_failed`), `BrowserCrashed` (`transport_error`, marks session `FAILED`), `BrowserScopeBlocked` (`scope_blocked`), `BrowserScriptError` (`script_error`). `browser_error_from_exception(exc)` maps any exception to `(failure_class_value, message)` for result blocks.

## Lifecycle

```
PENDING → STARTING → READY ⇄ ACTIVE
               ↓         ↓      ↓
            FAILED    SUSPENDED STOPPING → CLOSED / FAILED
```

`start_session_async` drives `PENDING → STARTING → READY`; `run_op` wraps each op in `READY/SUSPENDED → ACTIVE → READY`; `close_session_async` ends in `CLOSED` (or `FAILED` when the backend crashed). `reap_idle` closes sessions idle beyond `session_timeout_seconds` on every start.

## MCP surface (`tools/mcp_tools/browser.py`)

Registered only when `browser.enabled` + `backend: playwright` + `browser_runtime_available(config)` (all three, else the module registers nothing).

| Tool | Signature | Notes |
|---|---|---|
| `browser_start` | `(target, run_id="", headless=True)` | `start_session_async`; sandbox worker is headless-only |
| `browser_navigate` | `(target, session_id, url, timeout_seconds=30)` | URL host re-checked against allowlist |
| `browser_observe` | `(target, session_id, include_forms=True, include_endpoints=True)` | Bounded snapshot, never raw HTML |
| `browser_page_state` | `(target, session_id)` | Lightweight state without full observation drain |
| `browser_network_events` | `(target, session_id, limit=100, after_id="")` | Redacted records, paginated |
| `browser_storage` | `(target, session_id, origin="")` | Values redacted; persist via `cred_store_add` explicitly |
| `browser_screenshot` | `(target, session_id)` | Hashed artifact, `browser_artifact:<id>` evidence ref |
| `browser_discover_forms` | `(target, session_id)` | Metadata fingerprints, no submission |
| `browser_discover_endpoints` | `(target, session_id)` | REST/GraphQL from traffic + script refs |
| `browser_execute_js` | `(target, session_id, expression)` | Requires `browser.allow_mutating_actions` |
| `browser_submit` | `(target, session_id, form_index=0, field_values=None)` | Requires `browser.allow_mutating_actions`; form-action host re-checked |
| `browser_replay` | `(target, session_id, url="", event_id="", method="", headers_json="", body="")` | Requires `browser.allow_mutating_actions`; final URL host re-checked |
| `browser_close` | `(target, session_id)` | Idempotent hard close |

## Config keys (`browser:` block)

| Key | Default | Effect |
|---|---|---|
| `browser.enabled` | `false` | Master switch — stock installs never enable |
| `browser.backend` | `"none"` | `none` \| `playwright` (declared ≠ available) |
| `browser.headless` | `true` | Headless Chromium |
| `browser.max_sessions` | `2` | Registry cap; excess starts fail closed |
| `browser.session_timeout_seconds` | `300` | Op bound + idle-reap horizon |
| `browser.navigation_timeout_seconds` | `30` | Navigate bound |
| `browser.capture_screenshots` / `capture_network` / `capture_console` | `true/true/false` | Evidence capture toggles |
| `browser.persist_storage` | `false` | Storage harvest goes to credential store, never plaintext logs |
| `browser.allow_mutating_actions` | `false` | Lab opt-in for `execute_js` + `submit` + `replay` (read-only otherwise) |
| `browser.console_max_events` / `network_max_events` / `body_sample_max_bytes` / `dom_summary_max_chars` | `200/500/4096/8000` | Prompt-size bounds |
| `browser.artifact_dir` / `executable_path` / `worker_image` | `""` | Overrides; empty = workspace default / Playwright default / `breachpilot-sandbox:browser` |

## Example

```python
manager = BrowserManager(config, backend=playwright_backend)
session = await manager.start_session_async(target_ip="10.0.0.50", run_id="run-1")
result = await manager.run_op(session.session_id, "navigate", url="http://10.0.0.50/")
obs = await manager.run_op(session.session_id, "observe")
await manager.close_session_async(session.session_id)
```

## Tests (selected)

| File | Covers |
|---|---|
| `tests/test_browser_manager.py`, `test_browser_manager_async.py` | Lifecycle transitions, fail-closed starts, async funnel |
| `tests/test_browser_models.py` | Serialization round-trips, tolerant readers |
| `tests/test_browser_backend_contract.py` | ABC has no executable defaults |
| `tests/test_browser_capabilities.py` | Declared-≠-available rule, `unmet_requirements` |
| `tests/test_browser_audit_redaction.py` | Canary secrets never leak through serialization surfaces |
| `tests/test_browser_mcp_tools.py`, `test_browser_attack.py` | MCP gating incl. `allow_mutating_actions` |
| `tests/test_browser_config_defaults.py`, `test_doctor_browser.py`, `test_api_capabilities_browser.py` | Config defaults, doctor, `/capabilities` block |

## Related documentation

- [Browser agent design](../../../browser-agent-design.md)
- [Configuration overview](../../../configuration/overview.md)
- [Kernel overview](../kernel/overview.md)
- [MCP tools](../../../mcp-tools.md)
- [Safety model](../../../safety-model.md)

## Source map

- `tools/browser/manager.py`
- `tools/browser/interfaces.py`
- `tools/browser/models.py`
- `tools/browser/capabilities.py`
- `tools/browser/errors.py`
- `tools/mcp_tools/browser.py`
- `docs/browser-agent-design.md`
