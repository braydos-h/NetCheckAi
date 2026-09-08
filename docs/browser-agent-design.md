# Browser-Native Web Agent — Architecture & Integration Design

> **Status: implemented (Phase 1 read-only + Phase 2 mutating).** The Playwright backend behind the
> prepared interfaces is live: `tools/browser/playwright_backend.py` (Chromium via
> the optional `browser` extra), `tools/browser/sandbox_launcher.py` (one Chromium
> op per docker exec inside the worker netns — no host fallback), the async
> `BrowserManager` funnel, conditional `tools/mcp_tools/browser.py` tools, gated
> planner briefings, and doctor/API/config plumbing. Request replay
> (`browser_replay`: captured `event_id` as base, explicit url/method/headers/body
> overrides, final URL host re-checked) and form submission (`browser_submit`:
> fill by field name + submit, form-action host re-checked) are live behind the
> explicit lab opt-in `browser.allow_mutating_actions` (default off — without it
> both return `BLOCKED`). Playwright is importable only
> inside the engine boundary (enforced by `tests/test_no_playwright_regression.py`).

This document is the contract the implementation followed (originally written
for the PR *"Implement Playwright BrowserBackend behind the prepared browser
interfaces"*): the engine landed without replacing the domain vocabulary, the
manager boundary, the capability names, or the audit shape. Two deliberate
deviations from the §11 sketch: the backend lives at
`tools/browser/playwright_backend.py` (flat, per repo layout — not
`tools/browser/backends/`), and availability additionally accepts a configured
sandbox worker as a runnable home (host SDK not required when contained).

---

## 1. Why a browser seam at all

Modern web targets are JS-first: SPAs render after navigation, auth flows live
in cookies/`localStorage`/bearer headers, endpoints hide behind bundles. A
terminal-only agent cannot even *load* the app. The browser agent extends
BreachPilot with an authenticated, observed, evidence-producing browser view of
the locked target — under the same policy regime as every other tool:

- target-IP allowlist lock (`@require_allowlist` / `_target_lock_block`),
- mission ScopeGate consult,
- sandbox containment (future: browser worker),
- full JSONL audit + evidence traceability,
- secrets never in plaintext logs.

The non-goals of the seam are as important as the goals. It is NOT shell
escape, NOT a path around the sandbox, and NOT a replacement for
`run_web_scan`: the browser adds *session-aware* interaction (navigate →
observe → optionally act) on top of structured scanning.

## 2. Added now vs deferred vs future-backend

| Concern | State in this change | Where it lives |
|---|---|---|
| Domain models (session/action/observation/artifact/network/storage/result) | **Added** — pure data, deterministic serialization | `tools/browser/models.py` |
| `BrowserBackend` ABC (the one seam) | **Added** — abstract, 10 operations, no executable defaults | `tools/browser/interfaces.py` |
| `BrowserManager` (registry + lifecycle + fail-closed) | **Added** — metadata only, cannot execute | `tools/browser/manager.py` |
| Failure taxonomy mapping to global `FailureClass` | **Added** | `tools/browser/models.py` |
| `browser.*` capability vocabulary + availability rule | **Added** — all unavailable | `tools/browser/capabilities.py` |
| Config block `browser:` | **Added** — `enabled: false`, `backend: none` | `tools/config/schema.py`, `config.yaml` |
| `/api/v1/capabilities` browser status block | **Added** — metadata only, `available: false` | `tools/api/routes/system.py` |
| Benchmark `requires_capabilities` scenario metadata | **Added** — schema + detection only | `tools/benchmark/models.py`, `tools/benchmark/xben/manifest.py` |
| Sandbox family audit — browser registered as **planned** | **Added** | `tools/sandbox/family_audit.py` (`PLANNED_FAMILIES`) |
| Secret-redaction rules for browser material | **Added** — redacted-by-default serialization | `tools/browser/models.py` |
| Any browser subprocess / launch / navigation / JS execution | **Added** — Playwright backend, fail-closed when unconfigured | `tools/browser/playwright_backend.py`, `tools/browser/manager.py` |
| Backend registry entry | **Added** — `BACKEND_REGISTRY` + `register_playwright_backend` (call-time, never import-time) | `tools/browser/capabilities.py` |
| Playwright dependency, browser worker sandboxing, WebSocket/CDP transport | **Added** — optional `browser` extra + sandboxed launcher (one Chromium op per docker exec, no host fallback) | `tools/browser/sandbox_launcher.py` |
| Async session-start funnel (manager ↔ backend composition), planner prompt sections, ModuleContext surfacing, WebUI panels, benchmark skip-path classification | **Added** — funnel + briefings + MCP tools + capability block + scenario metadata | `tools/browser/manager.py`, `tools/mcp_tools/browser.py`, `tools/benchmark/models.py` |

> Note: the table above is current — the backend, execution funnel, MCP tools
> (`tools/mcp_tools/browser.py`), sandbox registration, and mutating ops
> (`browser_submit` / `browser_replay` / `browser_execute_js` behind
> `browser.allow_mutating_actions`) have landed; see the Status header and
> `docs/mcp-tools.md` §Browser.

## 3. Domain models (`tools/browser/models.py`)

One shared vocabulary for the whole feature, engine-neutral by construction.
House style: pure data + enums + JSON, deterministic hand-rolled `to_dict`
(field order, `.value` for enums), tolerant `from_dict` that falls back to
safe defaults on unknown enum strings or missing keys (a payload written by a
newer/older never breaks a reader).

- **`BrowserSession`** — metadata only; never a live handle. `session_id`
  (`bs-<seq>-<rand12>`), lifecycle `state`, `run_id` (ownership), `target_ip`
  (the locked target), `backend_id`, timestamps, metadata.
- **`BrowserAction`** — one requested operation: `kind`
  (`BrowserActionKind`: navigate / observe / execute_js / screenshot /
  get_network_events / get_storage / discover_forms / discover_endpoints /
  replay_request / submit_form / wait / close) + free-form `parameters` +
  `run_id` + `target_ip`. `replay_request` and `submit_form` execute behind
  the explicit lab opt-in `browser.allow_mutating_actions` (Phase 2, landed;
  without it both return `BLOCKED`). `browser_replay` additionally refuses
  captured events whose `replayable` flag is False.
- **`BrowserObservation`** — compact harvest of one kind
  (`BrowserObservationKind`: page_state / dom / forms / endpoints / network /
  storage / console / screenshot / scripts). Carries `payload`, `sensitive`
  flag, `evidence_refs`. Serialization surfaces:
  - `to_dict()` — in-memory full shape,
  - `to_redacted_dict()` — payload redacted when `sensitive`,
  - `to_audit_dict()` — the ONLY form allowed into generic audit metadata:
    payload dropped entirely, digest of keys + counts only.
- **`BrowserPageState`** — planning surface: url/final_url (redirect-aware),
  status, title, bounded `dom_summary` (never raw HTML), forms, endpoints,
  scripts, framework indicators, `graphql_endpoints`.
- **`BrowserNetworkEvent`** — request/response record with headers, sizes +
  sha256 digests, optional truncated `body_sample` (treated as sensitive),
  `replayable` flag (True for http/https captures; `browser_replay` refuses
  non-replayable events).
- **`BrowserCookie` / `BrowserStorageSnapshot`** — credential material.
  `to_dict()` redacts values by DEFAULT; `to_dict(redact=False)` is the
  explicit opt-in for the credential-store path only (§6).
- **`BrowserArtifact`** — persisted artifact (screenshot/HAR/page_html/log/
  data) with sha256 and `evidence_type` mapping to the legacy EvidenceStore
  subdirectory keys (`legacy/evidence.py::_EVIDENCE_SUBDIRS`).
- **`BrowserResult`** — structured result at the same level as attack-module
  `ModuleResult`: `success`, `failure_class`, `retryable`, `confidence`,
  `action_id` / `session_id` anchors, `produced_artifacts`, `evidence_refs`
  (`exploit_audit:<target>:<attempt_id>` / `browser_artifact:<id>`
  conventions), `follow_ups` planner hints, typed `error`, metadata.
- **`BrowserError`** — serializable failure payload (a dataclass, NOT the
  exception; exceptions live in `errors.py`).
- **`BrowserFailureClass`** — failure vocabulary. Overlapping concepts reuse
  the exact global `tools/failure_taxonomy.FailureClass` strings
  (`tool_unavailable`, `scope_blocked`, `auth_failed`, `transport_error`,
  `timeout`, `unexpected_output`, `unsupported_target`, `unknown`);
  browser-specific classes (`session_not_found`, `invalid_transition`,
  `navigation_failed`, `script_error`) have no global mapping.
  `BrowserFailureClass.failure_class()` converts for the recovery loop.
- **Lifecycle** — `BrowserSessionState` (pending → starting → ready ↔ active,
  suspended; stopping → closed/failed terminal) validated by
  `validate_session_transition()` against an explicit transition map.

## 4. Backend seam (`tools/browser/interfaces.py`)

```python
class BrowserBackend(ABC):
    backend_id: str          # matches browser.backend config
    display_name: str
    capabilities: tuple[str, ...]   # browser.* names this backend provides

    def is_configured(self, config) -> bool: ...   # metadata only, default False
    def health(self, config) -> dict[str, Any]: ... # doctor-shaped, no side effects

    @abstractmethod
    async def start_session(*, target, run_id, session_id, headless, metadata) -> BrowserSession: ...
    @abstractmethod
    async def stop_session(session_id) -> BrowserResult: ...
    @abstractmethod
    async def navigate(session_id, url, *, timeout_seconds) -> BrowserResult: ...
    @abstractmethod
    async def observe(session_id, *, include_forms, include_endpoints) -> BrowserObservation: ...
    @abstractmethod
    async def execute_action(session_id, action) -> BrowserResult: ...
    @abstractmethod
    async def capture_screenshot(session_id, *, artifact_path) -> BrowserArtifact: ...
    @abstractmethod
    async def get_network_events(session_id, *, limit, after_id) -> list[BrowserNetworkEvent]: ...
    @abstractmethod
    async def get_storage(session_id, *, origin) -> BrowserStorageSnapshot: ...
    @abstractmethod
    async def get_page_state(session_id) -> BrowserPageState: ...
    @abstractmethod
    async def close(session_id) -> BrowserResult: ...
```

Rules (mirrors the provider seam, `tools/providers/base.py`):

1. **The ABC is the ONLY seam** the rest of BreachPilot may cross for browser
   control. "API-specific translation lives ENTIRELY inside the adapter" — no
   Playwright/Selenium/CDP object may leak across; backends translate at the
   boundary into the models above.
2. **No policy in the backend.** A backend never consults the allowlist
   itself; the execution funnel that calls it is target-locked at the MCP
   layer and (for the future engine) sandboxed. The backend is the engine
   adapter, not the policy.
3. **No executable defaults below `is_configured`/`health`.** Every operation
   is `@abstractmethod`, so a backend must consciously implement or reject
   each — a partially implemented backend cannot be instantiated (asserted by
   test), and there is no inherited behavior that could drive a browser.
4. Failures surface as `BrowserBackendError` subclasses
   (`tools/browser/errors.py`), typed and classifiable via
   `browser_error_from_exception()`; there is no fallback that silently
   pretends a browser exists.

## 5. Manager boundary (`tools/browser/manager.py`)

`BrowserManager(config, *, backend: BrowserBackend | None = None)` is the
single ownership boundary for browser sessions. It **MAY**: validate
lifecycle transitions, allocate session ids (`new_session_id`), hold +
serialize session metadata (`sessions_metadata`, `sessions_for_run`),
expose `availability()` status, and accept an injected backend.

It **MUST NOT** (and structurally cannot): launch a browser, open a socket,
visit a URL, run JavaScript, submit a form, or mutate a request. With the
stock configuration every path fails closed:

- start with `browser.enabled: false` → `BrowserBackendUnavailable`,
- start with `backend: none` / unregistered backend → `BrowserBackendUnavailable`,
- start without a locked `target_ip` → `BrowserBackendUnavailable`,
- `max_sessions` exhausted → `BrowserBackendUnavailable`,
- `delegate_to_backend(...)` — even WITH a backend injected — raises
  `BrowserBackendUnavailable` ("deferred implementation"): the future async
  funnel composes manager transitions with `backend.start_session(...)`, and
  only that funnel delegates.

Backend injection is the test seam today and the registry seam in the future
backend PR (§11).

## 6. Capability metadata & availability (`tools/browser/capabilities.py`)

Stable `browser.*` names (contracts: scenario manifests, planner records, and
audit rows may reference them verbatim from day one):

```
browser.navigate          browser.form.inspect
browser.dom.inspect       browser.form.submit        (mutating: allow_mutating_actions)
browser.javascript.execute
browser.network.observe   browser.screenshot
browser.network.replay    (mutating: allow_mutating_actions) browser.endpoint.discover
browser.storage.read
```

Each record carries `name`, `description`, `read_only` (planner-cost hint),
and `available`. Availability rule — **declared is NOT available**:

```
available = browser.enabled AND backend != "none"
            AND backend in BACKEND_REGISTRY
            AND BACKEND_REGISTRY[backend].is_configured(...)
```

`BACKEND_REGISTRY` ships **empty** — it is the only way a capability can ever
become available, so a configured-but-uninstalled backend name in config.yaml
can never flip availability (fail closed). No prompt section references these
capabilities while they are unavailable; prompts must never instruct the
model to use tooling that cannot run.

`unmet_requirements(required, config)` returns which required names are
unavailable (all of them on a stock build, plus any unknown name — nothing
provides unknown names). `browser_available(config)` answers "can ANY
browser operation run" (always `False` here).

**Secrets rule (audit/evidence):** browser material is full of credential
material — cookie values, bearer tokens, `Authorization` headers, URL
credentials, localStorage/`sessionStorage` entries, request bodies. The
redaction single source stays `tools/kernel/audit.py`; `models.py` layers a
browser-specific structural pass on top:

- storage/cookie serialization redacts values by DEFAULT (opt-in raw only for
  `to_dict(redact=False)` credential-store paths),
- `BrowserNetworkEvent.to_redacted_dict()` redacts secret-named headers
  wholesale (Cookie/Set-Cookie/Authorization/…), masks `Authorization:
  Bearer …` / URL credentials / KEY=value lines via the kernel table, and
  masks JSON `"password": "…"`, `"token": "…"`-shaped content in body samples,
- `BrowserObservation.to_audit_dict()` (the only form allowed into generic
  audit metadata) **drops payloads entirely** — keys digest + counts only,
- recovered tokens/cookies must flow through the credential store
  (`tools/credential_store.py`), never into logs, config, or generic metadata.

Tests assert (with canary secrets) that no serialization surface leaks token
material into JSON-serializable output: `tests/test_browser_audit_redaction.py`.

Future browser actions must produce audit rows carrying: run id, session id,
target, URL/action type, timestamp, policy/scope decision, result status,
evidence refs, artifact refs — with sensitive fields absent or redacted by
construction (§11 checklist wires this into the MCP audit decorators).

## 7. Config (`browser:` block)

Defaults (schema + `config.yaml`; both unchanged in behavior for existing
installs — the block is OFF and names no backend):

```yaml
browser:
  enabled: false            # master switch — stock installs never enable
  backend: none             # none | future: playwright (requires registry entry)
  headless: true
  max_sessions: 2
  session_timeout_seconds: 300
  navigation_timeout_seconds: 30
  capture_screenshots: true
  capture_network: true
  capture_console: false
  persist_storage: false    # storage harvest goes to the credential store, never plaintext logs
```

The validator warns (never errors) on bad value types and errors only when
`browser` is not a mapping; a config file with no `browser:` key loads the
exact defaults above. Nothing else in the engine reads this block in the
preparation build.

### Enablement (operator)

```bash
python -m pip install -e ".[browser]"   # Playwright SDK (host-side)
python -m playwright install chromium   # browser runtime
```

```yaml
browser:
  enabled: true
  backend: playwright
```

Then `python main.py --doctor` must show the `browser` check green
(`host playwright + chromium`, or the browser worker image when contained).
Availability rule (`tools/browser/capabilities.py:browser_runtime_available`):
enabled + registered + runnable — host SDK present **or** a sandbox worker
configured. `backend: playwright` alone never flips it (fail closed).

Execution homes, in order:

1. **Contained (default posture):** `sandbox.enabled: true` + browser worker
   image built (`docker build -t breachpilot-sandbox:browser -f
   docker/sandbox/Dockerfile.browser docker/sandbox`). One Chromium op per
   docker exec inside the worker netns; no host fallback — sandbox
   enabled-but-unusable returns `SANDBOX_*` blocks.
2. **Host (explicit opt-out):** `sandbox.enabled: false` runs Chromium
   in-process. Lab-only. All browser coroutines hop onto one private
   daemon-thread loop (`tools/mcp_tools/browser.py:_get_browser_loop`) —
   Playwright connections bind to their creating loop, so a fresh loop per
   tool call breaks every op after `browser_start`.

`browser.allow_mutating_actions: false` (default) keeps `browser_execute_js`,
`browser_submit`, and `browser_replay` returning `BLOCKED`; set it `true` only
as an explicit lab opt-in.

## 8. MCP / sandbox / policy integration

The package deliberately sits at `tools/browser/`, NOT under
`tools/mcp_tools/` — MCP tool discovery (`collect_tools()`) walks only
`tools/mcp_tools/` (`modules/`, `terminal/`, top-level files), so the
preparation package is invisible to tool discovery and can neither
auto-register tools nor trip the AST decorator gate.

`tools/sandbox/family_audit.py` registers the browser family in
`PLANNED_FAMILIES` (status `planned`, `target_touching: true`) with the
pre-committed containment contract: when the backend lands it MUST be
registered as `sandboxed` (or a documented host exception), and its execution
must run inside an isolated browser worker with the same effective target
allowlist as other offensive tooling. Planned families never appear as audit
rows and never count as problems — the existing containment audit tests keep
their exact guarantees (unregistered == 0, problems == []).

Policy posture for the future execution path (unchanged from the lab rule
set): the browser execution funnel is target-locked through the MCP allowlist
(`_target_lock_block` extraction already covers URL authorities), consults
the mission ScopeGate, and records every gate decision in the audit row.
The backend NEVER touches the allowlist itself.

## 9. API + WebUI

`/api/v1/capabilities` returns an additive `browser` block:

```json
{"browser": {"enabled": false, "backend": "none", "available": false,
             "capabilities": [{"name": "...", "description": "...",
                               "read_only": true, "available": false}, ...]}}
```

Status metadata only — there are NO browser control endpoints, and `available`
is real (enabled + registered + runnable; never pretended). The WebUI consumes
the same `/capabilities` feature list it already does, plus a read-only
`GET /api/v1/system/browser` health endpoint (config summary, SDK/Chromium
probes, capability list — never launches). The System → Advanced page renders
a "Browser agent" section (Ready/Not ready/Disabled badges, setup hints per
missing piece, config stats, capability list) and the settings status overview
carries a Browser chip (Off/Ready/Not ready); `browser.*` keys are editable
under Advanced via the `browser` settings section. No run-page browser
controls exist in this build — sessions are driven by the agent through MCP
tools, and live sessions live in the MCP server process (not listed by the
API). The `browser` field stays typed additively: older clients ignore it.

## 10. Benchmarks

`BenchmarkScenario` gains `requires_capabilities: list[str]` (default `[]` —
byte-identical behavior for existing manifests). XBEN manifests may declare:

```json
{"benchmark_id": "xben-9001", "oracle": {"flags": [...]},
 "requires_capabilities": ["browser.navigate", "browser.dom.inspect"]}
```

Detection uses `tools.browser.capabilities.unmet_requirements`; the reserved
`FailureCategory.CAPABILITY_UNAVAILABLE` is defined for future classification
but **nothing sets it in this build** — the capability-gated skip path is
deferred (§11). No live scenario declares browser requirements yet.

## 11. Future implementation checklist (the Playwright PR)

Exact recommended next PR: **"Implement Playwright BrowserBackend behind the
prepared browser interfaces"**.

1. **Backend**: `tools/browser/backends/playwright_backend.py` implementing
   `BrowserBackend`; register in `BACKEND_REGISTRY` at call time (never at
   import — keep stock imports browser-free). All methods return `models.*`
   types; translate Playwright objects at the boundary; never emit Playwright
   exceptions across the seam (map via `browser_error_from_exception`).
2. **Execution funnel**: async manager→backend session start composing
   `start_session` (PENDING→STARTING→READY) and `delegate_to_backend`;
   target-locked at the MCP layer (`@require_allowlist("target")`), ScopeGate
   consult, `@audit_tool` rows with: run id, session id, target, URL, action
   type, timestamp, policy decision, result status, evidence + artifact refs.
3. **MCP tools**: new module `tools/mcp_tools/browser.py` (conditional
   registration on `browser.enabled` + a configured backend — the
   `killchain`/`snapshots` pattern), registering read-only surfaces first
   (`browser_navigate`, `browser_observe`, `browser_page_state`,
   `browser_network_events`, `browser_storage`, `browser_screenshot`);
   `browser_execute_js` / `browser_replay` gated behind explicit lab config.
4. **Sandbox migration**: move the family from `PLANNED_FAMILIES` to
   `SANDBOXED_FAMILIES` (browser worker container: allowlisted egress to the
   locked target only, no host FS, no operator-box credentials).
5. **Secrets**: route recovered cookies/tokens through `cred_store_add`;
   keep `persist_storage: false` default; add doctor checks (`tools/doctor.py`)
   for browser.enabled-without-backend and Playwright-not-installed.
6. **Planner/prompts**: only NOW inject OPSEC-safe browser briefings +
   skill entries; keep prompt references gated on `browser_available(config)`
   so an unconfigured install still renders zero browser guidance.
7. **Benchmarks**: skip-path classification using `unmet_requirements` →
   `TrialStatus.SKIPPED` + `FailureCategory.CAPABILITY_UNAVAILABLE`; wire the
   shortfall template in `tools/benchmark/runner.py` the same way as the
   sandbox shortfall.
8. **WebUI**: capability-gated browser panel (renders only when
   `capabilities.browser.available` is true); run-page events for session
   lifecycle (`browser.session_started`, `browser.action_result`) using the
   existing event envelope.
9. **Docs**: README config section, `docs/mcp-tools.md` tool table row,
   `docs/sandbox.md` family move, `docs/config-reference.md` live values.

## 12. Risks & mitigations

| Risk | Mitigation in this build |
|---|---|
| Someone wires a browser without containment | `BACKEND_REGISTRY` empty; manager + API fail closed; sandbox `PLANNED_FAMILIES` entry pre-commits the sandboxed-registration requirement; audit tests pin it |
| Secrets leak via logs/audit | redacted-by-default serialization, `to_audit_dict` drops payloads, canary-secret tests, credential-store rule |
| Capability becomes accidentally "available" | availability requires registry entry + `is_configured` (fail closed); stock builds always `False` |
| Prompt tells the model to use impossible tooling | no prompt surface references `browser.*` in this build; future briefings must gate on availability |
| Benchmark metrics drift from reality | `requires_capabilities` default `[]`; `CAPABILITY_UNAVAILABLE` reserved, unemitted; detection is pure metadata math |
| Backwards compatibility | additive config block (disabled), additive API key, additive benchmark field, additive sandbox summary key; import of `tools.browser` loads no browser package and no new dependency |