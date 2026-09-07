# WebUI

The bundled single-page app for driving BreachPilot assessments from a browser.
A Vite + React + TypeScript SPA under `webui/`, served by the local API daemon
and talking to the same `/api/v1` REST + WebSocket surface documented in
[api.md](api.md).

> Source: `webui/src/`. Built output: `webui/dist/` (gitignored, created on
> first `--web` run). App config lives in `config.yaml`, not in the webui tree.

---

## Table of Contents

1. [Overview](#overview)
2. [Run It](#run-it)
3. [Architecture](#architecture)
4. [Auth & Sessions](#auth--sessions)
5. [Real-Time Transport](#real-time-transport)
6. [Pages](#pages)
7. [The Run Wizard](#the-run-wizard)
8. [The Live Run View](#the-live-run-view)
9. [System Page](#system-page)
10. [Artifacts, Audit & Logs](#artifacts-audit--logs)
11. [Loot & Credentials](#loot--credentials)
12. [API Client Layer](#api-client-layer)
13. [UI Primitives & Styling](#ui-primitives--styling)
14. [Conventions](#conventions)
15. [Extension Points](#extension-points)
16. [File Map](#file-map)

---

## Overview

The WebUI is the browser front end for the loopback-only API daemon
(`--demon` / `--daemon` / `--web`). It mirrors the interactive CLI menu as a
guided wizard, streams run events in real time, surfaces pending decisions
(start-confirm, goal-select, tool-approval), and gives access to artifacts,
audit, logs, loot, and system config.

- **Stack:** Vite 5.4, React 18.3, TypeScript 5.6, TanStack Query 5.59,
  react-router-dom 6.27, Tailwind 3.4, Radix UI primitives (shadcn/ui style),
  lucide-react icons, react-markdown + remark-gfm.
- **Theme:** dark only (`<html class="dark">`, HSL CSS vars in `index.css`).
- **Target browser:** evergreen Chromium/Firefox/Safari. Build target
  `es2020`; no sourcemaps shipped.
- **Loopback only:** the daemon refuses non-loopback binds; the SPA proxies
  `/api` to `127.0.0.1:8765` in dev and is served same-origin in production.

The SPA never holds authority — every destructive action is gated by the
server's `AssessmentService` and `ExploitPolicy`. The WebUI only forwards
operator input and renders server state.

---

## Run It

### Production (bundled)

```powershell
python main.py --web
```

- Builds `webui/dist/` on first run (runs `npm install && npm run build`;
  requires Node.js + npm on `PATH`).
- Sets `api.serve_webui: true` **in memory only** (never written to
  `config.yaml`), mounts `dist/` at `/` with a deep-link SPA fallback, and
  opens a browser at `http://127.0.0.1:8765/`.
- Subsequent `--web` runs reuse the built `dist/` unless you delete it.
- `--demon` / `--daemon` start the API without serving the SPA, unless
  `api.serve_webui` is already `true` in `config.yaml`.

Bearer token is auto-generated into `.webui_secret_key` (gitignored) on first
boot, or set via `BREACHPILOT_API_TOKEN`. Paste it into the TokenGate prompt.

### Dev server (hot reload)

```powershell
cd webui
npm install
npm run dev      # http://127.0.0.1:5173  (strictPort)
```

The Vite dev server proxies `/api` → `http://127.0.0.1:8765` (or
`VITE_API_URL`) with `ws: true`, so the API daemon must be running separately
(`python main.py --demon`) for the SPA to function. Dev uses the same bearer
token as production — paste it into the TokenGate.

### Build & preview

```powershell
cd webui
npm run build      # tsc -b && vite build  →  webui/dist/
npm run preview    # vite preview --port 5173 --strictPort
```

`preview` serves the production build with the same `/api` proxy as dev.

### Env vars

| Var | Where | Purpose |
|-----|-------|---------|
| `VITE_API_URL` | `vite.config.ts` | Override the dev/preview `/api` proxy target (default `http://127.0.0.1:8765`) |
| `BREACHPILOT_API_TOKEN` | daemon | Bearer token (precedes `.webui_secret_key`) |
| `BREACHPILOT_API_KEY_FILE` | daemon | Provider secrets file (default `secr.json`) |

`__APP_VERSION__` is a Vite `define` injected from `package.json` version
(shown in the sidebar + footer).

---

## Architecture

### App tree

```
main.tsx
  └─ <App/>  (QueryClientProvider + BrowserRouter)
       └─ <TokenGate>            bearer token gate
            └─ <OnboardingGate>  first-run setup: provider + keys + ChatGPT OAuth
                 └─ <Routes>
                      └─ <Layout>  (sidebar + active-run pill + footer)
                           ├─ "/"                       → HomePage
                           ├─ "/sessions"               → RunListPage
                           ├─ "/runs/new"                → NewRunPage → <RunWizard>
                           ├─ "/runs/:runId"             → RunPage
                           ├─ "/runs/:runId/artifacts"   → ArtifactsPage
                           ├─ "/runs/:runId/loot"        → LootPage
                           ├─ "/runs/:runId/graph"       → GraphPage
                           ├─ "/skills"                  → SkillsPage
                           ├─ "/modules"                 → AttackModulesPage
                           ├─ "/goals"                   → GoalsPage
                           ├─ "/graph"                   → AttackGraphPage
                           ├─ "/stats"                   → StatsPage
                           ├─ "/benchmarks"              → BenchmarksPage
                           ├─ "/benchmarks/new"          → BenchmarksStartPage
                           ├─ "/benchmarks/history"      → BenchmarksHistoryPage
                           ├─ "/benchmarks/:runId"       → BenchmarkRunPage
                           ├─ "/ops"                     → OpsPage
                           ├─ "/connections"             → ConnectionsPage
                           ├─ "/memory"                  → MemoryPage
                           ├─ "/system"                  → SystemPage
                           ├─ "/help"                    → HelpPage
                           └─ "*"                        → <Navigate to="/sessions">
```

The two gates run before any route renders. `TokenGate` blocks until a valid
bearer token is verified against `GET /capabilities`. `OnboardingGate` blocks
only when `GET /secrets` reports ≥1 missing provider key **and** the user
hasn't dismissed it this session.

### State model

| State | Owner | Notes |
|-------|-------|-------|
| Server state (runs, decisions, config, secrets, tools, artifacts, audit, swarm, loot) | TanStack Query | `api/hooks.ts`. Cache keys centralized in `queryKeys`. Polls while active, stops at terminal. |
| Live run events | `useRunEvents` (`api/ws.ts`) | WS-first, SSE fallback. Local React state, deduped by `sequence`. |
| Token | module-level `inMemoryToken` (`api/client.ts`) | In-memory only; cleared via shared `expireSession` funnel on 401 / WS 4401 / sign-out. Never `sessionStorage`/`localStorage`. |
| Onboarding dismissed | `sessionStorage` (`breachpilot.onboarding.v1`) | Per-session flag. |
| Wizard form state | `run-create/RunWizard.tsx` local `useState` | Goal/target/review state so `buildRequest()` can serialize it. |
| URL state | react-router | `?path=recon\|attack\|fast` preselects wizard path; `:runId` route params. |

There is no global client store (no Redux/Zustand). TanStack Query is the
cache; `useState`/`useRef` hold the rest.

### Query defaults

`defaultQueryOptions` (`api/hooks.ts`):

- **retry:** up to 2 on network (`status === 0`) and 5xx; **no** retry on 4xx
  except 408/429.
- **staleTime:** 15s default (overridden per hook: capabilities 60s, config 30s,
  skills 60s, goals/schema `Infinity`).
- **gcTime:** 5 min.
- **meta.onErrorAuthClear:** hooks clear the stored token on 401.
- **refetchOnWindowFocus:** disabled globally in `App.tsx`.

Live polling: `useRuns` every 5s; `useRun` every 5s while `running`/`queued`/
`cancelling`, stops when terminal; `useDecisions` every 5s while a decision is
pending.

---

## Auth & Sessions

### TokenGate

First-load screen. Operator pastes the bearer token (from `.webui_secret_key`
or `BREACHPILOT_API_TOKEN`). On submit the SPA stores it in memory via
`setStoredToken` and calls `GET /capabilities` to verify:

- 401 → "Token rejected", clear token.
- `status === 0` → "Could not reach the API daemon. Start it with
  `python main.py --demon`".
- Success → render children.

Sign-out (sidebar "Clear token" / mobile header) clears the token and reloads
to `/`.

### Token storage

- Held in the module-level `inMemoryToken` in `api/client.ts` — never in
  `sessionStorage`/`localStorage`, where any XSS payload could replay it
  against the loopback API. Trade-off: a page refresh drops the session and
  `TokenGate` re-prompts (accepted: the token is one paste away in
  `.webui_secret_key`). Covered by `api/tokenStorage.test.ts`.
- Sent as `Authorization: Bearer <token>` on every REST call (`apiFetch`) and
  as the `auth` field of the WS handshake; the fetch-backed SSE transport in
  `api/sse.ts` also sends it only in the `Authorization` header (never in the
  URL, which would leak it into history/logs).
- Never logged, never persisted to disk by the SPA. Only the telemetry session
  baseline (`breachpilot.telemetry.sessionBaseline.v1`) uses `sessionStorage`.

### WebSocket auth

First message after accept must be `{"auth": "<token>", "after": <int>}`.
Close `4401` clears the token and surfaces "Authentication failed". See
[Real-Time Transport](#real-time-transport).

### OnboardingGate

After TokenGate, before routes. Calls `useSecrets`; if any key is `missing`
and the user hasn't dismissed onboarding this session (`breachpilot.onboarding.v1`
not `"1"`), renders the first-run setup card. The card asks for three things
up front so a fresh operator can configure everything before launching a run:

1. **AI provider** — `<ProviderPicker />` (Ollama / ChatGPT segmented control;
   persists `models.provider` via `PATCH /config`, flips `chatgpt.enabled` on for
   ChatGPT). Switching invalidates the `models` / `modelsLive` / `providers`
   caches immediately.
2. **Provider API keys** — configured + missing keys with write-only inputs.
   Submit → `PUT /secrets` → toast "API keys saved" → dismiss.
3. **ChatGPT (optional)** — `<ChatGptControls />` (always shown, labelled
   optional): Sign in with ChatGPT / Start proxy / Stop proxy, status badges,
   and the OAuth URL link. OAuth tokens never reach the UI.

"Skip for now" also dismisses without saving keys. Everything is re-editable
later under System → Models (provider + ChatGPT) and System → Secrets (keys).

> Provider secrets are stored in `secr.json` (default; override with
> `BREACHPILOT_API_KEY_FILE`). This is **distinct** from `.webui_secret_key`,
> which holds the API bearer token. See [api.md §Secrets](api.md).

---

## Real-Time Transport

`useRunEvents(runId, { after, enabled })` in `api/ws.ts` drives the live Run
view. Returns `{ events, status, authError, transport, reconnect, lastSeq }`.

### WebSocket (primary)

- URL: `ws(s)://<host>/api/v1/ws/v1/runs/<run_id>`.
- On open: send `{"auth": token, "after": lastSeq}`.
- Inbound frames are JSON `RunEvent`s; deduped by `sequence`, kept sorted.
- Heartbeats (`type: "heartbeat"`) update `lastSeq` but are not added to the
  event list.
- Reconnect with exponential backoff: `min(10000, 1000 * 2 ** attempt)`,
  reset on successful open.

### SSE fallback

After 3 consecutive WS failures the hook switches to fetch-backed SSE
(`api/sse.ts` `streamSSE` — the browser's native `EventSource` cannot set an
`Authorization` header):

- URL: `<origin>/api/v1/runs/<id>/events/stream?after=<seq>` (cursor factory
  re-invoked per attempt; token sent only in the `Authorization` header).
- Incremental `SseParser` (chunk-safe UTF-8 decode, `data:`/`event:`/`id:`/
  `retry:` fields, `:` keepalive comments dropped); dedup by `sequence` with
  `appendBounded`/`eventStore`.
- `SSE_WATCHDOG_MS` (90s, three missed 30s keepalives) aborts a silently dead
  stream; exponential backoff capped at 10s. `onStatus` drives the transport
  badge; `onFatal` with `authError` stops reconnecting.
- On SSE error: same backoff reconnect loop. SSE falls back to WS again on
  the next `reconnect()`.

### Close codes

| Code | Meaning | SPA behavior |
|------|---------|--------------|
| `4400` | Invalid cursor (`after` not a non-negative int) | Reset `lastSeq` to 0 and reconnect |
| `4401` | Auth failed | Clear token, surface error, stop reconnecting |
| `4403` | Origin rejected | Surface error, stop reconnecting |
| `4404` | Run not found | Surface error, stop reconnecting |
| `1011` | Server not configured / stream failed | Standard backoff reconnect |

A browser disconnect **does not cancel the run** — the backend ring buffer +
`events.jsonl` cover the gap; reconnect with the last `sequence` you saw as
`after`. `reconnect()` forces an immediate WS reconnect, resetting attempt
counters. The WS-layer watchdog marks the stream stale after 45s of silence
(incl. heartbeats) and force-reconnects at 90s (`STALE_AFTER_MS` /
`WATCHDOG_TIMEOUT_MS` in `ws.ts`), matching the 90s SSE watchdog.

### Transport badge

The Run page shows `WS` / `SSE` / connection-state labels (`reconnecting`,
`offline`, `connecting`, `error`, `—`), derived in `RunPage.tsx` from
`events.transport` + `events.status`.

---

## Pages

### Home (`/`)

Hero, live stats strip (total / active / completed / failed, from
`useRuns(50, 0)`), two action cards (`?path=recon` recon-first, `?path=attack`
new attack), an active-run banner if any run is live, and a "Recent sessions"
list (top 5 rows). Footer reminder: loopback only, authorized assets only.

### Sessions (`/sessions`)

Paginated table of runs (ID, state, target, mode, goal, model, created).
Per-row actions: Open, Resume (terminal runs only, calls `POST /resume` then
navigates), Delete (confirm prompt; `purge=true`). Active run disables "New
run" and surfaces a banner. Polls every 5s.

### New Run (`/runs/new`)

Thin wrapper around [`RunWizard`](#the-run-wizard). On create, navigates to
`/runs/<runId>`.

### Run (`/runs/:runId`)

See [The Live Run View](#the-live-run-view).

### Artifacts (`/runs/:runId/artifacts`)

See [Artifacts, Audit & Logs](#artifacts-audit--logs).

### Loot (`/runs/:runId/loot`)

See [Loot & Credentials](#loot--credentials).

### Run Graph (`/runs/:runId/graph`)

Per-run attack-path view (`GraphPage.tsx`): `AttackGraphDag` (DAG layout from
run artifacts) above the legacy `AttackGraph` list, gated on the
`enhanced/enhanced_report.json` artifact.

### Modules (`/modules`)

Read-only catalog of pre-packaged attack modules (`GET /attack/modules`): name,
description, family, target services/ports, required CVEs, and a destructive-ICS
flag. Search + family filter. `tools/attack_modules/` is the source; see
[docs/attack-modules.md](attack-modules.md).

### Goals (`/goals`)

Read-only catalog of preset goals (`GET /goals`) grouped by risk requirement
(safe / gated / high) with the opt-in requirement each level demands.

### Memory (`/memory`)

Attack-memory browser (`MemoryPage.tsx`, `useMemory`): lessons + items with
confidence filter, search, per-tab tables. Read-only.

### Stats (`/stats`)

Telemetry rollup (`StatsPage.tsx`): 14-day run histogram, recent runs, and
`useTelemetry` aggregates (tokens, calls, durations), capped at 200 runs / 50
telemetry records.

### Connections (`/connections`)

Operator-connection manager (`ConnectionsPage.tsx`, `useConnections` /
`useConnection` / `useCheckConnection` / `useRemoveConnection`): list, health
check, and removal with confirm dialog.

### Ops (`/ops`)

Read-only operations rollup (`OpsPage.tsx`, `GET /ops/summary`): kill-chain,
snapshots (+ counterfactual flag), eval baseline presence, browser backend, and
active provider. Enabling stays in System → Config (`PATCH /config`). Covered
by `tests/test_ops_summary.py`.

### Help (`/help`)

Static reference: quick-start steps, permission-mode explainer, run-phase
overview, and links into the `docs/` guides.

### Attack Graph (`/graph`)

Interactive three-panel investigation of a run's Attack Graph v2 store. See
[Attack Graph Page](#attack-graph-page). Enabled by `api.graph_route: true`
in `config.yaml`; when disabled the page shows the disabled-route error.

### Benchmarks (`/benchmarks`)

Benchmark dashboard + run detail (see [docs/benchmarks.md](benchmarks.md)).
The dashboard shows the latest run's metric cards (verified success rate,
solved, false-positive rate, median solve time, average cost, sandbox
violations), a run panel (suite / scenarios / tags / trials / model / sandbox
requirement / baseline options → `POST /api/v1/benchmarks/run`), run history
with SVG charts (verified rate, FP rate, solve time, cost), a comparison view
for any two runs (metric deltas + newly-solved / regressed / still-solved /
still-failing), and the run list. `BenchmarksRunPage` (`/benchmarks/:runId`)
adds the live progress view (current trial, phases, actions, sandbox state),
the structured mission timeline, scenario results table with
verified-vs-claimed columns, failure categories, the configuration and
environment (reproducibility pins: git SHA, model id/version, config hash,
sandbox image digest), and a Save-as-baseline action. Routes:
`/benchmarks` (dashboard), `/benchmarks/new` (start form), `/benchmarks/history`
(trend charts), `/benchmarks/:runId` (live + detail).

### System (`/system`)

See [System Page](#system-page).

---

## The Run Wizard

`run-create/RunWizard.tsx` — steps in `run-create/RunStepper.tsx`
(`STEPS = ["opsec", "settings", "target", "review"]`), mirroring the CLI
questionary flow.

```
opsec ──▶ settings ──▶ target ──▶ review
```

| Step | Collects |
|------|----------|
| `opsec` | OPSEC posture settings (see `OpsecSettings`). |
| `settings` | Execution path + model/profile/power-ups (see below). Preselectable via `?path=recon\|attack\|fast`. |
| `settings` | Model alias (provider-aware: Ollama live list + registry, or ChatGPT discovered models + `chatgpt.default_model`; refresh button); power-ups grid (filtered by `capabilities.run_options.flags`); recon-first tri-state; observer mode; skills mode + include/exclude multi-select; goal (preset by risk group or custom text, attack path only); run kind; `yes` skip-confirm toggle. |
| `target` | IPv4/IPv6/FQDN. Client-side `isValidTarget` mirrors `tools.validation_utils` (strict IPv4 octets, IPv6 must contain `:`, FQDN TLD ≥2 alpha). |
| `review` | Summary card (target/mode/goal/model/transport/permission/destructive/budgets/skill activations) + the start-confirm gate. |

### Create flow

1. On "Create run" from the target step, `POST /runs` with `buildRequest()`.
2. If the server returns `state` `queued`/`running` (e.g. `yes:true`), the
   wizard calls `onCreated(runId, state)` and the SPA navigates to the run.
3. Otherwise the wizard advances to `review`, where the `start_confirm`
   decision is rendered:
   - **Destructive** (`permission=full_access` + `attack_mode`): the operator
     must type the exact `required_confirmation_text` (e.g. `ALLOW 10.0.0.50`).
     The Confirm button is disabled until the input matches.
   - **Non-destructive**: a single "Proceed" button sends `"y"`.

### Power-up gating

`critic`, `reflection`, and `parallel_swarm` toggles are disabled unless
`swarm` is on. The request builder forces `critic`/`reflection` to `false`
when `swarm` is off.

### Manual kind warning

The API advertises `kind: "manual"` (no agent loop, tool gateway only), but
the SPA renders an amber notice that manual kind currently executes the normal
agent path, so operators aren't misled.

### Goal selection

Preset goals come from `GET /goals` (cached for the session via
`staleTime: Infinity`), grouped by `risk` (`safe` / `gated` / `high`). Custom
goals are free text. Setting a goal on the attack path disables recon-first.

---

## The Live Run View

`RunPage.tsx` — the primary surface during and after a run.

### Header

- Run ID (mono, with copy button) + `StatusBadge` + transport badge (`WS`/
  `SSE`/`—`).
- Target / mode / goal / model / permission line.
- **Live telemetry** (when available): tokens, calls, context-window size,
  ctx-used %, remaining — sourced from the latest `progress` event's
  `payload.telemetry`, falling back to `run.result.telemetry`.
- Actions: **Cancel** (active runs, opens a confirm dialog explaining
  cooperative cancellation), **Resume** (terminal runs only), **Artifacts**
  and **Loot** links.

### Event stream (left, main column)

`EventViewer` (`components/events/EventViewer.tsx`, rows in `eventRows.ts`)
renders the deduped, sequence-sorted event list (virtualized via TanStack
Virtual) with sticky-to-bottom scrolling, pause, search, type filters, and a
"jump to latest" button when scrolled up.
Event rendering:

| Event type | Rendered as |
|------------|-------------|
| `boot` / `ok` | Aggregated into a `BootChecklist` at the top (if any present) |
| `tool_request` + `tool_start` + `tool_result` | Correlated by `correlation_id` / `call_id` / `request_id` into one `ToolCallCard` (shows args, result, error, started/completed) |
| `approval` (pending) | `DecisionCard` inline (answered approvals hidden from the stream) |
| `recon_assessment` | `ReconAssessmentCard` |
| `goal_suggestions` | Ranked list (`GoalSuggestionCard`s, AI-generated first) |
| `state` | Compact state badge row |
| `progress` | Round/action/phase + elapsed seconds (telemetry is read off this) |
| `assistant` | LLM output text in a bordered card |
| `swarm` / `artifact` / `completion` / `error` / `heartbeat` | Inline |

### Pending decisions (right column)

- **Pending decisions** card: one `DecisionCard` per pending decision
  (`start_confirm`, `goal_select`, `tool_approval`). Answering calls
  `POST /runs/{id}/decisions/{decisionId}` and invalidates the run/decisions/
  runs-list queries.
- **Decisions** card: all decisions (pending + answered + expired) with kind,
  status, and answer.

Decisions from the REST endpoint are merged with any `approval` events the WS
delivered before the REST poll caught up (deduped by decision id).

### Tabs (below the stream)

| Tab | Shown when | Content |
|-----|-----------|---------|
| Recon | always | "Load recon assessment" button → fetches `recon_assessment.json` artifact and renders `ReconAssessmentCard`. Empty state if no recon ran. |
| Summary | always | `SessionSummaryCard` from `run.result`. |
| Tools | always | Manual tool panel (see below). Empty state if no live MCP session. |
| Audit | always | Audit chain validity banner + audit records table (first 6 columns). |
| Swarm | `request.swarm` | `swarm_state.json` viewer. |
| Campaign | `request.long_session` | `attack_states.json` viewer + manual campaign controls (see below). |

### Manual tool panel

Lists live MCP tool schemas (`GET /runs/{id}/tools`, only meaningful while the
run is active and the MCP session is open). Operator picks a tool, edits JSON
arguments in a textarea, and calls `POST /runs/{id}/tools/{name}/calls`. The
call is policy-gated server-side (`403 tool_denied` if the exploit policy
rejects it) and serialized through the run's `tool_lock` so it can't race the
agent loop. Result rendered in a mono `<pre>` with a copy button.

### Manual campaign controls

Active runs whose exploit session exposes the campaign tools get a "Manual
campaign control" card on the Campaign tab. Start (`start_autonomous_campaign`,
goal + aggression + confirm dialog — the run's target-IP allowlist lock still
applies), Step (`run_campaign_step`) and Stop (`stop_campaign`) all go through
the same tool-call endpoint as the manual tool panel. The campaign id returned
via `CAMPAIGN_STARTED:` pre-fills the editable id input; the operator can also
paste an id from an earlier or agent-started campaign. Manually started
campaigns write `exploit_workspace/campaigns/<id>/state.json` and are tracked
separately from the `attack_states.json` snapshot the tab displays.

### Swarm state

The Swarm tab renders the namespaced blackboard, the agent table, and the last
`reflection_agent` output (strategy-shift badge, confidence, what
worked/failed/patterns). The battle log card is scrollable; the server
persists the most recent 200 entries per swarm run.

Lists live MCP tool schemas (`GET /runs/{id}/tools`, only meaningful while the
run is active and the MCP session is open). Operator picks a tool, edits JSON
arguments in a textarea, and calls `POST /runs/{id}/tools/{name}/calls`. The
call is policy-gated server-side (`403 tool_denied` if the exploit policy
rejects it) and serialized through the run's `tool_lock` so it can't race the
agent loop. Result rendered in a mono `<pre>` with a copy button.

### Cancel

Cooperative: opens a dialog explaining the agent stops at the next boundary
and tears down MCP/swarm children. Calls `POST /runs/{id}/cancel`; the server
waits up to `api.shutdown_timeout_seconds` (default 15s) for the task to
finish.

### Resume

Terminal runs show a Resume button. `POST /runs/{id}/resume` creates a new
run linked by `resumed_from`, and the SPA navigates to the new run id. The new
run always goes through the confirmation gate (`yes=false`).

---

## System Page

`SystemPage.tsx` — six tabs.

| Tab | Content |
|-----|---------|
| Config | `ConfigEditor` — redacted `GET /config` view + `PATCH /config` form. Atomic write, `400 config_invalid` on validation failure. |
| Secrets | Per-provider-key status (`configured`/`missing`) + write-only inputs. `PUT /secrets` also loads values into the running daemon's env. Values are never returned. |
| Models | **AI provider card** — `SegmentedControl` picker (Ollama / ChatGPT) bound to `models.provider`; switching PATCHes `/config` (deep-merge: → chatgpt also sets `chatgpt.enabled: true`, mirroring the CLI menu; `/models` + `/providers` + `/models/live` are invalidated immediately so there's no stale window). When ChatGPT is active the card shows `GET /providers` status (signed-in / proxy-running / started-by-BreachPilot badges, host:port + default_model), a "Sign in with ChatGPT" prompt when not authenticated, "Sign in with ChatGPT" (`POST /providers/chatgpt/login` — backend-driven OAuth, URL shown as a link, tokens never reach the SPA), and Start/Stop proxy (`POST /providers/chatgpt/proxy/{start,stop}` — Stop only enabled when `we_started`). When Ollama is active the card notes embeddings also use Ollama. Below: live model list (`GET /models/live`, source badge `ollama`/`registry`/`chatgpt`, error line — for ChatGPT the proxy auto-starts on fetch so available GPT models populate once signed in) + configured models (registry for Ollama, `chatgpt.configured_models` for ChatGPT) + default. |
| Skills | Searchable list (`GET /skills/search?q=`) + detail pane (`GET /skills/<name>`) showing body, sections, tags, NIST CSF, MITRE ATT&CK, references. |
| Plugins | `GET /plugins` list with name/version/loaded/capabilities. Defensive `[]` on error. |
| Diagnostics | Buttons to run `POST /diagnostics/doctor` and `POST /diagnostics/self-test`; renders exit code badge + output `<pre>`. |

---

## Attack Graph Page

`AttackGraphPage.tsx` + `features/graph/*` — interactive investigation of the
run's Attack Graph v2 store (the same store `graph_builder` ingests from
`reports/<run_id>/`). Read-only, scope-isolated per run, gated by
`api.graph_route: true` (`404 graph_disabled` renders the disabled-route
message + config hint). Route: `/graph`.

Three-panel grid (`260px` filters / canvas / `340px` details):

| Panel | Component | What it does |
|-------|-----------|--------------|
| Left — filters | `GraphFilters` | Run/scope select (active runs first), server-side search (`q`, debounced), NodeType checkboxes, Status checkboxes, confidence slider (client-side view filter). Changing any filter resets the view to the base graph. |
| Center — canvas | `AttackGraphCanvas` + `GraphToolbar` + `GraphStats` | React Flow v11 graph: pan/zoom/fit/reset layout, drag nodes, click to select, keyboard-accessible. Toolbar: fit, reset, **+1 hop / +2 hops** neighborhood expansion, **Path** mode, **Merge conflicts** toggle, focus search. Stats chips (Nodes, Hosts, Services, Findings, Confirmed, Hypotheses…) from `summary`; conflict count + highest-degree hub. |
| Right — details | `GraphDetailsPanel` | Node ID, type, value, status, confidence, scope, source, first/last seen, observation/contradiction counts, properties, evidence refs, connected nodes grouped by edge type. Renders **only real metadata** — a node with no `severity`/`cvss_score`/`vuln_class` shows no such badge, and keys surfaced in dedicated rows are not repeated under generic Metadata. |

Behavior notes:

- **Search** matches value, type, status, source, id, evidence refs, and
  property values (CVSS, severity, vuln class). `nodeMatchesQuery` drives both
  the toolbar's focus-jump and the details panel.
- **Path mode** (`GraphPathFinder`): pick start/end nodes, set
  `max_length`/`max_paths`, request bounded paths, show the best path overlaid
  (non-path nodes dimmed).
- **Neighborhood expansion** merges BFS results into the local view state;
  filters are re-applied by resetting the view. Never mutates graph facts —
  view state is separate from the backend source of truth.
- **Large graphs**: the backend clamps `limit` to 500; the page shows a
  "Graph is large — refine filters" banner when `truncated` or >500 total
  nodes.
- **Live refresh**: WS artifact events invalidate `["graphExplorer", runId]`
  queries (`ws.ts`), and `useGraphPolling` refetches the graph every ~10s
  while the run is active. The page never streams the whole graph over the
  wire.
- **Merge conflicts** (`conflictsOpen`): a yellow "Merge conflicts" toolbar
  button opens the panel listing node, existing→proposed confidence, and
  reason. Conflicts are never hidden.
- **Accessibility**: keyboard-accessible controls, selected node shown with a
  ring (not color-only), details panel is usable without the graph.

Hooks (all in `features/graph/graphApi.ts`, TanStack Query, `graphKeys`
prefix): `useGraphRun`, `useGraphSummary`, `useGraphConflicts`, `useGraphNode`,
`useGraphNeighbors`, `useGraphPaths`, `useGraphPolling`, `useInvalidateGraph`.
Pure mapping + search live in `graphTransforms.ts` (enum→presentation
metadata, reactflow layout, evidence-ref parsing, summary chips) — nothing
there mutates graph facts. DTO types mirror the backend `to_dict()` shapes
exactly in `graphTypes.ts`.

---

## Artifacts, Audit & Logs

`ArtifactsPage.tsx` — three tabs.

### Artifacts

Left: file list from `GET /runs/{id}/artifacts` (name + bytes via
`formatBytes`). Right: `ArtifactViewer` for the selected artifact (fetched as
a blob via `useFetchArtifactBlob`, with a `useArtifactUrl` helper for direct
download links). Empty state until the run writes reports.

### Audit

Chain-validity banner (`chain_valid` + `chain_reason`) and a records table
showing the first 6 columns of each audit record. Same data as the Run page's
Audit tab, full-page.

### Logs

`useRunLog` tail viewer. Two log families:

| Family | Names |
|--------|-------|
| Run-level | `mcp_exploit_server.log`, `session_error.log`, `recon_first_error.log` |
| Per-attempt | `terminal.log`, `python_run.log`, `msf_output.log`, `run_active_check.ps1` |

Per-attempt logs require `attempt_id` + `target_ip`, discovered from artifact
paths matching `exploit_workspace/<ip?>/<attempt>/`. Tail size adjustable
(1–2000 lines). Refresh button. An amber notice explains the attempt-discovery
heuristic when no attempts are found.

---

## Loot & Credentials

`LootPage.tsx` — two sections.

### Credentials

`CredentialTable` (`useCredentials` → `GET /runs/{id}/credentials`).
Passwords are masked by default; `useRevealCredential` calls
`POST /runs/{id}/credentials/<index>/reveal` to fetch a single revealed value
and invalidates the credentials query on success.

### Loot

`useLoot` → `GET /runs/{id}/loot`. Each loot item is an expandable card
showing `loot_type`, `description`, and a collapsible `<pre>` with
`content`/`path`. Empty state when no loot captured.

---

## API Client Layer

`webui/src/api/` — the only place that talks to the daemon.

### `client.ts`

- `getStoredToken` / `setStoredToken` / `clearStoredToken` — `sessionStorage`
  wrapper, defensive against private-mode throws.
- `apiFetch<T>(path, opts)` — the single fetch wrapper. Injects
  `Authorization: Bearer`, JSON `Content-Type` on writes, normalizes errors to
  `ApiError`. `raw: true` returns a `Blob` (for artifact download). Aborts
  propagate as `AbortError` (no re-wrap). Prefixes `/api/v1` unless the path
  already starts with `http` or `/api/`.
- `ApiError` — `{ status, code, details, requestId, raw }` with `isAuth` /
  `isConflict` / `isNotFound` getters. `status === 0` means network failure.
- `wsUrlForRun`-style URL building lives in `ws.ts` from `window.location`
  + stored token. The fetch-backed SSE transport (`sse.ts`) sends the token
  only in the `Authorization` header — never `?token=` in the URL.

### `ws.ts`

`useRunEvents` — see [Real-Time Transport](#real-time-transport). Holds refs
for the socket, EventSource, attempt counter, reconnect timer, and a
"closed by unmount" guard so cleanup doesn't trigger reconnect. Exposes
`reconnect()` for manual retry.

### `hooks.ts`

TanStack Query hooks. `queryKeys` centralizes every cache key. Notable
patterns:

- `useCreateRun` / `useCancelRun` / `useResumeRun` / `useDeleteRun` /
  `useAnswerDecision` / `usePatchConfig` / `usePutSecrets` / `useCallTool` /
  `useRevealCredential` / `useFetchArtifactBlob` — mutations that invalidate
  the relevant list/run/decisions queries on success.
- `useRuns` / `useRun` / `useDecisions` — polling hooks with
  `refetchInterval` that stops at terminal / no-pending state.
- `useSwarmState` / `useCampaignState` — skip retry on 404 (state file
  optional).
- `useLiveModels` — swallows 503 and returns the error payload as data (so
  the UI can show the daemon's error message instead of throwing). Source is
  `ollama` / `registry` / `chatgpt`.
- `useProviders` / `useChatgptLogin` / `useChatgptProxyStart` /
  `useChatgptProxyStop` — ChatGPT provider status + login/proxy lifecycle.
  The three mutations invalidate `providers` / `modelsLive` / `models` on
  settle. Login surfaces the OAuth URL; proxy stop is gated on `we_started`.
- `usePatchConfig` — `PATCH /config` (deep-merge). `onSuccess` sets the `/config`
  cache and also invalidates `models` / `modelsLive` / `providers`, since any
  config change can affect the model list or provider status (e.g. switching
  `models.provider` from the System → Models AI-provider card).

### `types.ts`

All API shapes as TS types: `RunState`, `DecisionKind`, `RunPreview`,
`RunResult`, `RunEvent`, `Capabilities`, `ReconAssessment`, `SkillDetail`,
etc. Plus `ACTIVE_RUN_STATES` / `TERMINAL_RUN_STATES` constants and helpers
`isActiveState` / `isTerminalState` / `stateCategory` (pending/active/done).

---

## UI Primitives & Styling

### `components/ui/*`

shadcn/ui-style primitives built on Radix UI + `class-variance-authority` +
`cn()`: `badge`, `button`, `card`, `checkbox`, `dialog`, `input`, `label`,
`popover`, `scroll-area`, `select`, `separator`, `switch`, `tabs`,
`textarea`, `toast`, `tooltip`. Edit these by regenerating from shadcn or
editing in place — they are vendored, not an npm dependency.

### Custom components

| Component | Role |
|-----------|------|
| `Layout` | Sidebar + mobile header + active-run pill + footer. |
| `TokenGate` / `OnboardingGate` | Pre-route gates. |
| `run-create/RunWizard` | Multi-step run creation (opsec → settings → target → review). |
| `run-create/*` | Step sections: `ModeSelector`, `TargetField`, `GoalSelector`, `ModelSelector`, `ExecutionProfile`, `AdvancedExecutionSettings`, `SkillsSettings`, `OpsecSettings`, `RunReview`, `RunStepper`, `RunSummary`. |
| `ui/segmented` | `SegmentedControl`, `TriStateToggle`, `SkillMultiSelect` shared by the wizard (not a legacy `RunForm`). |
| `events/EventViewer` + `eventRows` / `BootChecklist` / `ToolCallCard` / `DecisionCard` / `ReconAssessmentCard` / `GoalSuggestionCard` / `SessionSummaryCard` | Event-stream renderers. |
| `StatusBadge` | Run-state → colored badge. |
| `CopyButton` | Clipboard copy with icon + label. |
| `ConfigEditor` | System → Config form. |
| `ArtifactViewer` | Artifact blob renderer. |
| `CredentialTable` | Masked credentials with reveal. |
| `Toaster` | Toast viewport (Radix toast). |

### Styling

- Tailwind 3.4 with `darkMode: ["class"]`. Colors are HSL CSS vars defined in
  `src/index.css` `:root` (dark-only; no light theme).
- `cn()` (`lib/utils.ts`) = `twMerge(clsx(...))` for class merging.
- Custom utilities in `index.css`: `bg-grid`, `bg-radial-fade`, `text-gradient`,
  `glow-primary`, `animate-scan`, `animate-pulse-ring`, `scrollbar-thin`.
- Fonts: mono stack `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`.
- Container: centered, `1rem` padding.

### `lib/utils.ts`

`cn`, `truncateId` (head 8 + tail 4 with ellipsis), `formatRelative` (just
now / Ns / Nm / Nh / Nd / ISO date), `formatBytes` (B/KB/MB/GB/TB).

---

## Conventions

- **Imports:** `@/` alias → `src/` (configured in both `vite.config.ts` and
  `tsconfig.app.json`).
- **TypeScript:** `strict`, `noUnusedLocals`, `noUnusedParameters`,
  `noFallthroughCasesInSwitch`. Target ES2021, lib ES2023 + DOM.
- **No comments in component code** unless explaining a non-obvious decision
  (e.g. `// ponytail: ...`). The codebase follows this.
- **Server state via TanStack Query only** — no ad-hoc `useEffect` fetches.
  Add a hook in `hooks.ts`, add a key in `queryKeys`.
- **Token via `client.ts` only** — never read the bearer token outside the
  client layer (the token lives in module memory; `sessionStorage` holds only
  the telemetry session baseline, onboarding flag, notice keys, and
  permission-mode prefs).
- **Error surfaces:** `ApiError` is the normalized shape; use its
  `.isAuth` / `.isConflict` / `.isNotFound` getters rather than checking
  `status` literally.
- **Redaction is server-side:** the SPA renders whatever `sanitize()` lets
  through. Don't add client-side secret scrubbing.
- **Loopback-only assumption:** the SPA never needs to handle public binds or
  CORS to non-loopback origins — the daemon refuses them. Don't add origin
  whitelisting UI.

---

## Extension Points

### Add a page

1. Create `src/routes/MyPage.tsx` exporting a component.
2. Add a `<Route>` under `<Layout>` in `App.tsx`.
3. Add a nav entry to `NAV_ITEMS` in `Layout.tsx` (with a lucide icon).
4. If it needs a new API hook, add it to `hooks.ts` + a key in `queryKeys`.

### Add an API hook

1. Add the response type to `types.ts`.
2. Add a key to `queryKeys` in `hooks.ts`.
3. Add a `useXxx` hook using `useQuery` / `useMutation`, spread
   `defaultQueryOptions`, set `enabled`/`staleTime`/`refetchInterval` as
   needed.
4. On mutations, invalidate the queries that should refetch
   (`qc.invalidateQueries({ queryKey: ... })`).
5. For new REST routes, the backend side is documented in
   [api.md](api.md) and lives in `tools/api/routes/`.

### Add a UI primitive

Prefer checking whether shadcn/ui already has one (badge/button/card/dialog/
input/etc.). If a new one is needed, vendor it under `components/ui/` using
Radix + `cva` + `cn`, matching the existing file style.

### Add an event renderer

`EventViewer`'s `renderSimpleEvent` (in `components/events/EventViewer.tsx`)
switch handles non-tool, non-approval events. Add a `case` for a new
`EventType` and a dedicated card component if the payload is structured (see
`ReconAssessmentCard` / `GoalSuggestionCard` for the pattern). Add the type
to `EventType` in `types.ts`.

### Add a tab to the Run page

Add a `<TabsTrigger>` + `<TabsContent>` in `RunPage.tsx`. Gate it on a
`request.*` flag if it's optional (see `swarm` / `long_session`). Fetch its
data via a hook in `hooks.ts`.

---

## File Map

```
webui/
├─ index.html                    # dark <html>, #root mount point
├─ package.json                  # name, version (→ __APP_VERSION__), scripts
├─ vite.config.ts                # dev/preview proxy, @/ alias, build target
├─ tailwind.config.ts            # darkMode class, HSL-var colors, mono font
├─ postcss.config.js             # tailwind + autoprefixer
├─ tsconfig.{app,node,json}.json # app: strict, @/* path map
└─ src/
   ├─ main.tsx                   # ReactDOM root
   ├─ App.tsx                    # QueryClient + BrowserRouter + gates + routes
   ├─ index.css                  # HSL vars, base + utilities
   ├─ vite-env.d.ts
   ├─ test/setup.ts              # jest-dom matchers + RTL cleanup per test
   ├─ lib/utils.ts               # cn, truncateId, formatRelative, formatBytes
   ├─ hooks/use-toast.ts         # toast store
   ├─ api/
   │  ├─ client.ts               # apiFetch, ApiError, token storage, ws/sse URL builders
   │  ├─ ws.ts                   # useRunEvents (WS + SSE fallback) + graph invalidation
   │  ├─ hooks.ts                # TanStack Query hooks + queryKeys
   │  └─ types.ts                # all API types + state helpers
   ├─ features/graph/            # Attack Graph page (see Attack Graph Page)
   │  ├─ AttackGraphPage.tsx     # three-panel layout + state orchestration
   │  ├─ AttackGraphCanvas.tsx   # React Flow v11 canvas (pan/zoom/fit/drag/select)
   │  ├─ GraphNodeTypes.tsx      # custom graph node renderer
   │  ├─ GraphFilters.tsx        # run/node-type/status/search/confidence
   │  ├─ GraphToolbar.tsx        # fit/reset/expand/path/conflicts/focus-search
   │  ├─ GraphStats.tsx          # summary chips + conflict count + hub
   │  ├─ GraphDetailsPanel.tsx   # real-metadata node inspector
   │  ├─ GraphPathFinder.tsx     # bounded start→end path requests
   │  ├─ graphApi.ts             # TanStack Query hooks (graphKeys)
   │  ├─ graphTransforms.ts      # pure DTO→UI mapping + search
   │  ├─ graphTypes.ts           # explorer API DTO types + enums
   │  ├─ index.ts
   │  └─ __tests__/              # vitest (jsdom) coverage
   ├─ components/
   │  ├─ Layout.tsx
   │  ├─ TokenGate.tsx
   │  ├─ OnboardingGate.tsx
   │  ├─ run-create/RunWizard.tsx # multi-step run creation (+ step sections)
   │  ├─ events/EventViewer.tsx  # event stream renderer (+ eventRows.ts)
   │  ├─ BootChecklist.tsx
   │  ├─ ToolCallCard.tsx
   │  ├─ DecisionCard.tsx
   │  ├─ ReconAssessmentCard.tsx
   │  ├─ GoalSuggestionCard.tsx
   │  ├─ SessionSummaryCard.tsx
   │  ├─ StatusBadge.tsx
   │  ├─ CopyButton.tsx
   │  ├─ ConfigEditor.tsx
   │  ├─ ArtifactViewer.tsx
   │  ├─ CredentialTable.tsx
   │  ├─ Toaster.tsx
   │  └─ ui/                     # vendored shadcn/ui primitives (Radix + cva)
   └─ routes/
      ├─ HomePage.tsx
      ├─ RunListPage.tsx
      ├─ NewRunPage.tsx          # wraps <RunWizard>
      ├─ RunPage.tsx             # live run view
      ├─ ArtifactsPage.tsx
      ├─ LootPage.tsx
      ├─ GraphPage.tsx           # per-run graph view
      ├─ MemoryPage.tsx
      ├─ SkillsPage.tsx
      ├─ AttackModulesPage.tsx
      ├─ GoalsPage.tsx
      ├─ StatsPage.tsx
      ├─ ConnectionsPage.tsx
      ├─ BenchmarksPage.tsx / BenchmarksStartPage.tsx / BenchmarksHistoryPage.tsx / BenchmarkRunPage.tsx
      ├─ OpsPage.tsx
      ├─ HelpPage.tsx
      └─ SystemPage.tsx
```

---

## Related

- [api.md](api.md) — the `/api/v1` REST + WebSocket reference the SPA talks to.
- [architecture.md](architecture.md) — system shape, entry points, Flow A/B.
- [getting-started.md](getting-started.md) — daemon setup, `--doctor`,
  `--self-test`.
- `config.yaml` `api` block — `host`, `port`, `token_file`,
  `allowed_origins`, `event_buffer_size`, `shutdown_timeout_seconds`,
  `serve_webui`. See [api.md §Config Reference](api.md).