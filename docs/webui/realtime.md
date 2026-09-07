---
title: Realtime — WS Primary + SSE Fallback, Watchdog, Event Windows
sources:
  - webui/src/api/ws.ts
  - webui/src/api/sse.ts
  - webui/src/api/eventStore.ts
  - webui/src/api/eventBuffer.ts
  - webui/src/api/client.ts
  - docs/webui/api-integration.md
tests: []
subsystem: webui
---

# Realtime events — WebSocket primary, SSE fallback

`useRunEvents(runId, { after, enabled })` in `webui/src/api/ws.ts` is the single live-event funnel. It seeds from replay, opens a WebSocket primary, and falls back to fetch-backed SSE after repeated WS failures. Both transports share one cursor (`lastSeqRef`), one bounded UI window (`MAX_EVENTS_PER_RUN = 1000`), and one session cache (`eventStore`, LRU-10).

## Transport overview

| Transport | URL pattern | Auth | When used |
|-----------|-------------|------|-----------|
| WebSocket primary (`connectWs`) | `ws(s)://<host>/api/v1/ws/v1/runs/<runId>` | first message `{ auth: token, after: N }` | default; `setTransport("websocket")` |
| SSE fallback (`connectSse` via `streamSSE`) | `<origin>/api/v1/runs/<runId>/events/stream?after=<seq>` | `Authorization: Bearer` header; never `?token=` query string | after `SSE_FALLBACK_THRESHOLD = 3` WS failures |
| Replay seed (`seedEvents`) | `/runs/<id>/events?tail=MAX_EVENTS_PER_RUN` via `apiFetch` | `Authorization: Bearer` via `apiFetch` | before first connect, and after close `4400` |

`useRunEvents` returns `{ events, status, stale, authError, transport, reconnect, lastSeq, dropped }`. `WsStatus` is `"idle" | "connecting" | "open" | "reconnecting" | "closed" | "error"`. `transport` is `"websocket" | "sse" | "none"`.

```ts
const { events, status, stale, authError, transport, reconnect, dropped } =
  useRunEvents(runId, { after: 0, enabled: true });
```

## WebSocket primary (`ws.ts`)

### Connect + auth

`connectWs(id)` builds the URL from `window.location` (`wss` when `protocol === "https:"`, else `ws`), opens a `WebSocket`, and on `onopen` resets `attemptRef`, stamps `lastFrameAtRef`, sets status `open`, and sends the cursor:

```ts
socket.send(JSON.stringify({ auth: token, after: lastSeqRef.current }));
```

`token` comes from `getStoredToken()`. `onmessage` parses `message.data` as `RunEvent` via `JSON.parse` and calls `handleEvent`; malformed frames are ignored. `onerror` sets status `error`.

### Close codes

| Code | Constant | Behavior in `onclose` |
|------|----------|------------------------|
| `4400` | `WS_CLOSE_CURSOR` | invalid cursor: reset `lastSeqRef` to `0`, clear local events/`dropped`, `eventStore.clear(id)`, re-run `seedEvents(id)` |
| `4401` | `WS_CLOSE_AUTH` | auth rejected: set `authError`, call `expireSession`, set status `error`, no reconnect |
| `4403` | `WS_CLOSE_ORIGIN` | origin rejected: set `authError`, set status `error`, no reconnect |
| `4404` | `WS_CLOSE_NOT_FOUND` | run not found: set `authError`, set status `error`, no reconnect |

The `onclose` guard only clears `wsRef` when the closing socket is still the active one, so a watchdog-triggered replacement is never orphaned. `closedByUnmountRef` stops all reconnects on unmount.

### Reconnect + SSE fallback

Transient closes increment `wsFailureCountRef`. At `>= SSE_FALLBACK_THRESHOLD` (3) the hook calls `connectSse(id)` and resets the counter; otherwise it schedules `connectWs(id)` with `backoffMs(attempt) = min(MAX_BACKOFF, 1000 * 2 ** attempt)` where `MAX_BACKOFF = 10_000`. `reconnect()` (exposed to UI) resets both counters, closes SSE and any WS socket, and calls `connectWs` fresh.

## SSE fallback (`streamSSE` Bearer header)

`connectSse(id)` cancels any pending WS reconnect timer, reads `getStoredToken()`, creates an `AbortController`, sets `setTransport("sse")`, and calls `streamSSE` with a URL factory so each reconnect uses the freshest cursor:

```ts
const handle = streamSSE({
  url: () =>
    `${loc.origin}/api/v1/runs/${encodeURIComponent(id)}/events/stream` +
    `?after=${lastSeqRef.current}`,
  token,
  signal: controller.signal,
  onEvent: (msg) => handleEvent(JSON.parse(msg.data ?? "")),
  onStatus: (state) => { /* connecting|open|reconnecting|closed → WsStatus */ },
  onActivity: () => { lastFrameAtRef.current = Date.now(); setStale(false); },
  onFatal: (error) => { /* authError → expireSession, else authError message */ },
});
```

The token travels only in the `Authorization: Bearer` header (`sse.ts` sets `headers.Authorization = "Bearer <token>"` plus `Accept: text/event-stream` and `Cache-Control: no-cache`). It is never logged, never put in errors, and never placed in the URL — native `EventSource` cannot set headers, which is why this path uses `fetch` instead.

### `streamSSE` lifecycle

| Option / symbol | Semantics from `sse.ts` |
|-----------------|--------------------------|
| `url: string \| (() => string)` | absolute URL or per-attempt factory (used for `?after=` cursor); never includes the token |
| `token: string` | Bearer token, header-only |
| `signal: AbortSignal` | external cancellation (run switch, unmount, auth change) |
| `onEvent(msg: SseMessage)` | one call per blank-line-terminated event |
| `onStatus(state: SseConnectionState)` | `connecting \| open \| reconnecting \| closed` |
| `onFatal(err: SseFatalError)` | non-retryable: `{ authError, message }`; message never contains the token |
| `onActivity()` | every successful transport-level read, including `:` keepalive comments the parser drops |
| `onOpen()`, `maxRetries` | optional open hook; default retries unlimited, `maxRetries` caps attempts |
| `SseHandle { close, restart }` | `close()` aborts + stops timers (idempotent); `restart()` drops the current connection and reconnects immediately with a fresh cursor |

HTTP handling: `401`/`403` → `fatal({ authError: true })` (do not reconnect); other non-OK → fatal non-auth; missing `response.body` → fatal. A server-side clean close emits `reconnecting` and schedules backoff `min(10_000, 1000 * 2 ** attempt)`. Abort from `close()`/`restart()` is silent; abort from the internal watchdog reconnects (see below).

## `SseParser`

Incremental, chunk-safe field parser. `push(chunk)` buffers partial lines and returns complete `SseMessage[]` per blank-line-terminated event; `finish()` flushes a trailing unterminated event at stream end.

| Field | Handling in `processLine` |
|-------|----------------------------|
| `:` comment / keepalive | ignored (never reaches `onEvent`; visible only via `onActivity`) |
| `data:` | appended; multiline `data:` lines joined with `"\n"` on `dispatch` |
| `event:` | sets event name when non-empty (default `"message"`) |
| `id:` | sets `lastId` unless the value contains `\0` |
| `retry:` | `parseInt` when numeric, else ignored |
| unknown field | ignored per spec |
| blank line | `dispatch`: emits `{ id, event, data, retry }` only when at least one `data:` line exists, then resets `data`/`eventType` |

```ts
const parser = new SseParser();
for (const message of parser.push(decoder.decode(value, { stream: true }))) {
  options.onEvent(message);
}
```

`SseMessage` is `{ id: string | null, event: string, data: string | null, retry: number | null }`.

## Watchdog + stale (90s watchdog, 45s stale)

The daemon heartbeats after ~30s of quiet on both transports (per the `ws.ts`/`sse.ts` comments). Two thresholds ride on `lastFrameAtRef` (every frame counts, heartbeats included):

| Constant | Value | Meaning |
|----------|-------|---------|
| `STALE_AFTER_MS` | `45_000` | silence while status is `open` flips the `stale` flag (UI warning, stream kept) |
| `WATCHDOG_TIMEOUT_MS` | `90_000` (90s) | three missed heartbeats: force-reconnect a socket the OS silently dropped (sleep, NAT expiry, no `onclose`) |
| `WATCHDOG_TICK_MS` | `10_000` | interval that evaluates silence |
| `SSE_WATCHDOG_MS` | `90_000` (90s) | fetch-SSE equivalent: abort a silent stream and reconnect via the normal backoff path |

WS tick behavior: when silence exceeds 90s and status is `open`, reset `lastFrameAtRef`/`attemptRef`, then `wsRef.current?.close()` (so `onclose` drives the normal reconnect + SSE-fallback path) or `sseHandleRef.current?.restart()` when on SSE. SSE internal behavior: `resetWatchdog()` arms on connect, open, and every read; firing resets the backoff ladder (`attempt = 0`), marks `watchdogTripped`, and aborts the active controller so the catch branch reconnects. `restart()` clears the previous generation's watchdog so it cannot kill the fresh connection.

Wake-up paths: `visibilitychange` → visible and `window` `online` events stamp `lastFrameAtRef`, reset backoff, clear `stale`, and call `reconnect()` when status is not `open`.

## Event pipeline

### Seed

`seedEvents(id, isCancelled?)` fetches `GET /runs/<id>/events?tail=MAX_EVENTS_PER_RUN`, reads `events`, `latest_sequence`, and `omitted_before` (falling back to `has_more_before ? oldest_sequence - 1 : 0` for older servers), sets `lastSeqRef = latest` as the live cursor, calls `eventStore.set(id, seeded, latest, older)`, and mirrors into local `events`/`dropped` state. On network/run-not-found failure it silently keeps the current cursor so the WS/SSE path can surface auth/404. When `eventStore.get(runId)` already has an entry, the effect reuses its cursor + events and connects without reseeding.

### `handleEvent` + batching

1. Stamp `lastFrameAtRef = Date.now()`, clear `stale`. Heartbeats bump `lastSeq` when newer and return early.
2. Drop duplicates with `sequence <= lastSeqRef.current`; otherwise advance `lastSeqRef`.
3. `eventStore.append(id, event)` and `patchCaches(event)`.
4. `IMMEDIATE_EVENT_TYPES = new Set(["state", "approval", "error", "title"])` flush synchronously (cancel any pending `requestAnimationFrame`, append `[...pending, event]` via `appendBounded`). All other types push to `pendingRef` and flush on the next animation frame (`flushPending` → `appendBounded(eventsRef.current, batch)`, accumulating `dropped`).

### `patchCaches` behavior

Best-effort React Query patching (`try/catch`, never breaks the stream) keyed off `runIdRef.current`:

| Event type | Cache effect |
|------------|--------------|
| `state` | `setQueryData(queryKeys.run(id))` with `payload.state` (plus `payload.result` when present); `invalidateQueries({ queryKey: ["runs"] })` |
| `approval` | `invalidateQueries({ queryKey: queryKeys.runDecisions(id) })` |
| `artifact` | `invalidateQueries({ queryKey: queryKeys.runArtifacts(id) })` and `invalidateQueries({ queryKey: ["graphExplorer", id] })` (attack graph rebuilds from audit/report artifacts) |

## Bounded windows (`MAX_EVENTS_PER_RUN = 1000`, `eventStore` LRU-10)

`MAX_EVENTS_PER_RUN = 1000` (in `eventBuffer.ts`) caps every live-event collection — UI state and `eventStore` alike. `appendBounded(prev, batch): AppendResult` is pure and never mutates `prev`:

```ts
export function appendBounded(prev: RunEvent[], batch: RunEvent[]): AppendResult {
  if (batch.length === 0) return { events: prev, dropped: 0 };
  const over = prev.length + batch.length - MAX_EVENTS_PER_RUN;
  if (over <= 0) return { events: [...prev, ...batch], dropped: 0 };
  // …trim only the head (or slice the batch tail when batch >= MAX)
}
```

`dropped` counts events aged out of the window; they still exist server-side.

| `eventStore` member | Semantics |
|---------------------|-----------|
| `MAX_RUNS = 10` + `evict()` | session-only in-memory LRU over run IDs; `get` re-inserts to mark most-recently-used, `set`/`append` re-insert after write, overflow deletes oldest first |
| `Entry { events, cursor, dropped }` | per-run window + live cursor + omitted-older count |
| `set(runId, events, cursor, dropped)` | trims via `appendBounded([], events)`, stores, evicts |
| `append(runId, event)` | no-ops when `event.sequence <= cursor` (dedupe); otherwise advances cursor, immutable `appendBounded`, accumulates `dropped`, re-inserts LRU |
| `get(runId)` / `cursor(runId)` / `clear(runId)` | LRU-touching read; cursor read defaulting to `0`; delete |
| singleton `eventStore` | shared across mounts so revisiting a run resumes from its cursor instead of replaying from zero |

## Auth + session expiry (`client.ts`)

The bearer token lives in module memory only (`getStoredToken` / `setStoredToken` / `clearStoredToken`). `expireSession(reason)` is the shared funnel for HTTP 401, WS close `4401`, and SSE fatal `authError`: first caller wins (guarded by stored-token presence), clears the token, dispatches `AUTH_EXPIRED_EVENT = "breachpilot:auth-expired"` for `TokenGate`, and toasts session expiry. `apiFetch` prefixes `/api/v1`, injects `Authorization: Bearer`, and normalizes errors into `ApiError`.

Implementation note: server-side heartbeat cadence (~30s), WS close-code origins, and `hmac` comparison live in the API daemon, not in the files read here; the client constants above are the contract surface.

## Related documentation

- [API Integration](./api-integration.md) — REST/hook endpoint map and transport table (`streamSSE` Bearer header, replay)
- [State](./state.md) — query keys, `patchCaches` invalidation fans, `eventBuffer`/`eventStore` summary, decision wiring
- [Overview](./overview.md) — WebUI bootstrap, routing, auth gates
- [API reference](../api.md) — daemon REST + WebSocket surface the SPA targets

## Source map

- `webui/src/api/ws.ts`
- `webui/src/api/sse.ts`
- `webui/src/api/eventStore.ts`
- `webui/src/api/eventBuffer.ts`
- `webui/src/api/client.ts`
