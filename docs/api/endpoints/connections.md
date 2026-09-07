---
title: Connections Endpoints — List, Get, Check, Remove, Listener Output
sources:
  - tools/api/routes/connections.py
  - tools/operator_connection/manager.py
  - tools/persistent_session_manager.py
  - tools/api/auth.py
  - app.py
tests:
  - tests/test_connections_api.py
subsystem: api
---

# Connections Endpoints

`tools/api/routes/connections.py:1` — `APIRouter(prefix="/api/v1", tags=["connections"])`. Created by `create_router(auth, config, config_path)` (`tools/api/routes/connections.py:107`) and mounted **unconditionally** in `app.py:168` / `app.py:182` (unlike the users routes, there is no feature gate). Every route below requires bearer (`_require_auth` `tools/api/routes/connections.py:111`); every `{connection_id}` route validates the id with `_validate_connection_id` and returns `404` for unknown ids.

Source of truth: the `ConnectionManager` (`tools/operator_connection/manager.py`) — this module never reads/writes `operator_connections.json` directly. Listener output goes through `PersistentSessionManager` (`tools/persistent_session_manager.py`), the same tmux/nohup/nc back-end the operator implants use. Workspace resolution (`tools/api/routes/connections.py:114`): `operator_connection.workspace_dir`, falling back to `exploit.workspace_dir`; relative paths resolve against `config_path.parent`.

Connection id validation (`tools/api/routes/connections.py:29`): empty → `400 Invalid connection id`; any `/`, `\`, `..`, length > 64, or chars outside `[A-Za-z0-9._-]+` → `400 Invalid connection id`. The canonical form is `conn-` + 8 hex chars (`_CONN_ID_RE`), but other manager-created ids are tolerated.

`ConnectionResponse` (`tools/api/routes/connections.py:45`):

| Field | Type | Notes |
|-------|------|-------|
| `connection_id` | `str` | e.g. `conn-1a2b3c4d` |
| `target_ip` | `str` | |
| `method` | `str` | implant/callback method |
| `callback_host` / `callback_port` | `str` / `int` | |
| `listener_name` | `str` | PersistentSessionManager listener name |
| `status` | `str` | `active\|stale\|removed\|error` |
| `created_at` | `float` | epoch |
| `created_at_iso` / `last_beacon_iso` / `last_check_iso` | `str\|null` | ISO-8601 projections |
| `last_beacon` / `last_check` | `float\|null` | epoch |
| `check_output` | `str` | last health-check output |
| `implant_path` / `mitre_technique` / `os_family` / `notes` | `str` | enrichment, may be `""` |

## `GET /api/v1/connections` — `list_connections`

`tools/api/routes/connections.py:142` — list persisted operator connections with optional filters and status counts.

Purpose: inventory of callback/beacon connections, filterable for dashboards.

Authentication: bearer required.

Query params:

| Param | Type | Notes |
|-------|------|-------|
| `status` | `str\|null` | `active\|stale\|removed\|error` (case-insensitive: stripped + lowered). Invalid value → `400` |
| `target` | `str\|null` | target-IP filter, passed to `mgr.list_connections(target_ip=...)` |

Status codes: `200` with `ConnectionsListResponse` (`tools/api/routes/connections.py:66`) — `{connections:[...], total, active, stale, removed, error}`. Counts are computed over the **filtered** set (`_counts(recs)` `tools/api/routes/connections.py:98`). `400` invalid status (`Invalid status 'x'. Must be one of: active, error, removed, stale`). `401` missing/bad bearer.

Error conditions: unknown `status` value; anything else is manager passthrough.

Example request:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/v1/connections?status=active&target=10.0.0.50"
```

Example response:

```json
{
  "connections": [
    {
      "connection_id": "conn-1a2b3c4d",
      "target_ip": "10.0.0.50",
      "method": "reverse_shell",
      "callback_host": "127.0.0.1",
      "callback_port": 4444,
      "listener_name": "listener-10-0-0-50",
      "status": "active",
      "created_at": 1756680000.0,
      "created_at_iso": "2026-08-31T12:00:00+00:00",
      "last_beacon": 1756680100.0,
      "last_beacon_iso": "2026-08-31T12:01:40+00:00",
      "last_check": 1756680200.0,
      "last_check_iso": "2026-08-31T12:03:20+00:00",
      "check_output": "listener running (no recent output)",
      "implant_path": "",
      "mitre_technique": "",
      "os_family": "",
      "notes": ""
    }
  ],
  "total": 1,
  "active": 1,
  "stale": 0,
  "removed": 0,
  "error": 0
}
```

Related events: none emitted.

WebUI usage: `ConnectionsPage` (`webui/src/routes/ConnectionsPage.tsx`, route `/connections` in `webui/src/App.tsx:70`, nav entry `webui/src/components/Layout.tsx:22`) driven by `useConnections({status, target})` (`webui/src/api/hooks.ts:1107`); the nav badge shows the live `active` count (`webui/src/components/Layout.tsx:79,131`).

Source file: `tools/api/routes/connections.py`.

## `GET /api/v1/connections/{connection_id}` — `get_connection`

`tools/api/routes/connections.py:173` — fetch one connection record via `mgr.get(cid)`.

Purpose: detail view for a single connection.

Authentication: bearer required.

Params: `connection_id` path param, validated by `_validate_connection_id`.

Status codes: `200` with a single `ConnectionResponse`. `400` invalid id shape. `404 Connection not found`. `401` missing/bad bearer.

Error conditions: traversal/oversize/malformed id → `400`; unknown id → `404`.

Example request:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/v1/connections/conn-1a2b3c4d
```

Example response:

```json
{
  "connection_id": "conn-1a2b3c4d",
  "target_ip": "10.0.0.50",
  "method": "reverse_shell",
  "callback_host": "127.0.0.1",
  "callback_port": 4444,
  "listener_name": "listener-10-0-0-50",
  "status": "active",
  "created_at": 1756680000.0,
  "created_at_iso": "2026-08-31T12:00:00+00:00",
  "last_beacon": 1756680100.0,
  "last_beacon_iso": "2026-08-31T12:01:40+00:00",
  "last_check": 1756680200.0,
  "last_check_iso": "2026-08-31T12:03:20+00:00",
  "check_output": "listener running (no recent output)",
  "implant_path": "",
  "mitre_technique": "",
  "os_family": "",
  "notes": ""
}
```

Related events: none emitted.

WebUI usage: `useConnection(connectionId)` (`webui/src/api/hooks.ts:1136`) powers the connection detail view in `ConnectionsPage`.

Source file: `tools/api/routes/connections.py`.

## `POST /api/v1/connections/{connection_id}/check` — `check_connection`

`tools/api/routes/connections.py:185` — health-check a connection against live listener state and persist the verdict.

Purpose: re-probe whether the listener back-end for a connection is still alive; updates `status` to `active`/`stale`, or `error` on hard failure.

Authentication: bearer required.

Body: none. Path param `connection_id` validated as above.

Behavior (`tools/api/routes/connections.py:196`):

1. `sess_mgr.read_listener_output(rec.listener_name, lines=100)` (bounded, never unlimited). Output starting with `LOG_NOT_FOUND`/`INVALID_NAME` → unhealthy; otherwise healthy iff `running` is true.
2. Fallback: if the listener looks stopped, `list_all_sessions()` is consulted — a matching running session flips the verdict to healthy with output `listener running (no recent output)`; otherwise output `listener '<name>' not running`.
3. `mgr.mark_check(cid, output, healthy)` (`tools/operator_connection/manager.py:223`) persists `active`/`stale` + output + `last_check`.
4. Hard failure (output prefixed `health check failed`) promotes the record to `error` with `check_output` truncated to 2000 chars and `mgr._save()`.

Status codes: `200` with the updated `ConnectionResponse`. `400` invalid id. `404 Connection not found` (before or after the check). `500 Health check error: ...` when the manager update itself throws. `401` missing/bad bearer.

Error conditions: unknown connection; listener gone (yields `stale`, not an error); `PersistentSessionManager` exception (yields `stale` or `error` record, `200`).

Example request:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/v1/connections/conn-1a2b3c4d/check
```

Example response (shape: updated `ConnectionResponse`):

```json
{
  "connection_id": "conn-1a2b3c4d",
  "target_ip": "10.0.0.50",
  "method": "reverse_shell",
  "callback_host": "127.0.0.1",
  "callback_port": 4444,
  "listener_name": "listener-10-0-0-50",
  "status": "stale",
  "created_at": 1756680000.0,
  "created_at_iso": "2026-08-31T12:00:00+00:00",
  "last_beacon": 1756680100.0,
  "last_beacon_iso": "2026-08-31T12:01:40+00:00",
  "last_check": 1756680300.0,
  "last_check_iso": "2026-08-31T12:05:00+00:00",
  "check_output": "listener 'listener-10-0-0-50' not running",
  "implant_path": "",
  "mitre_technique": "",
  "os_family": "",
  "notes": ""
}
```

Related events: none emitted.

WebUI usage: check mutation (`webui/src/api/hooks.ts:1169`, `POST .../check`) with connections-query invalidation (`webui/src/api/hooks.ts:1175`), so list/detail refresh after each check.

Source file: `tools/api/routes/connections.py`.

## `POST /api/v1/connections/{connection_id}/remove` — `remove_connection`

`tools/api/routes/connections.py:264` — retire a connection, preserving the record for audit, with best-effort listener cleanup.

Purpose: operator-initiated teardown of a callback connection.

Authentication: bearer required.

Body: none. Path param `connection_id` validated as above.

Behavior: `mgr.mark_removed(cid)` (`tools/operator_connection/manager.py:231`) flips status to `removed` (record kept, not deleted). Then best-effort `sess_mgr.stop_listener(listener_name)`, falling back to `stop_background_job(listener_name)`. Listener-stop failure never fails the removal (`listener_stopped: false`).

Status codes: `200` with `RemoveResponse` (`tools/api/routes/connections.py:84`) — `{connection: <ConnectionResponse>, removed: true, listener_stopped: bool}`. `400` invalid id. `404 Connection not found`. `401` missing/bad bearer.

Error conditions: unknown connection; `mark_removed` returning false → `404`.

Example request:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/v1/connections/conn-1a2b3c4d/remove
```

Example response:

```json
{
  "connection": {
    "connection_id": "conn-1a2b3c4d",
    "target_ip": "10.0.0.50",
    "method": "reverse_shell",
    "callback_host": "127.0.0.1",
    "callback_port": 4444,
    "listener_name": "listener-10-0-0-50",
    "status": "removed",
    "created_at": 1756680000.0,
    "created_at_iso": "2026-08-31T12:00:00+00:00",
    "last_beacon": 1756680100.0,
    "last_beacon_iso": "2026-08-31T12:01:40+00:00",
    "last_check": 1756680300.0,
    "last_check_iso": "2026-08-31T12:05:00+00:00",
    "check_output": "listener 'listener-10-0-0-50' not running",
    "implant_path": "",
    "mitre_technique": "",
    "os_family": "",
    "notes": ""
  },
  "removed": true,
  "listener_stopped": false
}
```

Related events: none emitted.

WebUI usage: remove mutation (`webui/src/api/hooks.ts:1186`, `POST .../remove`) with connections-query invalidation; removed rows stay visible under the `removed` status filter since the record is preserved.

Source file: `tools/api/routes/connections.py`.

## `GET /api/v1/connections/{connection_id}/listener` — `get_listener_output`

`tools/api/routes/connections.py:311` — bounded tail of the listener log backing a connection.

Purpose: inspect what a callback listener has received without opening an unbounded log.

Authentication: bearer required.

Query params:

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `lines` | `int` | `100` | `1..500` (FastAPI-validated); output additionally truncated to the last 16384 chars |

Status codes: `200` with `ListenerOutputResponse` (`tools/api/routes/connections.py:75`) — `{connection_id, listener_name, output, updated_at (UTC ISO), running, status}` where `status` is `running` / `stopped` / `not_found` (`LOG_NOT_FOUND`/`INVALID_NAME` output) / `unknown` (non-dict result) / `error` (exception → `output: "listener unavailable: ..."`). This route deliberately never `500`s on listener problems. `400` invalid id (or `lines` out of range, via query validation). `404 Connection not found`, or `404 No listener associated with this connection` when `listener_name` is empty. `401` missing/bad bearer.

Error conditions: unknown connection; connection with no listener name; missing listener log (returned as `status: "not_found"` with `200`, not an error).

Example request:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/v1/connections/conn-1a2b3c4d/listener?lines=50"
```

Example response:

```json
{
  "connection_id": "conn-1a2b3c4d",
  "listener_name": "listener-10-0-0-50",
  "output": "$ whoami\nwww-data\n",
  "updated_at": "2026-08-31T12:06:00+00:00",
  "running": true,
  "status": "running"
}
```

Related events: none emitted.

WebUI usage: `useConnectionListener(connectionId)` (`webui/src/api/hooks.ts:1153`) renders the listener tail in the connection detail view.

Source file: `tools/api/routes/connections.py`.

## Tests

`tests/test_connections_api.py` builds the app with a temp `config.yaml` and exercises list/get/check/remove/listener against mocked manager/session state.

## Related documentation

- [Runs endpoints](./runs.md) — run lifecycle these connections are opened from
- [Events endpoints](./events.md) — per-run event streams (connections routes emit none)
- [API overview](../overview.md) — daemon, loopback bind, router layout
- [API auth](../auth.md) — bearer token, loopback enforcement
- [API persistence](../persistence.md) — `api_runtime.db` backing store
- [Endpoint matrix](../endpoint-matrix.md) — full route table

## Source map

- `tools/api/routes/connections.py`
- `tools/operator_connection/manager.py`
- `tools/persistent_session_manager.py`
- `tools/api/auth.py`
- `app.py`
- `config.yaml`
- `tests/test_connections_api.py`
- `webui/src/routes/ConnectionsPage.tsx`
- `webui/src/api/hooks.ts`
- `webui/src/api/types.ts`
- `webui/src/components/Layout.tsx`
- `webui/src/App.tsx`
