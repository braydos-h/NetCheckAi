---
title: Users & Annotations Endpoints — Accounts, Login, Per-Run Operator Comments
sources:
  - tools/api/routes/users.py
  - tools/api/auth.py
  - tools/api/persistence.py
  - tools/api/event_broker.py
  - app.py
tests:
  - tests/test_users.py
subsystem: api
---

# Users & Annotations Endpoints

`tools/api/routes/users.py:1` — `APIRouter(prefix="/api/v1", tags=["users"])`, created by `create_router(auth, persistence)` (`tools/api/routes/users.py:68`). Multi-operator user accounts (stdlib `hashlib.pbkdf2_hmac` + `secrets`, no new dep) plus per-run annotations (operator comments on findings) for pair-testing collaboration. No roles/permissions system.

> **Feature gate — `api.multi_operator`.** These six routes are mounted **only** when `api.multi_operator` is true (`app.py:171` / `app.py:185`). With the gate absent/false the router is never created and every path below is an unmounted-route `404` — verified by `tests/test_users.py:236`. The lab `config.yaml:448` sets `multi_operator: true`; the default is off. The WebUI exposes the toggle as settings key `api.multi_operator` (`webui/src/features/settings/settingMeta.ts:2405`).
>
> The gate changes nothing about the trust boundary: the loopback bind (`assert_api_loopback`, `tools/api/auth.py`) still refuses non-loopback hosts, and every route below additionally requires the bearer token via `_require_auth` (`tools/api/routes/users.py:72`). The user account is an attribution layer on top of the bearer gate, not a replacement for it.

Shared models: `CreateUserRequest` / `LoginRequest` / `UserResponse` (`tools/api/routes/users.py:34`), `AnnotationRequest` / `AnnotationResponse` (`tools/api/routes/users.py:51`). Passwords are hashed with PBKDF2-HMAC-SHA-256, 200k iterations, 16-byte salt (`tools/api/auth.py:275` `hash_password` / `:292` `verify_password`); password hashes are stored in `api_runtime.db` (`tools/api/persistence.py:712`) and never returned by any route.

`UserResponse` (`tools/api/routes/users.py:44`): `{id, username, created_at, last_login}` — `last_login` is `""` until the first login.

`AnnotationResponse` (`tools/api/routes/users.py:58`): `{id, run_id, user_id, username, body, finding_ref, created_at}`.

## `POST /api/v1/users` — `create_user` — 201

`tools/api/routes/users.py:79` — create a user account.

Purpose: register an operator identity used to attribute annotations.

Authentication: bearer required (like every v1 route — the account does not bypass the token gate).

Body `CreateUserRequest`:

| Field | Type | Notes |
|-------|------|-------|
| `username` | `str` | required, 1..64 chars; duplicate → `409` |
| `password` | `str` | required, 1..256 chars; PBKDF2-hashed before storage, never returned |

Status codes: `201` with `UserResponse`. `404` when the gate is off (route unmounted). `409 username already exists` (`p.get_user_by_username` hit). `401` missing/bad bearer. `422` validation (empty/oversize fields).

Error conditions: duplicate username; gate disabled; invalid bearer.

Example request:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"operator-a","password":"hunter2-hunter2"}' \
  http://127.0.0.1:8765/api/v1/users
```

Example response:

```json
{
  "id": "u-9f3c2a1b",
  "username": "operator-a",
  "created_at": "2026-08-31T12:00:00+00:00",
  "last_login": ""
}
```

Related events: none emitted.

WebUI usage: no dedicated user-management UI was found in `webui/src`; accounts are created via this API directly. The gate is toggled in settings (`api.multi_operator`).

Source file: `tools/api/routes/users.py`.

## `POST /api/v1/users/login` — `login`

`tools/api/routes/users.py:96` — verify credentials and return the user record.

Purpose: authenticate an operator identity (attribution for annotations), recording the login timestamp.

Authentication: bearer required — login verifies the *account* password on top of the bearer gate; it does not issue a session or token.

Body `LoginRequest`:

| Field | Type | Notes |
|-------|------|-------|
| `username` | `str` | |
| `password` | `str` | checked with `verify_password` against stored hash + salt |

Status codes: `200` with `UserResponse`. `401 invalid username or password` — identical message for unknown user and wrong password (no oracle). `404` when the gate is off. `401` (bearer) missing/bad token.

Error conditions: unknown username; password mismatch. Note the response's `last_login` is the **previous** login timestamp: `touch_user_login` runs (`tools/api/persistence.py:758`) but the response is built from the pre-touch row (`tools/api/routes/users.py:106`).

Example request:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"operator-a","password":"hunter2-hunter2"}' \
  http://127.0.0.1:8765/api/v1/users/login
```

Example response:

```json
{
  "id": "u-9f3c2a1b",
  "username": "operator-a",
  "created_at": "2026-08-31T12:00:00+00:00",
  "last_login": ""
}
```

Related events: none emitted.

WebUI usage: no dedicated login UI in `webui/src`; called directly when attributing annotations to an operator.

Source file: `tools/api/routes/users.py`.

## `GET /api/v1/users` — `list_users`

`tools/api/routes/users.py:113` — list user accounts.

Purpose: enumerate operator identities for annotation attribution.

Authentication: bearer required.

Params: none.

Status codes: `200` with an array of `UserResponse`. Password hashes/salts are never included (response model has no such fields). `404` when the gate is off. `401` missing/bad bearer.

Error conditions: gate disabled.

Example request:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/v1/users
```

Example response:

```json
[
  {
    "id": "u-9f3c2a1b",
    "username": "operator-a",
    "created_at": "2026-08-31T12:00:00+00:00",
    "last_login": "2026-08-31T12:05:00+00:00"
  }
]
```

Related events: none emitted.

WebUI usage: no dedicated consumer in `webui/src`; queried directly to resolve `user_id` values for annotation calls.

Source file: `tools/api/routes/users.py`.

## `POST /api/v1/runs/{run_id}/annotations` — `add_annotation` — 201

`tools/api/routes/users.py:127` — attach an operator comment to a run (optionally pinned to a finding).

Purpose: pair-testing collaboration — operators leave notes on a run's findings.

Authentication: bearer required.

Body `AnnotationRequest`:

| Field | Type | Notes |
|-------|------|-------|
| `body` | `str` | required, 1..4096 chars — the comment |
| `finding_ref` | `str` | default `""`, max 256 — pins the comment to a finding |
| `user_id` | `str` | required, non-empty — must reference an existing user (`p.get_user`) |
| `username` | `str` | default `""`, max 64 — display name; falls back to the user's stored username when empty |

Status codes: `201` with `AnnotationResponse`. `404 run not found` (`p.get_run(run_id)` miss). `404 user not found` (`user_id` miss). `500 annotation persistence failed` (defensive: re-list after insert missed the new id). `404` when the gate is off. `401` missing/bad bearer. `422` validation (empty/oversize body, missing `user_id`).

Error conditions: unknown run; unknown `user_id`; gate disabled. The run need not be active — annotations work post-run (the event broker even re-arms closed brokers for post-run operator annotations, `tools/api/event_broker.py:638`).

Example request:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"body":"Confirmed RCE via crafted header — see finding F-00001.","finding_ref":"F-00001","user_id":"u-9f3c2a1b","username":"operator-a"}' \
  http://127.0.0.1:8765/api/v1/runs/20260831_120000/annotations
```

Example response:

```json
{
  "id": "a-4d2e1c0b",
  "run_id": "20260831_120000",
  "user_id": "u-9f3c2a1b",
  "username": "operator-a",
  "body": "Confirmed RCE via crafted header — see finding F-00001.",
  "finding_ref": "F-00001",
  "created_at": "2026-08-31T12:10:00+00:00"
}
```

Related events: none emitted (annotations are persistence-only; read them back via `list_annotations` below).

WebUI usage: no dedicated annotations UI in `webui/src`; written/read via this API directly.

Source file: `tools/api/routes/users.py`.

## `GET /api/v1/runs/{run_id}/annotations` — `list_annotations`

`tools/api/routes/users.py:153` — list annotations for a run, oldest first (`ORDER BY created_at`, `tools/api/persistence.py:795`).

Purpose: read back the operator discussion on a run.

Authentication: bearer required.

Params: `run_id` path param. No user filter — all annotations on the run are returned.

Status codes: `200` with an array of `AnnotationResponse` (empty `[]` when none). `404 run not found`. `404` when the gate is off. `401` missing/bad bearer.

Error conditions: unknown run; gate disabled.

Example request:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/v1/runs/20260831_120000/annotations
```

Example response:

```json
[
  {
    "id": "a-4d2e1c0b",
    "run_id": "20260831_120000",
    "user_id": "u-9f3c2a1b",
    "username": "operator-a",
    "body": "Confirmed RCE via crafted header — see finding F-00001.",
    "finding_ref": "F-00001",
    "created_at": "2026-08-31T12:10:00+00:00"
  }
]
```

Related events: none emitted.

WebUI usage: no dedicated consumer in `webui/src`.

Source file: `tools/api/routes/users.py`.

## `DELETE /api/v1/annotations/{annotation_id}` — `delete_annotation` — 204

`tools/api/routes/users.py:160` — delete one annotation (`p.delete_annotation`, `tools/api/persistence.py:808`).

Purpose: retract an operator comment. No ownership check — any bearer holder can delete any annotation (consistent with "no roles/permissions system").

Authentication: bearer required.

Params: `annotation_id` path param. Empty body response.

Status codes: `204` with empty body on success. `404 annotation not found` (`delete_annotation` returned false). `404` when the gate is off. `401` missing/bad bearer.

Error conditions: unknown annotation id; gate disabled.

Example request:

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/v1/annotations/a-4d2e1c0b -v
```

Example response: `204 No Content` (empty body).

Related events: none emitted.

WebUI usage: no dedicated consumer in `webui/src`.

Source file: `tools/api/routes/users.py`.

## Tests

`tests/test_users.py` covers PBKDF2 hashing (stdlib-only, fresh salt per call), user create/login/wrong-password/duplicate-409, annotation attach/list/delete, the unchanged loopback bind, and the gate-off case (routes not mounted).

## Related documentation

- [Runs endpoints](./runs.md) — `{run_id}` lifecycle that annotations attach to
- [Events endpoints](./events.md) — per-run streams (annotation routes emit none; broker re-arms for post-run use)
- [Decisions endpoints](./decisions.md) — operator-in-the-loop approvals (separate from annotations)
- [API overview](../overview.md) — daemon, loopback bind, router layout
- [API auth](../auth.md) — bearer token, PBKDF2 password hashing, loopback enforcement
- [API persistence](../persistence.md) — `users` / `annotations` tables in `api_runtime.db`
- [Endpoint matrix](../endpoint-matrix.md) — full route table including the gate note

## Source map

- `tools/api/routes/users.py`
- `tools/api/auth.py`
- `tools/api/persistence.py`
- `tools/api/event_broker.py`
- `app.py`
- `config.yaml`
- `tests/test_users.py`
- `webui/src/features/settings/settingMeta.ts`
