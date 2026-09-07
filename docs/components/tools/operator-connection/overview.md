---
title: Operator Connection — Overview
package: tools/operator_connection
files: [manager.py, implants.py]
---

# Operator Connection — Overview (`tools/operator_connection/`)

Operator-box → victim persistent RCE channel. `ConnectionManager` is the single source of truth for which victim has which persistence method beaconing to which operator listener; `implants.py` holds the nine rendered implant templates. Every victim touch is allowlist-gated at the MCP tool layer, and persistence is deployable only after RCE/foothold — the manager does not bypass that.

## Package map

| File | LOC | Role |
|---|---|---|
| `manager.py` | 291 | `ConnectionManager` + `ConnectionRecord` — JSON-persisted channel store |
| `implants.py` | 409 | `ImplantSpec` templates (`IMPLANT_METHODS`), `get_implant` / `list_implants` / `render_implant` |
| `__init__.py` | — | Re-exports manager + implant helpers |
| `tools/mcp_tools/operator_connection.py` | MCP | `rce_exec` / `establish_persistence` / `list_connections` / `check_connection` / `remove_persistence` / `rce_listener_start` / `persistence_catalog` |

## `manager.py` — `ConnectionManager`

```python
class ConnectionManager:
    def __init__(self, workspace: Path) -> None: ...
    def create_connection(self, target_ip, method, callback_host, callback_port,
                          listener_name="", implant_path="", mitre_technique="",
                          os_family="", notes="") -> ConnectionRecord: ...
    def list_connections(self, target_ip: str = "") -> list[ConnectionRecord]: ...
    def get(self, connection_id: str) -> ConnectionRecord | None: ...
    def find_by_target_method(self, target_ip: str, method: str) -> list[ConnectionRecord]: ...
    def mark_beacon(self, connection_id: str) -> None: ...
    def mark_check(self, connection_id: str, output: str, healthy: bool) -> None: ...
    def mark_removed(self, connection_id: str) -> bool: ...
    def remove(self, connection_id: str) -> bool: ...
    def summary(self) -> str: ...

def get_connection_manager(workspace: Path | None = None) -> ConnectionManager: ...
def reset_connection_manager() -> None: ...
```

`ConnectionRecord` fields: `connection_id` (`conn-<hex8>`), `target_ip`, `method`, `callback_host/port`, `listener_name`, `status` (`active/stale/removed/error`), `created_at`, `last_beacon`, `last_check`, `check_output` (2000-char cap), `implant_path`, `mitre_technique`, `os_family`, `notes`; `to_dict` adds ISO timestamp helpers.

Store layout: `<workspace>/operator_connections.json` (atomic tmp-write + `os.replace`) plus per-target shards `<workspace>/connections/<target_ip>.json`, kept in sync best-effort. `create_connection` validates via `validate_target_or_ip` and derives a deterministic default listener name (`persist-<target>-<method>`, clamped to 64 chars). The module singleton rebinds when a different workspace is passed, so per-target workspaces each see their own store.

## `implants.py` — implant catalog

```python
@dataclass(frozen=True)
class ImplantSpec:
    name: str
    os_family: str          # linux | windows | web | any
    description: str
    mitre_technique: str
    template: str           # {target_ip}/{callback_host}/{callback_port} placeholders
    verify_cmd: str
    remove_cmd: str
    requires_root: bool = False
    beacon_interval: str = "5m"

def get_implant(name: str) -> ImplantSpec | None: ...
def list_implants(os_filter: str = "") -> list[ImplantSpec]: ...
def render_implant(name: str, target_ip: str, callback_host: str = "",
                   callback_port: str = "4444") -> tuple[str, ImplantSpec]: ...
```

| Method | OS | MITRE | Beacon |
|---|---|---|---|
| `linux_cron` | linux | T1053.003 | every 5 min (`/dev/tcp` reverse shell) |
| `linux_systemd` | linux | T1543.002 | on boot, `Restart=always` |
| `linux_ssh_key` | linux | T1098.004 | on-demand (ed25519 `authorized_keys`) |
| `linux_bashrc` | linux | T1547.004 | on interactive login |
| `windows_schtask` | windows | T1053.005 | every 5 min as SYSTEM |
| `windows_registry` | windows | T1547.001 | on logon (HKCU Run key) |
| `windows_service` | windows | T1543.003 | on boot (requires admin) |
| `windows_startup` | windows | T1547.001 | on logon (Startup folder) |
| `web_php_shell` | web | T1505.003 | on HTTP request (`systemhealth.php`) |

Templates are victim-side Python/shell rendered with the locked `target_ip` + allowlist-checked `callback_host`; implants only ever contact victim IP + callback host. Unknown `render_implant` names raise `ValueError`.

## MCP surface (`tools/mcp_tools/operator_connection.py`)

| Tool | Signature | Gate | Notes |
|---|---|---|---|
| `rce_exec` | `(target_ip, command, technique="generic")` | `@require_allowlist()` + `_target_lock_block` on free text | Gate + evidence marker only: returns `RCE_EXEC_GATE` with the sanitized command and NEXT step; the operator dispatches via `run_exploit_terminal` / `run_python_file`. 4000-char cap |
| `establish_persistence` | `(target_ip, method="linux_cron", callback_host="", callback_port=4444, auto_start_listener=True, listener_type="netcat")` | `@require_allowlist()` + callback pivot lock | Renders implant into the attempt dir, optionally auto-starts the operator listener, creates the `ConnectionRecord` |
| `list_connections` | `(target_ip="")` | `@audit_tool` (local-only) | Every channel, or filtered to one victim |
| `check_connection` | `(target_ip, connection_id="", method="")` | `@require_allowlist()` | Listener liveness (operator box) + victim-side `verify_cmd` to run via RCE |
| `remove_persistence` | `(target_ip, connection_id="", method="", stop_listener=False)` | `@require_allowlist()` | Safe default: no id/method lists removables without removing; returns the victim-side remove command and tears down the record |
| `rce_listener_start` | `(port, listener_type="netcat", name="", protocol="tcp")` | `@audit_tool` | Thin wrapper over `PersistentSessionManager.start_listener`; `tls`/`https-beacon` additionally require `exploit.listeners.*` flags |
| `persistence_catalog` | `(os_filter="")` | `@audit_tool` | Nine methods with MITRE + verify commands; never drifts from `implants.py` |

Callback resolution precedence: explicit arg → `EXPLOIT_CALLBACK_HOST` env → first `exploit.allowed_targets` entry → `BLOCKED`. The callback host must itself be allowlisted (same pivot lock as `generate_payload` LHOST). Listeners run on the operator box only (`PersistentSessionManager` tmux/nohup/nc/socat/http/tls back-end); victim code never executes on the operator box.

Plugin authors: this family is the reference example for the pattern in `docs/plugin-development.md` — every target-touching tool stacks `ctx.require_allowlist()`, free-text command tools add the target-lock block, and read-only catalog tools use `ctx.audit_tool`.

## Lifecycle

```
rce_exec gate (whoami; id; hostname) ──► dispatch via run_exploit_terminal
      │
      ▼
establish_persistence(method, callback) ──► implant script in attempt dir
      │                                      + auto listener + ConnectionRecord
      ▼
list_connections / check_connection (verify_cmd on victim, read_listener_output on operator)
      │
      ▼
remove_persistence ──► victim remove_cmd + record teardown (+ optional listener stop)
```

## Config keys (`operator_connection:` block + adjacent)

| Key | Default | Effect |
|---|---|---|
| `operator_connection.enabled` | `true` | Advisory channel default (Implementation note: the MCP registrar itself applies no enabled gate — tools register whenever collected) |
| `operator_connection.auto_start_listener` | `true` | `establish_persistence` starts the beacon listener unless `false` is passed |
| `operator_connection.default_callback_port` | `4444` | Fallback when no port is passed or env-set |
| `operator_connection.default_listener_type` | `"netcat"` | Listener back-end for auto-start |
| `operator_connection.beacon_interval_seconds` | `300` | Documented beacon cadence |
| `operator_connection.health_check_interval_seconds` | `60` | Documented health-check cadence |
| `operator_connection.workspace_dir` | `"exploit_workspace"` | Record store root |
| `exploit.listeners.tls` / `dns` / `https_beacon` / `socks_pivot` | `false` | Each extended listener type is independently opt-in |
| `EXPLOIT_CALLBACK_HOST` / `EXPLOIT_CALLBACK_PORT` | env | Callback resolution overrides |

## Example

```python
from tools.operator_connection import render_implant, get_connection_manager

script, spec = render_implant("linux_cron", "10.0.0.50",
                              callback_host="10.0.0.5", callback_port="4444")
mgr = get_connection_manager(Path("exploit_workspace/10.0.0.50"))
rec = mgr.create_connection("10.0.0.50", "linux_cron", "10.0.0.5", 4444,
                            implant_path="attempt_1/persist_linux_cron.py",
                            mitre_technique=spec.mitre_technique,
                            os_family=spec.os_family)
print(mgr.summary())
```

## Tests (selected)

| File | Covers |
|---|---|
| `tests/test_connections_api.py` | Connection API surface |

Implementation note: no dedicated `test_operator_connection*.py` / `test_implants*.py` file was found in this pass; manager behavior is additionally exercised through the MCP-tool and API tests above.

## Related documentation

- [Plugin development](../../../plugin-development.md)
- [Configuration overview](../../../configuration/overview.md)
- [Verification overview](../verification/overview.md)
- [Killchain overview](../killchain/overview.md)
- [MCP tools](../../../mcp-tools.md)
- [Safety model](../../../safety-model.md)

## Source map

- `tools/operator_connection/manager.py`
- `tools/operator_connection/implants.py`
- `tools/operator_connection/__init__.py`
- `tools/mcp_tools/operator_connection.py`
