---
title: "Tool Family: snapshots"
sources:
  - tools/mcp_tools/snapshots.py
  - tools/snapshots.py
  - config.yaml
tests:
  - tests/test_snapshots.py
subsystem: mcp
---

# Tool Family: snapshots

- **Registration source:** `tools/mcp_tools/snapshots.py:22 register_snapshot_tools(mcp, *, ctx)` — auto-discovered via `collect_tools()`; no edit to `mcp_exploit_server.py` needed. Registers nothing unless `snapshots.enabled` is true (default false).
- **Gate:** all three tools take a `vm_id` bound to `@require_allowlist("vm_id")` — the allowlist IS the lock for infrastructure-touching calls. `snapshot_list` additionally uses `@audit_tool` and is read-only.
- **Purpose:** exposes the snapshot/rollback layer (`tools/snapshots.py`) to the agent — take a snapshot before destructive work, roll back when a run goes sideways, list recorded snapshots. The same `SnapshotManager` backs the automatic snapshot-before-destructive hooks in the exploit loop, the swarm bridge, and the campaign executor. Fail-open by contract: a snapshot failure logs and the action proceeds — snapshot infrastructure never becomes an attack-path gate. Authorized-testing-only: snapshots and reverts touch lab infrastructure backing a target you own or are explicitly authorized to test.

## Tools Exported (3) — conditional on `snapshots.enabled`

| Tool | Params | Result Shape | Gates / Notes |
|------|--------|--------------|---------------|
| `snapshot_create` | `vm_id: str`, `label: str=""` | `SNAPSHOT_CREATED:\nVM_ID: ...\nSNAPSHOT_ID: ...\nLABEL: ...\nPROVIDER: ...\nCREATED_AT: ...` | `@require_allowlist("vm_id")`. Empty `vm_id` → `BLOCKED: vm_id is required.` Provider exception → `ERROR: snapshot_create failed: ...`; `None` ref → `BLOCKED: snapshots disabled or the snapshot failed (no ref returned).` Default label `manual-<timestamp>`. |
| `snapshot_revert` | `vm_id: str`, `ref: str=""` | `SNAPSHOT_REVERTED:\nVM_ID: ...\nSNAPSHOT_ID: ...\nPROVIDER: ...` | `@require_allowlist("vm_id")`. Empty `ref` reverts the latest recorded snapshot. Unresolvable ref / disabled / provider refusal → `ERROR: snapshot_revert failed (...)`. Unindexed refs render `PROVIDER: (unindexed ref)`. |
| `snapshot_list` | `vm_id: str` | `SNAPSHOT_LIST:\nVM_ID: ...\nCOUNT: N` + `  - <snapshot_id>  label=<label>  created=<created_at>` lines | `@audit_tool` + `@require_allowlist("vm_id")`. Read-only; no target touch. Empty `vm_id` → `BLOCKED`; index errors → `ERROR: snapshot_list failed: ...`. |

Example — create against the fallback identity (raw target string):

```text
SNAPSHOT_CREATED:
VM_ID: 127.0.0.1
SNAPSHOT_ID: <provider-generated id>
LABEL: manual-<timestamp>
PROVIDER: docker
CREATED_AT: <iso timestamp>
```

Example — list:

```text
SNAPSHOT_LIST:
VM_ID: 127.0.0.1
COUNT: 2
  - <snapshot_id>  label=manual-<timestamp>  created=<iso timestamp>
  - <snapshot_id>  label=pre-exploit  created=<iso timestamp>
```

## vm_id Resolution (`_vm_id_for_target`)

The `vm_id` arg is resolved to a snapshottable identity in this order:

1. `snapshots.vm_map` (`{"127.0.0.1": "breachpilot-target"}`) — config mapping wins.
2. `SNAPSHOT_VM_MAP` env (`127.0.0.1=container`, comma-separated `target=vm_id` pairs).
3. Fallback: the raw target string.

The resolved id — not the raw arg — is what the allowlist gate and the provider see.

## Snapshot-Before-Destructive (`should_snapshot`)

Conservative documented rule; true only when `snapshots.enabled` is true AND `auto_before_destructive` is true (default), plus either:

- (a) the payload trips `command_analyzer._has_destructive`, or
- (b) the tool's action category (`exploit_agent.policy._TOOL_ACTION_CATEGORY`) is one of `credential_dumping` / `exploit_execution` / `lateral_movement` — intrusive even when the text alone does not look destructive.

Purely an extra safety net — never a gate.

## Providers (`get_provider`)

| Provider | Class | Notes |
|----------|-------|-------|
| `docker` | `DockerProvider` | Mandatory, fully-implemented stdlib-only path (`docker commit` for containers; re-create from the committed image for rollback). Named seams: `_docker`, `docker_commit`, `docker_inspect`, `docker_run_from_snapshot`, `docker_stop_rm` — tests monkeypatch the wrappers, never subprocess. Subprocess timeout 120 s (`_SUBPROCESS_TIMEOUT`). |
| `proxmox` | `ProxmoxProvider` | Best-effort wrapper; config `snapshots.providers.proxmox` (`host`, `node`). Credentials env-only, never in config or logs. |
| `libvirt` | `LibvirtProvider` (`_CommandProvider`) | Best-effort; `virsh_path` (default `virsh`). |
| `hyperv` | `HyperVProvider` (`_CommandProvider`) | Best-effort; `powershell_command` (default `powershell`). |
| `vmware` | `VMwareProvider` (`_CommandProvider`) | Best-effort; `vmrun_path` (default `vmrun`). |

`get_provider(name, config)` builds from the `snapshots.providers` block; unknown names raise `ValueError` listing the known providers. One restorable snapshot is a `SnapshotRef` (`provider`, `vm_id`, `snapshot_id`, `label`, `created_at`, `metadata`).

## Fail-Open Contract

- The manager keeps a JSON index beside the workspace audit trail so refs survive restarts, and enforces the rolling per-target cap (`max_snapshots_per_target`, oldest deleted first).
- Provider errors surface as `ERROR:` / `BLOCKED:` result strings — the MCP wrappers catch `Exception` and never raise, so the server never crashes on infrastructure failure.

## Dependencies

- `tools/snapshots.py` — `SnapshotManager` (`before_destructive` / `revert` / `list` / `delete`), `_vm_id_for_target`, `get_provider`, `should_snapshot`, `SnapshotRef`
- `tools/mcp_tools/registry.py` — `ToolContext` (`config`, `require_allowlist`, `workspace`)

## Config

- `snapshots.enabled: bool` (default false) — false registers nothing and disables `should_snapshot`.
- `snapshots.provider: str` (default `docker`) — `get_provider` key.
- `snapshots.auto_before_destructive: bool` (default true) — second half of the `should_snapshot` gate.
- `snapshots.max_snapshots_per_target: int` (default 3) — rolling cap, oldest deleted first.
- `snapshots.vm_map: map` (default `{}`) — target → vm_id overrides (`SNAPSHOT_VM_MAP` env as fallback).
- `snapshots.providers.docker.compose_file` (default `eval_targets/docker-compose.yml`), `hyperv.powershell_command` (`powershell`), `vmware.vmrun_path` (`vmrun`), `proxmox.host` / `proxmox.node` (`''`), `libvirt.virsh_path` (`virsh`).

## Auditing

All three tools pass through `@require_allowlist("vm_id")`, which writes `started`/`completed|blocked` audit rows; `snapshot_list` additionally uses `@audit_tool`.

## Validation

- Empty/blank `vm_id` → `BLOCKED: vm_id is required.` on all three tools (before resolution).
- `snapshot_create` with a blank `label` falls back to `manual-<timestamp>`; it never fails on label input.
- `snapshot_revert` with a blank `ref` reverts the most recent recorded snapshot (`snaps[-1]`); with no recorded snapshots the revert resolves to `None` → `ERROR`.

## Tests

- `tests/test_snapshots.py` — `test_snapshot_family_not_registered_when_disabled`, `test_snapshot_family_registers_three_tools`, `test_snapshot_create_blocked_for_unallowlisted_vm`, `test_snapshot_create_maps_target_to_vm_and_records`, `test_snapshot_revert_latest_and_unknown`, `test_snapshot_list_block`, `test_should_snapshot_destructive_vs_benign`, `test_should_snapshot_intrusive_category_without_destructive_text`, `test_should_snapshot_disabled_and_gate_off`, `test_vm_id_for_target_map_env_and_fallback`, `test_get_provider_unknown_and_known`, `test_docker_create_commit_tag_and_port_capture`, `test_docker_revert_stop_rm_then_run_with_ports`, `test_manager_records_and_reverts_by_ref_and_id`, `test_manager_cap_deletes_oldest`, `test_manager_fail_open_on_provider_errors`, `test_runner_snapshots_before_destructive_and_reverts_counterfactual`

## Related documentation

- [Retest tool family](./retest.md) — attaches best-effort snapshot state to the `EVIDENCE` line (fail-open)
- [Killchain tool family](./killchain.md) — verified-only transitions; snapshots are the rollback net behind attempts
- [MCP security](../security.md) — allowlist lock (the allowlist IS the lock)
- [MCP registration](../registration.md) — decorator contract

## Source map

- `tools/mcp_tools/snapshots.py` — `register_snapshot_tools` (`snapshot_create` / `snapshot_revert` / `snapshot_list`)
- `tools/snapshots.py` — `SnapshotManager`, `SnapshotRef`, provider layer, `get_provider`, `should_snapshot`, `_vm_id_for_target`
- `config.yaml` — `snapshots.enabled`, `snapshots.provider`, `snapshots.auto_before_destructive`, `snapshots.max_snapshots_per_target`, `snapshots.vm_map`, `snapshots.providers.*`
