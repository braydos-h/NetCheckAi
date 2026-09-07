---
title: Killchain — Overview
package: tools/killchain
files: [machine.py, edges.py, states.py]
---

# Killchain — Overview (`tools/killchain/`)

Verified-only kill-chain state machine (opt-in, default OFF). The LLM proposes; the machine verifies: a transition commits only after the edge's `verify` check specs pass through the shared evaluator. There is deliberately no unverified-transition code path — `killchain.require_verification` toggles reporting verbosity only.

## Package map

| File | LOC | Role |
|---|---|---|
| `states.py` | 60 | `AttackState` enum + tolerant `parse` with aliases |
| `edges.py` | 317 | Declarative edge registry (`EDGES`), stub set, placeholder resolution |
| `machine.py` | 448 | `KillChainMachine` — propose → playbook → verify → commit |
| `__init__.py` | — | Re-exports `AttackState`, `EDGES`, `KillChainMachine`, accessors |
| `tools/mcp_tools/killchain.py` | MCP | `killchain_status` / `killchain_attempt` / `killchain_plan` (registered only when `killchain.enabled`) |

## `states.py` — states

```python
class AttackState(str, Enum):
    DISCOVERED = "discovered"
    REACHABLE = "reachable"
    SERVICE_ACCESS = "service_access"
    CREDS_IN_HAND = "creds_in_hand"
    SHELL_AS_USER = "shell_as_user"
    SHELL_AS_ROOT = "shell_as_root"
    PIVOT_REACHABLE = "pivot_reachable"
    DOMAIN_CREDS = "domain_creds"
    DA = "da"

    @classmethod
    def parse(cls, value: str) -> "AttackState": ...
```

`str`-based so values serialize cleanly to JSON. `parse` is case/alias-insensitive (`root` → `shell_as_root`, `domain_admin` → `da`, …) and raises `ValueError` when unknown. Applicability is edge-driven: states appearing in `EDGES` are the ones a target can move between.

## `edges.py` — edge registry

Each edge is one verified transition: `edge_id`, `from_state`/`to_state`, `playbook` (ordered MCP tool calls), `verify` (check specs in the shared evaluator vocabulary), `evidence_type`. Playbook args may carry `{target_ip}`/`{user}`/`{password}` placeholders resolved from the transition context (only `str` values are formatted, so context cannot inject structure).

| Edge | From → To | Playbook → Verify |
|---|---|---|
| `tcp_reachable` | `discovered → reachable` | nmap port probe → `http_request` port check |
| `service_confirmed` | `reachable → service_access` | `get_service_fingerprint` → banner probe |
| `cred_harvest` | `service_access → creds_in_hand` | login POST → `http_login` |
| `cred_ssh_login` | `creds_in_hand → shell_as_user` | sshpass `id` → `shell_command` `uid=` |
| `cred_smb_login` | `creds_in_hand → service_access` | `lateral_exec whoami` → session probe |
| `cred_http_login` | `creds_in_hand → service_access` | (no playbook) → `http_login` |
| `msf_validated_exploit` | `service_access → shell_as_user` | `run_msf_module` → session probe |
| `file_upload_webshell` | `service_access → shell_as_user` | upload POST → webshell URL probe |
| `privesc_sudo_to_root` | `shell_as_user → shell_as_root` | `sudo -n id` → `uid=0(` probe |
| `domain_login_validate` | `creds_in_hand → domain_creds` | `lateral_exec` → NetExec `[+]` logon probe |
| `kerberoast_to_da` | `domain_creds → da` | `kerberoast` → DCSync `:::` hash-line probe |

| Symbol | Kind | Description |
|---|---|---|
| `STUB_EDGES` | frozenset | Empty — every registered edge ships a working verify story; excluded from BFS |
| `get_edge(edge_id)` | def | Registry lookup or `None` |
| `edges_from(state)` | def | Non-stub edges from a state (`[]` on unparseable state) |
| `all_edges(*, include_stubs=False)` | def | Full registry |
| `resolve_placeholders(value, context)` | def | Safe `{placeholder}` formatting; missing keys left as-is so the failure is visible |

## `machine.py` — `KillChainMachine`

```python
def __init__(self, *, graph_store, workspace="", config=None, session=None,
             tool_executor=None, check_executor=None, run_dir="",
             decision_log_enabled=True, now_fn=None) -> None: ...

async def attempt_transition(self, target, from_state, to_state,
                             edge_id=None, context=None) -> dict[str, Any]: ...
def status(self, target: str) -> dict[str, Any]: ...
def plan(self, target: str, goal_state: str = "") -> list[str]: ...
def can_transition(self, from_state: str, to_state: str) -> bool: ...
```

| Symbol | Kind | Description |
|---|---|---|
| `_run_tool(tool_name, args)` | async | One playbook step through the MCP tool layer (`tool_executor` preferred, else live `session.call_tool`) — allowlist + audit apply unchanged |
| `_executor()` | def | Check executor: injected or lazily built `default_check_executor` |
| `_resolve_edge(from, to, edge_id)` | def | Edge resolution with `(edge, error)` tuple; unknown states/edges are `blocked` results, not exceptions |
| `attempt_transition(...)` | async | Propose → run playbook → `verify_flag_check` every spec → commit only if all pass; returns `{success, edge_id, from_state, to_state, steps, checks, error/evidence_ref}` |
| `_commit(target, edge, ...)` | def | Merges `attack_state` onto the host node (`CONFIRMED`), writes an evidence node + `OBSERVED_ON` edge, returns `ev:killchain:<edge>:<ts>` |
| `status(target)` | def | `{target, state, applicable_edges, goal_state, path_to_goal}` (default state `discovered`) |
| `plan(target, goal_state="")` | def | BFS shortest edge-id path over non-stub edges (BloodHound shortest-path, generic) |
| `_log_decision(...)` | def | `verified_transition` / `verification_failed` decision-log events; never breaks the loop |

`goal_state` defaults to `shell_as_root` (`DEFAULT_GOAL_STATE`); `verbose_reporting` follows `require_verification`. MCP-death `BaseExceptionGroup` is caught via `_EXC_GROUP_CATCH` on both playbook and verify paths.

## MCP surface (`tools/mcp_tools/killchain.py`)

Registered only when `killchain.enabled` is true (default false). The machine is wired with an in-process tool executor (same decorated functions the agent calls, so every playbook step re-applies the allowlist + audit) and `AttackGraphStore` at `<workspace>/killchain_graph.db` (or `killchain.graph_db`).

| Tool | Signature | Notes |
|---|---|---|
| `killchain_status` | `(target)` | Read-only: state, applicable edges, path to goal. Audit-only, no target touch |
| `killchain_attempt` | `(target, from_state, to_state, edge_id="", context_json="")` | `@require_allowlist("target")`; `context_json` carries `{user, password, port, …}` placeholders |
| `killchain_plan` | `(target, goal_state="")` | Read-only BFS; defaults to configured `killchain.goal_state` |

## Lifecycle

```
propose (from_state → to_state, edge_id?)
      │
      ▼
run playbook via MCP tool layer (allowlist + audit)
      │
      ▼
verify every check spec independently
      │ fail
      ▼
STATE UNCHANGED ◄────────────── success ──► commit attack_state + evidence node
```

## Config keys (`killchain:` block)

| Key | Default | Effect |
|---|---|---|
| `killchain.enabled` | `false` | Registers the three MCP tools; loop renders briefing (empty when disabled) |
| `killchain.goal_state` | `"shell_as_root"` | BFS goal for `killchain_plan` / orchestrator edge path |
| `killchain.require_verification` | `true` | Reporting verbosity only — verification is always enforced |
| `killchain.graph_db` | `""` | Graph store path; empty = `<workspace>/killchain_graph.db` |

Fail-open by contract: any killchain build/advance error degrades to no-op, never breaks the attack path.

## Example

```python
machine = KillChainMachine(graph_store=store, config=config, tool_executor=executor)
print(machine.status("10.0.0.50"))
result = await machine.attempt_transition(
    "10.0.0.50", "shell_as_user", "shell_as_root",
    edge_id="privesc_sudo_to_root",
)
print(machine.plan("10.0.0.50", "da"))
```

## Tests (selected)

| File | Covers |
|---|---|
| `tests/test_killchain.py` | States, edges, verified-only transitions, BFS planning |

## Related documentation

- [Verification overview](../verification/overview.md)
- [Configuration overview](../../../configuration/overview.md)
- [MCP tools](../../../mcp-tools.md)
- [Safety model](../../../safety-model.md)

## Source map

- `tools/killchain/machine.py`
- `tools/killchain/edges.py`
- `tools/killchain/states.py`
- `tools/killchain/__init__.py`
- `tools/mcp_tools/killchain.py`
