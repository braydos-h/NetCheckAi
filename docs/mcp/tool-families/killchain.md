---
title: "Tool Family: killchain"
sources:
  - tools/mcp_tools/killchain.py
  - tools/killchain/machine.py
  - tools/killchain/states.py
  - tools/killchain/edges.py
  - config.yaml
tests:
  - tests/test_killchain.py
subsystem: mcp
---

# Tool Family: killchain

- **Registration source:** `tools/mcp_tools/killchain.py:89 register_killchain_tools(mcp, *, ctx)` — auto-discovered via `collect_tools()`; no edit to `mcp_exploit_server.py` needed. Registers nothing unless `killchain.enabled` is true (default false).
- **Gate:** `killchain_status` / `killchain_plan` are read-only `@audit_tool`; `killchain_attempt` is target-touching `@require_allowlist("target")` and verified-only — the LLM proposes, the machine executes the edge playbook through the normal MCP tool layer and verifies via shared check specs; only verified success moves the state.
- **Purpose:** exposes the kill-chain state machine (`tools/killchain/`) to the agent: a read-only snapshot, a verified transition attempt, and a read-only shortest-path plan. Authorized-testing-only: `killchain_attempt` executes attack playbooks against a target you own or are explicitly authorized to test.

## Tools Exported (3) — conditional on `killchain.enabled`

| Tool | Params | Result Shape | Gates / Notes |
|------|--------|--------------|---------------|
| `killchain_status` | `target: str` | `KILLCHAIN_STATUS:\nTARGET: ...\nSTATE: ...\nGOAL: ...\nAPPLICABLE_EDGES: ...\nPATH_TO_GOAL: ...` | `@audit_tool`. Read-only graph read — no target touch. Empty `target` → `BLOCKED: target is required.` |
| `killchain_attempt` | `target: str`, `from_state: str`, `to_state: str`, `edge_id: str=""`, `context_json: str=""` | `KILLCHAIN_TRANSITION:` (+ `EDGE`, `TRANSITION`, `VERIFICATION: [PASS]/[FAIL]` lines, `EVIDENCE:`) or `KILLCHAIN_FAILED:` (+ `BLOCKED:`/`ERROR:` lines, `STATE UNCHANGED (verification failed or transition rejected).`) | `@require_allowlist("target")`. Invalid target → `BLOCKED`; non-object or malformed `context_json` → `BLOCKED`; missing playbook tool → `ERROR: killchain_attempt unavailable: ...`. |
| `killchain_plan` | `target: str`, `goal_state: str=""` | `KILLCHAIN_PLAN:\nTARGET: ...\nCURRENT_STATE: ...\nGOAL_STATE: ...\nPATH:\n  1. <edge_id> (<from> -> <to>)\n...\nREGISTERED_EDGES: N (stubs excluded)` | `@audit_tool`. Read-only BFS over verified edges — executes nothing. Empty `target` → `BLOCKED`; unparsable goal → `BLOCKED`; no path → `(no registered edge path — free-form module planning applies)`. |

Example — status snapshot:

```text
KILLCHAIN_STATUS:
TARGET: 127.0.0.1
STATE: creds_in_hand
GOAL: shell_as_root
APPLICABLE_EDGES: (none)
PATH_TO_GOAL: (no registered path)
```

Example — plan with no registered path (goal defaults to the configured `killchain.goal_state`):

```text
KILLCHAIN_PLAN:
TARGET: 127.0.0.1
CURRENT_STATE: creds_in_hand
GOAL_STATE: shell_as_root
PATH:
  (no registered edge path — free-form module planning applies)
REGISTERED_EDGES: 0 (stubs excluded)
```

## Attempt Flow (Verified-Only Commit)

1. `context_json`, when non-empty, must parse to a JSON object (playbook placeholders such as `user`, `password`, `port`) — otherwise `BLOCKED`.
2. `machine.attempt_transition(target, from_state, to_state, edge_id=edge_id or None, context=context)` runs the edge playbook through the in-process tool executor, then independently verifies via check probes. Callers already inside an event loop hop to a worker thread so the machine gets a clean loop.
3. Success renders `KILLCHAIN_TRANSITION:` with per-check `[PASS]` lines and an `EVIDENCE:` ref; anything else renders `KILLCHAIN_FAILED:` with `BLOCKED:`/`ERROR:` detail, per-check `[FAIL]` lines where present, and the `STATE UNCHANGED` footer — the state only advances when verification passes.

## In-Process Dispatch

- `_in_process_tool_executor(mcp)` resolves the same decorated functions the agent invokes over MCP (`FastMCP._tool_manager._tools[name].fn`, falling back to an `mcp.tools` dict for test harnesses), so every playbook step re-applies the target-IP allowlist and writes audit rows. Sync functions run via `asyncio.to_thread`.
- `_in_process_shell_session(mcp)` wraps that dispatch as a sync `(tool_name, args) -> str` session for `shell_command` verify probes; dispatch failures raise, and `eval_checks` degrades them to UNVERIFIED, never a pass.

## Dependencies

- `tools.killchain` — `KillChainMachine` (`status` / `attempt_transition` / `plan` / `goal_state`), `all_edges`, `get_edge`
- `tools.killchain.states` — `AttackState` (`AttackState.parse` validates `killchain_plan` goals)
- `tools.eval_checks` — `default_check_executor` (verification probes)
- `tools.intelligence.graph.store` — `AttackGraphStore` (graph persistence)
- `tools.validation_utils` — `validate_target_or_ip` (`killchain_attempt` target check)

## Config

- `killchain.enabled: bool` (default false) — false registers nothing.
- `killchain.goal_state: str` (default `shell_as_root`) — default goal for `killchain_plan` and the status snapshot.
- `killchain.graph_db: str` (default `''` → `<workspace>/killchain_graph.db`; parent dirs created).
- `agent.decision_log_enabled: bool` (default true) — threaded into the machine.

Implementation note: `killchain.require_verification` (default true) is a config key, and the verified-only commit itself is documented in the module docstring ("only verified success moves the state"); the flag's exact plumbing lives in `tools/killchain/machine.py`, which this page does not cover.

## Auditing

`killchain_status` / `killchain_plan` use `@audit_tool`. `killchain_attempt` uses `@require_allowlist("target")`, which writes `started`/`completed|blocked` rows; every playbook step dispatched in-process is audited as its own tool call.

## Validation

- `killchain_status` / `killchain_plan`: empty `target` → `BLOCKED: target is required.`
- `killchain_attempt`: empty `target` → `BLOCKED: target is required.`; invalid IP/hostname → `BLOCKED: ... is not a valid target IP or hostname.`; non-object `context_json` → `BLOCKED: context_json must be a JSON object.`; malformed JSON → `BLOCKED: context_json is not valid JSON (...).`
- `killchain_plan`: unparsable `goal_state` → `BLOCKED: ...` (from `AttackState.parse`); explicit `edge_id` on attempt acts as a tiebreaker when several edges connect the states.

## Tests

- `tests/test_killchain.py` — `test_family_not_registered_when_disabled`, `test_family_registers_three_tools`, `test_killchain_status_block`, `test_killchain_status_blocked_on_empty_target`, `test_killchain_attempt_success_flow`, `test_killchain_attempt_blocked_when_not_allowlisted`, `test_killchain_attempt_bad_context_json`, `test_killchain_plan_block`, `test_verified_transition_commits_state_evidence_and_decision_log`, `test_failed_verification_leaves_state_unchanged`, `test_invalid_transition_rejected`, `test_bfs_plan_shortest_path`, `test_graph_state_survives_machine_reconstruction`

## Related documentation

- [Retest tool family](./retest.md) — reuses the in-process probe-dispatch precedent (`_in_process_tool_executor`)
- [Verify tool family](./verify.md) — N/N machine re-proof counterpart
- [Snapshots tool family](./snapshots.md) — rollback net behind destructive attempts
- [MCP security](../security.md) — allowlist lock + audit trail
- [MCP registration](../registration.md) — decorator contract

## Source map

- `tools/mcp_tools/killchain.py` — `register_killchain_tools`, `_in_process_tool_executor`, `_in_process_shell_session`
- `tools/killchain/machine.py` — `KillChainMachine` (`status` / `attempt_transition` / `plan`)
- `tools/killchain/states.py` — `AttackState`
- `tools/killchain/edges.py` — edge registry (`all_edges`, `get_edge`)
- `config.yaml` — `killchain.enabled`, `killchain.goal_state`, `killchain.require_verification`, `killchain.graph_db`
