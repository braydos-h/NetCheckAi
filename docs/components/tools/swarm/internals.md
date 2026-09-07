---
title: Swarm — Internals
package: tools/swarm
files: [orchestrator.py, blackboard.py, negotiation.py, milestones.py, state_store.py, reflection_run.py, bb_compat.py]
---

# Swarm — Internals (`tools/swarm/`)

Routing, shared blackboard, critic negotiation, milestone gating, reflection dispatch, and crash-safe persistence behind `SwarmOrchestrator`. Agent contracts live in `base.py`; per-agent behavior in `agents.md`.

## Package map

| File | Export | Line | Role |
|---|---|---|---|
| `orchestrator.py` | `SwarmOrchestrator` | 41 | Route + parallel dispatch + critic/reflection wiring + persist |
| `orchestrator.py` | `_DEFAULT_AGENT_MAP` | 30 | Phase → agent class (`recon/analysis/test/validate/exploit/post_exploit/report`) |
| `blackboard.py` | `Blackboard` | 47 | `dict` subclass + atomic writes + per-target buckets |
| `bb_compat.py` | `bb_set/append/extend/remove` | 29 | Atomic API on `Blackboard`, plain-dict fallback otherwise |
| `negotiation.py` | `_negotiate/_negotiation_loop` | 71 | Bounded critic↔task re-review loop |
| `negotiation.py` | `_NEGOTIABLE_KEYS` | 27 | 8 keys the critic may modify (how, never what) |
| `milestones.py` | `_mark_milestone/is_milestone_set/_await_milestone` | 14 | Per-`(target, phase)` completion events |
| `state_store.py` | `_persist_state/load_state/_trim_history` | 37 | `swarm_state.json` atomic snapshot + resume |
| `reflection_run.py` | `reflect` | 18 | Reflection-agent dispatch over the battle log |
| `base.py` | `Agent/AgentResult/AgentStatus` | 41 | Agent contract (`run(task, context)`) |

## `SwarmOrchestrator` (`orchestrator.py:41`)

```python
def __init__(
    self,
    context: dict[str, Any],
    *,
    agent_registry: dict[str, type[Agent]] | None = None,
    max_parallel: int = 3,
    critic_enabled: bool = True,
    reflection_enabled: bool = True,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
    state_path: Path | str | None = None,
    exploit_parallel: bool = False,
    negotiation_rounds: int = 0,
) -> None:
```

Constructor builds the `Blackboard` (12 seed keys), injects it as `context["blackboard"]`, and best-effort builds `context["skill_selection"]` (advisory phase hints; `None` on any failure). `self._lock` is a `threading.RLock` guarding only orchestrator metadata (`_agents`, `_results`, `_battle_log`, `_milestone_events`) — never `agent.run()` / `critic.run()`. In-memory caps: `_max_results = 500`, `_max_battle_log = 500`; persist throttle `_state_persist_interval = 5.0`s.

| Member | Line | Description |
|---|---|---|
| `route(task)` | 171 | Sequential: critic pre-check → `agent.run` (unlocked) → merge → milestone → persist → auto-reflect |
| `route_parallel(tasks)` | 313 | Semaphore-bounded parallel dispatch with recon-first filter + `depends_on` gating |
| `reflect(battle_log, session_state)` | 448 | Runs `ReflectionAgent`, writes `last_reflection`/`strategy_shift` |
| `get_blackboard()` | 452 | `flat()` snapshot (global bucket only) |
| `share_blackboard()` | 463 | Live `Blackboard` ref (shared with the autonomous path; callers must use atomic writes) |
| `model_client` | 480 | Shared LLM client from context (`None` until set) |
| `_spawn(agent_cls, task_id)` | 576 | Fresh instance, `RUNNING`, `agent_started` emit, throttled persist |
| `_emit(event_type, data)` | 486 | Callback via `safe_emit` (never raises) |

Seed keys (`orchestrator.py:134-149`): `recon_complete`, `vuln_research_complete`, `access_achieved`, `discovered_services`, `vulnerability_hypotheses`, `compromised_hosts`, `credentials_found`, `pivot_targets`, `loot`, `failed_modules`, `attack_surface_score`, `strategy_shift`.

### `route` lifecycle

1. Resolve `agent_cls = registry[phase]`; unknown phase → `FAILED` result.
2. `_spawn(agent_cls, task_id)` under lock (`:199`).
3. Critic pre-check (unlocked) when `critic_enabled` and `phase not in ("recon", "report")` (`:206`) via `_negotiate`; `deny` short-circuits with a `BLOCKED` result.
4. `result = agent.run(task, context)` unlocked (`:227`); a raising agent becomes `FAILED` (`agent.run raised: …`), never propagates.
5. Append `_results`, emit `agent_{status}`, append `_battle_log` entry (`task_id/tool/target/success/summary/error/findings/new_tasks`), trim (`:237-267`).
6. Merge `access_achieved/compromised_hosts/credentials_found/loot` from `result.output`: lists extend deduped, scalars first-write-wins, plus `blackboard_updated` emits (`:270-293`).
7. `_mark_milestone(target, phase)` even on failure (`:301`); `_persist_state(force=True)` (`:305`).
8. Auto `reflect` after `exploit`/`post_exploit` when enabled (`:308`).

```python
orch = SwarmOrchestrator(context, state_path="swarm_workspace/swarm_state.json")
result = orch.route({"task_id": "t1", "phase": "recon", "target": "10.0.0.5"})
```

### `route_parallel` lifecycle

Recon-first filter: only `recon`/`analysis` parallelize unless `exploit_parallel` or per-task `force_parallel` (`:352-363`). Each worker awaits its `depends_on = [target, phase]` milestone (600s ceiling, `:374-379`), then runs `route` in `run_in_executor` under `asyncio.Semaphore(max_parallel)`. `return_exceptions=True` maps strays to `FAILED` so one worker cannot cancel the batch. Results are re-ordered to input order (orphan/duplicate ids minted, never overwritten); a forced persist runs in `finally` so resume never loses the tail (`:411-446`).

```python
results = await orch.route_parallel([
    {"task_id": "r1", "phase": "recon", "target": "10.0.0.5"},
    {"task_id": "v1", "phase": "analysis", "target": "10.0.0.5",
     "depends_on": ["10.0.0.5", "recon"]},
])
```

## Blackboard API (`blackboard.py:47`, `bb_compat.py:29`)

`Blackboard` subclasses `dict` so every existing `bb["k"]` / `bb.get("k")` read hits the `__global__` bucket unchanged. All writes go through atomic methods (single `threading.Lock`; safe from worker threads and the event loop alike). Per-target writes (`target="10.0.0.5"`) land in isolated buckets; milestone keys stay global.

| Method | Line | Semantics |
|---|---|---|
| `get(key, default, *, target)` | 93 | `target=None` → global bucket; else namespaced |
| `set_scalar(key, value, *, target)` | 106 | Atomic overwrite, auto-creates bucket |
| `append_to(key, item, *, target)` | 115 | Atomic append, no dedup (O(1)) |
| `extend_list(key, items, *, target, dedupe=True)` | 133 | Atomic merge, order-preserving dedup |
| `remove_from_list(key, item, *, target)` | 164 | Atomic filter (reflection clears succeeded modules) |
| `get_target(target)` / `set_target(target, updates)` | 182 | Copy-out / merge-in one bucket |
| `targets()` | 203 | Bucket names excluding `__global__` |
| `snapshot()` / `merge_snapshot(snapshot)` | 210 | `{__global__:…, "<ip>":…}` round-trip; scalars overwrite, lists extend |
| `flat()` | 251 | Global bucket as a plain dict |
| `bb_set / bb_append / bb_extend / bb_remove` | `bb_compat.py:29` | Atomic path on `Blackboard`, plain-dict fallback for direct-agent tests |

```python
bb = orch.share_blackboard()
bb.set_scalar("discovered_services", services, target="10.0.0.5")
bb.extend_list("failed_modules", ["auxiliary/scanner/smb/x"], target="10.0.0.5")
orch.get_blackboard()["access_achieved"]  # legacy flat read
```

## Negotiation rounds (`negotiation.py:1`)

The negotiation is about *how* to execute a planned action, never *what* target/scope to hit. `_NEGOTIABLE_KEYS` (`negotiation.py:27`): `risk_level, require_mutation, alternative_tool, rate_limit_seconds, delay_seconds, timeout_seconds, max_retries, mutation_strategy`. Out-of-scope keys are dropped (`negotiation_keys_rejected` emit); a wholly out-of-scope proposal stops the loop and the pre-modification task runs (`negotiation_scope_rejected`).

| Function | Line | Description |
|---|---|---|
| `_negotiate(critic, task, task_id, target, agent)` | 71 | Round-0 review; `deny` → blocked result, `modify` → one-shot apply (`rounds=0`) or loop |
| `_negotiation_loop(critic, task, task_id, target, agent, first_modifications)` | 132 | Rounds `1..N`: re-review until `approve`/`deny`/scope-reject/deadlock/exhausted |
| `_filter_modifications(modifications, task_id, target, *, round_idx)` | 207 | Keep only negotiable keys |
| `_modifications_hash(modifications)` | 235 | SHA256 of sorted JSON for deadlock detection |
| `_record_block(critic, task, task_id, target, agent, reasoning)` | 243 | `BLOCKED` result + battle-log entry + `agent_blocked` emit |
| `_ensure_role_clients()` | 41 | Lazy `models.roles` critic client; best-effort, never breaks dispatch |

Stop conditions in the loop: `approve` (task runs), `deny` (blocked), scope-expanding proposal (pre-modification task runs), same-hash repeat twice (deadlock, `negotiation_deadlock`), rounds exhausted (`negotiation_exhausted`, task runs with last accepted modifications). Critic `run` always executes unlocked (it may call an LLM). The allowlist lock is untouched here — it is enforced separately at the MCP tool layer.

## Milestones (`milestones.py:1`)

One `threading.Event` per `(target, phase)`, created lazily under lock. `_mark_milestone` is idempotent and fires even after a failed agent so dependents degrade (empty findings) instead of wedging the campaign. `_await_milestone(target, phase, timeout)` returns `True`/`False`; `route_parallel` calls it with `timeout=600.0` from a worker thread so only that task waits. `is_milestone_set(target, phase)` is the non-blocking check for skip/redispatch decisions.

## Reflection dispatch (`reflection_run.py:18`)

```python
def reflect(self, battle_log: list[dict[str, Any]], session_state: dict[str, Any]) -> AgentResult:
```

No-op `IDLE` result when `reflection_enabled` is false. Otherwise builds task `reflect-<epoch>` (`battle_log` + `session_state`), runs `ReflectionAgent` under lock, appends + trims, writes `last_reflection` / `strategy_shift` scalars to the blackboard, emits `reflection_output`, and persists (throttled). See `agents.md` for the agent's strategy ladder.

## State persistence (`state_store.py:1`)

Writes go through `tools.kernel.orchestration.atomic_write_json` (crash-safe). Throttled to one write per 5s unless `force=True`; `route` forces on every task, `route_parallel` forces at batch end.

```python
def _persist_state(self, *, force: bool = False) -> None:
def load_state(self, path: Path | str | None = None) -> bool:
def _trim_history(self) -> None:
```

Snapshot shape (`state_store.py:55-78`): `{agents[{agent_id, agent_type, status, task_id}], blackboard: snapshot(), blackboard_schema: "namespaced", battle_log_tail[-200:], results_count, last_reflection, strategy_shift, updated_at}`. `load_state` restores only the blackboard (agent list + log tail are per-run state); handles namespaced (`blackboard_schema == "namespaced"` or `__global__` present) and legacy flat shapes (lists extended deduped, scalars replaced). Missing/corrupt file returns `False`, never raises. `_trim_history` bounds `_results`/`_battle_log` at 500 entries each.

```python
orch.load_state("swarm_workspace/swarm_state.json")  # resume: True, or False on fresh start
```

## Config keys

| Key | Default | Effect |
|---|---|---|
| `swarm.enabled` | `true` (`config.yaml:176`) | Master gate |
| `swarm.agents` | `[recon, vuln, exploit, post_exploit, critic, reflection]` (`config.yaml:177`) | Advertised roster |
| `swarm.max_parallel_agents` | `3` (`config.yaml:184`) | `max_parallel` semaphore (verified wired in `legacy/agent_loop.py:258`) |
| `swarm.parallel_enabled` | `false` (`config.yaml:185`) | Gates `route_parallel` + `spawn_subagent` registration (`run_service/prepare.py:767`, `mcp_tools/parallel_agents.py:273`) |
| `swarm.per_phase_concurrency` | `3` (`config.yaml:186`) | Semaphore size per schema comment (`config/schema.py:373`) |
| `swarm.exploit_parallel` | `false` (`config.yaml:187`) | Lets `exploit`/`post_exploit` parallelize in `route_parallel` |
| `swarm.subagent_timeout_seconds` | `600` (`config.yaml:188`) | `await_subagent` ceiling per schema comment |
| `swarm.negotiation_rounds` | lab `2` (`config.yaml:189`); schema default `0` (`config/schema.py:394`) | Bounded critic re-review loop; `0` = legacy one-shot |
| `critic_enabled` / `reflection_enabled` | mission config (`legacy/agent_loop.py:261`) | Gate pre-check and auto-reflect |

Implementation note: `run-service` construction wiring for `max_parallel`/`exploit_parallel`/`negotiation_rounds` outside `legacy/agent_loop.py` and `mcp_tools/parallel_agents.py` was not re-verified here; `per_phase_concurrency` → orchestrator plumbing was not re-verified (the orchestrator consumes the `max_parallel` constructor arg).

## Tests

| File | Covers |
|---|---|
| `tests/test_swarm.py` | Routing, `agent_type`, lifecycle, critic, reflection |
| `tests/test_swarm_parallel_phase3.py` | Milestones, `depends_on`, concurrency, per-target buckets, order |
| `tests/test_swarm_negotiation.py` | Negotiation deadlock + scope reject |
| `tests/test_swarm_observability.py` | Events + `swarm_state.json` + provider |
| `tests/test_swarm_history_bound.py` | `_trim_history` 500 cap |
| `tests/test_swarm_recon_fix.py` | ReconAgent via `ReconPipeline` (plain-dict blackboard path) |
| `tests/test_blackboard_concurrency.py` | `extend_list` atomicity |
| `tests/test_swarm_mcp_bridge.py` | `SwarmMcpBridge` dispatch/attach |
| `tests/test_swarm_bridge_contract.py` | Bridge contract |
| `tests/test_swarm_dynamic_composition.py` | Registry composition |
| `tests/test_swarm_integration.py` | End-to-end swarm |
| `tests/test_witness_agent.py` | Witness scan (not orchestrator-routed) |
| `tests/test_witness_wiring.py` | Witness lifecycle wiring |

## Related documentation

- [Swarm overview](./overview.md) — package map, `route` flow summary, skill-phase tags
- [Swarm agents](./agents.md) — all 7 agents, contracts, critic layers, reflection stages
- [Swarm subsystem](../../../swarm.md) — swarm vs campaign decision rule
- [Campaign](../../../campaign.md) — autonomous orchestrator, shared `atomic_write_json`/`safe_emit` vocabulary
- [Run service](../../../run-service.md) — transport-neutral run lifecycle, `parallel_enabled` gating
- [Config reference](../../../config-reference.md) — `swarm.*` key defaults

## Source map

- `tools/swarm/orchestrator.py` — `SwarmOrchestrator`, `_DEFAULT_AGENT_MAP`, `route`, `route_parallel`
- `tools/swarm/blackboard.py` — `Blackboard`, atomic writes, namespacing, snapshot/merge
- `tools/swarm/bb_compat.py` — `bb_set`, `bb_append`, `bb_extend`, `bb_remove`
- `tools/swarm/negotiation.py` — `_NEGOTIABLE_KEYS`, `_negotiate`, `_negotiation_loop`, `_record_block`
- `tools/swarm/milestones.py` — `_mark_milestone`, `is_milestone_set`, `_await_milestone`
- `tools/swarm/state_store.py` — `_persist_state`, `load_state`, `_trim_history`
- `tools/swarm/reflection_run.py` — `reflect`
- `tools/swarm/base.py` — `Agent`, `AgentResult`, `AgentStatus`
- `tools/kernel/orchestration.py` — `atomic_write_json`, `safe_emit`
- `tools/mcp_tools/parallel_agents.py` — `SwarmOrchestrator` sub-agent construction, `parallel_enabled` gate
- `tools/run_service/prepare.py` — `parallel_enabled` read, `swarm_state.json` progress
- `legacy/agent_loop.py` — `max_parallel`/`negotiation_rounds`/`state_path` wiring, resume `load_state`
- `tools/config/schema.py` — `swarm.*` defaults
- `config.yaml` — lab `swarm.*` values
