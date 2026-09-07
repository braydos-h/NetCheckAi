# Campaign Orchestrator

The autonomous campaign engine drives persistent multi-phase attacks across one or many targets: reconnaissance, exploitation, privilege escalation, lateral movement, persistence, and validation, with adaptive aggression, retries, and resume. The implementation lives in `tools/campaign/`; `tools/autonomous_orchestrator.py` is a thin facade that re-exports it so existing imports keep working.

## Package layout

| Module | Contents |
|---|---|
| `tools/autonomous_orchestrator.py` | Facade only. Re-exports `AutonomousOrchestrator`, `AttackModuleExecutor`, state classes, `find_modules` / `find_producers` / `get_module`, `ReconPipeline`, `observe_autonomous_progress`. Tests patch `find_modules` / `get_module` / `find_producers` through this module, and campaign code resolves them via `getattr` on this facade at call time. |
| `tools/campaign/orchestrator.py` | `AutonomousOrchestrator`: constructor wiring, `run_autonomous_campaign`, `_attack_target` delegation, delegating wrappers for batch / preflight / service-tasks / state-store. |
| `tools/campaign/state.py` | `AttackTask`, `AttackState`, `AggressionLevel`, `AttackPhase`, `TaskStatus`, `RetryEngine`, `observe_autonomous_progress` / `_report_autonomous_progress`. |
| `tools/campaign/executor.py` | `AttackModuleExecutor`: per-task lifecycle (scope, risk, critic, dispatch, classify, record, reflect). |
| `tools/campaign/phases.py` | Phase handlers (`_phase_reconnaissance`, `_phase_exploitation`, `_phase_privilege_escalation`, `_phase_lateral_movement`, `_phase_persistence`, `_phase_validation`, `_phase_local_takeover`, `_phase_killchain`), `_attack_target`, adaptive rounds, kill-chain machine builder. Bound onto `AutonomousOrchestrator` after class definition. |
| `tools/campaign/batch.py` | `_execute_task_batch`, prerequisite recovery (`_maybe_schedule_prereq`, `_prereq_artifact_kinds`, `_PREREQ_KIND_PATTERNS`), `_retry_failed_modules`. |
| `tools/campaign/preflight.py` | `_preflight_targets`: resolve / dedupe / scope-check / non-routable filter. |
| `tools/campaign/service_tasks.py` | `_create_service_specific_tasks`: extra exploit tasks per discovered service. |
| `tools/campaign/state_store.py` | `save_state` / `load_state` (`attack_states.json`) / `stop`. |
| `tools/kernel/orchestration.py` | Shared swarm + campaign vocabulary: `MAX_MODULE_FAILURES`, `atomic_write_json`, `safe_emit`. |

Basic usage:

```python
orchestrator = AutonomousOrchestrator(mission_config, workspace, tool_executor)
results = await orchestrator.run_autonomous_campaign(targets=["10.0.0.50"])
```

## Orchestrator lifecycle

### Construction

`AutonomousOrchestrator.__init__` wires (all best-effort where noted):

- `AttackModuleExecutor` with the swarm context passed through (scope gate, risk controller, evidence store, blackboard, model client, critic, reflection) plus `tool_executor`, an `OpsecManager` built from the `opsec` config block, a shared `ExperienceStore`, and an opt-in `SemanticMemoryManager`.
- Retry budget: `_max_module_failures` defaults to `MAX_MODULE_FAILURES` (3), overridable via `mission_config["agent"]["max_retries_per_task"]`. `_max_cycles` defaults to 100; `_max_aggression` defaults to `AggressionLevel("maximum")`.
- Opt-in capability flags read from `mission_config` (merged from `config.yaml`'s `autonomous` block by the campaign call sites): `persistence_phase`, `checkpoint_every`, `adaptive_replan`, `max_parallel_targets` (default 1, serial), `max_pivot_depth` (default 0, single-IP lock), `dedup_targets`, `skip_non_routable`, `hard_target_max_rounds`, kill-chain (`killchain.enabled`, `killchain.goal_state`), and the MSF advisory flag (`msf_auto_les` or `msf.auto_local_exploit_suggester`).

### `run_autonomous_campaign`

```text
run_autonomous_campaign(targets, resume=False, original_target="", resolved_ip="")
  -> stash original_target / resolved_ip for get_state()
  -> load_state(attack_states.json) when resume=True (missing file = fresh start)
  -> _preflight_targets(targets)            # opt-in filters, no scan spent yet
  -> per target: _attack_target(target)     # serial by default, or semaphore-bounded
  -> return {targets, results, duration, total_tasks, successful_exploits, states}
```

Details from `tools/campaign/orchestrator.py`:

- Each target runs under a crash-bounded guard: an unexpected exception records a `target_crash` timeline event and returns `{"status": "crashed", "error": ..., "state": ...}` instead of aborting the campaign.
- `max_parallel_targets: 1` (default) keeps the serial loop, including checkpoint interleaving. Higher values run targets concurrently under an `asyncio.Semaphore`.
- `checkpoint_every: N` (opt-in, 0 = off) calls `save_state()` every N completed targets; checkpoint failure is non-fatal.
- `stop()` flips `_running` to `False`; in-flight loops check it (`_attack_target` returns `{"status": "stopped", ...}`, adaptive rounds exit).

### `_attack_target` (per-target lifecycle)

```text
_attack_target(target, _depth=0)
  if is_local_target(target):  _phase_local_takeover -> _phase_validation -> complete
  _phase_reconnaissance
  if no open ports:            return no_attack_surface
  current_phase = ENUMERATION
  if killchain enabled and _phase_killchain verifies:  pass
  elif adaptive_replan:        _run_adaptive_rounds
  else:                        _phase_exploitation -> privesc (if access, not max priv)
                                                        -> lateral (if pivot targets)
  if persistence_phase and access_achieved:  _phase_persistence
  _phase_validation
  return {status: complete, state}
```

The local-target short-circuit exists because network brute force is the wrong shape when the operator is already on the box; the scope gate is not bypassed (privesc modules still route through `AttackModuleExecutor.execute`).

### Resume

`resume=True` loads `attack_states.json` before attacking. `_phase_reconnaissance` reuses `state.recon_result` when it already carries open ports (skips the re-scan); `AttackTask.from_dict` demotes persisted `RUNNING` / `RETRYING` tasks back to `PENDING` so a crash never wedges the queue on a stale in-flight status. Unknown enum strings degrade to defaults; `task_counter` and `prereq_tasks_added` are restored so resumed runs do not re-issue task IDs.

## AttackTask / AttackState / RetryEngine

### Enums

| Enum | Values |
|---|---|
| `AttackPhase` | `recon`, `enumeration`, `exploit`, `privesc`, `lateral`, `persistence`, `validation`, `report` |
| `TaskStatus` | `pending`, `running`, `completed`, `failed`, `retrying`, `blocked`, `chained` (waiting for prerequisite) |
| `AggressionLevel` | `stealth`, `normal`, `aggressive`, `maximum` |

### AttackTask

| Field | Meaning |
|---|---|
| `task_id` | `ATK-00001`-style ID from `_new_task_id` |
| `phase` / `module_name` / `target` / `parameters` | What to run, where, with which inputs |
| `status` | `TaskStatus`, starts `PENDING` |
| `aggression` / `priority` | Per-task aggression; scheduling priority (higher runs first in ranking) |
| `retry_count` / `max_retries` | Per-task retry budget, defaults to `MAX_MODULE_FAILURES` |
| `created_at` / `started_at` / `completed_at` | `time.monotonic()` timestamps |
| `result` / `error` / `evidence_refs` | Outcome payload, error string, evidence references |
| `chain_parent` / `chain_children` / `prerequisites` | Chaining links (prerequisite waiting uses `CHAINED`) |
| `created_from` | Provenance tag; `"recovery:prerequisite"` for recovery-scheduled producers |
| `failure_class` | Classified failure of the last attempt (`tools/failure_taxonomy.py` value, `""` = unclassified/success) |

`to_dict` / `from_dict` serialize the full task for `attack_states.json`.

### AttackState

| Field | Meaning |
|---|---|
| `target` / `current_phase` / `aggression` | Identity and campaign position |
| `privilege_level` | `none`, `user`, `admin`, `system`, `root` |
| `access_achieved` / `shell_type` | Foothold flag; `reverse`, `bind`, `webshell` |
| `successful_exploits` / `failed_attempts` | Module wins; per-module error lists |
| `attack_paths` | Vuln-chain links consumed by reporting |
| `credentials_found` / `loot` / `pivot_targets` | Harvested creds, loot paths, lateral candidates |
| `timeline` | Timestamped event log (`add_timeline_event`) |
| `recon_result` | `HostReconResult`, rebuilt via `from_dict` on resume |
| `persistence_established` | Confirmed persistence methods (e.g. `cron`, `schtask`, `webshell`) |
| `original_target` / `resolved_ip` / `discovered_subdomains` | Domain-targeting context for subdomain expansion |
| `hard_target_rounds` | Adaptive rounds with no access (reset per target) |

Key methods: `record_success` (sets shell/priv/creds/loot/pivots, emits `ui.compromise` / `ui.cred_dump`), `record_failure`, `escalate_aggression` (steps one level with a `ui.warning`), `should_continue` (true while no access, privilege below admin/system/root, or pivot targets remain).

### RetryEngine

`RETRY_STRATEGIES` maps module names to escalating parameter sets:

| Key | Escalation shape |
|---|---|
| `SSHBruteForce` | Longer timeout, more threads, larger wordlists, then `aggressive: True` |
| `SMBRelay` | Longer timeout, `null_session`, then relay + no signing check |
| `WebShellUpload` | PHP, then JSP, then ASPX extensions with bypass/encoding upgrades |
| `SQLInjection` | union, error, time-based, then stacked techniques with tamper scripts |
| `default` | Longer timeouts with retries, then `aggressive: True` |

`get_retry_parameters(module_name, attempt)` returns the strategy for that attempt, or the last one with extra aggression and a quadrupled timeout once exhausted. `should_retry` refuses when the attempt budget is spent, when `classify_failure` reports a permanent class, when the error matches the permanent-error substring list (`out of scope`, `permission denied`, `not authorized`, `blocked by scope`, `target unreachable`, `connection refused`), or when the tool is missing (`not found`, `not installed`).

## Phases

| Handler | Gate | What it does |
|---|---|---|
| `_phase_local_takeover` | `is_local_target(target)` | Best-effort local filesystem reads via `tool_executor`, then straight to privesc |
| `_phase_reconnaissance` | Always (skipped for local targets) | `ReconPipeline.recon_host`; reuses prior recon on resume; domain targets trigger crt.sh subdomain expansion with `add_discovered_target` auto-authorization |
| `_phase_exploitation` | Open ports exist | `find_modules(ctx, experience_store=...)` ranking, top 15 tasks plus deduped service-specific tasks, batch execute, aggression escalation + retry when no access |
| `_phase_privilege_escalation` | Access achieved, privilege below admin/system/root | OS-appropriate privesc modules, cloud/container gate on ports or OS hint, optional advisory `LocalExploitSuggester` follow-up |
| `_phase_lateral_movement` | `pivot_targets` non-empty | Max 5 pivots per level, visited-host skip, recursion capped at `max_pivot_depth`, skipped entirely for local targets |
| `_phase_persistence` | `persistence_phase` on and access achieved | OS + web persistence modules dispatched via `tool_executor`, confirmed via `PERSISTENCE_INSTALLED:` marker |
| `_phase_validation` | Always (end of lifecycle) | One `ValidateFinding` task (priority 90) per successful exploit |
| `_phase_killchain` | `killchain.enabled` | Verified edge path toward the goal state before free-form planning; first unverified edge falls back to normal phases |

Notes from `tools/campaign/phases.py`:

- Exploitation builds its `ModuleContext` with version, CPE, per-service CVE lists, recovered credentials, config, live attack state, and task parameters, then dedupes ranked vs service-specific tasks on `(module_name, port)`.
- Privesc picks `LinuxPrivescCheck` / `SUIDEnumeration` / `KernelExploitCheck` on Linux, `WindowsPrivescCheck` / `TokenImpersonation` / `ServiceMisconfiguration` on Windows, and adds `CloudPrivesc`, `K8sPrivesc`, `IMDSExploit`, `DockerSockEscape`, `S3BucketTakeover` when open ports intersect `{2375, 2376, 10250, 6443, 443, 80}` or the OS hints at cloud/container.
- Adaptive rounds (`_run_adaptive_rounds`) re-run exploitation with already-failed modules dropped, then privesc/lateral on their gates, then vuln-chain scheduling. The loop stops on `should_continue() == False`, the `max_cycles` round cap, a round with no novel candidate tasks, or the hard-target cutoff.
- `_schedule_vuln_chain` links the last successful exploit to recent credentials and pivot targets in `state.attack_paths` with a `vuln_chain_scheduled` timeline event.

## Prerequisite recovery

When a task fails with a `PREREQUISITE_MISSING` classification, `_execute_task_batch` schedules a producer module for the missing artifact and runs it inline before retrying the original. `_PREREQ_KIND_PATTERNS` maps error text to artifact kinds:

| Error pattern | Candidate artifact kinds |
|---|---|
| `credential\|creds\|password\|hash` | `credentials`, `hash_artifact` |
| `foothold\|session\|\bshell\b\|webshell` | `foothold`, `shell`, `webshell` |
| `admin\|root\|privilege\|high_priv\|admin_priv` | `high_priv`, `admin_priv` |

Bounds: one recovery task per failing task per batch (`prereq_scheduled` set), a campaign-level cap (`_prereq_recovery_cap`, defaults to the per-module failure budget), no self-recursion into the failing module, and recovery tasks never re-schedule (`created_from == "recovery:prerequisite"`). Candidates come from `find_producers(kind)` ordered cheapest/read-only-first with context-satisfied prerequisites ahead (`rank_producers`). If the producer does not complete, the original fails fast with no sleep/retry burned.

Batch execution otherwise uses an `asyncio.Semaphore(3)` with a retry loop (no recursive semaphore re-acquire), `RetryEngine.should_retry` gating, parameter updates from `get_retry_parameters`, and exponential backoff (`2**retry_count` seconds).

## Critic consult

`AttackModuleExecutor.execute` runs a `CriticAgent` pre-check (`_run_critic`) on top of the inline scope/risk checks. The critic receives the proposed action (`target`, `phase`, `tool`, `module_name`, `risk_level`, `aggression`) plus context (`scope_gate`, `risk_controller`, `mission`, `model_client`, `blackboard`) and returns approve, deny, or modify:

- `deny` blocks before any module code runs (`critic_deny` timeline event, failure recorded on the blackboard).
- `modify` mutates the task in place (`_apply_critic_modifications`): `high -> medium` downgrades `MAXIMUM` to `AGGRESSIVE`, `-> low` downgrades `MAXIMUM`/`AGGRESSIVE` to `NORMAL` (both tagged in `parameters`), and `require_mutation` sets `critic_require_mutation` for the retry path.
- No wired critic means only the inline checks apply. A critic exception denies fail-closed. After each attempt the executor records success/failure on the shared blackboard (feeding repeat-failure detection) and runs the advisory `ReflectionAgent` post-check, which updates `last_reflection` / `strategy_shift` / `failed_modules` itself.

## snapshot_before_destructive

`_snapshot_before_destructive` mirrors the exploit-loop hook for the no-MCP dispatch path: when `should_snapshot(module_name, command, mission_config)` is true (snapshots enabled plus auto-before-destructive plus a destructive command), it lazily builds a cached `SnapshotManager` and calls `before_destructive(target, label)` with label `pre-<module>-<attempt>`, recording `snapshot_taken` (snapshot id, provider, label) on the timeline. Fail-open by contract: any failure records `snapshot_err` and the dispatch proceeds. Snapshot providers and credentials are env-only; see the `snapshots` config reference.

## Observe hook

`observe_autonomous_progress(callback)` (in `tools/campaign/state.py`) is a context manager that routes one task's phase/action updates to `callback` via a `ContextVar`; `_report_autonomous_progress(**payload)` emits through `safe_emit`, so observability can never break an attack path. Every phase handler reports `phase` + `target` on entry; `execute` additionally reports `action`, `attempt`, and `tool`. The run-service layer consumes it to drive progress heartbeats:

```python
from tools.autonomous_orchestrator import observe_autonomous_progress

with observe_autonomous_progress(_track_progress):
    return await swarm_loop.run_autonomous_campaign([target_ip])
```

Implementation note: the consumer above lives in `tools/run_service/tasks.py`, where `_track_progress` updates the run's action count and current phase.

## Configuration (`autonomous.*`)

All Phase 2 capabilities default off so the default single-pass campaign is unchanged. Values below are the checked-in `config.yaml` defaults.

| Key | Default | Effect |
|---|---|---|
| `autonomous.persistence_phase` | `false` | Run the `PERSISTENCE` phase after access is achieved |
| `autonomous.checkpoint_every` | `0` | Save `attack_states.json` every N completed targets (`0` = off) |
| `autonomous.adaptive_replan` | `false` | Multi-round exploit/privesc/lateral loop with pre-round replan and vuln-chaining |
| `autonomous.max_parallel_targets` | `1` | Per-target fan-out under a semaphore (`1` = serial) |
| `autonomous.max_cycles` | `100` | Round cap for adaptive rounds |
| `autonomous.max_pivot_depth` | `0` | Pivot recursion depth (`0` = single-IP lock, pivots discovered but never recursed into) |
| `autonomous.dedup_targets` | `false` | Collapse duplicate IPs / CIDR overlap / hosts resolving to the same IP at entry |
| `autonomous.skip_non_routable` | `false` | Drop RFC1918/link-local/reserved addresses that are not the operator's own host |
| `autonomous.hard_target_max_rounds` | `0` | Give up on a target after this many adaptive rounds with no access (`0` = off) |

Adjacent mission-config keys the orchestrator reads:

| Key | Default | Effect |
|---|---|---|
| `max_aggression` | `"maximum"` | Aggression ceiling for escalation |
| `agent.max_retries_per_task` | `3` | Overrides the campaign-level per-module failure cap |
| `killchain.enabled` / `killchain.goal_state` | `false` / `"shell_as_root"` | Prefer verified kill-chain edges before free-form planning |
| `snapshots.enabled` / `snapshots.auto_before_destructive` | `false` / `true` | Snapshot gate for `_snapshot_before_destructive` |
| `msf_auto_les` (or `msf.auto_local_exploit_suggester`) | `false` | Advisory `LocalExploitSuggester` follow-up after the privesc batch |
| `orchestrator.semantic_memory` | `true` | Build a `SemanticMemoryManager` and `store_lesson` on confirmed wins (action type `orchestrator:module_success`) |
| `opsec.*` | disabled profile | Pacing/UA rotation resolved per task target (`resolve_for_target`) |

Implementation note: the `autonomous` block is merged into `mission_config` by the campaign call sites (MCP campaign tools), and the schema documents the Phase 2 subset at `tools/config/schema.py` near the `"autonomous"` key; if a key above is missing from the schema, the orchestrator's `mission_config.get` defaults still apply.

## Relation to swarm

Campaign and swarm are alternative execution paths within a run, never concurrent. Decision rule: `--swarm` for single-target specialist decomposition, campaign for persistent multi-phase queues across one or many targets, combined on high-value targets.

| Aspect | Campaign (`tools/campaign/`) | Swarm (`tools/swarm/`) |
|---|---|---|
| Decomposition | Sequential phases per target, task batches with concurrency 3 | Six specialist agents (recon, vuln, exploit, post-exploit, critic, reflection) with parallel dispatch |
| State model | Durable per-target `AttackState` + task queue, persisted to `attack_states.json` | Volatile cross-agent blackboard (`failed_modules`, `successful_modules`, reflections) |
| Reasoning gate | `CriticAgent` pre-check per module + `ReflectionAgent` post-check (both optional, wired through the executor) | Critic gates every non-recon action with bounded negotiation; reflection adapts strategy between phases |
| Retry logic | `RetryEngine` parameter strategies + aggression escalation + prerequisite recovery | Reflection failure-pattern thresholds over the same `MAX_MODULE_FAILURES` budget |
| Progress reporting | `observe_autonomous_progress` ContextVar hook | `event_callback` |
| Persistence | `atomic_write_json` for `attack_states.json` | `atomic_write_json` for `swarm_state.json` |
| Entry point | `AutonomousOrchestrator.run_autonomous_campaign` / MCP `start_autonomous_campaign` | `SwarmOrchestrator` via `AgentLoop` or run-service |

Shared vocabulary lives in `tools/kernel/orchestration.py` (`MAX_MODULE_FAILURES`, `atomic_write_json`, `safe_emit`) precisely so the two engines cannot drift apart on retry budgets, crash-safe writes, or the never-break-the-path callback contract.

## Related documentation

- [Swarm subsystem](swarm.md)
- [Runtime flows](runtime-flows.md)
- [Exploit agent](exploit-agent.md)

## Source map

- `tools/autonomous_orchestrator.py`
- `tools/campaign/__init__.py`
- `tools/campaign/orchestrator.py`
- `tools/campaign/state.py`
- `tools/campaign/executor.py`
- `tools/campaign/phases.py`
- `tools/campaign/batch.py`
- `tools/campaign/preflight.py`
- `tools/campaign/service_tasks.py`
- `tools/campaign/state_store.py`
- `tools/kernel/orchestration.py`
- `tools/mcp_tools/modules/campaign.py`
- `tools/run_service/tasks.py`
- `tools/config/schema.py`
- `config.yaml`
