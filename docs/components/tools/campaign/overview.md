---
title: Campaign — Overview
package: tools/campaign
files: [orchestrator.py, state.py, executor.py, phases.py, batch.py, preflight.py, service_tasks.py, state_store.py, __init__.py]
---

# Campaign — Overview (`tools/campaign/`)

Persistent multi-phase attack engine behind the `tools/autonomous_orchestrator.py` facade: per-target `AttackState` plus a task queue, phase handlers, scope-locked dispatch, retries, and resume. The concept (when to use campaign vs swarm, adaptive rounds, kill-chain design) lives in `docs/campaign.md`; this page is the implementation companion — classes, state machine, and file map.

## Architecture

```text
AutonomousOrchestrator (orchestrator.py)
  -> _preflight_targets (preflight.py)        # resolve / dedupe / scope-check, before any scan
  -> per target: _attack_target (phases.py)
       _phase_local_takeover  (local box: filesystem reads -> privesc)
       _phase_reconnaissance  (ReconPipeline.recon_host; reused on resume)
       _phase_exploitation    (find_modules ranking + service tasks -> batch)
       _phase_privilege_escalation / _phase_lateral_movement
       _phase_persistence     (opt-in) -> _phase_validation
       _phase_killchain       (opt-in verified edges, before free-form planning)
       _run_adaptive_rounds   (opt-in multi-round replan + vuln chaining)
  -> _execute_task_batch (batch.py) -> AttackModuleExecutor.execute (executor.py)
       scope gate -> risk -> critic pre-check -> module.run -> dispatch artifact
       -> classify -> record -> reflection post-check
  -> save_state / load_state (state_store.py, attack_states.json)
```

`tools/autonomous_orchestrator.py` is a thin facade re-exporting the package so old imports keep working. Patch-seam contract (verified in the shim docstring): tests patch `find_modules` / `get_module` / `find_producers` through the facade, and campaign code resolves those three helpers via `getattr` on the facade at call time — never a top-level `from tools.attack_modules import ...` for a name tests stub there.

## Package map

| File | Key symbols | Role |
|---|---|---|
| `orchestrator.py` | `AutonomousOrchestrator` | Constructor wiring, `run_autonomous_campaign`, `_attack_target` delegation, wrappers for batch / preflight / service-tasks / state-store; phase handlers bound after class definition |
| `state.py` | `AttackTask`, `AttackState`, `AggressionLevel`, `AttackPhase`, `TaskStatus`, `RetryEngine`, `observe_autonomous_progress` | Enums, task/state dataclasses, retry engine, progress hook |
| `executor.py` | `AttackModuleExecutor` | Per-task lifecycle: scope, risk, critic, dispatch, classify, record, reflect |
| `phases.py` | `_phase_*`, `_attack_target`, `_run_adaptive_rounds`, `_module_context` | Phase handlers (bound onto the orchestrator as `self._phase_*`) |
| `batch.py` | `_execute_task_batch`, `_maybe_schedule_prereq`, `_retry_failed_modules` | Concurrency-3 batches, prerequisite recovery, aggression-escalated retry |
| `preflight.py` | `_preflight_targets` | Campaign-entry target filtering |
| `service_tasks.py` | `_create_service_specific_tasks` | Extra exploit tasks per discovered service |
| `state_store.py` | `save_state`, `load_state`, `stop` | `attack_states.json` persistence + graceful stop |
| `__init__.py` | re-exports | `AutonomousOrchestrator`, `AttackModuleExecutor`, state classes, progress hook |

## `AutonomousOrchestrator` (`orchestrator.py:40`)

```python
class AutonomousOrchestrator:
    def __init__(
        self,
        mission_config: dict[str, Any],
        workspace_root: Path,
        tool_executor: Callable[[str, dict[str, Any]], str] | None = None,
        *,
        recon_config: ReconConfig | None = None,
        scope_gate: Any | None = None,
        risk_controller: Any | None = None,
        evidence_store: Any | None = None,
        blackboard: dict[str, Any] | None = None,
        model_client: Any = None,
        critic_agent: Any = None,
        reflection_agent: Any = None,
        experience_store: Any | None = None,
        semantic_memory: Any | None = None,
    ) -> None: ...
    def _new_task_id(self) -> str: ...                      # ATK-00001 style
    def get_state(self, target: str) -> AttackState: ...
    async def run_autonomous_campaign(
        self, targets: list[str], *, resume: bool = False,
        original_target: str = "", resolved_ip: str = "",
    ) -> dict[str, Any]: ...
    async def _attack_target(self, target: str, *, _depth: int = 0) -> dict[str, Any]: ...
    def save_state(self, path: Path | None = None) -> Path: ...
    def load_state(self, path: Path) -> bool: ...
    def stop(self) -> None: ...
```

Constructor wiring (`orchestrator.py:60-274`): builds `ReconPipeline`, a shared `ExperienceStore` (falls back to ranking without it), an `OpsecManager` from the `opsec` block (best-effort), and the `AttackModuleExecutor` with the swarm context passed through. Retry budget `_max_module_failures` defaults to `MAX_MODULE_FAILURES` (3, from `tools/kernel/orchestration.py`), overridable via `mission_config["agent"]["max_retries_per_task"]`; `_max_cycles` defaults to 100; `_max_aggression` defaults to `AggressionLevel("maximum")`.

`run_autonomous_campaign` lifecycle: stash `original_target`/`resolved_ip` for `get_state()` → `load_state` when `resume=True` (missing file = fresh start) → `_preflight_targets(targets)` → per-target `_attack_target` (serial by default; semaphore-bounded when `max_parallel_targets > 1`) → `{targets, results, duration, total_tasks, successful_exploits, states}`. Each target runs under a crash-bounded guard returning `{"status": "crashed", ...}` instead of aborting the campaign; `checkpoint_every: N` saves state every N completed targets (best-effort); `stop()` flips `_running` so in-flight loops exit with `{"status": "stopped", ...}`.

## State machine

### `AttackPhase` (`state.py:56`)

`RECONNAISSANCE="recon"`, `ENUMERATION="enumeration"`, `EXPLOITATION="exploit"`, `PRIVILEGE_ESCALATION="privesc"`, `LATERAL_MOVEMENT="lateral"`, `PERSISTENCE="persistence"`, `VALIDATION="validation"`, `REPORTING="report"`.

### `TaskStatus` (`state.py:67`)

`PENDING` → `RUNNING` → `COMPLETED` / `FAILED`; plus `RETRYING`, `BLOCKED` (scope/risk/critic gate), `CHAINED` (waiting for prerequisite). `AttackTask.from_dict` demotes persisted `RUNNING`/`RETRYING` to `PENDING` so a crash never wedges the queue, and unknown enum strings degrade to defaults.

### `AggressionLevel` (`state.py:49`)

`STEALTH` → `NORMAL` → `AGGRESSIVE` → `MAXIMUM`; `AttackState.escalate_aggression()` steps one level with a `ui.warning`.

### Per-target lifecycle (`phases.py:906`)

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

Result statuses: `complete`, `no_attack_surface`, `stopped`, `crashed`, `aborted`. `should_continue()` stays true while no access, privilege is below admin/system/root, or pivot targets remain.

## `AttackTask` / `AttackState` / `RetryEngine` (`state.py`)

`AttackTask` fields: `task_id`, `phase`, `module_name`, `target`, `parameters`, `status` (`PENDING`), `aggression` (`NORMAL`), `priority` (50), `retry_count`/`max_retries`, `created_at`/`started_at`/`completed_at`, `result`, `error`, `evidence_refs`, `chain_parent`/`chain_children`/`prerequisites`, `created_from` (provenance tag, `"recovery:prerequisite"` for recovery-scheduled producers), `failure_class` (classified failure of the last attempt, `""` = unclassified). Full `to_dict`/`from_dict` round-trip for `attack_states.json`.

`AttackState` fields: `target`, `current_phase`, `aggression`, `privilege_level` (`none`/`user`/`admin`/`system`/`root`), `access_achieved`, `shell_type`, `successful_exploits`, `failed_attempts`, `attack_paths`, `credentials_found`, `loot`, `pivot_targets`, `timeline`, `recon_result` (rebuilt via `HostReconResult.from_dict` on resume), `persistence_established`, `original_target`/`resolved_ip`/`discovered_subdomains` (domain targeting), `hard_target_rounds`.

```python
def add_timeline_event(self, event_type: str, description: str, metadata: dict[str, Any] | None = None) -> None
def record_failure(self, module_name: str, error: str) -> None
def record_success(self, module_name: str, result: dict[str, Any]) -> None
def escalate_aggression(self) -> None
def should_continue(self) -> bool
```

`record_success` sets shell/priv/creds/loot/pivots and emits `ui.compromise` / `ui.cred_dump` so a long campaign shows breakthroughs on the console.

`RetryEngine` (`state.py:361`): `RETRY_STRATEGIES` maps `SSHBruteForce`, `SMBRelay`, `WebShellUpload`, `SQLInjection` (plus `default`) to escalating parameter sets.

```python
@classmethod
def get_retry_parameters(cls, module_name: str, attempt: int) -> dict[str, Any]: ...
@classmethod
def should_retry(cls, module_name: str, error: str, attempt: int, max_attempts: int) -> bool: ...
```

`should_retry` refuses when the budget is spent, when `classify_failure` reports a permanent class, on permanent-error substrings (`out of scope`, `permission denied`, `target unreachable`, `connection refused`, …), or when the tool is missing (`not found`, `not installed`).

## `AttackModuleExecutor` (`executor.py:50`)

```python
class AttackModuleExecutor:
    def __init__(
        self, scope_gate: Any | None = None, risk_controller: Any | None = None,
        evidence_store: Any | None = None, *, blackboard: dict[str, Any] | None = None,
        mission_config: dict[str, Any] | None = None, model_client: Any = None,
        critic_agent: Any = None, reflection_agent: Any = None,
        tool_executor: Callable[[str, dict[str, Any]], str] | None = None,
        opsec_manager: Any | None = None, semantic_memory: Any | None = None,
        experience_store: Any | None = None,
    ) -> None: ...
    async def execute(self, task: AttackTask, state: AttackState) -> dict[str, Any]: ...
    async def execute_plan_step(self, step: StepContext) -> dict[str, Any]: ...
```

`execute()` order: mark `RUNNING` → fail-closed scope check (no gate wired = `BLOCKED`) → risk-budget check → `CriticAgent` pre-check (`deny` blocks, `modify` downgrades aggression in place; critic exception denies fail-closed) → resolve module through the facade → build `ModuleContext` (version/CPE/creds/task params/live attack state) → per-target OPSEC pacing → run with timeout → dispatch runnable artifact through `tool_executor` when wired (verified shell markers only set `access_achieved`) → `COMPLETED` only for `success`/`exploited`/`script_generated` (`info` stubs count as failed, never wins) → blackboard + semantic-lesson recording → advisory reflection post-check.

Supporting methods: `execute_plan_step` (FSM executor role — ephemeral task/state, folds outcome into `{success, evidence, failure_class}`; scope blocks map to `scope_blocked`), `_dispatch_module_artifact` (prefers `suggested_command`, else writes `script` to `<workspace>/modules/` and dispatches), `_dispatch_block_reason` (fail-closed target lock before dispatch), `_snapshot_before_destructive` (fail-open auto-snapshot), `_run_critic` / `_apply_critic_modifications` / blackboard recorders / `_run_reflection` / `_record_lesson_on_success` (all no-ops when their agent/store is unwired).

## Phases (`phases.py`)

| Handler | Gate | Behavior |
|---|---|---|
| `_phase_local_takeover` | `is_local_target(target)` | Best-effort local filesystem reads, then straight to privesc (scope gate still applies per task) |
| `_phase_reconnaissance` | Always (skipped for local) | `ReconPipeline.recon_host`; reuses prior recon on resume; domain targets trigger crt.sh subdomain expansion with `add_discovered_target` auto-authorization |
| `_phase_exploitation` | Open ports exist | `find_modules` ranking (top 15) plus deduped `_create_service_specific_tasks` on `(module_name, port)`; `skip_failed=True` drops already-failed modules in adaptive rounds; escalates aggression + retries when no access |
| `_phase_privilege_escalation` | Access, privilege below admin/system/root | OS-appropriate privesc sets; cloud/container modules gated on ports `{2375, 2376, 10250, 6443, 443, 80}` or OS hint; advisory `LocalExploitSuggester` follow-up when flagged |
| `_phase_lateral_movement` | `pivot_targets` non-empty | Max 5 pivots per level, visited-host skip, recursion capped at `max_pivot_depth`, never recurses from a local host |
| `_phase_persistence` | `persistence_phase` on and access achieved | OS + web persistence modules; confirms via `PERSISTENCE_INSTALLED:` marker into `state.persistence_established` |
| `_phase_validation` | Always (end of lifecycle) | One `ValidateFinding` task (priority 90) per successful exploit |
| `_phase_killchain` | `killchain.enabled` | BFS edge path toward the goal state, up to two attempts per edge; first unverified edge falls back to free-form planning |

`_run_adaptive_rounds` re-runs exploitation with failed modules dropped, then privesc/lateral on their gates, then `_schedule_vuln_chain` (last exploit → creds/pivots into `state.attack_paths`); stops on `should_continue() == False`, the `max_cycles` cap, a round with no novel candidates, or the hard-target cutoff. `_execute_task_batch` (`batch.py:22`) runs under an `asyncio.Semaphore(3)` with exponential-backoff retry and prerequisite recovery (`_maybe_schedule_prereq` schedules one producer per failing task per batch under a campaign-level cap; recovery tasks never re-schedule). `_preflight_targets` (`preflight.py:16`) applies the scope-gate pre-check, non-routable filter, and resolved-IP dedup — each opt-in, so a single-IP campaign is unchanged.

## Observe hook (`state.py:34`)

```python
@contextmanager
def observe_autonomous_progress(
    callback: Callable[[dict[str, Any]], None],
) -> Iterator[None]: ...
```

Routes one task's phase/action updates to `callback` via a `ContextVar`; `_report_autonomous_progress(**payload)` emits through `safe_emit` so observability can never break an attack path. The run-service layer consumes it for progress heartbeats:

```python
from tools.autonomous_orchestrator import observe_autonomous_progress

with observe_autonomous_progress(_track_progress):
    return await swarm_loop.run_autonomous_campaign([target_ip])
```

Implementation note: the consumer above lives in `tools/run_service/tasks.py` per the concept doc; the wiring was not re-verified here.

## Config keys

Checked-in `config.yaml` defaults; all Phase 2 capabilities default off so the single-pass campaign is unchanged.

| Key | Default | Effect |
|---|---|---|
| `autonomous.persistence_phase` | `false` | Run the `PERSISTENCE` phase after access |
| `autonomous.checkpoint_every` | `0` | Save `attack_states.json` every N completed targets (`0` = off) |
| `autonomous.adaptive_replan` | `false` | Multi-round exploit/privesc/lateral loop with pre-round replan + vuln chaining |
| `autonomous.max_parallel_targets` | `1` | Per-target fan-out under a semaphore (`1` = serial) |
| `autonomous.max_cycles` | `100` | Round cap for adaptive rounds |
| `autonomous.max_pivot_depth` | `0` | Pivot recursion depth (`0` = single-IP lock: pivots discovered, never recursed into) |
| `autonomous.dedup_targets` | `false` | Collapse duplicate IPs / CIDR overlap / same-IP hosts at entry |
| `autonomous.skip_non_routable` | `false` | Drop non-routable addresses that are not the operator's own host |
| `autonomous.hard_target_max_rounds` | `0` | Give up on a target after this many access-less adaptive rounds (`0` = off) |
| `max_aggression` | `"maximum"` | Aggression ceiling for escalation |
| `agent.max_retries_per_task` | `3` | Overrides the campaign-level per-module failure cap |
| `killchain.enabled` / `killchain.goal_state` | `false` / `"shell_as_root"` | Prefer verified kill-chain edges before free-form planning |
| `snapshots.enabled` / `snapshots.auto_before_destructive` | `false` / `true` | Snapshot gate for `_snapshot_before_destructive` |
| `msf_auto_les` (or `msf.auto_local_exploit_suggester`) | `false` | Advisory `LocalExploitSuggester` follow-up after the privesc batch |
| `opsec.*` | disabled profile | Pacing/UA rotation resolved per task target (`resolve_for_target`) |

Implementation note: `config.yaml` also carries `orchestrator.semantic_memory: true`, while the constructor gates on `mission_config.get("semantic_memory", ...)`; confirm how the call sites merge the `orchestrator` block before relying on that default.

## Examples

```python
orchestrator = AutonomousOrchestrator(mission_config, workspace, tool_executor)
results = await orchestrator.run_autonomous_campaign(targets=["10.0.0.50"])
```

```python
results = await orchestrator.run_autonomous_campaign(targets, resume=True)
orchestrator.stop()  # graceful stop; in-flight loops exit with stopped status
```

## Related documentation

- [Campaign concept](../../../campaign.md)
- [Benchmark overview](../benchmark/overview.md)
- [Kernel overview](../kernel/overview.md)
- [Swarm overview](../swarm/overview.md)
- [Recon overview](../recon/overview.md)

## Source map

- `tools/campaign/orchestrator.py`
- `tools/campaign/state.py`
- `tools/campaign/executor.py`
- `tools/campaign/phases.py`
- `tools/campaign/batch.py`
- `tools/campaign/preflight.py`
- `tools/campaign/service_tasks.py`
- `tools/campaign/state_store.py`
- `tools/campaign/__init__.py`
- `tools/autonomous_orchestrator.py`
- `tools/kernel/orchestration.py`
- `docs/campaign.md`
- `config.yaml`
