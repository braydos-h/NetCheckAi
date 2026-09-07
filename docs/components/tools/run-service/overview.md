---
title: Run Service — Overview
package: tools/run_service
files: [service.py, models.py, prepare.py, execute.py, tasks.py, providers.py, warmup.py, __init__.py]
---

# Run Service — Overview (`tools/run_service/`)

Transport-neutral preparation + execution engine shared by the CLI
(`main.async_main`) and the WebUI API daemon (`tools/api/run_manager.py`).
`AssessmentService` resolves a `RunRequest` into a `RunPreview` (`prepare`,
no side effects beyond config reads + `reports/<run_id>/` mkdir), then runs
the assessment (`execute`: MCP session, agent loop, swarm, reports) and
returns a `RunResult`. The service never calls `AttackUi` directly — operator
interaction flows through `DecisionProvider` / `EventSink` /
`ApprovalProvider` (terminal vs API adapters in `providers.py`).

## Package map

| File | Export | Line | Role |
|---|---|---|---|
| `service.py` | `AssessmentService` | 24 | `PrepareMixin` + `ExecuteMixin` + `TasksMixin` composition + `__init__` |
| `models.py` | `RunState` | 26 | `draft/preparing/awaiting_confirmation/queued/running/awaiting_input/cancelling/completed/failed/cancelled/interrupted` |
| `models.py` | `RunKind` | 42 | `AGENT` only (`MANUAL` removed — `execute` never branched on it) |
| `models.py` | `DecisionKind` | 53 | `START_CONFIRM/GOAL_SELECT/TOOL_APPROVAL/CAMPAIGN_NEXT_STEP` |
| `models.py` | `DecisionStatus` | 60 | `pending/answered/denied/expired` |
| `models.py` | `RunRequest` | 90 | Transport-neutral run description |
| `models.py` | `RunPreview` | 134 | Ready-to-begin gate data + `required_confirmation_text` |
| `models.py` | `RunResult` | 176 | Serializable outcome + `cancelled` + `objective_transitions` |
| `models.py` | `Decision` | 216 | `id/run_id/kind/prompt_text/required_text/options/status/answer/...` |
| `models.py` | `Event` | 235 | `sequence/timestamp/run_id/type/payload` |
| `models.py` | `EVENT_*` | 253 | `state/boot/progress/phase/goal_suggestions/recon_assessment/assistant/tool_request/tool_start/tool_result/approval/swarm/artifact/completion/error/fast_recon_*/ai_takeover_started` |
| `prepare.py` | `PrepareMixin` | 456 | `prepare` / `_prepare_sync` + router/model helpers |
| `prepare.py` | `Callables` | 438 | Injectable `build_router/open_session/run_session/goal_engine_cls/run_recon_assessment/run_safety_review/witness_agent_factory` |
| `prepare.py` | `_build_campaign_result_from_records` | 75 | Audit-records → minimal `campaign_result["states"]` for `EnhancedReportGenerator` |
| `prepare.py` | `_TelemetryAccumulator` | 288 | Incremental `llm_usage.jsonl` reader (byte offset, truncation-safe) |
| `prepare.py` | `_CreateTimings` | 171 | Per-stage `perf_counter` timings for run creation |
| `prepare.py` | `_request_to_args` | 828 | `RunRequest` → `argparse.Namespace` stand-in for skills/resume/CLI helpers |
| `execute.py` | `ExecuteMixin` | 63 | `execute` + `_start_witness` |
| `tasks.py` | `TasksMixin` | 49 | `_recon_first/_fast_recon/_setup_swarm/_run_session/_wait_swarm/_find_resume_match` |
| `providers.py` | protocols + adapters | 40 | `DecisionProvider/EventSink/ApprovalProvider/CancellationToken` + terminal/API impls |
| `warmup.py` | `warm_runtime_caches` | 28 | Daemon-boot cache warmup (plugins/skills/model-router) |
| `warmup.py` | `start_background_warmup` | 85 | `warm_runtime_caches` on a daemon thread |

## `AssessmentService` (`service.py:24`)

```python
class AssessmentService(PrepareMixin, ExecuteMixin, TasksMixin):
    def __init__(
        self,
        *,
        config: dict[str, Any] | None = None,
        callables: "Callables | None" = None,
    ) -> None: ...
```

Holds no run-specific mutable state between calls — `prepare` returns a
`RunPreview` that `execute` consumes. `config` pins an in-memory config
(`prepare` deep-copies it, then applies skills overrides); `callables` lets
the CLI pass its monkeypatchable module-level symbols (`open_session`,
`run_session`, `build_router`, `GoalEngine`) so tests patching `main.*` keep
working. The API path uses the direct-import defaults (`_DEFAULT_CALLABLES`,
`prepare.py:453`).

## `RunRequest` / `RunPreview` / `RunResult` (`models.py:90/134/176`)

```python
@dataclass
class RunRequest:
    target: str
    mode: RunMode = "attack"  # "recon" | "attack" | "fast"
    goal_name: str = ""
    custom_goal: str = ""
    recon_first: bool | None = None  # None = auto (recon-first when no goal)
    model_alias: str = ""
    config_path: Path = Path("config.yaml")
    reports_dir: Path = Path("reports")
    swarm: bool = False
    parallel_swarm: bool = False
    critic: bool = False
    reflection: bool = False
    adaptive_exploits: bool = False
    long_session: bool = False
    multi_model_consult: bool | None = None
    observer_mode: str = "hybrid"
    ultrathink: bool = False
    debug: bool = False
    plain: bool = False
    json_output: bool = False
    yes: bool = False
    skills_mode: str | None = None
    skills_include: list[str] = field(default_factory=list)
    skills_exclude: list[str] = field(default_factory=list)
    skills_no_reselect: bool = False
    resume_source: str = ""
    kind: RunKind = RunKind.AGENT
    interactive: bool = False
```

`is_agent_attack_mode(mode)` (`models.py:74`) is True for `attack`/`fast`;
`is_fast_mode(mode)` (`models.py:85`) is True for `fast` only.

`RunPreview` (`models.py:133`) carries everything the ready-to-begin gate
shows: `run_id/reports_dir/config_path/target_ip/original_target/resolved_ip/
resolved_domain/mode/goal_name/goal_description/model_alias/model_label/
transport_summary/permission/attack_mode/swarm/parallel_swarm/multi_model/
destructive/required_confirmation_text` (`"ALLOW <ip>"` when
`permission == full_access` + attack mode) plus `budgets`
(`commands/rounds/duration_minutes`), `skill_activations`, `skill_errors`,
`timings` (per-stage ms), `resumed_from`.

`RunResult` (`models.py:175`) carries `run_id/target_ip/mode/goal_name/
goal_description/total_actions/workspace/audit_path/records/messages/error/
swarm_result/active_skills/outcome_summary/telemetry/safety_review/
reports_dir/summary_path/run_json_path/cancelled/objective_transitions`
(`objective_transitions` = `[{from, to, at_checkpoint}]` from mid-run
checkpoints).

## Prepare / execute split + lifecycle

```
RunRequest ──prepare()──▶ RunPreview ──start_confirm──▶ execute() ──▶ RunResult
 (no I/O side          (worker thread,      (Decision)   (MCP session, agent loop,
  effects beyond         staged timings)                  swarm, reports)
  config reads)
```

`prepare` (`prepare.py:568`):

```python
async def prepare(
    self,
    request: RunRequest,
    *,
    run_id: str | None = None,
    progress: "Callable[[str, str], None] | None" = None,
) -> RunPreview: ...
```

Runs `_prepare_sync` on a worker thread (`asyncio.to_thread`). Stages
(`_STAGE_MESSAGES`, `prepare.py:44`): `config → plugins → router → model →
target_validate → target_resolve → goals → exploit_settings → skills →
filesystem`, each timed by `_CreateTimings` and reported via `progress(stage,
message)` (failures swallowed). Notable behavior: `_COLD_INIT_LOCK`
serializes cold plugin/skill-registry init across concurrent prepares;
provider-aware router build (`_build_router_for_config`, `prepare.py:486`)
keeps the ollama path byte-compatible with test fakes; target DNS resolves
via `resolve_target_bounded` with `api.dns_timeout_seconds` (default 5.0);
unresolvable goals degrade to a `custom("recon-first goal selection")`
placeholder resolved later in `execute`; `reports/<run_id>/` is mkdir'd
(timestamp id when `run_id` omitted).

`execute` (`execute.py:64`):

```python
async def execute(
    self,
    request: RunRequest,
    preview: RunPreview,
    *,
    decision_provider: DecisionProvider,
    event_sink: EventSink,
    cancellation: CancellationToken,
    model_client: Any | None = None,
    config: dict[str, Any] | None = None,
    approval_provider: Any | None = None,
    session_attach: Callable[[Any, list[dict[str, Any]], Any], None] | None = None,
) -> RunResult: ...
```

Lifecycle inside `execute`:

1. `RunLog.attach(reports_dir)` + emit `state: running`; optional advisory
   witness side task (`_start_witness`, `execute.py:761`) polling
   `scan_once()` every `witness.poll_interval_seconds`.
2. Build/refresh model client when not supplied
   (`_build_router_for_config` + `_ensure_client_registered`,
   `prepare.py:486/512`); resolve alias via `_resolve_model_alias`
   (`prepare.py:544` — chatgpt falls back to `chatgpt.default_model`, not
   the ollama default).
3. Resolve goal: `fast` → `_fast_recon` (auto-selects highest-ranked
   compatible goal, no blocking prompt); `recon_first` (auto when no goal
   given) → `_recon_first` (scan → `goal_suggestions` → `GOAL_SELECT`
   decision); `custom_goal`/preset direct; else interactive `GOAL_SELECT`
   decision; resume state overrides (`tasks.py:161`).
4. Build exploit settings (`build_cli_exploit_settings`) + runtime skill
   selection; set up swarm (`_setup_swarm`, `tasks.py:387`) as a sibling
   `asyncio.Task` with its own `_RunHeartbeat`.
5. Mid-run checkpoint closure (`_checkpoint_hook`, `execute.py:362`) — attack
   mode only: builds a `CAMPAIGN_NEXT_STEP` Decision from the loop's
   `CheckpointContext` (`access`: privesc/another_goal/finish/cancel;
   `no_path`: continue/change_goal/finish/cancel), parses `"<action>[:goal
   [:custom]]"` answers into `CheckpointOutcome`, records
   `objective_transitions` in `_goal_box`.
6. `_run_session` (`tasks.py:481`) → `run_exploit_session` → MCP session +
   `run_exploit_agent` loop; `_wait_swarm` (`tasks.py:567`) keeps the progress
   ticker alive until the swarm finishes (2s poll, `swarm_state.json`
   snapshot, `_compute_swarm_timeout` cap).
7. Post-run: telemetry snapshot, recon-mode safety review, `session_summary.md`
   + `run.json`, best-effort enhanced report via
   `_build_campaign_result_from_records` + `EnhancedReportGenerator`
   (`reports/<run_id>/enhanced/enhanced_report.{json,md,html}`), `artifact` +
   `completion` events, `RunLog.detach()`, and `cancelled` mapping from
   `cancelled_by_operator`.

`TasksMixin` helpers (`tasks.py`): `_find_resume_match(reports_dir,
resume_key)` (`:51`); `_recon_first(*, request, config, config_path,
target_ip, original_target, resolved_ip, resolved_domain, reports_dir,
model_client, model_alias, risk_profile, goal_engine, decision_provider,
event_sink, cancellation)` (`:67`); `_fast_recon(...)` same shape (`:181`);
`_setup_swarm(...)` (`:387`); `_run_session(...)` (`:481`); `_wait_swarm(...)`
(`:567`).

```python
# Example: prepare → confirm → execute (API-style providers)
service = AssessmentService()
preview = await service.prepare(RunRequest(target="10.0.0.50", mode="attack"))
answer = await decision_provider.request(Decision(
    id="", run_id=preview.run_id, kind=DecisionKind.START_CONFIRM,
    prompt_text="Ready to begin", required_text=preview.required_confirmation_text,
))
result = await service.execute(
    RunRequest(target="10.0.0.50", mode="attack"), preview,
    decision_provider=decision_provider, event_sink=event_sink,
    cancellation=CancellationToken(),
)
```

## Providers (`providers.py`)

| Protocol | Method | Terminal adapter | API adapter |
|---|---|---|---|
| `DecisionProvider` (`:44`) | `request(decision) -> str` | `TerminalDecisionProvider` (`:60`) → `AttackUi.ask_confirm/ask_destructive_confirm/ask_goal_from_suggestions/ask_tool_approval/_qselect` | `ApiDecisionProvider` (`:195`) → persist row + `state: awaiting_input` + `approval` event + `broker.await_answer` |
| `EventSink` (`:235`) | `emit(type, payload)` | `TerminalEventSink` (`:242`) no-op (CLI prints via `AttackUi`) | `ApiEventSink` (`:255`) → `EventBroker.emit` (JSONL + WS) |
| `ApprovalProvider` (`:272`) | `approve(action, command, detail, target) -> bool` | `TerminalApprovalProvider` (`:290`) wraps sync `prompt_func` via `asyncio.to_thread`, exact `ALLOW <host>` match | `ApiApprovalProvider` (`:319`) → `TOOL_APPROVAL` decision, exact `ALLOW <target>` match |
| `CancellationToken` (`:346`) | `cancel()/cancelled/wait()` | shared | shared (`RunManager.cancel` sets flag + cancels task) |

`_maybe_await` (`providers.py:21`) normalizes mixed sync/async `AttackUi`
methods. EOF/`KeyboardInterrupt` in terminal adapters returns `""` (deny) —
for `campaign_next_step` it returns `"finish"`.

## Warmup (`warmup.py`)

```python
def warm_runtime_caches(config: dict[str, Any] | None) -> dict[str, float]: ...
def start_background_warmup(config: dict[str, Any] | None) -> threading.Thread | None: ...
```

Pays cold-start costs once at daemon boot on a daemon thread
(`breachpilot-warmup`): plugin discovery (`tools.plugins.load_plugins`),
skill-registry parse (`tools.skill_registry_cache.get_registry`), and (ollama
only) model-router import + construction for a warm SSL context. Non-ollama
providers skip construction (their `build_router` may spawn subprocesses).
Every stage is individually wrapped — warmup never raises, performs no
network I/O or health checks. Returns per-stage ms timings.

## Config keys

| Key | Default | Used by |
|---|---|---|
| `ollama.host` | `https://api.ollama.com` | Router build (`prepare.py:489, 538`) |
| `models.registry` / `models.default_alias` / `models.info` | `glm` | Alias resolution + preview `model_label` (`prepare.py:544, 770`) |
| `mcp.http_port` | `8001` | MCP session transport + preview `transport_summary` (`prepare.py:774`; `tasks.py:93, 219`) |
| `exploit.permission` | `read_only` fallback | Preview `permission` + `destructive` verdict (`prepare.py:761, 769`) |
| `exploit.max_rounds` / `max_commands_per_session` / `attack_max_*` | n/a | Preview `budgets` (`prepare.py:780`) |
| `api.dns_timeout_seconds` | `5.0` | Bounded target resolve (`prepare.py:669`) |
| `long_session.enabled` / `request_timeout_seconds` | n/a | Model request timeout (`prepare.py:645`; `execute.py:139`) |
| `witness.enabled` / `poll_interval_seconds` / `escalate_to_event_broker` | off / `5.0` / true | Advisory witness side task (`execute.py:121, 784`) |
| `swarm.enabled` / `parallel_enabled` | false | Preview `swarm`/`parallel_swarm` (`prepare.py:765`); `_setup_swarm` gate (`execute.py:289`) |
| `multi_model.enabled` | false | Default for `multi_model_consult=None` (`prepare.py:721`; `execute.py:251`) |
| `skills.*` | — | CLI overrides (`_request_to_args`) + runtime selection (`prepare.py:629, 741`) |

Env overrides: `EXPLOIT_TARGET*` / `DISCOVERED_TARGETS` feed the target-IP
lock downstream (see exploit-agent runner); `BREACHPILOT_API_TOKEN` feeds API
auth (see `docs/run-service.md`).

```python
# Example: CLI-style injection (monkeypatch-compatible symbols)
service = AssessmentService(callables=Callables(
    build_router=main_mod.build_router,
    open_session=main_mod.open_exploit_mcp_session,
    run_session=main_mod.run_exploit_session,
    goal_engine_cls=main_mod.GoalEngine,
))
```

## Tests

| File | Covers |
|---|---|
| `tests/test_run_manager.py` | Single-active-run lifecycle through the service |
| `tests/test_run_create_startup.py` | `prepare` stages + create timings |
| `tests/test_api_runs.py` | `POST /runs` → preview → execute via `RunManager` |
| `tests/test_api_campaign_checkpoint.py` | `CAMPAIGN_NEXT_STEP` checkpoint decisions |
| `tests/test_witness_wiring.py` | Witness factory seam + advisory teardown |
| `tests/test_service_extraction.py` | `AssessmentService` transport-neutral extraction |

Implementation note: `docs/run-service.md` still cites `service.py:280-879`
line numbers from before the `prepare`/`execute`/`tasks` split — trust the
per-file locations in the package map above, not those stale references.

## Related documentation

- [Run service](../../../run-service.md)
- [Exploit Agent overview](../exploit-agent/overview.md)
- [Exploit Agent runner](../exploit-agent/runner.md)
- [Exploit Agent loop](../exploit-agent/loop.md)
- [Exploit Agent policy](../exploit-agent/policy.md)
- [Swarm overview](../swarm/overview.md)
- [Kernel overview](../kernel/overview.md)
- [Architecture](../../../architecture.md)

## Source map

- `tools/run_service/service.py`
- `tools/run_service/models.py`
- `tools/run_service/prepare.py`
- `tools/run_service/execute.py`
- `tools/run_service/tasks.py`
- `tools/run_service/providers.py`
- `tools/run_service/warmup.py`
- `tools/run_service/__init__.py`
