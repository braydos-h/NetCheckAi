---
title: Benchmark — Overview
package: tools/benchmark
files: [runner.py, service.py, registry.py, storage.py, models.py, xben/adapter.py, xben/manifest.py, targets.py, agent_runner.py, verifier.py, metrics.py, regression.py, replay.py, report.py, events.py, envinfo.py]
---

# Benchmark — Overview (`tools/benchmark/`)

Reproducible, oracle-verified benchmark suites. A provider owns one suite (XBEN is one), the runner executes provision → mission → verify → classify → persist per trial, and storage keeps machine-readable JSON as the source of truth. Concept, CLI, and reproducibility contract live in `docs/benchmarks.md`; this page is the implementation companion.

## Architecture

```text
provider (tools/benchmark/registry.py; XBEN via tools/benchmark/xben/)
  -> scenarios (tools/benchmark/models.py::BenchmarkScenario)
    -> provision/reset target   (tools/benchmark/targets.py::TargetManager)
    -> preflight port reachability (tools/benchmark/targets.py::target_ports_reachable)
    -> run BreachPilot mission  (tools/benchmark/agent_runner.py::MissionRunner)
    -> independently verify     (tools/benchmark/verifier.py::IndependentVerifier)
    -> classify + aggregate     (tools/benchmark/runner.py::BenchmarkRunner._classify, tools/benchmark/metrics.py)
    -> persist results          (tools/benchmark/storage.py::BenchmarkStorage)
    -> destroy/reset target     (tools/benchmark/targets.py::TargetManager.destroy_all)
    -> baseline / regression    (tools/benchmark/regression.py)
    -> report rendering         (tools/benchmark/report.py)
```

API path: `BenchmarkService` (`service.py`) owns at most one active run and fans events to subscribers; all benchmark logic lives in `BenchmarkRunner`.

## Package map

| File | Key symbols | Role |
|---|---|---|
| `models.py` | `TrialStatus`, `FailureCategory`, `ResetStrategy`, `BenchmarkScenario`, `TrialResult`, `RunConfig`, `RunEnvironment`, `RunSummary`, `unknown` | Pure data + enums + `to_dict`; no I/O |
| `registry.py` | `BenchmarkProvider`, `register_provider`, `get_provider`, `list_suites`, `list_scenarios`, `scenario_summary`, `default_manifest_dir` | Suite → scenario resolution; runner never hard-codes XBEN |
| `xben/adapter.py` | `XbenProvider` | `xben` suite provider over `benchmarks/xben/*.json` |
| `xben/manifest.py` | `parse_manifest`, `load_manifest_file`, `ManifestError` | Challenge JSON → `BenchmarkScenario` |
| `runner.py` | `BenchmarkRunner`, `mint_run_id` | Trial orchestration: provision → mission → verify → classify → persist |
| `service.py` | `BenchmarkService` | API lifecycle plumbing: active task, cancel, subscriber fan-out |
| `storage.py` | `BenchmarkStorage`, `RUN_INDEX_FILENAME` | Filesystem store under `reports/benchmarks/` |
| `targets.py` | `TargetManager`, `TargetProvisionError`, `target_ports_reachable` | Docker provision / reset / destroy + fail-fast probe |
| `agent_runner.py` | `MissionRunner`, `MissionResult` | One attack mission per trial via `run_exploit_session` |
| `verifier.py` | `IndependentVerifier`, `VerificationOutcome`, `default_verifier` | ONLY source of `oracle_verified_success` |
| `metrics.py` | `compute_run_summary`, `compute_scenario_summary`, `wilson_interval` | Pure aggregation; no I/O |
| `regression.py` | `save_baseline`, `load_baseline`, `compare_to_baseline`, `thresholds_from_config`, `RegressionResult` | Baselines + regression gates |
| `replay.py` | `build_replay_manifest`, `check_reproducibility`, `REPLAY_PIN_FIELDS` | Reproduction manifest + pin comparison |
| `report.py` | `render_report_markdown`, `render_report_html` | Public report rendered FROM stored JSON |
| `events.py` | `BenchmarkEventLogger`, `truncate_output` | Run + per-trial `events.jsonl` stream |
| `envinfo.py` | `collect_environment`, `config_hash`, `resolve_model_metadata` | Honest-or-unknown reproduction metadata |

## `models.py` — data contract

Design rules (`models.py:1`): verified vs claimed are always separate fields; unknown metadata is `"unknown"`/`None`, never substituted; deterministic `to_dict` output.

```python
def unknown(value: Any) -> str
```

| Symbol | Kind | Description |
|---|---|---|
| `TrialStatus` | enum | `VERIFIED` / `FAILED` / `FALSE_POSITIVE` / `TIMEOUT` / `INFRASTRUCTURE_ERROR` / `SKIPPED`; infra errors are distinct from exploit failures |
| `FailureCategory` | enum | `TARGET_PROVISION_FAILED`, `SANDBOX_FAILED`, `MODEL_FAILED`, `TIMEOUT`, `PLANNER_FAILURE`, `TOOL_FAILURE`, `VERIFICATION_FAILURE`, `FALSE_POSITIVE`, `NO_EXPLOIT_PATH`, `AGENT_ABORTED`, `TARGET_RESET_FAILED`, `CAPABILITY_UNAVAILABLE`, `UNKNOWN` |
| `ResetStrategy` | enum | `none` (static host) / `restart` / `recreate` |
| `BenchmarkScenario` | dataclass | `suite`, `scenario_id`, `name`, `description`, `target_type` (`docker` \| `host`), `target_image`, `target_host` (`127.0.0.1`), `target_ports`, `goal`, `expected_flags`, `oracle` (`{"flags", "host_owned_when"}`), `tags`, `difficulty`, `reset_strategy`, `timeout_seconds`, `source_manifest`, `requires_capabilities`; `benchmark_id` property = `<suite>/<scenario_id>` |
| `FlagCheck` | dataclass | `flag_id`, `description`, `check` dict |
| `TrialResult` | dataclass | `run_id`, `suite`, `scenario_id`, `trial_index`, `trial_id`, `status`, `agent_claimed_success`, `oracle_verified_success`, `false_positive`, `false_negative`, `failure_category`, `failure_detail`, durations/counters, `flags`, `evidence_refs`, `sandbox`, `target`, `telemetry` |
| `SandboxSnapshot` / `TargetSnapshot` / `TrialTelemetry` | dataclasses | Sandbox facts + target provisioning facts + model/token/cost counters |
| `RunEnvironment` | dataclass | Git SHA/dirty/branch, model provider/alias/id/version, reasoning config, temperature, config hashes, sandbox image + digest, target images, platform |
| `RunConfig` | dataclass | `suite`, `scenario_ids`, `tags`, `trials`, `timeout_seconds`, `model_alias`, `reasoning_profile`, `sandbox_required`, `save_baseline`, `check_regression`, `output_dir` |
| `ScenarioSummary` / `RunSummary` | dataclasses | Per-scenario and whole-run aggregates computed by `metrics.py` |

Core contract: a trial is solved only when the oracle confirms. Claimed-but-unverified is `FALSE_POSITIVE`; verified-but-unclaimed is `VERIFIED` with `false_negative=True`.

## Provider registry (`registry.py`)

The runner resolves suites through the registry and works purely against `BenchmarkScenario`.

```python
class BenchmarkProvider:
    suite_id: str = ""
    def load_scenarios(self, *, scenario_ids: list[str] | None = None, tags: list[str] | None = None) -> list[BenchmarkScenario]: ...
    def describe(self) -> dict[str, Any]: ...

def register_provider(provider: BenchmarkProvider) -> None
def get_provider(suite_id: str) -> BenchmarkProvider
def list_suites() -> list[dict[str, Any]]
def list_scenarios(suite_id: str) -> list[dict[str, Any]]
def scenario_summary(scenario: BenchmarkScenario) -> dict[str, Any]
def default_manifest_dir(suite_id: str) -> Path
```

- `register_provider` replaces by `suite_id`; empty `suite_id` raises `ValueError`.
- `get_provider` raises `KeyError` listing known suites (or `(none registered)`); API callers surface this as a user error, not a crash.
- `scenario_summary` is the UI-friendly descriptor without oracle payloads.
- `default_manifest_dir(suite_id)` is `benchmarks/<suite>/`.
- Discovery seams (`manifest_dir` / glob) are injectable so tests register fake suites without touching `benchmarks/`.

## XBEN adapter (`xben/adapter.py`, `xben/manifest.py`)

```python
class XbenProvider(BenchmarkProvider):
    suite_id = "xben"
    def __init__(self, manifest_dir: Path | str | None = None) -> None: ...
    def load_scenarios(self, *, scenario_ids: list[str] | None = None, tags: list[str] | None = None) -> list[BenchmarkScenario]: ...
    def describe(self) -> dict[str, Any]: ...

def parse_manifest(data: dict[str, Any], *, suite: str = "xben", source: str = "") -> BenchmarkScenario
def load_manifest_file(path: Path | str, *, suite: str = "xben") -> list[BenchmarkScenario]
class ManifestError(ValueError)
```

- Discovers `benchmarks/xben/*.json` (one challenge per file, or a top-level list); invalid manifests are skipped in `load_scenarios` (counted as `invalid_manifests` in `describe`), never aborting the suite.
- `parse_manifest` requires `benchmark_id` and a non-empty `oracle.flags` list; timeout accepts `timeout` or `timeout_seconds` (default `1800`); ports are int-coerced, invalid entries dropped.
- Oracle schema is the graded-eval oracle v2 flag schema, executed by the same `eval_checks` executors.

## `BenchmarkRunner` (`runner.py`)

```python
def mint_run_id() -> str

class BenchmarkRunner:
    def __init__(self, config: dict[str, Any], config_path: Path, *, storage: BenchmarkStorage | None = None,
                 run_session: Any = None, target_manager: TargetManager | None = None,
                 verifier_factory: Callable[[Any], IndependentVerifier] | None = None,
                 model_alias: str = "") -> None: ...
    async def run(self, run_config: RunConfig, *, cancel: asyncio.Event | None = None,
                  progress: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]: ...
    @staticmethod
    def _classify(mission_result: Any, verified: bool) -> tuple[str, str, str]: ...
```

`run()` lifecycle:

1. `get_provider(run_config.suite)` → `load_scenarios(scenario_ids, tags)`; empty match returns `{"error": ...}`.
2. `mint_run_id()` (`%Y%m%d_%H%M%S` + monotonic-ns suffix), `collect_environment(...)`, `storage.init_run(...)` (status `running`), `BenchmarkEventLogger` on `run_dir/events.jsonl` + `run_start` event.
3. Sandbox shortfall (`sandbox_required=true` but `sandbox.enabled=false`) logs `sandbox_unavailable`; every trial short-circuits to `INFRASTRUCTURE_ERROR`/`SANDBOX_FAILED` with no host fallback.
4. Per scenario × `trials`: emit `trial_start`, `_run_trial(...)`, `storage.write_trial(...)`; one fresh `TargetManager` per scenario, `destroy_all()` in `finally`; `cancel.is_set()` stops between trials.
5. Aggregate via `compute_run_summary`, `finalize_run(status, trials, summary, ...)`, render `report.md`/`.html` FROM the stored JSON, then best-effort baseline save / regression compare (never fails the run).
6. Returns `{run_id, suite, status, run_dir, report_markdown, report_html, summary, trials, regression}`.

`_run_trial()` order: sandbox gate → `provision` (trial 0) / `reset` (later trials; reset failure is `TARGET_RESET_FAILED`) → port-reachability preflight (`TARGET_PROVISION_FAILED` with the `docker compose -f eval_targets/docker-compose.yml up -d` hint) → loopback-containment preflight (`SANDBOX_FAILED` unless `sandbox.network.map_host_loopback` is opted in) → `MissionRunner.run_mission(...)` → timeout check → `_verify(...)` on a dedicated soft-fail MCP session → `_classify(...)` → false-positive override (`agent_claimed_success and not oracle_verified_success` forces `FALSE_POSITIVE`).

`_classify` mapping: verified → `(VERIFIED, UNKNOWN, "")`; `model client build failed` → `MODEL_FAILED`; MCP error with zero actions → `PLANNER_FAILURE`; zero tool calls and zero actions → `PLANNER_FAILURE`; all tool calls errored → `TOOL_FAILURE`; else `NO_EXPLOIT_PATH`.

Supporting modules:

- `targets.py`: `TargetManager.provision(scenario)`, `.reset(scenario)`, `.destroy(scenario)`, `.destroy_all()`; `target_ports_reachable(host, ports, timeout=1.0)` stdlib TCP probe shared with the readiness endpoint. Docker calls go through the `_docker_run` seam; `host` targets are adopted as-is.
- `agent_runner.py`: `MissionRunner.run_mission(scenario, *, workspace, trial_id, event_logger=None, goal=None, timeout_seconds=None)` wraps `run_exploit_session`, counts `llm_usage.jsonl` deltas for telemetry, detects claimed success from structured outcome counts, and extracts sandbox facts. Never raises; failures land in `MissionResult`.
- `verifier.py`: `IndependentVerifier(scenario, *, session=None, workspace=None, loop=None, executor=None)`; `verify()` / `verify_sync()` run each oracle flag through `verify_flag_check`; crashes and missing sessions degrade to fail-closed, never pass.
- `metrics.py`: `compute_run_summary(trials, *, run_id="", suite="", scenario_meta=None)` and `compute_scenario_summary(trials, scenario_id, name="", **meta)`; infra errors and skips are excluded from success-rate denominators; repeated trials get success probability, variance/stddev, and Wilson 95% CI via `wilson_interval(successes, total, z=1.96)`.
- `envinfo.py`: `collect_environment(config, *, model_alias="", benchmark_config=None, sandbox_enabled=False, sandbox_required=True)`; `config_hash` never copies secrets; `resolve_model_metadata` records `"unknown"` instead of guessing.
- `events.py`: `BenchmarkEventLogger(path, run_id="", sink=None).log(event_type, payload=None, *, trial_id="", scenario_id="", agent="", tool="", target="", level="info")`; append-only, secret-masked, truncated; writes never raise.
- `replay.py`: `build_replay_manifest(run_id, suite, config, environment, *, target_images=None)` stores the replay pins; `check_reproducibility(manifest, current)` reports per-field `match`/`mismatch`/`unknown` over `REPLAY_PIN_FIELDS`.
- `report.py`: `render_report_markdown(run, summary)` / `render_report_html(run, summary)` render FROM persisted JSON (JSON is canonical).

## `BenchmarkService` (`service.py`)

API-facing owner of at most one active run. No benchmark logic; route handlers delegate here.

```python
class BenchmarkService:
    def __init__(self, config: dict[str, Any], config_path: Path, *, run_manager: Any = None) -> None: ...
    def is_active(self) -> bool: ...
    @property
    def active_run_id(self) -> str | None: ...
    def status(self) -> dict[str, Any]: ...
    async def start_run(self, request: dict[str, Any]) -> dict[str, Any]: ...
    async def cancel(self) -> bool: ...
    def subscribe(self) -> asyncio.Queue[dict[str, Any] | None]: ...
    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any] | None]) -> None: ...
    async def shutdown(self) -> None: ...
```

- `start_run(request)` keys: `suite`, `scenarios`, `tags`, `trials`, `model`, `reasoning`, `sandbox_required`, `timeout_seconds`, `save_baseline`, `check_regression`. Validates suite presence, unknown suite (`unknown_suite`), empty filter match (`no_match`), and `trials` in 1–20 (`bad_trials`); refuses a second concurrent run and honors `api.max_concurrent_runs` when a run manager is wired. Mints the run inside the task and waits briefly so callers get a `run_id` immediately.
- `_execute` fans `run_id`-stamped progress events to subscribers, maps runner payload to `starting`/`running`/`completed`/`error`, and clears active state in `finally`.
- `cancel()` sets the cancel event (`cancelling`); `subscribe`/`unsubscribe` manage bounded (1000) queues with drop-oldest backpressure; `shutdown()` cancels the task and closes subscribers with `None`.

## Storage layout (`storage.py`)

Root defaults to `reports/benchmarks`, resolved to an absolute path at construction.

```text
reports/benchmarks/<suite>/<run_id>/
  run.json            RunConfig + RunEnvironment + replay manifest + trial list
  summary.json        RunSummary (absent mid-flight; run reads as running)
  events.jsonl        structured mission events (whole run)
  report.md / report.html   rendered FROM the JSON
  scenarios/<scenario_id>/trial_<n>.json   per-trial result
```

```python
class BenchmarkStorage:
    def __init__(self, root: Path | str = "reports/benchmarks") -> None: ...
    def run_dir(self, suite: str, run_id: str) -> Path: ...
    def scenario_dir(self, suite: str, run_id: str, scenario_id: str) -> Path: ...
    def init_run(self, suite: str, run_id: str, config: RunConfig, environment: RunEnvironment, scenario_ids: list[str]) -> Path: ...
    def write_trial(self, suite: str, run_id: str, trial: TrialResult) -> Path: ...
    def finalize_run(self, suite: str, run_id: str, *, status: str, trials: list[TrialResult],
                     summary: RunSummary | None, config: RunConfig, environment: RunEnvironment,
                     scenario_ids: list[str], manifest: dict[str, Any] | None = None) -> Path: ...
    def write_report(self, suite: str, run_id: str, markdown: str, html: str) -> tuple[Path, Path]: ...
    def load_run(self, suite: str, run_id: str) -> dict[str, Any] | None: ...
    def load_summary(self, suite: str, run_id: str) -> dict[str, Any] | None: ...
    def list_runs(self, suite: str | None = None) -> list[dict[str, Any]]: ...
    def list_suites(self) -> list[str]: ...
    def load_events(self, suite: str, run_id: str, *, trial_id: str = "", after: int = 0, limit: int = 500) -> list[dict[str, Any]]: ...
```

Writes are atomic (`.tmp` + `os.replace`); reads tolerate partial runs; `list_runs` merges the suite index (`runs_index.json`) with in-flight `run.json` rows; `load_events` filters by trial and sequence with corrupt-row tolerance. Path ids are validated against `^[A-Za-z0-9_.-]+$` with `..` rejected.

Implementation note: the concept doc shows a per-trial `trial_<n>_workspace/` directory that the storage module itself does not create; the runner derives the workspace path and the mission writes into it.

## Regression gates (`regression.py`)

```python
def thresholds_from_config(config: dict[str, Any] | None) -> RegressionThresholds
def save_baseline(summary: RunSummary, baseline_path: Path | str = DEFAULT_BASELINE_PATH) -> Path
def load_baseline(baseline_path: Path | str = DEFAULT_BASELINE_PATH) -> dict[str, Any] | None
def compare_to_baseline(summary: RunSummary, baseline: dict[str, Any] | None, thresholds: RegressionThresholds) -> RegressionResult
```

`RegressionThresholds`: `success_rate_tolerance` (0.02), `false_positive_tolerance` (0.01), `median_time_tolerance` (0.20 relative), `tool_actions_tolerance` (0.30 relative), `cost_tolerance` (0.30 relative). Hard findings fail CI (`--check-regression` exits 1): success-rate drop beyond tolerance, false-positive-rate rise beyond tolerance, any baseline-solved scenario now unsolved. Time / tool-action / cost rises are warnings; a missing or unreadable baseline is a hard failure. `RegressionResult` carries `passed`, `baseline_run_id`, `findings`, plus `hard_count` / `warning_count` / `improvement_count` and `messages()`.

## Lifecycle

```text
start_run(request) | --benchmark CLI
  -> BenchmarkRunner.run(RunConfig)
    -> for each scenario x trial: provision -> preflight -> mission -> verify -> classify -> write_trial
    -> compute_run_summary -> finalize_run -> render reports -> save_baseline / compare_to_baseline
  -> status completed | cancelled | error
```

One failing trial never aborts the suite; cancellation is checked between trials; baseline/regression is best-effort advisory on top of persisted results.

## Config keys (`benchmark.*`)

| Key | Default | Effect |
|---|---|---|
| `benchmark.output_dir` | `reports/benchmarks` | Storage root for suite run trees |
| `benchmark.trials` | `3` | Repeated trials per scenario when `--trials` is omitted (API clamps 1–20) |
| `benchmark.timeout_seconds` | `1800` | Per-trial mission budget default |
| `benchmark.sandbox_required` | `true` | No host-execution fallback; required-but-disabled marks every trial `INFRASTRUCTURE_ERROR`/`SANDBOX_FAILED` |
| `benchmark.baseline_path` | `reports/benchmarks/baseline.json` | `--save-baseline` / `--check-regression` target |
| `benchmark.regression.success_rate_tolerance` | `0.02` | Hard gate on verified-success-rate drop |
| `benchmark.regression.false_positive_tolerance` | `0.01` | Hard gate on false-positive-rate rise |
| `benchmark.regression.median_time_tolerance` | `0.2` | Warning gate on relative median-solve-time rise |
| `benchmark.regression.tool_actions_tolerance` | `0.3` | Warning gate on relative tool-action rise |
| `benchmark.regression.cost_tolerance` | `0.3` | Warning gate on relative cost rise |
| `benchmark.telemetry.events` / `token_usage` / `cost` | `true` | Event stream, token accounting, cost estimation |

Adjacent keys the runner reads: `sandbox.enabled`, `sandbox.image`, `sandbox.network.map_host_loopback`, `models.default_alias`, `mcp.http_port`, `api.max_concurrent_runs`.

## Examples

```bash
python main.py --benchmark xben
python main.py --benchmark xben --scenario xben-dvwa --trials 5
python main.py --benchmark xben --tag web
python main.py --benchmark-list
python main.py --benchmark xben --save-baseline
python main.py --benchmark xben --check-regression
docker compose -f eval_targets/docker-compose.yml up -d   # loopback lab before xben runs
```

```python
from tools.benchmark.registry import get_provider
provider = get_provider("xben")
scenarios = provider.load_scenarios(tags=["web"])
```

Implementation note: the WebUI Benchmarks nav, run panel, history charts, and comparison view described in the concept doc were not re-verified against route code here; treat the concept doc as canonical for UI behavior.

## Related documentation

- [Benchmarks concept](../../../benchmarks.md)
- [Campaign overview](../campaign/overview.md)
- [Kernel overview](../kernel/overview.md)
- [Swarm overview](../swarm/overview.md)
- [Recon overview](../recon/overview.md)

## Source map

- `tools/benchmark/runner.py`
- `tools/benchmark/service.py`
- `tools/benchmark/registry.py`
- `tools/benchmark/storage.py`
- `tools/benchmark/models.py`
- `tools/benchmark/xben/adapter.py`
- `tools/benchmark/xben/manifest.py`
- `tools/benchmark/targets.py`
- `tools/benchmark/agent_runner.py`
- `tools/benchmark/verifier.py`
- `tools/benchmark/metrics.py`
- `tools/benchmark/regression.py`
- `tools/benchmark/replay.py`
- `tools/benchmark/report.py`
- `tools/benchmark/events.py`
- `tools/benchmark/envinfo.py`
- `tools/benchmark_cli.py`
- `benchmarks/xben/`
- `docs/benchmarks.md`
- `config.yaml`
