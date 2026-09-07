---
title: Benchmarks Endpoints — Overview, Suites, Scenarios, Readiness, Runs, Events, SSE Stream, Baseline, Compare
sources:
  - tools/api/routes/benchmarks.py
  - tools/benchmark/service.py
  - tools/benchmark/storage.py
  - tools/benchmark/events.py
  - tools/benchmark/regression.py
  - tools/benchmark/registry.py
  - tools/benchmark/targets.py
tests:
  - tests/test_benchmark_api.py
subsystem: api
---

# Benchmarks Endpoints

`tools/api/routes/benchmarks.py:1` — `APIRouter(prefix="/api/v1/benchmarks", tags=["benchmarks"])`. Built by `create_router(auth, service, storage, config)` (`benchmarks.py:55`) and wired unconditionally in `app.py:169` / `app.py:183`. Handlers are thin transport adapters — all business logic lives in `tools/benchmark/` (runner / service / storage / regression).

Shared conventions: every route requires bearer via `_require_auth` (`benchmarks.py:65`, `Authorization: Bearer <token>` header — never a query param). Run ids are globally unique and resolved across suites by `_resolve_run` (`benchmarks.py:74`); unknown `run_id` is `404 {"detail":"Benchmark run not found"}`. Suite discovery is served from a per-router 15 s TTL cache (`_suite_cache`, `benchmarks.py:62`). Storage root defaults to `reports/benchmarks` (`tools/benchmark/storage.py:64`, `tools/benchmark/service.py:29`).

Request model `BenchmarkRunRequest` (`benchmarks.py:33`):

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `suite` | `str` | required | suite id (e.g. `xben`) |
| `scenarios` | `str[]` | `[]` | restrict to scenario ids |
| `tags` | `str[]` | `[]` | restrict to tagged scenarios |
| `trials` | `int\|null` | `null` (→ config `benchmark.trials`, default 1) | `1..20` |
| `model` | `str` | `""` | alias override, recorded never substituted |
| `reasoning` | `str` | `""` | reasoning profile label |
| `sandbox_required` | `bool\|null` | `null` (→ config default, true) | require the sandbox |
| `timeout_seconds` | `int\|null` | `null` (→ config default 1800) | `≥30`, per-trial mission timeout |
| `save_baseline` | `bool` | `false` | persist this run as regression baseline |
| `check_regression` | `bool` | `false` | compare against saved baseline |

Stored event shape (`tools/benchmark/events.py:76`): `{sequence, timestamp, elapsed_seconds, run_id, type, level, trial_id, scenario_id, agent, tool, target, payload}` (secrets redacted, long outputs truncated). Live fanout adds `run_end {type, run_id, summary}` and `run_error {type, run_id, error}` (`tools/benchmark/service.py:164`, `:170`).

## `GET /api/v1/benchmarks` — `benchmarks_overview`

- Purpose: one-call dashboard — registered suites, 20 most recent runs, active-run status, baseline meta.
- Authentication: bearer (`_require_auth`).
- Params/body: none.
- Status codes: `200` with `{suites:[SuiteInfo], runs:[RunIndexRow][:20], active:{run_id, state, error, last_run_id}, baseline:BaselineMeta}`; `401` missing/invalid token.
- Error conditions: none beyond auth (storage misses surface as empty lists, missing baseline as `{exists:false}`).
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  http://127.0.0.1:8765/api/v1/benchmarks
```

- Example response:

```json
{
  "suites": [{ "suite_id": "xben", "scenarios": 12 }],
  "runs": [{ "run_id": "20260907_120000", "suite": "xben", "status": "completed" }],
  "active": { "run_id": null, "state": "idle", "error": "", "last_run_id": "20260907_120000" },
  "baseline": { "exists": true, "path": "reports/benchmarks/baseline.json", "run_id": "20260907_120000" }
}
```

- Related events: none directly; `active` mirrors the `run_end` / `run_error` fanout state.
- WebUI usage: `fetchOverview()` (`webui/src/features/benchmarks/api.ts:18`) via `useBenchmarksOverview()` (`webui/src/features/benchmarks/useBenchmarksOverview.ts:13`, query key `["benchmarks","overview"]`) — serves `BenchmarksShell`, `BenchmarksPage`, `BenchmarkRunPage`.
- Source file: `tools/api/routes/benchmarks.py:117`.

## `GET /api/v1/benchmarks/suites` — `list_suites_route`

- Purpose: list registered benchmark suites (TTL-cached discovery).
- Authentication: bearer.
- Params/body: none.
- Status codes: `200 {suites:[SuiteInfo]}` (`{suite_id, scenarios, invalid_manifests?, manifest_dir?, tags?}`); `401`.
- Error conditions: none beyond auth.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  http://127.0.0.1:8765/api/v1/benchmarks/suites
```

- Example response:

```json
{ "suites": [{ "suite_id": "xben", "scenarios": 12, "tags": { "web": 5 } }] }
```

- Related events: none.
- WebUI usage: no dedicated accessor in `webui/src/features/benchmarks/api.ts` — the overview query (`fetchOverview` / `useBenchmarksOverview`) already carries `suites`; direct `fetch` possible.
- Source file: `tools/api/routes/benchmarks.py:129`.

## `GET /api/v1/benchmarks/suites/{suite_id}/scenarios` — `list_scenarios_route`

- Purpose: list a suite's scenario manifests.
- Authentication: bearer.
- Params/body: path `suite_id: str`. No query/body.
- Status codes: `200 {suite, scenarios:[ScenarioInfo]}`; `404` unknown suite (detail from registry `KeyError`); `401`.
- Error conditions: `404` when `get_provider(suite_id)` raises.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  http://127.0.0.1:8765/api/v1/benchmarks/suites/xben/scenarios
```

- Example response:

```json
{
  "suite": "xben",
  "scenarios": [
    {
      "scenario_id": "sqli-01", "name": "SQLi login bypass",
      "target_type": "docker", "target_image": "xben/sqli:1",
      "target_host": "", "target_ports": [], "tags": ["web"], "difficulty": "easy"
    }
  ]
}
```

- Related events: none.
- WebUI usage: `fetchSuiteScenarios()` (`webui/src/features/benchmarks/api.ts:27`) from `RunBenchmarkPanel.tsx:75` (scenario picker).
- Source file: `tools/api/routes/benchmarks.py:133`.

## `GET /api/v1/benchmarks/suites/{suite_id}/readiness` — `suite_readiness_route`

- Purpose: lab-target preflight before pressing Run — TCP-probe host-type targets on declared ports (same probe the runner uses to fail fast); a run started while `ready` is false finishes instantly with `INFRASTRUCTURE_ERROR/TARGET_PROVISION_FAILED`.
- Authentication: bearer.
- Params/body: path `suite_id: str`. No query/body.
- Status codes: `200 {suite, ready, lab_command, targets:[{scenario_id, target_type, target_host, target_ports, reachable, self_provisioned, detail}]}`; `404` unknown suite; `401`.
- Error conditions: `404` when `get_provider(suite_id)` raises. Probe budget: per-host timeout 0.5 s (`target_ports_reachable`), whole-suite budget 15 s — on timeout unprobed targets stay `reachable:false`.
- Reachability rules (`benchmarks.py:170`): docker + `target_image` → `reachable:true, self_provisioned:true` (runner provisions per trial); docker without image → `reachable:false`; host-type with no ports → `reachable:true`; host-type with ports → live TCP probe. `ready = bool(targets) and all(reachable)`.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  http://127.0.0.1:8765/api/v1/benchmarks/suites/xben/readiness
```

- Example response:

```json
{
  "suite": "xben",
  "ready": false,
  "lab_command": "docker compose -f eval_targets/docker-compose.yml up -d",
  "targets": [
    {
      "scenario_id": "smb-01", "target_type": "host",
      "target_host": "10.0.0.50", "target_ports": [445],
      "reachable": false, "self_provisioned": false,
      "detail": "lab target refused all declared ports"
    }
  ]
}
```

- Related events: none (preflight only).
- WebUI usage: `fetchSuiteReadiness()` (`webui/src/features/benchmarks/api.ts:31`) from `RunBenchmarkPanel.tsx:104` (lab warning).
- Source file: `tools/api/routes/benchmarks.py:146`.

## `GET /api/v1/benchmarks/runs` — `list_runs`

- Purpose: run index, optionally filtered by suite.
- Authentication: bearer.
- Params/body: query `suite: str|None` (default `None` = all suites), `limit: int 1..200` default `50`. No body.
- Status codes: `200 {runs:[RunIndexRow]}` (each `{run_id, suite, status, timestamp, trials_total, solved, verified_success_rate, false_positive_rate, median_solve_time, estimated_cost, total_tokens}`); `401`; `422` on query validation failure.
- Error conditions: `limit` outside `1..200` → `422`.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  "http://127.0.0.1:8765/api/v1/benchmarks/runs?suite=xben&limit=5"
```

- Example response:

```json
{
  "runs": [
    {
      "run_id": "20260907_120000", "suite": "xben", "status": "completed",
      "timestamp": "2026-09-07T12:00:00+00:00", "trials_total": 12,
      "solved": 9, "verified_success_rate": 0.75, "false_positive_rate": 0.0,
      "median_solve_time": 41.2, "estimated_cost": null, "total_tokens": 182044
    }
  ]
}
```

- Related events: none directly.
- WebUI usage: `fetchRuns()` (`webui/src/features/benchmarks/api.ts:35`) from `BenchmarksHistoryPage` (query key `["benchmarks","runs",100]`).
- Source file: `tools/api/routes/benchmarks.py:251`.

## `GET /api/v1/benchmarks/runs/{run_id}` — `get_run`

- Purpose: full run detail plus summary (summary is `null` while running).
- Authentication: bearer.
- Params/body: path `run_id: str`. No query/body.
- Status codes: `200 RunDetail {run_id, suite, status, config, environment, scenario_ids, trials, replay_manifest?, summary}`; `404` run not found; `401`.
- Error conditions: `404` when no suite's store has the id.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  http://127.0.0.1:8765/api/v1/benchmarks/runs/20260907_120000
```

- Example response (trimmed):

```json
{
  "run_id": "20260907_120000",
  "suite": "xben",
  "status": "completed",
  "config": { "suite": "xben", "trials": 1, "timeout_seconds": 1800, "sandbox_required": true },
  "scenario_ids": ["sqli-01"],
  "trials": [],
  "summary": { "run_id": "20260907_120000", "trials_total": 1, "verified_success_rate": 1.0 }
}
```

- Related events: terminal `run_end` / `run_error` fanout marks the run complete; poll this for the persisted `summary`.
- WebUI usage: `fetchRun()` (`webui/src/features/benchmarks/api.ts:42`) from `BenchmarkRunPage` (query key `["benchmarks","run",runId]`).
- Source file: `tools/api/routes/benchmarks.py:258`.

## `GET /api/v1/benchmarks/runs/{run_id}/scenarios` — `get_run_scenarios`

- Purpose: per-scenario trial results. Unlike `GET .../runs/{id}` (whose `trials` array is only persisted at finalize), the runner writes each `trial_<n>.json` the moment that trial ends — during a live run this is the only endpoint that reflects completed trials.
- Authentication: bearer.
- Params/body: path `run_id: str`. No query/body.
- Status codes: `200 {run_id, scenarios:[Trial]}` (each `Trial` per `webui/src/features/benchmarks/types.ts:95`); `404` run not found; `401`.
- Error conditions: unreadable/corrupt `trial_*.json` files are skipped, not errors; `*_events.jsonl` files excluded; empty `{scenarios:[]}` when the `scenarios/` dir does not exist yet.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  http://127.0.0.1:8765/api/v1/benchmarks/runs/20260907_120000/scenarios
```

- Example response (trimmed):

```json
{
  "run_id": "20260907_120000",
  "scenarios": [
    {
      "suite": "xben", "scenario_id": "sqli-01", "trial_index": 0,
      "status": "VERIFIED", "oracle_verified_success": true, "false_positive": false,
      "failure_category": "UNKNOWN", "flags_captured": 1, "flags_total": 1
    }
  ]
}
```

- Related events: none directly; trial completion is what makes new entries appear here.
- WebUI usage: `fetchRunScenarios()` (`webui/src/features/benchmarks/api.ts:52`) from `BenchmarkRunPage` (query key `["benchmarks","run-scenarios",runId]`).
- Source file: `tools/api/routes/benchmarks.py:264`.

## `GET /api/v1/benchmarks/runs/{run_id}/events` — `get_run_events`

- Purpose: paginated replay of the stored `events.jsonl` stream, optionally per trial.
- Authentication: bearer.
- Params/body:

| Param | Type | Default | Constraint |
|-------|------|---------|------------|
| `after` | int | `0` | `≥0` (exclusive — only `sequence > after`) |
| `trial_id` | str | `""` | exact match filter, empty = all |
| `limit` | int | `1000` | `1..5000` |

- Status codes: `200 {run_id, events:[BenchmarkEvent], latest_sequence, has_more}` (`has_more = len(events)==limit`); `404` run not found; `401`; `422` on validation failure.
- Error conditions: missing `events.jsonl` → `200` with `events:[]` (storage returns `[]`, `tools/benchmark/storage.py:269`); corrupt lines skipped.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  "http://127.0.0.1:8765/api/v1/benchmarks/runs/20260907_120000/events?after=0&limit=10"
```

- Example response:

```json
{
  "run_id": "20260907_120000",
  "events": [
    {
      "sequence": 1, "timestamp": "2026-09-07T12:00:01+00:00", "elapsed_seconds": 0.42,
      "run_id": "20260907_120000", "type": "trial_start", "level": "info",
      "trial_id": "sqli-01_t0", "scenario_id": "sqli-01",
      "agent": "", "tool": "", "target": "", "payload": {}
    }
  ],
  "latest_sequence": 1,
  "has_more": false
}
```

- Related events: returns the stored benchmark event stream (`sequence`, `type`, `trial_id`, `scenario_id`, `payload`); terminal entries are `run_end` / `run_error`.
- WebUI usage: `fetchRunEvents()` (`webui/src/features/benchmarks/api.ts:59`) polled from `BenchmarkRunPage` (query key `["benchmarks","run-events",runId]`) and `BenchmarksPage` latest-run events; no `EventSource` on this family — polling only.
- Source file: `tools/api/routes/benchmarks.py:292`.

## `GET /api/v1/benchmarks/runs/{run_id}/events/stream` — `stream_run_events`

- Purpose: SSE stream — replays stored events from `after`, then streams live fanout until `run_end` / `run_error` or ~60 s idle.
- Authentication: bearer via `Authorization` header (same dependency as every other route; token is never accepted in query — browsers' native `EventSource` cannot set headers, which is why the WebUI polls instead).
- Params/body: query `after: int ≥0` default `0`. No body.
- Status codes: `200 StreamingResponse text/event-stream` with headers `Cache-Control:no-cache`, `Connection:keep-alive`, `X-Accel-Buffering:no`; `404` run not found; `401`.
- Error conditions: `404` before streaming starts (unknown id); mid-stream the generator replays in 500-event pages via `asyncio.to_thread`, emits `: heartbeat` comments on 1 s queue timeouts, filters global fanout to this `run_id`, closes after ~60 consecutive idle seconds so the client can re-poll, and breaks on `run_end` / `run_error` for this run.
- Example request:

```bash
curl -N -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  "http://127.0.0.1:8765/api/v1/benchmarks/runs/20260907_120000/events/stream?after=0"
```

- Example response (SSE frames):

```json
{ "sse": "data: {\"sequence\":1,\"run_id\":\"20260907_120000\",\"type\":\"trial_start\",\"payload\":{}}",
  "heartbeat": ": heartbeat",
  "close": "server closes on run_end/run_error or ~60 s idle" }
```

- Related events: streams the full stored + live benchmark event sequence, ending with `run_end {type, run_id, summary}` or `run_error {type, run_id, error}`.
- WebUI usage: none — polling via `fetchRunEvents` is used instead (`webui/src/features/benchmarks/api.ts` has no stream accessor; `webui/src/api/sse.ts` fallback targets the runs family stream only).
- Source file: `tools/api/routes/benchmarks.py:310`.

## `POST /api/v1/benchmarks/run` — `start_run`

- Purpose: start a benchmark run (at most one active at a time, sharing the `api.max_concurrent_runs` cap with agent runs).
- Authentication: bearer.
- Params/body: JSON `BenchmarkRunRequest` (table at top; only `suite` required).
- Status codes: `200 {run_id, state}` (`state` starts as `starting`, then `running`); `409` on any service refusal — `suite is required` (`missing_suite`), unknown suite (`unknown_suite`), `no scenarios matched the given filters` (`no_match`), `trials must be between 1 and 20` (`bad_trials`), `a benchmark run is already active`, `<cap> run(s) already active...` (concurrency cap); `401`; `422` on body validation (`suite` missing, `trials` outside `1..20`, `timeout_seconds < 30`).
- Error conditions: filters matching zero scenarios → `409 no_match`; second start while active → `409`; run id is minted inside the task — the route waits briefly so callers can address it immediately.
- Example request:

```bash
curl -X POST -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"suite":"xben","trials":1,"save_baseline":false}' \
  http://127.0.0.1:8765/api/v1/benchmarks/run
```

- Example response:

```json
{ "run_id": "20260907_120305", "state": "starting" }
```

- Related events: the new run begins emitting progress events immediately (visible via events/stream); completion fans out `run_end` / `run_error`.
- WebUI usage: `startBenchmarkRun()` (`webui/src/features/benchmarks/api.ts:72`) from `RunBenchmarkPanel.tsx:140` (includes the `save_baseline` checkbox state).
- Source file: `tools/api/routes/benchmarks.py:367`.

## `POST /api/v1/benchmarks/runs/{run_id}/cancel` — `cancel_run`

- Purpose: cancel the active benchmark run (only the active run can be cancelled).
- Authentication: bearer.
- Params/body: path `run_id: str`. No body.
- Status codes: `200 {run_id, cancelled:bool}`; `404` when `svc.active_run_id != run_id` (`"Run is not active (only the active run can be cancelled)"`); `401`.
- Error conditions: finished/unknown id → `404` (even if the id exists in history but is not active).
- Example request:

```bash
curl -X POST -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  http://127.0.0.1:8765/api/v1/benchmarks/runs/20260907_120305/cancel
```

- Example response:

```json
{ "run_id": "20260907_120305", "cancelled": true }
```

- Related events: cancellation drives the run to `cancelled` state; no `run_end` summary fanout.
- WebUI usage: `cancelBenchmarkRun()` (`webui/src/features/benchmarks/api.ts:76`); run pages invalidate `["benchmarks","run",runId]`, `run-events`, `run-scenarios`, and `overview` after run mutations (`webui/src/routes/BenchmarkRunPage.tsx:284`).
- Source file: `tools/api/routes/benchmarks.py:374`.

## `GET /api/v1/benchmarks/baseline` — `get_baseline`

- Purpose: read the regression baseline meta (missing baseline is a `200`, not a `404`).
- Authentication: bearer.
- Params/body: none. Path resolution (`benchmarks.py:97`): config `benchmark.baseline_path` when set (relative paths resolve against the storage root), else `<storage.root>/baseline.json` (`DEFAULT_BASELINE_PATH` is `reports/benchmarks/baseline.json`, `tools/benchmark/regression.py:40`).
- Status codes: `200 BaselineMeta` — `{exists:false, path}` when absent, else `{exists:true, path, run_id, suite, timestamp, trials_total, verified_success_rate, ...}`; `401`.
- Error conditions: none beyond auth.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  http://127.0.0.1:8765/api/v1/benchmarks/baseline
```

- Example response:

```json
{
  "exists": true,
  "path": "reports/benchmarks/baseline.json",
  "run_id": "20260907_120000",
  "suite": "xben",
  "verified_success_rate": 0.75
}
```

- Related events: none.
- WebUI usage: no dedicated accessor in `webui/src/features/benchmarks/api.ts` — baseline meta arrives via the overview query (`fetchOverview` / `useBenchmarksOverview`); direct `fetch` possible.
- Source file: `tools/api/routes/benchmarks.py:384`.

## `POST /api/v1/benchmarks/baseline` — `save_baseline_route`

- Purpose: persist a completed run's summary as the regression baseline.
- Authentication: bearer.
- Params/body: JSON `{run_id: str}` (required).
- Status codes: `200 {saved:true, path, run_id}`; `400` when `run_id` missing; `404` run not found; `409` when the run is still running (`"Run has no summary yet (still running)"`); `422` when finished without a summary (`"Run finished without a summary (failed or cancelled)"`) or the summary fails `run_summary_from_dict` validation (`"Run summary is invalid: ..."`); `401`.
- Error conditions: running, failed, or cancelled runs cannot become baselines — only completed runs with a valid summary.
- Example request:

```bash
curl -X POST -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"run_id":"20260907_120000"}' \
  http://127.0.0.1:8765/api/v1/benchmarks/baseline
```

- Example response:

```json
{ "saved": true, "path": "reports/benchmarks/baseline.json", "run_id": "20260907_120000" }
```

- Related events: none.
- WebUI usage: `saveBaseline()` (`webui/src/features/benchmarks/api.ts:80`); the start-time `save_baseline` flag is separate (`RunBenchmarkPanel.tsx:50`, sent on `POST /run`).
- Source file: `tools/api/routes/benchmarks.py:388`.

## `GET /api/v1/benchmarks/compare` — `compare_runs`

- Purpose: compare two completed runs (metric deltas + per-scenario categories).
- Authentication: bearer.
- Params/body: query `run_a: str` (required, baseline run id), `run_b: str` (required, candidate run id). No body.
- Status codes: `200 {run_a:{run_id, suite, summary}, run_b:{...}, comparison:{metrics, scenarios, categories}}` (`compare_summaries_payload`, `tools/benchmark/regression.py:369`); `400` when `run_a == run_b`; `404` either run not found; `409` when either summary is missing (`"Both runs must be completed (summaries required)"`); `401`.
- Error conditions: same id twice → `400`; running/failed runs (no summary) → `409`.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  "http://127.0.0.1:8765/api/v1/benchmarks/compare?run_a=20260907_120000&run_b=20260907_130000"
```

- Example response (trimmed):

```json
{
  "run_a": { "run_id": "20260907_120000", "suite": "xben", "summary": { "verified_success_rate": 0.75 } },
  "run_b": { "run_id": "20260907_130000", "suite": "xben", "summary": { "verified_success_rate": 0.83 } },
  "comparison": {
    "metrics": [{ "metric": "verified_success_rate", "baseline": 0.75, "current": 0.83, "delta": 0.08, "direction": "improved" }],
    "scenarios": [{ "scenario_id": "sqli-01", "baseline": 1.0, "current": 1.0, "delta": 0.0, "category": "still_solved" }],
    "categories": { "newly_solved": [], "regressed": [] }
  }
}
```

- Related events: none (reads persisted summaries only).
- WebUI usage: `compareRuns()` (`webui/src/features/benchmarks/api.ts:84`) from `ComparisonView.tsx:89`.
- Source file: `tools/api/routes/benchmarks.py:410`.

## Related documentation

- [Endpoint matrix](../endpoint-matrix.md) — method/route/handler table for every family
- [Runs endpoints](./runs.md) — format model for this page; agent-run lifecycle (shares the concurrency cap)
- [Events endpoints](./events.md) — replay/pagination/SSE conventions reused by the benchmark event stream
- [System endpoints](./system.md) — `PATCH /api/v1/config` owns the `benchmark.*` settings these routes read
- [Benchmarks guide](../../benchmarks.md) — suites, trials, regression workflow

## Source map

- `tools/api/routes/benchmarks.py` — all 14 handlers + `BenchmarkRunRequest` + baseline path resolution
- `tools/benchmark/service.py` — `BenchmarkService` (active-run ownership, `start_run` validation, `cancel`, `subscribe` fanout, `run_end`/`run_error`)
- `tools/benchmark/storage.py` — `BenchmarkStorage` (run dirs, index, summaries, `load_events`)
- `tools/benchmark/events.py` — `BenchmarkEventLogger` event shape + redaction/truncation
- `tools/benchmark/regression.py` — `DEFAULT_BASELINE_PATH`, `load_baseline`, `save_baseline`, `compare_summaries_payload`
- `tools/benchmark/registry.py` — suite/scenario providers behind discovery + readiness
- `tools/benchmark/targets.py` — `target_ports_reachable` probe used by readiness
- `tools/benchmark/metrics.py` — `run_summary_from_dict` validation for baseline saves
- `app.py` — unconditional router wiring
- `webui/src/features/benchmarks/api.ts` — `fetchOverview`, `fetchSuiteScenarios`, `fetchSuiteReadiness`, `fetchRuns`, `fetchRun`, `fetchRunScenarios`, `fetchRunEvents`, `startBenchmarkRun`, `cancelBenchmarkRun`, `saveBaseline`, `compareRuns`
- `webui/src/features/benchmarks/useBenchmarksOverview.ts` — shared overview query
- `webui/src/features/benchmarks/types.ts` — `Trial`, `RunSummary`, `SuiteReadiness`, `RunComparison` shapes
- `webui/src/features/benchmarks/RunBenchmarkPanel.tsx` — start form + readiness/scenario loading
- `webui/src/features/benchmarks/ComparisonView.tsx` — compare consumer
- `webui/src/routes/BenchmarkRunPage.tsx` — run detail / scenarios / events polling
- `webui/src/routes/BenchmarksHistoryPage.tsx` — run index consumer
