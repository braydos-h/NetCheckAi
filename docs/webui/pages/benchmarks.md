---
title: Benchmarks Pages — Suites, New Run, History, Run Detail
sources:
  - webui/src/App.tsx
  - webui/src/routes/BenchmarksPage.tsx
  - webui/src/routes/BenchmarksStartPage.tsx
  - webui/src/routes/BenchmarksHistoryPage.tsx
  - webui/src/routes/BenchmarkRunPage.tsx
  - webui/src/features/benchmarks/api.ts
  - webui/src/features/benchmarks/useBenchmarksOverview.ts
  - webui/src/features/benchmarks/BenchmarksShell.tsx
  - webui/src/features/benchmarks/RunBenchmarkPanel.tsx
  - webui/src/features/benchmarks/format.ts
tests:
  - webui/src/features/benchmarks/__tests__/RunBenchmarkPanel.test.tsx
subsystem: webui
---

# Benchmarks (`/benchmarks`, `/benchmarks/new`, `/benchmarks/history`, `/benchmarks/:runId`)

Oracle-verified benchmark suites: sandboxed exploitation missions run against lab targets, one trial per scenario, with an independent oracle verifying captured flags afterwards. Ground truth comes from the oracle, never from agent claims (`BenchmarksShell` header). Four routes (`App.tsx:65-68`), one shared shell, one shared overview query.

## Shell and shared overview

`BenchmarksShell` (`features/benchmarks/BenchmarksShell.tsx:16`) wraps all four pages: `FlaskConical` title, sub-page nav, and a live-run pill linking to `/benchmarks/<run_id>` whenever a run is active.

| Nav item | Route |
|----------|-------|
| Overview | `/benchmarks` (`end: true`) |
| New run | `/benchmarks/new` (`end: true`) |
| Past benchmarks | `/benchmarks/history` (`end: true`) |

`useBenchmarksOverview` (`features/benchmarks/useBenchmarksOverview.ts:13`) is the single cached query (`["benchmarks", "overview"]`, `fetchOverview`, `staleTime: 15_000`, `gcTime: 5 * 60_000`) shared by the shell and all sub-pages. It polls every 3 s (`REFRESH_MS = 3000`) only while `isActiveState(active.state)`:

```tsx
refetchInterval: (query) => {
  const active = query.state.data?.active;
  return active && isActiveState(active.state) ? REFRESH_MS : false;
},
```

It derives `active` (default `{ run_id: null, state: "idle", error: "" }`) and `activeBusy` (`!!active.run_id && isActiveState(...)`), and invalidates `["benchmarks"]` once on the active-to-terminal transition so history picks up the run's index entry.

## API calls

All accessors live in `features/benchmarks/api.ts` (paths already prefixed with `/api/v1`; `fetchRuns`/`fetchRunEvents`/`compareRuns` build query strings with `URLSearchParams`).

| Function (`api.ts`) | Method / URL |
|---------------------|--------------|
| `fetchOverview` | `GET /api/v1/benchmarks` → `{ suites, runs, active, baseline }` |
| `fetchSuiteScenarios(suite)` | `GET /api/v1/benchmarks/suites/<suite>/scenarios` → `{ suite, scenarios }` |
| `fetchSuiteReadiness(suite)` | `GET /api/v1/benchmarks/suites/<suite>/readiness` → `SuiteReadiness` |
| `fetchRuns(suite?, limit = 50)` | `GET /api/v1/benchmarks/runs?suite=&limit=` → `{ runs }` |
| `fetchRun(runId, signal?)` | `GET /api/v1/benchmarks/runs/<runId>` → `RunDetail` |
| `fetchRunScenarios(runId, signal?)` | `GET /api/v1/benchmarks/runs/<runId>/scenarios` → `{ run_id, scenarios: Trial[] }` |
| `fetchRunEvents(runId, { after, trialId, limit = 1000, signal })` | `GET /api/v1/benchmarks/runs/<runId>/events?after=&trial_id=&limit=` → `{ run_id, events, latest_sequence, has_more? }` |
| `startBenchmarkRun(req)` | `POST /api/v1/benchmarks/run` → `{ run_id, state }` |
| `cancelBenchmarkRun(runId)` | `POST /api/v1/benchmarks/runs/<runId>/cancel` → `{ run_id, cancelled }` |
| `saveBaseline(runId)` | `POST /api/v1/benchmarks/baseline` body `{ run_id }` → `{ saved, path, run_id }` |
| `compareRuns(runA, runB)` | `GET /api/v1/benchmarks/compare?run_a=&run_b=` → `RunComparison` |

`fetchRunScenarios` is the only per-trial source during a live run: `run.json`'s `trials` array is persisted at finalize, while the runner writes each `trial_<n>.json` the moment that trial ends (`api.ts:46-51`).

## Overview (`BenchmarksPage.tsx`)

Live-run status, regression baseline, latest completed run, and a 5-row recent-runs preview. Data: `useBenchmarksOverview()` plus two derived queries — `["benchmarks", "latest-run", latestRunId]` (`fetchRun`, `staleTime: 30_000`) where `latestRunId` is the first `status === "completed"` row of the overview, and `["benchmarks", "latest-run-events", run_id]` (`fetchRunEvents(runId, { limit: 400 })`, `staleTime: 10_000`).

Sections in order:

- Error banner (`data-testid="benchmark-error-banner"`) when `active.state === "error"` — surfaces the service's error string instead of idling silently.
- Live banner (`data-testid="benchmark-live-banner"`) when `activeBusy && active.run_id` — links to `/benchmarks/<run_id>`, notes "live updates every 3s · events streaming".
- Regression baseline card (`data-testid="benchmark-baseline"`) when `overview.data.baseline.exists` — run-id link (or `path`), `formatPct` success/FP, `formatDuration` median, `formatCost` cost.
- Latest run — `MetricCards` for the `RunSummary`, plus a two-column grid: `BenchmarkTimeline` (`events`, `maxEvents={12}`) and `ScenarioResultsTable` (`trials`). Empty state (`data-testid="benchmarks-empty-state"`) links to `/benchmarks/new`.
- Recent runs preview — last 5 overview rows (`Run | Status | Verified | When`), full history under `/benchmarks/history`.

## New run (`BenchmarksStartPage.tsx` + `RunBenchmarkPanel.tsx`)

`BenchmarksStartPage` renders `RunBenchmarkPanel` (`suites`, `active`, `defaultModel` from `useDefaultModel`) plus two explainer cards: "What a run does" (lab targets, one trial per scenario, oracle verification with claimed-but-unverified outcomes recorded as false positives, results under the benchmark report directory and `/benchmarks/history`) and "Regression baseline" (`data-testid="start-baseline-card"`, same metrics as the overview card; empty text points at the detail page's "Save baseline" button).

`RunBenchmarkPanel` (`features/benchmarks/RunBenchmarkPanel.tsx:29`) selection semantics mirror the backend runner exactly:

- Suite select → `fetchSuiteScenarios(suite)` fills the scenario checklist; empty selection runs the whole suite. Tag chips are view filters for the checklist only and are never sent to the API.
- Trials per scenario (`Input type="number"`, clamped 1–20), model alias select (provider-aware `useModelOptions`, empty = server default), `Sandbox required` (default true, no host-execution fallback), `Save as baseline`, `Check regression vs baseline`.
- Lab-target readiness: `fetchSuiteReadiness(suite)` is best-effort; when `readiness.ready` is false and unreachable non-self-provisioned targets exist, a `data-testid="benchmark-lab-warning"` banner shows `readiness.lab_command`. A probe failure never blocks starting a run.
- `startRun` mutation posts `{ suite, scenarios: [...selectedScenarios], trials, model: model || undefined, sandbox_required, save_baseline, check_regression }`, invalidates `["benchmarks"]`, and navigates to `/benchmarks/<run_id>` (`data-testid="run-benchmark-button"`, disabled while `busy || !suite || isPending`). While `busy` (`isActiveState(active.state)`) all inputs are disabled.

## History (`BenchmarksHistoryPage.tsx`)

`REFRESH_MS = 3000`. `runsExtended` (`["benchmarks", "runs", 100]`, `fetchRuns(undefined, 100)`, `enabled: !!overview.data`, `keepPreviousData`, `staleTime: 15_000`) loads 100 rows in parallel with the overview and polls every 3 s only while the run is active; `historyRows` falls back to the overview's rows until it lands.

- Run history card — `HistoryCharts` plus a `Run | Suite | Status | Verified (solved/trials_total + formatPct) | FP | Median time | Cost` table, each run id linking to `/benchmarks/<run_id>`. Empty state links to `/benchmarks/new`.
- Compare runs card — `ComparisonView` fed with `{ run_id, suite, timestamp, status }` per row; shows metric deltas and per-scenario changes for any two runs.

## Run detail (`BenchmarkRunPage.tsx`)

Tabbed like the normal run page. Four polling queries plus two mutations, all keyed per `runId` from `useParams` (tab and trial filter reset on `runId` change):

| Query | Key | Polling |
|-------|-----|---------|
| `run` | `["benchmarks", "run", runId]` | `staleTime: 5_000`, `gcTime: 5 * 60_000`; refetch every 2 s while `isRunActive(data.status)` — terminal status is the only stop signal (`REFRESH_MS = 2000`) |
| `overview` | `["benchmarks", "overview"]` | refetch every 2 s while this run is the active one or its own status is active |
| `events` | `["benchmarks", "run-events", runId]` | `staleTime: 2_000`, `retry: false`; incremental `after` cursor once any page is cached, else up-to-5-page backfill (`limit: 1000`); `mergeEvents` dedups by `sequence`, sorts ascending, caps at `MAX_CACHED_EVENTS = 2000`; polls every 2 s while `live` |
| `runScenarios` | `["benchmarks", "run-scenarios", runId]` | enabled only while the run is active; `staleTime: 2_000`, `retry: false`, polls every 2 s while `live` |

Liveness: `live = !!runId && !orphaned && (!runStatus || isRunActive(runStatus)) && !overviewVeto`, where `overviewVeto` applies only when the overview has settled and names a different active run. `orphaned = isOrphanedRun(...)` (status still "running" but no runner owns it, e.g. daemon restart) renders an `INTERRUPTED` header badge and a `data-testid="benchmark-interrupted-banner"` card; the run cannot be resumed or cancelled.

Trials merge: `displayTrials` unions live `runScenarios` rows with stored `run.data.trials` by `trial_id` (stored wins); `normalizeTrial` fills gaps so tabs never throw on a slimmer payload. `activeTrial` is the newest unfinished trial; when the in-progress trial has no row yet, `liveHint` (latest event's `trial_id`/`scenario_id`) drives the live strip and `derivePhases` (`Provision | Exploit | Verify`, each `done | running | pending`). Progress denominator is the frozen `summary.trials_total` (then `config.trials × scenarios`), never the growing live count. `elapsedSec` is the max `elapsed_seconds` across events.

Mutations: `cancelBenchmarkRun` (destructive `Cancel` button while active, toasts and invalidates run/events/scenarios/overview) and `saveBaseline` (`Save baseline` button once a `summary` exists).

Banners and tabs:

- `benchmark-infra-banner` — completed run with `TARGET_PROVISION_FAILED` trials: lab was down, shows `docker compose -f eval_targets/docker-compose.yml up -d` plus the trial's `failure_detail`.
- `benchmark-sandbox-banner` — completed run with `SANDBOX_FAILED` trials: sandbox required but unreachable, no host-execution fallback.
- Tabs `Overview | Trials | Timeline | Evidence | Config` (`BarChart3`, `FlaskConical`, `ScrollText`, `FileSearch`, `Settings2` icons). Overview shows `MetricCards`, failure-category `Badge`s (`FALSE_POSITIVE` destructive), and a median/mean/tokens/cost summary grid. Timeline has a per-trial select filter and `BenchmarkTimeline maxEvents={400}`. Evidence lists per-trial oracle flags (`flag_id: passed/failed`), claimed summary, failure detail, and `audit_path`/`workspace`/`evidence_refs`. Config shows suite/trials/timeout/scenarios/tags/sandbox flag plus the `replay_manifest.replay_command` and the environment reproducibility pins (`git_sha` + dirty flag, `model_provider/model_id/model_alias`, `model_version`, `config_hash`, `sandbox_image @ digest`, platform + Python version).
- Aside: Run telemetry tiles (Trials `completed/total`, Events + elapsed, Tokens + cost, Verified + rate; plus False positives, Infra errors, Sandbox blocks once summarized) and a Replay card with the replay command and a back link to `/benchmarks`.

Formatting helpers (`features/benchmarks/format.ts`): `formatDuration`, `formatCost`, `formatPct(value, digits = 1)`, `isActiveState`, `runStatusToBadge`, `isOrphanedRun`.

## Related documentation

- [Run page](run.md)
- [Settings page](settings.md)
- [Other pages](other.md)

## Source map

- `webui/src/App.tsx`
- `webui/src/routes/BenchmarksPage.tsx`
- `webui/src/routes/BenchmarksStartPage.tsx`
- `webui/src/routes/BenchmarksHistoryPage.tsx`
- `webui/src/routes/BenchmarkRunPage.tsx`
- `webui/src/features/benchmarks/api.ts`
- `webui/src/features/benchmarks/useBenchmarksOverview.ts`
- `webui/src/features/benchmarks/BenchmarksShell.tsx`
- `webui/src/features/benchmarks/RunBenchmarkPanel.tsx`
- `webui/src/features/benchmarks/format.ts`
