# Benchmarks

BreachPilot's benchmark suite turns evaluation into a first-class, reproducible
feature: benchmark targets run under the existing sandboxed execution
architecture, outcomes are verified by an **independent oracle**, and every
run records enough metadata to reproduce and defend the numbers.

> **Warning — authorized lab environments only.** Benchmark targets are
> deliberately vulnerable images. Operate them exclusively against
> infrastructure you own or are explicitly authorized to test, in an isolated
> lab. The same authorization rules as the rest of BreachPilot apply.

## Architecture

The benchmark subsystem lives in `tools/benchmark/` and separates concerns so
no god-file owns everything:

```
benchmark provider (XBEN is one; suites plug in via tools/benchmark/registry.py)
    -> scenarios (tools/benchmark/models.py::BenchmarkScenario)
        -> provision/reset target   (tools/benchmark/targets.py)
        -> create sandbox           (existing tools/sandbox; no host fallback)
        -> run BreachPilot mission  (tools/benchmark/agent_runner.py
                                     wrapping tools/exploit_session.run_exploit_session)
        -> independently verify     (tools/benchmark/verifier.py reusing
                                     tools/eval_checks executors + eval_harness flag semantics)
        -> collect metrics          (tools/benchmark/metrics.py)
        -> persist results          (tools/benchmark/storage.py)
        -> destroy/reset target
```

- **`models.py`** — typed dataclasses: scenarios, trials, run config/environment,
  summaries. `TrialStatus` distinguishes `VERIFIED` / `FAILED` /
  `FALSE_POSITIVE` / `TIMEOUT` / `INFRASTRUCTURE_ERROR`.
- **`registry.py`** — provider registry. XBEN (`tools/benchmark/xben/`) is one
  provider; future suites register their own provider and the runner never
  changes.
- **`targets.py`** — target lifecycle (docker run/restart/teardown) with a
  monkeypatchable subprocess seam. Provision failures raise
  `TargetProvisionError` → the trial is `INFRASTRUCTURE_ERROR`, never a fake
  exploitation failure.
- **`agent_runner.py`** — one attack mission per trial. Detects the agent's
  **claimed** success from structured tool-outcome counters, captures token /
  model-call telemetry from the shared `llm_usage.jsonl` delta, converts the
  audit trail into structured events, and extracts sandbox facts.
- **`verifier.py`** — the ONLY source of `oracle_verified_success`. Reuses the
  graded eval's declarative check executors (`tools/eval_checks.py`): HTTP
  login/request probes, `file_contains` (incl. `loot://`), and `shell_command`
  through a dedicated soft-fail MCP session. A missing session degrades shell
  checks to UNVERIFIED (fail-closed).
- **`runner.py`** — orchestrates trials: provision → mission → verify →
  classify → persist → teardown. Async-safe, cancellable, and one failing
  trial never aborts the suite.
- **`service.py`** — API-facing owner of the active run (lifecycle plumbing
  only).
- **`metrics.py` / `regression.py` / `report.py` / `storage.py` / `replay.py`**
  — aggregation + statistics, baselines and regression detection, public
  report rendering, persistence, and reproduction manifests.

## Verified success vs claimed success

This is the core contract:

- `agent_claimed_success` — what the agent thought (from structured tool-outcome
  counts, **not** LLM prose, exit codes, or tool output text).
- `oracle_verified_success` — what the independent verifier confirmed on the
  target.

A trial is **solved only when the oracle confirms**. When the agent claims
success and the oracle disagrees, the trial is a `FALSE_POSITIVE` — its own
status and failure category, surfaced prominently in reports and the WebUI.
The inverse (oracle verified, agent undersold) is recorded as
`false_negative` where determinable.

## Running benchmarks

```bash
# WebUI (default no-args launch), then click "Benchmarks"
python main.py

# CLI: run a suite
python main.py --benchmark xben

# Filters and repetition
python main.py --benchmark xben --scenario xben-dvwa --trials 5
python main.py --benchmark xben --tag web

# List registered suites and their scenarios
python main.py --benchmark-list

# Baselines / regression gates (exit 1 on hard regressions)
python main.py --benchmark xben --save-baseline
python main.py --benchmark xben --check-regression
```

The existing `--eval` / `--eval-list` commands are unchanged; the benchmark
CLI reuses the same config validation and baseline workflow.

### Target setup

Scenario definitions live in `benchmarks/<suite>/*.json` (XBEN-style
manifests: `benchmark_id`, name, target image/host/ports, goal, tags,
difficulty, reset strategy, timeout, and the oracle). The shipped `xben`
manifests target the repo's `eval_targets/docker-compose.yml` lab suite:

```bash
docker compose -f eval_targets/docker-compose.yml up -d   # loopback-only
python main.py --benchmark xben
```

> **Loopback-lab + sandbox prerequisite.** The shipped `xben` manifests target
> `127.0.0.1`, but a sandboxed worker's loopback is container-local
> (`sandbox.network.map_host_loopback:false`), so sandboxed exploit execution
> cannot reach the lab by construction. Loopback trials fail fast as
> `INFRASTRUCTURE_ERROR/SANDBOX_FAILED` instead of burning the mission budget.
> For the loopback lab, rerun with the explicit lab opt-out
> (`sandbox.enabled:false` + `benchmark.sandbox_required:false`), or set
> `sandbox.network.map_host_loopback:true` (dev-lab localhost only, never for
> production runs).

A manifest can also declare `target_type: "docker"` + `target_image`, in which
case the benchmark provisions one container per trial itself (reset strategy
`recreate` or `restart`).

## Reproducibility

Every run records a reproduction manifest inside `run.json`: git SHA + dirty
status, model provider/alias/id/version, reasoning config, temperature,
config hash, benchmark config hash, sandbox image + digest, per-scenario
target images, and timestamps. **Missing metadata is recorded as `unknown` —
never silently substituted** — so reproducibility claims stay honest.
`tools/benchmark/replay.py::check_reproducibility` compares a stored run
against the current environment field-by-field.

## Metrics

Aggregate summaries include verified success rate, false-positive rate,
median/mean solve time and tool actions, token totals, estimated cost,
time-to-first-verified-success, sandbox-blocked action counts, and failure
categories. With repeated trials (`--trials N`) each scenario gets a success
probability, variance/standard deviation, and a Wilson 95% confidence
interval. A single lucky trial never reads as reliable — with one trial the
CI spans most of the range.

## Failure classification

Unsuccessful trials are classified to answer "why does BreachPilot fail
here?": `TARGET_PROVISION_FAILED`, `SANDBOX_FAILED`, `MODEL_FAILED`,
`TIMEOUT`, `PLANNER_FAILURE`, `TOOL_FAILURE`, `VERIFICATION_FAILURE`,
`FALSE_POSITIVE`, `NO_EXPLOIT_PATH`, `AGENT_ABORTED`, `TARGET_RESET_FAILED`,
`UNKNOWN`. Infrastructure failures (provision, sandbox) are reported as
`INFRASTRUCTURE_ERROR` and excluded from success-rate denominators — they are
not exploitation failures.

## Storage layout

```
reports/benchmarks/<suite>/<run_id>/
    run.json            config + environment + replay manifest + trial list
    summary.json        aggregated metrics
    events.jsonl        structured mission events (whole run)
    report.md/.html     public report rendered FROM the JSON (JSON is canonical)
    scenarios/<id>/trial_<n>.json          per-trial result
    scenarios/<id>/trial_<n>_workspace/    the mission's exploit workspace
```

Writes are atomic; a killed run never leaves a half-written JSON.

## Sandbox behavior

All benchmark attack execution funnels through the existing sandbox
(`tools/sandbox/`). With `benchmark.sandbox_required: true` (the default), a
run without `sandbox.enabled` marks every trial
`INFRASTRUCTURE_ERROR/SANDBOX_FAILED` — **there is no host-execution
fallback**. Runs record sandbox enabled state, image + digest, container id,
network-policy fingerprint, authorized destinations, and blocked/failure
counts. `tools/sandbox/family_audit.py` is the enforceable registry of every
MCP tool family's containment status (sandboxed vs documented host exception);
`tests/test_sandbox_family_audit.py` fails when a new subprocess-using family
appears without a registry entry.

## WebUI

The **Benchmarks** nav item opens the dashboard: verified success rate, solved,
false-positive rate, median solve time, average cost and sandbox-violation
cards; the run panel (suite, scenarios, tags, trials, model, sandbox
requirement, baseline options); run history with charts; the comparison view
(two arbitrary runs, per-scenario newly-solved/regressed/still-solved/
still-failing); and run detail pages with a live progress view, structured
timeline, configuration/environment pins, scenario results table and evidence
links. Historical runs survive restarts (everything is on disk).

## CI usage

- **PR CI** runs the fully mocked benchmark test suite (fake suite, fake
  mission, fake verifier, fake docker seams) — no model API keys, no live
  targets, plus the deterministic `fake` suite smoke path
  (`.github/workflows/benchmark.yml`).
- **Live benchmarks** run only via explicit/manual or scheduled jobs with
  secrets and the lab target suite up. `--check-regression` exits non-zero on
  hard regressions so it can gate CI.
