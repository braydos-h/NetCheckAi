# Run logs

Each run writes three complementary logs under `reports/<run_id>/`, plus session summary files. They answer different questions: `run.log` captures everything printed and logged, `activity.jsonl` is the operator-facing audit trail, and `decision_log.jsonl` records compact AI decision events.

## Run directory layout

`reports/<run_id>/` holds the per-run artifacts written by `tools/run_service/execute.py` and the three log modules:

| File | Writer | Contents |
|---|---|---|
| `run.log` | `RunLog.attach(reports_dir)` (`tools/run_log.py`) | Tee of all console output plus every logging record in the process |
| `activity.jsonl` | `ActivityLog(reports_dir, ...)` (`tools/activity_log.py`) | Operator-facing audit trail, one JSON object per line |
| `decision_log.jsonl` | `log_decision(reports_dir, ...)` (`tools/decision_log.py`) | Compact decision events, one JSON object per line |
| `session_state.json` | `tools/run_service/execute.py` | `session_id` plus start timestamp, for `--resume` |
| `session_summary.md` | `tools/run_service/execute.py` | Target, mode, goal, action counts, model usage, swarm rollup |
| `run.json` | `tools/run_service/execute.py` | Full result dict serialized as JSON |
| `events.jsonl` | API event broker | Authoritative event stream for the run |

`tools/api/routes/runs.py` serves a whitelist of these artifacts (`_ARTIFACT_WHITELIST`: `session_summary.md`, `run.json`, `recon_assessment.json`, `fast_recon.json`, `goal_suggestions.json`, `activity.jsonl`, `exploit_audit.jsonl`, `events.jsonl`, `session_error.log`, `recon_first_error.log`) and refuses path escapes via `_safe_child`. `tools/interactive_menu.py:_preview_report` reads `session_summary.md` (first 2000 chars) and counts `activity.jsonl` lines for its report preview.

Implementation note: the exact writers of `recon_assessment.json`, `fast_recon.json`, `goal_suggestions.json`, `session_error.log`, and `recon_first_error.log` were not traced in this pass; they are listed here only as served names from the runs.py whitelist.

## `decision_log.jsonl`

Structured AI decision logging (observability section 17 in the module docstring). One append-only file per run directory, written by `decision_log_path(run_dir)`:

```python
def decision_log_path(run_dir: Path | str) -> Path:
    return Path(run_dir) / "decision_log.jsonl"
```

Each record is a compact, field-typed decision event — never hidden chain-of-thought, never raw tool output. The fields are chosen so the WebUI can eventually render hypothesis to action to evidence to conclusion from these records.

### Schema via `log_decision` fields

```python
log_decision(
    run_dir,
    *,
    round_num=None,
    task_id="",
    target="",
    capability="",
    reason="",
    applicability=None,
    model_role="",
    duration_s=None,
    outcome="",
    failure_class="",
    success=None,
    evidence_refs=None,
)
```

| Parameter | Record key | Notes |
|---|---|---|
| — | `ts` | `time.time()` float, set by the logger |
| `round_num` | `round` | Loop round number, or `None` |
| `task_id` | `task_id` | Tool name, task id, or `killchain:<edge_id>` |
| `target` | `target` | Target IP or host the decision concerns |
| `capability` | `capability` | Tool or subsystem name |
| `reason` | `reason` | One-line summary, truncated to 300 chars |
| `applicability` | `applicability` | Optional float score, or `None` |
| `model_role` | `model_role` | Role label, or `""` |
| `duration_s` | `duration_s` | Optional duration in seconds |
| `outcome` | `outcome` | Operational status or transition label |
| `failure_class` | `failure_class` | Taxonomy value on failure, `""` on success |
| `success` | `success` | Boolean, or `None` |
| `evidence_refs` | `evidence_refs` | Up to 20 workspace file paths |

Example record:

```json
{"ts": 1757270400.0, "round": 3, "task_id": "run_exploit_terminal", "target": "10.0.0.50", "capability": "run_exploit_terminal", "reason": "uid=0(root) ...", "applicability": null, "model_role": "", "duration_s": null, "outcome": "completed", "failure_class": "", "success": true, "evidence_refs": []}
```

Fail-silent by design: `log_decision` wraps everything in `try/except` and never raises, so logging can never break the agent loop. The parent directory is created on every append.

### Writers

Two call sites write decision records, both best-effort and wrapped in their own guards.

Exploit-loop hook (`tools/exploit_agent/runner/_impl.py`), gated by `_decision_log_enabled` (read once from `agent.decision_log_enabled`, default true):

```python
_log_decision(
    reports_dir,
    round_num=_round + 1,
    task_id=name,
    target=target_ip,
    capability=name,
    reason=_one_line(result_text, 300),
    outcome=str(_action_result.operational_status.value),
    failure_class=_fc,
    success=success,
    evidence_refs=_ev_refs,
)
```

`failure_class` comes from `tools.failure_taxonomy.classify_failure` on the result text, only when the action did not succeed. `evidence_refs` extracts up to 10 workspace file paths from the result text:

```python
_ev_refs = re.findall(
    r"(?:exploit_workspace|reports|workspace)[\\/][^\s\"']+\.\w+",
    result_text,
)[:10]
```

Kill-chain transitions (`tools/killchain/machine.py:_log_decision`), skipped when `decision_log_enabled` is false or `run_dir` is `None`:

```python
log_decision(
    self.run_dir,
    task_id=f"killchain:{edge['edge_id']}",
    target=target,
    capability="killchain",
    reason=f"edge {edge['edge_id']} {edge['from_state']} -> {edge['to_state']}",
    model_role="killchain_machine",
    duration_s=duration_s,
    outcome="verified_transition" if success else "verification_failed",
    failure_class="" if success else "verify_failed",
    success=success,
    evidence_refs=[f"check:{c.get('flag_id', '')}:{'pass' if c.get('passed') else 'fail'}" for c in checks],
)
```

## `run.log`

Per-run console and logging capture. `RunLog.attach` is process-global: the API daemon runs runs sequentially in one process, so `attach()` re-points the same global tee and handler to the new run's file. `attach()` detaches any previous run first, and a stale attach self-heals on the next attach — the crash window's lines stay in the old log, which is exactly what helps when debugging.

Lifecycle in `tools/run_service/execute.py`:

```python
RunLog.attach(reports_dir)   # run start: tee console + logging into reports/<run_id>/run.log
# ... session runs ...
RunLog.detach()              # teardown, then again after the final RunResult is built
```

### Tee, attach, and detach

`_attach(reports_dir)` opens `reports_dir / "run.log"` in append mode (creating parents), then:

1. Drops the root logger to `DEBUG` and adds a single `FileHandler` at `DEBUG`, so every module's `NOTSET`-level logger propagates `DEBUG+` records into the run log. The root logger has no other handlers, so console output is unchanged. The previous root level is restored on detach.
2. Replaces `sys.stdout` and `sys.stderr` with `_Tee` mirrors that write to both the real stream and the log handle under a thread lock.
3. Writes a start banner:

```text
===== run started <iso-utc> argv=[...] log=<path> =====
```

`_Tee.write` strips ANSI escape sequences (`_ANSI_RE`) and carriage returns before writing to the file, so the log stays plain text. It never raises — stream or file errors are swallowed and it still returns `len(data)`.

Log line format (`_FORMAT`, dated `%Y-%m-%d %H:%M:%S`):

```text
2026-09-07 21:00:01 [INFO    ] ai_bug_bounty.creds:_warn_plaintext_fallback:227 — Credential-store encryption DISABLED: ...
```

`_detach()` removes and closes the handler, restores `sys.stdout`/`sys.stderr`, restores the old root level, and closes the handle. When the log file cannot be opened, `_attach` logs a `run.log unavailable` warning and returns with no handle.

## `ActivityLog` trail

`tools/activity_log.py` provides the plain activity logger: it writes the JSONL audit trail and prints clean CLI lines. Constructed per run in `tools/run_service/execute.py`:

```python
activity = ActivityLog(reports_dir, plain=request.plain)
activity.log("info", f"Session started: {mode} against {target_ip} with goal {goal.name}")
```

`ActivityLog(reports_dir, plain=False, max_events=80)` sets `audit_path` to `reports_dir / "activity.jsonl"` (creating parents) and keeps an in-memory ring of at most `max_events` events. The per-run witness side task tails this file (`reports/<run_id>/activity.jsonl`, advisory only, never gates the run).

### `log` and the audit entry shape

```python
activity.log(category, message, detail="", host="", severity="info")
```

Each call builds an `ActivityEvent` timestamped `HH:MM:SS` UTC, appends it to the ring (evicting the oldest past `max_events`), buffers one audit line, and prints a formatted line (colored unless `plain`). The buffer flushes to `activity.jsonl` every 10 entries.

```json
{"time": "21:00:01", "category": "info", "message": "Session started: attack against 10.0.0.50 with goal backdoor", "detail": "", "host": "", "severity": "info"}
```

| Field | Meaning |
|---|---|
| `time` | `HH:MM:SS` UTC string |
| `category` | Event category; also selects the CLI icon via `ICONS` |
| `message` | One-line human-readable message |
| `detail` | Optional detail (CLI prints up to 3 lines, 120 chars each) |
| `host` | Optional host, rendered as `[host]` |
| `severity` | `critical`, `high`, `medium`, `low`, `info`, `warning`, or `error` |

### Convenience wrappers

| Method | Behavior |
|---|---|
| `log(category, message, ...)` | Core append-plus-print path described above |
| `ping(subnet, result)` | `Ping sweep <subnet>` plus progress increment |
| `triage(subnet, result)` | `Triage scan <subnet>` |
| `tool_call(name, arguments, result="")` | `Args: {...}` detail plus truncated result |
| `blocked(reason)` | `Action blocked` at `warning` severity |
| `report_written(path)` | `Report written` with the path as detail |
| `budget_warning(remaining, kind)` | `Budget alert` at `warning` severity |
| `progress()` / `print_progress()` / `set_progress(**kwargs)` | Elapsed plus `subnets_done/subnets_total` line |
| `start()` / `stop()` | No-ops; the class also works as a context manager |

## Related documentation

- [Safety model](safety-model.md) — permission modes, the target-IP lock, and the audit and evidence safety layer.
- [Database and mission persistence](database-mission.md) — the SQLite schemas these per-run JSONL logs sit alongside.
- [Outcome judgment and evidence handling](outcome-evidence.md) — evidential versus execution status and the Flow A audit trail.

## Source map

- `tools/decision_log.py`
- `tools/run_log.py`
- `tools/activity_log.py`
- `tools/run_service/execute.py`
- `tools/exploit_agent/runner/_impl.py`
- `tools/killchain/machine.py`
- `tools/api/routes/runs.py`
- `tools/interactive_menu.py`
