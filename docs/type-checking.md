# Type-checking migration strategy

BreachPilot is migrating toward strict mypy incrementally. A whole-repo
strict conversion in one PR would be reckless (hundreds of errors across
unrelated subsystems); instead, existing debt is tolerated but **new debt
is rejected**.

## The three gates (CI `types` job)

1. **Permissive check** — `mypy --follow-imports=skip tools` with the
   `disable_error_code` suppressions in `pyproject.toml`. Must pass with
   zero errors. This is the primary gate: no new *unsuppressed* errors.
2. **Debt gate** — `python scripts/mypy_debt.py` runs mypy with *zero*
   suppressions (hermetic temp config, fixed `python_version = 3.12`) and
   compares against `mypy-baseline.txt` (total + per-file counts). Fails on
   **any increase** — a higher total, a higher per-file count, or errors in
   a previously clean file. Paying debt down always passes.
3. **Strict subsystems** — per-module overrides in `pyproject.toml` with
   `disable_error_code = []` plus the full `enable_error_code` list.
   Currently strict: `tools.validation_utils`, `tools.exceptions`,
   `tools.mcp_shared`, `tools.kernel.*`, `tools.sandbox.*`.

## Graduation order

1. `tools/kernel` — done (2026-09-07).
2. `tools/api` — next. `run_manager.py` holds 35 errors, nearly all
   `union-attr` on `handle.event_broker` (`RunEventBroker | None`); fixing
   them means deciding the None-contract at each emit site, not sprinkling
   asserts.
3. `tools/sandbox` — done (2026-09-07).
4. Orchestration/session code (`run_service/`, `mcp_session.py`,
   `campaign/`, `swarm/`) — largest remaining clusters
   (`run_service/execute.py`, `mcp_session.py`, `attack_ui.py`).
5. Remaining modules, highest-count first (`mypy-baseline.txt` is sorted
   for triage; error codes are dominated by `union-attr`, `attr-defined`,
   `name-defined`).

## How to graduate a module

1. Fix its errors with real types — `TypedDict`, dataclasses, `Protocol`,
   generics, explicit `Optional` + `None` narrowing. Do **not** silence
   with bare `Any`, per-file `ignore_errors`, or new `disable_error_code`
   entries.
2. Add the module to a strict override in `pyproject.toml` (copy the
   `enable_error_code` list from the `tools.kernel.*` block).
3. Run `python scripts/mypy_debt.py --update` and commit the refreshed
   `mypy-baseline.txt` together with the fixes.
4. Reduce per-file ignores as files become clean; never add new ones to
   cover new debt.

## Refreshing the baseline

Only after paying debt down: `python scripts/mypy_debt.py --update`,
verify the total dropped, commit. Never hand-edit the baseline upward —
the gate compares totals *and* per-file counts, so inflating one file
while fixing another still fails.
