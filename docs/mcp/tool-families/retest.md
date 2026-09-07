---
title: "Tool Family: retest"
sources:
  - tools/mcp_tools/retest.py
  - tools/exploit_agent/outcome_truth.py
  - tools/enhanced_reporting.py
  - tools/snapshots.py
tests:
  - tests/test_retest.py
subsystem: mcp
---

# Tool Family: retest

- **Registration source:** `tools/mcp_tools/retest.py:273 register_retest_tools(mcp, *, ctx)` — discovered via `collect_tools()` / `register_*_tools` naming; no edit to `mcp_exploit_server.py` needed.
- **Gate:** `@require_allowlist()` — re-executes a stored PoC probe against the finding's own asset, so the target-IP allowlist lock applies.
- **Purpose:** Closed-loop retest ("prove the fix"). Reloads a confirmed finding's stored verification probe and re-runs ONLY that probe against the current target; the verdict reuses the authoritative `outcome_truth` classifier (`tools/exploit_agent/outcome_truth.py`), never raw output words. Authorized-testing-only: retest probes execute attack commands against a target you own or are explicitly authorized to test.

## Tools Exported (1)

| Tool | Decorator | Params | Result Shape | Notes |
|------|-----------|--------|--------------|-------|
| `retest_finding` | `@require_allowlist()` | `target_ip: str`, `finding_id: str`, `run_id: str=""` | `RETEST_VERDICT:` block (`FINDING`, `TARGET`, `RUN`, `VERDICT`, `PROBE`, `EVIDENCE`, `DETAIL`) | Reloads `verification_probe` from `reports/<run_id>/enhanced/enhanced_report.json` (latest run containing the finding when `run_id` is empty) and re-executes ONLY that probe via `run_exploit_terminal` in-process. Persists `retest_status` + `retest_history[]` into the finding. |

## Parameters — Constraints

- `finding_id` and `target_ip` are required; empty values return `BLOCKED: ... is required.`
- `target_ip` must equal the finding's `affected_asset` (case-insensitive compare) — otherwise `BLOCKED: target_ip ... does not match the finding's affected_asset ...`.
- `run_id` empty means "latest run containing this finding" (newest-first scan of run dirs holding an `enhanced/enhanced_report.json`); unknown `finding_id` returns `ERROR: retest_finding: ...`.

## Result Shape

```text
RETEST_VERDICT:
FINDING: F-127.0.0.1-run_exploit_terminal
TARGET: 127.0.0.1
RUN: 2026-09-07T00-00-00
VERDICT: FIXED
PROBE: [shell_command] <probe command, first 300 chars>
EVIDENCE: reports/2026-09-07T00-00-00/enhanced/enhanced_report.json; snapshots recorded for target: 2
DETAIL: outcome_truth=FAILURE
```

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `STILL_OPEN` | The PoC output still shows compromise/cred-dump (`outcome_truth` `COMPROMISE` or `CRED_DUMP`; conservative — any access signal keeps the finding open). |
| `FIXED` | The PoC demonstrably fails against the current target (`outcome_truth` `FAILURE`). |
| `INCONCLUSIVE` | No stored probe, blocked/sandbox-failed run, empty output, or ambiguous output (`PARTIAL`/`UNKNOWN`/`NONE`). Fail-closed; never evidence the hole closed. |

Containment/policy markers always short-circuit to `INCONCLUSIVE` before classification: `SANDBOX_`, `BLOCKED:`, `TOOL_EXECUTION_ERROR:`, `UNKNOWN_TOOL:`, `ERROR:` — the marker-bearing line surfaces in `DETAIL` (first 300 chars).

## How It Works

1. `locate_finding` loads `(report_data, finding, json_path, resolved_run_id)` from the reports root, or raises `LookupError`.
2. `resolve_probe` returns the stored `verification_probe` dict, or `None` when absent/empty — the no-probe path persists `INCONCLUSIVE` with evidence `no stored verification probe for this finding` and returns `PROBE: (none stored)`.
3. `resolve_exec` fills `{target_ip}`/`{target}` placeholders in the probe's `exec` string, then `_run_probe_in_process` re-executes it via the already-registered `run_exploit_terminal` tool function in-process (`tools/mcp_tools/killchain._in_process_tool_executor`), so the allowlist lock, JSONL audit trail, and sandbox funnel apply unchanged. An executor crash becomes `TOOL_EXECUTION_ERROR: ...` output, which classifies `INCONCLUSIVE`.
4. `classify_retest_output` maps fresh probe output to `(verdict, detail)` via `classify_exploit_outcome`.
5. Snapshot state is read best-effort via `SnapshotManager.list` (index read only, fail-open) and attached to the `EVIDENCE` line as `snapshots recorded for target: N` — a snapshot failure never blocks the retest.
6. `persist_retest` stamps `retest_status` and appends `retest_history[]` (`timestamp`, `verdict`, `evidence` — the first 300 chars of probe output) in the existing run artifact JSON, then regenerates sibling `.md`/`.html` reports when present (best-effort).

Example probe stored on a finding:

```json
{
  "finding_id": "F-127.0.0.1-run_exploit_terminal",
  "affected_asset": "127.0.0.1",
  "verification_probe": {
    "type": "shell_command",
    "exec": "curl -s http://127.0.0.1/poc"
  }
}
```

## Dependencies

- `tools/exploit_agent/outcome_truth.py` — `classify_exploit_outcome`, `ExploitOutcome` (the verdict authority)
- `tools/mcp_tools/killchain.py` — `_in_process_tool_executor` for the in-process probe run
- `tools/enhanced_reporting.py` — `EnhancedReportGenerator` for sibling report regeneration
- `tools/snapshots.py` — `SnapshotManager`, `_vm_id_for_target` (best-effort context only)

## Config

Implementation note: there is no dedicated `retest:` config section. The reports root resolves via `_reports_root(config)`: config `reports_dir`, else the `BREACHPILOT_REPORTS_DIR` environment variable, else `reports`. The allowlist gate follows `exploit.require_explicit_allowlist` / `exploit.allowed_targets`.

## Auditing

`@require_allowlist()` writes `started` then `completed|blocked` to `exploit_audit.jsonl`. The probe re-execution itself goes through `run_exploit_terminal`, so it is audited as its own tool call too.

## Validation

- `target_ip` must match the finding's `affected_asset` — retest runs ONLY against the finding's own asset, never an arbitrary host.
- `record_retest` raises `ValueError` on an unknown verdict; persistence failures degrade the `EVIDENCE` line to `<path> (persistence failed — verdict not saved)` rather than failing the call.

## Tests

- `tests/test_retest.py` — finding lookup, probe resolution, output classification, persistence

## Related documentation

- [MCP security](../security.md) — allowlist lock + audit trail
- [MCP registration](../registration.md) — decorator contract
- [Verify tool family](./verify.md) — the N/N re-proof counterpart (`VERIFIED` / `HOLDING` / `INCONCLUSIVE`)

## Source map

- `tools/mcp_tools/retest.py`
- `tools/exploit_agent/outcome_truth.py`
- `tools/enhanced_reporting.py`
- `tools/snapshots.py`
