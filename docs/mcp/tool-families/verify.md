---
title: "Tool Family: verify"
sources:
  - tools/mcp_tools/verify.py
  - tools/mcp_tools/retest.py
  - tools/verify_oracle.py
  - tools/enhanced_reporting.py
tests:
  - tests/test_verify_oracle.py
subsystem: mcp
---

# Tool Family: verify

- **Registration source:** `tools/mcp_tools/verify.py:133 register_verify_tools(mcp, *, ctx)` — discovered via `collect_tools()` / `register_*_tools` naming; no edit to `mcp_exploit_server.py` needed.
- **Gate:** `@require_allowlist()` — re-executes a stored exploit probe against the finding's own asset, so the target-IP allowlist lock applies.
- **Purpose:** Machine re-proof of a CANDIDATE finding ("verify-or-it-didn't-happen"). Reloads the finding's stored verification probe and re-runs it N times; the verdict comes solely from `tools.verify_oracle.VerifyOracle` (N/N `outcome_truth` compromise proof). LLM text and exit codes never decide. Authorized-testing-only: verification probes execute attack commands against a target you own or are explicitly authorized to test.

## Tools Exported (1)

| Tool | Decorator | Params | Result Shape | Notes |
|------|-----------|--------|--------------|-------|
| `verify_finding` | `@require_allowlist()` | `target_ip: str`, `finding_id: str`, `run_id: str=""`, `repeats: int=2` | `VERIFY_VERDICT:` block (`FINDING`, `TARGET`, `RUN`, `VERDICT`, `PROOF_RUNS`, `PROOF_SHA256`, `PROBE`, `EVIDENCE`, `DETAIL`) | Reloads `verification_probe` from `reports/<run_id>/enhanced/enhanced_report.json` (latest run containing the finding when `run_id` is empty) and re-executes ONLY that probe N times via `run_exploit_terminal` in-process. Persists `verify_status` + `verify_history[]` (with proof capsule) into the finding. |

## Parameters — Constraints

- `finding_id` and `target_ip` are required; empty values return `BLOCKED: ... is required.`
- `target_ip` must equal the finding's `affected_asset` (case-insensitive compare) — otherwise `BLOCKED: target_ip ... does not match the finding's affected_asset ...`.
- `run_id` empty means "latest run containing this finding" (newest-first scan of run dirs holding an `enhanced/enhanced_report.json`); unknown `finding_id` returns `ERROR: verify_finding: ...`.
- `repeats` is the proof-run count N (default 2, clamped 1–5); unparseable values fall back to 2. ALL N runs must show compromise proof.

## Result Shape

```text
VERIFY_VERDICT:
FINDING: F-127.0.0.1-run_exploit_terminal
TARGET: 127.0.0.1
RUN: 2026-09-07T00-00-00
VERDICT: VERIFIED
PROOF_RUNS: 2
PROOF_SHA256: <sha256 of the proof capsule>
PROBE: [shell_command] <probe command, first 300 chars>
EVIDENCE: reports/2026-09-07T00-00-00/enhanced/enhanced_report.json
DETAIL: <oracle detail, first 500 chars>
```

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `VERIFIED` | All N runs show machine compromise proof. |
| `HOLDING` | Flaky or failing proof — stays a candidate. |
| `INCONCLUSIVE` | No stored probe, blocked/sandbox-failed run, or ambiguous output. Fail-closed; never a host fallback. |

## How It Works

1. `locate_finding` (shared with retest, lives in `tools/mcp_tools/retest.py`) loads `(report_data, finding, json_path, resolved_run_id)` or raises `LookupError`.
2. `resolve_probe` returns the stored `verification_probe` dict, or `None` when absent/empty — the no-probe path persists `INCONCLUSIVE` with detail `no stored verification probe for this finding` and returns `PROBE: (none stored)`.
3. `resolve_exec` fills `{target_ip}`/`{target}` placeholders in the probe's `exec` string, then `_run_probe_in_process` re-executes it via the already-registered `run_exploit_terminal` tool function in-process (`tools/mcp_tools/killchain._in_process_tool_executor`), so the allowlist lock, JSONL audit trail, and sandbox funnel apply unchanged. Sandbox failures surface as `SANDBOX_*` text and fail closed to `INCONCLUSIVE`.
4. `VerifyOracle.verify_sync({"exec": command}, repeats=n, run_ids=[resolved_run])` produces the verdict plus a proof capsule (`proof_capsule.to_dict()`, `.sha256`, `.outputs`).
5. `persist_verify` stamps `verify_status` and appends `verify_history[]` (`timestamp`, `verdict`, `evidence`, `proof_capsule`) in the existing run artifact JSON, then regenerates sibling `.md`/`.html` reports when present (best-effort).

## Dependencies

- `tools/mcp_tools/retest.py` — `locate_finding`, `resolve_probe`, `resolve_exec`, `_find_in_report`, `_read_report_json`, `_reports_root`, `_run_probe_in_process` (shared probe helpers live here, not in `verify.py`)
- `tools/verify_oracle.py` — `VerifyOracle`, `VERIFIED`, `HOLDING`, `INCONCLUSIVE`
- `tools/enhanced_reporting.py` — `EnhancedReportGenerator` for sibling report regeneration
- `tools/mcp_tools/killchain.py` — `_in_process_tool_executor` for the in-process probe run

## Config

Implementation note: there is no dedicated `verify:` config section. The reports root resolves via `_reports_root(config)`: config `reports_dir`, else the `BREACHPILOT_REPORTS_DIR` environment variable, else `reports`. The allowlist gate follows `exploit.require_explicit_allowlist` / `exploit.allowed_targets`.

## Auditing

`@require_allowlist()` writes `started` then `completed|blocked` to `exploit_audit.jsonl`. The probe re-execution itself goes through `run_exploit_terminal`, so it is audited as its own tool call too.

## Validation

- `target_ip` must match the finding's `affected_asset` — verify runs ONLY against the finding's own asset, never an arbitrary host.
- `repeats` clamped 1–5; all N must prove compromise.
- `record_verify` raises `ValueError` on an unknown verdict; persistence failures degrade the `EVIDENCE` line to `<path> (persistence failed — verdict not saved)` rather than failing the call.

## Tests

- `tests/test_verify_oracle.py` — oracle verdict semantics (`VERIFIED` / `HOLDING` / `INCONCLUSIVE`)

## Related documentation

- [MCP security](../security.md) — allowlist lock + audit trail
- [MCP registration](../registration.md) — decorator contract
- [Retest tool family](./retest.md) — the fix-proving counterpart (`STILL_OPEN` / `FIXED` / `INCONCLUSIVE`)

## Source map

- `tools/mcp_tools/verify.py`
- `tools/mcp_tools/retest.py`
- `tools/verify_oracle.py`
- `tools/enhanced_reporting.py`
