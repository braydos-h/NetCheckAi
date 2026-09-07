---
title: "Tool Family: hitl"
sources:
  - tools/mcp_tools/hitl.py
  - tools/mcp_tools/retest.py
  - tools/enhanced_reporting.py
  - config.yaml
tests:
  - tests/test_hitl.py
subsystem: mcp
---

# Tool Family: hitl

- **Registration source:** `tools/mcp_tools/hitl.py:301 register_hitl_tools(mcp, *, ctx)` — auto-discovered via `collect_tools()`; no edit to `mcp_exploit_server.py` needed. Registers nothing when `hitl.enabled` is false (default true).
- **Gate:** all three tools are local-only `@audit_tool` — zero target touch. Probe re-execution stays inside `verify_finding` / `retest_finding` via `run_exploit_terminal`.
- **Purpose:** proxy-backed HITL evidence loop, Flow A only ("agents propose, human decides"). Agent candidates land as `PROPOSED` findings in the run artifact (`reports/<run_id>/enhanced/enhanced_report.json`); only a human `APPROVED` / `REJECTED` decision promotes them. LLM verdicts (`verify_finding` / `retest_finding`) never write `hitl_status` — they stay machine evidence (`verify_status` / `retest_status`) until a human signs off.

## Tools Exported (3)

| Tool | Params | Result Shape | Gates / Notes |
|------|--------|--------------|---------------|
| `propose_finding` | `run_id: str`, `title: str`, `affected_asset: str`, `summary: str`, `probe_exec: str=""`, `evidence: str=""`, `severity: str="Medium"`, `vuln_class: str=""` | `HITL_PROPOSED:\nFINDING: ...\nRUN: ...\nSTATUS: PROPOSED (awaiting human Approve/Reject in the Evidence tab)\nTITLE: ...` | `@audit_tool`. Appends a `PROPOSED` finding — never `APPROVED`. Empty `run_id` → `BLOCKED`; empty `title`/`affected_asset`/`summary` → `BLOCKED`; unknown run dir → `ERROR`; unpersistable JSON → `ERROR`. `probe_exec` is stored, NOT executed. |
| `hitl_decide` | `finding_id: str`, `decision: str`, `note: str=""`, `run_id: str=""`, `actor: str=""` | `HITL_DECIDED:\nFINDING: ...\nRUN: ...\nDECISION: APPROVED\|REJECTED (actor=human)` | `@audit_tool`. Operator-only human path. Any `actor` other than `'human'` → `BLOCKED` (an LLM can never self-approve). Unknown decision → `ERROR`; unknown finding → `ERROR`. Persists `hitl_status` + `hitl_history[]` with actor. |
| `list_proposed` | `run_id: str=""` | `HITL_PROPOSED (run: ...): N awaiting review.` + up to 50 `- <finding_id> [<run>] <title> on <asset>` lines, then `... and N more` | `@audit_tool`. Empty `run_id` scans all runs newest-first. Approved/rejected findings are hidden. Unknown run → `ERROR`. |

Example — propose, then a human decides:

```text
HITL_PROPOSED:
FINDING: F-127-0-0-1-weak-credentials-on-ssh
RUN: 2026-09-07T00-00-00
STATUS: PROPOSED (awaiting human Approve/Reject in the Evidence tab)
TITLE: Weak credentials on SSH
```

```text
HITL_DECIDED:
FINDING: F-127-0-0-1-weak-credentials-on-ssh
RUN: 2026-09-07T00-00-00
DECISION: APPROVED (actor=human)
```

## Finding Lifecycle

1. Agent calls `propose_finding` → `propose_new_finding` appends a candidate with `hitl_status: PROPOSED` to `technical_findings[]` in the run artifact JSON; sibling `.md`/`.html` reports regenerate when present (`_refresh_siblings`, best-effort).
2. Machine re-proof (`verify_finding` / `retest_finding`) appends `verify_history[]` / `retest_history[]` only — `hitl_status` is never written, so the candidate stays `PROPOSED`.
3. A human approves/rejects via `hitl_decide` (or `POST /runs/{id}/decide`) → `persist_hitl_decision` stamps `hitl_status` + `hitl_history[]` and regenerates siblings.
4. The final report surfaces `APPROVED` findings only (`approved_findings`).

## Proposal Defaults (`propose_new_finding`)

| Field | Value |
|-------|-------|
| `finding_id` | `F-<asset slug, 24 chars>-<title slug>` via `_slug` (lowercase, `[^a-z0-9]+` → `-`, 40-char cap), `-2`, `-3`, … on collision |
| `severity` / `cvss.severity` | `severity` param, default `Medium` (`cvss.base_score: 0.0`) |
| `vuln_class` | `vuln_class` param, default `Unclassified` |
| `confidence` | `0.5` |
| `verification_probe` | `{"type": "shell_command", "exec": probe_exec}` when `probe_exec` is non-empty, else `{}` |
| `verify_status` | `HOLDING` (`verify_history: []`) |
| `retest_status` | `""` (`retest_history: []`) |
| `hitl_status` | `PROPOSED`, always — proposals can never self-approve |
| `hitl_history[0]` | `{decision: PROPOSED, note: "agent proposal — awaiting human review", actor: "agent"}` |

## Statuses and the Self-Approval Guard

- Constants: `PROPOSED`, `APPROVED`, `REJECTED`; `HITL_STATUSES = frozenset({PROPOSED, APPROVED, REJECTED})`; `HITL_DECISIONS = frozenset({APPROVED, REJECTED})`.
- `record_hitl_decision` raises `ValueError` on an unknown decision and `PermissionError` unless `actor == "human"` — enforced at both the helper and the `hitl_decide` wrapper (which `BLOCKED`s any other actor before lookup), and the REST decide route hardcodes `actor="human"`.
- Every decision appends `{timestamp, decision, note, actor: "human"}` to `hitl_history[]` and lands in the JSONL audit trail with its actor.

## Listing (`list_proposed_findings`)

- With `run_id` set, reads only that run — `LookupError` when it has no enhanced report.
- With `run_id` empty, scans all run dirs newest-first (`st_mtime`, reverse) and aggregates `PROPOSED` findings, injecting `_run_id` per item. Never raises on malformed entries.

## Proof Capsule (`proof_capsule`)

Read-only evidence bundle for the human reviewer — never executes. Surfaces the stored probe exec, the latest machine re-proof capsule, and the latest retest verdict:

| Field | Source |
|-------|--------|
| `finding_id` | the finding |
| `probe_exec` | `verification_probe.exec`, else the capsule's `probe_exec`, else `""` |
| `output_excerpt` | last capsule output (first 2000 chars), else last retest evidence |
| `proof_sha256` / `proof_runs` | capsule `sha256` / `n` |
| `verify_status` / `verify_detail` | finding `verify_status` (default `HOLDING`); last `verify_history[]` evidence/verdict |
| `retest_status` / `retest_detail` | finding `retest_status`; last `retest_history[]` evidence/verdict |

## Dependencies

- `tools/mcp_tools/retest.py` — `_find_in_report`, `_finding_file`, `_read_report_json`, `_reports_root`, `locate_finding` (finding lookup + reports-root resolution)
- `tools/enhanced_reporting.py` — `EnhancedReportGenerator` (sibling `.md`/`.html` regeneration), `approved_findings` (APPROVED-only final-report filter)

## Config

- `hitl.enabled: bool` (default true) — when false, `register_hitl_tools` returns without registering anything.

## Auditing

All three tools use `@audit_tool` (`started`/`completed|blocked` rows in `exploit_audit.jsonl`). Every decision lands in `hitl_history[]` and the JSONL audit trail with its actor (`human`).

## Validation

- `propose_finding`: empty `run_id` → `BLOCKED: run_id is required.`; empty `title`/`affected_asset`/`summary` → `BLOCKED: title, affected_asset, and summary are required.`; missing run dir → `ERROR: propose_finding: unknown run ...`; unpersistable JSON → `ERROR: propose_finding: cannot persist ...`.
- `hitl_decide`: empty `finding_id` → `BLOCKED`; `actor` not `'human'` → `BLOCKED: hitl_decide requires actor='human' (operator-only; agents cannot self-approve).`; unknown finding → `ERROR: hitl_decide: ...`; unknown decision → `ERROR`; unpersistable JSON → `ERROR: hitl_decide: cannot persist ...`.
- `record_hitl_decision` (helper): unknown decision raises `ValueError`; non-human actor raises `PermissionError`.
- `persist_hitl_decision` (helper): raises `LookupError` for findings absent from the artifact JSON.

## Tests

- `tests/test_hitl.py` — `test_hitl_disabled_registers_nothing`, `test_propose_never_approves_and_ids_unique`, `test_propose_validates_input`, `test_agent_actor_refused_at_helper`, `test_agent_actor_blocked_at_tool`, `test_unknown_decision_rejected`, `test_persist_decision_roundtrip`, `test_proof_capsule_from_stored_evidence`, `test_proof_capsule_empty_finding_never_raises`, `test_list_proposed_across_runs`, `test_list_proposed_hides_decided`, `test_propose_approve_report_shows_approved`, `test_propose_reject_hidden_from_approved`, `test_api_proposed_and_decide_live`, `test_api_decide_validation`

## Related documentation

- [Verify tool family](./verify.md) — machine re-proof (`verify_status`, proof capsule); never writes `hitl_status`
- [Retest tool family](./retest.md) — fix re-proof (`retest_status`); never writes `hitl_status`
- [MCP security](../security.md) — audit trail
- [MCP registration](../registration.md) — decorator contract

## Source map

- `tools/mcp_tools/hitl.py` — `register_hitl_tools`, `propose_new_finding`, `record_hitl_decision`, `persist_hitl_decision`, `list_proposed_findings`, `proof_capsule`
- `tools/mcp_tools/retest.py` — finding lookup + reports-root helpers (`locate_finding`, `_reports_root`, `_finding_file`)
- `tools/enhanced_reporting.py` — sibling report regeneration, `approved_findings`
- `config.yaml` — `hitl.enabled`
