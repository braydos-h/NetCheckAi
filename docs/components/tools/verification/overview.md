---
title: Verification — Overview
package: tools/verification
files: [poe_verifier.py]
---

# Verification — Overview (`tools/verification/`)

Independent proof that a claimed compromise is real. The PoE (proof-of-execution) verifier writes a unique canary token to the target, reads it back, and classifies privilege from identity probes. It never raises — any failure collapses to `verified=False` so a verification miss never aborts a campaign.

## Package map

| File | LOC | Role |
|---|---|---|
| `poe_verifier.py` | 325 | Canary write/read-back + privilege classification over a sync tool executor |
| `__init__.py` | — | Re-exports `verify_compromise`, `verify_compromise_sync`, `classify_privilege`, `extract_output` |
| `tools/verify_oracle.py` | oracle | `VerifyOracle` — deterministic N/N re-proof of a candidate finding via its stored probe |
| `tools/mcp_tools/verify.py` | MCP | `verify_finding` tool + `record_verify` / `persist_verify` artifact writers |
| `tools/mcp_tools/retest.py` | MCP | `retest_finding` (fix confirmation) + shared `_INCONCLUSIVE_MARKERS` |

## `poe_verifier.py` — PoE verifier

```python
ToolExecutor = Callable[..., Any]  # sync (tool_name, args) -> result_text

def extract_output(result: Any) -> str: ...
def classify_privilege(id_output: str, whoami_output: str = "") -> str: ...
def verify_compromise_sync(tool_executor: ToolExecutor, target_ip: str, *, timeout: int = 30) -> dict[str, Any]: ...
async def verify_compromise(tool_executor: ToolExecutor, target_ip: str, *, timeout: int = 30) -> dict[str, Any]: ...
```

| Symbol | Kind | Description |
|---|---|---|
| `_BLOCK_MARKERS` | const | `("BLOCKED:", "TOOL_EXECUTION_ERROR:", "ERROR:")` — any such result is a verification failure |
| `_token_for(target_ip)` | def | `(token, /tmp/poe_<hex>.txt)`; token embeds target IP + uuid4 so it cannot replay from a stale banner |
| `extract_output(result)` | def | Strips the `OUTPUT:` framing `run_exploit_terminal` adds; marker absent → whole text (plain-shell executors work too) |
| `classify_privilege(id_output, whoami_output="")` | def | `"root"` (`uid=0`), `"system"` (NT AUTHORITY/SYSTEM, TrustedInstaller), `"user"`, or `"unknown"` |
| `_run_executor(tool_executor, command, target_ip)` | def | One `run_exploit_terminal` call; exceptions become `TOOL_EXECUTION_ERROR:` strings, never raise |
| `_verify_sync(tool_executor, target_ip)` | def | Core logic: canary write + read-back + `id`/`whoami`/`hostname` in one shell call, token-echo check, privilege classification |
| `verify_compromise_sync` | def | Sync entry point (autonomous orchestrator path); validates inputs, never raises |
| `verify_compromise` | async | Offloads to `asyncio.to_thread` under an outer timeout; same dict shape, never raises |

Verdict dict keys: `verified` (bool), `evidence` (list[str]), `privilege`, `shell_type`, `token`, `target_ip`. The executor contract is the sync `(tool_name, args) -> result_text` shape shared with `SwarmMcpBridge.dispatch`.

## Oracles — machine re-proof

The PoE verifier proves *live compromise*; the oracles below re-prove *stored findings* N/N times. LLM text, OutcomeJudge text, and exit codes never decide — only machine evidence.

| Symbol | Location | Description |
|---|---|---|
| `VerifyOracle(run_fn=None)` | `tools/verify_oracle.py:127` | Re-proves one candidate through the injected `run_fn: exec -> output`; `None`/raising degrades to `INCONCLUSIVE` |
| `VerifyOracle.verify_sync(candidate, *, repeats=2, run_ids=None)` | `tools/verify_oracle.py:149` | Runs the stored `verification_probe.exec` N times → `VerifyOutcome(verdict, proof_capsule, detail)` |
| `VerifyOracle.verify(...)` | async | Worker-thread wrapper around `verify_sync` |
| `ProofCapsule` | `tools/verify_oracle.py:96` | Replayable proof: `probe_exec`, `n`, `outputs`, `sha256`, `run_ids` |
| `judge_outputs(outputs)` | def | N/N rule: any inconclusive → `INCONCLUSIVE`; all proof → `VERIFIED`; else `HOLDING` |
| `classify_verify_output(output)` | def | Proof = `outcome_truth` `COMPROMISE`/`CRED_DUMP` only; `FAILURE` is determinate non-proof |
| `verify_finding(target_ip, finding_id, run_id="", repeats=2)` | `tools/mcp_tools/verify.py:139` | Reloads the probe from `reports/<run_id>/enhanced/enhanced_report.json`, re-executes ONLY that probe via in-process `run_exploit_terminal` (allowlist + audit + sandbox funnel unchanged), persists `verify_status`/`verify_history[]` |
| `retest_finding(target_ip, finding_id, run_id="")` | `tools/mcp_tools/retest.py:279` | Fix confirmation: `STILL_OPEN` / `FIXED` / `INCONCLUSIVE` |
| `_INCONCLUSIVE_MARKERS` | `tools/mcp_tools/retest.py:53` | `SANDBOX_*`/`BLOCKED:`/crashes mean "probe did not run to a verdict" — fail closed, never a pass |

`target_ip` must equal the finding's `affected_asset` or verify refuses (`verify.py:158-162`).

## Lifecycle

```
claim compromise
      │
      ▼
poe_verifier: canary write → read-back → token echo? ──► verified + privilege
      │ no                                              (root/system/user/unknown)
      ▼
verified=False + evidence (campaign continues)
```

```
candidate finding ──► verify_finding ──► N probe runs ──► VERIFIED (N/N proof)
                                                        HOLDING (flaky/failing)
                                                        INCONCLUSIVE (no probe/blocked/ambiguous)
```

## Config keys

No dedicated block. Behavior is shaped by adjacent keys: sandbox failures surface as `SANDBOX_*` → `INCONCLUSIVE` (never host fallback); `repeats` defaults to 2 (clamped 1–5 in `verify_finding`).

## Example

```python
from tools.verification import verify_compromise_sync

verdict = verify_compromise_sync(dispatch, "10.0.0.50")
if verdict["verified"]:
    print(verdict["privilege"])  # "root" | "system" | "user" | "unknown"
```

```python
from tools.verify_oracle import VerifyOracle

oracle = VerifyOracle(run_fn=lambda exec_cmd: run_terminal(exec_cmd))
outcome = oracle.verify_sync({"verification_probe": {"exec": probe}}, repeats=2)
print(outcome.verdict, outcome.proof_capsule.sha256)
```

## Tests (selected)

| File | Covers |
|---|---|
| `tests/test_poe_verifier.py` | Canary round-trip, privilege classification, fail-closed paths |
| `tests/test_verify_oracle.py` | N/N verdict rules, proof capsules |
| `tests/test_finding_verifier.py`, `tests/test_retest.py` | MCP verify/retest verdicts + persistence |

Implementation note: the only in-repo importer of `tools.verification` found in this pass is `tests/test_poe_verifier.py`; orchestrator/swarm consumption described in the module docstring was not re-verified here.

## Related documentation

- [Outcome evidence](../../../outcome-evidence.md)
- [Killchain overview](../killchain/overview.md)
- [MCP tools](../../../mcp-tools.md)
- [Safety model](../../../safety-model.md)

## Source map

- `tools/verification/poe_verifier.py`
- `tools/verification/__init__.py`
- `tools/verify_oracle.py`
- `tools/mcp_tools/verify.py`
- `tools/mcp_tools/retest.py`
