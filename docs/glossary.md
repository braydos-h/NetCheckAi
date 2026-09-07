# Glossary

Alphabetical reference of domain terms used across this codebase and its
docs. Each entry gives one crisp definition and a `file:line` pointer to
where the term is defined or primarily used.

## Core Concepts

- **Attack module** — A self-contained, registered exploit/recon unit under
  `tools/attack_modules/modules/` with metadata (id, family, risk) and
  applicability scoring. See [attack-modules.md](attack-modules.md) and
  `tools/attack_modules/registry.py`.
- **Flow A** — The modern flow users run: `main.py` / `app.py` →
  `tools/exploit_agent/`, `tools/mcp_tools/`, `tools/swarm/`,
  `tools/autonomous_orchestrator.py`, `tools/run_service/`, `tools/api/`.
- **Flow B** — The legacy, SQLite-backed flow: `cli.py` + root-level
  `agent_loop.py` / `db.py` / `mission.py` / `scope_gate.py` /
  `safety_reviewer.py`. Shares only `db.py` and `mission.py` schemas with
  Flow A (AGENTS.md rule 2).
- **Mission** — The top-level unit of work (a target + goal + scope). Created
  in the DB (`db.py:717 create_mission`), driven by a mission controller
  (`mission.py`), executed task-by-task.
- **Run** — The run-service unit of execution (Flow A / WebUI): one lifecycle
  from create → start → running → complete/failed/cancelled, persisted in
  `api_runtime.db` (`tools/run_service/service.py`, `tools/api/run_manager.py`).
- **Attempt** — One exploit attempt inside a target session, stored under
  `exploit_workspace/<target_ip>/<attempt_id>/` with its own audit JSONL.

## Flows & Lifecycle

- **Agent loop** — The main agent cycle: plan → call tools → observe →
  reflect → repeat (`tools/exploit_agent/runner/_impl.py`, Flow B `agent_loop.py:61
  AgentLoop`).
- **Autonomous orchestrator** — Unattended mission driver that starts the MCP
  exploit server, feeds target/goal, and monitors the agent to completion
  (`tools/autonomous_orchestrator.py`, esp. `:1048` primary-target resolution).
- **Recon phase** — Discovery stage; Flow A goes through `tools/mcp_tools/recon.py`,
  enrichers in `tools/recon_enrichers.py`; recon stays `read_only` by design.
- **Exploit session** — An interactive or autonomous session against a
  resolved target IP where exploit MCP tools run under a permission mode.
- **Pivot** — Moving from a foothold to further hosts; gated in Flow B by the
  scope gate and in Flow A by the target allowlist (no separate pivot gate —
  AGENTS.md rule 3).

## Safety

- **Allowlist (target-IP lock)** — THE attack-mode safety boundary: the union
  of `EXPLOIT_TARGET` / `EXPLOIT_TARGET_IP` / `EXPLOIT_TARGET_DOMAIN` /
  `EXPLOIT_DISCOVERED_TARGETS` env vars plus config, matched at tool-call time
  (`tools/mcp_shared.py:494 _allowed_target_list`, `:563`,
  `tools/mcp_tools/terminal.py:64 _target_lock_block`). Matches exact IP,
  domain, `*.wildcard`, CIDR.
- **Permission mode** — `read_only` vs `full_access`; resolved by
  `_resolve_exploit_permission` with a read-only fallback for missing keys
  (`tools/exploit_agent/policy.py:380`). `full_access` auto-approves all
  commands — the allowlist is the lock, not the policy.
- **Scope gate** — Flow B pre-execution check that a target/task is inside
  declared mission scope (`scope_gate.py`). Flow A enforces scope via the
  allowlist instead.
- **Risk controller** — Flow B safety review layer that scores proposed
  actions and blocks high-risk ones outside scope (`risk_controller.py`).
- **Safety reviewer** — Flow B pre-attack gate that reviews recon results
  before exploitation (`safety_reviewer.py`).
- **Exception-group pattern** — anyio raises `BaseExceptionGroup`, not
  `Exception`; code wrapping MCP clients must use `_EXC_GROUP_CATCH` +
  `_is_exception_group` / `_log_nested_exceptions` from `tools/exceptions.py`
  (AGENTS.md rule 1).

## Outcomes & Evidence

- **Outcome** — Judgment of what an action/tool call achieved; classified on
  three axes (execution, evidential, exploit outcome) by `outcome_judge.py`.
- **Outcome truth** — The authoritative, evidence-backed record of an action's
  result (`tools/exploit_agent/outcome_truth.py`), distinct from the model's
  own claim (`outcome_classify.py`).
- **Evidence** — Atomic proof items (command output, files, screenshots)
  saved via `evidence.py EvidenceStore`; the exploit audit JSONL is a
  hash-chained trail under `exploit_workspace/`, promotable into the evidence
  store (`evidence.py:288 promote_exploit_audit`).
- **Finding** — A validated, report-ready conclusion tied to evidence;
  lifecycle created → validated → rejected → report_ready
  (`finding_verifier.py:77 FindingVerifier`).
- **PoE (Proof of Execution)** — Canary-based verification that an exploit
  actually ran, not just that the model claimed it did. Available as a
  primitive (`tools/verification/poe_verifier.py`) but **not wired into the
  live loop** — no production code calls it yet (test-only).
- **Report** — Generated summary of a mission/run, written under
  `reports/` (`report_generator.py`, `tools/enhanced_reporting.py`).
- **Audit trail** — Append-only JSONL of every tool call with redaction and
  hash chaining: `exploit_audit.jsonl`.

## Swarm

- **Swarm** — Multi-agent mission subsystem (`tools/swarm/`): orchestrator +
  blackboard + specialist agents.
- **Blackboard** — Shared mission state/messages bus agents read/write
  (`tools/swarm/blackboard.py`).
- **Orchestrator** — Swarm mission controller sequencing phases and agents
  (`tools/swarm/orchestrator.py`).
- **Swarm agents** — recon, vuln, exploit, post-exploit, critic, reflection
  (`tools/swarm/agents/`); critic reviews proposed actions for safety, and
  post-exploit handles privesc/loot/pivot.
- **Skill phase** — Swarm phase that injects runtime-skill guidance
  (`tools/swarm/skill_phase.py`).

## MCP & Tools

- **MCP** — Model Context Protocol; this repo runs three servers:
  exploit (`mcp_exploit_server.py`), engine (`mcp_engine_server.py`),
  defensive/legacy (`mcp_server.py`). See [mcp-wiring.md](mcp-wiring.md).
- **Tool family** — A group of MCP tools in one `tools/mcp_tools/<family>.py`
  file (recon, terminal, cracking, metasploit, ad, web_scan, …).
- **`@audit_tool`** — Decorator that registers + audits an exploit MCP tool;
  tools must also be added to the server tool list (`mcp_exploit_server.py`,
  `tools/mcp_tools/registry.py`).
- **`@require_allowlist()`** — Gate for target-touching tools: requires a
  target IP inside the allowlist (`tools/mcp_tools/registry.py`).
- **Tool catalog** — Phase-narrowed list of tools the agent may call
  (`tools/exploit_agent/tool_catalog.py`).

## Skills & Research

- **Skill** — Advisory `SKILL.md` (frontmatter + markdown) selected
  semantically; prompt context only, never execution authority
  (`tools/skill_registry.py:362 render_skill_context`, [skills.md](skills.md),
  [skill-authoring.md](skill-authoring.md)).
- **Recon enricher** — Post-scan parser that adds structured info (banner,
  TLS, SMTP, DB, HTTP spider) (`tools/recon_enrichers.py`).
- **Research assistant** — Read-only sidecar agent for web/CVE research with a
  JSON contract (`tools/exploit_agent/research_assistant.py:46`).
- **CVE lookup** — NVD API 2.0 client with LRU cache, rate limiting, circuit
  breaker, EPSS/KEV opt-in enrichment (`tools/cve_lookup.py`).

## UI & API

- **Run service** — Backend service managing runs, providers, events, and
  decisions (`tools/run_service/`); persisted in `api_runtime.db`.
- **Decision broker / event broker** — Route approval decisions and runtime
  events between agents, server, and WebUI over WS/SSE
  (`tools/api/decision_broker.py`, `tools/api/event_broker.py`).
- **Session titler** — Auto-generates human titles for runs
  (`tools/api/session_titler.py`).
- **WebUI** — Bundled React/Vite SPA under `webui/` (first `--web` run builds
  `webui/dist/`); docs in [webui.md](webui.md), API in [api.md](api.md).

## Runtime & Ops

- **`--doctor`** — Environment check (Python/nmap/Ollama/config)
  (`tools/doctor.py`).
- **`--self-test`** — Safe localhost smoke test (`tools/self_test.py`).
- **Sandbox** — Disposable per-run Docker worker (`tools/sandbox/`,
  default-on). Network containment via netns firewall over the effective
  allowlist; mid-session failures = `SANDBOX_*` fail-closed blocks; boot
  fallback = `sandbox.fallback_native` degrade-to-native + `SANDBOX_FALLBACK:` lines. See [sandbox.md](sandbox.md).
- **Loot / vault / credential_store** — Captured creds/loot per run
  (encrypted at rest via `tools/credential_store.py`); surfaced in WebUI
  Loot & Credentials page.
- **Beacon / listener** — Persistent RCE callback (`tools/operator_connection/`,
  `operator_connection` config; `default_callback_port: 4444`).
- **AttackPlan / DAG** — Prerequisite graph (`tools/attack_planner.py`:
  `ready_steps()` / `blocked_steps()` / `graph_summary()`); rendered in WebUI Attack Graph.
- **Killchain** — Opt-in stage machine (`killchain.enabled`, `tools/killchain/`;
  `killchain_status`/`attempt`/`plan` tools; verification-gated advances).
- **Snapshots** — Opt-in rollback (`snapshots.enabled`, `tools/snapshots.py`;
  `snapshot_create`/`revert`/`list`; `PROXMOX_API_TOKEN` env-only; fail-open).
- **GoalEngine** — Preset/custom goal resolution + risk gating (SAFE/GATED/HIGH)
  (`tools/goal_engine.py`).
- **`--long-session`** — Multi-hour mode: raises context/timeout/round budgets + checkpointed resume.
- **`secr.json`** — Gitignored local key file written by `--setup-api-keys` (never auto-loads `.env`).
- **`api_runtime.db` / decision_log / battle-log** — API persistence
  (`tools/api/persistence.py`) / per-run decision trail (`decision_log.jsonl`) /
  swarm cross-agent log.
- **TokenGate / bearer** — Loopback WebUI auth (`.webui_secret_key` or
  `BREACHPILOT_API_TOKEN`; WS `{"auth":…}` → 4401 on failure).
- **`@require_allowlist`** — Target-touching gate (IP/domain/`*.wildcard`/CIDR via `is_target_in_allowlist`).
- **Demo mode** — Scripted safe demonstration runs (`tools/demo_mode.py`).
- **Eval harness / benchmark** — Offline evaluation: legacy self-scored
  `tools/eval_harness.py` vs oracle-backed `tools/eval_benchmark.py`
  (verified/false-positive rates, risk ratio + CI). See
  [evaluation.md](evaluation.md).
- **Detection coverage** — Scoring of how visible/covered an attack path is
  to detection (`tools/detection_coverage.py`, `attack_modules/modules/detection.py`).
- **OPSEC** — Advisory briefing injected into prompts to reduce detection
  noise (`tools/exploit_agent/prompt.py:282 build_opsec_briefing`).
- **Workspace dirs** — Gitignored runtime state: `reports/`,
  `exploit_workspace/`, `research_workspace/`, `swarm_workspace/`,
  `webui/dist/`.
- **`opencode.jsonc`** — Editor-local config for the opencode editor's own
  model provider, gitignored; NOT application config (AGENTS.md rule 5).
  App config lives in `config.yaml` — see
  [config-reference.md](config-reference.md).

## Appendix A — Additional terms (alphabetical)

Quick index (see one-line definitions below):

| Term | Primary pointer |
|---|---|
| allowlist lock | `tools/kernel/allowlist.py:79` |
| `api_runtime.db` | `tools/api/persistence.py:19` |
| audit chain | `tools/exploit_agent/policy.py:144` |
| benchmark suite | `tools/benchmark/service.py:23` |
| blackboard | `tools/swarm/blackboard.py:47` |
| campaign | `tools/campaign/orchestrator.py:40` |
| credential vault | `tools/credential_store.py:297` |
| decision broker | `tools/api/decision_broker.py:19` |
| event broker | `tools/api/event_broker.py:431` |
| exploit policy | `tools/exploit_agent/policy.py:292` |
| HITL proposal | `tools/mcp_tools/hitl.py:155` |
| killchain | `tools/killchain/machine.py:45` |
| operator connection | `tools/operator_connection/manager.py:106` |
| oracle | `tools/eval_harness.py:635` |
| orchestrator | `tools/swarm/orchestrator.py:41` |
| permission mode | `tools/exploit_agent/policy.py:18` |
| PoE/PoC verification | `tools/verification/poe_verifier.py:238` |
| `research.db` | `db.py:959` |
| retest | `tools/mcp_tools/retest.py:279` |
| run handle | `tools/api/run_manager.py:86` |
| semantic matching | `tools/skill_embeddings.py:95` |
| skill reselect | `tools/exploit_agent/skills.py:44` |
| snapshot | `tools/snapshots.py:556` |
| tool catalog | `tools/exploit_agent/tool_catalog.py:207` |
| XBEN | `tools/benchmark/xben/manifest.py:53` |

- **allowlist lock** — Effective target set unioning config `exploit.allowed_targets` with runtime env (`EXPLOIT_TARGET`, `EXPLOIT_TARGET_IP`, `EXPLOIT_TARGET_DOMAIN`, `EXPLOIT_DISCOVERED_TARGETS`) (`tools/kernel/allowlist.py:79 _allowed_target_list`, `:114 add_discovered_target`; matcher `tools/validation_utils.py:651 is_target_in_allowlist`; enforcement `tools/mcp_tools/terminal/allowlist.py:203 _target_lock_block` via `tools/kernel/audit.py:369 make_require_allowlist`).
- **api_runtime.db** — API-run SQLite store name (`tools/api/persistence.py:19 _API_DB_NAME`, path built at `:162` under the reports dir), separate from Flow B's `research.db`.
- **audit chain** — Append-only, tamper-evident `exploit_audit.jsonl` record of every tool call (`tools/exploit_agent/policy.py:144 EXPLOIT_AUDIT_FILENAME`, `:148` completeness comment, `:382 approve_action`).
- **benchmark suite** — Reproducible oracle-verified trial runner (`tools/benchmark/service.py:23 BenchmarkService`; run shape `tools/benchmark/models.py:303 RunConfig`; refusal path `tools/benchmark/runner.py:180`).
- **blackboard** — Swarm shared dict-like mission state bus (`tools/swarm/blackboard.py:47 Blackboard`).
- **campaign** — Persistent multi-phase attack queue across targets driven by the autonomous orchestrator (`tools/campaign/orchestrator.py:40 AutonomousOrchestrator`; state `tools/campaign/state.py:183 AttackState`; executor `tools/campaign/executor.py:50 AttackModuleExecutor`).
- **credential vault** — Fernet at-rest encryption wrapper plus persistent loot/credential store (`tools/credential_store.py:167 _Vault`, `:297 CredentialStore`; key basename deny-list `:181 DENY_BASENAME`).
- **decision broker** — Per-run approval-decision futures between agent, server, and WebUI (`tools/api/decision_broker.py:19 DecisionBroker`, `:50 await_answer`, `:63 resolve`).
- **event broker** — Per-run JSONL plus ring-buffer pub/sub feeding SSE/WS (`tools/api/event_broker.py:431 RunEventBroker`, `:692 EventBrokerRegistry`; reconnect note `:6`).
- **exploit policy** — Attack-path approval object auto-approving everything on `full_access` except the threaded mission ScopeGate consult (`tools/exploit_agent/policy.py:292 ExploitPolicy`, `:382 approve_action`).
- **HITL proposal** — Agent-submitted `PROPOSED` candidate finding awaiting a human `APPROVED`/`REJECTED` decision (`tools/mcp_tools/hitl.py:49 PROPOSED`, `:155 propose_new_finding`, `:301 register_hitl_tools`, `:370 hitl_decide` operator-only).
- **killchain** — Opt-in evidence-verified stage machine (`tools/killchain/machine.py:45 KillChainMachine`; goal `tools/killchain/states.py:49 SHELL_AS_ROOT`; default `tools/config/schema.py:547 goal_state`).
- **operator connection** — Persistent RCE callback session management (`tools/operator_connection/manager.py:106 ConnectionManager`, `:47 ConnectionRecord`).
- **oracle** — Per-target expected-findings JSON used for scoring, never the agent's own claim (`tools/eval_harness.py:635 load_target_oracle`, `:646 score_against_oracle`).
- **orchestrator** — Either the swarm specialist-decomposition controller (`tools/swarm/orchestrator.py:41 SwarmOrchestrator`) or the persistent campaign controller (`tools/campaign/orchestrator.py:40 AutonomousOrchestrator`).
- **permission mode** — `read_only` vs `approve_only` vs `full_access` tri-state resolved from config (`tools/exploit_agent/policy.py:18 ExploitPermission`; resolver `tools/cli_exploit_settings.py:13 _resolve_exploit_permission`).
- **PoE/PoC verification** — Independent compromise re-proof (PoE canary/executor check `tools/verification/poe_verifier.py:238 verify_compromise_sync`; PoC probe tool `tools/mcp_tools/poc_verifier.py:26 register_poc_verifier_tools`; candidate re-proof `tools/mcp_tools/verify.py:133 register_verify_tools`).
- **research.db** — Flow B legacy mission SQLite filename (`db.py:959`, docstring example `:323`).
- **retest** — Re-execution of a confirmed finding's stored PoC probe returning `STILL_OPEN`/`FIXED`/`INCONCLUSIVE` (`tools/mcp_tools/retest.py:279 retest_finding`, `:149 classify_retest_output`, `:273 register_retest_tools`).
- **run handle** — In-memory per-run owner object holding the allowlist snapshot and lifecycle state (`tools/api/run_manager.py:86 RunHandle`, `:169` active-handle map).
- **semantic matching** — Cosine-similarity skill ranking over `nomic-embed-text`, advisory-only with deterministic tag-match floor (`tools/skill_embeddings.py:95 semantic_rank`).
- **skill reselect** — Mid-run advisory skill-hint rebuild when new services/CVEs appear, rate-guarded (`tools/exploit_agent/skills.py:44 _maybe_reselect_skills`; caps `tools/config/schema.py:719`).
- **snapshot** — Opt-in fail-open rollback point before destructive actions (`tools/snapshots.py:556 SnapshotManager`, `:48 SnapshotRef`, `:607 before_destructive`).
- **tool catalog** — Phase-narrowed allow-map from phase name to tool families (`tools/exploit_agent/tool_catalog.py:198 PHASE_TOOL_FAMILIES`, `:207 select_tools_for_phase`).
- **XBEN** — Declarative benchmark suite manifest parsed into a scenario (`tools/benchmark/xben/manifest.py:53 parse_manifest`; scenario shape `tools/benchmark/models.py:293`).

```bash
#Spot-check any pointer, e.g.:
grep -n "_allowed_target_list" tools/kernel/allowlist.py | head
grep -n "class RunHandle" tools/api/run_manager.py
grep -n "def parse_manifest" tools/benchmark/xben/manifest.py
```

### Related documentation

- [attack-modules.md](attack-modules.md), [mcp-wiring.md](mcp-wiring.md), [evaluation.md](evaluation.md), [benchmarks.md](benchmarks.md), [skills.md](skills.md), [swarm.md](swarm.md), [safety-model.md](safety-model.md), [run-service.md](run-service.md), [api.md](api.md), [config-reference.md](config-reference.md)

### Source map

- `tools/campaign/orchestrator.py`, `tools/campaign/state.py`, `tools/campaign/executor.py`
- `tools/swarm/orchestrator.py`, `tools/swarm/blackboard.py`
- `tools/exploit_agent/policy.py`, `tools/cli_exploit_settings.py`, `tools/exploit_agent/tool_catalog.py`, `tools/exploit_agent/skills.py`
- `tools/kernel/allowlist.py`, `tools/kernel/audit.py`, `tools/validation_utils.py`, `tools/mcp_tools/terminal/allowlist.py`
- `tools/api/decision_broker.py`, `tools/api/event_broker.py`, `tools/api/run_manager.py`, `tools/api/persistence.py`
- `tools/benchmark/service.py`, `tools/benchmark/models.py`, `tools/benchmark/runner.py`, `tools/benchmark/xben/manifest.py`
- `tools/eval_harness.py`
- `tools/verification/poe_verifier.py`, `tools/mcp_tools/poc_verifier.py`, `tools/mcp_tools/verify.py`, `tools/mcp_tools/retest.py`, `tools/mcp_tools/hitl.py`
- `tools/killchain/machine.py`, `tools/killchain/states.py`, `tools/snapshots.py`
- `tools/skill_embeddings.py`, `tools/operator_connection/manager.py`, `tools/credential_store.py`
- `db.py`, `tools/config/schema.py`

Implementation note: `RunHandle.allowlist` snapshot semantics and the single-active-run compat accessor (`tools/api/run_manager.py:205`) were read but not exhaustively traced; treat the one-line definition above as the verified shape, not a lifecycle guarantee.
