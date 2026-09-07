# Database & Mission Persistence

## Overview

Persistence is SQLite, split across **two independent databases** plus the filesystem:

| Database | File | Owns | Written by |
|---|---|---|---|
| Flow B research DB | `research_workspace/research.db` | missions, scope, tasks, hypotheses, observations, graph, evidence metadata, findings, audit, memories, embeddings, lessons | Flow B (root `cli.py` / `agent_loop.py` shims → `legacy.*`) and Flow A's evidence bridge |
| API runtime DB | `reports/api_runtime.db` | runs, decisions, users, annotations, custom_goals, app_state | WebUI daemon (`tools/api/persistence.py`) |

Per AGENTS.md rule 2, the two flows (Flow A exploit engine, Flow B legacy research loop) **share only the `db.py` and `mission.py` schemas**. Flow A's own state lives in `exploit_workspace/<ip>/exploit_audit.jsonl` (tamper-evident JSONL, not SQLite) and is bridged into the shared `evidence` table read-only (see [Evidence bridge](#evidence-bridge-flow-a--flow-b)).

`db.py` owns the schema, migrations, ID generation, and the thread-safe `DatabaseManager` wrapper. All IDs are `{prefix}-{seq:05d}-{8hex}` (`db.py:31-34`); timestamps are ISO8601 UTC (`db.py:27-28`); JSON fields are stored as TEXT and deserialized on read.

## Where the DB files live

- **`research_workspace/research.db`** — one DB per workspace root, **not** per mission. Missions are rows inside it. `agent_loop.py:96-97` opens `workspace_root / "research.db"`; `cli.py:48` does the same. The default singleton `get_default_db()` uses `RESEARCH_WORKSPACE` env or `research_workspace/` (`db.py:803-817`).
- **`research_workspace/<mission_id>/`** — per-mission *filesystem* workspace (evidence/, reports/, logs/, tasks/) created by `MissionController._init_workspace` (`mission.py:386-402`). Evidence files live here; their metadata rows live in `research.db`.
- **`reports/api_runtime.db`** — API daemon state, `ApiPersistence(reports_dir)` (`tools/api/persistence.py:90-95`). Deliberately separate so the daemon never touches Flow B's schema (`tools/api/persistence.py:3`).
- **`exploit_workspace/<ip>/exploit_audit.jsonl`** — Flow A's append-only audit log (not SQLite); promoted into `evidence` via `promote_exploit_audit` (`evidence.py:288-340`).
- No top-level `sandbox/` directory exists — sandbox code lives at `tools/sandbox/` (manager, docker backend/lifecycle, network) with the worker image at `docker/sandbox/` (`tools/sandbox/manager.py:1-14`; `docker/sandbox/Dockerfile:1-3`).
- Canonical audit helpers live at `tools/kernel/audit.py` (credential redaction + audit decorators), re-exported by `tools/mcp_shared.py` for backwards compat (`tools/kernel/audit.py:1-11`; `tools/mcp_shared.py:33-46`).

## Schema (Flow B research DB)

Schema version: **10** (`db.py:23`). DDL in `db.py:39-312`; migrations in `db.py:390-863`.

- v6 — `graph_nodes_v2` / `graph_edges_v2` typed intelligence-graph pair (`db.py:697-746`); legacy `graph_nodes` / `graph_edges` stay untouched.
- v7 — belief-state columns on `hypotheses` + `belief_transitions` log (`db.py:749-778`).
- v8 — `evidence.provenance_json` + `evidence_references` links (`db.py:781-803`).
- v9 — `decision_telemetry` log (`db.py:806-838`).
- v10 — `attempt_fingerprints` dedup table (`db.py:841-863`).

### ER-style diagram

```text
missions 1 ──< scope_rules
   │
   ├──< tasks 1 ──< observations
   │     │
   │     └──< outcome_assessments >── hypotheses (1 per mission+key)
   │                                     └──< belief_transitions (v7)
   │
   ├──< graph_nodes 1 ──< graph_edges (from/to node FKs)
   ├──< graph_nodes_v2 1 ──< graph_edges_v2 (v6, scope-based)
   ├──< evidence (task_id FK nullable, finding_id loose ref)
   │     └──< evidence_references (v8, source_table/source_id loose ref)
   ├──< findings
   ├──< audit_logs
   ├──< memories
   ├──< decision_telemetry (v9)
   ├──< attempt_fingerprints (v10)
   └──< embeddings (source_table/source_id loose ref)

lessons (global, no mission FK — cross-mission learning)
_migrations (version ledger)
```

### Table reference

| Table | Columns | Written by | Read by |
|---|---|---|---|
| `missions` | id, program_name, objective, risk_profile, testing_modes_json, target_assets_json, allowed_assets_json, disallowed_assets_json, forbidden_actions_json, rate_limits_json, accounts_json, notes, status, created_at, updated_at | `MissionController.create_from_config` (`mission.py:334-377`), `update_status` (`mission.py:415-424`) | `MissionController.load_mission` (`mission.py:405-412`), resume path (`agent_loop.py:119`) |
| `scope_rules` | id, mission_id, rule_type (allow/deny), target_type (domain/ip/cidr/wildcard_domain/url_prefix/action), pattern, notes, created_at | `db.add_scope_rule` (`db.py:748-762`) via `mission.py:354-370` | `ScopeGate` (Flow B), `db.get_scope_rules` (`db.py:764-771`) |
| `tasks` | id, mission_id, phase, target, asset_type, objective, hypothesis, preconditions_json, allowed_tools_json, risk_level, priority, required_human_approval, success_criteria_json, stop_conditions_json, status, result_summary, block_reason, evidence_refs_json, hypothesis_id, check_fingerprint, created_at, updated_at | `TaskQueue.create_task` (`task_queue.py:55-117`), status updates (`task_queue.py:141-201`), `HypothesisRepository.persist_assessment` blocks stale pending tasks (`outcome_judge.py:540-552`) | `TaskQueue.get_next_task` (`task_queue.py:119-139`), `list_*` (`task_queue.py:216-265`), `HypothesisRepository.prepare_task` dedup check (`outcome_judge.py:388-398`) |
| `hypotheses` | id, mission_id, hypothesis_key (sha256 of target+statement, UNIQUE per mission), statement, target, status, confidence, evidence_refs_json, attempt_count, independent_check_count, check_history_json, candidate_checks_json, last_information_value, created_at, updated_at, last_assessed_at | `HypothesisRepository.ensure_for_task` (`outcome_judge.py:317-372`), `persist_assessment` (`outcome_judge.py:520-539`), v4 migration backfill (`db.py:606-679`) | `HypothesisRepository.get/list_all/list_unresolved` (`outcome_judge.py:401-426`), `TaskQueue.get_next_task` join (`task_queue.py:121-124`) |
| `outcome_assessments` | id, mission_id, task_id (UNIQUE), hypothesis_id, execution_outcome, hypothesis_status, confidence, satisfied_criteria_json, unsatisfied_criteria_json, triggered_stop_conditions_json, evidence_refs_json, reasoning, information_value, another_investigation_justified, check_fingerprint, independent_check, attempt_count, created_at | `HypothesisRepository.persist_assessment` (`outcome_judge.py:490-519`) | `get_assessment_for_task` (`outcome_judge.py:570-576`) |
| `observations` | id, task_id, target, tool_name, input_summary, output_summary, facts_json, new_assets_json, new_endpoints_json, new_parameters_json, new_technologies_json, new_identities_json, new_objects_json, interesting_signals_json, possible_findings_json, dead_ends_json, recommended_followup_tasks_json, memory_updates_json, graph_updates_json, evidence_refs_json, hypothesis_evidence_json, confidence, usefulness, created_at | `agent_loop._save_observation` (`agent_loop.py:1287-1327`) | `OutcomeJudge.judge` (via observation mapping, `outcome_judge.py:635-661`), observer embedding (`observer.py:154`) |
| `graph_nodes` | id, mission_id, type, value, metadata_json, created_at | `TargetGraph.add_node` (`target_graph.py:48-66`) | `TargetGraph.query_graph` / `find_untested_assets` / `find_permission_boundaries` / `find_object_id_candidates` / `summarize_graph` (`target_graph.py:91-190`) |
| `graph_edges` | id, mission_id, from_node_id, to_node_id, relation, metadata_json, created_at | `TargetGraph.add_edge` (`target_graph.py:68-87`) | same queries as nodes |
| `evidence` | id, mission_id, task_id (nullable FK), finding_id (loose ref), type, path, summary, hash (sha256), metadata_json, created_at | `EvidenceStore.save` (`evidence.py:55-125`), Flow A bridge `promote_exploit_audit` / `record_run_output` (`evidence.py:288-421`) | `EvidenceStore.get/list_for_task/list_for_finding/list_for_mission` (`evidence.py:127-196`), `FindingVerifier.validate_finding` (`finding_verifier.py:181-192`), `ReportGenerator` |
| `findings` | id, mission_id, title, vuln_class, affected_asset, affected_endpoint, summary, impact, confidence, impact_score, status, rejection_reason, evidence_refs_json, reproduction_steps_json, missing_validation_json, created_at, updated_at | `FindingVerifier.create_candidate` (`finding_verifier.py:86-126`), status transitions (`finding_verifier.py:130-261`) | `FindingVerifier` list/get (`finding_verifier.py:265-302`), `ReportGenerator` (`report_generator.py:339-358`) |
| `audit_logs` | id, mission_id, task_id, event_type, message, metadata_json, created_at | `db.log_audit` (`db.py:773-787`) — mission_created, status_changed, outcome_judgment, etc. | CLI/status tooling |
| `memories` | id, mission_id, memory_type, target, fact, tags_json, confidence, metadata_json, created_at | `MemoryManager.remember` (`memory.py:71-113`), `mark_dead_end` (`memory.py:194-202`) | `MemoryManager.retrieve` / `retrieve_relevant` / `summarize_target` (`memory.py:115-231`) |
| `embeddings` | id, mission_id, source_table, source_id, embedding_json, created_at | `SemanticMemoryManager.store_embedding` (`tools/semantic_memory.py:110-129`) | `find_similar` (`tools/semantic_memory.py:175-241`) |
| `lessons` | id, pattern_hash, target_signature, action_type, outcome, confidence, embedding_json, metadata_json, text, created_at | `SemanticMemoryManager.store_lesson` (`tools/semantic_memory.py:131-173`), `ExperienceStore.record_outcome` (`tools/experience_store.py:96`) | `find_similar_lessons` (`tools/semantic_memory.py:243-333`), `ExperienceStore` Bayesian priors (`tools/experience_store.py:179-261`), `tools/skill_feedback.py` |
| `graph_nodes_v2` | id, scope, node_type, value, properties_json, confidence, status, first_seen, last_seen, evidence_refs_json, observation_count, contradiction_count, source, created_at | v6 migration (`db.py:697-746`) | Implementation note: consumers not traced in this pass |
| `graph_edges_v2` | id, scope, source_node_id, target_node_id, edge_type, properties_json, confidence, source, first_seen, last_seen, evidence_refs_json, observation_count, contradiction_count, created_at | v6 migration (`db.py:697-746`) | Implementation note: consumers not traced in this pass |
| `belief_transitions` | id, hypothesis_id, from_status, to_status, reason, evidence_refs_json, created_at | v7 migration (`db.py:749-778`) | Implementation note: consumers not traced in this pass |
| `evidence_references` | id, source_table, source_id, evidence_id, relation, weight, created_at | v8 migration (`db.py:781-803`) | Implementation note: consumers not traced in this pass |
| `decision_telemetry` | id, mission_id, run_id, timestamp, agent, event_type, decision, candidate_paths_json, selected_path, rejected_paths_json, ranking_scores_json, confidence, info_gain, graph_nodes_json, hypotheses_json, memory_retrieved_json, critic_objections_json, model_used, tokens, latency_ms, created_at | v9 migration (`db.py:806-838`) | Implementation note: consumers not traced in this pass |
| `attempt_fingerprints` | id, mission_id, fingerprint, target, service, action_family, status, detail, evidence_snapshot_json, repeat_count, retry_justification, timestamp, created_at | v10 migration (`db.py:841-863`) | Implementation note: consumers not traced in this pass |
| `_migrations` | version, applied_at | `ensure_schema` (`db.py:376-388`) | same |

### Status enums

**missions.status** — `active`, `paused`, `completed` (`mission.py:416`).

**tasks.status** — `pending`, `running`, `blocked`, `complete`, `failed`, `needs_approval` (`db.py:89-91`).
**tasks.phase** — `recon`, `analysis`, `test`, `validate`, `exploit`, `post_exploit`, `report` (`db.py:77`). Legacy aliases (`validation`, `exploitation`, `post-exploit`, `service_enumeration`, …) are normalized on insert (`task_queue.py:31-42`) and remapped by the v2 migration (`db.py:406-488`).

**hypotheses.status** — `open`, `confirmed`, `refuted`, `inconclusive`, `exhausted` (`db.py:108-110`). Terminal: confirmed/refuted/exhausted (`outcome_judge.py:39-45`).

**outcome_assessments.execution_outcome** — `succeeded`, `failed`, `blocked` (`db.py:130-132`).
**outcome_assessments.hypothesis_status** — same enum as hypotheses.

**findings.status** — `candidate`, `needs_validation`, `rejected`, `duplicate_suspected`, `validated`, `report_ready` (`db.py:233-235`). Transition map in `finding_verifier.py:33-40`:

```text
candidate ──> needs_validation / rejected / duplicate_suspected
needs_validation ──> validated / rejected / duplicate_suspected
duplicate_suspected ──> rejected / validated / needs_validation
validated ──> report_ready / rejected
report_ready ──> rejected
rejected ──> (terminal)
```

**evidence.type** — `raw_output`, `http_response`, `screenshot`, `note`, `diff`, `file`, `http_request`, `structured_json` (`db.py:210-212`).

**memory_type** — `working`, `episodic`, `semantic`, `target`, `hypothesis`, `dead_end`, `finding_note` (`db.py:259`); legacy aliases normalized in `memory.py:36-53`.

**lessons.outcome** — `success`, `failure`, `partial`, `unknown` (`db.py:283`).

## Mission lifecycle in the DB

```text
create_from_config (mission.py:312-383)
  → validate (mission.py:197-234)
  → INSERT missions (status='active') + scope_rules (allow/deny/action)
  → audit_logs 'mission_created'
  → workspace dirs (research_workspace/<id>/…)

run loop (legacy/agent_loop.py)
  → tasks created (pending) → picked by priority → running
  → observation + evidence + outcome assessment per task
  → hypothesis status transitions (open → confirmed/refuted/inconclusive/exhausted)
  → terminal hypothesis blocks sibling pending tasks (outcome_judge.py:540-552)

update_status (mission.py:415-424)  → active / paused / completed
resume (agent_loop.py:100-128)      → load_mission by id; DB row is source of truth
```

Resume is "load the mission row and re-point every manager at it" — the DB holds all resumable state (`agent_loop.py:100-109`). `reset_stale_running` re-queues tasks left `running` by a crash back to `pending` (`task_queue.py:181-201`).

## Evidence → finding → outcome pipeline

1. **Tool runs** → `ToolRouter` saves raw output via `EvidenceStore.save` (`tool_router.py:200`): file written under `research_workspace/<mission_id>/evidence/<subdir>/`, sha256 hash + summary + metadata row in `evidence` (`evidence.py:55-125`).
2. **Observer** parses output into a structured `Observation` (facts, new assets/endpoints/parameters/technologies, interesting signals, possible findings, dead ends, hypothesis evidence) — persisted by `agent_loop._save_observation` (`agent_loop.py:1287-1327`).
3. **OutcomeJudge** (`outcome_judge.py:190-307`) — deterministic, evidence-grounded. Separates *whether a tool ran* from *whether evidence resolved the hypothesis*:
   - `execution_outcome` from the execution result (`_execution_outcome`, `outcome_judge.py:622-632`): `succeeded`/`failed`/`blocked` (blocked = scope/approval gate, consumes no attempt).
   - `hypothesis_status` from structured observation fields only — raw-output words like "success" are not confirmation (`_structured_criterion_met`, `outcome_judge.py:690-724`; stopword list `outcome_judge.py:925-959`).
   - Terminal judgment requires `>= min_evidence_references` (default 1) persisted evidence refs; support/refutation scores from `hypothesis_evidence` polarity entries and facts (`_explicit_evidence_scores`, `outcome_judge.py:789-815`); contradiction detection (`_texts_contradict`, `outcome_judge.py:832-862`).
   - `confirmed` at support ≥ 0.75, `refuted` at refutation ≥ 0.75, `exhausted` after `max_inconclusive_attempts` (default 3) materially different checks (`outcome_judge.py:248-262`).
   - `information_value` (0-1) weights usefulness/structural/evidence/resolution (`_information_value`, `outcome_judge.py:865-895`).
4. **HypothesisRepository.persist_assessment** (`outcome_judge.py:428-568`) atomically inserts the `outcome_assessments` row, appends to `check_history_json`, updates hypothesis status/confidence/counters, blocks sibling pending tasks when terminal, and writes an `outcome_judgment` audit row.
5. **Dedup guards**: `build_hypothesis_key` (sha256 of normalized target+statement, `outcome_judge.py:579-581`) and `build_check_fingerprint` (sha256 of tool+args/method, `outcome_judge.py:584-602`). `prepare_task` raises `ClosedHypothesisError` / `DuplicateInvestigationError` (`outcome_judge.py:374-399`).
6. **FindingVerifier** (`finding_verifier.py`): `create_candidate` inserts a `candidate` finding with heuristic `impact_score` (`_score_impact`, `finding_verifier.py:306-329`). `validate_finding` runs the 10-point checklist (scope, evidence on disk, summary, impact, vuln class, reproduction steps) and auto-transitions to `validated` when complete (`finding_verifier.py:146-226`). `mark_report_ready` gates on `validated` (`finding_verifier.py:238-246`). Missing items can be turned back into `validate`-phase tasks (`generate_validation_tasks`, `finding_verifier.py:340-377`).

### Evidence bridge (Flow A → Flow B)

`promote_exploit_audit` (`evidence.py:288-340`) reads `exploit_workspace/<ip>/exploit_audit.jsonl` and writes one `structured_json` evidence row per MCP/Flow-A record, stamped with `audit_hash` + `row_attempt_id` in metadata so consumers can join back. Purely additive — the audit JSONL is never mutated (`evidence.py:258-262`). `task_id` is intentionally left empty because audit attempt ids are not Flow B task ids (`evidence.py:368-371`).

## Memory & embeddings

- **`memories`** table: `MemoryManager.remember` (`memory.py:71-113`) normalizes legacy type aliases, then optionally stores an embedding via `SemanticMemoryManager.store_embedding` (`memory.py:106-112`).
- **`embeddings`** table: vector JSON per (source_table, source_id) — memories, observations, etc. Generated by Ollama `/api/embeddings` (`tools/semantic_memory.py:48-106`), default model `nomic-embed-text`, host from `ollama.embed_host` (falls back to `ollama.host`; cloud path sends `OLLAMA_API_KEY` bearer, `tools/semantic_memory.py:73-77`). Similarity is numpy cosine in Python (`find_similar`, `tools/semantic_memory.py:175-241`); zero-length embeddings are skipped.
- **`lessons`** table: cross-mission learning. `store_lesson` (`tools/semantic_memory.py:131-173`) persists text + real embedding; `ExperienceStore.record_outcome` (`tools/experience_store.py:96`) writes Bayesian outcome rows with `embedding_json='[]'` (tracked, not recallable). `find_similar_lessons` (`tools/semantic_memory.py:243-333`) feeds `payload_crafter` and exploit reflection. The `text` column was added in migration v5 (`db.py:695-711`) — previously the lesson text was embedded but never persisted.
- `retrieve_relevant` (`memory.py:146-192`): exact target match first, semantic fallback across missions embedding the *context* (not the bare IP, which embeds to a meaningless vector).

## Task queue mechanics

`TaskQueue` (`task_queue.py`) is a persistent priority queue over the `tasks` table:

- `create_task` (`task_queue.py:55-117`) resolves hypothesis identity + check fingerprint first (`HypothesisRepository.prepare_task`), normalizes phase/risk/status, and scores priority if not supplied.
- `get_next_task` (`task_queue.py:119-139`) — the core query:

```sql
SELECT t.* FROM tasks t
LEFT JOIN hypotheses h ON h.id=t.hypothesis_id
WHERE t.mission_id=? AND t.status='pending'
  AND (h.id IS NULL OR h.status IN ('open','inconclusive'))
ORDER BY t.priority DESC, t.created_at ASC LIMIT 1
```

- Priority scoring (`_score_priority`, `task_queue.py:304-380`): phase bonus (exploit 30 > validate 25 > test 20), auth-boundary/object-reference/sensitive-data keyword bonuses, hypothesis novelty, information value, minus attempt/duplicate/scope-risk/noise penalties, clamped 0-100.
- `deduplicate` removes same (target, objective, phase) pending tasks (`task_queue.py:269-283`); `reprioritize` re-scores all pending (`task_queue.py:285-300`); `reset_stale_running` is the crash-resume primitive (`task_queue.py:181-201`).

## Target graph

`TargetGraph` (`target_graph.py`) models the attack surface in `graph_nodes`/`graph_edges`. Node types: program, asset, host, domain, ip, service, web_app, api, endpoint, parameter, identity, role, session, object, permission_boundary, technology, evidence, finding (`target_graph.py:25-29`). Edge relations: owns, exposes, resolves_to, serves, requires_auth, accepts_parameter, returns_object, belongs_to_user, accessible_by, tested_by, produced_evidence, indicates, blocked_by_scope, related_to (`target_graph.py:31-36`). Notable queries: `find_untested_assets` (no `tested_by` edge, `target_graph.py:129-141`), `find_permission_boundaries`, `find_object_id_candidates` (endpoint/parameter values matching id/uuid/object/user/order/account, `target_graph.py:152-162`), `summarize_graph` for LLM context.

## Report generation

`ReportGenerator` (`report_generator.py`) requires `report_ready` status (`report_generator.py:165-170`), renders the strict template (`REPORT_TEMPLATE`, `report_generator.py:53-135`) with severity from `impact_score` (`_severity_label`, `report_generator.py:39-48`), and writes `research_workspace/<mission_id>/reports/<finding_id>.md` (`report_generator.py:254-255`). `generate_summary_report` aggregates all report_ready/validated/candidate/rejected findings into `summary_report.md` (`report_generator.py:282-335`). `export_report` returns structured JSON (`report_generator.py:259-280`). Evidence refs are listed by id; content is fetched via `EvidenceStore.get`.

## API runtime DB (`reports/api_runtime.db`)

Separate schema, version **5** (`tools/api/persistence.py:18`), thread-safe via a single `threading.Lock` (`tools/api/persistence.py:164`):

- **`runs`** — id, created_at, updated_at, state, request_json, preview_json, result_json, resumed_from, error, cancelled_at, title, is_demo (`tools/api/persistence.py:27-40`). Live states (`draft`, `preparing`, `awaiting_confirmation`, `running`, `awaiting_input`, `queued`, `cancelling`) are marked `interrupted` with pending decisions expired on daemon startup via `recover_interrupted` (`tools/api/persistence.py:492-510`).
- **`decisions`** — id, run_id (FK cascade), kind, prompt_text, required_text, options_json, status (pending/answered/expired), answer, created_at, answered_at (`tools/api/persistence.py:42-54`). Written by `ApiDecisionProvider.request` (`tools/run_service/providers.py:210`), answered via `answer_decision` (`tools/api/persistence.py:537-558`).
- **`users`** — id, username (UNIQUE), password_hash, password_salt, created_at, last_login (v3, `tools/api/persistence.py:65-72`).
- **`annotations`** — id, run_id (FK cascade), user_id, username, body, finding_ref, created_at (v3, `tools/api/persistence.py:74-83`).
- **`custom_goals`** — id, name (UNIQUE, NOCASE), objective, created_at, updated_at (v5, `tools/api/persistence.py:87-95`).
- **`app_state`** — key, value tombstone/flag store (v4, `tools/api/persistence.py:121-125`); `runs.is_demo` flags demo sessions (`tools/api/persistence.py:39`).
- Migrations: v2 `runs.title` (`tools/api/persistence.py:101-103`); v3 users + annotations (`tools/api/persistence.py:108-119`); v4 `is_demo` + `app_state` (`tools/api/persistence.py:122-125`); v5 custom_goals (`tools/api/persistence.py:128-134`). `title` holds AI-generated session titles from `tools/api/session_titler.py` (default `TITLE_MODEL = "gemma4:31b-cloud"`, persisted via `update_run_title`, `tools/api/persistence.py:355-370`).

## Migration & back-compat

- `ensure_schema` (`db.py:377-387`) runs DDL (idempotent `CREATE TABLE IF NOT EXISTS`) then applies pending migrations 1..`_SCHEMA_VERSION`, recording each in `_migrations`.
- v2 — `tasks` phase enum widened to include `exploit`/`post_exploit`; table rebuilt with FK off, legacy phase values remapped (`db.py:415-496`).
- v3 — created_at indexes for high-volume tables (`db.py:498-517`).
- v4 — adds `hypotheses` + `outcome_assessments` tables, `tasks.hypothesis_id`/`check_fingerprint`, `observations.hypothesis_evidence_json`; backfills hypothesis identity for historical tasks without inferring success from execution status (`db.py:520-679`).
- v5 — `lessons.text` column (`db.py:682-694`).
- v6 — `graph_nodes_v2` / `graph_edges_v2` typed intelligence-graph tables; legacy graph tables untouched (`db.py:697-746`).
- v7 — belief-state columns on `hypotheses` + `belief_transitions` log (`db.py:749-778`).
- v8 — `evidence.provenance_json` + `evidence_references` links (`db.py:781-803`).
- v9 — `decision_telemetry` log (`db.py:806-838`).
- v10 — `attempt_fingerprints` dedup table with unique `(mission_id, fingerprint)` index (`db.py:841-863`).
- API DB `_init_db` (`tools/api/persistence.py:191-267`) runs `_DDL` then applies `_MIGRATION_V2`..`_MIGRATION_V5` idempotently; v2 adds `runs.title` (`tools/api/persistence.py:101-103`), v3 adds users + annotations (`tools/api/persistence.py:108-119`), v4 adds `runs.is_demo` + `app_state` (`tools/api/persistence.py:122-125`), v5 adds custom_goals (`tools/api/persistence.py:128-134`).
- Extension rule: schema changes go in `DDL` + `_SCHEMA_VERSION` + a `_migrate_vN_*` helper (`docs/extension-guide.md:224-225`).
- Back-compat notes: `get_default_db` ensures the schema (incl. `lessons`) exists on fresh Flow A installs (`db.py:955-969`); the legacy resume path calls `ensure_schema` before reading (`legacy/agent_loop.py:118`); `_row_to_*` helpers tolerate missing JSON fields; `_coerce_state` accepts both `HypothesisState` and mappings (`outcome_judge.py:1009-1036`).
- Root Flow B entry points (`cli.py`, `agent_loop.py`, `mission.py`, `evidence.py`, `task_queue.py`, `memory.py`, `tool_router.py`, `finding_verifier.py`, `report_generator.py`, `observer.py`) are `DeprecationWarning` shims re-exporting `legacy.*` (`cli.py:1-9`; `legacy/README.md:13-17`).

## Related documentation

- [Runtime flows](runtime-flows.md) — Database-Backed Research Loop vs Exploit Session Flow.
- [Architecture](architecture.md) — Flow A vs Flow B split and shared schemas.
- [Outcome Judgment and Evidence Handling](outcome-evidence.md) — evidential versus execution status and the Flow A audit trail.
- [Disposable Execution Sandbox](sandbox.md) — sandbox execution funnel and worker image.
- [Extension Guide](extension-guide.md) — adding persistent data (`DDL` + `_SCHEMA_VERSION` + `_run_migration`).
- [API Persistence](api/persistence.md) — the `api_runtime.db` schema, migrations, runs, and decisions.

## Source map

- `db.py`
- `tools/api/persistence.py`
- `tools/api/session_titler.py`
- `tools/run_service/providers.py`
- `tools/kernel/audit.py`
- `tools/mcp_shared.py`
- `tools/sandbox/manager.py`
- `docker/sandbox/Dockerfile`
- `cli.py`
- `agent_loop.py`
- `mission.py`
- `legacy/README.md`
- `legacy/cli.py`
- `legacy/agent_loop.py`
- `docs/extension-guide.md`
