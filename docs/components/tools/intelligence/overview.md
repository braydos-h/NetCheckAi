---
title: Intelligence — Overview
package: tools/intelligence
subpackages: [belief, evidence, fingerprint, graph, schemas, adapters]
---

# Intelligence — Overview (`tools/intelligence/`)

AttackGraph v2, belief modelling, evidence provenance, attempt fingerprinting,
structured schemas, and legacy adapters. 31 Python files across 6 subpackages + package `__init__.py`.

**Wiring status (verified against callers — do not describe all of this as a
Flow A primitive):**

- `graph/` — **active production path**: wrapped by `tools/api/graph_service.py`
  and `tools/api/graph_builder.py` behind the WebUI attack-path DAG API
  (`GET /api/v1/runs/{run_id}/graph`, default-off via `api.graph_route`
  per `tools/api/routes/graph.py:137`); the store is also the killchain
  backend (`tools/killchain/machine.py:30`, `tools/mcp_tools/killchain.py:101`,
  lazily in `tools/exploit_agent/runner/_impl.py:110` and
  `tools/campaign/phases.py:779` when `killchain.enabled`).
- `adapters/` — **legacy Flow B path (best-effort)**: `legacy/observer.py:163`
  (`ObserverAdapter.infer_confidence`) and `legacy/finding_verifier.py:214`
  (`FindingAdapter.ensure_reproduction_steps`) import them lazily;
  `AttackPhaseBridge.to_orchestrator` maps planner phases in
  `tools/campaign/executor.py:526`; the remaining adapters are test-only.
- `belief/`, `evidence/`, `fingerprint/`, `schemas/` — **scaffold / test-only**.
  Nothing in Flow A (`main.py`, the exploit loop, `mcp_exploit_server.py`)
  imports them; `fingerprint.tracker.is_permanent_failure` feeds
  `ObserverAdapter.classify_dead_end` (`adapters/observer_adapter.py:96`),
  which is in turn consumed by the legacy observer. `SafeSchemaLoader` has no
  production caller (verified: only tests import it).

## Layout

| Subpackage | Files | Purpose | Status |
|---|---|---|---|
| `belief/` | `state.py`, `confidence.py`, `store.py` | Hypothesis state + confidence calculus | scaffold (legacy adapter consumer) |
| `evidence/` | `reference.py`, `store.py`, `provenance.py` | Immutable refs + store + lineage | scaffold / test-only |
| `fingerprint/` | `attempt.py`, `tracker.py` | Safe retry/fingerprinting | scaffold (tracker used by legacy adapter) |
| `graph/` | `types.py`, `store.py`, `merge.py`, `traversal.py` | Attack graph | **active (WebUI API)** |
| `schemas/` | `base.py`, `validator.py`, `graph.py`, `outcome.py`, `planner.py`, `critic.py`, `strategy.py` | LLM output contracts | scaffold / test-only |
| `adapters/` | `planner_adapter.py`, `finding_adapter.py`, `memory_adapter.py`, `observer_adapter.py`, `target_graph_adapter.py` | Bridge to legacy surfaces | legacy Flow B (observer + finding adapters) |

---

## Belief (`belief/`)

### `state.py`

| Symbol | Kind | Line |
|---|---|---|
| `HypothesisStatus` | Enum | `unknown|suspected|likely|confirmed|refuted|exhausted` |
| `EvidencePolarity` | Enum | `supporting|contradicting|neutral` |
| `EvidenceObservation` | dataclass | `evidence_ref, polarity, weight, source, timestamp, independent, agent_interpretation` |
| `HypothesisState` | dataclass | `hypothesis_id, statement, target, current_confidence, supporting/contradicting_evidence` |
| `BeliefState` | class | `add_hypothesis, get, register_evidence/register_observation, next_discriminating_check, snapshot/load, top_unresolved, to_json/from_json` |

`compute_status` (`confidence.py:119`): `CONFIRMED` at confidence ≥ `0.75` with supporting evidence, `REFUTED` at ≤ `0.25` with contradicting evidence — a bare numeric claim without evidence never qualifies. Default update rule is `BAYESIAN_BETA` (pseudo-count `K = max(2, independent_observation_count)`); dependent (re-stated) evidence counts at `0.6` via `_independence_bonus`. `NonModelConfidence` / `TaggedConfidence` are separate non-belief scales (tool success, path viability, …) that must never be compared with hypothesis confidence.

### `store.py`

| Symbol | Kind | Line |
|---|---|---|
| `BeliefStore` | class | `upsert/get/delete/list_all/list_by_status/find_by_statement` |

In-memory store keyed by `mission_id`; persists nothing (caller persists). No confidence gating.

---

## Evidence (`evidence/`)

### `reference.py`

| Symbol | Kind | Line |
|---|---|---|
| `EvidenceSource` | Enum | `tool_output|banner|scanner|nvd_cve|exploit_db|manual|agent_observation|http_response|file_artifact|screenshot|note|target_side_oracle` |
| `EvidenceLevel` | Enum | `raw|derived|summarized` |
| `EvidenceReference` | dataclass | `ref_id, source_tool, target, timestamp, content_hash, create/from_dict/to_dict/normalize` |

`EvidenceReference.create(source_tool, target, timestamp, content, ...)` hashes content (`hash_content`), `normalize()` collapses whitespace / strips controls / trims to 500 chars, `_make_ref_id` stable. `CredentialRef.from_reference` (`graph/types.py:137`) extracts credential refs from `ev:credential:…` strings.

### `store.py`

| Symbol | Kind | Line |
|---|---|---|
| `EvidenceStoreV2` | class | `put/get/list_all/find_by_source_tool/find_by_target/count` |

Immutable append-only keyed by `ref_id`.

### `provenance.py`

| Symbol | Kind | Line |
|---|---|---|
| `ProvenanceEntry` | dataclass | `evidence_id, source, produced_by, producing_action, timestamp, content_hash, parent_evidence_id, confidence` |
| `ProvenanceChain` | class | `walk, find_by_source, lineage, confidence_at, to_dict/from_dict` |
| `ProvenanceTracker` | class | `register_root/register_derived, chain_for, summary` |

Root → leaf chain (`provenance.py:39`); `confidence_at` multiplies hop confidences (unknown id → `0.0`); `register_derived` raises `ValueError` on self-parent or unknown parent. Built for the evidence DAG, not tied to `HypothesisState`.

---

## Fingerprint (`fingerprint/`)

### `attempt.py`

| Symbol | Kind | Line |
|---|---|---|
| `AttemptStatus` | Enum | `attempted|inconclusive|failed|blocked|refuted|confirmed` |
| `ActionFamily` | Enum | `recon_scan|port_scan|service_banner|cve_check|exploit|brute_force|web_request|os_fingerprint|cred_validation|script_exec|tool_other` (+ `for_tool` mapping) |
| `Attempt` | dataclass | `target, service, action_family, parameters, hypothesis, technique_category, expected_observation; fingerprint()` |
| `RetryJustification` | Enum | `new_version_evidence|new_identity_context|service_state_changed|new_configuration_evidence|different_validation_method|none` |
| `RetryJustifier` | class | `evaluate(attempt, evidence_snapshot), describe` |
| `mask_secrets` | def | Copy with `password/pass/secret/token/key` values → `"<redacted>"` |

`fingerprint()` canonicalizes (lowercased target/service/hypothesis/category/observation, order-insensitive sorted params) then sha256. `RetryJustifier.evaluate` diffs the snapshot against its `previous_evidence` key, first matching change wins. `is_permanent_failure` / `PERMANENT_FAILURE_MARKERS` live in `tracker.py`, not `attempt.py`.

### `tracker.py`

| Symbol | Kind | Line |
|---|---|---|
| `AttemptTracker` | class | `record, has_attempted, status_of, is_repetition, all_fingerprints, retry_history, register_evidence_change, summary, clear` |
| `is_permanent_failure(output)` | def | Case-insensitive marker match (9 markers: scope, permission, unreachable, refused, not installed, …) |

`record` dedups on fingerprint (repeat bumps `repeat_count`); `is_repetition` returns `(bool, RetryJustification, detail)` — terminal FAILED/REFUTED retries need material evidence change, BLOCKED is deliberately non-terminal. In-memory, one `threading.Lock`. No production caller outside tests and `ObserverAdapter.classify_dead_end`.

---

## Graph (`graph/`)

### `types.py`

| Symbol | Kind | Line |
|---|---|---|
| `NodeType` | Enum | `asset|host|domain|ip|service|port|endpoint|application|technology|version|identity|role|credential_reference|trust_boundary|network_segment|vulnerability_candidate|finding|hypothesis|evidence|capability|security_control|observation` (unknown → `observation`) |
| `EdgeType` | Enum | `resolves_to|hosts|exposes|runs|depends_on|reachable_from|authenticates_to|has_role|trusts|related_to|supported_by|contradicted_by|derived_from|affected_by|protected_by|connected_to|same_as|observed_on` (unknown → `related_to`) |
| `NodeStatus` | Enum | `unknown|suspected|likely|confirmed|refuted|exhausted` |
| `GraphNode` / `GraphEdge` / `GraphUpdate` | dataclass | `to_dict/from_dict, redact_properties, make_evidence_ref` |

`GraphNode` holds `node_id, node_type, value, scope, properties, confidence, first_seen/last_seen, evidence_refs, observation/contradiction_count, status, source`; `to_dict` redacts credential-like property values via `redact_properties` (`credential|password|secret|token|key` → `"***"`). `make_evidence_ref(source_tool, target, timestamp, content_hash, ...)` returns `ev:` compact refs; `_cred_evidence_ref` points at protected-store entries. `_enum_or_default` safe coercion.

### `store.py`

| Symbol | Kind | Line |
|---|---|---|
| `AttackGraphStore` | class | `upsert_node/get_node/get_node_by_value/upsert_edge/delete_node/query_nodes/query_edges/neighbors/paths/summary/to_graph_nodes/to_graph_edges/close` |

SQLite-backed (`agv2_nodes` / `agv2_edges` / `agv2_meta`, `UNIQUE(scope, node_type, value)`); one `threading.RLock`, WAL mode. `_norm_value` case-folds `IP/HOST/DOMAIN/ASSET/ENDPOINT`. `to_graph_nodes` / `to_graph_edges` export full lists for `GraphTraversal`. `TargetGraphV2Adapter` bridges legacy `TargetGraph` reads, not the store backend.

### `traversal.py`

| Symbol | Kind | Line |
|---|---|---|
| `GraphTraversal(nodes, edges)` | class | `nodes_of_type, edges_of_type, neighbors, paths, path_exists, subgraph` (no `walk`) |

Pure queries over caller-supplied arrays (no store import, no cycles); all bounded (`max_hops` / `max_length` / `max_paths` / `max_nodes`, optional `scope` filter). `paths` enumerates simple paths cycle-safe; `subgraph` returns `(nodes, internal_edges, boundary_edges)`.

### `merge.py`

| Symbol | Kind | Line |
|---|---|---|
| `GraphMergeEngine(store)` | class | `apply(graph_update), preview, _check_node_conflict, _conflict` |
| `GraphMergeConflict` | dataclass | `edge_type, node_value, reason, existing_confidence, proposed_confidence` |
| `GraphMergeError` | exception | Missing edge endpoint (`ValueError` from the store, re-raised) |

Applies `GraphUpdate {node_updates[], edge_updates[], source_agent, timestamp, reason}` — nodes first, then edges; conflicting node mutations are skipped, the rest still apply. Merge key is `(scope, value)` with case-folding (`_CASE_FOLD_TYPES`). Tolerance `_CONFIDENCE_TOLERANCE = 0.2`.

---

## Schemas (`schemas/`)

| File | Export | Contract |
|---|---|---|
| `base.py` | `BaseSchema, ValidationResult{valid, errors, repaired, message}` | `validate(raw)`, `repair(raw, errors)`, `coerce(raw)`, `safe_load(raw)`; helpers `_safe_enum, _require_str, _clamp_float` |
| `validator.py` | `SafeSchemaLoader(validator, default_factory, schema_name)` | `extract_json_block`, `parse_json_block`, `load(raw_json_str)` |
| `graph.py` | `GraphMutationProposal{node, edge, mutation, confidence, evidence_ref, reason}, GraphMutationSchema` | `mutation ∈ add_node|add_edge|update_confidence|remove_node` (repair → `update_confidence`) |
| `outcome.py` | `OutcomeAssessment{verdict, confidence, supporting/contradictory_evidence, criteria_satisfied/not_satisfied, next_recommended_evidence, explanation}, OutcomeAssessmentSchema` | `verdict ∈ confirmed|refuted|inconclusive|exhausted|unknown` (repair → `unknown`) |
| `planner.py` | `PlannerProposal{hypothesis_id, statement, target, confidence, suggested_checks, …}, CandidatePath{steps, score, …}, HypothesisUpdate{statement, target, status, confidence, evidence_refs, reason}` + 3 schemas | Statement capped at `MAX_STATEMENT_LEN = 500`; `CandidatePath.steps` non-empty strings; `HypothesisUpdate.status ∈ open|confirmed|refuted|inconclusive|exhausted` (repair → `open`) |
| `critic.py` | `CriticReview{decision, objections, evidence_missing, alternate_explanations, stale_data, single_source, confidence, reasoning}, CriticReviewSchema` | `decision ∈ approve|deny|modify` (repair → `modify` fail-safe) |
| `strategy.py` | `StrategyReview{top_unresolved, uncertainty_areas, weak_assumption_paths, duplicate_work, recommended_evidence, overall_assessment, confidence}, StrategyReviewSchema` | All five list fields required (repair → `[]`) |

All schemas implement `validate`/`repair`/`coerce` (+ `safe_load` on the base) and log via `log_validation`/`dump_telemetry`. `SafeSchemaLoader.load` extracts the JSON block (fence-tolerant, bare `{…}`/`[…]`), validates, repairs once, coerces or falls back to `default_factory()`; never raises. See the Schema validator lifecycle section for the full flow.

---

## Adapters (`adapters/`)

| File | Class | Bridge |
|---|---|---|
| `planner_adapter.py` | `PlannerAdapter` + `AttackPhaseBridge` | `planning_score_to_confidence`, `task_confidence`, `attach_planning_metadata`, `to_orchestrator`, `to_attack_planner` |
| `finding_adapter.py` | `FindingAdapter` | `ensure_reproduction_steps, dedupe_findings, link_to_graph(verifier, target_graph, finding_row, node_map)` — legacy `TargetGraph`, not v2 `GraphUpdate` |
| `memory_adapter.py` | `MemoryAdapter` | `remember_graded, find_existing, dedup_remember, confidence_rank` |
| `observer_adapter.py` | `ObserverAdapter` | `populate_hypothesis_evidence, populate_graph_updates, infer_confidence, classify_dead_end` |
| `target_graph_adapter.py` | `TargetGraphV2Adapter` | `resolve_node_id, add_edge_by_value, edges_summary` vs legacy `target_graph.TargetGraph` |

Adapters are pure transforms + dedupe guards; no new persistence.

---

## Belief store lifecycle (`belief/store.py`, `belief/state.py`, `belief/confidence.py`)

Per-mission hypothesis tracking. `BeliefStore` holds `BeliefState` objects keyed by mission id; each `BeliefState` holds `HypothesisState`s keyed by generated uuid.

| Symbol | Kind | Line | Description |
|---|---|---|---|
| `BeliefStore.upsert(state)` | def | `store.py:15` | Insert/replace by `state.mission_id` |
| `BeliefStore.get(mission_id)` | def | `store.py:19` | `BeliefState` or `None` |
| `BeliefStore.delete(mission_id)` | def | `store.py:23` | Remove if present (no-op otherwise) |
| `BeliefStore.list_all()` | def | `store.py:27` | Every state, insertion order |
| `BeliefStore.list_by_status(status)` | def | `store.py:31` | States with ≥1 hypothesis in `status` |
| `BeliefStore.find_by_statement(statement)` | def | `store.py:35` | States containing an exact-statement match |
| `BeliefState.add_hypothesis(statement, target, entity="", provenance="")` | def | `state.py:95` | Create hypothesis, return its uuid |
| `BeliefState.register_evidence(hypothesis_id, evidence_observation)` | def | `state.py:117` | Append (deduped by `evidence_ref`) + confidence update |
| `BeliefState.register_observation(...)` | def | `state.py:134` | DEPRECATED field-based wrapper |
| `BeliefState.next_discriminating_check(hypothesis_id, available_checks)` | def | `state.py:155` | Best un-attempted check, freshness order |
| `BeliefState.snapshot() / load(snapshot_dict)` | def | `state.py:173` | Plain-dict round-trip |
| `BeliefState.top_unresolved(limit=5)` | def | `state.py:188` | Highest uncertainty first, excludes CONFIRMED/REFUTED/EXHAUSTED |
| `BeliefState.to_json() / from_json(payload)` | def | `state.py:205` | JSON round-trip via `snapshot`/`load` |
| `ConfidenceCalculator.update(rule, current, obs, state)` | def | `confidence.py:89` | Dispatch one observation to a rule |
| `DeterministicUpdater(rule).apply(hypothesis, observations)` | def | `confidence.py:154` | Fold observations in order, return final confidence |
| `compute_status(confidence, evidence_count, supporting_count, contradicting_count, exhausted)` | def | `confidence.py:119` | Confidence → `HypothesisStatus` |

Thresholds (`confidence.py:22-24`): `CONFIRMED_THRESHOLD = 0.75`, `REFUTED_THRESHOLD = 0.25`, `SUSPECTED_LIKELY_BOUND = 0.45`. Default rule is `BAYESIAN_BETA` (`ConfidenceCalculator.default_rule`); pseudo-count `K = max(2, independent_observation_count)`. `compute_status` only returns CONFIRMED/REFUTED when evidence exists on the matching side — a bare numeric claim never qualifies.

```python
store = BeliefStore()
state = BeliefState(mission_id="m1")
hid = state.add_hypothesis("SMB signing disabled", target="10.0.0.5")
state.register_evidence(hid, EvidenceObservation(
    evidence_ref="ev:nmap:10.0.0.5:abc123:ts",
    polarity=EvidencePolarity.SUPPORTING, weight=0.8))
store.upsert(state)
```

Implementation note: `config.yaml` carries `outcome_judgment.confirmation_threshold/refutation_threshold/min_evidence_references/max_inconclusive_attempts` (`config.yaml:343-347`) and `memory.experience_time_decay_days` (`config.yaml:342`); the exact call sites reading those keys were not re-verified here.

---

## Evidence store lifecycle (`evidence/store.py`, `evidence/reference.py`, `evidence/provenance.py`)

Immutable, content-addressed references plus DAG lineage. `EvidenceStoreV2.put` is idempotent: same `(source_tool, target, content_hash)` returns the existing id.

| Symbol | Kind | Line | Description |
|---|---|---|---|
| `EvidenceStoreV2.put(ref)` | def | `store.py:28` | Store, return `ref_id` (existing id on dedup) |
| `EvidenceStoreV2.get(ref_id)` | def | `store.py:41` | Fetch or `None` |
| `EvidenceStoreV2.list_all()` | def | `store.py:46` | Insertion order |
| `EvidenceStoreV2.find_by_source_tool(tool)` | def | `store.py:51` | Filter by producing tool |
| `EvidenceStoreV2.find_by_target(target)` | def | `store.py:56` | Filter by target |
| `EvidenceStoreV2.count()` | def | `store.py:61` | Number stored |
| `EvidenceReference.create(source_tool, target, timestamp, content, ...)` | classmethod | `reference.py:71` | Build with deterministic `ref_id` (sha256 hex `[:16]` of `source_tool\|target\|timestamp\|content_hash`) |
| `EvidenceReference.from_dict / to_dict` | def | `reference.py:107` | Tolerant round-trip |
| `EvidenceReference.hash_content(content)` | static | `reference.py:142` | sha256 hex digest |
| `EvidenceReference.normalize(excerpt)` | static | `reference.py:147` | Collapse whitespace, strip controls, trim to `MAX_EXCERPT_LEN = 500` |
| `ProvenanceTracker.register_root(...)` | def | `provenance.py:135` | Root evidence (no parent) |
| `ProvenanceTracker.register_derived(parent_id, child_id, ...)` | def | `provenance.py:165` | Attach derived; `ValueError` on self-parent or unknown parent |
| `ProvenanceTracker.chain_for(evidence_id)` | def | `provenance.py:205` | Chain or `None` |
| `ProvenanceChain.lineage(evidence_id)` | def | `provenance.py:50` | Root → id path, or `[]` |
| `ProvenanceChain.confidence_at(evidence_id)` | def | `provenance.py:66` | Product of hop confidences; unknown id → `0.0` |

`EvidenceSource` (`reference.py:23`): `tool_output, banner, scanner, nvd_cve, exploit_db, manual, agent_observation, http_response, file_artifact, screenshot, note, target_side_oracle`. `EvidenceLevel` (`reference.py:40`): `raw, derived, summarized`.

```python
store = EvidenceStoreV2()
ref = EvidenceReference.create("nmap", "10.0.0.5", "2026-09-07T00:00:00Z", "<scan xml>")
ref_id = store.put(ref)  # second put of identical content returns the same ref_id
```

---

## Graph merge and traversal (`graph/store.py`, `graph/merge.py`, `graph/traversal.py`, `graph/types.py`)

`AttackGraphStore(db_path, scope="")` (`store.py:93`) is SQLite-backed with `UNIQUE(scope, node_type, value)` dedup; values are case-folded for `IP/HOST/DOMAIN/ASSET/ENDPOINT`. `upsert_node` merges (max confidence, summed `observation_count`, order-preserving evidence-ref union); `upsert_edge` raises `ValueError` on a missing endpoint; `delete_node` cascades manually to touching edges.

| Symbol | Kind | Line | Description |
|---|---|---|---|
| `AttackGraphStore.upsert_node(node)` | def | `store.py:192` | Insert/merge, return `node_id` |
| `AttackGraphStore.get_node(node_id)` | def | `store.py:245` | Fetch or `None` |
| `AttackGraphStore.get_node_by_value(node_type, value, scope="")` | def | `store.py:251` | Same normalization as upsert |
| `AttackGraphStore.upsert_edge(edge)` | def | `store.py:263` | Insert/merge; `ValueError` if endpoint missing |
| `AttackGraphStore.query_nodes(scope, node_type, status, value_substring, limit=200)` | def | `store.py:323` | Filtered, bounded |
| `AttackGraphStore.query_edges(scope, edge_type, source_id, target_id, limit=200)` | def | `store.py:349` | Filtered, bounded |
| `AttackGraphStore.summary()` | def | `store.py:496` | Counts by type + totals |
| `GraphMergeEngine(store).apply(graph_update)` | def | `merge.py:54` | Nodes first, then edges; returns `list[GraphMergeConflict]`, conflicting mutations skipped |
| `GraphMergeEngine(store).preview(update)` | def | `merge.py:80` | Dry run, no mutation |
| `GraphTraversal(nodes, edges).neighbors(node_id, relation=None, max_hops=1, max_nodes=50)` | def | `traversal.py:65` | Bounded BFS, `(node, edge, distance)` in discovery order |
| `GraphTraversal(nodes, edges).paths(start, end, max_length=4, max_paths=10)` | def | `traversal.py:106` | Simple paths, cycle-safe |
| `GraphTraversal(nodes, edges).path_exists(a, b, max_hops=3)` | def | `traversal.py:151` | Boolean over `paths` |
| `GraphTraversal(nodes, edges).subgraph(node_ids, max_distance=1)` | def | `traversal.py:159` | `(nodes, internal_edges, boundary_edges)` |

Conflict rules (`merge.py:88-111`, tolerance `_CONFIDENCE_TOLERANCE = 0.2`): same value as different node types; CONFIRMED → REFUTED without `evidence_refs`; confidence swing beyond tolerance without `evidence_refs`. Merge key is `(scope, value)` with case-folding.

```python
engine = GraphMergeEngine(store)
conflicts = engine.apply(GraphUpdate(node_updates=[node], edge_updates=[edge], source_agent="recon"))
if conflicts:
    preview = engine.preview(update)  # inspect without mutating
```

---

## Schema validator lifecycle (`schemas/base.py`, `schemas/validator.py`)

Every schema follows validate → repair once → coerce/fallback, with telemetry on every load.

| Symbol | Kind | Line | Description |
|---|---|---|---|
| `BaseSchema.validate(raw)` | abstract | `base.py:83` | `ValidationResult{valid, errors, repaired, message}` |
| `BaseSchema.repair(raw, errors)` | abstract | `base.py:86` | Best-effort fixed copy |
| `BaseSchema.coerce(raw)` | abstract | `base.py:90` | Typed object; `ValueError` only when repair failed |
| `BaseSchema.safe_load(raw)` | def | `base.py:94` | Never raises: `(object, result)` or `(None, result)` |
| `extract_json_block(text)` | def | `validator.py:15` | First balanced `{…}`/`[…]` block, fence-tolerant, `None` if absent |
| `parse_json_block(text)` | def | `validator.py:63` | Extract + `json.loads`, `None` on failure |
| `SafeSchemaLoader(validator, default_factory, schema_name).load(raw_json_str)` | def | `validator.py:82` | Extract → parse → validate → repair once → coerce/default; always `log_validation` |
| `log_validation / dump_telemetry` | def | `base.py:28` | In-memory telemetry (+ optional JSONL path) |
| `_safe_enum / _require_str / _clamp_float` | helper | `base.py:47` | Shared coercion primitives |

Repair defaults (fail-safe, never toward certainty): graph mutation → `update_confidence` (`GRAPH_MUTATIONS`, `graph.py:9`); outcome verdict → `unknown` (`OUTCOME_VERDICTS`, `outcome.py:9`); planner status → `open` (`PLANNER_STATUSES`, `planner.py:10`, statements capped at `MAX_STATEMENT_LEN = 500`); critic decision → `modify` (`CRITIC_DECISIONS`, `critic.py:9`); strategy list fields → `[]` (`REQUIRED_LIST_FIELDS`, `strategy.py:9`). Confidence always clamped to `[0,1]`.

```python
loader = SafeSchemaLoader(CriticReviewSchema(), default_factory=lambda: CriticReview(decision="modify"), schema_name="critic")
review, result = loader.load(llm_text)  # never raises; result.repaired flags the repair path
```

---

## Config keys

| Key | Default | Consumer |
|---|---|---|
| `outcome_judgment.confirmation_threshold` / `refutation_threshold` / `min_evidence_references` / `max_inconclusive_attempts` | `0.75` / `0.75` / `1` / `3` (`config.yaml:343-347`) | `OutcomeJudge` via `tools/exploit_agent/outcome_adapter.py:336` — Flow A judgment, not the v2 `belief/` thresholds |
| `memory.experience_time_decay_days` | `90` (`config.yaml:342`) | Experience-store decay; `belief/confidence.py` has no time-decay reader |
| `agent.max_retries_per_task` | `2` (`config.yaml:520`) | Campaign per-module failure cap (`tools/campaign/orchestrator.py:182`), not the fingerprint tracker |
| No dedicated `intelligence.*` block | — | Intelligence is library-only; callers wire config explicitly |

Implementation note: the pre-existing table mapped these keys to `belief/*` internals; the consumers above are what the grep verified. The v2 belief thresholds (`CONFIRMED_THRESHOLD = 0.75`, `REFUTED_THRESHOLD = 0.25` in `confidence.py`) are module constants.

## Tests

| File | Covers |
|---|---|
| `tests/test_intelligence_belief.py` | `HypothesisState`/`BeliefState` thresholds + transitions |
| `tests/test_intelligence_evidence.py` | `EvidenceReference`/`EvidenceStoreV2`/`ProvenanceTracker` |
| `tests/test_intelligence_evidence_adversarial.py` | Secret redaction, hash collision |
| `tests/test_intelligence_fingerprint.py` | `Attempt.fingerprint`, `RetryJustifier`, `is_permanent_failure` |
| `tests/test_intelligence_fingerprint_adversarial.py` | Masqueraded secrets + replay |
| `tests/test_intelligence_graph_store.py` | `AttackGraphStore` CRUD + `neighbors`/`paths` |
| `tests/test_intelligence_graph_store_adversarial.py` | Duplicate `value` norm, conflict merge |
| `tests/test_intelligence_graph_types.py` | `GraphNode`/`GraphEdge` ser/deser + redact |
| `tests/test_intelligence_schemas.py` | All schemas validate/repair/coerce |
| `tests/test_intelligence_schemas_adversarial.py` | Malformed JSON block + overflow |
| `tests/test_intelligence_adapter_planner.py` | `PlannerAdapter` score↔confidence |
| `tests/test_intelligence_adapter_graph.py` | `TargetGraphV2Adapter` |
| `tests/test_intelligence_adapter_finding.py` | `FindingAdapter` dedupe |
| `tests/test_intelligence_adapter_memory.py` | `MemoryAdapter` grading |
| `tests/test_intelligence_adapter_observer.py` | `ObserverAdapter` classify |
| `tests/test_intelligence_adapter_adversarial.py` | `unsupported_confidence`, `AttackPhaseBridge` unknown-input, idempotent wiring |
| `tests/test_bel_adversarial.py` | Belief thresholds under adversarial drift |

## Related documentation

- [Swarm internals](../swarm/internals.md) — orchestrator routing, blackboard, negotiation, milestones, persistence
- [Swarm overview](../swarm/overview.md) — package map, `route` flow, skill-phase tags
- [Swarm agents](../swarm/agents.md) — per-agent behavior including the critic gate
- [Graph explorer API](../../../api/endpoints/graph-explorer.md) — WebUI DAG surface over `graph/`
- [Outcome evidence](../../../outcome-evidence.md) — Flow A `OutcomeJudge` vs v2 belief thresholds

## Source map

- `tools/intelligence/__init__.py`
- `tools/intelligence/belief/state.py` — `HypothesisStatus`, `EvidencePolarity`, `EvidenceObservation`, `HypothesisState`, `BeliefState`
- `tools/intelligence/belief/confidence.py` — `ConfidenceCalculator`, `DeterministicUpdater`, `compute_status`, `NonModelConfidence`
- `tools/intelligence/belief/store.py` — `BeliefStore`
- `tools/intelligence/evidence/reference.py` — `EvidenceSource`, `EvidenceLevel`, `EvidenceReference`
- `tools/intelligence/evidence/store.py` — `EvidenceStoreV2`
- `tools/intelligence/evidence/provenance.py` — `ProvenanceEntry`, `ProvenanceChain`, `ProvenanceTracker`
- `tools/intelligence/fingerprint/attempt.py` — `AttemptStatus`, `ActionFamily`, `Attempt`, `RetryJustification`, `RetryJustifier`, `mask_secrets`
- `tools/intelligence/fingerprint/tracker.py` — `AttemptTracker`, `PERMANENT_FAILURE_MARKERS`, `is_permanent_failure`
- `tools/intelligence/graph/types.py` — `NodeType`, `EdgeType`, `NodeStatus`, `GraphNode`, `GraphEdge`, `GraphUpdate`, `redact_properties`, `make_evidence_ref`
- `tools/intelligence/graph/store.py` — `AttackGraphStore`
- `tools/intelligence/graph/merge.py` — `GraphMergeEngine`, `GraphMergeConflict`, `GraphMergeError`
- `tools/intelligence/graph/traversal.py` — `GraphTraversal`
- `tools/intelligence/schemas/base.py` — `BaseSchema`, `ValidationResult`, `log_validation`, `dump_telemetry`
- `tools/intelligence/schemas/validator.py` — `extract_json_block`, `parse_json_block`, `SafeSchemaLoader`
- `tools/intelligence/schemas/graph.py` — `GraphMutationProposal`, `GraphMutationSchema`
- `tools/intelligence/schemas/outcome.py` — `OutcomeAssessment`, `OutcomeAssessmentSchema`
- `tools/intelligence/schemas/planner.py` — `PlannerProposal`, `CandidatePath`, `HypothesisUpdate` + schemas
- `tools/intelligence/schemas/critic.py` — `CriticReview`, `CriticReviewSchema`
- `tools/intelligence/schemas/strategy.py` — `StrategyReview`, `StrategyReviewSchema`
- `tools/intelligence/adapters/planner_adapter.py` — `PlannerAdapter`, `AttackPhaseBridge`
- `tools/intelligence/adapters/finding_adapter.py` — `FindingAdapter`
- `tools/intelligence/adapters/memory_adapter.py` — `MemoryAdapter`
- `tools/intelligence/adapters/observer_adapter.py` — `ObserverAdapter`
- `tools/intelligence/adapters/target_graph_adapter.py` — `TargetGraphV2Adapter`
- `tools/api/graph_service.py` — WebUI wrapper over `graph/`
- `tools/api/graph_builder.py` — DAG builder over `graph/`
- `tools/killchain/machine.py` — `AttackGraphStore` killchain consumer
- `tools/campaign/executor.py` — `AttackPhaseBridge.to_orchestrator` consumer
- `legacy/observer.py` — `ObserverAdapter` legacy consumer
- `legacy/finding_verifier.py` — `FindingAdapter` legacy consumer
