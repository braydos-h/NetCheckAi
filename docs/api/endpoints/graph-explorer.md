---
title: Graph Explorer Endpoints — Per-Run AttackGraph v2 (runs graph, summary, conflicts, node, neighbors, paths)
sources:
  - tools/api/routes/graph_explorer.py
  - tools/api/graph_service.py
  - tools/api/graph_builder.py
  - tools/intelligence/graph/types.py
  - tools/api/auth.py
  - tools/api/errors.py
tests:
  - tests/test_api_frontend.py
subsystem: api
---

# Graph Explorer Endpoints

`tools/api/routes/graph_explorer.py:43` — `APIRouter(prefix="/api/v1/graph", tags=["graph-explorer"])`, created by `create_router(auth, persistence, config)` and mounted in `app.py` alongside the legacy graph router (`app.py:166-167`, `app.py:180-181`). Read-only interactive investigation surface over the per-run AttackGraph v2 store built by `tools/api/graph_builder.py` and queried via `AttackGraphService` (`tools/api/graph_service.py:39`).

Gate: every handler calls `_gate()` first in the body (`tools/api/routes/graph_explorer.py:53-55`); when `api.graph_route:false` it raises `APIError("graph_disabled", ...)` → `404`. Config default is `true` (`config.yaml:449`, `tools/config/schema.py:800`). The bearer dependency (`Depends(_require_auth)`) resolves before the handler body, so unauthenticated callers still get `401` first.

Scope isolation: every query is bound to `scope=run:<run_id>` (`tools/api/graph_builder.py:50`); nodes from other runs are treated as not found. The store is an in-memory `AttackGraphStore` rebuilt lazily when the run's artifact fingerprint changes, cached LRU max 8 (`tools/api/graph_service.py:50-98`). All queries are bounded and never touch a target or mutate artifacts.

Authoritative ceilings (`tools/api/routes/graph_explorer.py:29-33`, clamped via `_clamp`, `tools/api/routes/graph_explorer.py:36-40` — out-of-range values clamp, never error):

| Bound | Ceiling | Default |
|-------|---------|---------|
| graph `limit` | 500 | 300 |
| neighbors `max_hops` | 4 | 1 |
| neighbors `max_nodes` | 200 | 50 |
| paths `max_length` | 8 | 4 |
| paths `max_paths` | 8 | 5 |

Node/edge shapes are `GraphNode.to_dict()` / `GraphEdge.to_dict()` (`tools/intelligence/graph/types.py:205-280`): node `{node_id, node_type, value, scope, properties (credential keys redacted), confidence, first_seen, last_seen, evidence_refs, observation_count, contradiction_count, status, source}`; edge `{edge_id, source_node_id, target_node_id, edge_type, scope, properties, confidence, source, first_seen, last_seen, evidence_refs, observation_count, contradiction_count}`. `node_type` is a `NodeType` member (`asset|host|domain|ip|service|port|endpoint|application|technology|version|identity|role|credential_reference|trust_boundary|network_segment|vulnerability_candidate|finding|hypothesis|evidence|capability|security_control|observation`); `status` is a `NodeStatus` member (`unknown|suspected|likely|confirmed|refuted|exhausted`). Invalid `node_type`/`status` filter values are silently ignored, never an error (`_parse_enums`, `tools/api/graph_service.py:305-313`).

Error envelope for all failures: `{error:{code, message, details, request_id}}` plus `X-Request-ID` header (`tools/api/errors.py:42-59`, `tools/api/errors.py:107-115`).

## `GET /api/v1/graph/runs/{run_id}` — `get_graph`

- **Method / Path:** `GET /api/v1/graph/runs/{run_id}`
- **Purpose:** Filtered nodes + edges for a run. `truncated:true` when `limit` is hit. Delegates to `service.graph(run, node_types, statuses, search, limit)` (`tools/api/graph_service.py:120`), which cross-products `(type,status)` combos, gathers edges whose endpoints are both included, and returns `total_nodes`.
- **Authentication:** Bearer required (`Depends(_require_auth)`, `tools/api/routes/graph_explorer.py:50-51` → `BearerAuth`, `tools/api/auth.py:173-194`). `401` when missing/invalid.
- **Parameters (query):**

  | Param | Type | Default | Constraint |
  |-------|------|---------|------------|
  | `node_type` | `string[]` (repeatable) | `[]` (no filter) | must be `NodeType` values; invalid entries ignored |
  | `status` | `string[]` (repeatable) | `[]` (no filter) | must be `NodeStatus` values; invalid entries ignored |
  | `q` | `string` | `""` | substring match on node value |
  | `limit` | `int` | `300` | clamped `1..500` |

  No body.
- **Status codes:** `200` success; `401` bad/missing bearer; `404 graph_disabled` when `api.graph_route:false`; `404 run_not_found` when the run is unknown.
- **Error conditions:** unknown `run_id`; disabled gate. Out-of-range `limit` clamps instead of erroring; bad enum filters are ignored.
- **Example request:**

  ```bash
  curl -s http://127.0.0.1:8765/api/v1/graph/runs/20260907_ab12cd34?q=10.0.0.50&limit=100 \
    -H "Authorization: Bearer $TOKEN"
  ```
- **Example response (`200`):**

  ```json
  {
    "run_id": "20260907_ab12cd34",
    "scope": "run:20260907_ab12cd34",
    "nodes": [
      {
        "node_id": "host:10.0.0.50",
        "node_type": "host",
        "value": "10.0.0.50",
        "scope": "run:20260907_ab12cd34",
        "properties": {},
        "confidence": 0.9,
        "first_seen": "2026-09-07T10:00:00+00:00",
        "last_seen": "2026-09-07T10:05:00+00:00",
        "evidence_refs": [],
        "observation_count": 3,
        "contradiction_count": 0,
        "status": "confirmed",
        "source": "ingest_run_metadata"
      }
    ],
    "edges": [
      {
        "edge_id": "e1",
        "source_node_id": "host:10.0.0.50",
        "target_node_id": "ip:10.0.0.50",
        "edge_type": "resolves_to",
        "scope": "run:20260907_ab12cd34",
        "properties": {},
        "confidence": 0.9,
        "source": "ingest_run_metadata",
        "first_seen": "2026-09-07T10:00:00+00:00",
        "last_seen": "2026-09-07T10:00:00+00:00",
        "evidence_refs": [],
        "observation_count": 1,
        "contradiction_count": 0
      }
    ],
    "total_nodes": 42,
    "truncated": true
  }
  ```
- **Related events:** None emitted (read-only `GET`). The WebUI invalidates its `graphExplorer` queries on WebSocket artifact/run events and polls every 10 s while the run is active (`webui/src/features/graph/graphApi.ts:141-169`).
- **WebUI usage:** `useGraphRun(runId, filters)` (`webui/src/features/graph/graphApi.ts:52`); filters panel `GraphFilters.tsx` / `GraphActiveFilters.tsx`; canvas `AttackGraphCanvas.tsx` on `AttackGraphPage.tsx` (route `/graph`, `webui/src/App.tsx:63`).
- **Source file:** `tools/api/routes/graph_explorer.py:66-79` (`get_graph`); service `tools/api/graph_service.py:120-151`.

## `GET /api/v1/graph/runs/{run_id}/summary` — `get_summary`

- **Method / Path:** `GET /api/v1/graph/runs/{run_id}/summary`
- **Purpose:** Counts + stats chips for a run: raw `store.summary()` plus computed `stats` (per-type counts, status counts, highest-degree node, conflict count). Delegates to `service.summary(run)` (`tools/api/graph_service.py:153-199`). `highest_degree_node` is `null` when the graph has no edges.
- **Authentication:** Bearer required (same `_require_auth` dependency). `401` when missing/invalid.
- **Parameters:** None (no query, no body).
- **Status codes:** `200` success; `401` bad/missing bearer; `404 graph_disabled` when `api.graph_route:false`; `404 run_not_found` when the run is unknown.
- **Error conditions:** unknown `run_id`; disabled gate.
- **Example request:**

  ```bash
  curl -s http://127.0.0.1:8765/api/v1/graph/runs/20260907_ab12cd34/summary \
    -H "Authorization: Bearer $TOKEN"
  ```
- **Example response (`200`):**

  ```json
  {
    "run_id": "20260907_ab12cd34",
    "summary": {"total_nodes": 42, "total_edges": 61, "nodes": {"host": 3}, "edges": {}},
    "stats": {
      "hosts": 3,
      "domains": 1,
      "ips": 3,
      "services": 5,
      "findings": 4,
      "hypotheses": 2,
      "evidence": 9,
      "observations": 12,
      "vulnerability_candidates": 2,
      "confirmed": 4,
      "likely": 3,
      "refuted": 1,
      "highest_degree_node": {"node_id": "host:10.0.0.50", "value": "10.0.0.50", "node_type": "host", "degree": 11},
      "conflict_count": 1
    }
  }
  ```
- **Related events:** None emitted (read-only `GET`). Same WebUI invalidation as above.
- **WebUI usage:** `useGraphSummary(runId)` (`webui/src/features/graph/graphApi.ts:69`); chips rendered by `GraphStats.tsx` on `AttackGraphPage.tsx`.
- **Source file:** `tools/api/routes/graph_explorer.py:81-87` (`get_summary`); service `tools/api/graph_service.py:153-199`.

## `GET /api/v1/graph/runs/{run_id}/conflicts` — `get_conflicts`

- **Method / Path:** `GET /api/v1/graph/runs/{run_id}/conflicts`
- **Purpose:** Merge-engine conflicts observed during ingestion (`GraphMergeEngine`), returned separately so they are never hidden. Delegates to `service.conflicts(run)` (`tools/api/graph_service.py:201-218`). Empty list when there is no conflict.
- **Authentication:** Bearer required (same `_require_auth` dependency). `401` when missing/invalid.
- **Parameters:** None (no query, no body).
- **Status codes:** `200` success; `401` bad/missing bearer; `404 graph_disabled` when `api.graph_route:false`; `404 run_not_found` when the run is unknown.
- **Error conditions:** unknown `run_id`; disabled gate.
- **Example request:**

  ```bash
  curl -s http://127.0.0.1:8765/api/v1/graph/runs/20260907_ab12cd34/conflicts \
    -H "Authorization: Bearer $TOKEN"
  ```
- **Example response (`200`):**

  ```json
  {
    "run_id": "20260907_ab12cd34",
    "conflicts": [
      {
        "node_value": "10.0.0.50",
        "reason": "confidence_mismatch",
        "existing_confidence": 0.9,
        "proposed_confidence": 0.4,
        "node_id": "host:10.0.0.50",
        "scope": "run:20260907_ab12cd34",
        "built_at": "2026-09-07T10:06:00+00:00"
      }
    ]
  }
  ```
- **Related events:** None emitted (read-only `GET`). Same WebUI invalidation as above.
- **WebUI usage:** `useGraphConflicts(runId)` (`webui/src/features/graph/graphApi.ts:78`); surfaced on `AttackGraphPage.tsx`.
- **Source file:** `tools/api/routes/graph_explorer.py:89-95` (`get_conflicts`); service `tools/api/graph_service.py:201-218`.

## `GET /api/v1/graph/runs/{run_id}/nodes/{node_id}` — `get_node`

- **Method / Path:** `GET /api/v1/graph/runs/{run_id}/nodes/{node_id}`
- **Purpose:** Single node detail plus up to 100 connected edges and up to 100 neighbors (scope-isolated). Delegates to `service.node(run, node_id)` (`tools/api/graph_service.py:220-236`), which returns `None` when the node is missing or belongs to another run's scope.
- **Authentication:** Bearer required (same `_require_auth` dependency). `401` when missing/invalid.
- **Parameters:** Path `run_id` (`string`, required), path `node_id` (`string`, required, URL-encoded). No query, no body.
- **Status codes:** `200` success; `401` bad/missing bearer; `404 graph_disabled` when `api.graph_route:false`; `404 run_not_found` when the run is unknown; `404 node_not_found` when the node is missing or out of scope.
- **Error conditions:** unknown `run_id`; disabled gate; unknown `node_id`; `node_id` from a different run's scope (treated as not found).
- **Example request:**

  ```bash
  curl -s "http://127.0.0.1:8765/api/v1/graph/runs/20260907_ab12cd34/nodes/host%3A10.0.0.50" \
    -H "Authorization: Bearer $TOKEN"
  ```
- **Example response (`200`):**

  ```json
  {
    "run_id": "20260907_ab12cd34",
    "node": {
      "node_id": "host:10.0.0.50",
      "node_type": "host",
      "value": "10.0.0.50",
      "scope": "run:20260907_ab12cd34",
      "properties": {},
      "confidence": 0.9,
      "first_seen": "2026-09-07T10:00:00+00:00",
      "last_seen": "2026-09-07T10:05:00+00:00",
      "evidence_refs": [],
      "observation_count": 3,
      "contradiction_count": 0,
      "status": "confirmed",
      "source": "ingest_run_metadata"
    },
    "edges": [],
    "neighbors": []
  }
  ```

  Error (`404`):

  ```json
  {"error": {"code": "node_not_found", "message": "Node host:10.0.0.99 not found in run 20260907_ab12cd34", "details": {}, "request_id": "3f9c..."}}
  ```
- **Related events:** None emitted (read-only `GET`). Same WebUI invalidation as above.
- **WebUI usage:** `useGraphNode(runId, nodeId)` (`webui/src/features/graph/graphApi.ts:87`); detail rendered by `GraphDetailsPanel.tsx` (node types/legend in `GraphNodeTypes.tsx`, `GraphLegend.tsx`).
- **Source file:** `tools/api/routes/graph_explorer.py:97-107` (`get_node`); service `tools/api/graph_service.py:220-236`.

## `GET /api/v1/graph/runs/{run_id}/nodes/{node_id}/neighbors` — `get_neighbors`

- **Method / Path:** `GET /api/v1/graph/runs/{run_id}/nodes/{node_id}/neighbors`
- **Purpose:** Bounded BFS neighborhood including the start node. Delegates to `service.neighbors(run, node_id, max_hops, max_nodes)` (`tools/api/graph_service.py:238-268`). `404` when the start node is unknown.
- **Authentication:** Bearer required (same `_require_auth` dependency). `401` when missing/invalid.
- **Parameters:**

  | Param | Location | Type | Default | Constraint |
  |-------|----------|------|---------|------------|
  | `run_id` | path | `string` | required | — |
  | `node_id` | path | `string` | required | URL-encoded |
  | `max_hops` | query | `int` | `1` | clamped `1..4` |
  | `max_nodes` | query | `int` | `50` | clamped `1..200` |

  No body. Out-of-range values clamp instead of erroring.
- **Status codes:** `200` success; `401` bad/missing bearer; `404 graph_disabled` when `api.graph_route:false`; `404 run_not_found` when the run is unknown; `404 node_not_found` when the start node is missing or out of scope.
- **Error conditions:** unknown `run_id`; disabled gate; unknown/out-of-scope start `node_id`.
- **Example request:**

  ```bash
  curl -s "http://127.0.0.1:8765/api/v1/graph/runs/20260907_ab12cd34/nodes/host%3A10.0.0.50/neighbors?max_hops=2&max_nodes=50" \
    -H "Authorization: Bearer $TOKEN"
  ```
- **Example response (`200`):**

  ```json
  {
    "run_id": "20260907_ab12cd34",
    "start_node": {
      "node_id": "host:10.0.0.50",
      "node_type": "host",
      "value": "10.0.0.50",
      "scope": "run:20260907_ab12cd34",
      "properties": {},
      "confidence": 0.9,
      "first_seen": "2026-09-07T10:00:00+00:00",
      "last_seen": "2026-09-07T10:05:00+00:00",
      "evidence_refs": [],
      "observation_count": 3,
      "contradiction_count": 0,
      "status": "confirmed",
      "source": "ingest_run_metadata"
    },
    "nodes": [],
    "edges": []
  }
  ```
- **Related events:** None emitted (read-only `GET`). Same WebUI invalidation as above.
- **WebUI usage:** `useGraphNeighbors(runId, nodeId, maxHops, maxNodes)` (`webui/src/features/graph/graphApi.ts:99`); neighborhood expansion on `AttackGraphPage.tsx` / `GraphDetailsPanel.tsx`.
- **Source file:** `tools/api/routes/graph_explorer.py:109-127` (`get_neighbors`); service `tools/api/graph_service.py:238-268`.

## `GET /api/v1/graph/runs/{run_id}/paths` — `get_paths`

- **Method / Path:** `GET /api/v1/graph/runs/{run_id}/paths`
- **Purpose:** Bounded simple-path discovery between two nodes. Delegates to `service.paths(run, start, end, max_length, max_paths)` (`tools/api/graph_service.py:270-299`). Each returned path is a list of `{distance, node, edge}` steps where `distance` starts at 1 (the start node itself is not emitted). Unknown endpoints return `200` with `[]`, not an error.
- **Authentication:** Bearer required (same `_require_auth` dependency). `401` when missing/invalid.
- **Parameters:**

  | Param | Location | Type | Default | Constraint |
  |-------|----------|------|---------|------------|
  | `run_id` | path | `string` | required | — |
  | `start` | query | `string` | required | start node id |
  | `end` | query | `string` | required | end node id |
  | `max_length` | query | `int` | `4` | clamped `1..8` |
  | `max_paths` | query | `int` | `5` | clamped `1..8` |

  No body. Missing `start`/`end` fails FastAPI query validation → `422 validation_error`.
- **Status codes:** `200` success (including `paths:[]` for unknown endpoints); `401` bad/missing bearer; `404 graph_disabled` when `api.graph_route:false`; `404 run_not_found` when the run is unknown; `422 validation_error` when required `start`/`end` query params are missing.
- **Error conditions:** unknown `run_id`; disabled gate; missing `start`/`end` (`422`). Unknown `start`/`end` node ids are NOT errors — they yield `[]`.
- **Example request:**

  ```bash
  curl -s "http://127.0.0.1:8765/api/v1/graph/runs/20260907_ab12cd34/paths?start=host%3A10.0.0.50&end=finding%3Asql-injection&max_length=4&max_paths=5" \
    -H "Authorization: Bearer $TOKEN"
  ```
- **Example response (`200`):**

  ```json
  {
    "run_id": "20260907_ab12cd34",
    "paths": [
      [
        {
          "distance": 1,
          "node": {
            "node_id": "finding:sql-injection",
            "node_type": "finding",
            "value": "sql-injection",
            "scope": "run:20260907_ab12cd34",
            "properties": {},
            "confidence": 0.8,
            "first_seen": "2026-09-07T10:02:00+00:00",
            "last_seen": "2026-09-07T10:05:00+00:00",
            "evidence_refs": [],
            "observation_count": 1,
            "contradiction_count": 0,
            "status": "likely",
            "source": "ingest_report"
          },
          "edge": {
            "edge_id": "e9",
            "source_node_id": "host:10.0.0.50",
            "target_node_id": "finding:sql-injection",
            "edge_type": "affected_by",
            "scope": "run:20260907_ab12cd34",
            "properties": {},
            "confidence": 0.8,
            "source": "ingest_report",
            "first_seen": "2026-09-07T10:02:00+00:00",
            "last_seen": "2026-09-07T10:02:00+00:00",
            "evidence_refs": [],
            "observation_count": 1,
            "contradiction_count": 0
          }
        }
      ]
    ]
  }
  ```
- **Related events:** None emitted (read-only `GET`). Same WebUI invalidation as above.
- **WebUI usage:** `useGraphPaths(runId, start, end, maxLength, maxPaths)` (`webui/src/features/graph/graphApi.ts:118`); path finder UI `GraphPathFinder.tsx` on `AttackGraphPage.tsx`.
- **Source file:** `tools/api/routes/graph_explorer.py:129-146` (`get_paths`); service `tools/api/graph_service.py:270-299`.

## Related documentation

- [Graph Endpoints — Legacy DAG and AttackGraph v2 Explorer](graph.md)
- [Endpoint Matrix](../endpoint-matrix.md)
- [API Overview](../overview.md)
- [Authentication](../auth.md)
- [WebSocket](../websocket.md)
- [Event Broker](../event-broker.md)

## Source map

- `tools/api/routes/graph_explorer.py`
- `tools/api/graph_service.py`
- `tools/api/graph_builder.py`
- `tools/intelligence/graph/types.py`
- `tools/intelligence/graph/store.py`
- `tools/api/auth.py`
- `tools/api/errors.py`
- `tools/api/persistence.py`
- `tools/config/schema.py`
- `config.yaml`
- `app.py`
- `webui/src/features/graph/graphApi.ts`
- `webui/src/features/graph/AttackGraphPage.tsx`
- `webui/src/features/graph/GraphPathFinder.tsx`
- `webui/src/features/graph/GraphDetailsPanel.tsx`
- `webui/src/App.tsx`
- `docs/api/endpoints/graph.md`
- `docs/api/endpoint-matrix.md`
