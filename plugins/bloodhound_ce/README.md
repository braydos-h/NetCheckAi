# bloodhound_ce

BloodHound CE data exchange: ingests BloodHound collection zips into
BloodHound CE and exposes pre-baked attack-path queries. Pairs with the
existing `bloodhound_collect` tool (which emits the zip); this plugin ingests
that zip into the CE REST API / neo4j graph and queries attack paths
(shortest path to Domain Admin, kerberoastable users, and more).

Source: `plugins/bloodhound_ce/plugin.yaml`, `plugins/bloodhound_ce/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers three MCP tools, all wrapped
with `@ctx.require_allowlist(target_param="target_ip", audit=True)` so the
target-IP allowlist lock + JSONL audit trail apply automatically. (`target_ip`
is gated on all three for audit-trail consistency, even on the read-only
query tools.)

- `bloodhound_ce_ingest(target_ip, zip_path)` — ingest a `.zip` produced by
  `bloodhound_collect` (relative paths resolve under the per-target
  workspace) into BloodHound CE via `POST /api/v2/ingest`. Refuses non-zip
  or missing files with `BLOCKED:`.
- `bloodhound_ce_query(target_ip, query_name, limit=50)` — run one pre-baked
  Cypher query against neo4j (falls back to `POST /api/v2/queries` when the
  driver is unavailable). Unknown query names are refused with `BLOCKED:`.
- `bloodhound_ce_list_queries(target_ip)` — advisory catalog of the
  available query names.

Pre-baked queries (`_QUERIES`): `shortest_path_to_domain_admin`,
`kerberoastable_users`, `asrep_roastable_users`, `dcsync_users`,
`all_admins`. Query bodies are capped in output (4000 chars) and `limit`
clamps to 1–500 (default 50).

## Config keys

```yaml
bloodhound_ce:
  enabled: false
  neo4j_uri: bolt://127.0.0.1:7687
  neo4j_user: neo4j
  neo4j_password_env: NEO4J_PASSWORD
  ce_api_url: http://127.0.0.1:8080
  ce_api_key_env: BLOODHOUND_CE_API_KEY
```

| Key                 | Type   | Default                  | Meaning                                          |
|---------------------|--------|--------------------------|--------------------------------------------------|
| `enabled`           | `bool` | `false`                  | Plugin-scoped enable flag; tools refuse without it |
| `neo4j_uri`         | `str`  | `bolt://127.0.0.1:7687`  | neo4j bolt endpoint (operator-side)              |
| `neo4j_user`        | `str`  | `neo4j`                  | neo4j username                                   |
| `neo4j_password_env`| `str`  | `NEO4J_PASSWORD`         | Env var holding the neo4j password               |
| `ce_api_url`        | `str`  | `http://127.0.0.1:8080`  | BloodHound CE REST base URL (operator-side)      |
| `ce_api_key_env`    | `str`  | `BLOODHOUND_CE_API_KEY`  | Env var holding the CE API key (Bearer, optional)|

## Credentials / env vars

- `NEO4J_PASSWORD` (default name; override via `neo4j_password_env`) —
  neo4j auth, env-only, never in config or logs.
- `BLOODHOUND_CE_API_KEY` (default name; override via `ce_api_key_env`) —
  CE REST Bearer token, env-only.
- Requires the `neo4j` Python package for direct graph queries; without it
  the plugin warns and falls back to the CE REST API, refusing with guidance
  if neither is reachable.

## Usage example

Opt in (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - bloodhound_ce

bloodhound_ce:
  enabled: true
  neo4j_uri: bolt://127.0.0.1:7687
  ce_api_url: http://127.0.0.1:8080
```

With `NEO4J_PASSWORD` (and optionally `BLOODHOUND_CE_API_KEY`) exported,
against an authorized target:

- `bloodhound_ce_ingest(target_ip="127.0.0.1", zip_path="bloodhound.zip")`
- `bloodhound_ce_list_queries(target_ip="127.0.0.1")`
- `bloodhound_ce_query(target_ip="127.0.0.1", query_name="kerberoastable_users")`

## Safety / advisory-only notes

- **Authorized testing only.** Collect and analyze AD data only in
  environments you own or are explicitly authorized to assess.
- The BloodHound CE / neo4j endpoint is **operator-side** (the operator's
  own box) — it does not need to be in `exploit.allowed_targets`, and
  target-touching gates still apply to `target_ip`.
- No log clearing, timestomping, EDR/AV defeat, DoS, or malware
  distribution.
