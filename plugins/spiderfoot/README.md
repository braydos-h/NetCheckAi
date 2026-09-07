# spiderfoot

SpiderFoot OSINT integration (passive): DNS, whois, certs, and leak data in
one tool via the SpiderFoot REST API. Passive only — queries public data
sources, never touches the target. The operator must start SpiderFoot with
its REST API enabled on the operator box before invoking this plugin.

Source: `plugins/spiderfoot/plugin.yaml`, `plugins/spiderfoot/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers four MCP tools, all passive and
all wrapped with `@audit_tool` (audit trail only, no `require_allowlist`
because there is no target touch):

- `spiderfoot_scan(target, modules="")` — start a passive scan
  (`POST /api/v1/scan` with `scan_target`, optional `modules`); returns the
  scan id. Refuses with `BLOCKED:` unless `spiderfoot.enabled` is true.
- `spiderfoot_scan_status(scan_id)` — poll scan status
  (`GET /api/v1/scan/<id>`).
- `spiderfoot_results(scan_id, limit=200)` — fetch completed-scan results
  (`GET /api/v1/scan/<id>/results`); `limit` is clamped to 1–1000 (default
  200); result bodies capped at 6000 chars.
- `spiderfoot_list_modules()` — list available modules for the `modules`
  parameter (`GET /api/v1/modules`). Refuses with `BLOCKED:` unless
  `spiderfoot.enabled` is true.

## Config keys

```yaml
spiderfoot:
  enabled: false
  api_url: http://127.0.0.1:5001
  api_key_env: SPIDERFOOT_API_KEY
  timeout_seconds: 60
```

| Key               | Type   | Default                 | Meaning                                              |
|-------------------|--------|-------------------------|------------------------------------------------------|
| `enabled`         | `bool` | `false`                 | Section flag; scan/list-modules tools refuse without it |
| `api_url`         | `str`  | `http://127.0.0.1:5001` | Operator-side SpiderFoot REST base URL               |
| `api_key_env`     | `str`  | `SPIDERFOOT_API_KEY`    | Env var holding the SpiderFoot API key               |
| `timeout_seconds` | `int`  | `60`                    | HTTP timeout for the scan-start request              |

## Credentials / env vars

- `SPIDERFOOT_API_KEY` (default name; override via `api_key_env`) — SpiderFoot
  API key, env-only, never in config or logs. Sent as the
  `X-SpiderFoot-API-Key` header plus an `api_key` query parameter (some
  SpiderFoot versions expect the query form). Requests work unauthenticated
  when unset.

## Usage example

Opt in (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - spiderfoot

spiderfoot:
  enabled: true
  api_url: http://127.0.0.1:5001
```

Start the SpiderFoot daemon with its REST API enabled, then:

- `spiderfoot_scan(target="example.com")`
- `spiderfoot_scan_status(scan_id="<id>")`
- `spiderfoot_results(scan_id="<id>")`
- `spiderfoot_list_modules()`

## Safety / advisory-only notes

- **Authorized testing only.** Use only against systems you own or are
  explicitly authorized to assess.
- **Passive only.** No active scanning and no third-party submissions beyond
  SpiderFoot's own public-source queries; advisory input to hypotheses, never
  target contact.
- No log clearing, timestomping, EDR/AV defeat, DoS, or malware distribution.
- Pure stdlib (`urllib`); no new dependency.
