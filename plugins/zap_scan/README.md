# zap_scan

OWASP ZAP REST integration: spider + active scan against authorized web
targets, correlated with the AI's hypothesis loop. Complements the built-in
`run_web_scan` tool (nikto/nuclei/sqlmap) with the ZAP path. The operator
must start ZAP with its REST API enabled before invoking this plugin.

Source: `plugins/zap_scan/plugin.yaml`, `plugins/zap_scan/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers four MCP tools, all wrapped
with `@ctx.require_allowlist(target_param="target_ip", audit=True)` so the
target-IP allowlist lock + JSONL audit trail apply automatically. The scanned
URL's host must resolve to an allowlisted IP.

- `zap_spider(target_ip, url, max_depth=5)` — start a ZAP spider scan
  (`/JSON/spider/action/scan/`); returns the scan id.
- `zap_active_scan(target_ip, url, recurse=True)` — start a ZAP active scan
  (`/JSON/ascan/action/scan/`); returns the scan id. Active scans send
  attack payloads — authorized targets only.
- `zap_scan_status(target_ip, scan_id)` — poll scan progress
  (`/JSON/ascan/view/status/`).
- `zap_alerts(target_ip, baseurl="")` — return recorded alerts
  (`/JSON/core/view/alerts/`), optionally filtered by base URL; alert bodies
  capped at 4000 chars.

Spider and active-scan tools additionally refuse with `BLOCKED:` unless
`zap_scan.enabled` is true in config (double-gate: `plugins.enabled` +
section flag).

## Config keys

```yaml
zap_scan:
  enabled: false
  api_url: http://127.0.0.1:8080
  api_key_env: ZAP_API_KEY
  context_name: breachpilot
  max_scan_duration_mins: 30
```

| Key                    | Type   | Default                 | Meaning                                              |
|------------------------|--------|-------------------------|------------------------------------------------------|
| `enabled`              | `bool` | `false`                 | Section flag; spider/active-scan tools refuse without it |
| `api_url`              | `str`  | `http://127.0.0.1:8080` | Operator-side ZAP REST base URL                      |
| `api_key_env`          | `str`  | `ZAP_API_KEY`           | Env var holding the ZAP API key                      |
| `context_name`         | `str`  | `breachpilot`           | Manifest-declared ZAP context name                   |
| `max_scan_duration_mins` | `int`| `30`                    | Manifest-declared scan time budget                   |

The plugin reads `enabled`, `api_url`, and `api_key_env` at call time;
`context_name` and `max_scan_duration_mins` are manifest-declared keys. The
API key is attached as the `apikey` parameter on every ZAP request (query
string for GET, form field for POST).

## Credentials / env vars

- `ZAP_API_KEY` (default name; override via `api_key_env`) — ZAP REST API
  key, env-only, never in config or logs. Omitted from requests when unset.

## Usage example

Opt in (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - zap_scan

zap_scan:
  enabled: true
  api_url: http://127.0.0.1:8080

exploit:
  allowed_targets:
    - 127.0.0.1
```

Start ZAP with the REST API enabled on the operator box, then against an
authorized target:

- `zap_spider(target_ip="127.0.0.1", url="http://127.0.0.1/")`
- `zap_scan_status(target_ip="127.0.0.1", scan_id="<id>")`
- `zap_active_scan(target_ip="127.0.0.1", url="http://127.0.0.1/")`
- `zap_alerts(target_ip="127.0.0.1", baseurl="http://127.0.0.1/")`

## Safety / advisory-only notes

- **Authorized testing only.** Active scans send attack payloads — run them
  only against targets you own or are explicitly authorized to test.
- ZAP daemon runs operator-side; only the scanned URL's host is
  target-gated through the allowlist.
- No log clearing, timestomping, EDR/AV defeat, DoS, or malware
  distribution.
- Pure stdlib (`urllib`); no new dependency.
