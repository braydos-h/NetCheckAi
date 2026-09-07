# shodan_recon

Passive Shodan OSINT plugin. Enriches a host with ports, banners, services,
and CVEs from the Shodan REST API cache without sending any traffic to the
target. Advisory-only: it informs the agent's hypotheses, never touches the
target.

Source: `plugins/shodan_recon/plugin.yaml`, `plugins/shodan_recon/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`, `config`. Registers two MCP tools
(`shodan_host_lookup`, `shodan_search`) and a `shodan_recon` config section.

## Config keys

The API key lives under the existing top-level `recon` block in `config.yaml`:

```yaml
recon:
  shodan_api_key: "YOUR_SHODAN_KEY"
```

The plugin also registers a `shodan_recon` config section (known to
`ConfigValidator`, no unknown-key warning):

| Key       | Type   | Default | Meaning                                  |
|-----------|--------|---------|------------------------------------------|
| `enabled` | `bool` | `false` | Plugin-scoped enable flag                |

## Credentials / env vars

None. The only secret is `recon.shodan_api_key` in `config.yaml`, sent as the
`key` query parameter to `https://api.shodan.io` via stdlib `urllib`.

## Usage example

The plugin ships with `enabled: true` in its manifest, but the tools refuse
with `BLOCKED:` until `recon.shodan_api_key` is set (two-gate: manifest
opt-in + key present). To disable entirely:

```yaml
plugins:
  disabled:
    - shodan_recon
```

Once the key is set, the agent can call (against authorized targets only):

- `shodan_host_lookup(ip="127.0.0.1")` — ports, hostnames, org, OS, CVE list,
  and per-service product/version/CPE from Shodan's cache. Returns structured
  JSON; failures return `{"error": ...}`, never raise.
- `shodan_search(query="apache")` — free-text Shodan search (max 500 chars,
  up to 20 matches), returning ip, port, product, version, hostnames, and
  CVEs per match.

## Safety / advisory-only notes

- **Authorized testing only.** Use only against systems you own or are
  explicitly authorized to assess.
- **Never touches the target.** The only network call is a GET to
  `https://api.shodan.io`; the IP is sent to Shodan (third-party data
  source), not probed directly.
- Both tools use `@ctx.audit_tool` (free-text query tools, no `target_ip`
  param), so every call lands in the JSONL audit trail. The target-IP
  allowlist lock is not in play because Shodan is a third-party source.
- Shodan banners are untrusted third-party text: the plugin returns
  structured JSON only, strips control characters and caps strings at 200
  chars (`_clean`), and never auto-executes returned strings.
- Pure stdlib (`urllib`); no new dependency.
