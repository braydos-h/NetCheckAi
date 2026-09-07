# caldera

Caldera adversary-emulation plugin: lists and runs Caldera abilities through
an authorized Caldera server (target-side). The Caldera server is treated as
a target — it must be in `exploit.allowed_targets` — and every tool is
`@require_allowlist()`-gated so the target-IP allowlist lock + JSONL audit
trail apply automatically.

Source: `plugins/caldera/plugin.yaml`, `plugins/caldera/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers two MCP tools:

- `caldera_list_abilities(target_ip)` — list abilities from the Caldera
  server, where `target_ip` is the Caldera server IP (must be allowlisted).
  Returns an error when `caldera.url` is unset or the API key env var is
  empty; otherwise returns a stub describing the `GET
  {url}/api/v2/abilities` call to wire (stdlib `urllib.request` with an
  `Authorization: Bearer` header).
- `caldera_run_ability(target_ip, ability_id)` — run an ability, where
  `target_ip` is the target the ability runs against (must be allowlisted)
  and `ability_id` is required. Same config/API-key errors; otherwise returns
  a stub describing the `POST {url}/api/v2/operations` call to wire.

Both tools are currently stubs: the `@require_allowlist` gate is the live
safety surface, while the REST call itself is left for the operator to wire
with pure-stdlib `urllib.request` (keeps the plugin testable without a live
Caldera server).

## Config keys

The plugin reads a top-level `caldera` block (no `config_section` is declared
in the manifest):

```yaml
caldera:
  url: https://127.0.0.1:8888
  api_key_env: CALDERA_API_KEY
```

| Key          | Type  | Default           | Meaning                                        |
|--------------|-------|-------------------|------------------------------------------------|
| `url`        | `str` | `""`              | Caldera server base URL; tools error when empty |
| `api_key_env`| `str`| `CALDERA_API_KEY` | Env var holding the Caldera API key            |

The manifest ships `enabled: true` (lab build); disable via
`plugins.disabled` if unused.

## Credentials / env vars

- `CALDERA_API_KEY` (default name; override via `api_key_env`) — Caldera REST
  API key, env-only, never in config or logs. Only the first 4 characters
  ever appear in output (redacted preview); tools refuse when it is unset.

## Usage example

```yaml
plugins:
  enabled:
    - caldera

caldera:
  url: https://127.0.0.1:8888

exploit:
  allowed_targets:
    - 127.0.0.1
```

```bash
export CALDERA_API_KEY="<key>"
```

Then, against the authorized Caldera server / target:

- `caldera_list_abilities(target_ip="127.0.0.1")`
- `caldera_run_ability(target_ip="127.0.0.1", ability_id="<ability-id>")`

## Safety / advisory-only notes

- **Authorized testing only.** Run abilities only via a Caldera server you
  operate, against targets you own or are explicitly authorized to test; the
  Caldera server itself must be in `exploit.allowed_targets`.
- Both tools are `@require_allowlist()`-gated: unlisted server/target IPs are
  refused before anything runs.
- Requires a separately deployed Caldera server plus REST access; the plugin
  adds no dependency (stdlib only).
