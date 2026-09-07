# sliver_c2

Sliver C2 bridge: implant generation, team-server session listing, and
single-command session interaction. Mirrors `tools/metasploit_bridge.py` for
modern C2 via the Sliver gRPC client, with a `sliver` CLI fallback when the
Python bindings are absent.

Source: `plugins/sliver_c2/plugin.yaml`, `plugins/sliver_c2/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers three MCP tools, all wrapped
with `@ctx.require_allowlist(target_param="target_ip", audit=True)` so the
target-IP allowlist lock + JSONL audit trail apply automatically.

- `sliver_list_sessions(target_ip)` — list active implant sessions that have
  called back to the team server. Queries team-server state only.
- `sliver_generate_implant(target_ip, callback_host, callback_port=443, os_name="linux", arch="amd64", format="executable")` — generate an implant binary, written under the per-target workspace (`exploit_workspace/<target_ip>/`) for delivery via the exploit agent.
- `sliver_interact_session(target_ip, session_id, command)` — run one
  command on an existing session (single command, not an interactive shell).

## Config keys

```yaml
sliver_c2:
  enabled: false
  server_binary: sliver-server
  client_binary: sliver
  grpc_host: 127.0.0.1
  grpc_port: 31337
  config_path: ~/.sliver/config
```

| Key             | Type   | Default              | Meaning                                              |
|-----------------|--------|----------------------|------------------------------------------------------|
| `enabled`       | `bool` | `false`              | Plugin-scoped enable flag                            |
| `server_binary` | `str`  | `sliver-server`      | Manifest-declared team-server binary name            |
| `client_binary` | `str`  | `sliver`             | Manifest-declared operator binary name (CLI fallback resolves `sliver` via PATH) |
| `grpc_host`     | `str`  | `127.0.0.1`          | Team-server gRPC host used by the Python client      |
| `grpc_port`     | `int`  | `31337`              | Team-server gRPC port used by the Python client      |
| `config_path`   | `str`  | `~/.sliver/config`   | Operator config file for the gRPC client (`~`-expanded) |

## Credentials / env vars

None directly — authentication rides on the Sliver operator config file at
`config_path`. The operator must already be running a Sliver team server
with a valid config file. Requires the `sliver` Python package for the gRPC
path; without it the plugin degrades to the `sliver operator` CLI fallback
(resolved via PATH), and refuses with an error string if neither exists.

## Usage example

Opt in (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - sliver_c2

exploit:
  allowed_targets:
    - 127.0.0.1
```

Against an authorized target, the agent can list sessions, generate an
implant calling back to the operator listener at `127.0.0.1:443`, and run a
command on a live session:

- `sliver_list_sessions(target_ip="127.0.0.1")`
- `sliver_generate_implant(target_ip="127.0.0.1", callback_host="127.0.0.1", callback_port=443)`
- `sliver_interact_session(target_ip="127.0.0.1", session_id="<id>", command="whoami")`

## Safety / advisory-only notes

- **Authorized testing only.** Generate implants and run session commands
  only against systems you own or are explicitly authorized to assess.
- **Callback hosts are target-side and never auto-authorized.**
  `sliver_generate_implant` re-checks `callback_host` against
  `exploit.allowed_targets` and refuses with `BLOCKED:` when absent — add
  the exact `host:port` of the team-server listener, never a wildcard.
- Commands that pivot past the authorized target are the operator's
  responsibility; terminal target-lock semantics apply.
- No log clearing, timestomping, EDR/AV defeat, DoS, or malware
  distribution.
