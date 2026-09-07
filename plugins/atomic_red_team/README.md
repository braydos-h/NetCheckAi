# atomic_red_team

Atomic Red Team test-YAML generator: maps discovered weaknesses to MITRE
ATT&CK techniques so the operator can validate SIEM/IDS/EDR detection
coverage. **Local-only YAML generation — this plugin does NOT execute the
tests.** Advisory output for the operator's own detections, never an action
against a target.

Source: `plugins/atomic_red_team/plugin.yaml`, `plugins/atomic_red_team/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers one MCP tool, wrapped with
`@audit_tool` (local text generation, no target touch):

- `generate_atomic_tests(findings)` — takes a comma-separated finding list
  (e.g. `"sqli, xss, open_ssh"`), maps each entry to its ATT&CK technique +
  atomic test via a vendored static table (case-insensitive, separator
  tolerant: `sql_injection` matches `sqli`), and returns
  `ATOMIC_TESTS_YAML:` text. Duplicate techniques are emitted once;
  unmapped findings are listed under `unmapped_findings:` with
  mapped/unmapped totals. Empty input returns an error (no exception).

Covered mappings (`finding` → technique / test / platform):

| Finding               | Technique      | Test                        | Platform  |
|-----------------------|----------------|-----------------------------|-----------|
| `sqli`                | `T1190`        | `T1190-1 Web Shell`         | `linux`   |
| `xss`                 | `T1059.007`    | `T1059.007-1 JavaScript execution` | `windows` |
| `command_injection`   | `T1059.004`    | `T1059.004-1 Shell command` | `linux`   |
| `weak_credentials`    | `T1110.001`    | `T1110.001-1 Password guessing` | `linux` |
| `default_credentials` | `T1078.001`    | `T1078.001-1 Default account login` | `linux` |
| `open_smb`            | `T1021.002`    | `T1021.002-1 SMB exec`      | `windows` |
| `open_ssh`            | `T1021.004`    | `T1021.004-1 SSH login`     | `linux`   |
| `exposed_service`     | `T1046`        | `T1046-1 Port scan`         | `linux`   |

## Config keys

None. The manifest declares no `config_section` and the tool reads no config
block. Loading is controlled by the standard plugin enablement (the manifest
ships `enabled: true`; disable via `plugins.disabled`).

## Credentials / env vars

None. No secret is read from config or environment.

## Usage example

The plugin loads by default (manifest `enabled: true`). To disable:

```yaml
plugins:
  disabled:
    - atomic_red_team
```

Generate detection-validation YAML from a run's findings:

- `generate_atomic_tests(findings="sqli, weak_credentials, open_ssh")`

Returns `ATOMIC_TESTS_YAML:` mapping each finding to its technique, plus an
`unmapped_findings:` list for anything the static table does not cover. If a
future variant ever executes tests against a live target, it must switch to
`@require_allowlist()`.

## Safety / advisory-only notes

- **Authorized testing only.** Generated YAML is for validating detection
  coverage on the operator's own SIEM/IDS/EDR.
- **Generation only, never execution.** The tool returns text; it runs no
  commands and contacts no target (`@audit_tool`, audit trail only).
- Pure stdlib; no new dependency.
