# snmp

SNMP enumeration plugin: snmpwalk-style queries (system inventory, users,
processes) against a target's UDP/161 SNMP service, plus community-string
guessing from a wordlist. Pure stdlib — snmpwalk is invoked as an external
`net-snmp` binary, no pysnmp dependency. Target-touching tools are
allowlist-locked.

Source: `plugins/snmp/plugin.yaml`, `plugins/snmp/plugin.py`

## Capabilities

Manifest capabilities: `attack_module`, `mcp_tool`. Registers one attack
module, one config section, and two MCP tools:

- Attack module `SNMPEnumeration` (`target_services: ["snmp"]`,
  `target_ports: [161]`) — advisory `run()` describing SNMP enumeration via
  community strings, with a suggested
  `snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1` command and a
  `generate_python_script()` helper that snmpwalks the system MIB
  (`1.3.6.1.2.1.1`).
- `snmp_enum_target(target_ip, community="", oid="", version="")` — enumerate
  the target with snmpwalk (defaults: community from `SNMP_COMMUNITY` env or
  `"public"`, version from config, full tree when `oid` is empty; output
  capped at 4000 chars).
  `@require_allowlist(target_param="target_ip", audit=True)`.
- `snmp_crack_community(target_ip, wordlist="")` — probe community strings
  one at a time against the system MIB, stopping at the first that returns
  non-empty output; defaults to a 10-entry built-in list (`public`,
  `private`, `community`, `admin`, `snmp`, `read`, `write`, `cisco`,
  `default`, `secret`). A file wordlist is capped at 100 lines.
  `@require_allowlist(target_param="target_ip", audit=True)`.

Both tools refuse with `BLOCKED:` unless `snmp.enabled` is `true` in config
(double-gate: `plugins.enabled` + section flag).

## Config keys

```yaml
snmp:
  enabled: false
  timeout: 10
  default_version: 2c
  community_env: SNMP_COMMUNITY
```

| Key               | Type   | Default           | Meaning                                              |
|-------------------|--------|-------------------|------------------------------------------------------|
| `enabled`         | `bool` | `false`           | Section flag; both tools refuse without `true`       |
| `timeout`         | `int`  | `10`              | Per-probe snmpwalk timeout in seconds                |
| `default_version` | `str`  | `2c`              | SNMP version passed as `-v` when the call omits it   |
| `community_env`   | `str`  | `SNMP_COMMUNITY`  | Env var holding the default community string         |

The section is registered via `register_config_section`, so
`ConfigValidator` treats `snmp` as a known top-level key.

## Credentials / env vars

- `SNMP_COMMUNITY` (default name; override via `community_env`) — default
  community string, env-only. Falls back to `"public"` when unset. Note the
  community string is echoed back in `SNMP_ENUM_RESULT` output (it is a
  protocol credential for the target service, not an operator secret).

## Usage example

Opt in (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - snmp

snmp:
  enabled: true
  timeout: 10
  default_version: 2c

exploit:
  allowed_targets:
    - 127.0.0.1
```

Against an authorized target with SNMP exposed:

- `snmp_enum_target(target_ip="127.0.0.1")`
- `snmp_enum_target(target_ip="127.0.0.1", community="private", oid="1.3.6.1.2.1.1")`
- `snmp_crack_community(target_ip="127.0.0.1")`

## Safety / advisory-only notes

- **Authorized testing only.** Query and guess community strings only on
  systems you own or are explicitly authorized to test.
- Both tools are `@require_allowlist()`-gated: unlisted target IPs are
  refused, and every call lands in the JSONL audit trail.
- Community guessing is bounded (one working string stops the loop; file
  wordlists capped at 100 entries) — no unbounded brute force.
- Requires `net-snmp` (`snmpwalk`) on the operator box; a missing binary
  surfaces a clear error.
