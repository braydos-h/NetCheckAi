---
title: "Tool Family: mitre"
sources:
  - tools/mcp_tools/mitre.py
  - tools/mitre_export.py
  - tools/mitre_technique_map.json
  - tools/kernel/audit.py
tests:
  - tests/test_mitre_export.py
subsystem: mcp
---

# Tool Family: mitre

- **Registration source:** `tools/mcp_tools/mitre.py:17 register_mitre_tools(mcp, *, ctx)` — auto-discovered, always registered.
- **Gate:** `@audit_tool` — local-only (reads `exploit_workspace/exploit_audit.jsonl` filtered by `target_ip`, writes a JSON layer file); no target touch, no network.
- **Purpose:** Map an authorized-testing run's audit trail to MITRE ATT&CK techniques and write a Navigator layer JSON for blue-team handoff.

## Tools Exported (1)

| Tool | Decorator | Params | Result Shape | Notes |
|------|-----------|--------|--------------|-------|
| `export_attack_navigator` | `@audit_tool` | `target_ip: str`, `output_path: str=""` | `MITRE_NAVIGATOR_EXPORT:` block or `BLOCKED: ...` | Local-only export; `output_path` coerced under `navigator_output_dir`. Empty audit trail returns `techniques: []`. |

## Signature

From `tools/mcp_tools/mitre.py:23`:

```python
@mcp.tool()
@audit_tool
def export_attack_navigator(target_ip: str, output_path: str = "") -> str:
```

The handler reads the `mitre` config block and delegates to the export function in `tools/mitre_export.py:269`:

```python
def export_attack_navigator(
    target_ip: str,
    output_path: str = "",
    *,
    audit_path: str | Path = "",
    technique_map_path: str | Path = "tools/mitre_technique_map.json",
    navigator_output_dir: str | Path = "reports/mitre",
    include_skills: bool = True,
) -> dict[str, Any]:
```

The MCP wrapper passes through only `target_ip` and `output_path`; the remaining keyword arguments come from config:

```python
result = _export_attack_navigator(
    target_ip,
    output_path,
    technique_map_path=mitre_cfg.get("technique_map", "tools/mitre_technique_map.json"),
    navigator_output_dir=mitre_cfg.get("navigator_output_dir", "reports/mitre"),
    include_skills=bool(mitre_cfg.get("include_skill_tags", True)),
)
```

## Inputs

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `target_ip` | `str` | required | Filters audit records by target; validated by `validate_target_or_ip`. Empty string exports all targets (per `tools/mitre_export.py:286-288`). |
| `output_path` | `str` | `""` | Optional layer filename; coerced under `navigator_output_dir` to prevent path traversal. Empty means auto-generated under the output dir. |

Example call:

```python
export_attack_navigator(target_ip="127.0.0.1")
export_attack_navigator(target_ip="127.0.0.1", output_path="run-127-0-0-1.json")
```

## Output format

On success the tool returns the block built at `tools/mcp_tools/mitre.py:44-50`:

```text
MITRE_NAVIGATOR_EXPORT:
layer_path: reports/mitre/<name>.json
techniques: <count>
technique_ids: T1059, T1595, ...
Open the layer JSON in ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/).
```

The underlying dict (per `tools/mitre_export.py:278-280`) is:

```json
{
  "layer_path": "reports/mitre/run-127-0-0-1.json",
  "techniques": 2,
  "technique_ids": ["T1059", "T1595"]
}
```

On failure the dict carries an `error` key and the tool returns a single line:

```text
BLOCKED: invalid target_ip: '...'
```

Failure semantics from `tools/mitre_export.py:19-25`:

| Condition | Behavior |
|-----------|----------|
| Empty audit trail | Layer with `techniques: []` |
| Unknown tool name | Skipped, never crashes |
| Malformed JSONL line | Line skipped |
| Missing output dir | Created with mkdir |
| Missing technique-map file | Falls back to built-in `_DEFAULT_MAP` |

## Technique mapping

Each audit record's `tool_name` maps to an ATT&CK technique ID via the static map (overridable by `tools/mitre_technique_map.json`), with occurrence counts per technique. Built-in fallback from `tools/mitre_export.py:45-61`:

| MCP tool name | Technique |
|---------------|-----------|
| `run_exploit_terminal` | `T1059` (Command and Scripting Interpreter) |
| `write_python_file`, `run_python_file` | `T1059.006` (Python) |
| `run_msf_module` | `T1210` (Exploitation of Remote Services) |
| `msf_generate_payload`, `generate_payload` | `T1027` (Obfuscated Files or Information) |
| `lateral_exec` | `T1021` (Remote Services) |
| `dump_credentials` | `T1003` (OS Credential Dumping) |
| `kerberoast` | `T1558.003` (Kerberoasting) |
| `run_hash_crack` | `T1110.002` (Password Cracking) |
| `run_web_scan` | `T1595` (Active Scanning) |
| `password_spray` | `T1110.003` (Password Spraying) |
| `asrep_roast` | `T1558.004` (AS-REP Roasting) |
| `golden_ticket` | `T1558.001` (Golden Ticket) |
| `pass_the_hash` | `T1550.002` (Pass the Hash) |

When `include_skills` is true, skill `mitre_attack` tags merge into the layer. Layer version is Navigator `4.5` (`_NAVIGATOR_LAYER_VERSION`), comments capped at 200 chars (`_MAX_COMMENT_CHARS`), techniques capped at 500 (`_MAX_TECHNIQUES`).

## Dependencies

- `tools/mitre_export.py` — `export_attack_navigator`, `load_technique_map`, `build_navigator_layer`
- `tools/mitre_technique_map.json` — curated tool-to-technique map
- `tools/skill_registry` — skill ATT&CK tags (when `include_skill_tags` is true)
- `tools/validation_utils.py` — `validate_target_or_ip`

## Config

From `config.yaml:482-486`:

```yaml
mitre:
  enabled: true
  technique_map: tools/mitre_technique_map.json
  navigator_output_dir: reports/mitre
  include_skill_tags: true
```

| Key | Default | Notes |
|-----|---------|-------|
| `mitre.technique_map` | `tools/mitre_technique_map.json` | Path to the tool-to-technique JSON map |
| `mitre.navigator_output_dir` | `reports/mitre` | `output_path` is coerced under this dir |
| `mitre.include_skill_tags` | `true` | Merge skill `mitre_attack` tags into the layer |

## Auditing

`@audit_tool` — `target_ip`/`output_path` are not secret; `started`/`completed|blocked` records mean layer exports appear in the audit trail itself.

## Validation

- `target_ip` is not allowlist-gated (local read) but filters the audit slice; invalid values return `{"error": ...}` → `BLOCKED: ...`.
- `output_path` traversal is coerced under `navigator_output_dir`.
- Audit fields are treated as data, never executed; comment length capped at 200 chars.

## Tests

- `tests/test_mitre_export.py` — technique mapping, empty audit, skill-tag merge, output dir coercion

## Related documentation

- [MCP security](../security.md) — audit trail source
- [MCP registration](../registration.md) — decorator contract
- [Terminal tool family](./terminal.md) — source of most mapped audit records

## Source map

- `tools/mcp_tools/mitre.py`
- `tools/mitre_export.py`
- `tools/mitre_technique_map.json`
- `tools/kernel/audit.py`
