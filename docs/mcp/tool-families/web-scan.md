---
title: "Tool Family: web-scan"
sources:
  - tools/mcp_tools/web_scan.py
  - tools/mcp_shared.py
  - tools/kernel/allowlist.py
  - tools/enhanced_reporting.py
  - tools/mitre_export.py
tests:
  - tests/test_mcp_web_scan.py
  - tests/test_nuclei_interop.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: web-scan

- **Registration source:** `tools/mcp_tools/web_scan.py:285 register_web_scan_tools(mcp, *, ctx)` — auto-discovered. First-class wrapper around the Kali web scanners otherwise shelled via `run_exploit_terminal`; gives parsed output, consistent audit records, and the same target-IP allowlist lock the shell-out path already has.
- **Gate:** `@require_allowlist()` on `target_ip` for `run_web_scan`; the two Nuclei interop tools are local-only `@audit_tool` (no target arg, no network).
- **Nuclei interop:** `run_web_scan` with `scanner="nuclei"` persists machine-readable `nuclei.jsonl` next to `<scanner>.log`; `parse_nuclei_results` maps those events to `TechnicalFinding` records (`nuclei-findings.json`); `generate_nuclei_template` turns a confirmed finding back into a reusable Nuclei template YAML.

## Tools Exported (3)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `run_web_scan` | `@require_allowlist()` on `target_ip` | `scanner: str`, `target_ip: str`, `port: int=80`, `path: str=""`, `options: str=""`, `timeout: int=300` | `WEB_SCAN_RESULT: completed\|failed\|timed_out\nATTEMPT_ID: ...\nSCANNER: ...\nTARGET: ip:port\nCOMMAND: <argv join>\nEXIT_CODE: N\nDURATION: Xs\nOUTPUT: <4000 tail>` + persists raw log to `<attempt_dir>/<scanner>.log` | Scanner must be in `_SCANNERS`; target via `validate_target_or_ip`; port 1–65535 (numeric strings coerced); `options` rejected on shell metacharacters then `shlex.split`. Missing binary → `SCANNER_NOT_INSTALLED` (skipped when sandboxed). Argv-only execution, never a shell. |
| `parse_nuclei_results` | `@audit_tool` only | `attempt_id: str=""` | `NUCLEI_FINDINGS: N confirmed-candidate\nATTEMPT_ID: ...` + up to 20 `FINDING: <id> \| <Severity> \| <template> \| <asset> \| <ATT&CK>` lines (or `... +N more`), full records saved as `nuclei-findings.json` | Reads `nuclei.jsonl` from the workspace-contained attempt dir; skips malformed lines; dedups by (template-id, host); `finding_id` collisions get a `-2`, `-3` suffix. Missing dir/file → `0 confirmed-candidate` with a "run run_web_scan with scanner nuclei first" note. |
| `generate_nuclei_template` | `@audit_tool` only | `finding_id: str=""` | `NUCLEI_TEMPLATE: VALID\|INVALID\nFINDING: ...\nTEMPLATE_ID: <slug>\nPATH: <workspace-relative>\nATTEMPT_ID: <source dir>\nDETAIL: ...` | Searches the workspace for `nuclei-findings.json` files, renders the template, writes `nuclei-template-<finding_id>.yaml` next to the source findings, then validates (YAML parse-back + schema, plus `nuclei -validate` when on PATH). Unknown id → `BLOCKED: unknown finding_id ... (run parse_nuclei_results first)`. |

## `_SCANNERS` and `_build_argv`

`_SCANNERS = {nikto, nuclei, sqlmap, gobuster, feroxbuster, whatweb, wpscan, dirb, dirbuster}` with `url = http://<target_ip>:<port>[path]` (port always explicit, `path` appended verbatim when non-empty) and `_DEFAULT_WORDLIST = /usr/share/wordlists/dirb/common.txt`:

| Scanner | Argv |
|---------|------|
| `nikto` | `["nikto", "-h", target_ip, "-p", port]` |
| `nuclei` | `["nuclei", "-u", url]` (+ `-jsonl -nc -o nuclei.jsonl` unless the operator already passed `-jsonl`/`-json`, `-nc`, `-o`/`-output`; run with `cwd=<attempt_dir>`) |
| `sqlmap` | `["sqlmap", "-u", url, "--batch"]` |
| `gobuster` / `feroxbuster` | `[scanner, "dir", "-u", url, "-w", _DEFAULT_WORDLIST]` |
| `dirb` | `["dirb", url, _DEFAULT_WORDLIST]` (no `dir` subcommand) |
| `dirbuster` | `["dirbuster", "-u", url, "-l", _DEFAULT_WORDLIST]` (headless CLI flags) |
| `whatweb` | `["whatweb", url]` |
| `wpscan` | `["wpscan", "--url", url, "--enumerate", "u"]` |

Extra `options` are appended after the base argv. Sandbox path runs the same argv via `run_argv_in_sandbox` (`cwd_host=<attempt_dir>`, `target_ip` + `command` passed for the sandbox gate); exit-code 127 / "No such file or directory" appends a `HINT` that the minimal worker image lacks the scanner and the agent should use a stdlib probe or a derived image instead of retrying.

## Nuclei event → finding mapping

`_nuclei_event_to_finding` reads `template-id` (also `templateID` / `template_id`; event skipped when absent), `info.name` / `info.severity` (normalized to `critical|high|medium|low|info`, else `info`), `info.classification` (`cvss-score` / `cvss-metrics`, falling back to per-severity defaults critical 9.1 / high 7.5 / medium 5.0 / low 3.0 / info 0.0, clamped to 0–10), `matched-at` (also `matched_at`; asset = matched URL else `host`/`ip` else `unknown`), `matcher-name`, `request`/`response` truncated to 500 chars as evidence, and `info.reference`/`references`. ATT&CK comes from the technique map with `run_web_scan`-key then `T1595` fallback (`_mitre_technique_for_template`). Records are `TechnicalFinding` with `finding_id = NUCLEI-<template-slug>-<host-slug>`, `confidence=0.7`, and a `nuclei -u <asset> -id <template>` reproduction step.

## Nuclei template generation and validation

`_render_nuclei_template` derives the template `id` slug (lowercased `vuln_class`, non-`[a-z0-9-]` → `-`, max 64 chars) and emits `id` / `info` (`name`, `author: breachpilot`, `severity`, `description`, `reference`, `classification.cvss-score` + optional `cvss-metrics`, `metadata` with `finding-id`, `affected-asset`, `mitre-technique`) / `http` (`GET {{BaseURL}}` with a `word` matcher on `body`, token from `_template_matcher_word` over evidence/title, else `vulnerable`). `_check_nuclei_template_schema` requires a top-level mapping with `id`, an `info` block with `name`/`severity`/`description` (severity in the Nuclei set or `unknown`), and a non-empty `http`/`requests` block whose matchers each declare `type`. `_validate_nuclei_template` returns `VALID`/`INVALID` with detail: YAML parse or schema failure → `INVALID`; `nuclei` absent from PATH → `VALID ... schema check only`; else `nuclei -t <path> -validate` (60 s timeout).

## Validation

- Unsupported scanner → `BLOCKED: unsupported scanner '...'. Allowed: ...`
- Missing/invalid target → `BLOCKED: target_ip is required.` / `BLOCKED: target_ip must be a valid IP address or domain.`
- Bad port (non-integer, bool, out of 1–65535) → `BLOCKED: port must be an integer between 1 and 65535.`
- `options` with `[;|&$`()<>]` or newline → `BLOCKED: options contains forbidden shell metacharacters.`; unparseable quoting → `BLOCKED: options string could not be parsed (unbalanced quotes).` (never reaches a shell — argv list only)
- `attempt_id` / `finding_id` must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,128}$` with no `..`, `/`, or `\`; attempt dirs are workspace-containment checked (`_resolve_attempt`); empty values → `BLOCKED: ... is required.`

## Typical flow

```python
# 1. Scan an authorized target (nuclei persists nuclei.jsonl for step 2).
run_web_scan(scanner="nuclei", target_ip="127.0.0.1", port=80, timeout=300)
# 2. Map the JSONL events to finding records.
parse_nuclei_results(attempt_id="<ATTEMPT_ID from step 1>")
# 3. Turn a confirmed finding back into a reusable template.
generate_nuclei_template(finding_id="NUCLEI-<template>-<host>")
```

## Dependencies

- `tools/kernel/allowlist.check_targets_allowlist` (via `@require_allowlist`), `_scanner_token_is_host`
- `tools/validation_utils.validate_target_or_ip`
- `tools/mcp_shared._run_with_pgrp_timeout`, `_attempt_dir`
- `tools/mcp_tools.registry` (`ToolContext`, `_positive_int`, `_run_with_pgrp_timeout`, `parse_extra_options`, `run_argv_captured`, `tool_slug`)
- `tools/enhanced_reporting.TechnicalFinding`, `CVSSScore`
- `tools/mitre_export.load_technique_map` (+ `tools/mitre_technique_map.json`)
- `shutil.which` for binary presence; `yaml.safe_dump` / `yaml.safe_load` for templates

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets` — the lock
- No per-scanner config; relies on the Kali wordlist location and binaries on `PATH` (or the sandbox worker image)

## Auditing

- `run_web_scan` via `@require_allowlist()` → `started` then `completed|blocked` (blocked flips `approved=False`). Raw scan log persisted to workspace for `read_workspace_file` retrieval and the audit trail.
- `parse_nuclei_results` / `generate_nuclei_template` via `@audit_tool` (local-only, no target IP in the audit record).

## Tests

- `tests/test_mcp_web_scan.py` — registration, unsupported-scanner/invalid-target rejection, out-of-allowlist block, shell-metachar rejection, happy path, not-installed case, URL-scanner argv building
- `tests/test_nuclei_interop.py` — tool registration, nuclei JSONL flag appending, operator-supplied JSON flags honored, event→finding mapping, dedup by template+host, blocked/missing attempt handling, template generation as valid YAML, blocked finding ids, `nuclei -validate` reporting without binary
- `tests/test_mcp_tool_registration.py` — expects `run_web_scan` presence

## Related documentation

- [Recon tool family](./recon.md) — recon pipeline counterpart
- [Terminal tool family](./terminal.md) — the shell-out path these scanners replace
- [MCP security](../security.md) — allowlist and validation detail
- [MCP registration](../registration.md) — decorator contract

## Source map

- `tools/mcp_tools/web_scan.py` — `register_web_scan_tools`, all 3 tools, `_build_argv`, `_SCANNERS`, `_DEFAULT_WORDLIST`, nuclei mapping/render/validate helpers
- `tools/enhanced_reporting.py` — `TechnicalFinding`, `CVSSScore`
- `tools/mitre_export.py` — `load_technique_map` (+ `tools/mitre_technique_map.json`)
- `tools/mcp_shared.py` — `_run_with_pgrp_timeout`, `_attempt_dir`, `check_targets_allowlist`
- `tools/validation_utils.py` — `validate_target_or_ip`
