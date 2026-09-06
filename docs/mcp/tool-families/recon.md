---
title: "Tool Family: recon"
sources:
  - tools/mcp_tools/recon.py
  - tools/recon_pipeline.py
  - tools/recon_osint.py
  - tools/recon_diff.py
  - tools/socket_scan.py
  - tools/kernel/audit.py
tests:
  - tests/test_mcp_tool_registration.py
  - tests/test_recon_pipeline.py
subsystem: mcp
---

# Tool Family: recon

- **Registration source:** `tools/mcp_tools/recon.py:10 register_recon_tools(mcp, *, ctx)` — auto-discovered; no edit to `mcp_exploit_server.py`.
- **Gate:** all 7 tools `@require_allowlist()` (target-IP lock + audit trail).

## Tools Exported (7)

| Tool | Params | Result Shape | What it does |
|------|--------|--------------|--------------|
| `check_os` | `target_ip: str` | `OS_CHECK_RESULTS:\nTARGET: ...\nTTL: ...? + Port X/tcp: open - banner + OS_VERDICT: WINDOWS|LINUX|MIXED/DETECTED_BOTH|UNKNOWN\nCONFIDENCE: ...\nHINTS: ...\nWINDOWS_GUIDANCE|LINUX_GUIDANCE|...` | Ping TTL analysis (platform-aware `ping -n 1` vs `-c 1` + `TTL=`) + 22-port TCP banner grabs (common + eval-target lab ports 3000/8081/8082/8083/2222/2121/2323/4455/3306) with HTTP HEAD on 80/443/3000/8080/8081/8082/8083, scores `windows_score` vs `linux_score`, banner keyword heuristics (`tools/mcp_tools/recon.py:19-180`). |
| `quick_scan` | `target_ip: str`, `ports: str="22,80,135,139,443,445,3389,3000,8080,8081,8082,8083,2222,2121,2323,4455,3306"` | `format_socket_scan_results` output | Comma-separated ports → delegates to `tools.socket_scan.socket_scan_sync` native TCP-connect + banner grab (same impl as recon pipeline no-privilege fallback, `tools/mcp_tools/recon.py:183-198`). |
| `run_full_recon` | `target_ip: str`, `aggression: str="normal"` (`stealth|normal|aggressive|maximum`) | `RECON_RESULT: completed\nATTEMPT_ID: ...\nTARGET: ...\nOS: ...\nTTL: ...\nSCAN_DURATION: ...\nSCAN_TOOL: ...\nOPEN_PORTS: N ...\nSAVED_JSON: <attempt_dir>/recon_result.json\nSERVICES: ...` + warnings/errors | `ReconConfig.from_config(config, aggression_level) -> ReconPipeline.recon_host(target_ip)` (primary Nmap with RustScan/Masscan fallback + service-aware secondary enumeration). Persists JSON via `result.to_dict()` (`tools/mcp_tools/recon.py:204-273`). |
| `get_service_fingerprint` | `target_ip: str`, `port: int` | `SERVICE_FINGERPRINT: ip:port\nPORT: ...\nSERVICE_GUESS: ...\nBANNER: ...\nSSL/TLS INFO?: Issuer/Subject/SAN/Valid Until` | TCP connect + HTTP HEAD for 80/8080/8000/3000/5000; TLS ports 443/8443/636/993/995/465/989/990 try `_ssl_module` create_default_context + `getpeercert()` + SAN extraction, else plain banner. Service guess from port/banners (`tools/mcp_tools/recon.py:275-404`). |
| `run_udp_recon` | `target_ip: str`, `top_ports: int=100` | `UDP_PORTS: completed\nTARGET: ...\nSCAN_TOOL: ...\nUDP_PORT_COUNT: N\nUDP_PORTS: [...]` | `ReconPipeline.recon_udp(target_ip, top_ports)` via `nmap -sU --top-ports N -sV` (root-required → auto-downgrade). Filters `protocol=="udp"` services (`tools/mcp_tools/recon.py:413-460`). |
| `run_osint_recon` | `target_ip: str` | `OSINT: completed\nTARGET: ...\nHOSTNAME: ...\nREVERSE_DNS: ...\nIPV6_ADDRESSES: ...\nCERT_TRANSPARENCY: N certs\nSHODAN: enabled|disabled` | Delegates to `tools.recon_osint.run_osint(target_ip)` — PASSIVE only (reverse DNS, DNS AAAA IPv6, crt.sh cert transparency, optional Shodan); no active scanning (`tools/mcp_tools/recon.py:462-507`). |
| `diff_recon_runs` | `old_path: str`, `new_path: str` | `RECON_DIFF: completed\nTARGET: ...\nSUMMARY: ...\nADDED_PORTS: ...\nREMOVED_PORTS: ...\nCHANGED_SERVICES: N\nNEW_CVES: ...\nLOST_CVES: ...\nOS_CHANGED: ...` | Loads two `recon_result.json` snapshots via `tools.recon_diff.diff_recon_files` — no scanning; require_allowlist for audit consistency only (`tools/mcp_tools/recon.py:509-556`). |

## Parameters — Validation

- `target_ip` validated by `validate_target_or_ip` (IPv4/IPv6/FQDN) — returns `ERROR: Invalid target (IP or domain).` on fail (for the async/full tools) or `BLOCKED: target_ip is required.` for check_os/quick_scan.
- `port` must be `1..65535`; `top_ports` coerced to 100 when non-positive.
- `aggression` mapped via `{"stealth":stealth, "normal":normal, "aggressive/maximum":aggressive}`.

## Result Shape — Common

- `ATTEMPT_ID` from `_attempt_dir`; `recon_result.json` persisted per `run_full_recon`.
- OS hints derived deterministically; warnings/errors capped to first 5 entries.

## Dependencies

- `tools/recon_pipeline.ReconPipeline`, `ReconConfig`, `HostReconResult`
- `tools/socket_scan.socket_scan_sync`, `format_socket_scan_results`
- `tools/recon_osint.run_osint`, `tools/recon_diff.diff_recon_files`
- `tools/validation_utils.validate_target_or_ip`, `is_target_in_allowlist`
- `tools/kernel/allowlist._allowed_target_list` (allowlist lock)

## Config

- `recon.*` — aggression defaults, `dns_zone_transfer` (used by `dns_recon` family, not this family)
- `nmap.path`, `nmap.sudo`, `nmap.priv_fallback` — primary scanner privilege handling
- `exploit.require_explicit_allowlist`, `exploit.allowed_targets` — lock

## Auditing

All `@require_allowlist()` → writes `started` then `completed|blocked` to `exploit_audit.jsonl` with redacted args; `run_full_recon`/`run_udp_recon` are `async` handlers (audit wrapper handles both sync/async). `diff_recon_runs` is allowlist-gated for audit consistency though it touches no target.

## Validation

- Syntactic IP/FQDN check before any socket or pipeline call.
- Allowlist gate refuses out-of-scope hosts before connect/scan.
- No subprocess shell injection — recon tools use pipeline (no argv shell strings in the handlers themselves).

## Tests

- `tests/test_mcp_tool_registration.py` — expects `check_os`, `quick_scan`, `run_full_recon`, `get_service_fingerprint`
- `tests/test_recon_pipeline.py` (pipeline unit), `tests/test_domain_mcp_tools.py` covers domain recon but not this family's port scans; mock the pipeline/socket scan in family tests.

## Related Docs

- `docs/mcp/security.md` — allowlist lock
- `docs/architecture.md` — ReconPipeline shape
- `docs/mcp/tool-families/domain.md` — domain recon counterpart
