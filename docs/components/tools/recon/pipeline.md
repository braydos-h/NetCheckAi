---
title: Recon — Pipeline
package: tools/recon
files: [pipeline.py, scanner.py, enumerator.py, config.py]
---

# Recon — Pipeline (`tools/recon/`)

Canonical recon implementation. `tools/recon_pipeline.py` is a deprecated shim re-exporting these modules. `ReconConfig.from_config` is the sole config entry point. See the family overview for enrichers, OSINT, diff, fast preset, socket fallback, and privilege handling.

## Architecture

```text
ReconPipeline.recon_host(target)            # pipeline.py:36
  → preflight probe (opt-in)                # probe_reachable; False+large sample = skip, None/small = proceed
  → PrimaryReconScanner.scan_host(target)   # scanner.py:160
      nmap → rustscan+nmap → masscan+nmap → python socket_scan
  → SecondaryEnumerator.enumerate_host(result)  # enumerator.py:33 (only if open_ports and parallel_secondary)
      per-service-family coroutines, semaphore-bounded, mutate result in place
  → get_attack_surface_summary(result)      # pipeline.py:113 (find_modules top-10)
```

Standalone additive path: `ReconPipeline.recon_udp` → `PrimaryReconScanner.recon_udp` → `_run_nmap_udp` (UDP only, no TCP scan, no secondary enumerators).

## Package map

| File | Role | Canonical for |
|---|---|---|
| `pipeline.py` | `ReconPipeline` orchestrator | `recon_host`, `recon_hosts`, `recon_udp`, `get_attack_surface_summary` |
| `scanner.py` | Primary scanning + `run_command` | `PrimaryReconScanner` |
| `enumerator.py` | Service-aware deep enumeration | `SecondaryEnumerator` |
| `config.py` | Data structures + config | `ServiceInfo`, `HostReconResult`, `ReconConfig`, `ToolAvailability` |

## `ReconPipeline` (`pipeline.py:23`)

```python
def __init__(self, config: ReconConfig | None = None) -> None
async def recon_host(self, target: str) -> HostReconResult
async def recon_hosts(self, targets: list[str]) -> list[HostReconResult]
async def recon_udp(self, target: str, top_ports: int | None = None) -> HostReconResult
def get_attack_surface_summary(self, result: HostReconResult) -> dict[str, Any]
```

Lifecycle of `recon_host`:

1. Optional preflight (`preflight_probe`): bare TCP `probe_reachable` on `preflight_ports` before the expensive scan. `False` (all refused) skips the full scan only when the probe set is at least `COMMON_PORTS`-sized; small-sample refused and `None` (timeout/filtered ambiguity) fall through to the normal scan. A skipped host returns an empty `HostReconResult` with an error note.
2. Primary: `self._primary.scan_host(target)`. Empty `open_ports` returns early (no secondary enumeration).
3. Secondary: `self._secondary.enumerate_host(result)` when `parallel_secondary` is true.
4. `scan_duration` clamped to a minimum of 0.0001s.

`recon_hosts` runs `recon_host` per target under `asyncio.gather` with `return_exceptions=True`. `recon_udp` defaults `top_ports` to `udp_top_ports` and delegates to the primary scanner. `get_attack_surface_summary` groups services by name and emits `services_by_name`, `high_value_targets` (ssh/rdp/smb), `credential_targets`, `web_targets` (http/https with headers/dirs/vulns from `svc.scripts`), `lateral_movement_targets` (smb/ldap), `privilege_escalation_hints` (docker ports 2375/2376/10250), and `recommended_attack_modules` (top 10 from `find_modules`).

## `PrimaryReconScanner` (`scanner.py:154`)

```python
def __init__(self, config: ReconConfig) -> None
async def scan_host(self, target: str) -> HostReconResult
async def recon_udp(self, target: str, top_ports: int = 100) -> HostReconResult
async def _run_nmap(self, target: str) -> HostReconResult | None
async def _run_nmap_udp(self, target: str, top_ports: int = 100) -> HostReconResult | None
async def _run_rustscan(self, target: str) -> HostReconResult | None
async def _run_masscan(self, target: str) -> HostReconResult | None
```

| Method | Line | Description |
|---|---|---|
| `scan_host` | 160 | Pyramid: nmap → rustscan+nmap → masscan+nmap → native socket scan; first stage with `open_ports` wins, errors accumulate |
| `_run_nmap` | 241 | Comprehensive TCP (`-sS -sV -O -Pn -T4 --script=vuln,default -p- -oX -`; stealth/aggressive variants by `aggression_level`); `apply_nmap_privilege` up front, one downgraded retry on `is_privilege_error` when `priv_fallback` is off; XML parse with grepable fallback; TTL → `os_family` |
| `_run_nmap_udp` / `recon_udp` | 337 / 439 | `-sU -sV -Pn --top-ports N --script=default,vuln -oX -`, parsed by `parse_udp_nmap_output` into `protocol="udp"` services + `udp_ports`; privilege retry uses a halved port set; `recon_udp` returns an error result when nmap is missing |
| `_run_rustscan` | 455 | Port discovery (`-a target -t 2000 -b 1000 --range 1-65535`) + targeted nmap service follow-up (top 50 ports); ports-only fallback when nmap fails |
| `_run_masscan` | 526 | `-p1-65535 --rate 1000 --wait 5 -oJ -` + nmap follow-up when available |
| `_parse_nmap_xml` / `_parse_nmap_grepable` | 601 / 689 | XML (hostname, MAC/vendor, osmatch, per-port service/scripts, hostscripts → `extended["hostscripts"]`) / grepable `-oG` fallback; open→`services`, filtered→`filtered_ports` |
| `_extract_ports_from_rustscan` / `_extract_ports_from_masscan` | 712 / 727 | `Open host:port` (+ `port -> Open`) / per-line JSON with regex fallback |
| `_ttl_to_os_family` | 750 | ≤64 Linux/Unix, ≤128 Windows, ≤255 Cisco/Network |

Command runner:

```python
async def run_command(cmd: list[str], *, timeout: int = 300, max_retries: int = 2,
                      retry_delay: float = 5.0, cwd: Path | None = None,
                      env: dict[str, str] | None = None,
                      capture_output: bool = True) -> tuple[bool, str, str, float]
```

Retries with exponential backoff (`retry_delay *= 1.5`) but short-circuits privilege errors (`is_privilege_error`) and `_NON_RETRYABLE_EXIT_CODES` (127, 126, 9009, 3221225477/86/76). Timeout kills the whole process group via `_kill_process`. Returns `(success, stdout, stderr, elapsed)`.

## `SecondaryEnumerator` (`enumerator.py:27`)

```python
def __init__(self, config: ReconConfig) -> None
async def enumerate_host(self, primary_result: HostReconResult) -> HostReconResult
```

`enumerate_host` builds one coroutine per detected service family, wraps each in a semaphore gate (`max_concurrent_secondary`), and gathers with `return_exceptions=True`. Coroutines mutate the shared `result` in place (no merge step); exceptions become `result.errors` entries. Families:

| Coroutine | Trigger | Tools / output |
|---|---|---|
| `_enumerate_http` (+ `_enumerate_http_service`) | http/https/http-proxy | Nikto, feroxbuster (gobuster fallback), nuclei, curl headers → `svc.scripts[nikto/feroxbuster/gobuster/nuclei/http_headers]`, `svc.technologies`, `evidence_refs` |
| `_enumerate_ssh` | ssh | nmap `ssh2-enum-algos,ssh-hostkey,ssh-auth-methods` + weak-cipher warnings + `hydra_ready` hint + `_map_openssh_cves` → `openssh_cves` |
| `_enumerate_smb` | microsoft-ds/smb/netbios-ssn/netbios-ns | enum4linux (null-session check), smbclient shares (`_extract_smb_shares`), nmap `smb-enum-*,smb-vuln-*` |
| `_enumerate_ldap` | ldap/ldaps/globalcatldap | ldapsearch anonymous bind, nmap `ldap-search,ldap-rootdse` |
| `_enumerate_ftp` | ftp | curl anonymous login, nmap `ftp-anon,ftp-vsftpd-backdoor,…` |
| `_enumerate_redis` | redis | Direct `nc` argv-list `INFO` probe (no shell); validates target via `validate_ipv4`/`is_fqdn` first |
| `_enumerate_elasticsearch` | elastic* | curl `_cluster/health` + `_cat/indices` |
| `_enumerate_docker_k8s` | ports 2375/2376/6443/10250/10255/30000 | curl docker `/version`, k8s `/api`, kubelet `/pods` |
| `_enumerate_rdp` | ms-wbt-server/rdp/terminal-server | nmap `rdp-enum-encryption,rdp-vuln-ms12-020`, NLA-disabled warning |

Additive `extended_enumerators` block (production default on via `from_config`; dataclass default off):

| Coroutine | Trigger | Output |
|---|---|---|
| `_enumerate_tls` | TLS-likely ports/services | nmap `ssl-cert,ssl-enum` → `svc.ssl_info` via `parse_tls_info` |
| `_enumerate_smtp` | smtp/smtps or ports 25/465/587 | nmap `smtp-commands,smtp-open-relay` → `svc.smtp_info` via `parse_smtp_banner` |
| `_enumerate_db` | DB ports/names | nmap `banner,default` → `svc.db_info` via `parse_db_banner` |
| `_enumerate_web_spider` | http/https | `http_spider` (bounded BFS, `asyncio.to_thread`) → `result.spider_results` |
| `_enumerate_osint` | always (once per host) | `run_osint` (passive) → `result.osint`, `result.ipv6_addresses` |

Depth flags (each opt-in, writes `result.extended[key]`, never raises): `_enumerate_subdomains` (crt.sh → `extended["subdomains"]`), `_enumerate_vhosts` (Host rotation → `extended["vhosts"]`), `_enumerate_waf` (header heuristics → `extended["waf"]`), `_enumerate_asn_whois` (RDAP → `extended["asn"]`), `_enumerate_cloud_metadata` (operator-box IMDS probe → `extended["cloud_metadata"]`), `_enumerate_snmp` (snmpwalk public → `extended["snmp"]`), `_enumerate_dns_zone_transfer` (dig AXFR → `extended["dns_zone"]`). HTTP ones take injectable `fetch_fn`, subprocess ones `run_fn`, so tests need no live network. Implementation note: per-service fan-out comments in the source describe serial-to-parallel refactors; exact concurrency bounds follow the shared semaphore above.

## `ReconConfig` keys (`config.py:199`)

```python
@classmethod
def from_config(cls, config: dict | None, **overrides: Any) -> "ReconConfig"
```

`from_config` reads the `nmap` section (path/sudo/priv_fallback) and the `recon` section (everything else); explicit kwargs win. `_concurrency_from_config` resolves `recon.max_concurrent_secondary`, else `recon.fast.service_concurrency`, default 3, minimum 1.

| Key | Dataclass default | `from_config` default | Effect |
|---|---|---|---|
| `nmap.path` / `sudo` / `priv_fallback` | `nmap` / false / true | same | Scanner binary, `sudo -n` prefix, `-sS`/`-O`→`-sT` downgrade |
| `recon.timeout_seconds` / `max_retries` / `retry_delay` | 300 / 2 / 5.0 | same | `run_command` budget for nmap paths |
| `recon.aggression_level` | `normal` | override only | `stealth`/`normal`/`aggressive` nmap argv |
| `recon.wordlist_path` | dirb common.txt | override only | feroxbuster/gobuster wordlist |
| `recon.fallback_enabled` | true | override only | Rustscan/masscan/socket fallback chain |
| `recon.parallel_secondary` / `max_concurrent_secondary` | true / 3 | 3 via `_concurrency_from_config` | Secondary fan-out on/off + semaphore bound |
| `recon.udp_top_ports` | 100 | override only | `recon_udp --top-ports N` |
| `recon.extended_enumerators` | false | **true** | TLS/SMTP/DB/spider/OSINT block |
| `recon.shodan_api_key` (+ `SHODAN_API_KEY` env) | `""` | env fallback | Empty disables Shodan in `run_osint` |
| `recon.subdomain_enum` / `vhost_discovery` / `waf_fingerprint` / `asn_whois` / `cloud_metadata_probe` / `snmp_enum` / `dns_zone_transfer` | false | false | Depth enumerators, each independently gated |
| `recon.preflight_probe` / `preflight_ports` / `preflight_timeout_ms` | false / [80, 443] / 1000 | same | Pre-scan reachability probe |

Data structures: `ServiceInfo` (`port, protocol, service, version, banner, cpe[], scripts{}, ssl_info, smtp_info, db_info, os_guess, confidence, technologies[]`, `to_dict`/`from_dict` tolerant of missing keys); `HostReconResult` (`target_ip, hostname, os_name/family/accuracy, ttl, mac/vendor, services[], open/filtered/udp_ports[], scan_duration/tool/raw_output` — `raw_output` dropped on `from_dict` round-trip for resume — `evidence_refs, errors/warnings, spider_results[], osint{}, ipv6_addresses[], extended{}`, plus `get_services_by_name/port`, `has_service/port`); `ToolAvailability.check(tool_name)` (`shutil.which` cache) / `reset()`.

## Examples

```python
from tools.recon.config import ReconConfig
from tools.recon.pipeline import ReconPipeline

pipeline = ReconPipeline(ReconConfig.from_config(config, aggression_level="normal"))
result = await pipeline.recon_host("10.0.0.50")
udp = await pipeline.recon_udp("10.0.0.50")          # additive UDP pass only
summary = pipeline.get_attack_surface_summary(result) # high-value/web/cred targets + top-10 modules

multi = await ReconPipeline().recon_hosts(["10.0.0.50", "10.0.0.51"])
```

```python
from tools.recon.config import ReconConfig

cfg = ReconConfig.from_config(
    {"nmap": {"sudo": True}, "recon": {"extended_enumerators": False}},
    aggression_level="stealth",
)
```

## Related documentation

- [Recon overview](./overview.md)
- [Kernel gates](../kernel/gates.md)
- [Kernel overview](../kernel/overview.md)
- [MCP tools](../../../mcp-tools.md)
- [Architecture](../../../architecture.md)

## Source map

- `tools/recon/pipeline.py`
- `tools/recon/scanner.py`
- `tools/recon/enumerator.py`
- `tools/recon/config.py`
- `tools/recon_pipeline.py`
- `tools/recon_enrichers.py`
- `tools/recon_osint.py`
- `tools/socket_scan.py`
- `tools/nmap_priv.py`
