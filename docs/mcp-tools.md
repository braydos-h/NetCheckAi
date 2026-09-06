# MCP Tool Layer

The MCP tool layer is how the AI-driven flows (Flow A exploit agent, recon,
swarm, foreign assistants) reach actual capabilities. Three servers exist,
with the exploit server carrying almost all of the attack surface. The
central wiring lives in `tools/mcp_tools/registry.py`; shared config,
audit, and the target-IP allowlist lock live in `tools/mcp_shared.py`.

## The Three MCP Servers

| Server | File | Role | Tools |
|---|---|---|---|
| Exploit | `mcp_exploit_server.py` | Permissive exploitation surface for the exploit agent / recon-first paths. Full terminal, workspace, Metasploit, credentials, AD/Kerberos, payloads, recon, research, sessions. Target-IP allowlist lock + audit trail. | ~120+ tools across ~30 families auto-discovered via `tools/mcp_tools/registry.py:collect_tools()` (pkgutil `register_*_tools` + AST decorator validation; no manual list) |
| Engine | `mcp_engine_server.py` | Advisory + history surface for foreign assistants (Claude Desktop, Cursor). Read-only: skill search/lookup, NVD CVE lookup, run history. No target touching, no terminal, no exploit surface (`mcp_engine_server.py:1-11`). | `search_skills`, `get_skill`, `cve_lookup`, `list_runs`, `get_run` (`mcp_engine_server.py:89-188`) |
| Legacy (defensive) | `mcp_server.py` | Scope-enforced Nmap scanning against `research.allowed_assets`. No exploit tools; every tool checks `_is_in_allowlist` (`mcp_server.py:79-108`) and the terminal is allowlisted Nmap shapes only (`mcp_server.py:283-312`). | `run_nmap_ping_sweep`, `run_nmap_triage_scan`, `run_nmap_basic_scan`, `run_nmap_service_scan`, `run_nmap_vuln_scan`, `run_limited_terminal`, `search_vulnerability_intel`, `search_cve_intel` |

All three share the HTTP transport hardening from
`tools/mcp_shared.run_mcp_http_server` (`tools/mcp_shared.py:1064-1084`):
loopback-only bind unless `--allow-public-bind` AND `MCP_ALLOW_PUBLIC_BIND=1`
(two-person rule, `tools/mcp_shared.py:1011-1030`), optional
`MCP_HTTP_TOKEN` bearer auth (`tools/mcp_shared.py:1033-1061`).

## Central Registry Wiring

`tools/mcp_tools/registry.py` is the dependency bundle + shared-helper module
for all exploit tool families. `mcp_exploit_server.create_mcp_server`
(`mcp_exploit_server.py:76-184`) builds the shared services, creates the two
decorator factories, and packages them into a `ToolContext`
(`tools/mcp_tools/registry.py:104-112`):

```python
require_allowlist = make_require_allowlist(workspace, config)  # mcp_exploit_server.py:141
audit_tool = make_audit_tool(workspace)                        # mcp_exploit_server.py:142
ctx = ToolContext(workspace, config, search, nvd, researcher,
                  audit_tool, require_allowlist)               # mcp_exploit_server.py:143-151
```

Every family exports `register_<family>_tools(mcp, *, ctx)` and is wired in
(`mcp_exploit_server.py:153-168`). The registry also re-exports shared
helpers the families `import *` from — `_attempt_dir`, `_run_with_pgrp_timeout`,
`_extract_scanner_targets`, `check_targets_allowlist`, stdlib modules
(`tools/mcp_tools/registry.py:478-495`). `_run_with_pgrp_timeout` is a
compatibility shim so old tests that monkeypatch
`mcp_exploit_server._run_with_pgrp_timeout` still control execution
(`tools/mcp_tools/registry.py:115-138`). Plugins may register extra tools via
`PLUGIN_REGISTRY.mcp_tool_factories`, wrapped in best-effort try/except
(`mcp_exploit_server.py:170-182`).

Subprocess execution everywhere funnels through `_run_with_pgrp_timeout`
(`tools/mcp_shared.py:915-997`): POSIX starts the child in its own session and
kills the whole process group (`os.killpg SIGKILL`) on timeout; Windows falls
back to `proc.kill()`. `subprocess.TimeoutExpired` is re-raised.

## Decorators and the Audit Trail

### `@require_allowlist` — target-IP gate for structured-target tools

`make_require_allowlist(workspace, config)` returns a decorator factory
(`tools/mcp_shared.py:651-750`). Applied as `@require_allowlist()` (target
param defaults to `target_ip`) or `@require_allowlist("domain")` (domain
families, e.g. `tools/mcp_tools/domain.py:292`). Behavior:

1. Binds the handler args and reads the target param (`tools/mcp_shared.py:671`).
2. Checks `_check_allowlist` (`tools/mcp_shared.py:558-571`): if
   `exploit.require_explicit_allowlist` is False → allowed; else the target
   must be in `_allowed_target_list(config)` via `is_target_in_allowlist`.
3. Writes a `started` audit record (`approved=allowed`), returns a
   `BLOCKED:` marker when disallowed, and on completion writes a `completed`
   or `blocked` record — inspecting the result string for blocked markers
   (Bug #16, `tools/mcp_shared.py:690-705`).
4. Handles sync and async handlers, preserving `__signature__` for FastMCP
   introspection.

### `@audit_tool` — audit for tools without a structured target

`make_audit_tool(workspace)` (`tools/mcp_shared.py:814-885`) wraps tools whose
target lives inside free text (msfconsole commands, lhost callbacks, script
bodies). It records `started`/`completed` (or `blocked`) rows and derives the
touched host(s) via `_extract_audit_target` (`tools/mcp_shared.py:779-811`):
RHOSTS/RHOST values from `command`/`script_content` plus `lhost` args. Result
markers `BLOCKED:`, `TERMINAL_RESULT: BLOCKED`, `ROOT_CMD_RESULT:`, `ERROR:`
flip the completion to `approved=False, status="blocked"`
(`tools/mcp_shared.py:763-776`).

### Audit log and redaction

Every record is appended to `exploit_workspace/exploit_audit.jsonl` by
`_audit_log` (`tools/mcp_shared.py:459-491`) with timestamp, target, tool
name, approved, status, command, args, attempt_id, code sha256, duration.
The log is append-only plaintext, so arguments are redacted before writing:
`_redact_args` (`tools/mcp_shared.py:429-456`) masks values whose parameter
name is a secret (`_SECRET_ARG_NAMES`, e.g. password/ntlm_hash/kerberos_ticket/
api_key, `tools/mcp_shared.py:270-286`), wholesale-redacts `input_text` and
`notes` (`_WHOLESALE_REDACT_FIELDS`, `tools/mcp_shared.py:386`), and scans
remaining strings for inline credential *shapes* (`_mask_secret_content`,
`tools/mcp_shared.py:389-408`): URL `user:pass@`, `-u user:pass`, `--password v`,
hydra-style `-p v` (scoped to hydra/medusa/crackmapexec/evil-winrm),
`set SMBPass v`, `-hashes LM:NT`, `-ntlm`, `KEY=VALUE` secrets,
`Authorization: Bearer`, python `auth=("u","p")` (`tools/mcp_shared.py:308-375`).

Attempt directories are `exploit_workspace/<ts>_<micros>_<random>` — the
random suffix prevents concurrent swarm dispatch from colliding on the same
microsecond (Bug #17, `tools/mcp_shared.py:889-898`).

## The Target-IP Allowlist Lock

The one attack-mode safety kept in the tool layer. `full_access` auto-approves
everything with no command-content/scope/pivot inspection; the allowlist IS
the lock (`tools/mcp_tools/terminal.py:57-94` docstring).

### `_allowed_target_list` — the effective allowlist

`tools/mcp_shared.py:494-534`. Union of:

- `config.yaml` → `exploit.allowed_targets` (operator-authorized extras —
  callback/C2 hosts)
- `EXPLOIT_TARGET` — the operator's literal `--target` (IP **or** domain), always set
- `EXPLOIT_TARGET_IP` — resolved IP for a domain target (set only for domains)
- `EXPLOIT_TARGET_DOMAIN` — the domain string (set only for domains)
- `EXPLOIT_DISCOVERED_TARGETS` — comma-separated hosts/IPs auto-authorized
  mid-run by subdomain expansion

These env vars are threaded into the MCP server process by
`tools/mcp_session.open_exploit_mcp_session` (`tools/mcp_session.py:254-266`):
`EXPLOIT_TARGET` is the primary lock identity, `EXPLOIT_TARGET_IP` lets
IP-based tools (nmap/metasploit) target the resolved host, and
`EXPLOIT_TARGET_DOMAIN` lets HTTP tools use the domain for Host/SNI.
`add_discovered_target(host, ip)` (`tools/mcp_shared.py:537-555`)
runtime-extends the allowlist for subdomains discovered by
`enumerate_subdomains` (each host is still gated through
`is_target_in_allowlist` — it only adds to the operator-authorized set, it
does not bypass the check).

### Matching (`tools/validation_utils.is_target_in_allowlist`, `tools/validation_utils.py:380-420`)

Case-insensitive. Exact IP or domain; `*.wildcard` domain suffix match
(`*.example.com` matches `a.example.com`); CIDR containment
(`ip_address in ip_network`, `strict=False`); normalized IP equality.

### Enforcement points

- **Structured target tools**: `@require_allowlist` (above).
- **Free-text terminal commands**: `_target_lock_block` in
  `tools/mcp_tools/terminal.py:57-94` — extracts destination tokens
  (command-analyzer URL authorities, `/dev/tcp` hosts, embedded IPs, scanner
  verb targets via `_extract_scanner_targets`, `tools/mcp_tools/registry.py:366-409`)
  and refuses the command if any resolves off-list. Used by
  `run_exploit_terminal` (`terminal.py:196`), `run_as_root` (`terminal.py:459`),
  `start_tmux_session` / `send_to_session` / `start_background_job`
  (`tools/mcp_tools/sessions.py:33,55,93`), and statically on the script body
  of `run_python_file` (`tools/mcp_tools/workspace.py:117-126`).
- **Free-text Metasploit / callback tools**: `check_targets_allowlist`
  (`tools/mcp_shared.py:622-648`) checks a list of host tokens; used by
  `msfconsole_command`, `msf_interact_session`, `msf_run_resource_script`
  (RHOSTS extraction via `_extract_msf_rhosts`, `tools/mcp_shared.py:599-619`,
  which also catches meterpreter pivot verbs `portfwd -r`, `route add`,
  `autoroute`), `msf_generate_payload`/`generate_payload`/`msf_start_handler`
  (lhost callback), `msf_run_recipe`, `msf_post_portfwd`/`msf_post_route`
  (pivot lock), `kerberoast`/AD tools' `dc_ip` (`_gate_dc`,
  `tools/mcp_tools/ad.py:41-51`), `responder_relay` (relay target list built
  ONLY from `_allowed_target_list`, `tools/mcp_tools/ad.py:271-278`),
  `start_listener` socks_pivot `upstream_host`, `spawn_subagent` target, and
  `run_campaign_step`'s state.json target.
- **Empty-allowlist behavior**: with `require_explicit_allowlist: true` but
  no targets, checks fail closed (`tools/mcp_shared.py:565`); with the flag
  false, the lock is off everywhere (each gate short-circuits).

## Permission Resolution (`_resolve_exploit_permission`)

`tools/cli_exploit_settings.py:12-30`. The permission comes from
`config.yaml` → `exploit.permission`; an unknown value **or a missing key**
falls back to `READ_ONLY` via the `.get("permission", "read_only")` default —
the safe baseline, so a partial/missing config never silently becomes live.
Recon relies on this: recon builds settings with
`ExploitPermission.READ_ONLY` unconditionally (`tools/cli_exploit_settings.py:157-164`),
and attack mode only upgrades to `FULL_ACCESS` when config explicitly grants
it (`tools/cli_exploit_settings.py:112-115`). `READ_ONLY` short-circuits in
the policy layer (`tools/exploit_agent/policy.py:380-411`) and tool calls are
refused (`tools/exploit_agent/tool_calls.py:279`). The MCP tool layer itself
does not check permission — it relies on the allowlist lock; permission is a
Flow A policy-layer concept.

## Exception-Group Handling (`tools/exceptions.py`)

Anyio task groups raise `BaseExceptionGroup` on MCP subprocess death — **not**
an `Exception` subclass — so bare `except Exception` around
`stdio_client` / `streamable_http_client` / `ClientSession.initialize()` /
`session.call_tool()` silently misses real errors. Rules
(`tools/exceptions.py:1-8`):

- Catch with `_EXC_GROUP_CATCH = (Exception, BaseExceptionGroup)` on Python
  3.11+ (`tools/exceptions.py:38-41`); on older Pythons it degrades to
  `(Exception,)` since `BaseExceptionGroup` doesn't exist.
- `_is_exception_group(exc)` (`tools/exceptions.py:15-19`) identifies PEP 654
  groups (checks `BaseExceptionGroup` or duck-types `exceptions` tuple attr).
- `_log_nested_exceptions(exc)` (`tools/exceptions.py:22-35`) recursively
  walks group children and prints each nested traceback with an index prefix —
  use it in the except block so the real cause surfaces instead of the group
  wrapper.

## Tool Families and Tools

Registration requirement (AGENTS.md rule 4): every exploit MCP tool is
decorated (`@mcp.tool()` + `@audit_tool` or `@require_allowlist(...)`) inside
its family module — single-source via `tools/mcp_tools/registry.py:collect_tools()` (pkgutil + AST validation, fails CI if decorator missing); no manual list edit in `mcp_exploit_server.py` (30 families — 24 in `tools/mcp_tools/` (23 modules + the `terminal/` package) + 6 in `tools/mcp_tools/modules/*.py`).

Legend: **Lock** = `@require_allowlist` (structured `target_ip`/`domain` param
gated by the allowlist), `audit` = `@audit_tool`, `targets` = manual
`check_targets_allowlist` on extracted hosts, `cfg` = config-gated
registration, `—` = neither (no target touch).

### Terminal — `tools/mcp_tools/terminal.py`

| Tool | Params | Target | Lock |
|---|---|---|---|
| `run_exploit_terminal` | `command` | free text | lock via `_target_lock_block` + audit |
| `run_as_root` | `command` | free text | lock via `_target_lock_block` + audit |
| `apt_install` | `packages` | — | audit |
| `pip_install` | `packages` | — | audit |
| `git_clone` | `repo_url`, `target_dir` | — | audit |
| `install_package` | `manager`, `packages` | — | audit |
| `download_and_install` | `url`, `install_type`, `target_name` | — | audit |
| `update_system` | `upgrade` | — | audit |
| `check_environment` | `tools` | — | — |
| `preflight_env_check` | — | — | — |

All subprocesses use `_run_with_pgrp_timeout`; long scans should redirect to a
file read back via `read_workspace_file`. `apt_install`/`install_package`
(apt/snap)/`run_as_root` short-circuit when passwordless sudo is unavailable
(`_require_sudo_or_pivot`, `terminal.py:97-129`) to avoid hanging on an
interactive prompt.

### Workspace — `tools/mcp_tools/workspace.py`

| Tool | Params | Target | Lock |
|---|---|---|---|
| `write_python_file` | `filename`, `code`, `binary` | — | audit |
| `run_python_file` | `target_ip`, `filename` | yes | `@require_allowlist` + static body scan |
| `read_workspace_file` | `filename` | — | audit |
| `list_workspace` | — | — | — |

`binary=True` writes base64-decoded raw bytes (byte-exact for keys/PEM);
`run_python_file` passes the target as `sys.argv[1]`, `--target`, and
`ACTIVE_CHECK_TARGET`. Operator-box filesystem is unrestricted (LAB BUILD).

### Recon — `tools/mcp_tools/recon.py`

| Tool | Params | Target | Lock |
|---|---|---|---|
| `check_os` | `target_ip` | yes | allowlist |
| `quick_scan` | `target_ip`, `ports` | yes | allowlist |
| `run_full_recon` | `target_ip`, `aggression` | yes | allowlist |
| `run_udp_recon` | `target_ip`, `top_ports` | yes | allowlist |
| `run_osint_recon` | `target_ip` | yes | allowlist |
| `get_service_fingerprint` | `target_ip`, `port` | yes | allowlist |
| `diff_recon_runs` | `old_path`, `new_path` | no touch | allowlist (audit consistency) |

Recon pipelines (`ReconPipeline`) honor `nmap.sudo`/`priv_fallback` for
privileged flags.

### Research — `tools/mcp_tools/research.py` (no target touch, no lock)

| Tool | Params | Lock |
|---|---|---|
| `search_exploit_db` | `query` | — |
| `search_web_exploit` | `query` | — |
| `fetch_webpage` | `url` | — |
| `deep_research` | `query` | — |
| `search_cve_intel` | `query` | — |
| `cve_to_poc` | `cve_id` | — |

Research tools are read-only; web tools return
`disabled_research_tools_message` when research API keys are missing.

### Runtime Skills — `tools/mcp_tools/runtime_skills.py` (cfg: `skills.enabled` + `allow_model_lookup`)

| Tool | Params | Lock |
|---|---|---|
| `list_runtime_skills` | `include_maybe`, `limit` | audit |
| `search_runtime_skills` | `query`, `tags`, `include_maybe`, `limit` | audit |
| `load_runtime_skill` | `name`, `reason` | audit |
| `list_skill_references` | `name` | audit |

Advisory methodology only — never changes scope/permission/approval.

### Peer Models — `tools/mcp_tools/peer_models.py` (cfg: `multi_model.enabled`)

| Tool | Params | Lock |
|---|---|---|
| `consult_peer_models` | `question`, `context`, `preferred_aliases` | audit |

Peers receive no tool schemas; consultation budget from
`multi_model.max_consultations`.

### Parallel Agents — `tools/mcp_tools/parallel_agents.py` (cfg: `swarm.parallel_enabled`)

| Tool | Params | Target | Lock |
|---|---|---|---|
| `spawn_subagent` | `phase`, `target`, `objective`, `services`, `known_cves` | yes | `check_targets_allowlist` + audit |
| `await_subagent` | `subagent_id`, `timeout_seconds` | — | audit |
| `list_subagents` | — | — | audit |

Sub-agents run in-process via `SwarmOrchestrator.route()` (Path B — no live
MCP ClientSession) and inherit the allowlist lock at spawn time.

### Metasploit — `tools/mcp_tools/metasploit.py`

| Tool | Params | Target | Lock |
|---|---|---|---|
| `run_msf_module` | `module`, `target_ip`, `options` | yes | allowlist |
| `msf_run_exploit` | `module`, `target_ip`, `options`, `payload`, `wait_seconds` | yes | allowlist |
| `msf_run_auxiliary` | `module`, `target_ip`, `options`, `wait_seconds` | yes | allowlist |
| `msf_run_recipe` | `name`, `target_ip`, `session_id`, `options` | yes | targets (RHOSTS) + audit |
| `msfconsole_command` | `command`, `wait_seconds`, `read_lines` | free text | targets (RHOSTS/pivots) + audit |
| `msf_run_resource_script` | `script_content` | free text | targets (RHOSTS) + audit |
| `msf_interact_session` | `session_id`, `command`, `wait_seconds` | free text | targets (RHOSTS) + audit |
| `msf_generate_payload` | `payload_type`, `lhost`, `lport`, `fmt`, `platform`, `arch`, `options`, `encoder`, `iterations` | callback | targets (lhost) + audit |
| `msf_start_handler` | `lhost`, `lport`, `payload`, `options` | callback | targets (lhost) + audit |
| `msf_post_portfwd` | `session_id`, `remote_host`, `remote_port`, `local_port` | pivot | targets + audit |
| `msf_post_route` | `session_id`, `subnet` | pivot | targets + audit |
| `msfconsole_start` / `msfconsole_stop` | — | — | audit |
| `msf_list_sessions` / `msf_kill_session` | `session_id` | — | audit |
| `msf_run_post_module` | `module`, `session_id`, `options` | — | audit |
| `msf_post_hashdump` / `msf_post_getsystem` | `session_id` | — | audit |
| `msf_stop_handler` | — | — | audit |

`run_msf_module` builds a resource file from `shlex`-parsed `key=value`
options with metacharacter rejection (C1) and runs msfconsole with an argv
list (no shell).

### Payloads — `tools/mcp_tools/payloads.py`

| Tool | Params | Target | Lock |
|---|---|---|---|
| `generate_payload` | `payload_type`, `lhost`, `lport`, `format`, `platform`, `arch`, `options` | callback | targets (lhost) + audit |

Whitelists payload types/formats/platforms/archs; options rejected on shell
metacharacters; msfvenom run as argv list.

### Credentials — `tools/mcp_tools/credentials.py`

| Tool | Params | Target | Lock |
|---|---|---|---|
| `cred_store_add` | `target_ip`, `username`, `password`, `credential_type`, `source_host`, `target_host`, `notes` | yes | allowlist |
| `cred_store_get` | `target_ip`, `username`, `target_host`, `include_secret` | yes | allowlist |
| `cred_store_list` | `target_ip` | yes | allowlist |
| `cred_store_confirm` | `target_ip`, `username`, `target_host`, `credential_type`, `validated` | yes | allowlist |
| `lateral_exec` | `target_ip`, `method`, `username`, `password`, `ntlm_hash`, `command` | yes | allowlist |
| `dump_credentials` | `target_ip`, `method`, `username`, `password`, `ntlm_hash`, `domain`, `output_file`, `target_user` | yes | allowlist |
| `kerberoast` | `target_ip`, `domain`, `username`, `password`, `ntlm_hash`, `dc_ip` | yes | allowlist + targets (dc_ip) |

Vault secrets are Fernet-encrypted at rest (`CredentialStore`); the `notes`
and `password` args are redacted from the audit log. `cred_store_confirm`
requires `validated=True` — unvalidated credentials are never promoted.

### Active Directory / Kerberos — `tools/mcp_tools/ad.py` (all per-tool gates under `exploit.ad_kerberos.*`, default OFF except `smb_signing_check`)

| Tool | Params | Target | Lock |
|---|---|---|---|
| `asrep_roast` | `target_ip`, `domain`, `username`, `password`, `ntlm_hash`, `dc_ip`, `users_file` | yes | allowlist + targets (dc_ip) |
| `pass_the_hash` | `target_ip`, `username`, `ntlm_hash`, `service`, `command` | yes | allowlist |
| `adcs_enum` | `target_ip`, `username`, `password`, `ntlm_hash`, `domain`, `dc_ip` | yes | allowlist + targets (dc_ip) |
| `bloodhound_collect` | `target_ip`, `domain`, `username`, `password`, `ntlm_hash`, `dc_ip` | yes | allowlist + targets (dc_ip) |
| `responder_relay` | `target_ip`, `iface`, `command` | yes | allowlist + relay list from `_allowed_target_list` only |
| `smb_signing_check` | `target_ip` | yes | allowlist (detection-only, default ON) |
| `golden_ticket` | `target_ip`, `domain`, `username`, `krbtgt_hash`, `sid`, `duration` | yes | allowlist |

All commands run as argv lists (no shell) via `_run_with_pgrp_timeout`;
outputs land under `exploit_workspace/<ip>/<attempt_id>/`.

### Attack Modules & Orchestration — `tools/mcp_tools/attack_modules.py`

| Tool | Params | Target | Lock |
|---|---|---|---|
| `jwt_tamper` | `target_ip`, `jwt_token` | yes | allowlist |
| `ssti_probe` | `target_ip`, `port` | yes | allowlist |
| `graphql_introspect` | `target_ip`, `port` | yes | allowlist |
| `race_request` | `target_ip`, `port`, `endpoint`, `concurrent` | yes | allowlist |
| `timing_oracle` | `target_ip`, `port` | yes | allowlist |
| `request_smuggling_probe` | `target_ip`, `port` | yes | allowlist |
| `password_spray` | `target_ip`, `port`, `password` | yes | allowlist |
| `cve_to_exploit_synth` | `target_ip`, `cve_id`, `service_name`, `version` | yes | allowlist |
| `run_attack_module` | `module_name`, `target_ip`, `options` | yes | allowlist |
| `create_attack_plan` | `target_ip`, `target_os`, `known_cves` | yes | allowlist |
| `get_current_plan` | `target_ip` | yes | allowlist |
| `replan` | `target_ip`, `failure_reason` | yes | allowlist |
| `craft_exploit` | `target_ip`, `service_name`, `version`, `os_hint`, `module_name` | yes | allowlist |
| `start_autonomous_campaign` | `target_ip`, `goal`, `aggression_level` | yes | allowlist |
| `run_campaign_step` | `campaign_id` | from state.json | targets + audit |
| `hash_crack_identify` | `hash_value` | — | — |
| `list_attack_modules` | — | — | — |
| `mutate_exploit` | `script_id`, `failure_output` | — | — |
| `get_campaign_status` | `campaign_id` | — | — |

`cve_to_exploit_synth` uses the verified `cve_to_poc` resolver (never
invents PoC URLs) and branches templates per CVE family.

### Web Scan — `tools/mcp_tools/web_scan.py`

| Tool | Params | Target | Lock |
|---|---|---|---|
| `run_web_scan` | `scanner`, `target_ip`, `port`, `path`, `options`, `timeout` | yes | allowlist |

Scanners: nikto/nuclei/sqlmap/gobuster/feroxbuster/whatweb/wpscan/dirb/
dirbuster; parsed output + audit record; options sanitized like
`generate_payload`.

### Domain — `tools/mcp_tools/domain.py` (domain families lock on the `domain` param)

| Tool | Params | Target | Lock |
|---|---|---|---|
| `resolve_domain` | `domain`, `record_types` | domain | `@require_allowlist("domain")` |
| `enumerate_subdomains` | `domain`, `sources`, `max_results` | domain | `@require_allowlist("domain")`; auto-authorizes discoveries |
| `dns_recon` | `domain`, `zone_transfer` | domain | `@require_allowlist("domain")` |
| `domain_whois` | `domain` | domain | `@require_allowlist("domain")` |
| `vhost_enum` | `target_ip`, `port`, `domain`, `wordlist`, `timeout` | IP | allowlist |

`enumerate_subdomains` adds every discovered host to
`EXPLOIT_DISCOVERED_TARGETS` via `add_discovered_target` (host + resolved IP)
and flags dangling-CNAME takeover candidates. AXFR is opt-in and double-gated
by `recon.dns_zone_transfer`.

### Cracking — `tools/mcp_tools/cracking.py` (local-only, no target)

| Tool | Params | Lock |
|---|---|---|
| `run_hash_crack` | `hash_value`, `tool`, `hash_mode`, `wordlist`, `rules`, `timeout` | audit |

Runs hashcat/john locally, auto-identifies mode, returns recovered plaintext
via `--show`.

### Sessions — `tools/mcp_tools/sessions.py`

| Tool | Params | Target | Lock |
|---|---|---|---|
| `start_tmux_session` | `name`, `command` | free text | lock via `_target_lock_block` + audit |
| `send_to_session` | `name`, `input_text` | free text | lock via `_target_lock_block` + audit |
| `start_background_job` | `name`, `command` | free text | lock via `_target_lock_block` + audit |
| `start_listener` | `name`, `port`, `listener_type`, `protocol`, `directory`, `upstream_host`, `upstream_port` | pivot | targets (socks_pivot upstream) + audit; new types cfg-gated |
| `read_session_output` / `kill_session` | `name` | — | — |
| `read_job_output` / `stop_background_job` | `name` | — | — |
| `read_listener_output` / `stop_listener` | `name` | — | — |
| `list_sessions` / `list_processes` | `pattern` | — | — |
| `kill_process` | `name_or_pid` | — | audit |

`input_text` keystrokes are gated because they can issue a pivot command
inside a running session (defense-in-depth).

### Assessment State & Capability Discovery — `tools/mcp_tools/assessment_state.py` (capability upgrade §8/§16)

Six tools let the agent inspect its own state, discover capabilities, and
drive the task graph / hypothesis store instead of reconstructing context from
conversation history. Registered via `register_assessment_state_tools(mcp, ctx)`
in `mcp_exploit_server.py`; backed by `tools/assessment_state.py`
(`aggregate_state`, `AssessmentStateStore`) and `tools/attack_modules`
(`capability_record`, `applicability_explain`, `find_producers`).

| Tool | Params | Target | Lock |
|---|---|---|---|
| `get_assessment_state` | `target_ip` | yes | allowlist |
| `query_capabilities` | `scope` ("modules"\|"tools"\|"skills"), `service` | — | audit |
| `get_capability_details` | `name`, `scope` | — | audit |
| `get_evidence` | `target_ip`, `limit`, `tool` | yes | allowlist |
| `record_hypothesis` | `target_ip`, `statement`, `confidence`, `expected_evidence`, `created_from` | yes | allowlist + re-validate |
| `update_task` | `target_ip`, `step_index`, `action` (complete\|fail\|cancel\|reset), `success`, `summary`, `failure_class`, `reason` | yes | allowlist + re-validate |

`get_assessment_state` renders a compact `ASSESSMENT_STATE:` snapshot from
`aggregate_state` (goal/phase, hypotheses, plan-DAG ready/blocked summary, newest
recon services/CVEs, credential count, audit rollup). `get_evidence` emits
`exploit_audit:<target>:<attempt_id>` refs only — never raw command/args.
`record_hypothesis` / `update_task` write LLM-owned state files, so their
handlers re-validate the target against the allowlist before writing (the
`run_campaign_step` precedent) — the returned blocks are `ASSESSMENT_STATE:` /
`CAPABILITIES:` / `CAPABILITY_DETAILS:` / `EVIDENCE:` / `HYPOTHESIS_RECORDED:` /
`TASK_UPDATED:`.

### Kill-Chain — `tools/mcp_tools/killchain.py` (cfg: `killchain.enabled`, default OFF)

Conditional family (the `replay_simulate` / peer-models precedent): nothing
registers unless `killchain.enabled` is true in config. Backed by
`tools/killchain/` (machine, stages, persistence). The exploit loop builds a
per-target `KillChainMachine` when enabled and renders a `KILLCHAIN BRIEFING`
into the system prompt.

| Tool | Params | Target | Lock |
|---|---|---|---|
| `killchain_status` | `target` | no (graph read) | audit |
| `killchain_attempt` | `target`, `from_state`, `to_state`, `edge_id` (optional), `context_json` (optional) | yes | allowlist + audit (verification enforced) |
| `killchain_plan` | `target`, `goal_state` (optional) | no (graph read) | audit |

`killchain_status` returns a `KILLCHAIN_STATUS:` block (current state, goal,
applicable edges, BFS path to goal). `killchain_attempt` runs the edge's
playbook through the normal MCP tool layer (allowlist + audit apply) and then
independently verifies success via check probes — the state is only updated
when verification passes; the returned block is `KILLCHAIN_TRANSITION:` on
success or `KILLCHAIN_FAILED:`. `killchain_plan` runs a BFS over the verified
edge graph toward `killchain.goal_state` (default
`shell_as_root`) and returns `KILLCHAIN_PLAN:`.

### Snapshots — `tools/mcp_tools/snapshots.py` (cfg: `snapshots.enabled`, default OFF)

Infrastructure-touching family backed by `tools/snapshots.py` (Docker
commit/rollback mandatory path; Proxmox/libvirt/Hyper-V/VMware best-effort).
Both write tools take a `vm_id` that must resolve to an operator-authorized
target — `@require_allowlist("vm_id")` + `@audit_tool`, and the vm_id → target
resolution goes through `snapshots._vm_id_for_target` (the `snapshots.vm_map`
or `SNAPSHOT_VM_MAP` env). Fail-open by contract: provider errors return
`ERROR:` blocks, never crash the server.

| Tool | Params | Target | Lock |
|---|---|---|---|
| `snapshot_create` | `vm_id`, `label` (optional) | yes | allowlist + audit |
| `snapshot_revert` | `vm_id`, `ref` (optional; empty = latest recorded) | yes | allowlist + audit |
| `snapshot_list` | `vm_id` | read-only | allowlist + audit |

Returned blocks: `SNAPSHOT_CREATED:` / `SNAPSHOT_REVERTED:` / `SNAPSHOT_LIST:`.
The same `SnapshotManager` backs the automatic snapshot-before-destructive
hooks in the exploit loop (`tools/exploit_agent/runner/_impl.py`), the swarm
bridge (`tools/swarm_bridge.py`), and the campaign executor
(`tools/campaign/executor.py`) — those hooks are always fail-open and take no
snapshot at all when `snapshots.enabled` is false. With
`replay_simulator.counterfactual: true`, a failed exploit action that had a
snapshot is auto-reverted and the mutated payload retries against the clean
state; both outcomes land in `final_result["counterfactual"]`.

### Retest — `tools/mcp_tools/retest.py` (always registered)

Closed-loop retest ("prove the fix"). One tool re-runs a confirmed
finding's stored PoC probe against the current target:

| Tool | Params | Target | Lock |
|---|---|---|---|
| `retest_finding` | `target_ip`, `finding_id`, `run_id` (optional; empty = latest run containing it) | yes | allowlist |

The probe (`verification_probe`, a `shell_command` spec captured from the
finding's successful audit record via `tools/run_service/prepare.py` and
carried on `TechnicalFinding`) is re-executed ONLY through the registered
`run_exploit_terminal` function in-process (the killchain playbook-dispatch
precedent), so the allowlist lock, audit trail, and sandbox funnel apply
unchanged — `SANDBOX_*` output classifies `INCONCLUSIVE` (fail closed, no
host fallback). The verdict reuses the `outcome_truth` classifier:
compromise/cred_dump → `STILL_OPEN`, explicit failure → `FIXED`, anything
else (no stored probe, blocked run, ambiguous output) → `INCONCLUSIVE`.
The verdict persists into the finding's `retest_status`/`retest_history[]`
in `reports/<run_id>/enhanced/enhanced_report.json` (sibling `.md`/`.html`
regenerated when present); snapshot state is attached best-effort via
`SnapshotManager.list` (fail-open). Returned block: `RETEST_VERDICT:`.

### HITL — `tools/mcp_tools/hitl.py` (cfg: `hitl.enabled`, default true)

Proxy-backed HITL evidence loop, Flow A only ("agents propose, human
decides" — Caido Replay / Burp AT style). Agent candidates land as
`PROPOSED` findings; only a human `APPROVED`/`REJECTED` promotes them:

| Tool | Params | Target | Lock |
|---|---|---|---|
| `propose_finding` | `run_id`, `title`, `affected_asset`, `summary`, `probe_exec`, `evidence`, `severity`, `vuln_class` | no | audit |
| `hitl_decide` | `finding_id`, `decision` (`APPROVED`/`REJECTED`), `note`, `run_id` (optional), `actor` (must be `'human'`) | no | audit |
| `list_proposed` | `run_id` (optional; empty = all runs, newest first) | no | audit |

All three are local-only `@audit_tool` (zero target touch — probe re-exec
stays inside `verify_finding`/`retest_finding`). `verify_poc` /
`verify_finding` / `retest_finding` never write `hitl_status`, so machine
verdicts stay `PROPOSED` until a human signs off; `record_hitl_decision`
raises `PermissionError` for any non-`human` actor, so an LLM can never
self-approve (every decision lands in `hitl_history[]` and the JSONL audit
trail with its actor). Decisions persist into `hitl_status`/`hitl_history[]`
in the run artifact JSON (sibling `.md`/`.html` regenerated when present).
Returned blocks: `HITL_PROPOSED:` / `HITL_DECIDED:`. WebUI: the Evidence tab
on the run page (`GET /runs/{id}/proposed`, `POST /runs/{id}/decide`, live
via the `hitl_decision` event); `approved_findings()` is the final-report
filter (APPROVED-only).

### Browser — `tools/mcp_tools/browser.py` (cfg: `browser.enabled` + `backend: playwright`)

Conditional family (the killchain/snapshots precedent): nothing registers
unless browser execution is actually runnable (host Playwright SDK or a
configured sandbox worker). Every target-touching tool takes `target` first
(`@require_allowlist("target")` + `@audit_tool`) and cross-checks the session's
target lock; URL hosts are re-checked against the allowlist per navigation.
Chromium runs one op per docker exec inside the browser worker netns
(`SandboxPlaywrightLauncher`) — strict fail-closed, never host fallback.
The launcher is cached per workspace so engine sessions survive across tool
calls.

| Tool | Params | Target | Lock |
|---|---|---|---|
| `browser_start` | `target`, `run_id` (optional), `headless` (default true) | yes | allowlist + audit |
| `browser_navigate` | `target`, `session_id`, `url`, `timeout_seconds` (optional) | yes | allowlist + audit (URL host re-checked) |
| `browser_observe` | `target`, `session_id`, `include_forms`/`include_endpoints` | yes | allowlist + audit |
| `browser_page_state` | `target`, `session_id` | yes | allowlist + audit |
| `browser_network_events` | `target`, `session_id`, `limit`, `after_id` | yes | allowlist + audit |
| `browser_storage` | `target`, `session_id`, `origin` (optional) | yes | allowlist + audit (values redacted) |
| `browser_screenshot` | `target`, `session_id` | yes | allowlist + audit |
| `browser_execute_js` | `target`, `session_id`, `expression` | yes | allowlist + audit + `browser.allow_mutating_actions` |
| `browser_discover_forms` | `target`, `session_id` | yes | allowlist + audit |
| `browser_discover_endpoints` | `target`, `session_id` | yes | allowlist + audit |
| `browser_close` | `target`, `session_id` | yes | allowlist + audit |
| `browser_submit` | `target`, `session_id`, `form_index`, `field_values` ({name: value}) | yes | allowlist + audit + `browser.allow_mutating_actions` (form action host re-checked) |
| `browser_replay` | `target`, `session_id`, `url`/`event_id`, `method`, `headers_json`, `body` | yes | allowlist + audit + `browser.allow_mutating_actions` (final URL host re-checked) |

Returned blocks: `SESSION_STARTED:` / `NAVIGATED:` / `OBSERVED:` / `NETWORK_EVENTS:` /
`STORAGE:` / `SCREENSHOT:` / `JS_RESULT:` / `SUBMITTED:` / `REPLAYED:` / `SESSION_CLOSED:`, plus `SANDBOX_*`
fail-closed blocks when the worker is unavailable. Storage values are redacted;
persist useful credentials via `cred_store_add` explicitly. The one-shot
`browser_attack_navigate` lives in the `browser_attack` plugin (separate opt-in,
separate name — no collision by construction).

## Adding a New Exploit MCP Tool (checklist)

Matches AGENTS.md rule 4 and `mcp_exploit_server.py:153-177` (30 families — 24 in `tools/mcp_tools/` + 6 in `tools/mcp_tools/modules/*.py` via `collect_tools()`).

1. **Add the tool in its family module** (`tools/mcp_tools/<family>.py`) as a
   function nested inside `register_<family>_tools(mcp, *, ctx)` with
   `@mcp.tool()` on top.
2. **Choose the gate** (see the decorator table above):
   - structured `target_ip` param → `@require_allowlist()` (below `@mcp.tool()`);
   - domain param (domain families) → `@require_allowlist("domain")`;
   - free-text command/script/lhost → `@audit_tool` + manual
     `check_targets_allowlist(...)` on extracted hosts;
   - no target touch → `@audit_tool` only (or nothing for pure queries).
3. **Validate inputs at the trust boundary**: `validate_target_or_ip` on
   target args, strict regexes on free-text params that are interpolated or
   shell-adjacent (module paths, package names, target_dir), `shlex` parsing +
   shell-metacharacter rejection for `options`-style strings.
4. **Run subprocesses through `_run_with_pgrp_timeout`** with an argv list
   (never a shell string) and a timeout, returning structured `STATUS` +
   `ATTEMPT_ID` + `OUTPUT:` text.
5. **Write artifacts under `_attempt_dir(workspace)`** per attempt; return
   paths in the result so `read_workspace_file` can retrieve them.
6. **No manual registration in `mcp_exploit_server.py`** — `tools/mcp_tools/registry.py:collect_tools()` auto-discovers every `register_*_tools` via `pkgutil` + AST validation (fails CI if decorator missing). For plugins, wrap handler in `ctx.require_allowlist()` / `ctx.audit_tool` and register via `PLUGIN_REGISTRY.mcp_tool_factories` (`mcp_exploit_server.py:174-182`).
7. **If the tool touches a target**: confirm the target flows through the
   allowlist union (runtime env vars or `exploit.allowed_targets`) — the
   allowlist IS the lock; do not re-add removed command-content gates.
8. **Secret-adjacent params**: ensure arg names land in `_SECRET_ARG_NAMES`
   or `_WHOLESALE_REDACT_FIELDS` so `_redact_args` masks them in the audit
   log, and never write raw command text to the audit log a second time
   (double-logging leaks credentials).
9. **Tests**: add a mock-subprocess test under `tests/` (no live Nmap) and
   run `python -m pytest tests/ -v` + `ruff check .` before PR (no CI).
