---
title: MCP Security — Target Lock, Allowlist, Audit, Redaction, Validation
sources:
  - tools/mcp_shared.py
  - tools/kernel/allowlist.py
  - tools/kernel/audit.py
  - tools/kernel/workspace.py
  - tools/validation_utils.py
  - tools/command_analyzer.py
  - tools/mcp_tools/terminal.py
  - tools/mcp_session.py
tests:
  - tests/test_mcp_tool_scope.py
  - tests/test_mcp_injection_hardening.py
  - tests/test_domain_allowlist.py
  - tests/test_mcp_shared_helpers.py
subsystem: mcp
---

# MCP Security

The one attack-mode safety kept in the tool layer. `full_access` auto-approves everything with no command/scope/pivot inspection; the target-IP allowlist lock IS the lock (`tools/mcp_tools/terminal.py:60-70`). Recon stays `read_only` via the missing-key fallback in `_resolve_exploit_permission`. `allowlist.py` + `audit.py` + `workspace.py` are the shared kernel (`tools/kernel/`, `tools/mcp_shared` re-exports).

## `_allowed_target_list` — the effective allowlist

`tools/kernel/allowlist.py:35-52` (re-exported at `tools/mcp_shared.py:494-534`):

Union of:

- `config["exploit"]["allowed_targets"]: list[str]` — operator-authorized extras (callback/C2 hosts)
- `EXPLOIT_TARGET` — literal `--target` (IP **or** domain), always set by `tools/mcp_session.py:257`
- `EXPLOIT_TARGET_IP` — resolved IP for a domain target (`mcp_session.py:267`, only when `original_target` + `resolved_ip` both set)
- `EXPLOIT_TARGET_DOMAIN` — domain string (`mcp_session.py:268`)
- `EXPLOIT_DISCOVERED_TARGETS` — comma-separated hosts/IPs via `add_discovered_target(host, ip)` (`tools/kernel/allowlist.py:55-64`, called by `tools/mcp_tools/domain.py:475,478`)

`add_discovered_target` runtime-extends the allowlist for subdomains discovered by `enumerate_subdomains`; each host is still gated through `is_target_in_allowlist`, it only widens the operator-authorized set.

**Provenance (no global raw-IP authorization):** only the discovered
*hostname* is appended to `EXPLOIT_DISCOVERED_TARGETS`. A resolved IP is
recorded in the provenance store (`tools/kernel/discovered.py`: hostname,
addresses, resolution timestamp, TTL/expiry, source/reason) and is usable
bare only when the IP itself is explicitly allowlisted — otherwise only in
a hostname-tied context: the sandbox policy (which resolves each
authorized hostname host-side to ALL its A/AAAA addresses and records the
full mapping in `NetworkPolicy.resolved_domain_addresses` + the audit
payload's `discovered_provenance`), or structured IP+hostname tools via the
`@require_allowlist(host_param=...)` pair check (e.g. `vhost_enum` with a
`Host:` header / SNI context). Entries expire (`DISCOVERY_TTL_S`, default
600s), so DNS changes fail closed instead of lingering. Authorizing one
hostname therefore never silently authorizes its shared-hosting/CDN IP for
unrelated use.

Env vars are threaded into the MCP server process by `open_exploit_mcp_session` (`tools/mcp_session.py:256-272`) via `StdioServerParameters(env=env)` and `Popen(env=env)`.

## Matching — `is_target_in_allowlist`

`tools/validation_utils.py:380-427` — case-insensitive, supports:

- **Exact** IP or domain (`target_clean == asset_clean`)
- **Wildcard** domain: `*.example.com` matches `a.example.com` via `target_clean.endswith(".example.com")` (`tools/validation_utils.py:403-407`)
- **CIDR** containment: `ip_address in ip_network(asset_clean, strict=False)` (`tools/validation_utils.py:412-417`)
- **Normalized IP equality** via `ip_address` (`tools/validation_utils.py:420-424`)

CIDR-subset-of-CIDR (asset itself is a CIDR) handled by defensive `_is_in_allowlist` wrapper (`mcp_server.py:96-107`) via `subnet_of`.

## Enforcement Points

### 1. Structured target tools — `@require_allowlist`

`make_require_allowlist(workspace, config)` (`tools/kernel/audit.py:232-321`):

- Reads `target_ip` (or `domain` for domain families) via `inspect.signature` binding
- `_check_allowlist` (`tools/kernel/allowlist.py:67-80`): `require_explicit_allowlist: false` → allowed; else target must be in `_allowed_target_list` via `is_target_in_allowlist`; empty allowlist with flag `true` fails closed
- Writes `started` audit (`approved=allowed`), returns `BLOCKED:` on deny with `ATTEMPT_ID: preflight`, else calls handler and writes `completed`/`blocked` based on `_result_is_blocked(result)`

Example: `tools/mcp_tools/recon.py:20 check_os`, `tools/mcp_tools/domain.py:292 resolve_domain(@require_allowlist("domain"))`.

### 2. Free-text terminal — `_target_lock_block`

`tools/mcp_tools/terminal.py:60-97`:

- Honors `exploit.require_explicit_allowlist`; when off → no block. When on but `_allowed_target_list` empty → no block (no scope to enforce).
- Extracts destination tokens: `_cmd_extract_destinations(command)` (URL authorities, `/dev/tcp|udp` hosts, `LHOST/RHOST`, network verbs via `tools/command_analyzer._extract_destinations`), `extract_ips_from_command` (bare IPv4), and `_extract_scanner_targets` (scanner verbs: `nmap/masscan/rustscan/nikto/nuclei/...` via `tools/kernel/allowlist.py:122-240`). Dedupes, decodes integer-encoded IPs via `_cmd_endpoint_ips`, then checks each through `is_target_in_allowlist`. First off-list token returns `BLOCKED: Target X not in explicit allowlist. Add it to exploit.allowed_targets...`.

Used by: `run_exploit_terminal` (`terminal.py:222`), `run_as_root` (`terminal.py:504`), `start_tmux_session`/`send_to_session`/`start_background_job` (`tools/mcp_tools/sessions.py:33,55,93`), and statically on script body in `run_python_file` (`tools/mcp_tools/workspace.py:123-125`) + its `target_ip` param gate (`validate_target_or_ip`).

### 3. Free-text Metasploit / callback / pivot — `check_targets_allowlist`

`tools/kernel/allowlist.py:101-119`:

- `check_targets_allowlist([hosts], config)` — same flag logic; each host checked via `is_target_in_allowlist` against `_allowed_target_list`; returns `(False, reason)` on first off-list host.
- Used by: `msfconsole_command`/`msf_interact_session`/`msf_run_resource_script` (extract `RHOSTS/RHOST` + `portfwd/route/autoroute` pivots via `_extract_msf_rhosts`, `tools/kernel/allowlist.py:24-98`), `msf_generate_payload`/`generate_payload`/`msf_start_handler` ( `lhost` callback), `msf_run_recipe`, `msf_post_portfwd`/`msf_post_route`, `kerberoast`/`ad._gate_dc` (`dc_ip` secondary host), `responder_relay` (relay target list built **only** from `_allowed_target_list`, `tools/mcp_tools/ad.py:271-278`), `start_listener` socks_pivot `upstream_host`, `spawn_subagent` target (`tools/mcp_tools/parallel_agents.py:321`).

### Empty-allowlist behavior

- `require_explicit_allowlist: true` but no targets → all allowlist checks fail closed (`tools/kernel/allowlist.py:73-74, 109-110`)
- Flag `false` → every gate short-circuits to `allowed` (lock is off — recon-style)

## Audit Trail

Every handler via `make_require_allowlist` / `make_audit_tool` appends to `exploit_workspace/exploit_audit.jsonl` via `_audit_log` (`tools/kernel/audit.py:169-198`):

```json
{"timestamp": "iso", "target_ip": "...", "tool_name": "...", "approved": true, "status": "started|completed|blocked", "command": "masked", "args": {"redacted": "..."}, "attempt_id": "...", "code_sha256": "...", "duration_seconds": 0.0}
```

- `started` record before gating; `completed` or `blocked` after. `_result_is_blocked(result)` (`tools/kernel/audit.py:204-209`) flips to `blocked` when result starts with `BLOCKED:`, `TERMINAL_RESULT: BLOCKED`, `ROOT_CMD_RESULT:`, `ERROR:` (`_BLOCKED_RESULT_MARKERS`).
- `_extract_audit_target` (`tools/kernel/audit.py:212-229`) derives `target_ip` for `@audit_tool` from `command`/`script_content` (RHOSTs extraction) + `lhost`.
- `attempt_id` from `_attempt_dir` (`tools/kernel/workspace.py:101-106`) is `YYYYmmdd_HHMMSS_micro + _ + token_hex(4)` — concurrent swarm dispatch can't collide.

## Redaction

`_redact_args(args)` (`tools/kernel/audit.py:152-166`):

- Per-arg name exact lower match against `_SECRET_ARG_NAMES` (`tools/kernel/audit.py:27-60`): `password/passwd/pass/passphrase/secret/shared_secret/pre_shared_key/secret_key/signing_key/ntlm_hash/ntlm/hash/kerberos_ticket/asrep_key/rc4_key/aes_key/token/auth_token/access_token/refresh_token/session_key/cookies/authorization/api_key/apikey/credential/credentials/creds/private_key/priv_key` → `***REDACTED***`
- Wholesale-redact fields `_WHOLESALE_REDACT_FIELDS = {input_text, notes}` (`tools/kernel/audit.py:120`) — free-text attacker payloads never land in the audit trail in cleartext
- Remaining strings via `_mask_secret_content` (`tools/kernel/audit.py:123-134`) with 10 regexes (`tools/kernel/audit.py:64-118`): URL `user:pass@` masked, `-u user:pass`, `--password v`, hydra-style `-p v` (scoped to hydra/medusa/crackmapexec/evil-winrm), `set SMBPass v`, `-hashes LM:NT`, `-ntlm`, `KEY=VALUE` secrets, `Authorization: Bearer/Digest/...`, python `auth=("u","p")`

Workspace reads: `read_workspace` caps output at 120k chars (`tools/kernel/workspace.py:130-131`); `_redact_startup_text` (`tools/mcp_session.py:682-693`) redacts secret values, Bearer, URL creds, and `key=value` before surfacing server log tails in startup errors (`_server_log_tail`, `tools/mcp_session.py:696-717` caps 20 lines / 4000 chars).

## Input Validation

- `validate_target_or_ip(s)` (`tools/validation_utils.py:128-136` alias for `validate_target`) — strict IPv4 via `_STRICT_IPV4_RE` + `IPv4Address`, IPv6 via `ip_address`, FQDN via `_FQDN_RE` (allows `*.` wildcard, RFC1035 253-char cap). Domain resolution via `resolve_target_to_ip(host, resolver_fn, family)` (`tools/validation_utils.py:139-182`, injectable for tests) and `resolve_target` (`tools/validation_utils.py:185-210`).
- `preflight_command_check(command)` (`tools/validation_utils.py:337-377`) — sanitizes trailing-garbage IPs via `sanitize_target_in_command`, warns about missing tools (`nmap/rustscan/...` via `is_tool_installed`/`shutil.which`), returns `{valid, original_command, sanitized_command, corrections, missing_tools, blocked_reason}`.
- `_run_with_pgrp_timeout` (`tools/mcp_shared.py:235-317`) — POSIX `start_new_session` + `killpg SIGKILL` on timeout; Windows `proc.kill()`. Re-raises `TimeoutExpired` so callers' `except` matches `subprocess.run` contract. Never use `bash -c` strings — always `argv` lists with `shlex.split` + shell-metachar rejection (`;|&$`()<>|\n`) in payloads/metasploit/web_scan families.
- `_is_inside_workspace` / `_resolve_workspace_file` (`tools/kernel/workspace.py:15-85`) — containment for workspace reads; `read_workspace` coerces absolute paths under workspace root, finds by `rglob` newest match when also inside.

## Related Docs

- `docs/mcp/overview.md`
- `docs/mcp/registration.md`
- `docs/mcp/lifecycle.md` — env propagation and HTTP bearer hardening
- `docs/mcp/tool-families/*.md` — per-family validation notes
