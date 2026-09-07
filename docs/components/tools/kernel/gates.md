---
title: Kernel — Gates
package: tools/kernel
files: [audit.py, allowlist.py]
---

# Kernel — Gates (`tools/kernel/`)

Audit decorators + the target-IP allowlist union. Factories in `audit.py` build the `@require_allowlist` / `@audit_tool` decorators every MCP tool registers through (`tools/mcp_tools/registry.py`); the lock itself lives in `allowlist.py`. Re-exported by `tools.mcp_shared` for backwards compat.

## Architecture

```text
tool call → require_allowlist(target_param, audit, host_param)   # audit.py:369
              → _check_allowlist(target, config)                 # allowlist.py:225
              → _allowed_target_list(config)                     # allowlist.py:79
                  = exploit.allowed_targets ∪ EXPLOIT_* env
              → pre-log started|blocked → run-or-BLOCKED → terminal|failed row
              → exploit_audit.jsonl (redacted via _redact_args)
```

Both decorators wrap sync and async functions via `inspect.signature` + `functools.wraps`, preserve the original signature (`__signature__`), and tag the wrapper (`__wrapped_require_allowlist__`, `__wrapped_audit_tool__`).

## `make_require_allowlist` mechanics (`audit.py:369`)

```python
def make_require_allowlist(workspace: Path, config: dict[str, Any] | None):
    def require_allowlist(target_param: str = "target_ip", *, audit: bool = True, host_param: str | None = None):
        def decorator(fn): ...
        return decorator
    return require_allowlist
```

Lifecycle per call (async and sync wrappers are identical apart from `await`):

1. `bound = sig.bind(*args, **kwargs); bound.apply_defaults()`.
2. `target_ip = bound.arguments.get(target_param, "")` → `_check_allowlist(target_ip, config)` → `(allowed, reason)`.
3. On deny with `host_param` set, `_pair_fallback` gets a second chance: the pair is accepted iff the hostname in `host_param` is itself allowlisted AND the provenance store ties the IP to that hostname (`tools.kernel.discovered.is_pair_authorized`). Success reason is `target in allowlist via <host> (<source>)`.
4. Pre-log (when `audit=True`) to `<workspace>/exploit_audit.jsonl`: `approved=allowed`, `status="blocked"|"started"`, `args=_redact_args(...)`, `attempt_id` from the bound `attempt_id` arg, `extra=allowlist_env_audit_extra(config) or None` (names env widening on the row).
5. On deny, return without running `fn`:
   `BLOCKED: <reason>\nATTEMPT_ID: preflight\nTOOL: <fn>\nTARGET: <target_ip>`.
6. On allow, run `fn` timed with `time.monotonic()`; exceptions (including `BaseException`, so anyio `BaseExceptionGroup`/cancellation still records) write a `failed` row via `_log_failure` and re-raise; returned results write `completed`/`blocked` via `_log_terminal` (`blocked` iff `_result_is_blocked(result)`).

## `make_audit_tool` mechanics (`audit.py:542`)

```python
def make_audit_tool(workspace: Path):
    def audit_tool(fn): ...
    return audit_tool
```

Audit-only (no gate): target comes from `_extract_audit_target(bound)` (hosts parsed out of `command`/`script_content` via `_extract_msf_rhosts` plus a structured `lhost` arg, comma-joined), always logs `started` with `approved=True`, then the terminal `completed`/`blocked` or `failed` row exactly as above. Used for local-only tools with no target to lock (e.g. hash cracking).

## Gate variants

The `target_param` names whichever bound argument holds the gated value; `host_param` adds the IP+hostname pair fallback.

| Decorator spelling | Gated param | Use | Call site |
|---|---|---|---|
| `@require_allowlist()` | `target_ip` (default) | Standard target-touching tools | `tools/mcp_tools/recon.py:39`, `tools/mcp_tools/verify.py:138`, `tools/mcp_tools/workspace.py:216` |
| `@require_allowlist("target")` | `target` | Tools whose arg is named `target` | `tools/mcp_tools/killchain.py:147`, `tools/mcp_tools/browser.py:204` |
| `@require_allowlist("vm_id")` | `vm_id` | Snapshot tools gate the backing VM id (resolved via `_vm_id_for_target` before the manager call) | `tools/mcp_tools/snapshots.py:39,64,91` |
| `@require_allowlist("domain")` | `domain` | Domain tools gate the domain string | `tools/mcp_tools/domain.py:593,659,878,1231` |
| `@require_allowlist(host_param="domain")` | `target_ip` + `domain` pair | `vhost_enum`: probe target is an IP but every request carries a `Host:`/SNI context from `domain`; a shared-hosting IP is accepted only when provenance ties it to the allowlisted domain | `tools/mcp_tools/domain.py:1068` |
| `@audit_tool` alone | — | Local-only tools (no target to lock) | `tools/mcp_tools/cracking.py` (`run_hash_crack`) |

Implementation note: variant call sites above (other than `domain.py:1068` and `snapshots.py:39-91`, read directly) were located via search, not re-read; exact line numbers may drift by a few lines.

## Allowlist union (`allowlist.py:47-111`)

```python
_ENV_UNION_KEYS = ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN",
                   "EXPLOIT_DISCOVERED_TARGETS", "EXPLOIT_ALLOWED_TARGETS")
def _env_union_entries() -> list[str]
def _allowed_target_list(config: dict[str, Any] | None) -> list[str]
def _check_allowlist(target_ip: str, config: dict[str, Any] | None) -> tuple[bool, str]
def check_targets_allowlist(targets: list[str], config: dict[str, Any] | None) -> tuple[bool, str]
def allowlist_env_audit_extra(config: dict[str, Any] | None) -> dict[str, Any]
def add_discovered_target(host: str, ip: str | None = None, *, source: str = "") -> None
```

- Effective allowlist = `exploit.allowed_targets` ∪ env union, order-preserving deduped. Single-value keys (`EXPLOIT_TARGET`, `EXPLOIT_TARGET_IP`, `EXPLOIT_TARGET_DOMAIN`) contribute one entry each; the two list keys (`EXPLOIT_DISCOVERED_TARGETS`, `EXPLOIT_ALLOWED_TARGETS`) split on commas.
- `_check_allowlist` enforces whenever ANY authorization material exists (config entries or env union). A fully empty union stays fail-closed when `exploit.require_explicit_allowlist` is true, permissive (`(True, "no allowlist configured")`) otherwise. `check_targets_allowlist` applies the same rule per host in a list.
- Env widening is never silent: `_env_widening_note` appends `(env union widens the lock: ...)` to reasons, and `allowlist_env_audit_extra` puts `{"allowlist_env_union": [...]}` on the audit row (`{}` when the env adds nothing).
- Matching is `tools.validation_utils.is_target_in_allowlist` (exact, `*.wildcard` with dot-boundary, CIDR, domains).
- `add_discovered_target` runtime-extends `EXPLOIT_DISCOVERED_TARGETS` with a discovered hostname only: the host must validate, the union must be non-empty, and the host must either match the union directly or be a strict subdomain of an allowed FQDN (`is_subdomain_of`; suffix collisions rejected). A resolved IP is NOT appended — it goes to the provenance store (`tools.kernel.discovered.record_discovered_host`) and is usable bare only when explicitly allowlisted, otherwise only in a hostname-tied pair check.

MSF/scanner extraction helpers (what the gates look inside before checking):

| Symbol | Line | Description |
|---|---|---|
| `_extract_msf_rhosts(text)` | 318 | `RHOSTS`/`RHOST` + `LHOST` callbacks + `portfwd -r` / `route add` / `autoroute` pivot hosts; splits comma/whitespace lists, drops `file:` indirection |
| `_extract_msf_lhosts(text)` | 252 | `set[g] LHOST <host>` egress callbacks; skips `0.0.0.0` listen-all |
| `_extract_msf_option_hosts(options)` | 290 | `LHOST`/`RHOST`/`RHOSTS` values from a parsed options dict (`_MSF_OPTION_HOST_KEYS`) |
| `_extract_scanner_targets(command)` | 471 | `shlex` argv-walk over `_SCANNER_VERBS` (16 verbs: nmap, masscan, rustscan, nikto, nuclei, gobuster, …), skipping `_SCANNER_VALUE_FLAGS` values and `_SHELL_SEPARATORS`; host-shaped via `_scanner_token_is_host` (IP/CIDR/FQDN/`*.wild`) |

## Secret redaction (`audit.py:29-190`)

```python
_REDACTED = "***REDACTED***"
_SECRET_ARG_NAMES  # frozenset of 30 names
_WHOLESALE_REDACT_FIELDS = frozenset({"input_text", "notes"})
def _mask_secret_content(value: Any) -> Any
def _redact_nested(value: Any) -> Any
def _redact_args(args: dict[str, Any] | None) -> dict[str, Any]
```

- `_SECRET_ARG_NAMES` (30): `password, passwd, pass, passphrase, secret, shared_secret, pre_shared_key, secret_key, signing_key, ntlm_hash, ntlm, hash, kerberos_ticket, asrep_key, rc4_key, aes_key, token, auth_token, access_token, refresh_token, session_key, cookies, authorization, api_key, apikey, credential, credentials, creds, private_key, priv_key`. Any arg (or nested dict key, case-insensitive) with one of these names becomes `***REDACTED***` wholesale.
- `_MASK_RES` (13 regexes over string values): `_MASK_URL_AUTH_RE` (`scheme://user:pass@`), `_MASK_U_FLAG_RE` (`-u user:pass`), `_MASK_LONG_PW_RE` (`--password/--passwd/--passphrase/--pass/--pwd/-pass…`), `_MASK_HYDRA_P_RE` (hydra/medusa/crackmapexec/netexec/cme/evil-winrm `-p/-P`), `_MASK_MSF_SET_RE` (`set SMBPass/PASSWORD/…`), `_MASK_HASHES_RE` (`-hashes lm:nt`), `_MASK_NTLM_FLAG_RE` (`-ntlm <hex>`), `_MASK_KV_SECRET_RE` (`KEY=secret`), `_MASK_KV_COLON_RE` (`password: secret` YAML/JSON forms + `NTLM:` lines), `_MASK_NTLM_PAIR_RE` (bare `32hex:32hex`), `_MASK_PEM_RE` (PEM private-key blocks), `_MASK_AUTH_HDR_RE` (`Authorization: Basic/Bearer/…`), `_MASK_PY_AUTH_TUPLE_RE` (`auth=("u","p")`).
- `_redact_args`: secret-named args → redacted; `input_text`/`notes` → redacted wholesale when truthy; strings → `_mask_secret_content`; anything else → `_redact_nested` (dicts key-checked recursively, lists/tuples descended element-wise). The `extra` payload on audit rows goes through the same `_redact_args` pipeline.

## Audit JSONL rows (`audit.py:193-338`)

```python
def _audit_log(audit_path: Path, *, target_ip: str, tool_name: str, approved: bool,
               status: str, command: str = "", args: dict | None = None,
               attempt_id: str = "", code_sha256: str = "",
               duration_seconds: float = 0.0, extra: dict | None = None) -> None
AuditStatus = Literal["started", "completed", "blocked", "failed"]
_BLOCKED_RESULT_MARKERS = ("BLOCKED:", "TERMINAL_RESULT: BLOCKED", "ROOT_CMD_RESULT: BLOCKED", "ERROR:")
```

- File: `<workspace>/exploit_audit.jsonl`, one JSON object per line: `{timestamp, target_ip, tool_name, approved, status, command (masked), args (redacted), attempt_id, code_sha256, duration_seconds}` plus non-`None` `extra` keys merged in. Parent dir creation is cached in `_MKDIR_CACHE`.
- `started` (pre-log, `approved=True|False`) → exactly one terminal sibling guaranteed: `completed` (`_result_is_blocked` false), `blocked` (result text starts with a blocked marker), or `failed` (escaping exception incl. `BaseExceptionGroup`/cancellation, with `extra={"error_class", "error_summary"}` sanitized and capped at 500 chars via `_failure_extra`). Failure-path writes go through best-effort `_safe_audit_log` so a full disk never masks the original exception.
- `attempt_id` is taken from the bound `attempt_id` argument when the tool takes one (`_extract_attempt_id`), else `""`.

Example rows (field order as written):

```json
{"timestamp": "2026-09-07T00:00:00+00:00", "target_ip": "10.0.0.50", "tool_name": "run_msf_module", "approved": true, "status": "started", "command": "", "args": {"target_ip": "10.0.0.50", "lhost": "10.0.0.5"}, "attempt_id": "20260907_000000_000000_ab12cd34", "code_sha256": "", "duration_seconds": 0.0, "allowlist_env_union": ["10.0.0.50"]}
{"timestamp": "2026-09-07T00:00:05+00:00", "target_ip": "10.0.0.50", "tool_name": "run_msf_module", "approved": true, "status": "completed", "command": "", "args": {"target_ip": "10.0.0.50", "lhost": "10.0.0.5"}, "attempt_id": "20260907_000000_000000_ab12cd34", "code_sha256": "", "duration_seconds": 4.2}
```

## Config keys (read via the `config` dict)

| Key | Default | Effect |
|---|---|---|
| `exploit.allowed_targets` | `[127.0.0.1]` (`config.yaml`) | Base allowlist before env union |
| `exploit.require_explicit_allowlist` | `true` | Empty union fail-closed when true, permissive when false |
| `EXPLOIT_TARGET` / `EXPLOIT_TARGET_IP` / `EXPLOIT_TARGET_DOMAIN` | env (threaded by `tools/mcp_session.py`) | Single-host union entries (runtime `--target`, resolved IP, domain) |
| `EXPLOIT_DISCOVERED_TARGETS` / `EXPLOIT_ALLOWED_TARGETS` | env (comma-separated) | Multi-host union entries; discovered hosts appended here by `add_discovered_target` |
| `exploit.workspace_dir` | `exploit_workspace` | Root under which `exploit_audit.jsonl` is written |

## Examples

```python
from tools.kernel.audit import make_audit_tool, make_require_allowlist

require_allowlist = make_require_allowlist(workspace, config)
audit_tool = make_audit_tool(workspace)

@require_allowlist()                    # gates target_ip
async def run_msf_module(target_ip: str, module: str, ...): ...

@require_allowlist("vm_id")             # gates vm_id (snapshots)
def snapshot_create(vm_id: str, label: str = ""): ...

@require_allowlist("domain")            # gates domain (domain tools)
async def dns_recon(domain: str, ...): ...

@require_allowlist(host_param="domain") # target_ip + domain pair (vhost_enum)
async def vhost_enum(target_ip: str, port: int = 80, domain: str = "", ...): ...

@audit_tool                             # audit-only, no gate (local tools)
def run_hash_crack(hash_file: str, ...): ...
```

## Related documentation

- [Kernel overview](./overview.md)
- [Recon pipeline](../recon/pipeline.md)
- [Recon overview](../recon/overview.md)
- [MCP tools](../../../mcp-tools.md)
- [Architecture](../../../architecture.md)

## Source map

- `tools/kernel/audit.py`
- `tools/kernel/allowlist.py`
- `tools/kernel/discovered.py`
- `tools/kernel/workspace.py`
- `tools/kernel/orchestration.py`
- `tools/mcp_shared.py`
- `tools/mcp_tools/registry.py`
- `tools/mcp_tools/snapshots.py`
- `tools/mcp_tools/domain.py`
