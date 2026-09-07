---
title: "Tool Family: sessions"
sources:
  - tools/mcp_tools/sessions.py
  - tools/persistent_session_manager.py
  - tools/kernel/audit.py
  - tools/kernel/workspace.py
tests:
  - tests/test_mcp_tool_registration.py
  - tests/test_persistent_session_manager.py
subsystem: mcp
---

# Tool Family: sessions

- **Registration source:** `tools/mcp_tools/sessions.py:9 register_session_tools(mcp, *, ctx)` — auto-discovered. Thin wrappers over `PersistentSessionManager` (`tools/persistent_session_manager.py`).
- **Gate:** free-text command/session creation via `@audit_tool` + manual `_target_lock_block(command, config)`; pure read/stop/list via `@audit_tool` only or no lock.

## Tools Exported (13)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `start_tmux_session` | `@audit_tool` + `_target_lock_block(command)` | `name: str`, `command: str` | `SESSION_STARTED: name\nTYPE: tmux\nCOMMAND: ...\nPID: ...\nSTATUS: running` or `SESSION_FAILED: ...` or `BLOCKED: target-IP lock — ...` | Delegates to `PersistentSessionManager(workspace).start_tmux_session(name, cmd, cwd=workspace)`; manager cached lazily on `mcp._session_mgr`. |
| `send_to_session` | `@audit_tool` + `_target_lock_block(input_text)` | `name`, `input_text: str` | `SENT_TO_SESSION: name\nINPUT: ...[:200]` or `SEND_FAILED: ...` or `BLOCKED` | Defense-in-depth: keystrokes can pivot host (`ssh evil`) so input text is gated. |
| `read_session_output` | `@audit_tool` | `name`, `lines: int=100` | `SESSION_OUTPUT: name\nLINES: ...\nOUTPUT:` or `READ_FAILED` | `mgr.read_session_output(name, lines)`. |
| `kill_session` | `@audit_tool` | `name` | `SESSION_KILLED: name\nSUCCESS: bool\nMESSAGE: ...` | `mgr.kill_session(name)` (tmux/background/listener). |
| `start_background_job` | `@audit_tool` + `_target_lock_block(command)` | `name`, `command` | `JOB_STARTED: name\nTYPE: background\nCOMMAND: ...\nPID: ...\nLOG: ...\nSTATUS: running` or `JOB_FAILED` / `BLOCKED` | `nohup` detached job via `mgr.start_background_job(name, cmd, cwd=workspace)`. |
| `read_job_output` | `@audit_tool` | `name`, `lines=100` | `JOB_OUTPUT: name\nRUNNING: bool\nLINES: ...\nOUTPUT:` | `mgr.read_job_output(name, lines)`. |
| `stop_background_job` | `@audit_tool` | `name` | `JOB_STOPPED: name\nSUCCESS: ...\nMESSAGE: ...` | `mgr.stop_background_job`. |
| `start_listener` | `@audit_tool` + conditional pivot gate | `name`, `port: int`, `listener_type="netcat"` (`netcat|socat|http|tls|dns|https-beacon|socks_pivot`), `protocol="tcp"`, `directory=""`, `upstream_host=""`, `upstream_port=0` | `LISTENER_STARTED: name\nTYPE: ...\nPORT: port/proto\nPID: ...\nLOG: ...\nSTATUS: running` or `LISTENER_FAILED` / `BLOCKED: exploit.listeners.tls is disabled` / `BLOCKED: Host ... not in allowlist` | New C2 types `tls/dns/https-beacon/socks_pivot` require `exploit.listeners.<key>: true` (keys `tls, dns, https_beacon, socks_pivot`); `socks_pivot` `upstream_host` must be allowlist-gated via `check_targets_allowlist`. |
| `read_listener_output` | `@audit_tool` | `name`, `lines=100` | `LISTENER_OUTPUT: name\nRUNNING: bool\nLINES: ...\nOUTPUT:` | `mgr.read_listener_output`. |
| `stop_listener` | `@audit_tool` | `name` | `LISTENER_STOPPED: name\nSUCCESS: ...\nMESSAGE: ...` | `mgr.stop_listener`. |
| `list_sessions` | `@audit_tool` | — | `SESSIONS: N active` + `● [type] name — status (pid=..., cmd=...)` or `No active sessions.` | `mgr.list_all_sessions()` — tmux + background + listeners unified. |
| `list_processes` | `@audit_tool` | `pattern: str=""` | `PROCESSES: N matching 'pat'\n  PID pid (user) CPU:.. MEM:.. — command` or `No processes matching` | `mgr.list_processes(pattern)`; error entries shown. |
| `kill_process` | `@audit_tool` | `name_or_pid: str` | `KILL_RESULT: ...\nSUCCESS: ...\nMESSAGE: ...` | `mgr.kill_process(name_or_pid)` — tracked name or raw PID. |

## Dependencies

- `tools/persistent_session_manager.PersistentSessionManager`, `get_session_manager(workspace)`
- `tools/mcp_tools/terminal._target_lock_block`, `tools/kernel/allowlist.check_targets_allowlist`
- `tools/kernel/workspace._attempt_dir` (indirect via manager)

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets` — lock for command/session creation
- `exploit.listeners.{tls,dns,https_beacon,socks_pivot}: bool` — per-new-type gate (legacy `netcat/socat/http` ungated)
- No session-specific timeout config; timeouts handled by `PersistentSessionManager`.

## Auditing

- Creation tools write `started`/`completed|blocked` with command masked; free-text commands are `input_text`-wholesale not applicable here but `password` etc. still masked if present in args.
- Read/stop/list tools still audit (`@audit_tool`) — consistent trail even for local reads.
- Manager state under workspace; `mcp._session_mgr` singleton lazy-initialized.

## Validation

- Free-text dests gated before manager call — off-allowlist host → `BLOCKED: target-IP lock — ...` without reaching `tmux`/`nohup`.
- `socks_pivot` upstream host allowlist-gated (the pivot lock); `tls/dns/https-beacon` config-gated.
- Input text in `send_to_session` gated (defense-in-depth against in-session pivot).

## Tests

- `tests/test_persistent_session_manager.py` — session CRUD, listeners
- `tests/test_mcp_tool_registration.py` — expects `start_tmux_session`, `start_background_job`, `start_listener`

## Sandbox execution + egress guard (zero-tool helpers)

`sandbox_exec.py` and `egress_guard.py` register no `@mcp.tool` — they are the shared execution plane that sessions, terminal, Metasploit, and scanner tools funnel through. Documented here because background sessions/listeners run on the same contained-vs-host path.

### `sandbox_exec.py` — contained-execution funnel

```python
def run_command_in_sandbox(ctx: Any, command: str, *, timeout: int, cwd_host: Any = None, tool_name: str = "", user: str = "") -> tuple[bool, Any]
def run_argv_in_sandbox(ctx: Any, argv: list[str], *, target_ip: str = "", command: str = "", timeout: int = 300, cwd_host: Any = None, tool_name: str = "") -> tuple[bool, Any]
def collect_command_targets(command: str) -> list[str]
def sandbox_error_block(exc: Exception, *, tool_name: str = "") -> str
def sandbox_fallback_notice(ctx: Any) -> str
def loopback_hint(target_ip: str, config: Any) -> str
```

- `run_command_in_sandbox` / `run_argv_in_sandbox` return `(True, SandboxResult)` on a contained execution, `(False, None)` when no sandbox manager is attached (sandbox disabled → documented legacy host-execution mode), and raise `SandboxError` on sandbox/policy/scope/entry failure — the caller renders the `SANDBOX_*` block. Fail-closed: host execution is never an automatic fallback for attack commands.
- Scope: the FULL extracted target list (not just the primary) goes through the manager's own `_enforce_scope` first (`_enforce_full_scope`), so a multi-destination command whose primary is allowlisted but whose secondary is not still blocks. `collect_command_targets` uses the same extractor union as the tool-layer target lock, so the scope gate can never authorize what the string layer would deny.
- Entry gates: non-empty command/argv, positive-int timeout, safe `--user` token (`_SAFE_USER_RE`), path-like `cwd_host` mapped via `manager.container_path` (outside-workspace fails closed). The argv variant runs `argv` verbatim (never shelled); its `command` string is extraction-only.
- `loopback_hint` returns a `HINT:` remediation line when a loopback target fails from inside the sandbox (container-local loopback; needs `sandbox.network.map_host_loopback:true`), decoding obfuscated loopback forms via the shared endpoint-IP extractor. Advisory only.
- `sandbox_fallback_notice` emits `SANDBOX_FALLBACK:` only when the server degraded via the boot-time native fallback (`ctx.sandbox_notice`); configured host mode stays quiet. Config: `sandbox.*` (`enabled`, `fallback_native`, `network.map_host_loopback`).

### `egress_guard.py` — runtime egress enforcement for `run_python_file` children

```python
DENIAL_MARKER = "BP_EGRESS_DENIED"
def build_egress_preamble(allowlist: list[str] | None) -> str
def egress_denied_in_output(text: Any) -> str | None
```

- The static `_target_lock_block` body scan only sees literal destinations; a host built at runtime (`sys.argv` slicing, concat, base64/hex decode, `os.environ`) sails through. The tool prepends a stdlib-only preamble (`GUARD_PREAMBLE`, `json`/`ipaddress`/`socket`/`os` — the child may run in the sandbox worker where `tools.*` is not importable) that wraps `socket.socket.connect` / `socket.create_connection` and denies any host outside the effective target-IP allowlist at connect time.
- Matcher: exact case-insensitive, `*.wildcard` with dot boundary (bare parent NOT covered), CIDR. Fail-closed (matcher error denies); empty allowlist permits everything. Known ceiling: subprocess-spawned network clients (`curl`/`nc` via `os.system`) are NOT intercepted — literals there are still caught by the static scan, and the sandbox netns firewall is the backstop when sandboxed.
- `egress_denied_in_output` extracts the denied host from the `BP_EGRESS_DENIED` marker so the tool renders a clean `BLOCKED:` result instead of a traceback.

## Related Docs

- `docs/mcp/tool-families/terminal.md` — terminal's `_target_lock_block` reused here
- `docs/mcp/security.md` — pivot lock
