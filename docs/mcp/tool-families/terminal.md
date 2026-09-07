---
title: "Tool Family: terminal"
sources:
  - tools/mcp_tools/terminal/__init__.py
  - tools/mcp_tools/terminal/execute.py
  - tools/mcp_tools/terminal/package.py
  - tools/mcp_tools/terminal/privilege.py
  - tools/mcp_tools/terminal/allowlist.py
  - tools/mcp_shared.py
  - tools/kernel/audit.py
  - tools/kernel/workspace.py
  - tools/validation_utils.py
  - tools/command_analyzer.py
  - tools/kernel/allowlist.py
tests:
  - tests/test_mcp_injection_hardening.py
  - tests/test_mcp_tool_registration.py
  - tests/test_mcp_shared_helpers.py
  - tests/test_sudo_pivot.py
  - tests/test_env_probe.py
subsystem: mcp
---

# Tool Family: terminal

- **Registration source:** `tools/mcp_tools/terminal/__init__.py:31 register_terminal_tools(mcp, *, ctx)` — aggregates three sub-registrars; auto-discovered via `collect_tools()`, no edit to `mcp_exploit_server.py` needed.
- **Workspace:** per-attempt dirs via `_attempt_dir(workspace)` (`tools/kernel/workspace.py`).
- **Subprocess:** `_run_with_pgrp_timeout` (`tools/mcp_shared.py`) with POSIX `killpg` on timeout; live results are secret-masked via `_mask_secret_content` before return/emit.
- **Sandbox:** execution tools funnel through `tools/mcp_tools/sandbox_exec.py` (`run_command_in_sandbox` / `run_argv_in_sandbox`) when `ctx.sandbox` is set, failing closed with `SANDBOX_*` blocks instead of falling back to host execution; otherwise the legacy host path runs.

## Module split

| Module | Registrar | Tools | Responsibility |
|--------|-----------|-------|----------------|
| `terminal/execute.py` | `_register_execute_tools` | `run_exploit_terminal`, `run_as_root`, `git_clone` | Interactive shell funnel + privileged exec + repo fetch |
| `terminal/privilege.py` | `_register_privilege_tools` | `check_environment`, `preflight_env_check` | Privilege helpers (`_require_sudo_or_pivot`, `_find_windows_bash`, `_platform_system`) + environment probes |
| `terminal/package.py` | `_register_package_tools` | `apt_install`, `pip_install`, `install_package`, `download_and_install`, `update_system` | Package management (apt/pip/gem/npm/go/cargo/snap, URL installs, system upgrade) |
| `terminal/allowlist.py` | (helpers, no tools) | — | `_target_lock_block` (the target-IP lock) + `_opsec_advisory_block` (advisory OPSEC feedback) |

## Tools Exported (10)

| Tool | Module | Params | Result Shape | Gates / Notes |
|------|--------|--------|--------------|---------------|
| `run_exploit_terminal` | execute | `command: str` | `TERMINAL_RESULT: completed\|failed\|timed_out\|blocked (exit_code, duration)\nATTEMPT_ID: ...\nCOMMAND_ORIGINAL: ...\nCOMMAND_SANITIZED: ...\nPREFLIGHT_WARNING? / PREFLIGHT_CORRECTIONS?\nOPSEC_ADVISORY? (advisory)\nWORKSPACE: <attempt_dir>\nOUTPUT: <tail4000>` | `@audit_tool` + manual `_target_lock_block` on the FULL sanitized command (RULE-LOCK-FIRST). Empty → `BLOCKED: empty command.`; over the 10 MiB anti-fill cap → `BLOCKED: ... anti-fill cap...`. Preflight via `preflight_command_check` (sanitizes IP typos, warns on missing tools, never blocks except empty). Host path preserves `&&`/pipes/redirects through a wrapper script (`run_exploit.sh` / `run_exploit.cmd`; Windows prefers Git Bash via `_find_windows_bash`, else cmd.exe; Linux via the configured shell). |
| `run_as_root` | execute | `command: str` | `ROOT_CMD_RESULT: completed\|failed\|timed_out\|blocked ...\nCOMMAND: ...\nOUTPUT:` | `@audit_tool` + preflight + manual `_target_lock_block` on the FULL sanitized command **before** the sudo pivot (off-target reports the lock, not the pivot) + `_require_sudo_or_pivot`. Host path runs `sudo <command> 2>&1` via `_run_with_pgrp_timeout`; in-sandbox it runs as container root (`SUDO: not required (executed as container root)`). |
| `git_clone` | execute | `repo_url: str`, `target_dir: str=""` | `GIT_CLONE_RESULT: completed\|failed\|timed_out (exit_code)\nREPO: ...\nPATH: ...\nOUTPUT:` (+ `PREFLIGHT_WARNING` prefix when the URL existence probe fails) | Local-only `@audit_tool` (never an allowlist). URL must match `https?://...\.git` or `https?://github.com/...`; `target_dir` must match `[A-Za-z0-9._-]{1,80}` with workspace containment via `_is_inside_workspace` (fail closed). Existence preflight via `url_exists` warns only, never blocks (private repos still clone). Pure argv list (`git clone -- url dir`), no shell anywhere. Timeout from `exploit.command_timeout_seconds`, default 120 s here. |
| `check_environment` | privilege | `tools: str=""` | `ENVIRONMENT_CHECK:\nOS: ...\nPython: ...\n[+/-] tool: path (version)\nSUMMARY: N/M\nMISSING: ...\nHINT: ...` | Local-only `@audit_tool`. Default list from `_check_env_default_tools` = `tools.env_probe.ENV_TOOLS` + extras (`masscan rustscan feroxbuster nuclei metasploit-framework ldapsearch aircrack-ng wireshark tcpdump wget ruby gem npm go cargo snap`), deduped. Per tool: `shutil.which` + `--version` then `-version` probe. `HINT` is sudo-aware (install commands when sudo exists, `write_python_file` pivot otherwise). |
| `preflight_env_check` | privilege | — | `render_env_context(preflight_env_probe())` or `ENV_OK: all standard pentest tools present.` or `PREFLIGHT_ENV_CHECK_ERROR: ...` | Local-only `@audit_tool`. Probes sudo/pip installability plus per-tool fallback (`install_via_apt / install_via_pip / write_python_fallback`). Call once at session start or after installing a tool. |
| `apt_install` | package | `packages: str` (space-separated) | `APT_INSTALL_RESULT: completed\|failed\|timed_out (exit_code=...)\nPACKAGES: ...\nOUTPUT:` | Per-package regex `[a-zA-Z0-9_.+-]{1,60}`; `_require_sudo_or_pivot` short-circuits without passwordless sudo. Runs `sudo apt install -y ...` (300 s timeout, 4000-char tail). |
| `pip_install` | package | `packages: str` | `PIP_INSTALL_RESULT: ... (exit_code=...)\nPACKAGES: ...\nOUTPUT:` | Per-package regex `[A-Za-z0-9_.\-]{1,60}`; `pip install ...` via `bash -c` (120 s, 3000-char tail). No sudo gate. |
| `install_package` | package | `manager: str`, `packages: str` | `INSTALL_RESULT: completed\|failed\|timed_out (exit_code)\nMANAGER: ...\nPACKAGES: ...\nOUTPUT:` | `manager` in `apt|pip|gem|npm|go|cargo|snap` else `BLOCKED: unsupported manager ...`; packages `^[A-Za-z0-9_.+\-/@]{1,80}$`. Commands: apt `sudo apt install -y` (600 s), pip `pip install`, gem `gem install`, npm `npm install -g`, go `go install`, cargo `cargo install`, snap `sudo snap install` (600 s); default 300 s. `sudo` branches gated by `_require_sudo_or_pivot`. |
| `download_and_install` | package | `url: str`, `install_type: str="auto"`, `target_name: str=""` | `DOWNLOAD_RESULT: failed ...` or `INSTALL_RESULT: ...\nTYPE: deb\|tarball\|zip\|binary\n...` | URL `^https?://[A-Za-z0-9._/\-:@%+?=~&]+$`; `auto` detects from suffix (`.deb` → deb, `.tar.gz`/`.tgz` → tarball, `.zip` → zip, else binary); `target_name` basename `[A-Za-z0-9._-]{1,120}`. `curl -fsSL -o` into the attempt dir, then deb (`sudo dpkg -i` + `sudo apt-get install -f -y`), tarball (`tar -xzf`), zip (`unzip -q`), or binary (`shutil.move` → `/usr/local/bin`, workspace-only `chmod 0o755` fallback). |
| `update_system` | package | `upgrade: bool=True` | `UPDATE_RESULT: ... (apt update only)` or `UPDATE_RESULT: ... (update) / ... (upgrade)\nUPDATE_OUTPUT:...\nUPGRADE_OUTPUT:...` | `sudo apt update 2>&1` (300 s), then optionally `sudo apt upgrade -y 2>&1` (600 s). |

## Gates

- **Target-IP lock (`_target_lock_block`, `terminal/allowlist.py:203`).** The one attack-mode safety kept: free-text commands in `run_exploit_terminal` / `run_as_root` are scanned for every destination (command-analyzer dests + bare IPs + scanner-verb targets, including hostnames and encoded forms) and every one must be in `_allowed_target_list(config)`. RULE-LOCK-FIRST — the gate sees the FULL untruncated input; only display OUTPUT tails are cut (with a `[truncated]` marker from `_tail`). Listen-all wildcards (`0.0.0.0`, `::`) are exempt (bind listens, it does not pivot); loopback (`127.0.0.1`, `::1`, `localhost`) stays gated. `RHOSTS/RHOST/LHOST file:...` indirection is denied outright, never expanded. Fail-closed when `require_explicit_allowlist` is set with an empty union.
- **Sudo pivot (`_require_sudo_or_pivot`, `terminal/privilege.py:34`).** `apt_install`, the apt/snap branches of `install_package`, and `run_as_root` short-circuit with a `BLOCKED: ... requires passwordless sudo ... PIVOT: call preflight_env_check ... write_python_file + run_python_file ...` message when passwordless sudo is unavailable — instead of hanging on an interactive password prompt. Never raises (falls through to the legacy spawn path when sudo status is undeterminable); always pivots on Windows.
- **Local-only tools skip the lock:** `git_clone`, `check_environment`, `preflight_env_check`, and all of `package.py` (except via the sudo pivot) are `@audit_tool` only — no target touch, no allowlist.
- **OPSEC advisory (`_opsec_advisory_block`, `terminal/allowlist.py:134`).** Advisory only, never blocks: appends noise score + quieter rewrite + pacing posture to `run_exploit_terminal` results when OPSEC is enabled for the target; empty for local/private targets or on any build error.

## Result Shape — Common

- `attempt_id` from `_attempt_dir`; per-attempt `terminal.log` (secret-masked, capped at 200 000 chars) plus the `run_exploit.sh` / `run_exploit.cmd` wrapper that preserves chaining/pipes/redirects.
- Only size bounds on commands: the 10 MiB anti-fill cap (`_MAX_COMMAND_CHARS = 10 * 1024 * 1024` in `execute.py`); live DISPLAY tails capped (`_OUTPUT_CHARS = 4000`, `_GIT_OUTPUT_CHARS = 3000`) while gates always saw the full text. Secrets are masked in both persisted logs and live results; cracking plaintext is recovered via `run_hash_crack`, never by scraping terminal output.
- Execution timeout from `_config_timeout`: `exploit.command_timeout_seconds` validated via `_positive_int` (default 300; `git_clone` passes default 120). Sandbox results additionally carry a `SANDBOX:` identity line and a loopback hint for loopback targets.

## Typical flow

```python
# 1. Check the operator box has what the engagement needs.
check_environment(tools="nmap nuclei python3")
# HINT names install_package/apt_install, or preflight_env_check when sudo is missing.

# 2. Run a command against an authorized target (target-IP locked).
run_exploit_terminal(command="nmap -sV -oN scan.txt 127.0.0.1")
# Long scans: redirect to a file (-oN scan.txt) and read back with read_workspace_file.

# 3. Fetch an exploit PoC into the workspace (local-only, never allowlisted).
git_clone(repo_url="https://github.com/example/poc.git")
```

## Dependencies

- `tools/validation_utils.preflight_command_check`, `extract_ips_from_command`, `is_target_in_allowlist`, `is_private_or_local_target`
- `tools/command_analyzer._extract_destinations`, `_endpoint_ips`
- `tools/kernel/allowlist._extract_scanner_targets`, `_allowed_target_list` (via `tools/mcp_shared`), `_is_inside_workspace`, `check_targets_allowlist`
- `tools/opsec.OpsecManager` (advisory block only, never blocks execution)
- `tools/env_probe.ENV_TOOLS`, `_can_passwordless_sudo`, `preflight_env_probe`, `render_env_context`
- `tools/exploit_search.url_exists` (git_clone advisory preflight)
- `tools/mcp_tools/sandbox_exec` (`run_command_in_sandbox`, `run_argv_in_sandbox`, `sandbox_error_block`, `sandbox_fallback_notice`, `collect_command_targets`, `loopback_hint`)

## Config

- `exploit.shell: str` (default `bash`) — honors `shutil.which` plus Windows Git Bash fallbacks (`C:\Program Files\Git\...`)
- `exploit.command_timeout_seconds: int` (default 300)
- `exploit.require_explicit_allowlist: bool` — when true, the terminal lock is active (fail-closed on empty union)
- `exploit.allowed_targets: list[str]` — extra allowed hosts (operator-authorized callback/C2 hosts go here)

## Auditing

All 10 use `@audit_tool` (records `started`/`completed|blocked` with `_redact_args`; `input_text` wholesale-redacted; command masked by `_mask_secret_content`). `run_exploit_terminal`/`run_as_root` add the explicit allowlist check inside; blocked results (`TERMINAL_RESULT: blocked` / `ROOT_CMD_RESULT: blocked`) flip the audit to `approved=False`.

## Validation

- `preflight_command_check` sanitizes trailing-garbage IPs (`sanitize_target_in_command`); execution tools run the sanitized command but echo both original and sanitized (masked).
- Package names, repo URLs, download URLs, and `target_dir`/`target_name` are regex-gated; invalid → `BLOCKED: ...` before any subprocess spawns.
- `options`-style free text is not present in this family; where extra flags exist elsewhere they are `shlex.split`, never shelled (`git_clone` is a pure argv list on the host path).

## Tests

- `tests/test_mcp_injection_hardening.py` — IPv6/hostname lock, allowlisted pass, destructive-in-lab allow, off-target block, script-body lock, argv-no-shell, traversal neutralize
- `tests/test_mcp_tool_registration.py` — core tool presence (`run_exploit_terminal`)
- `tests/test_mcp_shared_helpers.py` — `_run_with_pgrp_timeout` helper behavior
- `tests/test_sudo_pivot.py` — `apt_install` / `run_as_root` / `install_package` pivot without sudo, target-lock-wins ordering, Windows behavior
- `tests/test_env_probe.py` — env-context rendering, sudo-aware fallback flags, `check_environment` default derivation from `ENV_TOOLS`

## Terminal submodules

`register_terminal_tools` (`terminal/__init__.py:31`) aggregates three sub-registrars; `terminal/allowlist.py` registers no tools — it holds the shared gate helpers the other two submodules (and the sessions family) call.

### `terminal/allowlist.py` — gates, no tools

```python
def _target_lock_block(command: str, config: Any, *, allow_empty: bool = False, include_scanner_targets: bool = True) -> str | None
def _opsec_advisory_block(sanitized_command: str, config: Any) -> str
def _runtime_target_union() -> list[str]
def _is_union_entry_local(entry: str, extra_local_cidrs: Any = None) -> bool
```

- `_target_lock_block` is the allowlist check entry point: extracts every destination (`command_analyzer._extract_destinations` + `extract_ips_from_command` + kernel `_extract_scanner_targets`, decoded via `_endpoint_ips`) and requires each in `_allowed_target_list(config)` via `is_target_in_allowlist`. Returns `None` (pass) or a block-reason string. `allow_empty=True` is only for static literal scans (Python script bodies whose structured `target_ip` gate already fired); free-text shell keeps `False` (fail closed). `include_scanner_targets=False` only for Python-source scans (the shell argv heuristic misfires on source). `_BIND_ALL_TOKENS` (`0.0.0.0`, `::`, …) exempt; loopback stays gated; `RHOSTS/RHOST/LHOST file:…` indirection denied via `_FILE_INDIRECTION_RE`.
- `_opsec_advisory_block` resolves `OpsecManager` against the full runtime union (`_runtime_target_union`: `EXPLOIT_TARGET` / `_IP` / `_DOMAIN` / `DISCOVERED_TARGETS`); OFF only when every member classifies local via `_is_union_entry_local`, else a 4-line advisory block. Never blocks.
- Lifecycle: pure functions, no state — called inline by `run_exploit_terminal` / `run_as_root` (RULE-LOCK-FIRST, before execution) and by sessions-family creation tools.
- Config keys: `exploit.require_explicit_allowlist`, `exploit.allowed_targets` (+ `EXPLOIT_*` env union), `opsec.*`.

### `terminal/package.py` — package management

```python
def _register_package_tools(mcp: Any, *, ctx: ToolContext) -> None
def apt_install(packages: str) -> str
def pip_install(packages: str) -> str
def install_package(manager: str, packages: str) -> str
def download_and_install(url: str, install_type: str = "auto", target_name: str = "") -> str
def update_system(upgrade: bool = True) -> str
```

- All five are local-only `@audit_tool` (no allowlist — no target touch); only the `sudo` branches consult `_require_sudo_or_pivot` (from `privilege.py`).
- `apt_install` / `pip_install`: single-manager shorthands with per-package regex gates (`[a-zA-Z0-9_.+-]{1,60}` / `[A-Za-z0-9_.\-]{1,60}`); `sudo apt install -y` (300 s) / `pip install` (120 s) via `bash -c`.
- `install_package`: `manager` in `apt|pip|gem|npm|go|cargo|snap` (else `BLOCKED`); packages `^[A-Za-z0-9_.+\-/@]{1,80}$`; apt/snap branches (`sudo apt install -y` 600 s, `sudo snap install` 600 s) pivot-gated, the rest run directly (default 300 s).
- `download_and_install`: URL `^https?://…$`; `auto` detects `deb` / `tarball` / `zip` / `binary` from suffix; `curl -fsSL -o` into the attempt dir, then `sudo dpkg -i` + `apt-get install -f -y` (deb), `tar -xzf` / `unzip -q` into the attempt dir, or `shutil.move` → `/usr/local/bin` with workspace-only `chmod 0o755` fallback (binary). `target_name` basename-gated `[A-Za-z0-9._-]{1,120}`.
- `update_system`: `sudo apt update` (300 s), optionally `sudo apt upgrade -y` (600 s); `upgrade=False` stops after update.
- Lifecycle: validate regexes → sudo pivot check (where applicable) → `_run_with_pgrp_timeout` / `subprocess.run` → `*_RESULT:` block with a capped output tail.
- Config keys: none package-specific; timeouts are fixed per tool (see above); workspace root from `ctx.workspace`.

```python
apt_install(packages="nmap hydra gobuster")
install_package(manager="pip", packages="impacket requests")
download_and_install(url="https://github.com/example/tool/releases/download/v1/tool.tar.gz")
update_system(upgrade=False)
```

### `terminal/privilege.py` — environment probes + privilege helpers

```python
def _register_privilege_tools(mcp: Any, *, ctx: ToolContext) -> None
def check_environment(tools: str = "") -> str
def preflight_env_check() -> str
def _require_sudo_or_pivot(tool_name: str, payload: str) -> str | None
def _check_env_default_tools() -> list[str]
def _find_windows_bash(config: Any) -> str | None
def _platform_system() -> str
```

- `check_environment(tools="")`: local-only `@audit_tool`; empty arg checks `_check_env_default_tools()` (`tools.env_probe.ENV_TOOLS` + extras, deduped). Per tool: `shutil.which` + `--version` then `-version` probe; returns `ENVIRONMENT_CHECK:` with OS/Python lines, per-tool `[+]/[-]` lines, `SUMMARY: N/M`, `MISSING: …`, and a sudo-aware `HINT` (install commands when passwordless sudo exists, `preflight_env_check` + `write_python_file` pivot otherwise).
- `preflight_env_check()`: local-only `@audit_tool`; renders `render_env_context(preflight_env_probe())` — sudo/pip installability plus per-missing-tool fallback (`install_via_apt` / `install_via_pip` / `write_python_fallback`). Call once at session start or after installing a tool.
- `_require_sudo_or_pivot`: returns a `BLOCKED: … PIVOT: …` message when `_can_passwordless_sudo()` is false (always pivots on Windows); never raises — undeterminable sudo status falls through to the legacy spawn path. Ordering: the target lock fires before this pivot.
- `_find_windows_bash`: configured `exploit.shell` on `PATH`, then common Git Bash install paths; `None` → cmd.exe fallback.
- Lifecycle: probes run at call time (no caching); `check_environment` is the fast `which` sweep, `preflight_env_check` the deeper installability probe.
- Config keys: `exploit.shell` (default `bash`).

```python
check_environment(tools="nmap nuclei python3")
preflight_env_check()
```

## Related documentation

- [Sessions tool family](./sessions.md) — reuses `_target_lock_block` for session commands
- [MCP security](../security.md) — target lock + redaction
- [MCP registration](../registration.md) — decorator contract
- [Sandbox](../../sandbox.md) — disposable execution worker and fail-closed rule

## Source map

- `tools/mcp_tools/terminal/__init__.py` — `register_terminal_tools` aggregate (execute + privilege + package)
- `tools/mcp_tools/terminal/execute.py` — `run_exploit_terminal`, `run_as_root`, `git_clone`, `_tail`, `_config_timeout`, size caps
- `tools/mcp_tools/terminal/package.py` — `apt_install`, `pip_install`, `install_package`, `download_and_install`, `update_system`
- `tools/mcp_tools/terminal/privilege.py` — `check_environment`, `preflight_env_check`, `_require_sudo_or_pivot`, `_check_env_default_tools`, `_find_windows_bash`, `_platform_system`
- `tools/mcp_tools/terminal/allowlist.py` — `_target_lock_block`, `_opsec_advisory_block`, `_runtime_target_union`, `_is_union_entry_local`
- `config.yaml` — `exploit.shell`, `exploit.command_timeout_seconds`, `exploit.require_explicit_allowlist`, `exploit.allowed_targets`
