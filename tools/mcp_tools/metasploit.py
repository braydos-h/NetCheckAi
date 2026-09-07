"""Metasploit MCP tool registration.

Bridge tools are host-side msfconsole/tmux processes: under the disposable
sandbox they fail closed via ``_msf_bridge_or_blocked`` (no host fallback).
``run_msf_module`` is the sandbox-safe path (msfconsole runs inside the
worker from a resource file). Option strings are parsed with the shared
``parse_extra_options`` helper so shell metacharacters are rejected in one
place; module/payload names are regex + length gated; numeric args are
clamped; only display OUTPUT tails are truncated (with a marker) — gates
always see the FULL input.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from typing import Any

from tools.mcp_shared import (
    _attempt_dir,
    _extract_msf_option_hosts,
    _extract_msf_rhosts,
    check_targets_allowlist,
)
from tools.mcp_tools.registry import ToolContext, _platform_system, parse_extra_options
from tools.mcp_tools.sandbox_exec import sandbox_error_block
from tools.metasploit_bridge import MSF_RECIPES, MetasploitBridge, get_metasploit_bridge, get_msf_recipe
from tools.sandbox.exceptions import SandboxError
from tools.validation_utils import validate_target_or_ip

# Module/payload paths: Metasploit module path chars only, bounded length so a
# value cannot break out of the msfconsole ``use`` / ``set PAYLOAD`` line.
_MODULE_RE = re.compile(r"^[A-Za-z0-9_./-]{1,120}$")
_PAYLOAD_RE = re.compile(r"^[A-Za-z0-9_./-]{1,120}$")
# Option keys: bare ``set <KEY>`` tokens only.
_OPT_KEY_RE = re.compile(r"^[A-Za-z0-9_]{1,60}$")
# Short enum-ish fields (fmt/platform/arch/encoder): no slashes, bounded.
_SHORT_FIELD_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")

_MAX_OUTPUT_CHARS = 2000
_MAX_LOG_CHARS = 4000
_MAX_SESSIONS_SHOWN = 100
_MSF_RUN_TIMEOUT = 600


def _tail(text: Any, limit: int) -> str:
    """Return the display tail of ``text`` with a truncation marker.

    Args:
        text: Raw output (None-safe, stringified).
        limit: Max chars to show (tail).
    Returns:
        Full text when short, else a ``[truncated ...]`` header plus the last
        ``limit`` chars. Gates always saw the FULL text; only display is cut.
    Gates: None (pure display helper).
    Side-effects: None.
    """
    s = str(text or "")
    if len(s) <= limit:
        return s
    return f"[truncated - showing last {limit} of {len(s)} chars]\n{s[-limit:]}"


def _validate_module(module: str) -> str | None:
    """Validate a Metasploit module path.

    Args:
        module: Raw module path (e.g. ``exploit/...``).
    Returns:
        Error string to return, or None when valid.
    Gates: Regex + length (``_MODULE_RE``).
    Side-effects: None.
    """
    if not module or not module.strip():
        return "BLOCKED: module path is required."
    if not _MODULE_RE.match(module.strip()):
        return "BLOCKED: module path must match [A-Za-z0-9_./-]{1,120}."
    return None


def _validate_payload(payload: str) -> str | None:
    """Validate a Metasploit payload path (empty = not set, valid).

    Args:
        payload: Raw payload (e.g. ``windows/meterpreter/reverse_tcp``).
    Returns:
        Error string or None.
    Gates: Regex + length (``_PAYLOAD_RE``).
    Side-effects: None.
    """
    p = (payload or "").strip()
    if not p:
        return None
    if not _PAYLOAD_RE.match(p):
        return "BLOCKED: payload must match [A-Za-z0-9_./-]{1,120}."
    return None


def _validate_short_field(value: str, label: str) -> str | None:
    """Validate a short enum-ish field (fmt/platform/arch/encoder).

    Args:
        value: Raw field value.
        label: Field name for the error message.
    Returns:
        Error string or None.
    Gates: Regex + length (``_SHORT_FIELD_RE``).
    Side-effects: None.
    """
    if not _SHORT_FIELD_RE.match((value or "").strip()):
        return f"BLOCKED: invalid {label} {value!r}."
    return None


def _clamp_port(value: Any) -> tuple[int | None, str | None]:
    """Validate a TCP/UDP port number.

    Args:
        value: Raw port (int or digit string; bool rejected).
    Returns:
        ``(port, None)`` on success, ``(None, error)`` on bad shape/range.
    Gates: Integer 1-65535.
    Side-effects: None.
    """
    if isinstance(value, bool):
        return None, "BLOCKED: port must be an integer between 1 and 65535."
    try:
        port = int(str(value).strip() if isinstance(value, str) else value)
    except (TypeError, ValueError, AttributeError):
        return None, "BLOCKED: port must be an integer between 1 and 65535."
    if port < 1 or port > 65535:
        return None, "BLOCKED: port must be an integer between 1 and 65535."
    return port, None


def _clamp_session_id(value: Any) -> tuple[int | None, str | None]:
    """Validate a Metasploit session id.

    Args:
        value: Raw session id.
    Returns:
        ``(sid, None)`` when a positive int, else ``(None, error)``.
    Gates: Positive int 1-1000000.
    Side-effects: None.
    """
    if isinstance(value, bool):
        return None, "BLOCKED: session_id must be a positive integer."
    try:
        sid = int(str(value).strip() if isinstance(value, str) else value)
    except (TypeError, ValueError, AttributeError):
        return None, "BLOCKED: session_id must be a positive integer."
    if sid <= 0 or sid > 1000000:
        return None, "BLOCKED: session_id must be a positive integer."
    return sid, None


def _clamp_wait(value: Any, default: float) -> tuple[float | None, str | None]:
    """Clamp a wait duration to the sane msfconsole range.

    Args:
        value: Raw seconds (int/float/digit string).
        default: Fallback when value is None/empty.
    Returns:
        ``(seconds, None)`` clamped to 0.5-600, or ``(None, error)``.
    Gates: Numeric range clamp.
    Side-effects: None.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return default, None
    if isinstance(value, bool):
        return None, "BLOCKED: wait_seconds must be a number."
    try:
        secs = float(value)
    except (TypeError, ValueError):
        return None, "BLOCKED: wait_seconds must be a number."
    if secs != secs or secs == float("inf") or secs == float("-inf"):
        return None, "BLOCKED: wait_seconds must be a number."
    return min(max(secs, 0.5), 600.0), None


def _clamp_read_lines(value: Any, default: int = 100) -> tuple[int, str | None]:
    """Clamp a read-back line count.

    Args:
        value: Raw line count.
        default: Fallback when value is None/empty.
    Returns:
        ``(lines, None)`` clamped to 1-1000 (never an error; invalid falls
        back to ``default`` so a bad count cannot break the read).
    Gates: Range clamp 1-1000.
    Side-effects: None.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return default, None
    if isinstance(value, bool):
        return default, None
    try:
        lines = int(str(value).strip() if isinstance(value, str) else value)
    except (TypeError, ValueError, AttributeError):
        return default, None
    return min(max(lines, 1), 1000), None


def _clamp_iterations(value: Any) -> tuple[int | None, str | None]:
    """Validate an msfvenom encoder iteration count.

    Args:
        value: Raw iterations.
    Returns:
        ``(n, None)`` when 1-10, else ``(None, error)``.
    Gates: Integer 1-10 (bounds encoder loops).
    Side-effects: None.
    """
    if isinstance(value, bool):
        return None, "BLOCKED: iterations must be an integer between 1 and 10."
    try:
        n = int(str(value).strip() if isinstance(value, str) else value)
    except (TypeError, ValueError, AttributeError):
        return None, "BLOCKED: iterations must be an integer between 1 and 10."
    if n < 1 or n > 10:
        return None, "BLOCKED: iterations must be an integer between 1 and 10."
    return n, None


def _parse_msf_options(options: str) -> tuple[dict[str, str], str | None]:
    """Parse free-form ``key=value`` options via shared ``parse_extra_options``.

    Args:
        options: Raw options string (``"RHOSTS=... LPORT=4444"``).
    Returns:
        ``(opts_dict, None)`` on success; ``({}, error)`` with a BLOCKED
        string when metacharacters/unbalanced quotes hit, a token lacks
        ``=``, or a key fails ``_OPT_KEY_RE``. Passwords/hashes are never
        capped (NO-CAP-SECRETS) — only the key shape is gated.
    Gates: Shared shell-metachar rejection + key regex.
    Side-effects: None.
    """
    opts = (options or "").strip()
    if not opts:
        return {}, None
    tokens, err = parse_extra_options(opts)
    if err:
        return {}, err
    parsed: dict[str, str] = {}
    rejected: list[str] = []
    for tok in tokens:
        if "=" not in tok:
            rejected.append(tok)
            continue
        key, _, val = tok.partition("=")
        if not _OPT_KEY_RE.match(key):
            return {}, f"BLOCKED: invalid option key {key!r}."
        parsed[key] = val
    if rejected:
        return {}, f"BLOCKED: options must be key=value pairs; rejected: {rejected}."
    return parsed, None


def register_metasploit_tools(mcp: Any, *, ctx: ToolContext) -> None:
    """Register the Metasploit tool family on ``mcp``.

    Args:
        mcp: The MCP server to register tools on.
        ctx: ToolContext (workspace + config + audit/allowlist used here).
    Returns: None.
    Gates: Per-tool gates documented on each tool (structured
        ``@require_allowlist`` where a ``target_ip`` param exists, manual
        ``check_targets_allowlist`` elsewhere, always on FULL input).
    Side-effects: Registers the MSF ``@mcp.tool`` functions.
    """
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def run_msf_module(module: str, target_ip: str, options: str = "") -> str:
        """Run a Metasploit module against the target. Pass the module path (e.g. 'exploit/multi/http/log4shell_header_injection') and key=value options separated by spaces. The module runs in a visible terminal.

        Args:
            module: Metasploit module path ([A-Za-z0-9_./-]{1,120}).
            target_ip: Target IP or domain (structured allowlist gate).
            options: Extra ``key=value`` pairs (shared metachar parser).
        Returns:
            MSF_RESULT block with attempt id, module, target, full options,
            and a marked OUTPUT-only log tail.
        Gates:
            ``@require_allowlist`` on target_ip; module regex/length;
            ``_parse_msf_options`` on the FULL options string; manual
            ``_extract_msf_rhosts`` over the FULL ``set`` lines (RHOSTS/RHOST/
            LHOST/pivot) so an options-carried host cannot bypass the lock.
            Passwords/hashes are never capped.
        Side-effects:
            Writes msf_run.rc + msf_output.log under the attempt dir; runs
            msfconsole (sandbox worker when enabled, host argv otherwise).
        """
        mod_err = _validate_module(module)
        if mod_err:
            return mod_err
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP address or domain."

        attempt_dir, attempt_id = _attempt_dir(workspace)
        log_path = attempt_dir / "msf_output.log"

        # Parse the FULL options string first (RULE-LOCK-FIRST); only display
        # tails are truncated later. Shared parser rejects shell metacharacters
        # in one place so this family cannot drift from web_scan/payloads.
        opts_raw = (options or "").strip()
        parsed_opts, opts_err = _parse_msf_options(opts_raw)
        if opts_err:
            return opts_err
        set_lines = [f"set {key} {val}" for key, val in parsed_opts.items()]

        # Tool-layer scope gate over the FULL set lines: the options text
        # becomes ``set`` lines in the resource file verbatim, so an
        # options-carried host (``LHOST=evil.com`` callback egress,
        # ``RHOSTS=`` target override) would otherwise bypass the structured
        # target_ip gate. _extract_msf_rhosts covers RHOSTS, RHOST, LHOST,
        # and pivot hosts.
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts("\n".join(set_lines)), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: run_msf_module\nMODULE: {module}"

        # Build a msfconsole resource file (one command per line) and invoke
        # msfconsole with an argv list (no shell). This replaces the previous
        # bash -c / cmd /c ``msfconsole -x "..."`` wrappers that were shell-
        # injectable via the module/opts/target_ip string.
        rc_path = attempt_dir / "msf_run.rc"
        rc_lines = [f"use {module}", f"set RHOSTS {target_ip}"]
        rc_lines.extend(set_lines)
        rc_lines.append("run")
        rc_lines.append("exit -y")
        rc_path.write_text("\n".join(rc_lines) + "\n", encoding="utf-8")

        # ---- sandbox path: msfconsole runs INSIDE the disposable worker from
        # the resource file bound under /workspace (no host metasploit).
        if getattr(ctx, "sandbox", None) is not None:
            from tools.mcp_tools.sandbox_exec import run_argv_in_sandbox

            try:
                _rc_container = ctx.sandbox.container_path(rc_path)
            except SandboxError as exc:
                return f"MSF_RESULT: blocked\n{sandbox_error_block(exc, tool_name='run_msf_module')}"
            _msf_argv = ["msfconsole", "-q", "-r", _rc_container]
            start = time.monotonic()
            try:
                _ran, result = run_argv_in_sandbox(
                    ctx,
                    _msf_argv,
                    target_ip=str(target_ip),
                    timeout=_MSF_RUN_TIMEOUT,
                    cwd_host=attempt_dir,
                    tool_name="run_msf_module",
                )
            except SandboxError as exc:
                return f"MSF_RESULT: blocked\n{sandbox_error_block(exc, tool_name='run_msf_module')}"
            merged = result.stdout or ""
            if result.stderr:
                merged = f"{merged}\n{result.stderr}" if merged else result.stderr
            try:
                log_path.write_text(merged, encoding="utf-8", errors="replace")
            except OSError:
                pass
            return (
                f"MSF_RESULT: {result.status} (exit_code={result.exit_code}, "
                f"duration={result.duration_seconds:.1f}s, sandbox)\n"
                f"ATTEMPT_ID: {attempt_id}\n"
                f"MODULE: {module}\n"
                f"TARGET: {target_ip}\n"
                f"OPTIONS: {opts_raw}\n"
                f"LOG_TAIL:\n{_tail(merged, _MAX_LOG_CHARS)}"
            )

        # Linux/macOS: honor exploit.msfconsole_path from config when msfconsole
        # isn't on PATH under that name (default "msfconsole"). No effect on
        # Windows, which still uses the same argv via CREATE_NEW_CONSOLE.
        _msf_bin = str((config or {}).get("exploit", {}).get("msfconsole_path", "msfconsole")) or "msfconsole"
        msf_argv = [_msf_bin, "-q", "-r", str(rc_path)]
        start = time.monotonic()
        if _platform_system() == "Windows":
            proc = subprocess.Popen(
                msf_argv,
                cwd=str(attempt_dir),
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
            timeout = _MSF_RUN_TIMEOUT
            try:
                exit_code = proc.wait(timeout=timeout)
                status = "completed" if exit_code == 0 else "failed"
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                exit_code = None
                status = "timed_out"
        else:
            with open(str(log_path), "w") as fh:
                proc = subprocess.Popen(
                    msf_argv,
                    cwd=str(attempt_dir),
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                timeout = _MSF_RUN_TIMEOUT
                try:
                    exit_code = proc.wait(timeout=timeout)
                    status = "completed" if exit_code == 0 else "failed"
                except subprocess.TimeoutExpired:
                    # M2: reap the whole process group on timeout.
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                    exit_code = None
                    status = "timed_out"

        elapsed = time.monotonic() - start
        log_tail = ""
        if log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="replace")
            log_tail = _tail(text, _MAX_LOG_CHARS)

        return (
            f"MSF_RESULT: {status} (exit_code={exit_code}, duration={elapsed:.1f}s)\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"MODULE: {module}\n"
            f"TARGET: {target_ip}\n"
            f"OPTIONS: {opts_raw}\n"
            f"LOG_TAIL:\n{log_tail}"
        )

    _msf_bridge: MetasploitBridge | None = None
    mcp._msf_bridge = None

    def _msf_bridge_or_blocked() -> Any:
        """Bridge accessor that FAILS CLOSED when the sandbox is enabled.

        Args: None.
        Returns:
            The shared host-side ``MetasploitBridge``.
        Gates:
            Sandbox presence: when ``ctx.sandbox`` is set, raises
            ``SandboxUnsupportedError`` (a ``SandboxError``) instead of
            touching the host loopback bridge. Every bridge tool catches it
            and returns a canonical SANDBOX_* block — never a traceback,
            never a silent host fallback. Workarounds: drive msfconsole
            inside the worker via run_exploit_terminal / run_msf_module, or
            deliberately set ``sandbox.enabled: false`` for legacy host mode.
        Side-effects: Lazily creates and caches the bridge on ``mcp``.
        """
        if getattr(ctx, "sandbox", None) is not None:
            from tools.sandbox.exceptions import SandboxUnsupportedError

            raise SandboxUnsupportedError(
                "Metasploit RPC bridge cannot execute inside the disposable sandbox "
                "(host-side loopback process). Use msfconsole inside the worker via "
                "run_exploit_terminal / run_msf_module, or set sandbox.enabled: false "
                "to deliberately restore host-mode metasploit."
            )
        return _get_msf_bridge()

    def _get_msf_bridge() -> MetasploitBridge:
        if mcp._msf_bridge is None:
            mcp._msf_bridge = get_metasploit_bridge(workspace)
        return mcp._msf_bridge

    @mcp.tool()
    @audit_tool
    def msfconsole_start() -> str:
        """Start an interactive msfconsole session in a tmux session. This is a persistent session that stays running in the background. Use msfconsole_command to send commands to it.

        Args: None.
        Returns:
            MSFCONSOLE_STARTED block (name, message, marked initial-output
            tail) or MSFCONSOLE_FAILED, or a SANDBOX_* block under sandbox.
        Gates: ``@audit_tool`` only (local-only: starts the host console, no
            target). Sandbox fails closed via ``_msf_bridge_or_blocked``.
        Side-effects: Starts the persistent host msfconsole (host mode only).
        """
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSFCONSOLE_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msfconsole_start')}"
        result = bridge.start_console()
        if result.get("success"):
            return (
                f"MSFCONSOLE_STARTED\n"
                f"NAME: {result.get('name')}\n"
                f"MESSAGE: {result.get('message')}\n"
                f"INITIAL_OUTPUT:\n{_tail(result.get('initial_output', ''), 500)}"
            )
        return f"MSFCONSOLE_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msfconsole_stop() -> str:
        """Stop the interactive msfconsole session.

        Args: None.
        Returns:
            MSFCONSOLE_STOPPED block, or a SANDBOX_* block under sandbox.
        Gates: ``@audit_tool`` only (local-only). Sandbox fails closed via
            ``_msf_bridge_or_blocked``.
        Side-effects: Stops the persistent host msfconsole (host mode only).
        """
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSFCONSOLE_STOPPED: blocked\n{sandbox_error_block(exc, tool_name='msfconsole_stop')}"
        result = bridge.stop_console()
        return f"MSFCONSOLE_STOPPED\nSUCCESS: {result.get('success')}\nMESSAGE: {result.get('message', '')}"

    @mcp.tool()
    @audit_tool
    def msfconsole_command(command: str, wait_seconds: float = 2.0, read_lines: int = 100) -> str:
        """Execute a command in the interactive msfconsole session. Use for: loading modules, setting options, running exploits, checking sessions, etc. The command is sent to the persistent msfconsole and output is captured.

        Args:
            command: FULL free-text msfconsole command (never truncated
                before gating).
            wait_seconds: Prompt-wait budget (clamped 0.5-600).
            read_lines: Output lines to read back (clamped 1-1000).
        Returns:
            MSFCONSOLE_COMMAND block with a marked OUTPUT-only tail, a
            BLOCKED line for out-of-scope hosts, or a SANDBOX_* block.
        Gates:
            ``@audit_tool`` + MANUAL ``_extract_msf_rhosts`` over the FULL
            command (RHOSTS/RHOST/LHOST/pivot) via
            ``check_targets_allowlist`` — a direct MCP client bypasses the
            agent loop's policy, so the tool layer refuses out-of-scope
            hosts itself. ``set LHOST evil.com`` stages an egress callback
            and is gated the same way. Only the display OUTPUT tail is cut.
        Side-effects: Sends the command to the persistent msfconsole.
        """
        # Tool-layer scope gate on the FULL command (RULE-LOCK-FIRST).
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts(command), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msfconsole_command\nCOMMAND: {command[:200]}"
        wait, wait_err = _clamp_wait(wait_seconds, 2.0)
        if wait_err or wait is None:
            return wait_err or "BLOCKED: wait_seconds must be a number."
        lines, _ = _clamp_read_lines(read_lines, 100)
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSFCONSOLE_COMMAND_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msfconsole_command')}"
        result = bridge.console_command(command, wait, lines)
        if result.get("success"):
            tail = _tail(result.get("output", ""), _MAX_OUTPUT_CHARS)
            return f"MSFCONSOLE_COMMAND: {command}\nWAIT: {wait}s\nOUTPUT:\n{tail}"
        return f"MSFCONSOLE_COMMAND_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @require_allowlist()
    def msf_run_exploit(
        module: str, target_ip: str, options: str = "", payload: str = "", wait_seconds: float = 30.0
    ) -> str:
        """Run a Metasploit exploit module against a target using the persistent msfconsole. Provide module path (e.g., 'exploit/multi/http/log4shell_header_injection'), target IP, and optional key=value options separated by spaces. Returns the full exploit output including any session that was created.

        Args:
            module: Exploit module path (regex + length gated).
            target_ip: Target IP or domain (structured allowlist gate).
            options: Extra ``key=value`` pairs (shared metachar parser).
            payload: Optional payload path (regex + length gated).
            wait_seconds: Exploit-wait budget (clamped 0.5-600).
        Returns:
            MSF_EXPLOIT_RESULT block with a marked OUTPUT-only tail.
        Gates:
            ``@require_allowlist`` on target_ip; module/payload shape;
            ``_parse_msf_options`` on the FULL options string; manual
            ``_extract_msf_option_hosts`` over the parsed options (LHOST
            callback egress / RHOST target override cannot bypass the lock).
            Secrets never capped.
        Side-effects: Runs the exploit via the persistent msfconsole.
        """
        mod_err = _validate_module(module)
        if mod_err:
            return mod_err
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        pay_err = _validate_payload(payload)
        if pay_err:
            return pay_err
        opts, opts_err = _parse_msf_options(options)
        if opts_err:
            return opts_err
        # Tool-layer scope gate: the free-form options dict is forwarded to the
        # bridge (which skips only RHOSTS), so an options-carried host
        # (``LHOST=evil.com`` callback egress, ``RHOST=`` target override) would
        # otherwise bypass the structured target_ip gate.
        allowed, reason = check_targets_allowlist(_extract_msf_option_hosts(opts), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_run_exploit\nMODULE: {module}"
        wait, wait_err = _clamp_wait(wait_seconds, 30.0)
        if wait_err or wait is None:
            return wait_err or "BLOCKED: wait_seconds must be a number."
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_EXPLOIT_RESULT: blocked\n{sandbox_error_block(exc, tool_name='msf_run_exploit')}"
        result = bridge.run_exploit(module, target_ip, opts, payload.strip(), wait)
        lines = [
            f"MSF_EXPLOIT_RESULT: {result.get('status', 'unknown')}",
            f"MODULE: {module}",
            f"TARGET: {target_ip}",
            f"DURATION: {result.get('duration_seconds', 0):.1f}s",
        ]
        if result.get("session_created"):
            sess = result["session_created"]
            sid, stype, stip = sess.get("session_id"), sess.get("session_type"), sess.get("target_ip")
            lines.append(f"SESSION_OPENED: id={sid} type={stype} target={stip}")
        if result.get("error"):
            lines.append(f"ERROR: {result['error']}")
        lines.append(f"OUTPUT:\n{_tail(result.get('output', ''), _MAX_OUTPUT_CHARS)}")
        return "\n".join(lines)

    @mcp.tool()
    @require_allowlist()
    def msf_run_auxiliary(module: str, target_ip: str, options: str = "", wait_seconds: float = 15.0) -> str:
        """Run a Metasploit auxiliary module (scanner, fuzzer, dos, etc.) against a target. Use for: port scanning, service enumeration, vulnerability checking.

        Args:
            module: Auxiliary module path (regex + length gated).
            target_ip: Target IP or domain (structured allowlist gate).
            options: Extra ``key=value`` pairs (shared metachar parser).
            wait_seconds: Module-wait budget (clamped 0.5-600).
        Returns:
            MSF_AUXILIARY_RESULT block with a marked OUTPUT-only tail.
        Gates:
            ``@require_allowlist`` on target_ip; module shape;
            ``_parse_msf_options`` on the FULL options string; manual
            ``_extract_msf_option_hosts`` over the parsed options.
        Side-effects: Runs the auxiliary module via the persistent msfconsole.
        """
        mod_err = _validate_module(module)
        if mod_err:
            return mod_err
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        opts, opts_err = _parse_msf_options(options)
        if opts_err:
            return opts_err
        allowed, reason = check_targets_allowlist(_extract_msf_option_hosts(opts), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_run_auxiliary\nMODULE: {module}"
        wait, wait_err = _clamp_wait(wait_seconds, 15.0)
        if wait_err or wait is None:
            return wait_err or "BLOCKED: wait_seconds must be a number."
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_AUXILIARY_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msf_run_auxiliary')}"
        result = bridge.run_auxiliary(module, target_ip, opts, wait)
        if result.get("success"):
            return f"MSF_AUXILIARY_RESULT: {module}\nTARGET: {target_ip}\nOUTPUT:\n{_tail(result.get('output', ''), _MAX_OUTPUT_CHARS)}"
        return f"MSF_AUXILIARY_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_list_sessions() -> str:
        """List all active Metasploit sessions (meterpreter, shell, cmd). Returns session IDs, types, target IPs, and platforms.

        Args: None.
        Returns:
            MSF_SESSIONS block (capped at 100 rows), an empty notice, or a
            SANDBOX_* block under sandbox.
        Gates: ``@audit_tool`` only (local-only: reads host session state).
            Sandbox fails closed via ``_msf_bridge_or_blocked``.
        Side-effects: None (read-only list).
        """
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_SESSIONS: blocked\n{sandbox_error_block(exc, tool_name='msf_list_sessions')}"
        sessions = bridge.list_sessions()
        if not sessions:
            return "MSF_SESSIONS: No active Metasploit sessions."
        shown = sessions[:_MAX_SESSIONS_SHOWN]
        lines = [f"MSF_SESSIONS: {len(sessions)} active", ""]
        for s in shown:
            lines.append(
                f"  [{s['session_id']}] {s['session_type']} {s['platform']} — "
                f"{s['target_ip']}:{s['target_port']} (via {s.get('via_exploit', 'unknown')})"
            )
            lines.append(f"      status: {s.get('status', 'unknown')}, info: {s.get('info', '')}")
        if len(sessions) > _MAX_SESSIONS_SHOWN:
            lines.append(f"[truncated - showing {_MAX_SESSIONS_SHOWN} of {len(sessions)} sessions]")
        return "\n".join(lines)

    @mcp.tool()
    @audit_tool
    def msf_interact_session(session_id: int, command: str, wait_seconds: float = 3.0) -> str:
        """Send a command to a specific Metasploit session (meterpreter or shell). Use for: running post-exploitation commands, gathering system info, pivoting, etc. The session is backgrounded after the command completes.

        Args:
            session_id: Positive session id (clamped).
            command: FULL free-text session command (never truncated before
                gating; may itself set RHOSTS for a route/portfwd).
            wait_seconds: Command-wait budget (clamped 0.5-600).
        Returns:
            MSF_SESSION_INTERACT block with a marked OUTPUT-only tail, a
            BLOCKED line for out-of-scope hosts, or a SANDBOX_* block.
        Gates:
            ``@audit_tool`` + MANUAL ``_extract_msf_rhosts`` over the FULL
            command (the command can pivot to a new host even on an existing
            session). Only the display OUTPUT tail is cut.
        Side-effects: Sends the command to the live session, then backgrounds it.
        """
        sid, sid_err = _clamp_session_id(session_id)
        if sid_err or sid is None:
            return sid_err or "BLOCKED: session_id must be a positive integer."
        # Tool-layer scope gate on the FULL command: it can set RHOSTS for a
        # route/portfwd to a new host; refuse out-of-scope hosts even on an
        # existing session.
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts(command), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_interact_session\nCOMMAND: {command[:200]}"
        wait, wait_err = _clamp_wait(wait_seconds, 3.0)
        if wait_err or wait is None:
            return wait_err or "BLOCKED: wait_seconds must be a number."
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_SESSION_INTERACT_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msf_interact_session')}"
        result = bridge.interact_session(sid, command, wait)
        if result.get("success"):
            return (
                f"MSF_SESSION_INTERACT: session {sid}\n"
                f"COMMAND: {command}\n"
                f"OUTPUT:\n{_tail(result.get('output', ''), _MAX_OUTPUT_CHARS)}"
            )
        return f"MSF_SESSION_INTERACT_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_run_post_module(module: str, session_id: int, options: str = "") -> str:
        """Run a post-exploitation module against a specific Metasploit session. Use for: privilege escalation, credential harvesting, persistence, keylogging, screenshot, etc.

        Args:
            module: Post module path (regex + length gated).
            session_id: Positive session id (clamped).
            options: Extra ``key=value`` pairs (shared metachar parser).
        Returns:
            MSF_POST_RESULT block with a marked OUTPUT-only tail, or a
            SANDBOX_* block under sandbox.
        Gates:
            ``@audit_tool`` + module shape + session clamp +
            ``_parse_msf_options`` on the FULL options string. Secrets never
            capped.
        Side-effects: Runs the post module against the live session.
        """
        mod_err = _validate_module(module)
        if mod_err:
            return mod_err
        sid, sid_err = _clamp_session_id(session_id)
        if sid_err or sid is None:
            return sid_err or "BLOCKED: session_id must be a positive integer."
        opts, opts_err = _parse_msf_options(options)
        if opts_err:
            return opts_err
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_POST_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msf_run_post_module')}"
        result = bridge.run_post_module(module, sid, opts)
        if result.get("success"):
            return f"MSF_POST_RESULT: {module}\nSESSION: {sid}\nOUTPUT:\n{_tail(result.get('output', ''), _MAX_OUTPUT_CHARS)}"
        return f"MSF_POST_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_kill_session(session_id: int) -> str:
        """Kill a specific Metasploit session.

        Args:
            session_id: Positive session id (clamped).
        Returns:
            MSF_SESSION_KILLED block with a marked OUTPUT-only tail, or a
            SANDBOX_* block under sandbox.
        Gates: ``@audit_tool`` + session clamp.
        Side-effects: Kills the live session.
        """
        sid, sid_err = _clamp_session_id(session_id)
        if sid_err or sid is None:
            return sid_err or "BLOCKED: session_id must be a positive integer."
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_SESSION_KILLED: blocked\n{sandbox_error_block(exc, tool_name='msf_kill_session')}"
        result = bridge.kill_session(sid)
        return (
            f"MSF_SESSION_KILLED: {sid}\n"
            f"SUCCESS: {result.get('success', False)}\n"
            f"OUTPUT:\n{_tail(result.get('output', ''), 500)}"
        )

    @mcp.tool()
    @audit_tool
    def msf_generate_payload(
        payload_type: str,
        lhost: str,
        lport: int = 4444,
        fmt: str = "exe",
        platform: str = "windows",
        arch: str = "x64",
        options: str = "",
        encoder: str = "",
        iterations: int = 1,
    ) -> str:
        """Generate a payload using msfvenom through the Metasploit bridge. Supports encoders and bad character avoidance. Returns the path to the generated payload file.

        Args:
            payload_type: Payload path (regex + length gated).
            lhost: Callback host (syntax + allowlist gated; egress lock).
            lport: Callback port (clamped 1-65535).
            fmt: Output format (short-field shape).
            platform: Target platform (short-field shape).
            arch: Target arch (short-field shape).
            options: Extra msfvenom options (shared metachar parser).
            encoder: Encoder name (short-field shape, "" = none).
            iterations: Encoder iterations (clamped 1-10).
        Returns:
            MSF_PAYLOAD_GENERATED block with a marked OUTPUT-only tail, a
            BLOCKED line for out-of-scope lhost, or a SANDBOX_* block.
        Gates:
            ``@audit_tool`` + MANUAL ``check_targets_allowlist([lhost])`` on
            the FULL lhost (a callback to an out-of-scope host is an egress
            path). Payload/field shapes gated; secrets never capped.
        Side-effects: Runs msfvenom via the bridge; writes the payload file.
        """
        pay_err = _validate_payload(payload_type)
        if pay_err:
            return pay_err
        if not lhost or not lhost.strip() or not validate_target_or_ip(lhost.strip()):
            return "BLOCKED: lhost must be a valid IP address or domain."
        # Tool-layer scope gate: lhost is the payload's callback host. A payload
        # that calls back to an out-of-scope host is an egress path the allowlist
        # must gate (mirrors the command-analyzer egress check on the agent path).
        allowed, reason = check_targets_allowlist([lhost.strip()], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_generate_payload\nLHOST: {lhost}"
        port, port_err = _clamp_port(lport)
        if port_err or port is None:
            return port_err or "BLOCKED: port must be an integer between 1 and 65535."
        for _field_val, _field_label in ((fmt, "format"), (platform, "platform"), (arch, "arch")):
            _field_err = _validate_short_field(_field_val, _field_label)
            if _field_err:
                return _field_err
        if (encoder or "").strip():
            _enc_err = _validate_short_field(encoder, "encoder")
            if _enc_err:
                return _enc_err
        count, count_err = _clamp_iterations(iterations)
        if count_err or count is None:
            return count_err or "BLOCKED: iterations must be an integer between 1 and 10."
        _extra_tokens, extra_err = parse_extra_options(options)
        if extra_err:
            return extra_err
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_PAYLOAD_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msf_generate_payload')}"
        result = bridge.generate_payload(
            payload_type.strip(), lhost.strip(), port, fmt.strip(), platform.strip(), arch.strip(),
            options, encoder.strip(), count,
        )
        if result.get("success"):
            return (
                f"MSF_PAYLOAD_GENERATED\n"
                f"TYPE: {payload_type}\n"
                f"FORMAT: {fmt}\n"
                f"PLATFORM: {platform}/{arch}\n"
                f"FILE: {result.get('file')}\n"
                f"SIZE: {result.get('file_size')} bytes\n"
                f"COMMAND: {result.get('command')}\n"
                f"OUTPUT:\n{_tail(result.get('output', ''), 1000)}"
            )
        return f"MSF_PAYLOAD_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_run_resource_script(script_content: str) -> str:
        """Create and run a Metasploit resource script in the persistent msfconsole. Resource scripts automate sequences of msfconsole commands. Use for: automated exploitation chains, mass scanning, post-exploitation workflows.

        Args:
            script_content: FULL resource script text (never truncated before
                gating; script code is never capped).
        Returns:
            MSF_RESOURCE_SCRIPT_EXECUTED block with a marked OUTPUT-only
            tail, a BLOCKED line for out-of-scope hosts, or a SANDBOX_* block.
        Gates:
            ``@audit_tool`` + MANUAL ``_extract_msf_rhosts`` over the FULL
            script (it can ``set RHOSTS <any host>; run``). Only the display
            OUTPUT tail is cut.
        Side-effects: Writes the script and runs it in the persistent msfconsole.
        """
        # Tool-layer scope gate on the FULL script (RULE-LOCK-FIRST): a
        # resource script is free-text msfconsole commands that can
        # ``set RHOSTS <any host>; run``. Extract every RHOSTS/RHOST value
        # and refuse any host outside the allowlist.
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts(script_content), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_run_resource_script"
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_RESOURCE_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msf_run_resource_script')}"
        result = bridge.run_resource_script(script_content)
        if result.get("success"):
            return f"MSF_RESOURCE_SCRIPT_EXECUTED\nOUTPUT:\n{_tail(result.get('output', ''), _MAX_OUTPUT_CHARS)}"
        return f"MSF_RESOURCE_FAILED: {result.get('error', 'unknown error')}"

    # ── Phase 3: recipe dispatch + handler orchestration + post wrappers ──

    def _listener_cfg() -> dict[str, Any]:
        return ((config or {}).get("exploit", {}) or {}).get("msf", {}) or {}

    def _msf_enabled(key: str, default: bool = False) -> bool:
        return bool(_listener_cfg().get(key, default))

    @mcp.tool()
    @audit_tool
    def msf_run_recipe(name: str, target_ip: str = "", session_id: int = 0, options: str = "") -> str:
        """Run a named Metasploit recipe (curated module+option preset). Recipes: smb_version, bluekeep, psexec, cred_gather_win, local_exploit_suggester, hashdump, getsystem, handler. Pass target_ip for exploit/auxiliary kinds, session_id for post kinds, and extra key=value options to override the preset.

        Args:
            name: Recipe name (must exist in the catalog).
            target_ip: Target for exploit/auxiliary kinds (syntax-checked
                when present; allowlist-gated with option hosts).
            session_id: Session for post kinds (positive when the recipe
                needs one).
            options: Extra ``key=value`` overrides (shared metachar parser).
        Returns:
            MSF_RECIPE_RESULT block with a marked OUTPUT-only tail, a
            BLOCKED line, or a SANDBOX_* block.
        Gates:
            Config gate (``msf.recipes_enabled``); recipe-name allowlist;
            ``_parse_msf_options`` on the FULL options string; manual
            ``check_targets_allowlist`` over target_ip plus every
            LHOST/RHOST/RHOSTS host in options (callback egress + target
            override). Secrets never capped.
        Side-effects: Dispatches via the bridge to run_exploit /
            run_auxiliary / run_post_module / start_handler by kind.
        """
        if not _msf_enabled("recipes_enabled", False):
            return f"BLOCKED: msf.recipes_enabled is disabled. Recipe: {name}"
        recipe = get_msf_recipe(name)
        if not recipe:
            return f"BLOCKED: unknown MSF recipe {name!r}. Available: {', '.join(sorted(MSF_RECIPES))}"
        opts, opts_err = _parse_msf_options(options)
        if opts_err:
            return opts_err
        # Allowlist gate: target_ip (exploit/auxiliary) and any LHOST/RHOST/
        # RHOSTS host carried in options (egress + override).
        dests: list[str] = [target_ip.strip()] if (target_ip or "").strip() else []
        if dests and not validate_target_or_ip(dests[0]):
            return "ERROR: Invalid target (IP or domain)."
        dests.extend(_extract_msf_option_hosts(opts))
        allowed, reason = check_targets_allowlist(dests, config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_run_recipe\nRECIPE: {name}"
        if recipe.get("kind") == "post":
            sid, sid_err = _clamp_session_id(session_id)
            if sid_err or sid is None:
                return "BLOCKED: post recipes require a positive session_id."
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_RECIPE_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msf_run_recipe')}"
        result = bridge.run_recipe(name, (target_ip or "").strip(), int(session_id or 0), opts)
        if result.get("success"):
            return (
                f"MSF_RECIPE_RESULT: {name}\n"
                f"MODULE: {recipe['module']}\n"
                f"KIND: {recipe['kind']}\n"
                f"OUTPUT:\n{_tail(result.get('output', ''), _MAX_OUTPUT_CHARS)}"
            )
        return f"MSF_RECIPE_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_start_handler(
        lhost: str, lport: int = 4444, payload: str = "windows/meterpreter/reverse_tcp", options: str = ""
    ) -> str:
        """Start exploit/multi/handler as a backgrounded job to catch a generated payload. lhost is the operator callback host (must be in allowed_targets). Pairs with msf_generate_payload: generate a reverse payload, then start a handler on the same LHOST/LPORT.

        Args:
            lhost: Operator callback host (syntax + allowlist gated).
            lport: Callback port (clamped 1-65535).
            payload: Handler payload (regex + length gated).
            options: Extra ``key=value`` pairs (shared metachar parser;
                option-carried hosts allowlist-gated).
        Returns:
            MSF_HANDLER_STARTED block with a marked OUTPUT-only tail, a
            BLOCKED line, or a SANDBOX_* block.
        Gates:
            ``@audit_tool`` + MANUAL ``check_targets_allowlist`` on the FULL
            lhost plus every option-carried host. Secrets never capped.
        Side-effects: Starts the backgrounded handler job in msfconsole.
        """
        # Allowlist gate: lhost is the payload's callback host (operator box).
        if not lhost or not lhost.strip() or not validate_target_or_ip(lhost.strip()):
            return "BLOCKED: lhost must be a valid IP address or domain."
        allowed, reason = check_targets_allowlist([lhost.strip()], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_start_handler\nLHOST: {lhost}"
        port, port_err = _clamp_port(lport)
        if port_err or port is None:
            return port_err or "BLOCKED: port must be an integer between 1 and 65535."
        pay_err = _validate_payload(payload)
        if pay_err:
            return pay_err
        opts, opts_err = _parse_msf_options(options)
        if opts_err:
            return opts_err
        opt_hosts = _extract_msf_option_hosts(opts)
        if opt_hosts:
            opt_allowed, opt_reason = check_targets_allowlist(opt_hosts, config)
            if not opt_allowed:
                return f"BLOCKED: {opt_reason}\nTOOL: msf_start_handler\nLHOST: {lhost}"
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_HANDLER_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msf_start_handler')}"
        result = bridge.start_handler(lhost.strip(), port, payload.strip(), opts)
        if result.get("success"):
            return (
                f"MSF_HANDLER_STARTED\n"
                f"LHOST: {lhost}\nLPORT: {port}\nPAYLOAD: {payload}\n"
                f"OUTPUT:\n{_tail(result.get('output', ''), 1500)}"
            )
        return f"MSF_HANDLER_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_stop_handler() -> str:
        """Stop all backgrounded handler jobs in the persistent msfconsole (jobs -K).

        Args: None.
        Returns:
            MSF_HANDLER_STOPPED block with a marked OUTPUT-only tail, or a
            SANDBOX_* block under sandbox.
        Gates: ``@audit_tool`` only (local-only). Sandbox fails closed via
            ``_msf_bridge_or_blocked``.
        Side-effects: Kills all handler jobs (``jobs -K``).
        """
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_HANDLER_STOPPED: blocked\n{sandbox_error_block(exc, tool_name='msf_stop_handler')}"
        result = bridge.stop_handler()
        return (
            f"MSF_HANDLER_STOPPED\nSUCCESS: {result.get('success', False)}\nOUTPUT:\n{_tail(result.get('output', ''), 500)}"
        )

    def _post_module(session_id: int, module: str, label: str, options: str = "") -> str:
        """Shared runner for the meterpreter post wrappers.

        Args:
            session_id: Positive session id (clamped).
            module: Post module path.
            label: Short label for result lines.
            options: Extra ``key=value`` pairs (shared metachar parser).
        Returns:
            MSF_POST_RESULT / MSF_POST_FAILED block, a BLOCKED line, or a
            SANDBOX_* block under sandbox.
        Gates: Session clamp + ``_parse_msf_options`` on the FULL options.
        Side-effects: Runs the post module against the live session.
        """
        sid, sid_err = _clamp_session_id(session_id)
        if sid_err or sid is None:
            return f"BLOCKED: {label} requires a positive session_id."
        opts, opts_err = _parse_msf_options(options)
        if opts_err:
            return opts_err
        try:
            bridge = _msf_bridge_or_blocked()
        except SandboxError as exc:
            return f"MSF_POST_FAILED: blocked\n{sandbox_error_block(exc, tool_name='msf_post_' + label)}"
        result = bridge.run_post_module(module, sid, opts)
        if result.get("success"):
            return f"MSF_POST_RESULT: {label}\nSESSION: {sid}\nOUTPUT:\n{_tail(result.get('output', ''), _MAX_OUTPUT_CHARS)}"
        return f"MSF_POST_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_post_hashdump(session_id: int) -> str:
        """Dump SAM hashes from a Windows meterpreter session (post/windows/gather/hashdump).

        Args:
            session_id: Positive session id (clamped).
        Returns: MSF_POST_RESULT block, BLOCKED line, or SANDBOX_* block.
        Gates: ``@audit_tool`` + session clamp (via ``_post_module``).
        Side-effects: Dumps SAM hashes via the live session.
        """
        return _post_module(session_id, "post/windows/gather/hashdump", "hashdump")

    @mcp.tool()
    @audit_tool
    def msf_post_getsystem(session_id: int) -> str:
        """Attempt SYSTEM elevation on a Windows meterpreter session (post/windows/escalate/getsystem).

        Args:
            session_id: Positive session id (clamped).
        Returns: MSF_POST_RESULT block, BLOCKED line, or SANDBOX_* block.
        Gates: ``@audit_tool`` + session clamp (via ``_post_module``).
        Side-effects: Attempts privilege elevation via the live session.
        """
        return _post_module(session_id, "post/windows/escalate/getsystem", "getsystem")

    @mcp.tool()
    @audit_tool
    def msf_post_portfwd(session_id: int, remote_host: str, remote_port: int, local_port: int = 0) -> str:
        """Forward a local port through a meterpreter session to a remote host (portfwd). remote_host must be in allowed_targets (the allowlist is the pivot lock).

        Args:
            session_id: Positive session id (clamped).
            remote_host: Pivot target (FULL allowlist gate — the pivot lock).
            remote_port: Remote port (clamped 1-65535).
            local_port: Local bind port (0 = auto, else 1-65535).
        Returns: MSF_POST_RESULT block, BLOCKED line, or SANDBOX_* block.
        Gates:
            ``@audit_tool`` + MANUAL ``check_targets_allowlist`` on the FULL
            remote_host + port clamps + session clamp.
        Side-effects: Establishes the port forward through the live session.
        """
        allowed, reason = check_targets_allowlist([remote_host], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_post_portfwd\nREMOTE: {remote_host}"
        rport, rport_err = _clamp_port(remote_port)
        if rport_err or rport is None:
            return rport_err or "BLOCKED: remote_port must be an integer between 1 and 65535."
        if isinstance(local_port, bool):
            return "BLOCKED: local_port must be 0 (auto) or an integer between 1 and 65535."
        try:
            lp = int(str(local_port).strip() if isinstance(local_port, str) else (local_port or 0))
        except (TypeError, ValueError, AttributeError):
            return "BLOCKED: local_port must be 0 (auto) or an integer between 1 and 65535."
        if lp != 0 and (lp < 1 or lp > 65535):
            return "BLOCKED: local_port must be 0 (auto) or an integer between 1 and 65535."
        return _post_module(
            session_id,
            "post/multi/manage/portfwd",
            "portfwd",
            f"remote_host={remote_host} remote_port={rport} local_port={lp}",
        )

    @mcp.tool()
    @audit_tool
    def msf_post_route(session_id: int, subnet: str) -> str:
        """Add a route through a meterpreter session to a target subnet (post/multi/manage/autoroute). The subnet's network address must be in allowed_targets (pivot lock).

        Args:
            session_id: Positive session id (clamped).
            subnet: Target subnet (``net`` or ``net/prefix``; the network
                address is FULL allowlist-gated).
        Returns: MSF_POST_RESULT block, BLOCKED line, or SANDBOX_* block.
        Gates:
            ``@audit_tool`` + MANUAL ``check_targets_allowlist`` on the FULL
            network address + prefix shape (0-32) + session clamp.
        Side-effects: Adds the route through the live session.
        """
        raw = (subnet or "").strip()
        if not raw:
            return "BLOCKED: subnet is required."
        net = raw.split("/")[0].strip()
        if not net or not validate_target_or_ip(net):
            return f"BLOCKED: invalid subnet {subnet!r}."
        if "/" in raw:
            prefix = raw.split("/", 1)[1].strip()
            if not prefix.isdigit() or int(prefix) < 0 or int(prefix) > 32:
                return f"BLOCKED: invalid subnet prefix in {subnet!r}."
        allowed, reason = check_targets_allowlist([net], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_post_route\nSUBNET: {subnet}"
        return _post_module(session_id, "post/multi/manage/autoroute", "route", f"subnet={raw}")
