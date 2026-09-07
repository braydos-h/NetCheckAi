"""Metasploit MCP tool registration."""

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
from tools.mcp_tools.registry import ToolContext, _platform_system
from tools.metasploit_bridge import MSF_RECIPES, MetasploitBridge, get_metasploit_bridge, get_msf_recipe
from tools.validation_utils import validate_target_or_ip


def register_metasploit_tools(mcp: Any, *, ctx: ToolContext) -> None:
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
        """Run a Metasploit module against the target. Pass the module path (e.g. 'exploit/multi/http/log4shell_header_injection') and key=value options separated by spaces. The module runs in a visible terminal."""
        if not module or not module.strip():
            return "BLOCKED: module path is required."
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        # C1: validate module path -- only Metasploit module path chars
        # (letters, digits, _, ., /, -) and bounded length; reject anything
        # that could break out of the msfconsole `use` command.
        if not re.fullmatch(r"[A-Za-z0-9_./-]{1,120}", module):
            return "BLOCKED: module path must match [A-Za-z0-9_./-]{1,120}."
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP address or domain."

        attempt_dir, attempt_id = _attempt_dir(workspace)
        log_path = attempt_dir / "msf_output.log"

        # C1: parse opts with shlex and reject tokens without '=' or bearing
        # shell metacharacters. Rebuild the set commands from sanitized pairs so
        # a malicious ``options`` string cannot inject into the msfconsole
        # command stream (which previously was concatenated into a bash -c /
        # cmd /c ``msfconsole -x "..."`` string).
        opts = options.strip() if options else ""
        import shlex as _shlex

        set_lines: list[str] = []
        rejected_opts: list[str] = []
        if opts:
            try:
                tokens = _shlex.split(opts)
            except ValueError:
                return "BLOCKED: options string could not be parsed (unbalanced quotes)."
            for tok in tokens:
                if "=" not in tok:
                    rejected_opts.append(tok)
                    continue
                key, _, val = tok.partition("=")
                if not re.fullmatch(r"[A-Za-z0-9_]{1,60}", key):
                    return f"BLOCKED: invalid option key {key!r}."
                # Reject shell metacharacters in the value (defense-in-depth; the
                # value is written to a resource file and never reaches a shell,
                # but a value containing ;/`/$() could still confuse msfconsole).
                if re.search(r"[;|&$`()]|<|>|\\|\n", val):
                    return f"BLOCKED: option value for {key!r} contains forbidden characters."
                set_lines.append(f"set {key} {val}")
        if rejected_opts:
            return f"BLOCKED: options must be key=value pairs; rejected: {rejected_opts}."

        # Tool-layer scope gate: the options text becomes ``set`` lines in the
        # resource file verbatim, so an options-carried host (``LHOST=evil.com``
        # callback egress, ``RHOSTS=`` target override) would otherwise bypass
        # the structured target_ip gate. _extract_msf_rhosts covers RHOSTS,
        # RHOST, LHOST, and pivot hosts.
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
            from tools.mcp_tools.sandbox_exec import run_argv_in_sandbox, sandbox_error_block
            from tools.sandbox.exceptions import SandboxError

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
                    timeout=600,
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
                f"OPTIONS: {opts}\n"
                f"LOG_TAIL:\n{merged[-4000:]}"
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
            timeout = 600
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
                timeout = 600
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
            log_tail = text[-4000:]

        return (
            f"MSF_RESULT: {status} (exit_code={exit_code}, duration={elapsed:.1f}s)\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"MODULE: {module}\n"
            f"TARGET: {target_ip}\n"
            f"OPTIONS: {opts}\n"
            f"LOG_TAIL:\n{log_tail}"
        )

    _msf_bridge: MetasploitBridge | None = None
    mcp._msf_bridge = None

    def _msf_bridge_or_blocked() -> Any:
        """Bridge accessor that FAILS CLOSED when the sandbox is enabled.

        The Metasploit RPC bridge is a HOST-side process on the operator's
        loopback that the sandbox netns deliberately denies. Under the sandbox,
        bridge tooling cannot silently run on the host (no automatic fallback):
        it raises SandboxUnsupportedError, which the MCP layer surfaces as a
        SANDBOX_* block. Workarounds: drive msfconsole inside the worker via
        run_exploit_terminal / run_msf_module, or deliberately set
        ``sandbox.enabled: false`` in config.yaml for legacy host-mode metasploit.
        """
        if getattr(ctx, "sandbox", None) is not None:
            from tools.sandbox.exceptions import SandboxUnsupportedError
            from tools.sandbox.mcp_bridge import sandbox_block

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
        """Start an interactive msfconsole session in a tmux session. This is a persistent session that stays running in the background. Use msfconsole_command to send commands to it."""
        bridge = _get_msf_bridge()
        result = bridge.start_console()
        if result.get("success"):
            return (
                f"MSFCONSOLE_STARTED\n"
                f"NAME: {result.get('name')}\n"
                f"MESSAGE: {result.get('message')}\n"
                f"INITIAL_OUTPUT:\n{result.get('initial_output', '')[:500]}"
            )
        return f"MSFCONSOLE_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msfconsole_stop() -> str:
        """Stop the interactive msfconsole session."""
        bridge = _get_msf_bridge()
        result = bridge.stop_console()
        return f"MSFCONSOLE_STOPPED\nSUCCESS: {result.get('success')}\nMESSAGE: {result.get('message', '')}"

    @mcp.tool()
    @audit_tool
    def msfconsole_command(command: str, wait_seconds: float = 2.0, read_lines: int = 100) -> str:
        """Execute a command in the interactive msfconsole session. Use for: loading modules, setting options, running exploits, checking sessions, etc. The command is sent to the persistent msfconsole and output is captured."""
        # Tool-layer scope gate: a direct MCP client can bypass the agent loop's
        # ExploitPolicy.approve_action, so extract RHOSTS/RHOST from the free-
        # text command and refuse any host not in exploit.allowed_targets.
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts(command), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msfconsole_command\nCOMMAND: {command[:200]}"
        bridge = _get_msf_bridge()
        result = bridge.console_command(command, wait_seconds, read_lines)
        if result.get("success"):
            return f"MSFCONSOLE_COMMAND: {command}\nWAIT: {wait_seconds}s\nOUTPUT:\n{result.get('output', '')}"
        return f"MSFCONSOLE_COMMAND_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @require_allowlist()
    def msf_run_exploit(
        module: str, target_ip: str, options: str = "", payload: str = "", wait_seconds: float = 30.0
    ) -> str:
        """Run a Metasploit exploit module against a target using the persistent msfconsole. Provide module path (e.g., 'exploit/multi/http/log4shell_header_injection'), target IP, and optional key=value options separated by spaces. Returns the full exploit output including any session that was created."""
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        bridge = _get_msf_bridge()
        opts: dict[str, str] = {}
        if options.strip():
            for item in options.strip().split():
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
        result = bridge.run_exploit(module, target_ip, opts, payload, wait_seconds)
        lines = [
            f"MSF_EXPLOIT_RESULT: {result.get('status', 'unknown')}",
            f"MODULE: {module}",
            f"TARGET: {target_ip}",
            f"DURATION: {result.get('duration_seconds', 0):.1f}s",
        ]
        if result.get("session_created"):
            sess = result["session_created"]
            lines.append(
                f"SESSION_OPENED: id={sess.get('session_id')} type={sess.get('session_type')} target={sess.get('target_ip')}"
            )
        if result.get("error"):
            lines.append(f"ERROR: {result['error']}")
        lines.append(f"OUTPUT:\n{result.get('output', '')[:2000]}")
        return "\n".join(lines)

    @mcp.tool()
    @require_allowlist()
    def msf_run_auxiliary(module: str, target_ip: str, options: str = "", wait_seconds: float = 15.0) -> str:
        """Run a Metasploit auxiliary module (scanner, fuzzer, dos, etc.) against a target. Use for: port scanning, service enumeration, vulnerability checking."""
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        bridge = _get_msf_bridge()
        opts: dict[str, str] = {}
        if options.strip():
            for item in options.strip().split():
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
        result = bridge.run_auxiliary(module, target_ip, opts, wait_seconds)
        if result.get("success"):
            return f"MSF_AUXILIARY_RESULT: {module}\nTARGET: {target_ip}\nOUTPUT:\n{result.get('output', '')[:2000]}"
        return f"MSF_AUXILIARY_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_list_sessions() -> str:
        """List all active Metasploit sessions (meterpreter, shell, cmd). Returns session IDs, types, target IPs, and platforms."""
        bridge = _get_msf_bridge()
        sessions = bridge.list_sessions()
        if not sessions:
            return "MSF_SESSIONS: No active Metasploit sessions."
        lines = [f"MSF_SESSIONS: {len(sessions)} active", ""]
        for s in sessions:
            lines.append(
                f"  [{s['session_id']}] {s['session_type']} {s['platform']} Ã¢â‚¬â€ "
                f"{s['target_ip']}:{s['target_port']} (via {s.get('via_exploit', 'unknown')})"
            )
            lines.append(f"      status: {s.get('status', 'unknown')}, info: {s.get('info', '')}")
        return "\n".join(lines)

    @mcp.tool()
    @audit_tool
    def msf_interact_session(session_id: int, command: str, wait_seconds: float = 3.0) -> str:
        """Send a command to a specific Metasploit session (meterpreter or shell). Use for: running post-exploitation commands, gathering system info, pivoting, etc. The session is backgrounded after the command completes."""
        # Tool-layer scope gate: the command can set RHOSTS for a route/portfwd
        # to a new host; refuse out-of-scope hosts even on an existing session.
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts(command), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_interact_session\nCOMMAND: {command[:200]}"
        bridge = _get_msf_bridge()
        result = bridge.interact_session(session_id, command, wait_seconds)
        if result.get("success"):
            return (
                f"MSF_SESSION_INTERACT: session {session_id}\n"
                f"COMMAND: {command}\n"
                f"OUTPUT:\n{result.get('output', '')[:2000]}"
            )
        return f"MSF_SESSION_INTERACT_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_run_post_module(module: str, session_id: int, options: str = "") -> str:
        """Run a post-exploitation module against a specific Metasploit session. Use for: privilege escalation, credential harvesting, persistence, keylogging, screenshot, etc."""
        bridge = _get_msf_bridge()
        opts: dict[str, str] = {}
        if options.strip():
            for item in options.strip().split():
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
        result = bridge.run_post_module(module, session_id, opts)
        if result.get("success"):
            return f"MSF_POST_RESULT: {module}\nSESSION: {session_id}\nOUTPUT:\n{result.get('output', '')[:2000]}"
        return f"MSF_POST_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_kill_session(session_id: int) -> str:
        """Kill a specific Metasploit session."""
        bridge = _get_msf_bridge()
        result = bridge.kill_session(session_id)
        return (
            f"MSF_SESSION_KILLED: {session_id}\n"
            f"SUCCESS: {result.get('success', False)}\n"
            f"OUTPUT:\n{result.get('output', '')[:500]}"
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
        """Generate a payload using msfvenom through the Metasploit bridge. Supports encoders and bad character avoidance. Returns the path to the generated payload file."""
        # Tool-layer scope gate: lhost is the payload's callback host. A payload
        # that calls back to an out-of-scope host is an egress path the allowlist
        # must gate (mirrors the command-analyzer egress check on the agent path).
        allowed, reason = check_targets_allowlist([lhost], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_generate_payload\nLHOST: {lhost}"
        bridge = _get_msf_bridge()
        result = bridge.generate_payload(payload_type, lhost, lport, fmt, platform, arch, options, encoder, iterations)
        if result.get("success"):
            return (
                f"MSF_PAYLOAD_GENERATED\n"
                f"TYPE: {payload_type}\n"
                f"FORMAT: {fmt}\n"
                f"PLATFORM: {platform}/{arch}\n"
                f"FILE: {result.get('file')}\n"
                f"SIZE: {result.get('file_size')} bytes\n"
                f"COMMAND: {result.get('command')}\n"
                f"OUTPUT:\n{result.get('output', '')[:1000]}"
            )
        return f"MSF_PAYLOAD_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_run_resource_script(script_content: str) -> str:
        """Create and run a Metasploit resource script in the persistent msfconsole. Resource scripts automate sequences of msfconsole commands. Use for: automated exploitation chains, mass scanning, post-exploitation workflows."""
        # Tool-layer scope gate: a resource script is free-text msfconsole
        # commands that can ``set RHOSTS <any host>; run``. Extract every
        # RHOSTS/RHOST value and refuse any host outside the allowlist.
        allowed, reason = check_targets_allowlist(_extract_msf_rhosts(script_content), config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_run_resource_script"
        bridge = _get_msf_bridge()
        result = bridge.run_resource_script(script_content)
        if result.get("success"):
            return f"MSF_RESOURCE_SCRIPT_EXECUTED\nOUTPUT:\n{result.get('output', '')[:2000]}"
        return f"MSF_RESOURCE_FAILED: {result.get('error', 'unknown error')}"

    # ── Phase 3: recipe dispatch + handler orchestration + post wrappers ──

    def _listener_cfg() -> dict[str, Any]:
        return ((config or {}).get("exploit", {}) or {}).get("msf", {}) or {}

    def _msf_enabled(key: str, default: bool = False) -> bool:
        return bool(_listener_cfg().get(key, default))

    @mcp.tool()
    @audit_tool
    def msf_run_recipe(name: str, target_ip: str = "", session_id: int = 0, options: str = "") -> str:
        """Run a named Metasploit recipe (curated module+option preset). Recipes: smb_version, bluekeep, psexec, cred_gather_win, local_exploit_suggester, hashdump, getsystem, handler. Pass target_ip for exploit/auxiliary kinds, session_id for post kinds, and extra key=value options to override the preset."""
        if not _msf_enabled("recipes_enabled", False):
            return f"BLOCKED: msf.recipes_enabled is disabled. Recipe: {name}"
        recipe = get_msf_recipe(name)
        if not recipe:
            return f"BLOCKED: unknown MSF recipe {name!r}. Available: {', '.join(sorted(MSF_RECIPES))}"
        # Allowlist gate: target_ip (exploit/auxiliary) and any RHOSTS in options.
        dests: list[str] = [target_ip] if target_ip else []
        opts: dict[str, str] = {}
        if options.strip():
            for item in options.strip().split():
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
                    if k.upper() in ("RHOSTS", "RHOST"):
                        dests.append(v)
        allowed, reason = check_targets_allowlist(dests, config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_run_recipe\nRECIPE: {name}"
        bridge = _get_msf_bridge()
        result = bridge.run_recipe(name, target_ip, session_id, opts)
        if result.get("success"):
            return (
                f"MSF_RECIPE_RESULT: {name}\n"
                f"MODULE: {recipe['module']}\n"
                f"KIND: {recipe['kind']}\n"
                f"OUTPUT:\n{result.get('output', '')[:2000]}"
            )
        return f"MSF_RECIPE_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_start_handler(
        lhost: str, lport: int = 4444, payload: str = "windows/meterpreter/reverse_tcp", options: str = ""
    ) -> str:
        """Start exploit/multi/handler as a backgrounded job to catch a generated payload. lhost is the operator callback host (must be in allowed_targets). Pairs with msf_generate_payload: generate a reverse payload, then start a handler on the same LHOST/LPORT."""
        # Allowlist gate: lhost is the payload's callback host (operator box).
        allowed, reason = check_targets_allowlist([lhost], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_start_handler\nLHOST: {lhost}"
        bridge = _get_msf_bridge()
        opts: dict[str, str] = {}
        if options.strip():
            for item in options.strip().split():
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
        result = bridge.start_handler(lhost, lport, payload, opts)
        if result.get("success"):
            return (
                f"MSF_HANDLER_STARTED\n"
                f"LHOST: {lhost}\nLPORT: {lport}\nPAYLOAD: {payload}\n"
                f"OUTPUT:\n{result.get('output', '')[:1500]}"
            )
        return f"MSF_HANDLER_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_stop_handler() -> str:
        """Stop all backgrounded handler jobs in the persistent msfconsole (jobs -K)."""
        bridge = _get_msf_bridge()
        result = bridge.stop_handler()
        return (
            f"MSF_HANDLER_STOPPED\nSUCCESS: {result.get('success', False)}\nOUTPUT:\n{result.get('output', '')[:500]}"
        )

    def _post_module(session_id: int, module: str, label: str, options: str = "") -> str:
        """Shared runner for the meterpreter post wrappers."""
        if int(session_id or 0) <= 0:
            return f"BLOCKED: {label} requires a positive session_id."
        bridge = _get_msf_bridge()
        opts: dict[str, str] = {}
        if options.strip():
            for item in options.strip().split():
                if "=" in item:
                    k, v = item.split("=", 1)
                    opts[k] = v
        result = bridge.run_post_module(module, int(session_id), opts)
        if result.get("success"):
            return f"MSF_POST_RESULT: {label}\nSESSION: {session_id}\nOUTPUT:\n{result.get('output', '')[:2000]}"
        return f"MSF_POST_FAILED: {result.get('error', 'unknown error')}"

    @mcp.tool()
    @audit_tool
    def msf_post_hashdump(session_id: int) -> str:
        """Dump SAM hashes from a Windows meterpreter session (post/windows/gather/hashdump)."""
        return _post_module(session_id, "post/windows/gather/hashdump", "hashdump")

    @mcp.tool()
    @audit_tool
    def msf_post_getsystem(session_id: int) -> str:
        """Attempt SYSTEM elevation on a Windows meterpreter session (post/windows/escalate/getsystem)."""
        return _post_module(session_id, "post/windows/escalate/getsystem", "getsystem")

    @mcp.tool()
    @audit_tool
    def msf_post_portfwd(session_id: int, remote_host: str, remote_port: int, local_port: int = 0) -> str:
        """Forward a local port through a meterpreter session to a remote host (portfwd). remote_host must be in allowed_targets (the allowlist is the pivot lock)."""
        allowed, reason = check_targets_allowlist([remote_host], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_post_portfwd\nREMOTE: {remote_host}"
        lp = int(local_port or 0)
        return _post_module(
            session_id,
            "post/multi/manage/portfwd",
            "portfwd",
            f"remote_host={remote_host} remote_port={remote_port} local_port={lp}",
        )

    @mcp.tool()
    @audit_tool
    def msf_post_route(session_id: int, subnet: str) -> str:
        """Add a route through a meterpreter session to a target subnet (post/multi/manage/autoroute). The subnet's network address must be in allowed_targets (pivot lock)."""
        net = (subnet or "").split("/")[0].strip()
        allowed, reason = check_targets_allowlist([net], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: msf_post_route\nSUBNET: {subnet}"
        return _post_module(session_id, "post/multi/manage/autoroute", "route", f"subnet={subnet}")
