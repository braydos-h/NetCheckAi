"""Execution tools for terminal MCP (run_exploit_terminal, run_as_root, git_clone)."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.kernel.audit import _mask_secret_content
from tools.mcp_shared import _is_inside_workspace
from tools.mcp_tools.registry import ToolContext, _attempt_dir, _run_with_pgrp_timeout
from tools.mcp_tools.sandbox_exec import (
    collect_command_targets,
    loopback_hint,
    run_argv_in_sandbox,
    run_command_in_sandbox,
    sandbox_error_block,
    sandbox_fallback_notice,
)
from tools.mcp_tools.terminal.allowlist import _opsec_advisory_block, _target_lock_block
from tools.mcp_tools.terminal.privilege import _find_windows_bash, _require_sudo_or_pivot
from tools.sandbox.exceptions import SandboxError
from tools.validation_utils import preflight_command_check

__all__ = ["_register_execute_tools"]


def _sandbox_terminal_ok(result: Any) -> tuple[str, str, int | None, float]:
    """(status, output_tail, exit_code, duration) from a contained SandboxResult."""
    merged = result.stdout or ""
    if result.stderr:
        merged = f"{merged}\n{result.stderr}" if merged else result.stderr
    tail = merged[-4000:]
    return result.status, tail, result.exit_code, result.duration_seconds


def _sandbox_status_line(manager: Any) -> str:
    try:
        st = manager.status()
        return (
            f"SANDBOX: run_id={st.get('run_id', '')} container={st.get('container_id', '')[:12]} "
            f"network_locked={st.get('network_locked', False)} image={st.get('image', '')}\n"
        )
    except Exception:  # ponytail: bare except intentional -- status is advisory, never blocks the result
        return "SANDBOX: active\n"


def _platform_system() -> str:
    import platform

    if os.name == "nt":
        return "Windows"
    try:
        return platform.system()
    except Exception:  # ponytail: bare except intentional -- platform probe fallback only
        return "Linux"


def _register_execute_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool

    @mcp.tool()
    @audit_tool
    def run_exploit_terminal(command: str) -> str:
        """Run any shell command in a dedicated visible terminal window. The command executes synchronously; output is captured and RETURNED in the result under an OUTPUT: section. Use for running Kali tools, nmap, curl, netcat, searchsploit, etc. IMPORTANT: for long scans (nmap -sV), redirect output to a file with -oN scan.txt so you can read it later with read_workspace_file."""
        if not command or not command.strip():
            return "BLOCKED: empty command."
        if len(command) > 4000:
            return "BLOCKED: command too long."

        original_command = command
        preflight = preflight_command_check(command)
        if not preflight["valid"]:
            return (
                f"TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                f"ATTEMPT_ID: preflight\n"
                f"COMMAND_ORIGINAL: {original_command}\n"
                f"COMMAND_SANITIZED: {preflight['sanitized_command']}\n"
                f"BLOCKED_REASON: {preflight['blocked_reason']}"
            )

        sanitized_command = preflight["sanitized_command"]
        corrections = preflight["corrections"]

        _lock_reason = _target_lock_block(sanitized_command, config)
        if _lock_reason:
            return (
                f"TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                f"ATTEMPT_ID: preflight\n"
                f"COMMAND_ORIGINAL: {original_command}\n"
                f"COMMAND_SANITIZED: {sanitized_command}\n"
                f"BLOCKED_REASON: {_lock_reason}"
            )

        missing_tools = preflight["missing_tools"]
        preflight_note = ""
        if missing_tools:
            preflight_note = f"PREFLIGHT_WARNING: Missing tools on PATH: {', '.join(missing_tools)}.\n"
        if corrections:
            preflight_note += f"PREFLIGHT_CORRECTIONS: {json.dumps(corrections)}\n"

        attempt_dir, attempt_id = _attempt_dir(workspace)
        log_path = attempt_dir / "terminal.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # ---- sandbox path (fail closed): when the disposable execution
        # sandbox is enabled, the command runs inside the hardened worker
        # container -- NEVER on the host. Any sandbox failure returns a
        # SANDBOX_* block instead of falling back to host execution.
        if getattr(ctx, "sandbox", None) is not None:
            _opsec_advisory = _opsec_advisory_block(sanitized_command, config)
            try:
                _ran, result = run_command_in_sandbox(
                    ctx, sanitized_command, timeout=300, cwd_host=attempt_dir, tool_name="run_exploit_terminal"
                )
            except SandboxError as exc:
                return (
                    f"TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                    f"ATTEMPT_ID: {attempt_id}\n"
                    f"COMMAND_ORIGINAL: {original_command}\n"
                    f"COMMAND_SANITIZED: {sanitized_command}\n"
                    f"{preflight_note}"
                    f"{sandbox_error_block(exc, tool_name='run_exploit_terminal')}"
                )
            _sstatus, _output_tail, _exit_code, _elapsed = _sandbox_terminal_ok(result)
            _hint = ""
            try:
                # ponytail: unconditional for loopback targets -- gating on output
                # substrings ("connection refused") misses curl/python/timeout
                # variants and exit-0-masked probes (cmd1; curl | head).
                _targets = collect_command_targets(sanitized_command)
                _primary = _targets[0] if _targets else ""
                if _primary:
                    _hint = loopback_hint(_primary, config)
            except Exception:  # ponytail: bare except intentional -- hint is advisory only
                _hint = ""
            # Persisted logs are redacted: raw stdout may carry dumped hashes,
            # tokens, or key material that must not sit on disk in the clear.
            # (The live OUTPUT below stays verbatim -- cracking workflows need
            # the recovered plaintext.)
            _logged = _mask_secret_content((result.stdout or "") + ("\n" + result.stderr if result.stderr else ""))
            log_path.write_text(
                f"{'=' * 60}\nCOMMAND: {_mask_secret_content(sanitized_command)}\n{'=' * 60}\n"
                + _logged
                + f"\nEXIT_CODE: {_exit_code if _exit_code is not None else 'timed_out'}\n",
                encoding="utf-8",
                errors="replace",
            )
            return (
                f"TERMINAL_RESULT: {_sstatus} (exit_code={_exit_code}, duration={_elapsed:.1f}s)\n"
                f"ATTEMPT_ID: {attempt_id}\n"
                f"COMMAND_ORIGINAL: {original_command}\n"
                f"COMMAND_SANITIZED: {sanitized_command}\n"
                f"{preflight_note}"
                f"{_sandbox_status_line(ctx.sandbox)}"
                f"{_opsec_advisory}"
                f"{_hint}"
                f"WORKSPACE: {attempt_dir}\n"
                f"OUTPUT:\n{_output_tail}"
            )

        start = time.monotonic()
        is_windows = _platform_system() == "Windows"
        header = f"{'=' * 60}\nCOMMAND: {_mask_secret_content(sanitized_command)}\n{'=' * 60}\n"
        log_path.write_text(header, encoding="utf-8", errors="replace")

        _bash_on_windows = _find_windows_bash(config) if is_windows else None
        if is_windows and _bash_on_windows is None:
            wrapper = attempt_dir / "run_exploit.cmd"
            wrapper.write_text(
                f"@echo off\r\n"
                f"title AI Exploit Terminal\r\n"
                f'cd /d "{attempt_dir}"\r\n'
                f"{sanitized_command} >> terminal.log 2>&1\r\n"
                f"echo EXIT_CODE: %ERRORLEVEL% >> terminal.log\r\n",
                encoding="ascii",
                errors="replace",
            )
            proc = subprocess.Popen(
                ["cmd.exe", "/c", str(wrapper)],
                cwd=str(attempt_dir),
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        else:
            if _bash_on_windows:
                _shell_bin = _bash_on_windows
            else:
                _shell = str((config or {}).get("exploit", {}).get("shell", "bash")) or "bash"
                _shell_bin = shutil.which(_shell) or _shell
            wrapper = attempt_dir / "run_exploit.sh"
            wrapper.write_text(
                f'#!{_shell_bin}\ncd "{attempt_dir}"\n{sanitized_command} 2>&1\necho EXIT_CODE: $?\n',
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            proc = subprocess.Popen(
                [_shell_bin, str(wrapper)],
                cwd=str(attempt_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        timeout = 300
        out_bytes: bytes | str | None = None
        try:
            if is_windows and _bash_on_windows is None:
                exit_code = proc.wait(timeout=timeout)
                status = "completed" if exit_code == 0 else "failed"
            else:
                out_bytes, _ = proc.communicate(timeout=timeout)
                exit_code = proc.returncode
                status = "completed" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired:
            if is_windows:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            else:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
            if not (is_windows and _bash_on_windows is None):
                try:
                    out_bytes, _ = proc.communicate(timeout=5)
                except _EXC_GROUP_CATCH:
                    out_bytes = out_bytes or b""
            exit_code = None
            status = "timed_out"

        elapsed = time.monotonic() - start
        output_tail = ""
        if out_bytes is not None:
            try:
                text = out_bytes.decode("utf-8", errors="replace") if isinstance(out_bytes, bytes) else str(out_bytes)
                log_path.write_text(header + _mask_secret_content(text), encoding="utf-8", errors="replace")
                output_tail = text[-4000:]
            except _EXC_GROUP_CATCH:
                pass
        elif log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="replace")
            output_tail = text[-4000:]

        _opsec_advisory = _opsec_advisory_block(sanitized_command, config)

        return (
            f"TERMINAL_RESULT: {status} (exit_code={exit_code}, duration={elapsed:.1f}s)\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"COMMAND_ORIGINAL: {original_command}\n"
            f"COMMAND_SANITIZED: {sanitized_command}\n"
            f"{preflight_note}"
            f"{sandbox_fallback_notice(ctx)}"
            f"{_opsec_advisory}"
            f"WORKSPACE: {attempt_dir}\n"
            f"OUTPUT:\n{output_tail}"
        )

    @mcp.tool()
    @audit_tool
    def run_as_root(command: str) -> str:
        """Run ANY command with sudo (root privileges). Use for commands that require root: tcpdump, iptables, systemctl, writing to /etc, raw socket operations, etc. The command runs synchronously and output is captured."""
        if not command or not command.strip():
            return "BLOCKED: empty command."
        if len(command) > 4000:
            return "BLOCKED: command too long."
        original_command = command
        _lock_reason = _target_lock_block(command, config)
        if _lock_reason:
            return f"ROOT_CMD_RESULT: blocked (target lock: {_lock_reason})"
        _pivot = _require_sudo_or_pivot("run_as_root", original_command)
        if _pivot:
            return _pivot
        # ---- sandbox path: root INSIDE the disposable worker (confined by
        # --cap-drop ALL / no devices / netns firewall / workspace-only bind);
        # host root is never involved.
        if getattr(ctx, "sandbox", None) is not None:
            try:
                _ran, result = run_command_in_sandbox(ctx, command, timeout=300, tool_name="run_as_root", user="root")
            except SandboxError as exc:
                return f"ROOT_CMD_RESULT: blocked\n{sandbox_error_block(exc, tool_name='run_as_root')}"
            merged = result.stdout or ""
            if result.stderr:
                merged = f"{merged}\n{result.stderr}" if merged else result.stderr
            return (
                f"ROOT_CMD_RESULT: {result.status} (exit_code={result.exit_code}, sandbox)\n"
                f"COMMAND: {original_command}\nSUDO: not required (executed as container root)\n"
                f"OUTPUT:\n{merged[-4000:]}"
            )
        cmd = f"sudo {command} 2>&1"
        try:
            returncode, out, err = _run_with_pgrp_timeout(
                ["bash", "-c", cmd],
                300,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output = (out + "\n" + err)[-4000:]
            status = "completed" if returncode == 0 else "failed"
            return (
                f"{sandbox_fallback_notice(ctx)}"
                f"ROOT_CMD_RESULT: {status} (exit_code={returncode})\nCOMMAND: {original_command}\nOUTPUT:\n{output}"
            )
        except subprocess.TimeoutExpired:
            return f"{sandbox_fallback_notice(ctx)}ROOT_CMD_RESULT: timed_out\nCOMMAND: {original_command}"
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"{sandbox_fallback_notice(ctx)}ROOT_CMD_RESULT: error - {exc}"

    @mcp.tool()
    @audit_tool
    def git_clone(repo_url: str, target_dir: str = "") -> str:
        """Clone a Git repository (GitHub exploit/PoC/tool) into the workspace. Provide the full repo URL (e.g., 'https://github.com/user/repo.git'). Optional target_dir for a custom folder name."""
        if not repo_url or not repo_url.strip():
            return "BLOCKED: repo_url is required."
        url = repo_url.strip()
        if not re.fullmatch(r"https?://[a-zA-Z0-9._/\-:@]+\.git", url) and not re.fullmatch(
            r"https?://github\.com/[a-zA-Z0-9._\-/]+", url
        ):
            return "BLOCKED: invalid repo URL. Must be a GitHub/GitLab HTTPS URL."
        dir_name = target_dir.strip() if target_dir.strip() else url.rstrip("/").split("/")[-1].replace(".git", "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", dir_name):
            return f"BLOCKED: target_dir must match [A-Za-z0-9._-]{{1,80}} (got {dir_name!r})."
        clone_dir = workspace / dir_name
        if not _is_inside_workspace(workspace, clone_dir.resolve()):
            return f"BLOCKED: clone target {clone_dir} escapes the exploit workspace."

        preflight_note = ""
        if url.lower().startswith(("http://", "https://")):
            try:
                from tools.exploit_search import url_exists as _url_exists_check

                _ok, _reason = _url_exists_check(url, timeout=8)
            except _EXC_GROUP_CATCH:
                _ok, _reason = True, None
            if not _ok:
                preflight_note = (
                    f"PREFLIGHT_WARNING: URL existence check failed ({_reason}); "
                    f"if this is a private/auth-gated repo the clone may still "
                    f"succeed. If the clone fails, use cve_to_poc instead of "
                    f"guessing URLs.\n"
                )

        # ---- sandbox path: clone inside the worker (egress is governed by
        # the pinned RESEARCH_HOSTS set + the netns firewall, not by the host).
        if getattr(ctx, "sandbox", None) is not None:
            import shlex as _shlex

            _clone_cmd = f"git clone -- {_shlex.quote(url)} {_shlex.quote(dir_name)}"
            try:
                _ran, result = run_command_in_sandbox(
                    ctx, _clone_cmd, timeout=120, cwd_host=workspace, tool_name="git_clone"
                )
            except SandboxError as exc:
                return f"{preflight_note}GIT_CLONE_RESULT: blocked\n{sandbox_error_block(exc, tool_name='git_clone')}"
            merged = result.stdout or ""
            if result.stderr:
                merged = f"{merged}\n{result.stderr}" if merged else result.stderr
            return (
                f"{preflight_note}GIT_CLONE_RESULT: {result.status} (exit_code={result.exit_code}, sandbox)\n"
                f"REPO: {url}\nPATH: {clone_dir} (container: /workspace/{dir_name})\n"
                f"OUTPUT:\n{merged[-3000:]}"
            )

        try:
            returncode, out, err = _run_with_pgrp_timeout(
                ["git", "clone", "--", url, str(clone_dir)],
                120,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output = (out + "\n" + err)[-3000:]
            status = "completed" if returncode == 0 else "failed"
            return (
                f"{preflight_note}{sandbox_fallback_notice(ctx)}GIT_CLONE_RESULT: {status} (exit_code={returncode})\n"
                f"REPO: {url}\nPATH: {clone_dir}\nOUTPUT:\n{output}"
            )
        except subprocess.TimeoutExpired:
            return f"{preflight_note}{sandbox_fallback_notice(ctx)}GIT_CLONE_RESULT: timed_out\nREPO: {url}"
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"{preflight_note}{sandbox_fallback_notice(ctx)}GIT_CLONE_RESULT: error - {exc}"
