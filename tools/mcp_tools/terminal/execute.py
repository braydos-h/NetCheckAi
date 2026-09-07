"""Execution tools for terminal MCP (run_exploit_terminal, run_as_root, git_clone).

Family: interactive shell funnel + privileged exec + repo fetch.

Tool-type classification (gates):
- ``run_exploit_terminal`` -- command-content, no ``target_ip`` param:
  ``@audit_tool`` + MANUAL ``_target_lock_block`` on the FULL sanitized
  command (RULE-LOCK-FIRST: the gate sees every destination; only display
  OUTPUT tails are truncated, with a ``[truncated]`` marker).
- ``run_as_root`` -- command-content, no ``target_ip`` param: ``@audit_tool``
  + preflight check + MANUAL ``_target_lock_block`` on the FULL sanitized
  command (fires BEFORE the sudo pivot) + ``_require_sudo_or_pivot``.
- ``git_clone`` -- local-only (no ``target_ip`` param, no target touch):
  ``@audit_tool`` ONLY, never an allowlist. URL format gate + existence
  preflight (advisory warning, never blocks) + workspace containment.

Intentional shell paths (preserved, never extended): the host
``run_exploit_terminal`` path runs the FULL sanitized command through a
wrapper script (``run_exploit.sh`` / ``run_exploit.cmd``) so ``&&`` chaining,
pipes, and redirects keep working; ``run_as_root`` runs
``bash -c "sudo <command> 2>&1"``. No other tool in this family uses a shell
(``git_clone`` host path is a pure argv list). Secrets are never capped
(RULE-NO-CAP-SECRETS): the only size bound on commands is an MB-scale
anti-fill cap; persisted logs AND live results (COMMAND_*/OUTPUT) are
secret-masked before return/emit. Cracking workflows recover plaintext via
the ``run_hash_crack`` tool result, not by scraping terminal output.
"""

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

from tools.kernel.audit import _mask_secret_content
from tools.mcp_shared import _is_inside_workspace
from tools.mcp_tools.registry import ToolContext, _attempt_dir, _positive_int, _run_with_pgrp_timeout
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

# MB-scale anti-fill ONLY (per RULE-NO-CAP-SECRETS): commands carrying
# code/passwords/PEM/base64 are never capped small; this just stops a runaway
# write from filling the operator disk or blowing past ARG_MAX.
_MAX_COMMAND_CHARS = 10 * 1024 * 1024
# Display OUTPUT tails (live result) + persisted-log bound (terminal.log).
_OUTPUT_CHARS = 4000
_GIT_OUTPUT_CHARS = 3000
_MAX_LOG_FILE_CHARS = 200_000


def _tail(text: Any, limit: int) -> str:
    """Last ``limit`` chars of ``text`` with a ``[truncated]`` marker when cut.

    Args:
        text: Raw output (None-safe, stringified).
        limit: Max chars to show (tail).

    Returns:
        Full text when short, else a ``[truncated ...]`` header + last
        ``limit`` chars. Gates always saw the FULL text; only display is cut.

    Gates:
        None (pure display helper).

    Side-effects:
        None.
    """
    body = str(text or "")
    if len(body) <= limit:
        return body
    return f"[truncated - showing last {limit} of {len(body)} chars]\n{body[-limit:]}"


def _config_timeout(config: Any, default: int = 300) -> int:
    """Host/sandbox run timeout from ``exploit.command_timeout_seconds``.

    Args:
        config: Full config dict (reads the ``exploit`` block).
        default: Fallback seconds when the key is missing/invalid.

    Returns:
        Positive-int seconds (validated via ``_positive_int``).

    Gates:
        None (reads config; validation falls back, never raises).

    Side-effects:
        None.
    """
    try:
        raw = (config or {}).get("exploit", {}).get("command_timeout_seconds", default)
    except (AttributeError, TypeError):
        return default
    return _positive_int(raw, default)


def _sandbox_terminal_ok(result: Any) -> tuple[str, str, int | None, float]:
    """(status, output_tail, exit_code, duration) from a contained SandboxResult.

    Args:
        result: Sandbox result with ``stdout`` / ``stderr`` / ``status`` /
            ``exit_code`` / ``duration_seconds``.

    Returns:
        Tuple of status, raw OUTPUT tail (marked when trimmed -- callers
        mask with ``_mask_secret_content`` before return), exit code, and
        duration.

    Gates:
        None (renders the contained execution -- the sandbox already gated).

    Side-effects:
        None.
    """
    merged = result.stdout or ""
    if result.stderr:
        merged = f"{merged}\n{result.stderr}" if merged else result.stderr
    return result.status, _tail(merged, _OUTPUT_CHARS), result.exit_code, result.duration_seconds


def _sandbox_status_line(manager: Any) -> str:
    """One-line sandbox identity for the result block (advisory, never blocks).

    Args:
        manager: Session sandbox manager (``status()`` dict).

    Returns:
        ``SANDBOX:`` line, or a bare fallback when the probe fails.

    Gates:
        None (advisory only).

    Side-effects:
        None.
    """
    try:
        st = manager.status()
        return (
            f"SANDBOX: run_id={st.get('run_id', '')} container={st.get('container_id', '')[:12]} "
            f"network_locked={st.get('network_locked', False)} image={st.get('image', '')}\n"
        )
    except Exception:  # ponytail: bare except intentional -- status is advisory, never blocks the result
        return "SANDBOX: active\n"


def _platform_system() -> str:
    """Operator OS name (Windows vs platform.system()).

    Returns:
        ``"Windows"`` on operator Windows, else ``platform.system()``
        (``"Linux"`` fallback when the probe fails).

    Gates:
        None.

    Side-effects:
        None.
    """
    import platform

    if os.name == "nt":
        return "Windows"
    try:
        return platform.system()
    except Exception:  # ponytail: bare except intentional -- platform probe fallback only
        return "Linux"


def _register_execute_tools(mcp: Any, *, ctx: ToolContext) -> None:
    """Register the terminal execution family on ``mcp``.

    Args:
        mcp: The MCP server to register tools on.
        ctx: ToolContext (workspace + config + audit_tool used here; sandbox
            selects the contained vs legacy host path per call).

    Returns:
        None.

    Gates:
        Per-tool gates inside each body (see family docstring).

    Side-effects:
        Registers ``run_exploit_terminal`` / ``run_as_root`` / ``git_clone``.
    """
    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool

    @mcp.tool()
    @audit_tool
    def run_exploit_terminal(command: str) -> str:
        """Run any shell command in a dedicated visible terminal window. The command executes synchronously; output is captured and RETURNED in the result under an OUTPUT: section. Use for running Kali tools, nmap, curl, netcat, searchsploit, etc. IMPORTANT: for long scans (nmap -sV), redirect output to a file with -oN scan.txt so you can read it later with read_workspace_file.

        Args:
            command: Full shell command text (never truncated before the gate;
                an MB-scale anti-fill cap is the only size bound, so
                code/passwords/PEM/base64 are never capped small).

        Returns:
            TERMINAL_RESULT block (status, exit code, duration, attempt id,
            original + sanitized command, OUTPUT tail) or a preflight /
            target-lock BLOCKED TERMINAL_RESULT.

        Gates:
            Empty/MB-cap pre-gates; ``preflight_command_check`` (sanitizes IP
            typos, never blocks except empty); MANUAL ``_target_lock_block``
            on the FULL sanitized command (RULE-LOCK-FIRST -- fail closed when
            ``require_explicit_allowlist`` is enforced).

        Side-effects:
            Executes the sanitized command (sandbox worker when enabled, fail
            closed -- else the host wrapper-script shell funnel, preserving
            ``&&`` chaining/pipes/redirects); writes terminal.log
            (secret-masked, capped). Live COMMAND_*/OUTPUT in the returned
            block are secret-masked before return/emit.
        """
        if not command or not command.strip():
            return "BLOCKED: empty command."
        if len(command) > _MAX_COMMAND_CHARS:
            return f"BLOCKED: command exceeds the {_MAX_COMMAND_CHARS}-byte anti-fill cap; split the command."

        original_command = command
        preflight = preflight_command_check(command)
        if not preflight["valid"]:
            return (
                "TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                "ATTEMPT_ID: preflight\n"
                f"COMMAND_ORIGINAL: {_mask_secret_content(original_command)}\n"
                f"COMMAND_SANITIZED: {_mask_secret_content(preflight['sanitized_command'])}\n"
                f"BLOCKED_REASON: {preflight['blocked_reason']}"
            )

        sanitized_command = preflight["sanitized_command"]
        corrections = preflight["corrections"]
        # Live-result display values: secrets are masked BEFORE return/emit
        # (the raw commands above still drive execution + the lock gate).
        shown_original = _mask_secret_content(original_command)
        shown_sanitized = _mask_secret_content(sanitized_command)

        # RULE-LOCK-FIRST: the gate sees the FULL sanitized command -- never a
        # truncated prefix (an off-target host past any display cap must block).
        _lock_reason = _target_lock_block(sanitized_command, config)
        if _lock_reason:
            return (
                "TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                "ATTEMPT_ID: preflight\n"
                f"COMMAND_ORIGINAL: {shown_original}\n"
                f"COMMAND_SANITIZED: {shown_sanitized}\n"
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
        timeout = _config_timeout(config)

        # ---- sandbox path (fail closed): when the disposable execution
        # sandbox is enabled, the command runs inside the hardened worker
        # container -- NEVER on the host. Any sandbox failure returns a
        # SANDBOX_* block instead of falling back to host execution.
        if getattr(ctx, "sandbox", None) is not None:
            _opsec_advisory = _opsec_advisory_block(sanitized_command, config)
            try:
                _ran, result = run_command_in_sandbox(
                    ctx, sanitized_command, timeout=timeout, cwd_host=attempt_dir, tool_name="run_exploit_terminal"
                )
            except SandboxError as exc:
                return (
                    "TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\n"
                    f"ATTEMPT_ID: {attempt_id}\n"
                    f"COMMAND_ORIGINAL: {shown_original}\n"
                    f"COMMAND_SANITIZED: {shown_sanitized}\n"
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
            # Persisted AND live outputs are masked: raw stdout may carry
            # dumped hashes, tokens, or key material that must neither sit on
            # disk nor echo verbatim in results/events in the clear.
            _logged = _mask_secret_content((result.stdout or "") + ("\n" + result.stderr if result.stderr else ""))
            log_path.write_text(
                f"{'=' * 60}\nCOMMAND: {_mask_secret_content(sanitized_command)}\n{'=' * 60}\n"
                + _tail(_logged, _MAX_LOG_FILE_CHARS)
                + f"\nEXIT_CODE: {_exit_code if _exit_code is not None else 'timed_out'}\n",
                encoding="utf-8",
                errors="replace",
            )
            return (
                f"TERMINAL_RESULT: {_sstatus} (exit_code={_exit_code}, duration={_elapsed:.1f}s)\n"
                f"ATTEMPT_ID: {attempt_id}\n"
                f"COMMAND_ORIGINAL: {shown_original}\n"
                f"COMMAND_SANITIZED: {shown_sanitized}\n"
                f"{preflight_note}"
                f"{_sandbox_status_line(ctx.sandbox)}"
                f"{_opsec_advisory}"
                f"{_hint}"
                f"WORKSPACE: {attempt_dir}\n"
                f"OUTPUT:\n{_mask_secret_content(_output_tail)}"
            )

        start = time.monotonic()
        is_windows = _platform_system() == "Windows"
        header = f"{'=' * 60}\nCOMMAND: {_mask_secret_content(sanitized_command)}\n{'=' * 60}\n"
        log_path.write_text(header, encoding="utf-8", errors="replace")

        _bash_on_windows = _find_windows_bash(config) if is_windows else None
        if is_windows and _bash_on_windows is None:
            wrapper = attempt_dir / "run_exploit.cmd"
            wrapper.write_text(
                "@echo off\r\n"
                "title AI Exploit Terminal\r\n"
                f'cd /d "{attempt_dir}"\r\n'
                f"{sanitized_command} >> terminal.log 2>&1\r\n"
                "echo EXIT_CODE: %ERRORLEVEL% >> terminal.log\r\n",
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
                except Exception:  # ponytail: bare except intentional -- post-kill drain is best-effort
                    out_bytes = out_bytes or b""
            exit_code = None
            status = "timed_out"

        elapsed = time.monotonic() - start
        output_tail = ""
        if out_bytes is not None:
            try:
                text = out_bytes.decode("utf-8", errors="replace") if isinstance(out_bytes, bytes) else str(out_bytes)
                log_path.write_text(
                    header + _tail(_mask_secret_content(text), _MAX_LOG_FILE_CHARS),
                    encoding="utf-8",
                    errors="replace",
                )
                # Live OUTPUT is masked before return (same as the persisted
                # log above) -- secrets must not echo verbatim in results.
                output_tail = _mask_secret_content(_tail(text, _OUTPUT_CHARS))
            except Exception:  # ponytail: bare except intentional -- decode failure keeps prior (empty) tail
                pass
        elif log_path.exists():
            # cmd.exe path appends raw output to terminal.log via shell
            # redirect: mask before return, then mask the persisted copy.
            raw_text = log_path.read_text(encoding="utf-8", errors="replace")
            output_tail = _mask_secret_content(_tail(raw_text, _OUTPUT_CHARS))
            try:
                log_path.write_text(
                    _tail(_mask_secret_content(raw_text), _MAX_LOG_FILE_CHARS),
                    encoding="utf-8",
                    errors="replace",
                )
            except OSError:
                pass

        _opsec_advisory = _opsec_advisory_block(sanitized_command, config)

        return (
            f"TERMINAL_RESULT: {status} (exit_code={exit_code}, duration={elapsed:.1f}s)\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"COMMAND_ORIGINAL: {shown_original}\n"
            f"COMMAND_SANITIZED: {shown_sanitized}\n"
            f"{preflight_note}"
            f"{sandbox_fallback_notice(ctx)}"
            f"{_opsec_advisory}"
            f"WORKSPACE: {attempt_dir}\n"
            f"OUTPUT:\n{output_tail}"
        )

    @mcp.tool()
    @audit_tool
    def run_as_root(command: str) -> str:
        """Run ANY command with sudo (root privileges). Use for commands that require root: tcpdump, iptables, systemctl, writing to /etc, raw socket operations, etc. The command runs synchronously and output is captured.

        Args:
            command: Full shell command text (never truncated before the gate;
                an MB-scale anti-fill cap is the only size bound).

        Returns:
            ROOT_CMD_RESULT block (status, exit code, command, OUTPUT tail),
            or a preflight / target-lock / sudo-pivot block.

        Gates:
            Empty/MB-cap pre-gates; ``preflight_command_check`` (sanitizes IP
            typos); MANUAL ``_target_lock_block`` on the FULL sanitized
            command -- fires BEFORE the sudo pivot (RULE-LOCK-FIRST); then
            ``_require_sudo_or_pivot`` short-circuits when passwordless sudo
            is unavailable.

        Side-effects:
            Executes ``sudo <sanitized-command>`` (container root when
            sandboxed, fail closed -- else host ``bash -c``, preserving
            ``&&`` chaining). Live COMMAND/OUTPUT in the returned block are
            secret-masked before return/emit.
        """
        if not command or not command.strip():
            return "BLOCKED: empty command."
        if len(command) > _MAX_COMMAND_CHARS:
            return f"BLOCKED: command exceeds the {_MAX_COMMAND_CHARS}-byte anti-fill cap; split the command."
        original_command = command
        preflight = preflight_command_check(command)
        if not preflight["valid"]:
            return (
                f"ROOT_CMD_RESULT: blocked (preflight: {preflight['blocked_reason']})\n"
                f"COMMAND: {_mask_secret_content(original_command)}"
            )
        sanitized_command = preflight["sanitized_command"]
        # Live-result display value: masked before return (raw drives execution).
        shown_command = _mask_secret_content(original_command)
        # RULE-LOCK-FIRST: lock on the FULL sanitized command, before the sudo
        # pivot, so an off-target command reports the lock (not the pivot).
        _lock_reason = _target_lock_block(sanitized_command, config)
        if _lock_reason:
            return f"ROOT_CMD_RESULT: blocked (target lock: {_lock_reason})"
        _pivot = _require_sudo_or_pivot("run_as_root", sanitized_command)
        if _pivot:
            return _pivot
        timeout = _config_timeout(config)
        # ---- sandbox path: root INSIDE the disposable worker (confined by
        # --cap-drop ALL / no devices / netns firewall / workspace-only bind);
        # host root is never involved.
        if getattr(ctx, "sandbox", None) is not None:
            try:
                _ran, result = run_command_in_sandbox(
                    ctx, sanitized_command, timeout=timeout, tool_name="run_as_root", user="root"
                )
            except SandboxError as exc:
                return f"ROOT_CMD_RESULT: blocked\n{sandbox_error_block(exc, tool_name='run_as_root')}"
            merged = result.stdout or ""
            if result.stderr:
                merged = f"{merged}\n{result.stderr}" if merged else result.stderr
            return (
                f"ROOT_CMD_RESULT: {result.status} (exit_code={result.exit_code}, sandbox)\n"
                f"COMMAND: {shown_command}\nSUDO: not required (executed as container root)\n"
                f"OUTPUT:\n{_mask_secret_content(_tail(merged, _OUTPUT_CHARS))}"
            )
        cmd = f"sudo {sanitized_command} 2>&1"
        try:
            returncode, out, err = _run_with_pgrp_timeout(
                ["bash", "-c", cmd],
                timeout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output = _mask_secret_content(_tail(((out or "") + "\n" + (err or "")), _OUTPUT_CHARS))
            status = "completed" if returncode == 0 else "failed"
            return (
                f"{sandbox_fallback_notice(ctx)}"
                f"ROOT_CMD_RESULT: {status} (exit_code={returncode})\nCOMMAND: {shown_command}\nOUTPUT:\n{output}"
            )
        except subprocess.TimeoutExpired:
            return f"{sandbox_fallback_notice(ctx)}ROOT_CMD_RESULT: timed_out\nCOMMAND: {shown_command}"
        except Exception as exc:  # ponytail: bare except intentional -- run failure is data, not a crash
            return f"{sandbox_fallback_notice(ctx)}ROOT_CMD_RESULT: error - {exc}"

    @mcp.tool()
    @audit_tool
    def git_clone(repo_url: str, target_dir: str = "") -> str:
        """Clone a Git repository (GitHub exploit/PoC/tool) into the workspace. Provide the full repo URL (e.g., 'https://github.com/user/repo.git'). Optional target_dir for a custom folder name.

        Args:
            repo_url: Full HTTPS repo URL (format-gated to https Git URLs).
            target_dir: Optional custom folder name ([A-Za-z0-9._-]{1,80}).

        Returns:
            GIT_CLONE_RESULT block (status, exit code, repo, path, OUTPUT
            tail), BLOCKED on gate failure, or a PREFLIGHT_WARNING prefix when
            the URL existence check fails (advisory -- the clone still runs).

        Gates:
            Local-only ``@audit_tool`` (never an allowlist -- no target
            touch). URL format regex; ``target_dir`` charset/length;
            workspace containment (fail closed on escape).

        Side-effects:
            Clones via argv-list ``git clone`` (sandbox worker when enabled,
            else host ``_run_with_pgrp_timeout`` with the configured timeout);
            no shell anywhere on this path.
        """
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
        timeout = _config_timeout(config, 120)

        preflight_note = ""
        if url.lower().startswith(("http://", "https://")):
            try:
                from tools.exploit_search import url_exists as _url_exists_check

                _ok, _reason = _url_exists_check(url, timeout=8)
            except Exception:  # ponytail: bare except intentional -- existence check never blocks the clone
                _ok, _reason = True, None
            if not _ok:
                preflight_note = (
                    f"PREFLIGHT_WARNING: URL existence check failed ({_reason}); "
                    "if this is a private/auth-gated repo the clone may still "
                    "succeed. If the clone fails, use cve_to_poc instead of "
                    "guessing URLs.\n"
                )

        # ---- sandbox path: clone inside the worker (egress is governed by
        # the pinned RESEARCH_HOSTS set + the netns firewall, not by the host).
        if getattr(ctx, "sandbox", None) is not None:
            import shlex as _shlex

            _clone_cmd = f"git clone -- {_shlex.quote(url)} {_shlex.quote(dir_name)}"
            try:
                _ran, result = run_command_in_sandbox(
                    ctx, _clone_cmd, timeout=timeout, cwd_host=workspace, tool_name="git_clone"
                )
            except SandboxError as exc:
                return f"{preflight_note}GIT_CLONE_RESULT: blocked\n{sandbox_error_block(exc, tool_name='git_clone')}"
            merged = result.stdout or ""
            if result.stderr:
                merged = f"{merged}\n{result.stderr}" if merged else result.stderr
            return (
                f"{preflight_note}GIT_CLONE_RESULT: {result.status} (exit_code={result.exit_code}, sandbox)\n"
                f"REPO: {_mask_secret_content(url)}\nPATH: {clone_dir} (container: /workspace/{dir_name})\n"
                f"OUTPUT:\n{_mask_secret_content(_tail(merged, _GIT_OUTPUT_CHARS))}"
            )

        try:
            returncode, out, err = _run_with_pgrp_timeout(
                ["git", "clone", "--", url, str(clone_dir)],
                timeout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output = _mask_secret_content(_tail(((out or "") + "\n" + (err or "")), _GIT_OUTPUT_CHARS))
            status = "completed" if returncode == 0 else "failed"
            return (
                f"{preflight_note}{sandbox_fallback_notice(ctx)}GIT_CLONE_RESULT: {status} (exit_code={returncode})\n"
                f"REPO: {_mask_secret_content(url)}\nPATH: {clone_dir}\nOUTPUT:\n{output}"
            )
        except subprocess.TimeoutExpired:
            return (
                f"{preflight_note}{sandbox_fallback_notice(ctx)}GIT_CLONE_RESULT: timed_out\n"
                f"REPO: {_mask_secret_content(url)}"
            )
        except Exception as exc:  # ponytail: bare except intentional -- run failure is data, not a crash
            return f"{preflight_note}{sandbox_fallback_notice(ctx)}GIT_CLONE_RESULT: error - {exc}"
