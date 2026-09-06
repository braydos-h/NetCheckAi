"""Workspace MCP tool registration."""

from __future__ import annotations

import base64 as _base64
import hashlib
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from tools.kernel.workspace import read_workspace
from tools.mcp_shared import _attempt_dir, _resolve_workspace_file
from tools.mcp_tools.registry import ToolContext, _platform_system, ps_quote
from tools.mcp_tools.terminal import _target_lock_block
from tools.validation_utils import validate_target_or_ip


def register_workspace_tools(mcp: Any, *, ctx: ToolContext) -> None:
    from tools.mcp_tools.sandbox_exec import run_argv_in_sandbox

    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @audit_tool
    def write_python_file(filename: str, code: str, binary: bool = False) -> str:
        """Write an AI-generated Python exploit script. The script receives the target IP as sys.argv[1] (bare positional), as --target <ip>, and via the ACTIVE_CHECK_TARGET env var. Read sys.argv[1] (simplest), or use argparse with parse_known_args() so the bare positional is not flagged as an unrecognized argument. Use only standard library imports (socket, ssl, http, json, etc.) or common pip packages. Pass a bare .py name to save into the workspace, or an absolute path to write anywhere on the operator box (LAB BUILD: unrestricted).

        With binary=True, ``code`` is a base64 payload and the file is written as raw bytes (no shell interpolation, no UTF-8 re-encoding). Use this to materialize a private key / PEM / binary blob that must be byte-exact -- then `chmod 600` it via run_exploit_terminal. Never paste keys through a shell heredoc."""
        if not filename or not filename.strip():
            return "BLOCKED: empty filename."
        if not code or not code.strip():
            return "BLOCKED: empty code."
        # LAB BUILD: operator-box filesystem is unrestricted -- arbitrary
        # filenames/paths/sizes and any code content (destructive/dynamic
        # included) are accepted. An absolute path writes anywhere on the
        # operator box; a bare/relative name writes into the attempt dir. The
        # operator box is a throwaway lab VM.
        raw_name = str(filename).strip().replace("\\", "/").strip("'\"")
        attempt_dir, attempt_id = _attempt_dir(workspace)
        raw_path = Path(raw_name) if raw_name else None
        if raw_path and raw_path.is_absolute():
            script_path = raw_path
        else:
            script_path = attempt_dir / (raw_path.name if raw_path else "")
        script_path.parent.mkdir(parents=True, exist_ok=True)

        if binary:
            # Byte-exact channel for key/PEM/binary materialization. base64 is
            # the safe wire format for arbitrary bytes through the MCP JSON
            # schema (which is str-typed); a non-base64 / non-UTF-8 key pasted
            # as text would be corrupted by write_text (libcrypto "no start
            # line"). Validate strictly so a malformed payload fails loudly
            # instead of silently writing garbage.
            try:
                payload = _base64.b64decode(code, validate=True)
            except (ValueError, TypeError) as exc:
                return f"BLOCKED: binary=True requires valid base64 ({exc})."
            script_path.write_bytes(payload)
            code_sha = hashlib.sha256(payload).hexdigest()
            size_note = f"SIZE: {len(payload)} bytes"
            mode_note = "binary"
        else:
            script_path.write_text(code, encoding="utf-8")
            code_sha = hashlib.sha256(code.encode("utf-8")).hexdigest()
            size_note = f"SIZE: {len(code)} chars"
            mode_note = "text"

        return (
            f"PYTHON_FILE_WRITTEN: {script_path.name}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"PATH: {script_path}\n"
            f"MODE: {mode_note}\n"
            f"SHA256: {code_sha}\n"
            f"{size_note}\n"
        )

    @mcp.tool()
    @require_allowlist()
    def run_python_file(target_ip: str, filename: str) -> str:
        """Execute a previously written Python exploit script against the target IP. The script is searched across the entire workspace (all subdirectories) by filename, so you do not need to know the exact path. The script runs in a visible terminal window. Pass the target IP to attack. The IP is passed as sys.argv[1] (bare positional) AND as --target <ip> AND via the ACTIVE_CHECK_TARGET env var; scripts should read sys.argv[1] or use argparse parse_known_args()."""
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        # M4: validate the target IP before it is interpolated into the
        # PowerShell WindowTitle / env / argv -- a crafted target_ip could
        # inject into the .ps1 wrapper otherwise.
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP address or domain."
        cleaned = str(filename).strip().replace("\\", "/").split("/")[-1]
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}\.py", cleaned):
            return "BLOCKED: invalid filename."

        attempt_dir, attempt_id = _attempt_dir(workspace)
        # Search the entire workspace (including subdirectories) for the script
        script_path = _resolve_workspace_file(workspace, cleaned, suffix=".py")
        if not script_path.exists() or not script_path.is_file():
            return f"FILE_NOT_FOUND: {cleaned} not found in workspace {workspace}."

        # Copy script into current attempt dir so it runs from a known location
        local_script = attempt_dir / cleaned
        if script_path != local_script:
            import shutil

            shutil.copy2(str(script_path), str(local_script))
            script_path = local_script

        # Tool-layer target lock: the script body is executed verbatim, so a
        # literal-IP pivot to another host (e.g. socket.connect(("10.0.0.99",
        # 4444)) or os.system("nc <other_ip>")) must be gated the same way
        # run_exploit_terminal gates shell commands -- otherwise run_python_file
        # is a trivial bypass of the target-IP lock.
        # ponytail: static body scan, same ceiling as terminal._target_lock_block
        # -- catches literal IPs/URLs; a dynamically-constructed or DNS-resolved
        # destination is not caught (raise via allowed_targets or accept the gap).
        # Scanner-verb extraction is off here: that argv heuristic is built for
        # shell, and on Python source it misfires (an "nmap -sV" mention in a
        # comment plus "s.settimeout(...)" blocks the script as "Target
        # s.settimeout is not in the explicit allowlist").
        try:
            _body = script_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            _body = ""
        _block = _target_lock_block(_body, config, allow_empty=True, include_scanner_targets=False)
        if _block:
            return f"BLOCKED: {_block}\nTOOL: run_python_file\nSCRIPT: {cleaned}"

        log_path = attempt_dir / "python_run.log"

        # ---- sandbox path (fail closed): AI-generated Python NEVER runs in the
        # operator's interpreter when the sandbox is enabled -- it is executed
        # by the python3 inside the disposable worker, from the same
        # attempt-dir copy under /workspace. Host execution is not a fallback.
        if getattr(ctx, "sandbox", None) is not None:
            from tools.mcp_tools.sandbox_exec import sandbox_error_block
            from tools.sandbox.exceptions import SandboxError

            sandbox = ctx.sandbox
            try:
                container_script = sandbox.container_path(attempt_dir / cleaned)
                container_cwd = sandbox.container_path(attempt_dir)
            except SandboxError as exc:
                return f"BLOCKED: {exc}\nTOOL: run_python_file"
            _argv = [
                "python3",
                container_script,
                str(target_ip),
                "--target",
                str(target_ip),
            ]
            start = time.monotonic()
            try:
                _ran, result = run_argv_in_sandbox(
                    ctx,
                    _argv,
                    target_ip=str(target_ip),
                    timeout=300,
                    cwd_host=attempt_dir,
                    tool_name="run_python_file",
                )
            except SandboxError as exc:
                return f"PYTHON_RUN_RESULT: blocked\n{sandbox_error_block(exc, tool_name='run_python_file')}"
            merged = result.stdout or ""
            if result.stderr:
                merged = f"{merged}\n{result.stderr}" if merged else result.stderr
            text = (
                f"COMMAND: {' '.join(_argv)}\n"
                + merged
                + f"\nEXIT_CODE: {result.exit_code if result.exit_code is not None else 'timed_out'}\n"
            )
            log_path.write_text(text, encoding="utf-8", errors="replace")
            return (
                f"PYTHON_RUN_RESULT: {result.status} (exit_code={result.exit_code}, duration={result.duration_seconds:.1f}s, sandbox)\n"
                f"ATTEMPT_ID: {attempt_id}\n"
                f"SCRIPT: {script_path}\n"
                f"TARGET: {target_ip}\n"
                f"LOG_TAIL:\n{merged[-3000:]}"
            )

        # Pass the target IP as BOTH a bare positional (argv[1]) AND --target <ip>.
        # The attack-module templates the AI copies (network_smb/web/auth_creds)
        # and the orchestrator's `python <path> <ip>` dispatch read sys.argv[1]
        # as the bare IP; synthesis-style scripts use argparse --target. Reading
        # sys.argv[1] always works; an argparse script should use
        # parse_known_args() (or an optional positional) so the bare IP is not
        # flagged as an unrecognized argument.
        argv = [sys.executable, str(script_path), str(target_ip), "--target", str(target_ip)]
        env = os.environ.copy()
        env["ACTIVE_CHECK_TARGET"] = str(target_ip)
        env["EXPLOIT_WORKSPACE"] = str(attempt_dir)

        start = time.monotonic()
        if _platform_system() == "Windows":
            wrapper = attempt_dir / "run_python.ps1"
            exe = ps_quote(argv[0])
            args = ", ".join(ps_quote(a) for a in argv[1:])
            wrapper.write_text(
                "\n".join(
                    [
                        "$ErrorActionPreference = 'Continue'",
                        f"$Host.UI.RawUI.WindowTitle = {ps_quote('AI Exploit Python: ' + str(target_ip))}",
                        f"Set-Location -LiteralPath {ps_quote(str(attempt_dir))}",
                        f"$args = @({args})",
                        f"& {exe} @args 2>&1 | Tee-Object -FilePath {ps_quote(str(log_path))}",
                    ]
                ),
                encoding="utf-8",
            )
            proc = subprocess.Popen(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(wrapper)],
                cwd=str(attempt_dir),
                env=env,
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
            timeout = 300
            try:
                exit_code = proc.wait(timeout=timeout)
                status = "completed" if exit_code == 0 else "failed"
            except subprocess.TimeoutExpired:
                proc.kill()
                exit_code = None
                status = "timed_out"
        else:
            with open(str(log_path), "w") as fh:
                proc = subprocess.Popen(
                    argv,
                    cwd=str(attempt_dir),
                    env=env,
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                timeout = 300
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
            log_tail = text[-3000:]

        from tools.mcp_tools.sandbox_exec import sandbox_fallback_notice

        return (
            f"{sandbox_fallback_notice(ctx)}"
            f"PYTHON_RUN_RESULT: {status} (exit_code={exit_code}, duration={elapsed:.1f}s)\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"SCRIPT: {script_path}\n"
            f"TARGET: {target_ip}\n"
            f"LOG_TAIL:\n{log_tail}"
        )

    @mcp.tool()
    @audit_tool
    def read_workspace_file(filename: str) -> str:
        """Read a file inside the run workspace by path. Absolute paths escaping the workspace are refused (fail closed); relative names resolve under the workspace."""
        return read_workspace(workspace, filename)

    @mcp.tool()
    @audit_tool
    def list_workspace() -> str:
        """List all files in the exploit workspace directory (LAB BUILD: nothing is hidden)."""
        workspace.mkdir(parents=True, exist_ok=True)
        ws = workspace.resolve()
        # LAB BUILD: operator-box filesystem is unrestricted; the
        # credentials/ subtree is no longer hidden.
        entries: list[Path] = []
        MAX_ENTRIES = 5000
        try:
            for root, dirnames, filenames in os.walk(ws, followlinks=False):
                root_path = Path(root)
                for name in dirnames + filenames:
                    entries.append(root_path / name)
                    if len(entries) >= MAX_ENTRIES:
                        break
                if len(entries) >= MAX_ENTRIES:
                    break
        except OSError:
            pass
        files = sorted(
            entries,
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
            reverse=True,
        )
        if not files:
            return "WORKSPACE: empty."
        lines = ["WORKSPACE:", ""]
        for f in files[:50]:
            if f.is_file():
                size = f.stat().st_size if f.exists() else 0
                mtime = datetime.fromtimestamp(f.stat().st_mtime if f.exists() else 0).isoformat()
                rel = f.relative_to(ws)
                lines.append(f"  {rel} ({size} bytes, modified {mtime})")
            elif f.is_dir():
                rel = f.relative_to(ws)
                lines.append(f"  {rel}/ (directory)")
        return "\n".join(lines)
