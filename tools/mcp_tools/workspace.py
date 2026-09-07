"""Workspace MCP tool registration.

Family: workspace file I/O + AI-script execution.

Tool-type classification (gates):
- ``write_python_file`` -- local-only (no ``target_ip`` param): ``@audit_tool`` ONLY.
  LAB BUILD: operator-box writes stay unrestricted (any path/size/content); the ONLY
  bound is an MB-scale anti-fill cap. Never cap code/passwords/PEM/base64 small.
- ``run_python_file`` -- declarative ``target_ip`` param: ``@require_allowlist()`` on the
  structured target PLUS a manual ``_target_lock_block`` scan of the FULL script body
  (stored code executes verbatim, so without the body scan it would be a trivial pivot
  bypass) PLUS a runtime socket-egress guard (``egress_guard`` preamble wraps
  ``socket.connect``/``create_connection`` in the child, so argv/concat/decode-built
  destinations are denied at connect time however they were constructed).
  Scanner-verb extraction stays OFF for Python source (shell argv heuristic
  misfires on ``.py``). The gate always sees the full body; only display OUTPUT tails
  are truncated (with a ``[truncated]`` marker).
- ``read_workspace_file`` / ``list_workspace`` -- local-only: ``@audit_tool`` ONLY, never
  an allowlist. ``list_workspace`` caps the walk and redacts the ``credentials/`` subtree
  (count shown, names hidden); ``read_workspace_file`` stays workspace-contained via the
  kernel helper (120k chars with ``[truncated]`` marker).
"""

from __future__ import annotations

import base64 as _base64
import hashlib
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from tools.kernel.allowlist import _allowed_target_list
from tools.kernel.audit import _mask_secret_content
from tools.kernel.workspace import read_workspace
from tools.mcp_shared import _attempt_dir, _resolve_workspace_file
from tools.mcp_tools.egress_guard import build_egress_preamble, egress_denied_in_output
from tools.mcp_tools.registry import ToolContext, run_argv_captured
from tools.mcp_tools.terminal import _target_lock_block
from tools.validation_utils import validate_target_or_ip

# MB-scale anti-fill ONLY (per RULE-NO-CAP-SECRETS): secrets/code/PEM/base64 are never
# capped small; this just stops a runaway write from filling the operator disk.
_MAX_WRITE_BYTES = 10 * 1024 * 1024
# Host capture bound (pre-tail) -> display tail -> persisted-log bound.
_CAPTURE_CHARS = 65536
_LOG_TAIL_CHARS = 3000
_MAX_LOG_FILE_CHARS = 200_000
# Walk/listing bounds for list_workspace.
_MAX_WALK_ENTRIES = 5000
_MAX_LIST_SHOWN = 50


def _positive_timeout(value: Any, default: int) -> int:
    """Positive-int timeout from config (fallback ``default`` when missing/invalid)."""
    if isinstance(value, bool):
        return default
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return default
    return ivalue if ivalue > 0 else default


def _config_timeout(config: Any, default: int = 300) -> int:
    """Host-run timeout from ``exploit.command_timeout_seconds`` (validated positive int)."""
    try:
        raw = (config or {}).get("exploit", {}).get("command_timeout_seconds", default)
    except (AttributeError, TypeError):
        return default
    return _positive_timeout(raw, default)


def _tail(text: str, limit: int) -> str:
    """Last ``limit`` chars of ``text`` with a ``[truncated]`` marker when cut.

    Display OUTPUT tails only -- gates always see the full input.
    """
    body = str(text or "")
    if len(body) <= limit:
        return body
    return f"[truncated - showing last {limit} of {len(body)} chars]\n{body[-limit:]}"


def _format_python_result(
    *,
    status: str,
    exit_code: int | None,
    duration_s: float,
    attempt_id: str,
    script_path: Path,
    target_ip: str,
    log_tail: str,
    sandbox_mode: bool,
    hint: str = "",
    fallback_notice: str = "",
) -> str:
    """Single PYTHON_RUN_RESULT formatter shared by the sandbox and host paths."""
    suffix = ", sandbox)" if sandbox_mode else ")"
    head = f"PYTHON_RUN_RESULT: {status} (exit_code={exit_code}, duration={duration_s:.1f}s{suffix}"
    parts: list[str] = []
    if fallback_notice.strip():
        parts.append(fallback_notice.rstrip("\n"))
    parts.extend(
        [
            head,
            f"ATTEMPT_ID: {attempt_id}",
            f"SCRIPT: {script_path}",
            f"TARGET: {target_ip}",
        ]
    )
    if hint.strip():
        parts.append(hint.rstrip("\n"))
    parts.append(f"LOG_TAIL:\n{log_tail}")
    return "\n".join(parts)


def register_workspace_tools(mcp: Any, *, ctx: ToolContext) -> None:
    from tools.mcp_tools.sandbox_exec import loopback_hint, run_argv_in_sandbox

    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @audit_tool
    def write_python_file(filename: str, code: str, binary: bool = False) -> str:
        """Write an AI-generated Python exploit script.

        The script receives the target IP as sys.argv[1] (bare positional), as
        --target <ip>, and via the ACTIVE_CHECK_TARGET env var. Read sys.argv[1]
        (simplest), or use argparse with parse_known_args() so the bare positional
        is not flagged as an unrecognized argument. Use only standard library imports
        (socket, ssl, http, json, etc.) or common pip packages. Pass a bare .py name
        to save into the workspace, or an absolute path to write anywhere on the
        operator box (LAB BUILD: unrestricted).

        With binary=True, ``code`` is a base64 payload and the file is written as raw
        bytes (no shell interpolation, no UTF-8 re-encoding). Use this to materialize a
        private key / PEM / binary blob that must be byte-exact -- then `chmod 600` it
        via run_exploit_terminal. Never paste keys through a shell heredoc.

        Args:
            filename: Bare name (saved into the attempt dir) or absolute path
                (written anywhere on the operator box).
            code: Text source, or base64 payload when binary=True.
            binary: Byte-exact raw-bytes write instead of UTF-8 text.

        Returns:
            PYTHON_FILE_WRITTEN block (path, mode, SHA256, size) or BLOCKED.

        Gates:
            Local-only ``@audit_tool``. No allowlist, no content inspection -- the only
            bound is the MB-scale anti-fill cap.

        Side-effects:
            Creates parent dirs and writes the file verbatim (byte-exact in binary mode).
        """
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
            if len(payload) > _MAX_WRITE_BYTES:
                return f"BLOCKED: payload exceeds the {_MAX_WRITE_BYTES}-byte anti-fill cap; split the write."
            script_path.write_bytes(payload)
            code_sha = hashlib.sha256(payload).hexdigest()
            size_note = f"SIZE: {len(payload)} bytes"
            mode_note = "binary"
        else:
            if len(code) > _MAX_WRITE_BYTES:
                return f"BLOCKED: code exceeds the {_MAX_WRITE_BYTES}-char anti-fill cap; split the write."
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
        """Execute a previously written Python exploit script against the target IP.

        The script is searched across the entire workspace (all subdirectories) by
        filename, so you do not need to know the exact path. It runs synchronously with
        captured output (LOG_TAIL in the result, full log at python_run.log). The target
        IP is passed as sys.argv[1] (bare positional) AND as --target <ip> AND via the
        ACTIVE_CHECK_TARGET env var; scripts should read sys.argv[1] or use argparse
        parse_known_args().

        Args:
            target_ip: Declarative target (IP or domain); allowlist-gated.
            filename: Previously written ``.py`` basename.

        Returns:
            PYTHON_RUN_RESULT block (status, exit code, duration, target, LOG_TAIL),
            BLOCKED on gate failure, or FILE_NOT_FOUND.

        Gates:
            Declarative ``@require_allowlist()`` on ``target_ip`` PLUS a manual
            ``_target_lock_block`` scan of the FULL script body (stored code executes
            verbatim -- without the body scan this tool would be a trivial pivot
            bypass). Scanner-verb extraction stays OFF for Python source.

        Side-effects:
            Copies the script into a fresh attempt dir and executes it (sandbox worker
            when enabled, otherwise the shared host runner with the configured
            ``exploit.command_timeout_seconds``); writes python_run.log (masked).
        """
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        # M4: validate the target IP before it is interpolated into argv/env --
        # a crafted target_ip could inject into the child process otherwise.
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
            shutil.copy2(str(script_path), str(local_script))
            script_path = local_script

        # Tool-layer target lock: the script body is executed verbatim, so a
        # literal-IP pivot to another host (e.g. socket.connect(("10.0.0.99",
        # 4444)) or os.system("nc <other_ip>")) must be gated the same way
        # run_exploit_terminal gates shell commands -- otherwise run_python_file
        # is a trivial bypass of the target-IP lock.
        # Layer 1 (static): literal IPs/URLs in the FULL body.
        # Layer 2 (runtime): the egress-guard preamble wraps socket.connect in
        # the child, so argv/concat/decode-built destinations are denied at
        # connect time however they were constructed.
        # Scanner-verb extraction is off here: that argv heuristic is built for
        # shell, and on Python source it misfires (an "nmap -sV" mention in a
        # comment plus "s.settimeout(...)" blocks the script as "Target
        # s.settimeout is not in the explicit allowlist").
        # RULE-LOCK-FIRST: the gate sees the FULL body -- never a truncated prefix.
        try:
            _body = script_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            _body = ""
        _block = _target_lock_block(_body, config, allow_empty=True, include_scanner_targets=False)
        if _block:
            return f"BLOCKED: {_block}\nTOOL: run_python_file\nSCRIPT: {cleaned}"
        # Runtime egress guard: same effective union the static gate enforced.
        _egress_preamble = build_egress_preamble(_allowed_target_list(config))

        def _denied_block(_captured_text: str) -> str | None:
            """Clean BLOCKED result when the child egress guard fired, else None."""
            _denied_host = egress_denied_in_output(_captured_text)
            if _denied_host is None:
                return None
            return (
                f"BLOCKED: runtime egress guard denied socket connection to {_denied_host} "
                f"(not in the explicit allowlist). Add it to config.yaml exploit.allowed_targets "
                f"to authorize.\nTOOL: run_python_file\nSCRIPT: {cleaned}"
            )

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
                # Validate the cwd mapping fails closed (run_argv_in_sandbox re-maps cwd_host itself).
                sandbox.container_path(attempt_dir)
            except SandboxError as exc:
                return f"BLOCKED: {exc}\nTOOL: run_python_file"
            # The egress-guard preamble runs first inside the worker's python
            # (same argv contract: sys.argv is pinned explicitly below).
            _sandbox_bootstrap = (
                f"{_egress_preamble}import runpy as _runpy; _runpy.run_path({container_script!r}, run_name='__main__')"
            )
            _argv = [
                "python3",
                "-c",
                _sandbox_bootstrap,
                str(target_ip),
                "--target",
                str(target_ip),
            ]
            try:
                _ran, result = run_argv_in_sandbox(
                    ctx,
                    _argv,
                    target_ip=str(target_ip),
                    timeout=_config_timeout(config),
                    cwd_host=attempt_dir,
                    tool_name="run_python_file",
                )
            except SandboxError as exc:
                return f"PYTHON_RUN_RESULT: blocked\n{sandbox_error_block(exc, tool_name='run_python_file')}"
            merged = result.stdout or ""
            if result.stderr:
                merged = f"{merged}\n{result.stderr}" if merged else result.stderr
            _denied = _denied_block(merged)
            if _denied is not None:
                log_path.write_text(
                    f"COMMAND: python3 {container_script} {target_ip} --target {target_ip} (sandbox, egress-guarded)\n"
                    + _tail(_mask_secret_content(merged), _MAX_LOG_FILE_CHARS)
                    + "\nEXIT_CODE: denied\n",
                    encoding="utf-8",
                    errors="replace",
                )
                return _denied
            # Persisted logs are masked: raw stdout may carry dumped hashes, tokens, or
            # key material that must not sit on disk in the clear. (The live LOG_TAIL
            # below stays verbatim -- cracking workflows need the recovered plaintext.)
            log_path.write_text(
                f"COMMAND: {' '.join(_argv)}\n"
                + _tail(_mask_secret_content(merged), _MAX_LOG_FILE_CHARS)
                + f"\nEXIT_CODE: {result.exit_code if result.exit_code is not None else 'timed_out'}\n",
                encoding="utf-8",
                errors="replace",
            )
            _hint = ""
            try:
                # ponytail: unconditional for loopback targets -- see terminal/execute.py
                _hint = loopback_hint(str(target_ip), config)
            except Exception:  # ponytail: bare except intentional -- hint is advisory only
                _hint = ""
            return _format_python_result(
                status=result.status,
                exit_code=result.exit_code,
                duration_s=result.duration_seconds,
                attempt_id=attempt_id,
                script_path=script_path,
                target_ip=str(target_ip),
                log_tail=_tail(merged, _LOG_TAIL_CHARS),
                sandbox_mode=True,
                hint=_hint,
            )

        # ---- host path (sandbox disabled: documented legacy mode): run the script via
        # the shared captured runner. The child bootstraps itself (argv list, no shell):
        # chdir to the attempt dir, set ACTIVE_CHECK_TARGET/EXPLOIT_WORKSPACE, pin
        # sys.argv to [script, target, --target, target], then runpy the script -- so the
        # advertised contract holds without mutating the server process (no os.chdir /
        # os.environ games, safe under concurrent tool calls).
        _bootstrap = (
            f"{_egress_preamble}"
            "import os, runpy, sys; "
            f"os.chdir({str(attempt_dir)!r}); "
            f"os.environ['ACTIVE_CHECK_TARGET'] = {str(target_ip)!r}; "
            f"os.environ['EXPLOIT_WORKSPACE'] = {str(attempt_dir)!r}; "
            f"sys.argv = [{str(script_path)!r}, {str(target_ip)!r}, '--target', {str(target_ip)!r}]; "
            f"runpy.run_path({str(script_path)!r}, run_name='__main__')"
        )
        _argv = [sys.executable, "-c", _bootstrap]
        _friendly = f"{sys.executable} {script_path} {target_ip} --target {target_ip} (cwd={attempt_dir})"
        _status, _rc, _captured, _elapsed = run_argv_captured(_argv, _config_timeout(config), max_chars=_CAPTURE_CHARS)
        _denied_host = _denied_block(_captured)
        if _denied_host is not None:
            try:
                log_path.write_text(
                    f"{'=' * 60}\nCOMMAND: {_friendly} (egress-guarded)\n{'=' * 60}\n"
                    + _tail(_mask_secret_content(_captured), _MAX_LOG_FILE_CHARS)
                    + "\nEXIT_CODE: denied\n",
                    encoding="utf-8",
                    errors="replace",
                )
            except OSError:
                pass
            return _denied_host
        _tail_out = _tail(_captured, _LOG_TAIL_CHARS)
        try:
            log_path.write_text(
                f"{'=' * 60}\nCOMMAND: {_friendly}\n{'=' * 60}\n"
                + _tail(_mask_secret_content(_captured), _MAX_LOG_FILE_CHARS)
                + f"\nEXIT_CODE: {_rc if _rc is not None else 'timed_out'}\n",
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            pass

        from tools.mcp_tools.sandbox_exec import sandbox_fallback_notice

        return _format_python_result(
            status=_status,
            exit_code=_rc,
            duration_s=_elapsed,
            attempt_id=attempt_id,
            script_path=script_path,
            target_ip=str(target_ip),
            log_tail=_tail_out,
            sandbox_mode=False,
            fallback_notice=sandbox_fallback_notice(ctx),
        )

    @mcp.tool()
    @audit_tool
    def read_workspace_file(filename: str) -> str:
        """Read a file inside the run workspace by path.

        Args:
            filename: Workspace-relative path (or absolute path under the workspace).

        Returns:
            File text (capped at 120k chars with a ``[truncated]`` marker), BLOCKED for
            empty names / paths escaping the workspace, or FILE_NOT_FOUND.

        Gates:
            Local-only ``@audit_tool``. Workspace-contained by construction -- absolute
            paths escaping the workspace are refused (fail closed).

        Side-effects:
            None (read-only).
        """
        return read_workspace(workspace, filename)

    @mcp.tool()
    @audit_tool
    def list_workspace() -> str:
        """List all files in the exploit workspace directory.

        Args:
            None.

        Returns:
            Newest-first WORKSPACE listing (capped at 50 shown entries with a
            ``[truncated]`` marker), or "WORKSPACE: empty."

        Gates:
            Local-only ``@audit_tool``. The ``credentials/`` subtree is redacted
            (entry count shown, names/sizes hidden).

        Side-effects:
            None (read-only walk, bounded at 5000 entries, no symlink following).
        """
        workspace.mkdir(parents=True, exist_ok=True)
        ws = workspace.resolve()
        entries: list[Path] = []
        walk_capped = False
        try:
            for root, dirnames, filenames in os.walk(ws, followlinks=False):
                root_path = Path(root)
                for name in dirnames + filenames:
                    entries.append(root_path / name)
                    if len(entries) >= _MAX_WALK_ENTRIES:
                        walk_capped = True
                        break
                if walk_capped:
                    break
        except OSError:
            pass
        # Redact the credentials/ subtree: count it, never list names/sizes/mtimes.
        # Vault keyfiles are deny-listed anywhere in the tree: count them,
        # never list names/sizes/mtimes (serving a keyfile path hands the
        # credential-store Fernet key to the model).
        visible: list[Path] = []
        cred_count = 0
        key_count = 0
        for entry in entries:
            try:
                rel = entry.relative_to(ws)
            except ValueError:
                continue
            if entry.name == ".vault_key":
                key_count += 1
                continue
            if rel.parts and rel.parts[0] == "credentials":
                cred_count += 1
                continue
            visible.append(entry)

        def _mtime(path: Path) -> float:
            try:
                return path.stat().st_mtime
            except OSError:
                return 0

        files = sorted(visible, key=_mtime, reverse=True)
        if not files and not cred_count and not key_count:
            return "WORKSPACE: empty."
        lines = ["WORKSPACE:", ""]
        if cred_count:
            lines.append(f"  credentials/ ({cred_count} entries redacted)")
        if key_count:
            lines.append(f"  <{key_count} vault keyfile(s) redacted>")
        shown = 0
        for f in files[:_MAX_LIST_SHOWN]:
            try:
                rel = f.relative_to(ws)
            except ValueError:
                continue
            if f.is_file():
                try:
                    size = f.stat().st_size
                    mtime = datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                except OSError:
                    continue
                lines.append(f"  {rel} ({size} bytes, modified {mtime})")
                shown += 1
            elif f.is_dir():
                lines.append(f"  {rel}/ (directory)")
                shown += 1
        total = len(files) + cred_count + key_count
        if walk_capped or total > shown + (cred_count > 0) + (key_count > 0):
            lines.append(f"... [truncated - showing {shown} of {total} entries]")
        return "\n".join(lines)
