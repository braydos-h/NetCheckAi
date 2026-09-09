"""Sandbox execution helpers for MCP tool families.

One funnel for "run this argv / this command inside the disposable worker
instead of on the host", with the shared destination extraction that both the
scope gate and the audit target come from. Fail-closed contract lives in
``tools/sandbox``: any ``SandboxError`` here becomes a ``SANDBOX_*`` result
block -- host execution is never an automatic fallback for attack commands.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

from tools.command_analyzer import _endpoint_ips as _cmd_endpoint_ips
from tools.command_analyzer import _extract_destinations as _cmd_extract_destinations
from tools.sandbox.exceptions import SandboxError, SandboxWorkspaceError
from tools.sandbox.mcp_bridge import manager_from_ctx, sandbox_block
from tools.validation_utils import extract_ips_from_command

__all__ = [
    "collect_command_targets",
    "run_command_in_sandbox",
    "run_argv_in_sandbox",
    "sandbox_error_block",
    "sandbox_fallback_notice",
    "loopback_hint",
]

# Container --user allowlist: passed through to ``docker exec --user`` as an
# argv element (no shell), but an injection-shaped value still fails closed
# here rather than reaching the backend.
_SAFE_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def loopback_hint(target_ip: str, config: Any) -> str:
    """One-line remediation when a loopback target fails from inside the sandbox.

    Sandbox loopback is container-local by design; host loopback needs the
    explicit dev opt-in ``sandbox.network.map_host_loopback:true``. Without a
    hint the agent retries Connection-refused commands for dozens of rounds,
    or hallucinates a host-execution escape that does not exist (the sandbox
    is fail-closed: no mid-run host fallback). Returns "" unless the target
    is loopback with mapping disabled.

    Encoded loopback forms (decimal ``2130706433``, hex ``0x7f000001``,
    octal, and the full ``127.0.0.0/8`` range -- not just ``127.0.0.1``) are
    decoded via the shared endpoint-IP extractor so an obfuscated loopback
    probe gets the same hint instead of an unbounded retry loop.

    Args:
        target_ip: Bare target host/IP as passed to the tool (not a URL).
        config: Config dict (only the ``sandbox`` section is read).

    Returns:
        The ``HINT:`` remediation line, or "" when no hint applies.

    Gates:
        None (advisory only -- never blocks or allows execution).

    Side-effects:
        None.
    """
    if not isinstance(target_ip, str):
        return ""
    tip = target_ip.strip()
    if not tip:
        return ""
    low = tip.lower().rstrip(".")
    if low.startswith("[") and low.endswith("]"):
        low = low[1:-1].strip()
    is_loopback = low in ("localhost", "127.0.0.1", "::1")
    if not is_loopback:
        try:
            for cand in _cmd_endpoint_ips(tip):
                try:
                    if ipaddress.ip_address(cand).is_loopback:
                        is_loopback = True
                        break
                except ValueError:
                    continue
        except Exception:  # ponytail: bare except intentional -- hint never blocks results
            pass
    if not is_loopback:
        try:
            if ipaddress.ip_address(low).is_loopback:
                is_loopback = True
        except ValueError:
            pass
    if not is_loopback:
        return ""
    try:
        sandbox_cfg = (config or {}).get("sandbox") or {}
        if not bool(sandbox_cfg.get("enabled", True)):
            return ""
        network = sandbox_cfg.get("network") or {}
        if bool(network.get("map_host_loopback", False)):
            return ""
    except Exception:  # ponytail: bare except intentional -- hint never blocks results
        return ""
    return (
        "HINT: target is host loopback but sandbox loopback is container-local "
        "(sandbox.network.map_host_loopback:false). All commands run inside the disposable "
        "worker -- there is no host-execution fallback, do not claim you switched. Do not "
        "retry the same loopback probe; treat as TARGET_UNREACHABLE and report the operator "
        "prerequisite (sandbox.network.map_host_loopback:true for dev-lab localhost, or "
        "sandbox.enabled:false).\n"
    )


def collect_command_targets(command: str) -> list[str]:
    """All host-shaped destinations a command plausibly touches.

    Same union of extractors the tool-layer target lock
    (``terminal.allowlist._target_lock_block``) uses, so the sandbox scope gate
    can never authorize what the string layer would deny (and vice versa).
    Endpoint tokens are expanded to concrete IPs where possible.

    Args:
        command: Full shell command text (never truncated -- the gate must
            see every destination, including encoded forms).

    Returns:
        Deduped, order-preserving list of destination tokens (IPs, decoded
        endpoint IPs, hostnames, CIDRs).

    Gates:
        None (pure extraction -- the scope gate consumes the result).

    Side-effects:
        None.
    """
    if not isinstance(command, str) or not command:
        return []
    tokens: list[str] = []
    for tok in _cmd_extract_destinations(command):
        if tok and tok not in tokens:
            tokens.append(tok)
    for ip in extract_ips_from_command(command):
        if ip and ip not in tokens:
            tokens.append(ip)
    try:
        from tools.kernel.allowlist import _extract_scanner_targets

        for tok in _extract_scanner_targets(command):
            if tok and tok not in tokens:
                tokens.append(tok)
    except ImportError:  # defensive: extractor set must never break execution
        pass
    targets: list[str] = []
    for tok in tokens:
        decoded = _cmd_endpoint_ips(tok)
        for t in decoded if decoded else [tok]:
            if t and t not in targets:
                targets.append(t)
    return targets


def sandbox_error_block(exc: Exception, *, tool_name: str = "") -> str:
    """Canonical SANDBOX_* fail-closed block for any sandbox failure.

    Args:
        exc: The sandbox failure (``SandboxError`` subclass or unexpected).
        tool_name: Calling MCP tool name, surfaced as the ``TOOL:`` line.

    Returns:
        Structured result block (never a traceback, never a host fallback).

    Gates:
        None (renders the denial -- the gate already fired).

    Side-effects:
        None.
    """
    if isinstance(exc, SandboxError):
        return sandbox_block(exc, tool_name=tool_name)
    # Unexpected failure on the sandbox path: still fail closed.
    return sandbox_block(
        SandboxError(f"sandbox execution failed: {exc}"),
        tool_name=tool_name,
    )


def sandbox_fallback_notice(ctx: Any) -> str:
    """``SANDBOX_FALLBACK:`` result line for the legacy host-execution path.

    Non-empty only when this server process degraded to native execution via
    the boot-time native fallback (``ctx.sandbox_notice`` set by
    ``mcp_exploit_server``); empty when the sandbox is disabled as
    configured -- degraded-mode executions must be loud, configured host mode
    stays quiet.

    Args:
        ctx: Tool context carrying the optional ``sandbox_notice`` string.

    Returns:
        The ``SANDBOX_FALLBACK:`` line, or "" when not in fallback mode.

    Gates:
        None (labels the execution mode -- the boot decision already fired).

    Side-effects:
        None.
    """
    notice = getattr(ctx, "sandbox_notice", "") or ""
    return f"SANDBOX_FALLBACK: {notice}\n" if notice else ""


def _validate_timeout(timeout: Any) -> int:
    """Positive-int timeout gate (fail closed on missing/invalid values)."""
    if isinstance(timeout, bool):
        raise SandboxError(f"sandbox execution requires a positive timeout (got {timeout!r})")
    try:
        value = int(timeout)
    except (TypeError, ValueError):
        raise SandboxError(f"sandbox execution requires a positive timeout (got {timeout!r})") from None
    if value <= 0:
        raise SandboxError(f"sandbox execution requires a positive timeout (got {timeout!r})")
    return value


def _validate_tool_name(tool_name: Any, *, default: str) -> str:
    """Tool-name gate: empty maps to the caller's funnel default for audit."""
    if tool_name is None:
        return default
    if not isinstance(tool_name, str):
        raise SandboxError(f"sandbox execution requires a string tool_name (got {tool_name!r})")
    text = tool_name.strip()
    return text or default


def _validate_user(user: Any) -> str:
    """Container-user gate: "" (backend default) or a safe --user token."""
    if user is None:
        return ""
    if not isinstance(user, str):
        raise SandboxError(f"sandbox execution requires a string user (got {user!r})")
    text = user.strip()
    if not text:
        return ""
    if not _SAFE_USER_RE.fullmatch(text):
        raise SandboxError(f"sandbox execution refused unsafe user {user!r}")
    return text


def _validate_cwd_host(cwd_host: Any) -> None:
    """Host-cwd type gate: None (no cwd) or a path-like the mapper can bind."""
    if cwd_host is None:
        return
    if isinstance(cwd_host, (str, os.PathLike)):
        return
    raise SandboxWorkspaceError(f"sandbox execution requires a path cwd_host (got {type(cwd_host).__name__})")


def _enforce_full_scope(manager: Any, targets: list[str]) -> None:
    """Scope the FULL extracted target list through the manager's own gate.

    The manager's ``execute``/``execute_argv`` only scope-checks the single
    ``target_ip`` it receives (the primary). A multi-destination command whose
    primary is allowlisted but whose secondary is not would otherwise sail
    through -- so every extracted destination is run through the manager's
    exact ``_enforce_scope`` first (same research-host exception, same
    empty-allowlist semantics, no divergent reimplementation). Managers
    without the seam (test fakes) skip the pre-check; the real funnel still
    re-checks the primary inside ``execute``.
    """
    enforce = getattr(manager, "_enforce_scope", None)
    if not callable(enforce):
        return
    for target in targets:
        if target:
            enforce(target)


def _container_path_for_caller(manager: Any, cwd_host: Any, *, tool_name: str) -> str | None:
    """Map the host workspace prefix to its container prefix for the caller.

    Args:
        manager: Session sandbox manager owning the workspace bind.
        cwd_host: Host path under the run workspace (None = no cwd).
        tool_name: Calling MCP tool name, prefixed onto mapping failures so
            the audit block names the funnel that supplied the bad prefix.

    Returns:
        Container path string, or None when no cwd was given.

    Gates:
        Workspace containment (delegated to ``manager.container_path``).

    Side-effects:
        None (pure path mapping).
    """
    if cwd_host is None:
        return None
    try:
        return manager.container_path(cwd_host)
    except SandboxError as exc:
        raise SandboxWorkspaceError(f"{tool_name}: {exc}") from exc
    except Exception as exc:  # fail closed: a mapping failure blocks, never runs uncontained
        raise SandboxWorkspaceError(f"{tool_name}: workspace path mapping failed: {exc}") from exc


def run_command_in_sandbox(
    ctx: Any,
    command: str,
    *,
    timeout: int,
    cwd_host: Any = None,
    tool_name: str = "",
    user: str = "",
    targets: list[str] | None = None,
) -> tuple[bool, Any]:
    """Execute one shell command inside the session sandbox.

    Args:
        ctx: Tool context carrying the session sandbox manager.
        command: Full shell command text (never truncated -- both the
            scope gate and the worker see the complete input).
        timeout: Per-command timeout seconds (positive int, fail closed).
        cwd_host: Host path under the run workspace, mapped to its
            container prefix (paths outside the workspace fail closed).
        tool_name: Calling MCP tool name for scope/audit (empty maps to
            ``run_exploit_terminal``, the shell funnel's caller).
        user: Container user ("" = backend default; otherwise a safe
            ``--user`` token such as ``root``).
        targets: Pre-parsed destination list (single-parse threading: the
            caller already ran the lock union over ``command``). When given,
            ``collect_command_targets`` is skipped; the list is still run
            through the manager scope gate below. None = parse here.

    Returns:
        ``(True, SandboxResult)`` on a contained execution (the sandbox
        itself is the boundary; exit codes are the agent's problem).
        ``(False, None)`` means no sandbox manager is attached
        (sandbox disabled => documented legacy host-execution mode).
        Raises ``SandboxError`` on sandbox/policy/scope/entry failure
        (caller renders the SANDBOX_* block).

    Gates:
        Entry validation (non-empty command, positive timeout, safe user,
        path-like cwd) + the FULL extracted target list through the
        manager scope gate (primary forwarded for the manager audit).

    Side-effects:
        Contained process execution + sandbox-context audit row inside the
        manager (container id, network decision, exit code, duration).
    """
    manager = manager_from_ctx(ctx)
    if manager is None:
        return False, None
    if not isinstance(command, str) or not command.strip():
        raise SandboxError("sandbox execution requires a non-empty command")
    timeout_value = _validate_timeout(timeout)
    tool_value = _validate_tool_name(tool_name, default="run_exploit_terminal")
    user_value = _validate_user(user)
    _validate_cwd_host(cwd_host)
    targets = list(targets) if targets is not None else collect_command_targets(command)
    _enforce_full_scope(manager, targets)
    target_ip = targets[0] if targets else ""
    cwd = _container_path_for_caller(manager, cwd_host, tool_name=tool_value)
    result = manager.execute(
        command,
        timeout=timeout_value,
        cwd=cwd,
        user=user_value,
        target_ip=target_ip,
        tool_name=tool_value,
    )
    return True, result


def run_argv_in_sandbox(
    ctx: Any,
    argv: list[str],
    *,
    target_ip: str = "",
    command: str = "",
    timeout: int = 300,
    cwd_host: Any = None,
    tool_name: str = "",
    targets: list[str] | None = None,
) -> tuple[bool, Any]:
    """Argv-list variant for structured tools (web_scan, impacket, msfvenom...).

    Args:
        ctx: Tool context carrying the session sandbox manager.
        argv: Full argv list (non-empty, all non-empty strings -- passed
            to the worker verbatim, never truncated, never shelled).
        target_ip: Structured tool target (merged at the head of the
            command-derived list so the scope gate sees both).
        command: Human-readable command string used ONLY for destination
            extraction (the worker runs ``argv``, never this string).
        timeout: Per-command timeout seconds (positive int, fail closed).
        cwd_host: Host path under the run workspace, mapped to its
            container prefix (paths outside the workspace fail closed).
        tool_name: Calling MCP tool name for scope/audit (passed through;
            empty lets the manager audit fall back to ``sandbox.execute``).
        targets: Pre-parsed command-derived destination list (single-parse
            threading: skips ``collect_command_targets`` on ``command``;
            ``target_ip`` is still merged at the head). None = parse here.

    Returns:
        ``(True, SandboxResult)`` on a contained execution;
        ``(False, None)`` when no sandbox manager is attached (documented
        legacy host-execution mode). Raises ``SandboxError`` on
        sandbox/policy/scope/entry failure.

    Gates:
        Entry validation (non-empty argv, positive timeout, string
        target/command, path-like cwd) + the FULL merged target list
        (structured target plus every command-derived destination)
        through the manager scope gate (primary forwarded for audit).

    Side-effects:
        Contained process execution + sandbox-context audit row inside the
        manager.
    """
    manager = manager_from_ctx(ctx)
    if manager is None:
        return False, None
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise SandboxError("sandbox execution requires a non-empty argv list of strings")
    if target_ip is None:
        target_text = ""
    elif isinstance(target_ip, str):
        target_text = target_ip.strip()
    else:
        raise SandboxError(f"sandbox execution requires a string target_ip (got {target_ip!r})")
    if command is None:
        command_text = ""
    elif isinstance(command, str):
        command_text = command
    else:
        raise SandboxError(f"sandbox execution requires a string command (got {command!r})")
    timeout_value = _validate_timeout(timeout)
    tool_value = _validate_tool_name(tool_name, default="")
    _validate_cwd_host(cwd_host)
    targets = list(targets) if targets is not None else (collect_command_targets(command_text) if command_text else [])
    if target_text and target_text not in targets:
        targets.insert(0, target_text)
    primary = targets[0] if targets else target_text
    _enforce_full_scope(manager, targets)
    cwd = _container_path_for_caller(manager, cwd_host, tool_name=tool_value or "sandbox.execute")
    result = manager.execute_argv(
        argv,
        timeout=timeout_value,
        cwd=cwd,
        target_ip=primary,
        tool_name=tool_value,
    )
    return True, result
