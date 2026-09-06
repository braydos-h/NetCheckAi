"""Sandbox execution helpers for MCP tool families.

One funnel for "run this argv / this command inside the disposable worker
instead of on the host", with the shared destination extraction that both the
scope gate and the audit target come from. Fail-closed contract lives in
``tools/sandbox``: any ``SandboxError`` here becomes a ``SANDBOX_*`` result
block -- host execution is never an automatic fallback for attack commands.
"""

from __future__ import annotations

from typing import Any

from tools.command_analyzer import _endpoint_ips as _cmd_endpoint_ips
from tools.command_analyzer import _extract_destinations as _cmd_extract_destinations
from tools.sandbox.exceptions import SandboxError
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


def loopback_hint(target_ip: str, config: Any) -> str:
    """One-line remediation when a loopback target fails from inside the sandbox.

    Sandbox loopback is container-local by design; host loopback needs the
    explicit dev opt-in ``sandbox.network.map_host_loopback:true``. Without a
    hint the agent retries Connection-refused commands for dozens of rounds,
    or hallucinates a host-execution escape that does not exist (the sandbox
    is fail-closed: no mid-run host fallback). Returns "" unless the target
    is loopback with mapping disabled.
    """
    tip = (target_ip or "").strip().lower()
    if tip not in ("127.0.0.1", "localhost", "::1"):
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
    """
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
    """Canonical SANDBOX_* fail-closed block for any sandbox failure."""
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
    """
    notice = getattr(ctx, "sandbox_notice", "") or ""
    return f"SANDBOX_FALLBACK: {notice}\n" if notice else ""


def run_command_in_sandbox(
    ctx: Any,
    command: str,
    *,
    timeout: int,
    cwd_host: Any = None,
    tool_name: str = "",
    user: str = "",
) -> tuple[bool, Any]:
    """Execute one shell command inside the session sandbox.

    Returns ``(True, SandboxResult)`` on a contained execution (the sandbox
    itself is the boundary; exit codes are the agent's problem) and raises
    ``SandboxError`` on sandbox/policy/scope failure (caller renders the
    SANDBOX_* block). ``(False, None)`` means no sandbox manager is attached
    (sandbox disabled => documented legacy host-execution mode).

    ``cwd_host`` is a HOST path under the run workspace; it is mapped to its
    container path via the manager (paths outside the workspace fail closed).
    """
    manager = manager_from_ctx(ctx)
    if manager is None:
        return False, None
    targets = collect_command_targets(command)
    target_ip = targets[0] if targets else ""
    cwd = manager.container_path(cwd_host) if cwd_host is not None else None
    result = manager.execute(
        command,
        timeout=timeout,
        cwd=cwd,
        user=user,
        target_ip=target_ip,
        tool_name=tool_name or "run_exploit_terminal",
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
) -> tuple[bool, Any]:
    """Argv-list variant for structured tools (web_scan, impacket, msfvenom...)."""
    manager = manager_from_ctx(ctx)
    if manager is None:
        return False, None
    targets = collect_command_targets(command) if command else []
    if target_ip and target_ip not in targets:
        targets.insert(0, target_ip)
    primary = targets[0] if targets else target_ip
    cwd = manager.container_path(cwd_host) if cwd_host is not None else None
    result = manager.execute_argv(
        argv,
        timeout=timeout,
        cwd=cwd,
        target_ip=primary,
        tool_name=tool_name,
    )
    return True, result
