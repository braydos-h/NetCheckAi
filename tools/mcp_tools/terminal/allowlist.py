"""Allowlist and OPSEC helpers for terminal tools."""

from __future__ import annotations

import os
from typing import Any

from tools.command_analyzer import _endpoint_ips as _cmd_endpoint_ips
from tools.command_analyzer import _extract_destinations as _cmd_extract_destinations
from tools.exceptions import _EXC_GROUP_CATCH
from tools.kernel.allowlist import _extract_scanner_targets
from tools.mcp_shared import _allowed_target_list
from tools.opsec import OpsecManager
from tools.validation_utils import extract_ips_from_command, is_target_in_allowlist

__all__ = ["_opsec_advisory_block", "_target_lock_block"]

# The listen-all wildcard is never a pivot target: ``socket.bind(("0.0.0.0",
# ...))`` listens, it does not connect anywhere. Loopback *names* such as
# ``localhost`` / ``::1`` stay gated -- they are real connection targets and
# the lock pins them (see test_run_exploit_terminal_blocks_ipv6_not_in_allowlist).
_BIND_ALL_TOKENS = frozenset({"0.0.0.0"})


def _opsec_advisory_block(sanitized_command: str, config: Any) -> str:
    """Build an advisory OPSEC feedback block for a command the AI just ran.

    Target-aware (resolves against the runtime ``EXPLOIT_TARGET``): returns ``""``
    when OPSEC is OFF for this target (local/private, or OPSEC disabled). When ON,
    surfaces a live noise score, a suggested quieter rewrite, and the pacing
    posture. ADVISORY ONLY -- the command always executes regardless of this
    block; ``is_quiet_blocked`` and ``noise_budget`` are NOT consulted and stay
    dormant (no attack-path gate is re-added). Best-effort: any OPSEC build error
    degrades to ``""`` and never blocks the result.
    """
    try:
        _target_ip = os.environ.get("EXPLOIT_TARGET", "")
        mgr = OpsecManager.from_config(config or {}).resolve_for_target(_target_ip)
        if not mgr.profile.enabled:
            return ""
        noise = mgr.score_command_noise(sanitized_command)
        alt = mgr.suggest_low_noise_alternative(sanitized_command)
        reasons = ", ".join(noise["reasons"][:3]) or "none"
        alt_line = alt if alt else "no rewrite available"
        if mgr.profile.min_gap_seconds > 0 or mgr.profile.jitter_seconds > 0:
            pacing = f"min_gap={mgr.profile.min_gap_seconds}s jitter={mgr.profile.jitter_seconds}s active"
        else:
            pacing = "off (no min_gap/jitter configured)"
        return (
            f"OPSEC_ADVISORY: (advisory -- does not block; you decide)\n"
            f"- Noise score: {noise['score']} (matched: {reasons})\n"
            f"- Suggested quieter rewrite: {alt_line}\n"
            f"- Pacing posture: {pacing}\n"
        )
    except _EXC_GROUP_CATCH:
        return ""


def _target_lock_block(
    command: str, config: Any, *, allow_empty: bool = False, include_scanner_targets: bool = True
) -> str | None:
    """Return a block reason if ``command`` touches a host outside the target
    allowlist, else None.

    LAB BUILD: this is the one attack-mode safety kept -- the target-IP lock.
    The policy no longer inspects command content, so the lock is enforced here
    at the tool layer. The allowlist unions the runtime ``--target`` via the
    ``EXPLOIT_TARGET`` env var (see ``mcp_shared._allowed_target_list``); every
    destination endpoint (URL authorities, /dev/tcp hosts, LHOST/RHOST, scanner
    verb targets, bare IPs) must be in that allowlist. Operator-authorized
    callback/C2 hosts are added via ``exploit.allowed_targets`` in config.yaml.

    Fail closed on empty: a target-touching free-text command that names no
    checkable destination (variable indirection, ``curl $URL``) cannot prove it
    stays inside the allowlist, so it is denied. ``allow_empty=True`` is only
    for static literal scans (e.g. a Python script body) where the absence of
    literals means no literal pivot -- and where the tool's structured
    ``target_ip`` gate already denies an empty target.
    ``include_scanner_targets=False`` is only for Python-source scans
    (``run_python_file``): the scanner-verb argv heuristic is built for shell,
    and on Python source it misfires (an ``nmap -sV`` mention in a comment
    plus ``s.settimeout(...)`` extracts ``s.settimeout`` as a "target").
    Literal-IP / URL / socket.connect gates still apply there.
    """
    exploit_cfg = (config or {}).get("exploit", {})
    if not exploit_cfg.get("require_explicit_allowlist", False):
        return None
    allowed_targets = _allowed_target_list(config)
    if not allowed_targets:
        return "require_explicit_allowlist is True but allowed_targets is empty -- no targets authorized; add exploit.allowed_targets or set EXPLOIT_TARGET"
    _dest_tokens: list[str] = []
    for _tok in _cmd_extract_destinations(command):
        if _tok not in _dest_tokens:
            _dest_tokens.append(_tok)
    for _ip in extract_ips_from_command(command):
        if _ip not in _dest_tokens:
            _dest_tokens.append(_ip)
    if include_scanner_targets:
        for _tok in _extract_scanner_targets(command):
            if _tok not in _dest_tokens:
                _dest_tokens.append(_tok)
    if not _dest_tokens and not allow_empty:
        # Fail closed: a target-touching free-text command that names no
        # destination cannot prove it stays inside the allowlist (bare
        # `curl $URL`, variable indirection, DNS-resolved hosts). Name the
        # target literally.
        return (
            "No allowlisted target found in command. Target-touching tools must "
            "name their destination literally so it can be checked against "
            "exploit.allowed_targets. (For local enumeration, declare scope "
            "first, e.g. 'echo <target-ip> & whoami & hostname'.)"
        )
    for _tok in _dest_tokens:
        _decoded = _cmd_endpoint_ips(_tok)
        _targets = _decoded if _decoded else [_tok]
        for _t in _targets:
            if isinstance(_t, str) and _t.strip().lower() in _BIND_ALL_TOKENS:
                continue
            if not is_target_in_allowlist(_t, allowed_targets):
                return (
                    f"Target {_t} is not in the explicit allowlist. "
                    f"Add it to config.yaml exploit.allowed_targets to authorize."
                )
    return None
