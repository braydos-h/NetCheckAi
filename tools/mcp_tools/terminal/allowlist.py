"""Allowlist and OPSEC helpers for terminal tools."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

from tools.command_analyzer import _endpoint_ips as _cmd_endpoint_ips
from tools.command_analyzer import _extract_destinations as _cmd_extract_destinations
from tools.kernel.allowlist import _extract_scanner_targets
from tools.mcp_shared import _allowed_target_list
from tools.opsec import OpsecManager
from tools.validation_utils import extract_ips_from_command, is_private_or_local_target, is_target_in_allowlist

__all__ = [
    "_is_union_entry_local",
    "_opsec_advisory_block",
    "_runtime_target_union",
    "_target_lock_block",
]

# The listen-all wildcards are never pivot targets: ``socket.bind(("0.0.0.0",
# ...))`` / ``socket.bind(("::", ...))`` listen, they do not connect anywhere.
# Loopback addresses/names such as ``127.0.0.1`` / ``::1`` / ``localhost``
# stay gated -- they are real connection targets and the lock pins them (see
# test_run_exploit_terminal_blocks_ipv6_not_in_allowlist). ``[::]`` (bracketed
# IPv6 unspecified in URLs) normalizes to ``::`` via ``_cmd_endpoint_ips``, so
# the bare ``::`` entry covers it; the expanded ``0:0:...:0`` form normalizes
# the same way but is listed explicitly in case decoding ever fails and the raw
# token survives.
_BIND_ALL_TOKENS = frozenset({"0.0.0.0", "::", "[::]", "0:0:0:0:0:0:0:0"})

# ``file:`` target-list indirection (``set RHOSTS file:/tmp/hosts`` /
# ``RHOSTS=file:/tmp/hosts``) loads targets from disk, bypassing the
# literal-target check -- denied outright, never expanded. Narrow to MSF host
# options (RHOSTS/RHOST/LHOST) so local ``file://`` reads (``curl
# file:///etc/hosts``) are NOT caught here; those still fail-closed below
# unless they name a target literally. The ``\\b`` word boundary avoids
# matching ``profile:`` / ``write_python_file``.
_FILE_INDIRECTION_RE = re.compile(r"(?i)\b(?:RHOSTS?|LHOST)\b\s*(?:=\s*)?['\"]?\s*file\s*:")


def _is_union_entry_local(entry: str, extra_local_cidrs: Any = None) -> bool:
    """True when an allowlist-union entry classifies as local/private.

    Args:
        entry: One allowlist entry (exact IP, CIDR, FQDN, ``*.wildcard``).
        extra_local_cidrs: Operator-configured local ranges from the OPSEC profile.

    Returns:
        True only when confidently local: exact IPs via
        :func:`is_private_or_local_target`, CIDRs via ``ip_network`` privacy
        flags, wildcards via their parent domain. Anything else (public IP,
        unresolvable domain, malformed, wildcard for public scope) returns
        False so OPSEC stays ON (the safe default).

    Gates:
        None -- pure classifier, never blocks.

    Side-effects:
        None (best-effort DNS via ``is_private_or_local_target``; never raises).
    """
    if not entry or not isinstance(entry, str):
        return False
    s = entry.strip()
    if not s:
        return False
    # Wildcard: classify the parent (``*.example.com`` -> ``example.com``). A
    # wildcard for a public scope stays public (ON, safe); DNS failure also
    # stays public via the safe default below.
    if s.lower().startswith("*."):
        parent = s[2:].strip().rstrip(".")
        if not parent:
            return False
        try:
            return bool(is_private_or_local_target(parent, list(extra_local_cidrs or [])))
        except Exception:  # ponytail: bare except intentional -- classifier never raises
            return False
    # CIDR: ``10.0.0.0/24`` -- ip_address fails, so check ip_network flags.
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
            return bool(
                net.is_private
                or net.is_loopback
                or net.is_link_local
                or net.is_reserved
                or net.is_multicast
                or net.is_unspecified
            )
        except ValueError:
            return False
    try:
        return bool(is_private_or_local_target(s, list(extra_local_cidrs or [])))
    except Exception:  # ponytail: bare except intentional -- classifier never raises
        return False


def _runtime_target_union() -> list[str]:
    """Return the runtime target union the OPSEC posture resolves against.

    Args:
        None -- reads ``EXPLOIT_TARGET`` / ``EXPLOIT_TARGET_IP`` /
        ``EXPLOIT_TARGET_DOMAIN`` / ``EXPLOIT_DISCOVERED_TARGETS`` from the
        environment (the same runtime identity the target-IP lock unions in
        ``mcp_shared._allowed_target_list``).

    Returns:
        Deduped, order-preserving list of runtime target strings (may be
        empty when no target env is set).

    Gates:
        None -- pure reader, never blocks.

    Side-effects:
        None.
    """
    targets: list[str] = []
    for _key in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN"):
        _val = os.environ.get(_key, "").strip()
        if _val and _val not in targets:
            targets.append(_val)
    _discovered = os.environ.get("EXPLOIT_DISCOVERED_TARGETS", "").strip()
    if _discovered:
        for _tok in _discovered.split(","):
            _tok = _tok.strip()
            if _tok and _tok not in targets:
                targets.append(_tok)
    return targets


def _opsec_advisory_block(sanitized_command: str, config: Any) -> str:
    """Build an advisory OPSEC feedback block for a command the AI just ran.

    Args:
        sanitized_command: The (preflight-sanitized) shell command just run.
            Scored verbatim -- never truncated or redacted here (scoring needs
            the full text; the block itself carries no secret material).
        config: Full config dict (reads the ``opsec`` block).

    Returns:
        ``""`` when OPSEC is OFF for this target (local/private, or OPSEC
        disabled), else a 4-line ``OPSEC_ADVISORY:`` block (noise score,
        quieter rewrite, pacing posture). ``""`` on any build error.

    Gates:
        None -- ADVISORY ONLY. The command always executes regardless of this
        block; ``is_quiet_blocked`` and ``noise_budget`` are NOT consulted and
        stay dormant (no attack-path gate is re-added).

    Side-effects:
        None (pure scoring + string build; never executes, never touches audit).

    Target-aware (resolves against the FULL runtime target union, not just
    ``EXPLOIT_TARGET``): OPSEC is OFF only when EVERY union member resolves
    local/private via ``OpsecManager.resolve_for_target``; ANY public member
    keeps the configured posture ON (safe default). An empty union keeps the
    configured posture (``resolve_for_target("")`` returns self).
    """
    try:
        base = OpsecManager.from_config(config or {})
        _targets = _runtime_target_union()
        if not _targets:
            mgr = base.resolve_for_target("")
        elif not base.profile.local_targets_off:
            # Operator opted out of the local-off rule: every target keeps
            # the configured posture (mirrors OpsecProfile.resolve_for_target).
            mgr = base
        else:
            _local_cidrs = base.profile.local_cidrs
            _all_local = all(_is_union_entry_local(_t, _local_cidrs) for _t in _targets)
            if _all_local:
                # Canonical disabled profile (preserves local_targets_off /
                # local_cidrs / public_autonomy knobs for later re-resolution).
                # Resolved via a known-local IP rather than _targets[0] so CIDR
                # entries (e.g. "10.0.0.0/24", which resolve_for_target would
                # misclassify as public) still yield OFF.
                mgr = base.resolve_for_target("127.0.0.1")
            else:
                mgr = base
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
    except Exception:  # ponytail: bare except intentional -- advisory never blocks the result
        return ""


def _target_lock_block(
    command: str, config: Any, *, allow_empty: bool = False, include_scanner_targets: bool = True
) -> str | None:
    """Return a block reason if ``command`` touches a host outside the target allowlist, else None.

    LAB BUILD: this is the one attack-mode safety kept -- the target-IP lock.
    The policy no longer inspects command content, so the lock is enforced here
    at the tool layer on the FULL untruncated input (callers must pass the whole
    command; truncation happens only on display OUTPUT tails, never before this
    gate -- RULE-LOCK-FIRST). Every destination endpoint (URL authorities,
    /dev/tcp hosts, LHOST/RHOST, scanner-verb targets, bare IPs) must be in the
    allowlist. Operator-authorized callback/C2 hosts are added via
    ``exploit.allowed_targets`` in config.yaml.

    Args:
        command: Full shell command / script-body text (never truncated -- the
            gate must see every destination, including encoded forms).
        config: Full config dict (reads the ``exploit`` block).
        allow_empty: Only for static literal scans (e.g. a Python script body)
            where the absence of literals means no literal pivot -- and where
            the tool's structured ``target_ip`` gate already denies an empty
            target. Free-text shell commands keep ``False`` (fail closed).
        include_scanner_targets: Only ``False`` for Python-source scans
            (``run_python_file``): the scanner-verb argv heuristic is built for
            shell, and on Python source it misfires (an ``nmap -sV`` mention in
            a comment plus ``s.settimeout(...)`` extracts ``s.settimeout`` as a
            "target"). Literal-IP / URL / socket.connect gates still apply.

    Returns:
        ``None`` when every extracted destination is allowlisted (or exempt
        bind-all / empty-with-``allow_empty``); otherwise a human-readable
        block reason naming the offending host (or the fail-closed / empty /
        file-indirection reason).

    Gates:
        ``exploit.require_explicit_allowlist`` (off = ``None``); empty
        effective allowlist (fail closed); ``file:`` target-list indirection
        (denied outright, never expanded); per-destination
        ``is_target_in_allowlist`` against the full
        ``_allowed_target_list`` union. Listen-all wildcards (``0.0.0.0``,
        ``::``) are exempt -- ``bind()`` listens, it does not pivot.
        Loopback (``127.0.0.1`` / ``::1`` / ``localhost``) stays gated.

    Side-effects:
        None (pure string extraction + allowlist match).
    """
    exploit_cfg = (config or {}).get("exploit", {})
    if not exploit_cfg.get("require_explicit_allowlist", False):
        return None
    allowed_targets = _allowed_target_list(config)
    if not allowed_targets:
        return (
            "require_explicit_allowlist is True but allowed_targets is empty -- no targets "
            "authorized; add exploit.allowed_targets or set EXPLOIT_TARGET"
        )
    if not isinstance(command, str) or not command:
        if allow_empty:
            return None
        return (
            "No allowlisted target found in command. Target-touching tools must "
            "name their destination literally so it can be checked against "
            "exploit.allowed_targets. (For local enumeration, declare scope "
            "first, e.g. 'echo <target-ip> & whoami & hostname'.)"
        )
    # ``file:`` target-list indirection loads hosts from disk, bypassing the
    # literal-target check -- denied outright, never expanded (mirrors the
    # kernel MSF extractors, which drop ``file:`` tokens instead of gating).
    if _FILE_INDIRECTION_RE.search(command):
        return (
            "Target list indirection (RHOSTS/RHOST/LHOST file:...) is not allowed -- "
            "name the destination literally so it can be checked against "
            "exploit.allowed_targets."
        )
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
