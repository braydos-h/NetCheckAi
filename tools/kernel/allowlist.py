"""Target-IP allowlist helpers — the ONE attack-mode safety gate.

Extracted from ``tools.mcp_shared`` (Phase 2 kernel). The allowlist union
(``exploit.allowed_targets`` + ``EXPLOIT_TARGET`` / ``_IP`` / ``_DOMAIN`` /
``DISCOVERED_TARGETS`` / ``ALLOWED_TARGETS`` env vars) IS the target-IP lock
(``safety-model.md`` §Exploit Permission Modes). Both flows and every
target-touching MCP tool import from here; ``tools.mcp_shared`` re-exports
for backwards compat.

Ponytail: pure functions + env-var union + ``is_target_in_allowlist``
matcher (supports domains, ``*.wildcard``, CIDR).
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from collections.abc import Mapping
from typing import Any

from tools.validation_utils import is_fqdn, is_target_in_allowlist, validate_target

_MSF_RHOSTS_RE = re.compile(
    r"\bset(?:g)?\s+(?:RHOSTS|RHOST)\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
    re.IGNORECASE,
)
# LHOST / callback hosts: a reverse payload or handler that calls back to an
# out-of-scope host is an egress path the allowlist must gate — the same lock
# as RHOSTS, mirrored from generate_payload / msf_generate_payload which gate
# their structured ``lhost`` param via check_targets_allowlist([lhost]).
_MSF_LHOST_RE = re.compile(
    r"\bset(?:g)?\s+(?:LHOST)\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
    re.IGNORECASE,
)
_MSF_PIVOT_RE = re.compile(
    r"(?i:\bportfwd\b)[^\n]*?(?:\s-r\s+)(\S+)"
    r"|(?i:\broute\s+add\s+)(\S+)"
    r"|(?i:\bautoroute)(?:\s+add|\s+-s)?\s+(\S+)"
)


# Env vars unioned into the effective allowlist. Any entry from these widens
# the lock beyond config.yaml — the gates must name that widening (see
# ``_env_union_entries``) instead of silently absorbing it.
_ENV_UNION_KEYS = (
    "EXPLOIT_TARGET",
    "EXPLOIT_TARGET_IP",
    "EXPLOIT_TARGET_DOMAIN",
    "EXPLOIT_DISCOVERED_TARGETS",
    "EXPLOIT_ALLOWED_TARGETS",
)


def _config_only_targets(config: dict[str, Any] | None) -> list[str]:
    """``exploit.allowed_targets`` from config alone (no env union)."""
    exploit_cfg = (config or {}).get("exploit", {})
    return [t for t in list(exploit_cfg.get("allowed_targets", [])) if t]


def _env_union_entries() -> list[str]:
    """Every allowlist entry contributed by the environment (deduped, ordered)."""
    out: list[str] = []
    for env_key in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN"):
        val = os.environ.get(env_key, "").strip()
        if val and val not in out:
            out.append(val)
    for env_key in ("EXPLOIT_DISCOVERED_TARGETS", "EXPLOIT_ALLOWED_TARGETS"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            for tok in raw.split(","):
                tok = tok.strip()
                if tok and tok not in out:
                    out.append(tok)
    return out


def _allowed_target_list(config: dict[str, Any] | None) -> list[str]:
    """The effective allowlist = config ``exploit.allowed_targets`` UNION env vars.

    See ``tools.mcp_shared._allowed_target_list`` docstring (verbatim move).
    """
    allowed = list(_config_only_targets(config))
    for tok in _env_union_entries():
        if tok not in allowed:
            allowed.append(tok)
    return allowed


def _env_widening_note(config: dict[str, Any] | None) -> str:
    """Human-readable note naming env entries that widen the lock beyond config.

    Empty when the environment contributes nothing new. Gate reasons embed
    this so env widening is never silent — it shows up in BLOCKED/allowed
    reasons and (via the boot-time audit event) in ``exploit_audit.jsonl``.
    """
    config_only = set(_config_only_targets(config))
    extra = [t for t in _env_union_entries() if t not in config_only]
    if not extra:
        return ""
    return f" (env union widens the lock: {', '.join(extra)})"


def allowlist_env_audit_extra(config: dict[str, Any] | None) -> dict[str, Any]:
    """``extra`` payload for audit rows naming the env widening, or ``{}``."""
    config_only = set(_config_only_targets(config))
    extra = [t for t in _env_union_entries() if t not in config_only]
    if not extra:
        return {}
    return {"allowlist_env_union": extra}


def add_discovered_target(host: str, ip: str | None = None, *, source: str = "") -> None:
    """Runtime-extend the allowlist with a discovered subdomain (hardened).

    Allowlist-checked: the discovered host must be either directly allowlisted
    (exact / wildcard / CIDR via is_target_in_allowlist) or a strict subdomain
    of an already-allowed FQDN (is_subdomain_of). This prevents a compromised
    enumerator or LLM from widening the lock to an arbitrary external asset
    (e.g. badexample.com vs example.com via suffix collision, or evil.com via
    EXPLOIT_DISCOVERED_TARGETS injection). If ``require_explicit_allowlist`` is
    false the check is skipped (legacy). An empty existing allowlist denies
    expansion (no base to authorize from). Validated targets only; malformed
    hosts are dropped.

    Provenance (no global raw-IP authorization): only the *hostname* is
    appended to ``EXPLOIT_DISCOVERED_TARGETS``. A resolved ``ip`` is recorded
    in the provenance store (:mod:`tools.kernel.discovered`) tied to that
    hostname — it is usable bare only when the IP itself is explicitly
    allowlisted, otherwise only in a hostname-tied context (sandbox policy,
    IP+hostname pair checks). Authorizing ``allowed.example.com`` therefore
    never silently authorizes its shared-hosting/CDN IP for unrelated use.
    """
    import logging

    from tools.validation_utils import is_subdomain_of

    logger = logging.getLogger(__name__)
    if not host or not isinstance(host, str):
        return
    host = host.strip()
    if not host:
        return
    # Basic host validation — must be an IP or FQDN
    if not validate_target(host):
        logger.warning("add_discovered_target denied: invalid host %r", host)
        return
    if ip is not None:
        ip = ip.strip() if isinstance(ip, str) else str(ip).strip()
        if ip and not validate_target(ip):
            logger.warning("add_discovered_target denied: invalid ip %r for host %r", ip, host)
            return
        if not ip:
            ip = None

    # Load config for allowlist base (env union); best-effort — env-only if missing
    config: dict[str, Any] | None = None
    try:
        from pathlib import Path as _P

        from tools.kernel.config import load_config as _load

        _cfg_path = _P("config.yaml")
        if _cfg_path.exists():
            config = _load(_cfg_path)
    except Exception as e:  # noqa: BLE001
        logger.warning("add_discovered_target config load failed: %s — using env-only allowlist", e)
        config = None

    # Discovered-host expansion is ALWAYS validated against the union: a
    # false ``require_explicit_allowlist`` no longer lets any enumerated host
    # silently widen the lock. An empty union still denies expansion (no base
    # to authorize from).
    existing_allowed = _allowed_target_list(config)
    if not existing_allowed:
        logger.warning(
            "add_discovered_target denied: allowlist empty, cannot authorize %r (no base to expand from)",
            host,
        )
        return
    # Direct allowlist match (exact, wildcard with dot-boundary, CIDR)
    if is_target_in_allowlist(host, existing_allowed):
        pass
    else:
        # Subdomain expansion: host must be a strict subdomain of an allowed FQDN
        allowed_domains = [
            a.strip().lower().lstrip("*.").rstrip(".")
            for a in existing_allowed
            if is_fqdn(a.strip().lower().lstrip("*."))
        ]
        if not allowed_domains:
            logger.warning(
                "add_discovered_target denied: %r not in allowlist and no domain in allowlist to be subdomain of %r",
                host,
                existing_allowed,
            )
            return
        subdomain_ok = any(is_subdomain_of(host, dom) for dom in allowed_domains if dom)
        if not subdomain_ok:
            logger.warning(
                "add_discovered_target denied: %r not in allowlist and not subdomain of %r",
                host,
                allowed_domains,
            )
            return
    # Provenance, not global authorization: a resolved IP inherits the
    # host's authorization ONLY in a hostname-tied context. It is recorded
    # against the hostname (see tools.kernel.discovered) and is NEVER
    # appended to EXPLOIT_DISCOVERED_TARGETS as a bare reusable entry —
    # otherwise authorizing one hostname would silently authorize its
    # shared-hosting/CDN IP for unrelated use.

    vals = [t.strip() for t in os.environ.get("EXPLOIT_DISCOVERED_TARGETS", "").split(",") if t.strip()]
    if host not in vals:
        vals.append(host)
    os.environ["EXPLOIT_DISCOVERED_TARGETS"] = ",".join(vals)

    if ip and ip != host:
        from tools.kernel.discovered import record_discovered_host

        record_discovered_host(host, [ip], source=source or "add_discovered_target")


def _check_allowlist(target_ip: str, config: dict[str, Any] | None) -> tuple[bool, str]:
    """Return (allowed, reason) for target_ip against the effective allowlist.

    The lock enforces whenever ANY authorization material exists (config
    ``allowed_targets`` or any ``EXPLOIT_*`` env union) — a false
    ``require_explicit_allowlist`` no longer silently disables every check
    while the environment widens the lock. A fully empty union (no config
    entries, no env entries) stays fail-closed when the flag demands an
    explicit allowlist, and permissive otherwise. Env widening is named in
    the reason so it is never silent.
    """
    exploit_cfg = (config or {}).get("exploit", {})
    require = bool(exploit_cfg.get("require_explicit_allowlist", False))
    allowed_targets = _allowed_target_list(config)
    if not allowed_targets:
        if require:
            return False, "require_explicit_allowlist is True but allowed_targets is empty"
        return True, "no allowlist configured"
    if is_target_in_allowlist(target_ip, allowed_targets):
        return True, f"target in allowlist{_env_widening_note(config)}"
    return False, (
        f"Target IP {target_ip} is not in the explicit allowlist. "
        f"Add it to config.yaml exploit.allowed_targets to authorize."
        f"{_env_widening_note(config)}"
    )


def _extract_msf_lhosts(text: str) -> list[str]:
    """Extract LHOST callback hosts from msfconsole text.

    ``set LHOST <host>`` / ``setg LHOST <host>`` stage a reverse handler that
    calls back to ``<host>`` — an egress path the target-IP lock must gate the
    same way it gates RHOSTS. Comma/whitespace-separated lists are split;
    ``file:`` indirection is denied outright (never expanded, never returned).
    The ``0.0.0.0`` listen-all wildcard is skipped: like ``socket.bind`` in the
    terminal lock (``tools/mcp_tools/terminal/allowlist._BIND_ALL_TOKENS``), a
    handler listening on all interfaces names no egress target.
    """
    if not text:
        return []
    out: list[str] = []
    for m in _MSF_LHOST_RE.findall(text):
        tok = next((g for g in m if g), "").strip().strip("\"';")
        if not tok or tok.lower().startswith("file:"):
            continue
        for part in re.split(r"[,\s]+", tok):
            part = part.strip().strip("\"';")
            if not part or part.lower().startswith("file:"):
                continue
            if part == "0.0.0.0":
                continue
            if part not in out:
                out.append(part)
    return out


# Options-dict keys whose VALUE is a host the allowlist must gate. LHOST is
# the reverse-handler callback (egress); RHOST/RHOSTS override the module
# target — the bridge forwards every options key except its own reserved set,
# so an options-carried host would otherwise bypass the structured target_ip
# gate (P0: ``options='LHOST=evil.com'`` staged a handler to an off-list host
# while target_ip itself was allowlisted).
_MSF_OPTION_HOST_KEYS = frozenset({"LHOST", "RHOST", "RHOSTS"})


def _extract_msf_option_hosts(options: Mapping[str, Any] | None) -> list[str]:
    """Return allowlist-gatable hosts from a parsed MSF options mapping.

    Values for ``LHOST`` / ``RHOST`` / ``RHOSTS`` keys (case-insensitive);
    ``RHOSTS`` lists are split on commas/whitespace, ``file:`` indirection is
    dropped, and the ``0.0.0.0`` listen-all wildcard is skipped for ``LHOST``
    (mirrors :func:`_extract_msf_lhosts`). Non-string values are stringified;
    unknown keys are ignored.
    """
    out: list[str] = []
    if not options:
        return out
    for key, value in options.items():
        if not isinstance(key, str) or key.strip().upper() not in _MSF_OPTION_HOST_KEYS:
            continue
        if value is None:
            continue
        for part in re.split(r"[,\s]+", str(value)):
            part = part.strip().strip("\"';")
            if not part or part.lower().startswith("file:"):
                continue
            if part == "0.0.0.0" and key.strip().upper() == "LHOST":
                continue
            if part not in out:
                out.append(part)
    return out


def _extract_msf_rhosts(text: str) -> list[str]:
    """Extract RHOSTS/RHOST + LHOST + pivot hosts from msfconsole text.

    Comma/whitespace-separated lists (``RHOSTS a,b`` / ``RHOSTS a b``) are
    split into individual hosts; ``file:`` indirection (``RHOSTS file:/tmp/h``)
    is denied outright (never expanded, never returned). LHOST callback hosts
    are included: a reverse payload calling back to an out-of-scope host is an
    egress path the allowlist must gate (mirrors the generate_payload lhost
    gate).
    """
    if not text:
        return []
    out: list[str] = []
    for m in _MSF_RHOSTS_RE.findall(text):
        tok = next((g for g in m if g), "").strip().strip("\"';")
        if not tok or tok.lower().startswith("file:"):
            continue
        for part in re.split(r"[,\s]+", tok):
            part = part.strip().strip("\"';")
            if not part or part.lower().startswith("file:"):
                continue
            if part not in out:
                out.append(part)
    # LHOST callbacks are an egress path the lock must gate (P0: ``set LHOST
    # evil.com`` previously extracted to [] and check_targets_allowlist([])
    # returns True on empty input, so the callback sailed through).
    for host in _extract_msf_lhosts(text):
        if host not in out:
            out.append(host)
    for m in _MSF_PIVOT_RE.finditer(text):
        for g in m.groups():
            if g:
                tok = g.strip().strip("\"';")
                if tok and tok not in out:
                    out.append(tok)
    return out


def check_targets_allowlist(targets: list[str], config: dict[str, Any] | None) -> tuple[bool, str]:
    """Return (allowed, reason) for a list of hosts.

    Same enforcement rule as :func:`_check_allowlist`: the lock enforces
    whenever any authorization material exists; a fully empty union stays
    fail-closed when the flag demands an explicit allowlist, permissive
    otherwise. Env widening is named in the reason.
    """
    exploit_cfg = (config or {}).get("exploit", {})
    require = bool(exploit_cfg.get("require_explicit_allowlist", False))
    allowed_targets = _allowed_target_list(config)
    if not allowed_targets:
        if require:
            return False, "require_explicit_allowlist is True but allowed_targets is empty"
        return True, "no allowlist configured"
    for t in targets:
        if not t:
            continue
        if not is_target_in_allowlist(t, list(allowed_targets)):
            return False, (
                f"Host {t} is not in the explicit allowlist. "
                f"Add it to config.yaml exploit.allowed_targets to authorize."
                f"{_env_widening_note(config)}"
            )
    return True, f"all named hosts in allowlist{_env_widening_note(config)}"


# H4: scanner verbs whose positional arguments are the scan targets.
# ``command_analyzer._NETVERB_HOST_RE`` covers ssh/nc/curl/... but omits scanners
# (nmap/masscan/rustscan/...), so a bare hostname/CIDR/FQDN target after a
# scanner would slip past the allowlist gate. The old single-regex approach
# treated every ``-flag`` as value-less, so a space-separated value flag like
# nmap ``-p 445,139,135,389`` had its *port list* captured as the "target" and
# the whole command was blocked even when the real target was authorized. The
# argv-walk below fixes that.
_SCANNER_VERBS = {
    "nmap",
    "masscan",
    "rustscan",
    "nikto",
    "nuclei",
    "gobuster",
    "feroxbuster",
    "sqlmap",
    "smbclient",
    "enum4linux",
    "hydra",
    "whatweb",
    "wpscan",
    "dirb",
    "dirbuster",
    "amass",
    "sublist3r",
}

# Flags whose space-separated value is a dotted/host-shaped token that is NOT
# the scan target -- output files (-oN scan.txt), wordlists (-w rockyou.txt),
# exclude/include files (-iL/--excludefile), request/config files, the source
# IP (-S), and the proxy. Skipping their value prevents a dotted filename or a
# source IP from being mistaken for the target.
_SCANNER_VALUE_FLAGS = {
    "-o",
    "--output",
    "-oN",
    "-oX",
    "-oG",
    "-oA",
    "-oS",
    "-oM",
    "--output-file",
    "-w",
    "--wordlist",
    "-iL",
    "--excludefile",
    "--includefile",
    "-r",
    "--request-file",
    "-c",
    "--config-file",
    "--config",
    "-L",
    "-P",
    "--proxy",
    "--proxy-file",
    "--auth-file",
    "-S",
    "--source-ip",
}

_SHELL_SEPARATORS = {"|", ";", "&&", "||", ">", "<", ">>", "2>", "&"}


def _scanner_token_is_host(token: str) -> bool:
    """True if ``token`` is host-shaped and thus a plausible scan target."""
    if not token:
        return False
    if validate_target(token):
        return True
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        pass
    if token.startswith("*."):
        rest = token[2:]
        return bool(rest) and is_fqdn(rest)
    return False


def _is_scanner_verb_token(token: str) -> bool:
    """True if ``token`` invokes a scanner (basename-aware)."""
    base = token.replace("\\", "/").split("/")[-1]
    return base.lower() in _SCANNER_VERBS


def _extract_scanner_targets(command: str) -> list[str]:
    """Extract host-shaped scan-target tokens from a scanner command (Phase 3 move).

    Verbatim from ``tools.mcp_tools.registry._extract_scanner_targets``.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    targets: list[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        if _is_scanner_verb_token(tokens[i]):
            i += 1
            while i < n:
                t = tokens[i]
                if t in _SHELL_SEPARATORS or _is_scanner_verb_token(t):
                    break
                if t.startswith("-"):
                    if t in _SCANNER_VALUE_FLAGS and i + 1 < n:
                        i += 2
                        continue
                    i += 1
                    continue
                if _scanner_token_is_host(t) and t not in targets:
                    targets.append(t)
                i += 1
            continue
        i += 1
    return targets
