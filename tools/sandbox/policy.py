"""Sandbox network-authorization policy: who may the worker talk to?

The application layer (``_target_lock_block``, ``@require_allowlist``,
destination parsing) stays active as defense-in-depth, but it is NOT the
containment boundary: this module derives the concrete IP/CIDR allow set from
the same allowlist sources and hands it to ``tools/sandbox/network.py`` which
installs a default-DROP firewall inside the worker netns. The policy is
independent of the command string -- ``python exploit.py`` with no visible
destination cannot gain internet access.

DNS is controlled, never a bypass: authorized domains are resolved HOST-SIDE
here, validated against the allowlist, the resolved IPs are added to the
allowlist, and the mapping is recorded in the audit trail. In-container
resolvers only whitelist-mode DNS ("controlled" = docker embedded resolver via
loopback; \"none\" = DNS fully blocked).
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from tools.kernel.allowlist import _allowed_target_list
from tools.sandbox.models import NetworkPolicy
from tools.validation_utils import is_fqdn

logger = logging.getLogger(__name__)

__all__ = [
    "METADATA_DESTINATIONS",
    "RESEARCH_HOSTS",
    "build_network_policy",
    "authorize_destinations",
]

# Cloud-metadata / link-local destinations always denied. Implicit in the
# default-DROP ruleset but enforced explicitly so policy audits show it.
METADATA_DESTINATIONS = [
    "169.254.169.254",  # AWS/GCP/Azure IMDS
    "169.254.0.0/16",  # RFC3927 link-local (incl. metadata)
    "fd00:ec2::254",  # AWS IMDS IPv6
    "100.100.100.200",  # Alibaba metadata
    "fe80::/10",  # IPv6 link-local
]

# Targets that mean "everywhere" when they appear in the allowlist; a sandbox
# policy cannot express them safely, so they are rejected by build_network_policy.
_AUTHORIZE_ALL_TOKENS = {"0.0.0.0/0", "::/0", "*", "any", "all"}

# Pinned exploit-research egress: the exploit workflow depends on pulling PoC/
# tool repos and reading public advisories. When ``network.allow_research_hosts``
# is true (default) these DOMAINS are resolved HOST-SIDE (through the same
# controlled-DNS machinery) and their resolved IPs are added to the firewall
# authorization. It is a fixed, auditable list -- never a hostname wildcard,
# never user data. If resolution yields nothing, the host simply is not
# authorized (that fetch fails closed; no dynamic DNS in the worker).
RESEARCH_HOSTS = (
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "gitlab.com",
)


def build_network_policy(config: dict[str, Any] | None, *, gateway: str = "") -> NetworkPolicy:
    """Derive the concrete egress allowlist from the effective target allowlist.

    Every allowlist entry is one of: IP, CIDR, FQDN (resolved host-side here),
    ``*.wildcard`` domain (only its *dynamically discovered, separately
    authorized* resolved IPs apply -- the wildcard itself adds nothing), or
    ``localhost``/``127.0.0.1`` (sandbox loopback only unless
    ``sandbox.network.map_host_loopback`` is explicitly true, in which case the
    network gateway is added as the dev host-loopback mapping -- never silent).

    Raises ValueError for targets the policy cannot express safely (``0.0.0.0/0``
    etc.) so the caller fail-closes instead of authorizing the internet.
    """
    from tools.config.schema import CONFIG_SCHEMA

    sandbox_cfg = (config or {}).get("sandbox") or {}
    defaults = (CONFIG_SCHEMA.get("sandbox") or {}).get("network") or {}
    network_cfg = {**(defaults or {}), **(sandbox_cfg.get("network") or {})}
    map_loopback = bool(network_cfg.get("map_host_loopback", False))
    extra_cidrs = [
        str(c).strip() for c in (network_cfg.get("extra_allow_cidrs") or []) if isinstance(c, str) and str(c).strip()
    ]
    allow_dns = str(network_cfg.get("allow_dns", "controlled") or "controlled").strip().lower()
    if allow_dns not in ("controlled", "none"):
        allow_dns = "controlled"

    explicit_blocks = list(METADATA_DESTINATIONS)
    authorized: list[str] = []
    resolved_domains: dict[str, str] = {}
    resolved_domain_addresses: dict[str, list[str]] = {}
    unresolved: list[str] = []

    loopback_hits = False
    for token in _allowed_target_list(config):
        tok = str(token).strip()
        if not tok:
            continue
        low = tok.lower()
        if low in _AUTHORIZE_ALL_TOKENS:
            raise ValueError(f"target {tok!r} authorizes all destinations; the sandbox policy refuses to express it")
        if low in ("localhost", "127.0.0.1", "::1"):
            loopback_hits = True
            continue  # sandbox loopback is always usable (lo interface)
        # CIDR?
        try:
            network = ipaddress.ip_network(tok, strict=False)
            if network.prefixlen == 0:
                raise ValueError(f"target {tok!r} authorizes all destinations; sandbox policy refuses it")
            _append_unique(authorized, str(network))
            continue
        except ValueError as exc:
            if "refuses it" in str(exc) or "refuses to express" in str(exc):
                raise
        # Bare IP?
        try:
            ipaddress.ip_address(tok)
            _append_unique(authorized, tok)
            continue
        except ValueError:
            pass
        # Wildcard domain: no static authorization (resolved hosts arrive via
        # EXPLOIT_DISCOVERED_TARGETS and are picked up on policy refresh).
        if tok.startswith("*."):
            unresolved.append(tok)
            continue
        # FQDN: resolve host-side (ALL A/AAAA addresses), validate against
        # the allowlist, record the full hostname-tied mapping. This is the
        # hostname-tied context: these IPs are authorized *because* they are
        # the current resolution of this specific authorized hostname, and
        # the provenance (hostname, addresses, timestamp, source) is recorded
        # for the audit trail — never as bare reusable entries.
        if is_fqdn(tok):
            resolved = _resolve_authorized(tok, config)
            for ip in resolved:
                _append_unique(authorized, ip)
            if resolved:
                resolved_domains[tok] = resolved[0]
                resolved_domain_addresses[tok] = list(resolved)
            else:
                unresolved.append(tok)
            continue
        # Unknown shape: record as unresolved so audits show what was NOT authorized.
        unresolved.append(tok)

    if extra_cidrs:
        for cidr in extra_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                logger.warning("sandbox extra_allow_cidrs ignored (invalid): %s", cidr)
                continue
            _append_unique(authorized, cidr)

    if map_loopback and loopback_hits and gateway:
        _append_unique(authorized, gateway)

    if bool(network_cfg.get("allow_research_hosts", True)):
        for host in RESEARCH_HOSTS:
            ips = _resolve_authorized(host, config, _skip_allowlist=True)
            for ip in ips:
                _append_unique(authorized, ip)
            if ips:
                resolved_domains[host] = ips[0]
                resolved_domain_addresses[host] = list(ips)
            else:
                unresolved.append(f"{host} (unresolved at policy build)")

    # Controlled DNS: docker's embedded resolver listens on the container's
    # loopback (127.0.0.11); loopback ACCEPT covers it. In "none" mode
    # network.py adds explicit REJECT rules for port 53 (incl. lo) so no DNS
    # bypass exists.
    dns_servers = ["127.0.0.11"] if allow_dns == "controlled" else []

    return NetworkPolicy(
        authorized_destinations=authorized,
        explicitly_blocked=explicit_blocks,
        allow_dns=allow_dns,
        dns_servers=dns_servers,
        resolved_domains=resolved_domains,
        resolved_domain_addresses=resolved_domain_addresses,
        unresolved_targets=unresolved,
        enforced=bool(network_cfg.get("enforce", True)),
    )


def _append_unique(lst: list[str], value: str) -> None:
    if value not in lst:
        lst.append(value)


def _resolve_authorized(domain: str, config: dict[str, Any] | None, *, _skip_allowlist: bool = False) -> list[str]:
    """Resolve a domain host-side and return ALL its allowed IPs (A+AAAA).

    Uses :func:`tools.validation_utils.resolve_all_addresses` (system
    resolver, never raises) so every current address of an authorized
    hostname is considered — a single first-A-record lookup would silently
    drop IPv6 / round-robin siblings.

    Callers only pass operator-authorized hostnames here: union tokens from
    :func:`_allowed_target_list` (config ``allowed_targets`` + runtime
    target env, each gated at entry) or the pinned RESEARCH_HOSTS set
    (``_skip_allowlist=True`` — authorization comes from the fixed list, not
    the target allowlist). Unlisted domains never reach this function, so
    there is nothing further to validate against — and re-checking the
    domain against the union it came from would be a tautology.

    The full hostname-tied mapping is recorded in the provenance store
    (hostname, addresses, timestamp, source) so the audit trail shows *why*
    each firewall IP is authorized.
    """
    from tools.kernel.discovered import record_discovered_host
    from tools.validation_utils import resolve_all_addresses

    addrs = resolve_all_addresses(domain)
    if not addrs:
        return []
    record_discovered_host(domain, addrs, source="sandbox:policy")
    return list(addrs)


def authorize_destinations(destinations: list[str], config: dict[str, Any] | None) -> tuple[bool, str]:
    """Command-level scope decision for literal destinations (SANDBOX_SCOPE_DENIED).

    Defense-in-depth layer: the MCP tools' own ``_target_lock_block`` already
    string-gates; this re-checks the same extracted destinations against the
    effective allowlist using the SAME shared matcher. Fails closed on an empty
    allowlist when ``require_explicit_allowlist`` is true.
    """
    from tools.kernel.allowlist import check_targets_allowlist

    return check_targets_allowlist(destinations, config)


def audit_policy_payload(policy: NetworkPolicy) -> dict[str, Any]:
    """Sandbox-context dict for the audit trail (secret-free by construction)."""
    from tools.kernel.discovered import snapshot

    return {
        "authorized_destinations": list(policy.authorized_destinations),
        "explicitly_blocked": list(policy.explicitly_blocked),
        "allow_dns": policy.allow_dns,
        "resolved_domains": dict(policy.resolved_domains),
        "resolved_domain_addresses": {k: list(v) for k, v in policy.resolved_domain_addresses.items()},
        "discovered_provenance": snapshot(),
        "unresolved_targets": list(policy.unresolved_targets),
        "enforced": policy.enforced,
        "fingerprint": policy.fingerprint(),
    }
