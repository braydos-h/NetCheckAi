"""Provenance-aware discovered-target store — hostname-tied IP authorization.

Problem: :func:`tools.kernel.allowlist.add_discovered_target` used to append
a discovered hostname's resolved IP to ``EXPLOIT_DISCOVERED_TARGETS`` as a
bare, globally reusable entry. Authorizing ``allowed.example.com`` therefore
silently authorized its resolved shared-hosting/CDN IP for *any* use — an
unrelated co-hosted site (or a later DNS change re-pointing that IP) inherited
the authorization with no trace of where it came from.

This module keeps the provenance instead: every hostname → address mapping
records *which hostname* it came from, *when* it was resolved, a TTL/expiry,
and the *source/reason*. A resolved IP is then usable only:

- bare, when the IP itself is explicitly allowlisted (config
  ``exploit.allowed_targets`` / ``EXPLOIT_TARGET_IP`` / CIDR), or
- tied to its hostname — via :func:`is_pair_authorized` (structured tools
  that take an IP + hostname pair, e.g. vhost enumeration with a ``Host:``
  header) or via the sandbox policy, which resolves each authorized hostname
  host-side and authorizes exactly those addresses with the mapping recorded.

Entries expire (default ``DISCOVERY_TTL_S``); expired entries authorize
nothing until re-recorded, so DNS changes and stale resolutions fail closed
instead of lingering as permanent process-global authorization. The store is
in-process and lock-guarded; ``EXPLOIT_DISCOVERED_TARGETS`` remains the
cross-process transport but now carries hostnames only, never raw IPs.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from typing import Any

# Default lifetime of a hostname → address mapping. Short enough that a DNS
# change stops authorizing the old address promptly; long enough that a
# campaign doesn't re-enumerate every few minutes. The sandbox policy
# re-resolves host-side on every policy build regardless of this TTL.
DISCOVERY_TTL_S = 600.0

# Hard cap so a runaway enumerator cannot grow the store without bound; the
# oldest entries are evicted first.
_MAX_ENTRIES = 5000


@dataclass
class DiscoveredHost:
    """One authorized hostname and the addresses it resolved to."""

    hostname: str
    addresses: tuple[str, ...] = ()
    resolved_at: float = field(default_factory=time.monotonic)
    ttl_seconds: float = DISCOVERY_TTL_S
    source: str = ""
    reason: str = ""

    def fresh(self, now: float | None = None) -> bool:
        """True when the entry has not yet expired."""
        return (now if now is not None else time.monotonic()) - self.resolved_at < self.ttl_seconds

    def audit_row(self) -> dict[str, Any]:
        """Secret-free audit representation of this entry."""
        return {
            "hostname": self.hostname,
            "addresses": list(self.addresses),
            "resolved_at": self.resolved_at,
            "ttl_seconds": self.ttl_seconds,
            "source": self.source,
            "reason": self.reason,
        }


_STORE: dict[str, DiscoveredHost] = {}
_LOCK = threading.Lock()


def _normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def record_discovered_host(
    hostname: str,
    addresses: str | list[str] | tuple[str, ...] | None,
    *,
    source: str = "",
    reason: str = "",
    ttl_seconds: float = DISCOVERY_TTL_S,
) -> DiscoveredHost | None:
    """Record (or refresh) a hostname → addresses mapping. Never raises.

    Only syntactically valid IP literals are stored; anything else is
    dropped. Re-recording a hostname *replaces* its address set (so a DNS
    change revokes the old address) and refreshes the timestamp. Returns the
    entry, or None when the hostname itself is invalid.
    """
    from tools.validation_utils import is_fqdn

    if not hostname or not isinstance(hostname, str):
        return None
    host = _normalize_hostname(hostname)
    if not is_fqdn(host):
        return None
    if addresses is None:
        addrs: list[str] = []
    elif isinstance(addresses, str):
        addrs = [addresses]
    else:
        addrs = list(addresses)
    clean: list[str] = []
    for addr in addrs:
        if not isinstance(addr, str):
            continue
        addr = addr.strip().split("%")[0]
        if not addr or addr in clean:
            continue
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            continue
        clean.append(addr)
    entry = DiscoveredHost(
        hostname=host,
        addresses=tuple(clean),
        resolved_at=time.monotonic(),
        ttl_seconds=max(1.0, float(ttl_seconds)),
        source=source or "",
        reason=reason or "",
    )
    with _LOCK:
        if host not in _STORE and len(_STORE) >= _MAX_ENTRIES:
            # Evict the stalest entry first — bounded growth, no exceptions.
            oldest = min(_STORE.values(), key=lambda e: e.resolved_at)
            _STORE.pop(oldest.hostname, None)
        _STORE[host] = entry
    return entry


def get_discovered_host(hostname: str) -> DiscoveredHost | None:
    """Return the *fresh* entry for ``hostname``, else None. Never raises."""
    if not hostname or not isinstance(hostname, str):
        return None
    with _LOCK:
        entry = _STORE.get(_normalize_hostname(hostname))
        if entry is None or not entry.fresh():
            return None
        return entry


def resolved_ips_for_host(hostname: str) -> tuple[str, ...]:
    """Fresh resolved addresses for ``hostname`` (empty when none/expired)."""
    entry = get_discovered_host(hostname)
    return entry.addresses if entry else ()


def is_pair_authorized(ip: str, hostname: str, *, allowed: list[str] | None = None) -> bool:
    """True when ``ip`` may be used in a context tied to ``hostname``.

    Either the IP itself is explicitly allowlisted (via ``allowed``, matched
    with the shared :func:`is_target_in_allowlist` matcher — CIDR/wildcard
    aware), or a fresh provenance entry ties the IP to the hostname. An
    expired entry, an unknown hostname, or an IP the hostname never resolved
    to all return False. Never raises.
    """
    from tools.validation_utils import is_target_in_allowlist

    if not ip or not hostname or not isinstance(ip, str) or not isinstance(hostname, str):
        return False
    ip = ip.strip().split("%")[0]
    host = _normalize_hostname(hostname)
    if not ip or not host:
        return False
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    if allowed and is_target_in_allowlist(ip, allowed):
        return True
    entry = get_discovered_host(host)
    return entry is not None and ip in entry.addresses


def snapshot() -> list[dict[str, Any]]:
    """Secret-free audit snapshot of all fresh entries, oldest first."""
    with _LOCK:
        entries = [e for e in _STORE.values() if e.fresh()]
    entries.sort(key=lambda e: e.resolved_at)
    return [e.audit_row() for e in entries]


def clear_discovered() -> None:
    """Drop all provenance entries (run boundaries, tests)."""
    with _LOCK:
        _STORE.clear()
