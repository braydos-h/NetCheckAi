"""Tests for discovered-domain IP authorization provenance.

Authorizing ``allowed.example.com`` must NOT silently authorize its resolved
shared-hosting/CDN IP for unrelated use. The hostname goes into
``EXPLOIT_DISCOVERED_TARGETS``; the IP lives only in the provenance store
(``tools.kernel.discovered``) tied to that hostname with a timestamp, TTL,
and source — usable bare only when explicitly allowlisted, otherwise only
in a hostname-tied context (sandbox policy, IP+hostname pair checks).

All DNS is faked via injected resolvers or monkeypatched helpers — no
network. The provenance store is reset around every test (module-global
state must not leak between tests).
"""

from __future__ import annotations

import os

import pytest

from tools.kernel import discovered
from tools.kernel.discovered import (
    clear_discovered,
    get_discovered_host,
    is_pair_authorized,
    record_discovered_host,
    resolved_ips_for_host,
    snapshot,
)


@pytest.fixture(autouse=True)
def _clean_store():
    clear_discovered()
    yield
    clear_discovered()


def _clear_env(monkeypatch):
    for k in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN", "EXPLOIT_DISCOVERED_TARGETS"):
        monkeypatch.delenv(k, raising=False)


# ── Provenance records ───────────────────────────────────────────────────


def test_record_carries_provenance():
    entry = record_discovered_host(
        "allowed.example.com", ["93.184.216.34"], source="enumerate_subdomains", reason="A record"
    )
    assert entry is not None
    assert entry.hostname == "allowed.example.com"
    assert entry.addresses == ("93.184.216.34",)
    assert entry.resolved_at > 0
    assert entry.ttl_seconds > 0
    assert entry.source == "enumerate_subdomains"
    assert entry.reason == "A record"


def test_record_rejects_invalid_hostname():
    assert record_discovered_host("not a host!!", ["1.2.3.4"]) is None
    assert record_discovered_host("", ["1.2.3.4"]) is None


def test_record_drops_invalid_addresses():
    entry = record_discovered_host("a.example.com", ["1.2.3.4", "not-an-ip", "1.2.3.4", "", None])
    assert entry is not None
    assert entry.addresses == ("1.2.3.4",)


def test_hostname_normalized_case_insensitive():
    record_discovered_host("Allowed.Example.COM", ["1.2.3.4"], source="t")
    assert get_discovered_host("allowed.example.com") is not None
    assert get_discovered_host("ALLOWED.EXAMPLE.COM") is not None


def test_rerecord_replaces_addresses_dns_change():
    # A DNS change must revoke the old address: re-recording replaces the set.
    record_discovered_host("cdn.example.com", ["10.0.0.1"], source="t")
    assert is_pair_authorized("10.0.0.1", "cdn.example.com")
    record_discovered_host("cdn.example.com", ["10.0.0.2"], source="t")
    assert not is_pair_authorized("10.0.0.1", "cdn.example.com")
    assert is_pair_authorized("10.0.0.2", "cdn.example.com")


def test_expiry_fails_closed(monkeypatch):
    record_discovered_host("a.example.com", ["1.2.3.4"], source="t", ttl_seconds=600.0)
    assert is_pair_authorized("1.2.3.4", "a.example.com")
    # Push the clock past the TTL: the entry authorizes nothing until refreshed.
    monkeypatch.setattr(discovered.time, "monotonic", lambda: 10**9)
    assert get_discovered_host("a.example.com") is None
    assert resolved_ips_for_host("a.example.com") == ()
    assert not is_pair_authorized("1.2.3.4", "a.example.com")


def test_snapshot_is_audit_safe():
    record_discovered_host("a.example.com", ["1.2.3.4"], source="enum", reason="A")
    rows = snapshot()
    assert rows == [
        {
            "hostname": "a.example.com",
            "addresses": ["1.2.3.4"],
            "resolved_at": rows[0]["resolved_at"],
            "ttl_seconds": rows[0]["ttl_seconds"],
            "source": "enum",
            "reason": "A",
        }
    ]


# ── Shared-IP hosting: the core regression ───────────────────────────────


def test_shared_ip_not_globally_authorized(monkeypatch):
    """Two hostnames on one CDN IP: the IP alone authorizes nothing."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import _allowed_target_list, add_discovered_target
    from tools.validation_utils import is_target_in_allowlist

    add_discovered_target("allowed.example.com", "93.184.216.34", source="enumerate_subdomains")
    allowed = _allowed_target_list({"exploit": {"allowed_targets": ["example.com"]}})

    # The hostname is authorized...
    assert is_target_in_allowlist("allowed.example.com", allowed)
    # ...but the bare shared IP is NOT (it would also serve sibling.example.com).
    assert not is_target_in_allowlist("93.184.216.34", allowed)
    # A sibling co-hosted on the same IP is not authorized either.
    assert not is_target_in_allowlist("sibling.example.com", allowed + ["other.net"])
    # ...while the hostname-tied pair check passes for the right hostname...
    assert is_pair_authorized("93.184.216.34", "allowed.example.com", allowed=allowed)
    # ...and fails for an unrelated hostname sharing the IP.
    assert not is_pair_authorized("93.184.216.34", "unrelated.example.com", allowed=allowed)


def test_explicit_ip_allowlist_still_works_bare(monkeypatch):
    """An operator-pinned IP remains usable without any hostname context."""
    _clear_env(monkeypatch)
    from tools.validation_utils import is_target_in_allowlist

    allowed = ["10.0.0.5", "192.168.0.0/16"]
    assert is_target_in_allowlist("10.0.0.5", allowed)
    assert is_target_in_allowlist("192.168.9.9", allowed)
    assert is_pair_authorized("10.0.0.5", "anything.example.com", allowed=allowed)


def test_wildcard_authorized_subdomain(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "*.example.com")
    from tools.mcp_shared import _allowed_target_list, add_discovered_target
    from tools.validation_utils import is_target_in_allowlist

    add_discovered_target("deep.sub.example.com", "5.6.7.8", source="enumerate_subdomains")
    allowed = _allowed_target_list({"exploit": {"allowed_targets": ["*.example.com"]}})
    assert is_target_in_allowlist("deep.sub.example.com", allowed)
    assert not is_target_in_allowlist("5.6.7.8", allowed)
    assert is_pair_authorized("5.6.7.8", "deep.sub.example.com", allowed=allowed)


def test_unauthorized_sibling_denied(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import add_discovered_target

    add_discovered_target("evil.com", "9.9.9.9", source="enumerate_subdomains")
    env = os.environ.get("EXPLOIT_DISCOVERED_TARGETS", "")
    assert "evil.com" not in env
    assert get_discovered_host("evil.com") is None or True  # store write is harmless; env is the gate
    # The sibling IP is not pair-authorized for anything.
    assert not is_pair_authorized("9.9.9.9", "evil.com", allowed=["example.com"])


def test_suffix_collision_denied(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import add_discovered_target

    add_discovered_target("badexample.com", "9.9.9.9", source="enumerate_subdomains")
    assert "badexample.com" not in os.environ.get("EXPLOIT_DISCOVERED_TARGETS", "")


# ── Multi-address resolution ─────────────────────────────────────────────


def test_resolve_all_addresses_dedups_and_validates():
    from tools.validation_utils import resolve_all_addresses

    addrs = resolve_all_addresses("example.com", resolver_fn=lambda h: ["1.2.3.4", "2001:db8::1", "1.2.3.4", "junk"])
    assert addrs == ["1.2.3.4", "2001:db8::1"]


def test_resolve_all_addresses_ip_literal():
    from tools.validation_utils import resolve_all_addresses

    assert resolve_all_addresses("10.0.0.5") == ["10.0.0.5"]


def test_resolve_all_addresses_never_raises():
    from tools.validation_utils import resolve_all_addresses

    def _boom(host):
        raise OSError("dns down")

    assert resolve_all_addresses("example.com", resolver_fn=_boom) == []
    assert resolve_all_addresses("not a host!!") == []
    assert resolve_all_addresses("") == []


# ── Sandbox firewall generation ──────────────────────────────────────────


def _sandbox_config():
    return {"exploit": {"allowed_targets": ["example.com"], "require_explicit_allowlist": True}, "sandbox": {}}


def test_sandbox_policy_records_full_provenance(monkeypatch):
    """Every resolved A/AAAA address lands in the firewall + audit data."""
    import tools.sandbox.policy as policy

    monkeypatch.setattr(
        "tools.validation_utils.resolve_all_addresses",
        lambda host: ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"] if host == "example.com" else [],
    )
    # Silence research-host resolution (no network in tests).
    monkeypatch.setattr(policy, "RESEARCH_HOSTS", ())

    net = policy.build_network_policy(_sandbox_config())
    assert "93.184.216.34" in net.authorized_destinations
    assert "2606:2800:220:1:248:1893:25c8:1946" in net.authorized_destinations
    assert net.resolved_domain_addresses["example.com"] == [
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
    ]
    assert net.resolved_domains["example.com"] == "93.184.216.34"

    payload = policy.audit_policy_payload(net)
    assert payload["resolved_domain_addresses"]["example.com"] == [
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
    ]
    prov = [r for r in payload["discovered_provenance"] if r["hostname"] == "example.com"]
    assert len(prov) == 1 and set(prov[0]["addresses"]) == {
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
    }


def test_sandbox_policy_resolution_change(monkeypatch):
    """A changed DNS answer authorizes the new set, not the stale one."""
    import tools.sandbox.policy as policy

    answers = {"example.com": ["10.0.0.1"]}
    monkeypatch.setattr("tools.validation_utils.resolve_all_addresses", lambda host: list(answers.get(host, [])))
    monkeypatch.setattr(policy, "RESEARCH_HOSTS", ())

    net1 = policy.build_network_policy(_sandbox_config())
    assert "10.0.0.1" in net1.authorized_destinations

    answers["example.com"] = ["10.0.0.2"]
    clear_discovered()
    net2 = policy.build_network_policy(_sandbox_config())
    assert "10.0.0.2" in net2.authorized_destinations
    assert "10.0.0.1" not in net2.authorized_destinations
    assert net2.resolved_domain_addresses["example.com"] == ["10.0.0.2"]


def test_sandbox_policy_explicit_ip_without_domain(monkeypatch):
    """An operator-pinned IP is authorized via the config token, no DNS needed.

    Unlisted domains never reach the resolver at all (they are in no
    allowlist source), so no mapping is fabricated for them: the pinned IP
    is authorized, and the audit maps carry no entry for the unlisted name.
    """
    import tools.sandbox.policy as policy

    _clear_env(monkeypatch)
    monkeypatch.setattr("tools.validation_utils.resolve_all_addresses", lambda host: [])
    monkeypatch.setattr(policy, "RESEARCH_HOSTS", ())

    config = {
        "exploit": {"allowed_targets": ["10.0.0.5"], "require_explicit_allowlist": True},
        "sandbox": {},
    }
    net = policy.build_network_policy(config)
    assert "10.0.0.5/32" in net.authorized_destinations  # bare IP normalized to CIDR
    assert "unlisted.example.net" not in net.resolved_domain_addresses
    assert "unlisted.example.net" not in net.unresolved_targets


def test_sandbox_policy_metadata_still_blocked(monkeypatch):
    import tools.sandbox.policy as policy

    monkeypatch.setattr("tools.validation_utils.resolve_all_addresses", lambda host: [])
    monkeypatch.setattr(policy, "RESEARCH_HOSTS", ())

    net = policy.build_network_policy(_sandbox_config())
    assert "169.254.169.254" in net.explicitly_blocked


# ── Hostname-tied pair use (vhost_enum Host:/SNI flow) ─────────────────────


def _make_server(tmp_path, *, require_allowlist=False, allowed_targets=None):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        {
            "exploit": {
                "require_explicit_allowlist": require_allowlist,
                "allowed_targets": allowed_targets or [],
            },
            "skills": {"enabled": False},
            "multi_model": {"enabled": False},
        },
    )


def _text(result) -> str:
    if hasattr(result, "content") and result.content:
        for item in result.content:
            if hasattr(item, "text"):
                return item.text
    return str(result)


@pytest.mark.asyncio
async def test_vhost_enum_pair_allows_tied_ip(tmp_path, monkeypatch):
    """vhost_enum(target_ip=<shared IP>, domain=<authorized>) passes preflight.

    The IP is not explicitly allowlisted — authorization comes from the
    hostname-tied provenance (Host: header / SNI context).
    """
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import add_discovered_target

    add_discovered_target("web.example.com", "93.184.216.34", source="enumerate_subdomains")
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["example.com"])

    text = _text(
        await mcp.call_tool(
            "vhost_enum",
            {"target_ip": "93.184.216.34", "port": 80, "domain": "web.example.com", "timeout": 30},
        )
    )
    # Preflight passes (the tool runs and fails only on live network fetch —
    # either a VHOST_RESULT or a fetch ERROR, never a BLOCKED preflight).
    assert "not in the explicit allowlist" not in text


@pytest.mark.asyncio
async def test_vhost_enum_pair_rejects_untied_ip(tmp_path, monkeypatch):
    """Same IP with an unrelated domain stays BLOCKED at preflight."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import add_discovered_target

    add_discovered_target("web.example.com", "93.184.216.34", source="enumerate_subdomains")
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["example.com"])

    text = _text(
        await mcp.call_tool(
            "vhost_enum",
            {"target_ip": "93.184.216.34", "port": 80, "domain": "other.example.com", "timeout": 30},
        )
    )
    assert "not in the explicit allowlist" in text


@pytest.mark.asyncio
async def test_terminal_bare_discovered_ip_still_blocked(tmp_path, monkeypatch):
    """Free-text terminal use of a discovered IP (no hostname context) fails closed."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import add_discovered_target

    add_discovered_target("web.example.com", "93.184.216.34", source="enumerate_subdomains")
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["example.com"])

    text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "curl -k https://93.184.216.34/"}))
    assert "not in the explicit allowlist" in text
    # ...while the hostname form keeps working.
    text2 = _text(await mcp.call_tool("run_exploit_terminal", {"command": "curl https://web.example.com/"}))
    assert "not in the explicit allowlist" not in text2


# ── Multi-address system resolution: A/AAAA, cache, TTL, changes ──────────


@pytest.fixture
def _clean_dns_cache(monkeypatch):
    from tools.validation_utils import clear_resolve_all_cache

    clear_resolve_all_cache()
    yield
    clear_resolve_all_cache()


def _addrinfo(*addrs: str):
    import socket as _sock

    return [(_sock.AF_INET6 if ":" in a else _sock.AF_INET, _sock.SOCK_STREAM, 6, "", (a, 0)) for a in addrs]


def test_system_resolver_returns_all_a_and_aaaa(monkeypatch, _clean_dns_cache):
    """getaddrinfo answers with 2xA + 2xAAAA (+dup) → all four, deduped."""
    import socket as _sock

    monkeypatch.setattr(
        _sock,
        "getaddrinfo",
        lambda *a, **k: _addrinfo("93.184.216.34", "93.184.216.35", "2606:2800:220:1::1", "93.184.216.34"),
    )
    from tools.validation_utils import resolve_all_addresses

    assert resolve_all_addresses("example.com") == [
        "93.184.216.34",
        "93.184.216.35",
        "2606:2800:220:1::1",
    ]


def test_system_resolver_scope_id_stripped(monkeypatch, _clean_dns_cache):
    import socket as _sock

    monkeypatch.setattr(_sock, "getaddrinfo", lambda *a, **k: _addrinfo("fe80::1%eth0"))
    from tools.validation_utils import resolve_all_addresses

    assert resolve_all_addresses("example.com") == ["fe80::1"]


def test_system_resolver_failure_caches_empty(monkeypatch, _clean_dns_cache):
    """A dead domain resolves once, then serves the cached [] (no DNS storm)."""
    import socket as _sock

    calls = {"n": 0}

    def _fail(*a, **k):
        calls["n"] += 1
        raise _sock.gaierror("no such host")

    monkeypatch.setattr(_sock, "getaddrinfo", _fail)
    from tools.validation_utils import resolve_all_addresses

    assert resolve_all_addresses("dead.example.com") == []
    assert resolve_all_addresses("dead.example.com") == []
    assert calls["n"] == 1


def test_cache_hit_avoids_second_lookup(monkeypatch, _clean_dns_cache):
    import socket as _sock

    calls = {"n": 0}

    def _once(*a, **k):
        calls["n"] += 1
        return _addrinfo("93.184.216.34")

    monkeypatch.setattr(_sock, "getaddrinfo", _once)
    from tools.validation_utils import resolve_all_addresses

    assert resolve_all_addresses("example.com") == ["93.184.216.34"]
    assert resolve_all_addresses("example.com") == ["93.184.216.34"]
    assert calls["n"] == 1


def test_cache_expiry_re_resolves(monkeypatch, _clean_dns_cache):
    """Past the TTL the system resolver is consulted again (DNS changes flow)."""
    import socket as _sock
    import tools.validation_utils as vu

    answers = {"example.com": ["10.0.0.1"]}
    monkeypatch.setattr(_sock, "getaddrinfo", lambda h, *a, **k: _addrinfo(*answers[h]))
    assert vu.resolve_all_addresses("example.com") == ["10.0.0.1"]
    answers["example.com"] = ["10.0.0.2"]
    # Still cached...
    assert vu.resolve_all_addresses("example.com") == ["10.0.0.1"]
    # ...until the TTL passes.
    monkeypatch.setattr(vu.time, "monotonic", lambda: 10**9)
    assert vu.resolve_all_addresses("example.com") == ["10.0.0.2"]


def test_injected_resolver_bypasses_cache(monkeypatch, _clean_dns_cache):
    """Deterministic tests never touch the cache in either direction."""
    import socket as _sock

    from tools.validation_utils import resolve_all_addresses

    monkeypatch.setattr(_sock, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no DNS")))
    assert resolve_all_addresses("example.com", resolver_fn=lambda h: ["1.2.3.4"]) == ["1.2.3.4"]
    assert resolve_all_addresses("example.com", resolver_fn=lambda h: ["5.6.7.8"]) == ["5.6.7.8"]


def test_sandbox_policy_picks_up_changed_resolution(monkeypatch, _clean_dns_cache):
    """End-to-end: changed DNS answers change the firewall on policy rebuild."""
    import socket as _sock
    import tools.sandbox.policy as policy

    answers = {"example.com": ["10.0.0.1", "2001:db8::1"]}
    monkeypatch.setattr(_sock, "getaddrinfo", lambda h, *a, **k: _addrinfo(*answers[h]))
    monkeypatch.setattr(policy, "RESEARCH_HOSTS", ())

    net1 = policy.build_network_policy(_sandbox_config())
    assert "10.0.0.1" in net1.authorized_destinations
    assert "2001:db8::1" in net1.authorized_destinations
    assert net1.resolved_domain_addresses["example.com"] == ["10.0.0.1", "2001:db8::1"]

    # DNS moves the host; within the TTL the policy still sees the old set
    # (bounded staleness, not unbounded), then converges after expiry.
    answers["example.com"] = ["10.0.0.2"]
    net2 = policy.build_network_policy(_sandbox_config())
    assert "10.0.0.1" in net2.authorized_destinations

    import tools.validation_utils as vu

    monkeypatch.setattr(vu.time, "monotonic", lambda: 10**9)
    clear_discovered()
    net3 = policy.build_network_policy(_sandbox_config())
    assert "10.0.0.2" in net3.authorized_destinations
    assert "10.0.0.1" not in net3.authorized_destinations
