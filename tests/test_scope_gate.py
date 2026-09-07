"""Tests for the scope gate module.

Covers:
- Exact domain matching
- Wildcard domain matching
- IP address matching
- CIDR matching
- Deny rule precedence
- Forbidden action detection
- Third-party asset detection
- Rate limit enforcement
"""

from __future__ import annotations

import time

import pytest

from db import DatabaseManager, _new_id
from scope_gate import (
    ScopeGate,
    _classify_target_type,
    _clean_asset,
    _is_third_party_asset,
)

# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    return db


@pytest.fixture
def scope_gate(temp_db):
    mid = _new_id("M")
    return ScopeGate(
        temp_db,
        mid,
        allowed_assets=["example.com", "*.example.com", "192.168.1.0/24", "10.0.0.1", "api.example.org"],
        disallowed_assets=["banned.example.com", "10.0.0.99"],
        forbidden_actions=["uncontrolled_fuzzing", "brute_force"],
        risk_profile="standard_authorized",
    )


# ── Asset classification ───────────────────────────────────────────────────


def test_classify_domain():
    assert _classify_target_type("example.com") == "domain"


def test_classify_wildcard():
    assert _classify_target_type("*.example.com") == "wildcard_domain"


def test_classify_ip():
    assert _classify_target_type("192.168.1.1") == "ip"


def test_classify_cidr():
    assert _classify_target_type("10.0.0.0/24") == "cidr"


# ── Rule matching ─────────────────────────────────────────────────────────


def test_exact_domain_match(scope_gate):
    result = scope_gate.check_scope("example.com", "recon", "nmap_scan", "low")
    assert result.allowed is True
    assert "example.com" in result.reason


def test_exact_domain_no_match(scope_gate):
    result = scope_gate.check_scope("evil.com", "recon", "nmap_scan", "low")
    assert result.allowed is False
    assert "not in the authorized scope" in result.reason.lower()


def test_wildcard_domain_match(scope_gate):
    result = scope_gate.check_scope("sub.example.com", "recon", "nmap_scan", "low")
    assert result.allowed is True


def test_wildcard_domain_nested(scope_gate):
    result = scope_gate.check_scope("deep.nested.example.com", "recon", "nmap_scan", "low")
    assert result.allowed is True


def test_ip_match(scope_gate):
    result = scope_gate.check_scope("10.0.0.1", "recon", "nmap_scan", "low")
    assert result.allowed is True


def test_cidr_match(scope_gate):
    result = scope_gate.check_scope("192.168.1.42", "recon", "nmap_scan", "low")
    assert result.allowed is True


def test_cidr_no_match(scope_gate):
    result = scope_gate.check_scope("192.168.2.1", "recon", "nmap_scan", "low")
    assert result.allowed is False


# ── Deny rule precedence ──────────────────────────────────────────────────


def test_deny_overrides_allow(scope_gate):
    # 10.0.0.99 is both in allowed_assets... wait, no — it's only in disallowed.
    # But if we add it as both, deny should win.
    result = scope_gate.check_scope("10.0.0.99", "recon", "nmap_scan", "low")
    assert result.allowed is False
    assert "out of scope" in result.reason.lower()


def test_deny_domain(scope_gate):
    result = scope_gate.check_scope("banned.example.com", "recon", "nmap_scan", "low")
    assert result.allowed is False


# ── Forbidden actions ─────────────────────────────────────────────────────


def test_hard_forbidden_action(scope_gate):
    result = scope_gate.check_scope("example.com", "denial_of_service", "any_tool", "low")
    assert result.allowed is False


def test_custom_forbidden_action(scope_gate):
    result = scope_gate.check_scope("example.com", "brute_force", "hydra", "high")
    assert result.allowed is False


def test_safe_action_allowed(scope_gate):
    result = scope_gate.check_scope("example.com", "recon", "nmap_scan", "low")
    assert result.allowed is True


# ── Asset cleaning ────────────────────────────────────────────────────────


def test_clean_asset_strips_http():
    assert _clean_asset("https://example.com/path?q=1") == "example.com"


def test_clean_asset_strips_port():
    assert _clean_asset("example.com:443") == "example.com"


def test_clean_asset_preserves_ip():
    assert _clean_asset("10.0.0.1") == "10.0.0.1"


# ── Rate limit ────────────────────────────────────────────────────────────


def test_rate_limit_enforced(scope_gate, monkeypatch):
    # Deterministic: fake monotonic clock, 20 calls spaced 10ms apart in a
    # 0.2s window with default 2 req/s -> exactly the first 2 pass.
    import scope_gate as _sg

    now = [1000.0]
    monkeypatch.setattr(_sg.time, "monotonic", lambda: now[0])
    allowed_count = 0
    for _ in range(20):
        result = scope_gate.check_scope("example.com", "recon", "nmap_scan", "low")
        if result.allowed:
            allowed_count += 1
        now[0] += 0.01
    assert allowed_count == 2


def test_rate_limit_resets_after_window(tmp_path):
    db = DatabaseManager(tmp_path / "rate.db")
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    mid = _new_id("M")
    gate = ScopeGate(
        db,
        mid,
        allowed_assets=["example.com"],
        rate_limits={"default_requests_per_second": 10},
    )
    # First call should pass
    result = gate.check_scope("example.com", "recon", "nmap_scan", "low")
    assert result.allowed is True
    # Many calls at high rate limit should all pass
    for _ in range(9):
        result = gate.check_scope("example.com", "recon", "nmap_scan", "low")
        assert result.allowed is True


# ── Risk level gating ────────────────────────────────────────────────────


def test_high_risk_requires_approval_in_standard(scope_gate):
    # scope_gate uses standard_authorized risk profile
    result = scope_gate.check_scope("example.com", "recon", "nmap_scan", "high")
    assert result.allowed is True
    assert result.requires_human_approval is True


def test_low_risk_no_approval(scope_gate):
    result = scope_gate.check_scope("example.com", "recon", "nmap_scan", "low")
    assert result.allowed is True
    assert result.requires_human_approval is False


# ── Edge cases ────────────────────────────────────────────────────────────


def test_empty_asset(scope_gate):
    result = scope_gate.check_scope("", "recon", "nmap_scan", "low")
    assert result.allowed is False


def test_very_long_asset(scope_gate):
    long_asset = "a" * 500 + ".example.com"
    result = scope_gate.check_scope(long_asset, "recon", "nmap_scan", "low")
    # Wildcard *.example.com matches any subdomain regardless of length
    assert result.allowed is True


def test_list_scope(scope_gate):
    scope = scope_gate.list_scope()
    assert "example.com" in scope["allow"]
    assert "*.example.com" in scope["allow"]
    assert "banned.example.com" in scope["deny"]


def test_is_asset_in_scope(scope_gate):
    assert scope_gate.is_asset_in_scope("example.com") is True
    assert scope_gate.is_asset_in_scope("evil.com") is False


# ── Substring blocklist vs planner phases (regression) ──────────────────────
#
# Before the fix, ``_HARD_FORBIDDEN_SUBSTRINGS`` included "exploit"/"attack"/
# "kill"/"fuzz". Because ``action_type`` is always a planner phase string
# (``planner.py`` emits ``phase="exploit"``; ``mission.py`` lists "exploit" as a
# valid testing_mode), those substrings hard-blocked Flow B's own legitimate
# exploit phase before risk-gating ever ran. The hard-forbidden *actions*
# (denial_of_service, destructive_exploit, ...) are still exact-matched against
# ``forbidden_action_strs`` and still present as substrings, so removing the
# four phase-name substrings only re-enables legitimate phases -- it does not
# weaken the destructive / DoS blocks.


@pytest.fixture
def high_auth_gate(temp_db):
    """A gate configured for high_authorized_testing with an in-scope asset."""
    mid = _new_id("M")
    return ScopeGate(
        temp_db,
        mid,
        allowed_assets=["10.0.0.50"],
        disallowed_assets=[],
        forbidden_actions=[],
        risk_profile="high_authorized_testing",
    )


def test_exploit_phase_allowed_under_high_auth(high_auth_gate):
    """Regression: the planner's exploit phase must not be hard-blocked."""
    result = high_auth_gate.check_scope("10.0.0.50", "exploit", "metasploit", "high")
    assert result.allowed is True, result.reason
    # High risk under high_authorized_testing needs no human approval.
    assert result.requires_human_approval is False


def test_attack_phase_allowed_under_high_auth(high_auth_gate):
    result = high_auth_gate.check_scope("10.0.0.50", "attack", "metasploit", "high")
    assert result.allowed is True, result.reason


@pytest.mark.parametrize("phase", ["recon", "test", "validate", "report", "analysis"])
def test_standard_phases_allowed(high_auth_gate, phase):
    result = high_auth_gate.check_scope("10.0.0.50", phase, "tool", "low")
    assert result.allowed is True, result.reason


def test_exploit_phase_routes_to_risk_gating_not_hard_block(temp_db):
    """Under standard_authorized, a high-risk exploit should be *allowed but
    flagged for human approval* -- not blanket-denied by a substring sweep."""
    gate = ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["10.0.0.50"],
        forbidden_actions=[],
        risk_profile="standard_authorized",
    )
    result = gate.check_scope("10.0.0.50", "exploit", "metasploit", "high")
    assert result.allowed is True, result.reason
    assert result.requires_human_approval is True


# ── Defense-in-depth preserved (the DoS/destructive substrings stay) ─────────


@pytest.mark.parametrize("action_type", ["dos", "overload", "crash", "saturate"])
def test_dos_family_substrings_still_blocked(high_auth_gate, action_type):
    result = high_auth_gate.check_scope("10.0.0.50", action_type, "tool", "low")
    assert result.allowed is False
    assert "dangerous" in result.reason.lower()


def test_destructive_exploit_still_blocked(high_auth_gate):
    """Removing the bare "exploit" substring must NOT weaken the destructive
    block -- "destructive_exploit" is its own kept substring AND a hard-forbidden
    action, so it blocks regardless of which gate fires first."""
    result = high_auth_gate.check_scope("10.0.0.50", "destructive_exploit", "tool", "low")
    assert result.allowed is False


def test_compound_action_with_dos_substring_blocked(high_auth_gate):
    """An action_type that merely *contains* a DoS substring is still blocked."""
    result = high_auth_gate.check_scope("10.0.0.50", "slow_dos_attack", "tool", "low")
    assert result.allowed is False


# ── IPv6 asset cleaning (H17 regression) ───────────────────────────────────
#
# Before the fix, ``_clean_asset`` ran ``rsplit(":", 1)`` on any string with a
# colon that did not start with ``[``. IPv6 literals contain multiple colons,
# so ``2001:db8::1`` was mangled into ``2001:db8::`` (dropping the final ``1``
# as a "port"), and ``[2001:db8::1]:443`` lost only the ``:443`` but kept its
# brackets -- neither result round-tripped through ``ipaddress.ip_address``.


def test_clean_asset_preserves_bare_ipv6():
    """A bare IPv6 literal must survive cleaning unchanged."""
    assert _clean_asset("2001:db8::1") == "2001:db8::1"


def test_clean_asset_preserves_bare_ipv6_loopback():
    assert _clean_asset("::1") == "::1"


def test_clean_asset_unbrackets_ipv6_with_port():
    """``[2001:db8::1]:443`` -> ``2001:db8::1`` (un-bracketed, port stripped)."""
    assert _clean_asset("[2001:db8::1]:443") == "2001:db8::1"


def test_clean_asset_unbrackets_ipv6_no_port():
    assert _clean_asset("[2001:db8::1]") == "2001:db8::1"


def test_clean_asset_strips_port_ipv4():
    """IPv4 host:port still strips the port (single-colon path)."""
    assert _clean_asset("example.com:443") == "example.com"


def test_clean_asset_strips_port_ipv4_address():
    assert _clean_asset("10.0.0.1:8080") == "10.0.0.1"


def test_clean_asset_preserves_ipv4_no_port():
    assert _clean_asset("10.0.0.1") == "10.0.0.1"


def test_clean_asset_ipv6_url_with_path_and_port():
    """A full https URL with a bracketed IPv6 + port + path cleans to the IP."""
    assert _clean_asset("https://[2001:db8::1]:443/path?q=1") == "2001:db8::1"


def test_clean_asset_bare_ipv6_round_trips_through_ipaddress():
    """The cleaned result must be a valid IPv6 address (not a truncated form)."""
    import ipaddress

    cleaned = _clean_asset("2001:db8::1")
    assert str(ipaddress.ip_address(cleaned)) == cleaned


def test_clean_asset_bracketed_ipv6_round_trips_through_ipaddress():
    import ipaddress

    cleaned = _clean_asset("[2001:db8::1]:443")
    assert str(ipaddress.ip_address(cleaned)) == cleaned


# ── Third-party detection anchored pattern (M30 regression) ─────────────────
#
# Before the fix, ``_is_third_party_asset`` did a substring scan over
# ``_THIRD_PARTY_DOMAINS`` -- ``"aws" in "laws.com"`` was True, so the innocent
# domain ``laws.com`` was flagged as third-party infrastructure. The anchored
# ``_THIRD_PARTY_PATTERN`` requires the known label to be a real DNS label
# (preceded by a label boundary), so substring false-positives are eliminated
# while real CDN hosts (``cdn.example.com``) are still flagged.


def test_is_third_party_asset_laws_com_is_not_third_party():
    """``laws.com`` contains the substring ``aws`` but is not AWS infra."""
    assert _is_third_party_asset("laws.com") is False


def test_is_third_party_asset_cdn_is_third_party():
    assert _is_third_party_asset("cdn.example.com") is True


def test_is_third_party_asset_cloudfront_label():
    assert _is_third_party_asset("img.cloudfront.net") is True


def test_is_third_party_asset_googleapis_label():
    assert _is_third_party_asset("www.googleapis.com") is True


def test_is_third_party_asset_plain_domain_is_not_third_party():
    assert _is_third_party_asset("example.com") is False


def test_is_third_party_asset_explicit_cdn_label_still_flagged():
    """The explicit ``cdn.`` label check is retained as belt-and-braces."""
    assert _is_third_party_asset("cdn.something.invalid") is True


def test_third_party_detection_in_scope_gate_does_not_flag_laws_com(temp_db):
    """End-to-end: ``laws.com`` is allowed into scope without being rejected
    as third-party infra (provided it has an explicit allow rule)."""
    gate = ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["laws.com"],
        risk_profile="standard_authorized",
    )
    result = gate.check_scope("laws.com", "recon", "nmap_scan", "low")
    assert result.allowed is True
    assert result.is_third_party is False


# ── default_rps kwarg (M33 regression) ──────────────────────────────────────
#
# Before the fix, ``ScopeGate.__init__`` only honored
# ``rate_limits['default_requests_per_second']`` and ignored the Mission's
# ``default_rate_limit_rps``. The new ``default_rps`` kwarg lets callers
# (``agent_loop.py``) pass the Mission default; the per-call ``rate_limits``
# dict still wins when both are supplied.


def test_scope_gate_default_rps_kwarg_honored(temp_db):
    gate = ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["example.com"],
        default_rps=5.0,
    )
    assert gate._default_rps == 5.0


def test_scope_gate_default_rps_fallback_when_neither_given(temp_db):
    gate = ScopeGate(temp_db, _new_id("M"), allowed_assets=["example.com"])
    assert gate._default_rps == 2.0


def test_scope_gate_rate_limits_dict_overrides_default_rps_kwarg(temp_db):
    """Per-call ``rate_limits`` dict wins over the ``default_rps`` kwarg."""
    gate = ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["example.com"],
        rate_limits={"default_requests_per_second": 10},
        default_rps=5.0,
    )
    assert gate._default_rps == 10.0


def test_scope_gate_default_rps_governs_rate_limit(temp_db):
    """A ``default_rps=1`` gate must throttle the second call in the same window."""
    gate = ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["example.com"],
        default_rps=1.0,
        risk_profile="standard_authorized",
    )
    first = gate.check_scope("example.com", "recon", "nmap_scan", "low")
    assert first.allowed is True
    # Same 1-second window, bucket now at the cap of 1.
    second = gate.check_scope("example.com", "recon", "nmap_scan", "low")
    assert second.allowed is False
    assert "Rate limit" in second.reason
