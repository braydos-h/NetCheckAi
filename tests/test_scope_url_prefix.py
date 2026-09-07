"""Tests for ``url_prefix`` mission scope authorization (``scope_gate.py``).

Mission assets classified as ``url_prefix`` (e.g.
``https://example.com/admin/``) must authorize at path level: the scheme,
hostname (case-insensitive), normalized port, and path are all significant,
and the path comparison is directory-boundary safe so
``https://example.com/admin`` does NOT authorize
``https://example.com/administrator``.

URL parsing uses :mod:`urllib.parse` (never string splitting); malformed
URLs fail closed. Query strings and fragments do not affect scope.

All tests mock subprocess/network — scope matching is pure Python.
"""

from __future__ import annotations

import pytest

from db import DatabaseManager, _new_id
from scope_gate import (
    ScopeGate,
    _canonicalize_url,
    _classify_target_type,
    _url_prefix_matches,
)

# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    return db


@pytest.fixture
def url_gate(temp_db):
    mid = _new_id("M")
    return ScopeGate(
        temp_db,
        mid,
        allowed_assets=["https://example.com/admin", "http://[2001:db8::1]/v6"],
        disallowed_assets=["https://example.com/admin/secret"],
        risk_profile="standard_authorized",
    )


# ── Classification ───────────────────────────────────────────────────────


def test_classify_url_prefix():
    assert _classify_target_type("https://example.com/admin/") == "url_prefix"
    assert _classify_target_type("http://example.com/") == "url_prefix"
    assert _classify_target_type("HTTPS://EXAMPLE.COM/x") == "url_prefix"


def test_classify_non_url_unchanged():
    assert _classify_target_type("example.com") == "domain"
    assert _classify_target_type("*.example.com") == "wildcard_domain"
    assert _classify_target_type("10.0.0.1") == "ip"
    assert _classify_target_type("10.0.0.0/24") == "cidr"


# ── Canonicalization ─────────────────────────────────────────────────────


def test_canonicalize_basic():
    assert _canonicalize_url("https://example.com/admin") == ("https", "example.com", None, "/admin")


def test_canonicalize_host_case_insensitive():
    assert _canonicalize_url("HTTPS://EXAMPLE.COM/Admin") == ("https", "example.com", None, "/Admin")


def test_canonicalize_default_port_normalized():
    assert _canonicalize_url("https://example.com:443/admin") == ("https", "example.com", None, "/admin")
    assert _canonicalize_url("http://example.com:80/admin") == ("http", "example.com", None, "/admin")


def test_canonicalize_explicit_port_kept():
    assert _canonicalize_url("https://example.com:8443/admin") == ("https", "example.com", 8443, "/admin")


def test_canonicalize_empty_path_is_root():
    assert _canonicalize_url("https://example.com") == ("https", "example.com", None, "/")


def test_canonicalize_drops_query_and_fragment():
    assert _canonicalize_url("https://example.com/admin?x=1#frag") == ("https", "example.com", None, "/admin")


def test_canonicalize_ipv6():
    assert _canonicalize_url("http://[2001:db8::1]:8080/v6") == ("http", "2001:db8::1", 8080, "/v6")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not a url",
        "example.com/admin",
        "http://",
        "https://",
        "https:///path-only",
        "://missing-scheme.com/x",
        "https://exa mple.com/x",
        "https://example.com:badport/x",
        "https://example.com:99999/x",
        "http://exam%zzple.com/",
    ],
)
def test_canonicalize_malformed_returns_none(bad):
    # Entries fail on missing scheme/host, whitespace, bad port, or a
    # percent-escape in the hostname — all fail closed.
    assert _canonicalize_url(bad) is None


def test_percent_escape_in_path_is_opaque():
    # ``%zz`` in the *path* is not valid decoding input, but the path is
    # opaque scope text: it canonicalizes, yet never prefix-matches a real
    # rule path, so matching still fails closed.
    assert _canonicalize_url("https://example.com/%zz") is not None
    assert not _url_prefix_matches("https://example.com/admin", "https://example.com/%zz")


# ── Matcher unit tests ───────────────────────────────────────────────────


def test_exact_url_matches():
    assert _url_prefix_matches("https://example.com/admin", "https://example.com/admin")


def test_child_path_matches():
    assert _url_prefix_matches("https://example.com/admin", "https://example.com/admin/users")
    assert _url_prefix_matches("https://example.com/admin/", "https://example.com/admin/users")


def test_sibling_path_rejected():
    assert not _url_prefix_matches("https://example.com/admin", "https://example.com/other")
    assert not _url_prefix_matches("https://example.com/admin/", "https://example.com/other")


def test_similar_prefix_attack_rejected():
    # The critical boundary case: "/administrator" is NOT under "/admin".
    assert not _url_prefix_matches("https://example.com/admin", "https://example.com/administrator")
    assert not _url_prefix_matches("https://example.com/admin/", "https://example.com/administrator")
    assert not _url_prefix_matches("https://example.com/admin", "https://example.com/admin-panel")


def test_scheme_mismatch_rejected():
    assert not _url_prefix_matches("https://example.com/admin", "http://example.com/admin/x")


def test_host_mismatch_rejected():
    assert not _url_prefix_matches("https://example.com/admin", "https://evil.com/admin/x")
    assert not _url_prefix_matches("https://example.com/admin", "https://sub.example.com/admin/x")


def test_host_case_insensitive():
    assert _url_prefix_matches("https://example.com/admin", "https://EXAMPLE.COM/admin/x")


def test_explicit_ports():
    assert _url_prefix_matches("https://example.com:8443/admin", "https://example.com:8443/admin/x")
    assert not _url_prefix_matches("https://example.com:8443/admin", "https://example.com/admin/x")
    assert not _url_prefix_matches("https://example.com/admin", "https://example.com:8443/admin/x")


def test_default_port_equivalent():
    assert _url_prefix_matches("https://example.com:443/admin", "https://example.com/admin/x")
    assert _url_prefix_matches("https://example.com/admin", "https://example.com:443/admin/x")


def test_ipv6_urls():
    assert _url_prefix_matches("http://[2001:db8::1]/v6", "http://[2001:db8::1]/v6/hosts")
    assert not _url_prefix_matches("http://[2001:db8::1]/v6", "http://[2001:db8::2]/v6/hosts")


def test_query_and_fragment_ignored():
    assert _url_prefix_matches("https://example.com/admin", "https://example.com/admin/x?key=val#frag")


def test_malformed_asset_or_pattern_fails_closed():
    assert not _url_prefix_matches("https://example.com/admin", "not a url")
    assert not _url_prefix_matches("not a url", "https://example.com/admin/x")
    assert not _url_prefix_matches("https://example.com/admin", "example.com")
    assert not _url_prefix_matches("https://example.com/admin", "")


def test_bare_host_does_not_match_url_rule():
    # A bare domain asset is broader than a path-scoped rule — fail closed.
    assert not _url_prefix_matches("https://example.com/admin", "example.com")


# ── End-to-end through ScopeGate ─────────────────────────────────────────


def test_gate_allows_exact_and_child(url_gate):
    assert url_gate.check_scope("https://example.com/admin", "recon", "web", "low").allowed
    assert url_gate.check_scope("https://example.com/admin/users", "recon", "web", "low").allowed


def test_gate_blocks_similar_prefix_and_sibling(url_gate):
    assert not url_gate.check_scope("https://example.com/administrator", "recon", "web", "low").allowed
    assert not url_gate.check_scope("https://example.com/other", "recon", "web", "low").allowed


def test_gate_blocks_scheme_and_host_mismatch(url_gate):
    assert not url_gate.check_scope("http://example.com/admin/x", "recon", "web", "low").allowed
    assert not url_gate.check_scope("https://evil.com/admin/x", "recon", "web", "low").allowed


def test_gate_deny_rule_beats_allow(url_gate):
    # ``https://example.com/admin/secret`` is explicitly disallowed even
    # though it sits under the allowed ``/admin`` prefix.
    assert not url_gate.check_scope("https://example.com/admin/secret/tokens", "recon", "web", "low").allowed


def test_gate_ipv6_prefix(url_gate):
    assert url_gate.check_scope("http://[2001:db8::1]/v6/hosts", "recon", "web", "low").allowed
    assert not url_gate.check_scope("http://[2001:db8::2]/v6/hosts", "recon", "web", "low").allowed


def test_gate_malformed_asset_denied(url_gate):
    assert not url_gate.check_scope("https://", "recon", "web", "low").allowed


# ── No regression on host-based matching ─────────────────────────────────


def test_host_rules_still_match_url_assets(temp_db):
    """A plain domain allow rule still authorizes a URL asset on that host.

    ``check_scope`` normalizes ``https://example.com/page`` to its host for
    non-URL rules — URL support must not break host-level scope.
    """
    gate = ScopeGate(temp_db, _new_id("M"), allowed_assets=["example.com"])
    assert gate.check_scope("https://example.com/some/page", "recon", "web", "low").allowed
    assert not gate.check_scope("https://evil.com/some/page", "recon", "web", "low").allowed


def test_domain_wildcard_ipv4_ipv6_cidr_unaffected(temp_db):
    gate = ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["example.com", "*.example.com", "10.0.0.5", "2001:db8::1", "192.168.0.0/16"],
    )
    assert gate.check_scope("example.com", "recon", "t", "low").allowed
    assert gate.check_scope("sub.example.com", "recon", "t", "low").allowed
    assert not gate.check_scope("other.com", "recon", "t", "low").allowed
    assert gate.check_scope("10.0.0.5", "recon", "t", "low").allowed
    assert not gate.check_scope("10.0.0.6", "recon", "t", "low").allowed
    assert gate.check_scope("2001:db8::1", "recon", "t", "low").allowed
    assert not gate.check_scope("2001:db8::2", "recon", "t", "low").allowed
    assert gate.check_scope("192.168.5.5", "recon", "t", "low").allowed
    assert not gate.check_scope("192.167.5.5", "recon", "t", "low").allowed
