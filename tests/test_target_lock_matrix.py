"""Direct matrix tests for the target-IP allowlist lock (critical path).

Covers ``is_target_in_allowlist`` + ``_target_lock_block`` + ``check_targets_allowlist``
across exact / CIDR / wildcard / IPv6 / fail-closed cases. Previously only
indirect (``test_tier4_correctness::test_terminal_does_not_block_benign_nmap``).
"""

from __future__ import annotations

import pytest

from tools.kernel.allowlist import check_targets_allowlist
from tools.mcp_tools.terminal.allowlist import _target_lock_block
from tools.validation_utils import is_target_in_allowlist


def _cfg(*allowed: str) -> dict:
    return {"exploit": {"require_explicit_allowlist": True, "allowed_targets": list(allowed)}}


# ── is_target_in_allowlist ─────────────────────────────────────────────


@pytest.mark.parametrize(
    ("target", "allowed", "expected"),
    [
        ("10.0.0.5", ["10.0.0.5"], True),  # exact IP
        ("10.0.0.5", ["10.0.0.0/24"], True),  # CIDR contains
        ("10.0.1.5", ["10.0.0.0/24"], False),  # CIDR miss
        ("foo.example.com", ["*.example.com"], True),  # wildcard child
        ("notexample.com", ["*.example.com"], False),  # suffix collision denied
        ("example.com", ["*.example.com"], False),  # bare parent not covered
        ("sub.example.com", ["example.com"], False),  # parent does not cover child
        ("EXAMPLE.COM", ["example.com"], True),  # case-insensitive
        ("example.com.", ["example.com"], True),  # trailing dot stripped
        ("2001:db8::1", ["2001:db8::/32"], True),  # IPv6 CIDR
        ("2001:db8::1", ["10.0.0.0/8"], False),  # IPv6 vs IPv4 miss
        ("", ["10.0.0.5"], False),  # empty target
        ("10.0.0.5", [], False),  # empty allowlist
    ],
)
def test_is_target_in_allowlist_matrix(target: str, allowed: list[str], expected: bool) -> None:
    assert is_target_in_allowlist(target, allowed) is expected


def test_host_with_port_fails_closed_documents_callers_must_strip() -> None:
    # Ports/zones are not stripped by the matcher; callers (browser urlparse,
    # terminal endpoint decoder) must strip before checking.
    assert is_target_in_allowlist("10.0.0.5:80", ["10.0.0.5"]) is False
    assert is_target_in_allowlist("example.com:8080", ["example.com"]) is False


# ── check_targets_allowlist ────────────────────────────────────────────


def test_check_targets_allowlist_empty_string_skipped() -> None:
    ok, _ = check_targets_allowlist([""], _cfg("10.0.0.5"))
    assert ok is True


def test_check_targets_allowlist_blocks_evil() -> None:
    ok, reason = check_targets_allowlist(["10.0.0.5", "evil.com"], _cfg("10.0.0.5"))
    assert ok is False
    assert "evil.com" in reason


def test_check_targets_allowlist_disabled_when_not_required() -> None:
    ok, _ = check_targets_allowlist(["evil.com"], {"exploit": {}})
    assert ok is True


# ── _target_lock_block ─────────────────────────────────────────────────


def test_lock_allows_benign_nmap_on_allowlisted_target() -> None:
    assert _target_lock_block("nmap -sV 10.0.0.5", _cfg("10.0.0.5")) is None


def test_lock_blocks_ipv6_not_in_allowlist() -> None:
    block = _target_lock_block("ping6 2001:db8::99", _cfg("10.0.0.5"))
    assert block is not None  # either explicit deny or fail-closed no-literal


def test_lock_blocks_evil_ip() -> None:
    block = _target_lock_block("nmap -sV 10.0.0.5 1.2.3.4", _cfg("10.0.0.5"))
    assert block is not None
    assert "1.2.3.4" in block


def test_lock_fail_closed_on_variable_indirection() -> None:
    block = _target_lock_block("curl $URL", _cfg("10.0.0.5"))
    assert block is not None
    assert "literally" in block


def test_lock_allow_empty_only_for_static_scans() -> None:
    assert _target_lock_block("echo hello", _cfg("10.0.0.5"), allow_empty=True) is None
    assert _target_lock_block("echo hello", _cfg("10.0.0.5")) is not None


def test_lock_skips_bind_all_listen_wildcard() -> None:
    assert _target_lock_block("socket.bind(('0.0.0.0', 4444))", _cfg("10.0.0.5")) is None


def test_lock_disabled_when_allowlist_not_required() -> None:
    assert _target_lock_block("nmap -sV 1.2.3.4", {"exploit": {}}) is None


def test_lock_empty_allowlist_fail_closed() -> None:
    block = _target_lock_block("nmap -sV 10.0.0.5", _cfg())
    assert block is not None
    assert "allowed_targets is empty" in block


def test_lock_cidr_scanner_target_allowed() -> None:
    assert _target_lock_block("nmap -sV 10.0.0.0/24", _cfg("10.0.0.0/24")) is None
