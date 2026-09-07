"""Tests for the token-bucket scope rate limiter (``scope_gate.py``).

The old sliding-window limiter clamped fractional RPS via
``max(1, int(rps))``, so 0.2 req/s behaved as ~1 req/s. The token bucket
honors fractional rates (0.1/0.2/0.5 RPS) as well as multi-RPS rates.

The clock is injected by monkeypatching ``time.monotonic`` (the same seam
the limiter reads) — fully deterministic, no real sleeps.
"""

from __future__ import annotations

from typing import Any

import pytest

import scope_gate as _sg
from db import DatabaseManager, _new_id
from scope_gate import ScopeGate, _bucket_spec


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    return db


class _Clock:
    """Injectable monotonic clock (seconds, float)."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    clk = _Clock()
    monkeypatch.setattr(_sg.time, "monotonic", clk)
    return clk


def _gate(temp_db, rps: float) -> ScopeGate:
    return ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["example.com"],
        rate_limits={"default_requests_per_second": rps},
    )


def _check(gate: ScopeGate) -> Any:
    return gate.check_scope("example.com", "recon", "nmap_scan", "low")


# ── Fractional rates ─────────────────────────────────────────────────────


@pytest.mark.parametrize("rps", [0.1, 0.2, 0.5])
def test_fractional_rate_allows_burst_of_one_then_throttles(temp_db, clock, rps):
    gate = _gate(temp_db, rps)
    # Burst capacity for sub-1 rates is a single request.
    assert _check(gate).allowed is True
    assert _check(gate).allowed is False
    # Still denied just before the refill interval elapses...
    clock.advance(1.0 / rps - 0.01)
    assert _check(gate).allowed is False
    # ...and allowed once a full interval has passed.
    clock.advance(0.01)
    assert _check(gate).allowed is True


def test_fractional_rate_sustained_average(temp_db, clock):
    """0.2 RPS sustains ~1 request per 5s over a long window."""
    gate = _gate(temp_db, 0.2)
    allowed = 0
    for _ in range(60):
        if _check(gate).allowed:
            allowed += 1
        clock.advance(1.0)
    # Allows at t=0,5,...,55s: 1 burst token + 11 refills in 60 iterations.
    assert allowed == 12


def test_half_rps_timing(temp_db, clock):
    gate = _gate(temp_db, 0.5)
    assert _check(gate).allowed is True
    clock.advance(1.0)
    assert _check(gate).allowed is False
    clock.advance(1.0)
    assert _check(gate).allowed is True


# ── Normal multi-RPS rates ───────────────────────────────────────────────


def test_multi_rps_burst_then_refill(temp_db, clock):
    gate = _gate(temp_db, 5.0)
    for _ in range(5):
        assert _check(gate).allowed is True
    assert _check(gate).allowed is False
    # 0.2s refills one token at 5/s.
    clock.advance(0.2)
    assert _check(gate).allowed is True
    assert _check(gate).allowed is False


def test_idle_time_does_not_bank_unbounded_burst(temp_db, clock):
    """Tokens cap at capacity: idling an hour still yields only one burst."""
    gate = _gate(temp_db, 2.0)
    clock.advance(3600.0)
    assert _check(gate).allowed is True
    assert _check(gate).allowed is True
    assert _check(gate).allowed is False


# ── Retry / remaining info ───────────────────────────────────────────────


def test_denial_reports_retry_after(temp_db, clock):
    gate = _gate(temp_db, 0.5)
    assert _check(gate).allowed is True
    denied = _check(gate)
    assert denied.allowed is False
    assert denied.rate_limit_remaining == 0
    assert denied.retry_after_seconds is not None
    assert denied.retry_after_seconds == pytest.approx(2.0)
    # Waiting out the reported delay unblocks.
    clock.advance(denied.retry_after_seconds)
    assert _check(gate).allowed is True


def test_allow_reports_remaining(temp_db, clock):
    gate = _gate(temp_db, 3.0)
    first = _check(gate)
    assert first.allowed is True
    assert first.rate_limit_remaining == 2
    assert first.retry_after_seconds is None


# ── Edge cases ───────────────────────────────────────────────────────────


def test_nonpositive_rate_clamps_to_legacy_floor(temp_db, clock):
    """A misconfigured 0/negative rate behaves as 1/s (never lockout, never unlimited)."""
    assert _bucket_spec(0) == (1.0, 1.0)
    assert _bucket_spec(-5) == (1.0, 1.0)
    gate = _gate(temp_db, 0)
    assert _check(gate).allowed is True
    assert _check(gate).allowed is False
    clock.advance(1.0)
    assert _check(gate).allowed is True


def test_no_sleep_inside_scope_check(temp_db, clock, monkeypatch):
    """The limiter is a pure decision — it must never block the caller."""
    import time as _time

    gate = _gate(temp_db, 0.1)
    monkeypatch.setattr(_time, "sleep", lambda s: (_ for _ in ()).throw(AssertionError("must not sleep")))
    assert _check(gate).allowed is True
    assert _check(gate).allowed is False


def test_buckets_isolated_per_asset_and_action(temp_db, clock):
    gate = ScopeGate(
        temp_db,
        _new_id("M"),
        allowed_assets=["example.com", "other.com"],
        rate_limits={"default_requests_per_second": 1.0},
    )
    assert gate.check_scope("example.com", "recon", "t", "low").allowed is True
    assert gate.check_scope("example.com", "recon", "t", "low").allowed is False
    # A different asset gets its own bucket.
    assert gate.check_scope("other.com", "recon", "t", "low").allowed is True
