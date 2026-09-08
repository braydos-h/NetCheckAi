"""P2 regression: ScopeGate DB hydration, custom forbidden actions, rate floor.

Read-only against ``scope_gate.py`` / ``db.py`` — no source edits here.

Single-threaded deterministic parts only. The ``_rate_buckets`` dict is
shared mutable state with no lock; a threaded hammer test would be flaky by
construction and is intentionally NOT written here. Follow-up for the owning
role: guard ``_check_rate_limit`` bucket creation with a lock (or document
single-threaded use) — see remaining_concerns.
"""

from __future__ import annotations

import pytest

from db import DatabaseManager, _new_id
from scope_gate import ScopeGate, _bucket_spec


@pytest.fixture
def temp_db(tmp_path):
    db = DatabaseManager(tmp_path / "test.db")
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
    return db


def _mission_with_rules(db, *, allow=(), deny=(), deny_action=()):
    with db.connection(write=True) as conn:
        mid = db.create_mission(conn)["id"]
        for pattern in allow:
            db.add_scope_rule(conn, mid, "allow", "domain", pattern)
        for pattern in deny:
            db.add_scope_rule(conn, mid, "deny", "domain", pattern)
        for pattern in deny_action:
            db.add_scope_rule(conn, mid, "deny", "action", pattern)
    return mid


# ── DB hydration ─────────────────────────────────────────────────────────────


def test_load_from_db_hydrates_allow_and_deny(temp_db):
    mid = _mission_with_rules(
        temp_db, allow=["example.com"], deny=["evil.example.com"]
    )
    gate = ScopeGate(temp_db, mid, allowed_assets=[], risk_profile="standard_authorized")
    assert gate.list_scope()["allow"] == []
    gate.load_from_db()
    assert gate.list_scope()["allow"] == ["example.com"]
    assert gate.list_scope()["deny"] == ["evil.example.com"]
    assert gate.check_scope("example.com", "recon", "t", "low", enforce_rate_limit=False).allowed is True
    assert gate.check_scope("evil.example.com", "recon", "t", "low", enforce_rate_limit=False).allowed is False


def test_load_from_db_hydrates_action_deny_as_forbidden(temp_db):
    mid = _mission_with_rules(temp_db, allow=["example.com"], deny_action=["brute_force"])
    gate = ScopeGate(temp_db, mid, risk_profile="standard_authorized")
    gate.load_from_db()
    assert "brute_force" in gate.list_forbidden_actions()
    out = gate.check_scope("example.com", "brute_force", "t", "low", enforce_rate_limit=False)
    assert out.allowed is False


def test_load_from_db_replaces_constructor_rules(temp_db):
    """Hydration clears first: stale constructor rules must not survive."""
    mid = _mission_with_rules(temp_db, allow=["fresh.example.com"])
    gate = ScopeGate(
        temp_db,
        mid,
        allowed_assets=["stale.example.com"],
        risk_profile="standard_authorized",
    )
    gate.load_from_db()
    assert gate.list_scope()["allow"] == ["fresh.example.com"]
    assert gate.check_scope("stale.example.com", "recon", "t", "low", enforce_rate_limit=False).allowed is False


def test_load_from_db_empty_rules_denies_everything(temp_db):
    with temp_db.connection(write=True) as conn:
        mid = temp_db.create_mission(conn)["id"]
    gate = ScopeGate(temp_db, mid, allowed_assets=["example.com"])
    gate.load_from_db()
    assert gate.list_scope()["allow"] == []
    assert gate.check_scope("example.com", "recon", "t", "low", enforce_rate_limit=False).allowed is False


# ── Custom forbidden actions ─────────────────────────────────────────────────


def test_list_forbidden_actions_merges_custom_and_hard(temp_db):
    with temp_db.connection(write=True) as conn:
        mid = temp_db.create_mission(conn)["id"]
    gate = ScopeGate(
        temp_db,
        mid,
        allowed_assets=["example.com"],
        forbidden_actions=["uncontrolled_fuzzing", "denial_of_service"],
        risk_profile="standard_authorized",
    )
    forbidden = gate.list_forbidden_actions()
    assert "uncontrolled_fuzzing" in forbidden  # custom
    assert "denial_of_service" in forbidden  # hard-blocked, deduped not duplicated
    assert forbidden.count("denial_of_service") == 1
    assert "malware" in forbidden  # hard set intact


# ── Rate-bucket boundary: rps 0 / negative clamp, never lock out or open ─────


@pytest.mark.parametrize("bad_rps", [0, -5, 0.0, float("nan")])
def test_bucket_spec_non_positive_clamps_to_floor(bad_rps):
    rate, capacity = _bucket_spec(bad_rps)
    assert rate == 1.0
    assert capacity == 1.0


def test_zero_rps_config_does_not_lock_out(temp_db, monkeypatch):
    """A misconfigured 0/negative RPS clamps to 1/s: first call passes,
    immediate second is rate-limited (fail-closed, deterministic)."""
    import time as _time

    now = [1000.0]
    monkeypatch.setattr(_time, "monotonic", lambda: now[0])
    with temp_db.connection(write=True) as conn:
        mid = temp_db.create_mission(conn)["id"]
    gate = ScopeGate(
        temp_db,
        mid,
        allowed_assets=["10.0.0.99"],
        rate_limits={"default_requests_per_second": 0},
        risk_profile="standard_authorized",
    )
    first = gate.check_scope("10.0.0.99", "recon", "t", "low")
    assert first.allowed is True
    second = gate.check_scope("10.0.0.99", "recon", "t", "low")
    assert second.allowed is False
    assert second.retry_after_seconds > 0
