"""Tests for exception-safe audit logging (``tools/kernel/audit.py``).

Contract under test:

- Every ``started`` record is guaranteed a terminal sibling: ``completed``,
  ``blocked``, or ``failed``. A tool that raises must still produce a
  terminal ``failed`` record — then the original exception propagates
  unchanged.
- Failure records carry the exception class, a sanitized (credential-
  redacted) error summary, elapsed duration, tool name, target, and the
  attempt ID when the tool takes one.
- ``BaseExceptionGroup`` (anyio task-group subprocess death) and
  ``asyncio.CancelledError`` are logged and re-raised as-is — cancellation
  semantics are preserved, nothing is swallowed or converted.
- Secrets in exception text (passwords, tokens, hashes, private keys,
  Authorization headers) never reach disk in cleartext.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tools.mcp_shared import _REDACTED, make_audit_tool, make_require_allowlist

_ALLOW_CONFIG = {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.50"]}}


def _records(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / "exploit_audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _statuses(workspace: Path) -> list[str]:
    return [r["status"] for r in _records(workspace)]


# ── make_audit_tool: sync + async ────────────────────────────────────────


def test_sync_tool_raise_produces_failed_record(tmp_path: Path):
    gated = make_audit_tool(tmp_path)

    @gated
    def boom(target_ip: str = "") -> str:
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError, match="kaboom"):
        boom(target_ip="10.0.0.50")
    assert _statuses(tmp_path) == ["started", "failed"]
    rec = _records(tmp_path)[1]
    assert rec["tool_name"] == "boom"
    assert rec["approved"] is False
    assert rec["error_class"] == "RuntimeError"
    assert rec["error_summary"] == "kaboom"
    assert rec["duration_seconds"] >= 0.0


@pytest.mark.asyncio
async def test_async_tool_raise_produces_failed_record(tmp_path: Path):
    gated = make_audit_tool(tmp_path)

    @gated
    async def boom(target_ip: str = "") -> str:
        raise ValueError("async kaboom")

    with pytest.raises(ValueError, match="async kaboom"):
        await boom(target_ip="10.0.0.50")
    assert _statuses(tmp_path) == ["started", "failed"]
    assert _records(tmp_path)[1]["error_class"] == "ValueError"


def test_sync_tool_raise_before_return_no_partial_state(tmp_path: Path):
    """A tool that throws before returning still leaves a clean started→failed pair."""
    gated = make_audit_tool(tmp_path)
    calls = {"n": 0}

    @gated
    def flaky(target_ip: str = "") -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("reset by peer")
        return "ok"

    with pytest.raises(ConnectionError):
        flaky(target_ip="10.0.0.50")
    assert flaky(target_ip="10.0.0.50") == "ok"
    assert _statuses(tmp_path) == ["started", "failed", "started", "completed"]


def test_attempt_id_recorded_when_available(tmp_path: Path):
    gated = make_audit_tool(tmp_path)

    @gated
    def with_attempt(target_ip: str = "", attempt_id: str = "") -> str:
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError):
        with_attempt(target_ip="10.0.0.50", attempt_id="ATT-123")
    recs = _records(tmp_path)
    assert recs[0]["attempt_id"] == "ATT-123"
    assert recs[1]["attempt_id"] == "ATT-123"


# ── make_require_allowlist: sync + async ─────────────────────────────────


def test_allowlisted_sync_tool_raise_audited(tmp_path: Path):
    gated = make_require_allowlist(tmp_path, _ALLOW_CONFIG)

    @gated("target_ip")
    def boom(target_ip: str = "") -> str:
        raise RuntimeError("sync allowlist boom")

    with pytest.raises(RuntimeError, match="sync allowlist boom"):
        boom(target_ip="10.0.0.50")
    assert _statuses(tmp_path) == ["started", "failed"]
    rec = _records(tmp_path)[1]
    assert rec["target_ip"] == "10.0.0.50"
    assert rec["error_class"] == "RuntimeError"


@pytest.mark.asyncio
async def test_allowlisted_async_tool_raise_audited(tmp_path: Path):
    gated = make_require_allowlist(tmp_path, _ALLOW_CONFIG)

    @gated("target_ip")
    async def boom(target_ip: str = "") -> str:
        raise RuntimeError("async allowlist boom")

    with pytest.raises(RuntimeError, match="async allowlist boom"):
        await boom(target_ip="10.0.0.50")
    assert _statuses(tmp_path) == ["started", "failed"]


def test_blocked_preflight_still_no_failed_record(tmp_path: Path):
    """Preflight denial keeps its single blocked record (no tool ran, nothing failed)."""
    gated = make_require_allowlist(tmp_path, _ALLOW_CONFIG)

    @gated("target_ip")
    def boom(target_ip: str = "") -> str:
        raise AssertionError("must not run")

    out = boom(target_ip="9.9.9.9")
    assert out.startswith("BLOCKED:")
    assert _statuses(tmp_path) == ["blocked"]


def test_completed_path_unchanged(tmp_path: Path):
    gated = make_require_allowlist(tmp_path, _ALLOW_CONFIG)

    @gated("target_ip")
    def ok(target_ip: str = "") -> str:
        return "done"

    assert ok(target_ip="10.0.0.50") == "done"
    recs = _records(tmp_path)
    assert _statuses(tmp_path) == ["started", "completed"]
    assert recs[1]["approved"] is True
    assert "error_class" not in recs[1]
    assert recs[1]["duration_seconds"] >= 0.0


# ── Secret redaction in failure records ──────────────────────────────────


# Secret shapes pinned to the shared redaction pipeline's contract
# (``_mask_secret_content`` — the same pipeline ordinary argument logging
# uses; its shape coverage is owned by ``test_audit_redaction.py``). These
# prove the new ``error_summary`` field routes through redaction instead of
# writing exception text raw.
@pytest.mark.parametrize(
    "secret",
    [
        "password=hunter2",
        "api_key=AKIAIOSFODNN7EXAMPLE",
        "Authorization: Bearer xyzzy-token",
        "crack failed for -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
        "token=super-secret-value",
    ],
)
def test_secrets_in_exception_text_redacted(tmp_path: Path, secret: str):
    gated = make_audit_tool(tmp_path)

    @gated
    def leaky(target_ip: str = "") -> str:
        raise RuntimeError(f"connection failed: {secret}")

    with pytest.raises(RuntimeError):
        leaky(target_ip="10.0.0.50")
    rec = _records(tmp_path)[1]
    assert rec["status"] == "failed"
    assert secret not in rec["error_summary"], rec["error_summary"]
    assert secret not in (tmp_path / "exploit_audit.jsonl").read_text(encoding="utf-8")
    assert _REDACTED in rec["error_summary"] or rec["error_summary"] == "" or "failed" in rec["error_summary"].lower()


# ── Exception-group + cancellation semantics ─────────────────────────────


@pytest.mark.asyncio
async def test_exception_group_logged_and_reraised_intact(tmp_path: Path):
    """BaseExceptionGroup (e.g. anyio/MCP subprocess death) is not swallowed.

    The leaf is a KeyboardInterrupt so CPython keeps this a true
    ``BaseExceptionGroup`` (an all-Exception group would coerce to
    ``ExceptionGroup``) — and, critically, an ``except Exception`` handler
    would MISS it entirely. The decorator must catch ``BaseException``.
    """
    gated = make_audit_tool(tmp_path)

    @gated
    async def grouped(target_ip: str = "") -> str:
        raise BaseExceptionGroup("task group failed", [KeyboardInterrupt()])
        return "unreachable"  # pragma: no cover

    with pytest.raises(BaseExceptionGroup) as excinfo:
        await grouped(target_ip="10.0.0.50")
    assert "task group failed" in str(excinfo.value)
    recs = _records(tmp_path)
    assert _statuses(tmp_path) == ["started", "failed"]
    assert recs[1]["error_class"] == "BaseExceptionGroup"


@pytest.mark.asyncio
async def test_cancellation_logged_and_propagates(tmp_path: Path):
    """asyncio cancellation still cancels — the audit record must not convert it."""
    gated = make_audit_tool(tmp_path)

    @gated
    async def slow(target_ip: str = "") -> str:
        await asyncio.sleep(30)
        return "unreachable"  # pragma: no cover

    task = asyncio.ensure_future(slow(target_ip="10.0.0.50"))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert _statuses(tmp_path) == ["started", "failed"]
    assert _records(tmp_path)[1]["error_class"] == "CancelledError"


def test_keyboard_interrupt_sync_logged_and_propagates(tmp_path: Path):
    gated = make_audit_tool(tmp_path)

    @gated
    def interrupted(target_ip: str = "") -> str:
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        interrupted(target_ip="10.0.0.50")
    assert _statuses(tmp_path) == ["started", "failed"]
    assert _records(tmp_path)[1]["error_class"] == "KeyboardInterrupt"


def test_audit_write_failure_never_masks_tool_error(tmp_path: Path, monkeypatch):
    """A broken audit sink must not replace the tool's original exception."""
    import tools.kernel.audit as audit_mod

    gated = make_audit_tool(tmp_path)

    @gated
    def boom(target_ip: str = "") -> str:
        raise RuntimeError("original failure")

    real_log = audit_mod._audit_log
    calls = {"n": 0}

    def flaky_log(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] > 1:  # let "started" through, fail the "failed" write
            raise OSError("disk full")
        return real_log(*args, **kwargs)

    monkeypatch.setattr(audit_mod, "_audit_log", flaky_log)
    with pytest.raises(RuntimeError, match="original failure"):
        boom(target_ip="10.0.0.50")
