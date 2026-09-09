"""Tests for Deep Run Logs: deep-error records, activity flush, errors endpoint.

Covers: stuck_loop kind registration, build_deep_error_record redaction +
traceback fields, emit_deep_error errors.jsonl mirror (fail-open), activity
stop() flush + ISO-8601 timestamps, GET /runs/{id}/errors (whitelist, kind
filter, tail), and the swarm failure emitter.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from tools.activity_log import ActivityLog
from tools.api.deep_errors import (
    DEEP_ERROR_KINDS,
    build_deep_error_record,
    emit_deep_error,
)

# Async tests are marked individually (asyncio_mode is auto, but the explicit
# mark keeps intent clear without warning on the sync tests).


# ── Kind registry ─────────────────────────────────────────────────────────────


def test_stuck_loop_kind_registered():
    assert "stuck_loop" in DEEP_ERROR_KINDS
    for kind in ("model_call", "circuit_open", "mcp_transport", "parse", "tool_error"):
        assert kind in DEEP_ERROR_KINDS


# ── Record builder ────────────────────────────────────────────────────────────


def test_record_carries_fixer_fields():
    record = build_deep_error_record(
        "run-1",
        kind="stuck_loop",
        exc=RuntimeError("terminal constraint: blocked"),
        ctx={
            "phase": "validation",
            "round": 12,
            "tool_name": "run_exploit_terminal",
            "attempt_id": "a1",
            "retry": 3,
            "corr_id": "action-7",
            "response_excerpt": "outcome summary",
        },
    )
    assert record["run_id"] == "run-1"
    assert record["kind"] == "stuck_loop"
    assert record["phase"] == "validation"
    assert record["round"] == 12
    assert record["tool"]["name"] == "run_exploit_terminal"
    assert record["attempt_id"] == "a1"
    assert record["retry"] == 3
    assert record["corr_id"] == "action-7"
    assert record["error"]["class"] == "RuntimeError"
    assert "ts" in record and "T" in record["ts"]  # ISO-8601, not HH:MM:SS


def test_record_redacts_secrets():
    record = build_deep_error_record(
        "run-1",
        kind="tool_error",
        exc=ValueError("bad password=hunter2 token=abc123"),
        ctx={"args": {"password": "hunter2", "target_ip": "10.0.0.5"}},
    )
    blob = json.dumps(record)
    assert "hunter2" not in blob
    assert "10.0.0.5" in blob  # non-secret context preserved


def test_stuck_loop_has_no_traceback_but_hook_silent_does():
    # stuck_loop is a synthesized stall marker (RuntimeError built at the
    # call site), not a caught exception — no traceback expected.
    stuck = build_deep_error_record("r", kind="stuck_loop", exc=RuntimeError("x"), ctx={})
    assert stuck["error"]["traceback"] is None
    try:
        raise ValueError("boom")
    except ValueError as exc:
        parsed = build_deep_error_record("r", kind="parse", exc=exc, ctx={})
    assert parsed["error"]["traceback"] is not None
    assert "ValueError" in parsed["error"]["traceback"]


# ── Emitter (fail-open mirror) ────────────────────────────────────────────────


class _FailingSink:
    async def emit(self, event_type: str, payload: dict) -> None:
        raise ConnectionError("sink down")


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    async def emit(self, event_type: str, payload: dict) -> None:
        self.events.append((event_type, payload))


@pytest.mark.asyncio
async def test_emit_mirrors_errors_jsonl(tmp_path):
    sink = _RecordingSink()
    reports_dir = tmp_path / "run-9"
    await emit_deep_error(
        sink,
        "run-9",
        kind="stuck_loop",
        exc=RuntimeError("terminal constraint: blocked"),
        ctx={"phase": "validation", "round": 5},
        reports_dir=reports_dir,
    )
    assert len(sink.events) == 1
    event_type, record = sink.events[0]
    assert event_type == "error"
    mirror = reports_dir / "errors.jsonl"
    assert mirror.is_file()
    row = json.loads(mirror.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert row["kind"] == "stuck_loop"
    assert row["round"] == 5


@pytest.mark.asyncio
async def test_emit_never_raises(tmp_path):
    # A broken sink must not break the run (fail-open contract).
    await emit_deep_error(
        _FailingSink(),
        "run-9",
        kind="tool_error",
        exc=RuntimeError("x"),
        ctx={},
        reports_dir=tmp_path / "run-9",
    )


# ── Activity log: flush + timestamps ──────────────────────────────────────────


def test_stop_flushes_buffer(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    for i in range(5):
        log.log("info", f"m{i}")
    assert not (tmp_path / "activity.jsonl").exists()
    log.stop()
    content = (tmp_path / "activity.jsonl").read_text(encoding="utf-8")
    assert content.count("\n") == 5


def test_timestamps_are_iso8601(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    log.log("info", "hello")
    log._flush_audit()
    entry = json.loads((tmp_path / "activity.jsonl").read_text(encoding="utf-8").strip())
    assert "T" in entry["time"]  # ISO-8601 date+time, not HH:MM:SS


def test_tool_call_keeps_failure_context(tmp_path):
    log = ActivityLog(tmp_path, plain=True)
    long_result = "ERROR: " + "x" * 3000
    log.tool_call("run_exploit_terminal", {"target_ip": "10.0.0.5"}, result=long_result)
    assert long_result[:2000] in log.events[-1].detail
    log._flush_audit()


# ── GET /runs/{id}/errors ─────────────────────────────────────────────────────


def _make_client(tmp_path, monkeypatch, token="test-token-0123456789abcdef01234567"):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from tools.run_service.service import Callables

    class _FakeRouter:
        _clients = {"glm": MagicMock()}

        def get_client(self, name):
            return self._clients[name]

    async def _fake_run_session(**kwargs):
        return {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""}

    callables = Callables(build_router=lambda *a, **k: _FakeRouter(), run_session=_fake_run_session)
    from app import create_app

    return TestClient(create_app(config_path=config_path, callables=callables))


def _auth(token="test-token-0123456789abcdef01234567"):
    return {"Authorization": f"Bearer {token}"}


def _seed_errors(run_id: str):
    run_dir = Path("reports") / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        {"kind": "stuck_loop", "round": 5, "error": {"class": "RuntimeError"}},
        {"kind": "tool_error", "round": 6, "error": {"class": "TimeoutError"}},
        {"kind": "stuck_loop", "round": 9, "error": {"class": "RuntimeError"}},
    ]
    (run_dir / "errors.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def test_errors_empty_for_new_run(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/runs", json={"target": "10.0.0.50", "mode": "attack", "goal": "recon_only"}, headers=_auth()
    ).json()
    resp = client.get(f"/api/v1/runs/{created['run_id']}/errors", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert data["records"] == []
    assert data["total_records"] == 0


def test_errors_kind_filter_and_tail(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/runs", json={"target": "10.0.0.50", "mode": "attack", "goal": "recon_only"}, headers=_auth()
    ).json()
    _seed_errors(created["run_id"])
    resp = client.get(f"/api/v1/runs/{created['run_id']}/errors?kind=stuck_loop", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_records"] == 2
    assert {r["kind"] for r in data["records"]} == {"stuck_loop"}
    assert sorted(data["kinds"]) == ["stuck_loop", "tool_error"]
    resp = client.get(f"/api/v1/runs/{created['run_id']}/errors?tail=1", headers=_auth())
    assert len(resp.json()["records"]) == 1
    assert resp.json()["records"][0]["round"] == 9


def test_errors_404_for_unknown_run(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/runs/nope/errors", headers=_auth())
    assert resp.status_code == 404


def test_errors_jsonl_in_artifact_whitelist(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/runs", json={"target": "10.0.0.50", "mode": "attack", "goal": "recon_only"}, headers=_auth()
    ).json()
    _seed_errors(created["run_id"])
    names = [
        a["name"]
        for a in client.get(f"/api/v1/runs/{created['run_id']}/artifacts", headers=_auth()).json()["artifacts"]
    ]
    assert "errors.jsonl" in names


# ── Swarm failure emitter ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_swarm_deep_error_emitter_noop_without_reports_dir():
    from tools.run_service.tasks import _emit_swarm_deep_error

    sink = _RecordingSink()
    await _emit_swarm_deep_error(sink, None, RuntimeError("x"), {})
    assert sink.events == []


@pytest.mark.asyncio
async def test_swarm_deep_error_emitter_mirrors(tmp_path):
    from tools.run_service.tasks import _emit_swarm_deep_error

    sink = _RecordingSink()
    reports_dir = tmp_path / "run-s"
    await _emit_swarm_deep_error(sink, reports_dir, asyncio.TimeoutError("timed out"), {"tool_name": "swarm_campaign"})
    assert len(sink.events) == 1
    assert sink.events[0][1]["kind"] == "stuck_loop"
    assert (reports_dir / "errors.jsonl").is_file()
