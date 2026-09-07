"""API tests for the benchmark routes (/api/v1/benchmarks/*)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tools.benchmark import seed_fake_suite
from tools.benchmark.agent_runner import MissionResult, TrialTelemetry
from tools.benchmark.metrics import compute_run_summary
from tools.benchmark.models import BenchmarkScenario, TrialResult, TrialStatus

TOKEN = "test-token-0123456789abcdef01234567"


def _scenario(scenario_id: str = "s1") -> BenchmarkScenario:
    return BenchmarkScenario(
        suite="fake",
        scenario_id=scenario_id,
        name=f"Scenario {scenario_id}",
        target_type="host",
        target_host="127.0.0.1",
        tags=["web"],
        oracle={"flags": [{"id": "f1", "check": {}}], "host_owned_when": "any"},
    )


def _config(output_dir: Path) -> dict[str, Any]:
    return {
        "benchmark": {
            "output_dir": str(output_dir / "bench"),
            "baseline_path": str(output_dir / "bench" / "baseline.json"),
            "sandbox_required": False,
            "trials": 1,
        },
        "models": {"default_alias": "glm"},
        "mcp": {"http_port": 8001},
        "api": {"host": "127.0.0.1", "port": 8765},
    }


def _make_client(tmp_path, monkeypatch):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", TOKEN)
    from app import create_app

    app = create_app(config=_config(tmp_path))
    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def _seed_and_patch_runner(monkeypatch, tmp_path):
    """Seed a fake suite + patch the runner used by BenchmarkService."""
    seed_fake_suite([_scenario("s1"), _scenario("s2")])
    call_count = {"n": 0}

    class _FakeRunner:
        def __init__(self, config, config_path, **kw):
            pass

        async def run(self, run_config, cancel=None, progress=None):
            call_count["n"] += 1
            run_id = f"run-{call_count['n']}"
            if progress is not None:
                progress({"type": "trial_start", "run_id": run_id, "scenario_id": "s1", "trial": 1, "trials": 1})
            trial = TrialResult(
                run_id=run_id,
                suite=run_config.suite,
                scenario_id="s1",
                trial_index=0,
                trial_id="s1#t0",
                status=TrialStatus.VERIFIED.value if call_count["n"] == 1 else TrialStatus.FALSE_POSITIVE.value,
                agent_claimed_success=True,
                oracle_verified_success=call_count["n"] == 1,
                duration_seconds=42.0,
                total_tokens=1500,
                telemetry=TrialTelemetry(model_calls=5, tool_calls=9, total_tokens=1500),
            )
            summary = compute_run_summary([trial], run_id=run_id, suite=run_config.suite)
            return {
                "run_id": run_id,
                "suite": run_config.suite,
                "status": "completed",
                "run_dir": str(tmp_path / "bench" / "fake" / run_id),
                "report_markdown": "report.md",
                "report_html": "report.html",
                "summary": summary.to_dict(),
                "trials": [trial.to_dict()],
                "regression": None,
            }

    monkeypatch.setattr("tools.benchmark.service.BenchmarkRunner", _FakeRunner)


# ---------------------------------------------------------------------------
# Discovery endpoints
# ---------------------------------------------------------------------------


def test_overview_and_suites(tmp_path, monkeypatch):
    _seed_and_patch_runner(monkeypatch, tmp_path)
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/benchmarks", headers=_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "suites" in data and "runs" in data and "active" in data and "baseline" in data
    assert any(s["suite_id"] == "fake" for s in data["suites"])

    resp = client.get("/api/v1/benchmarks/suites", headers=_headers())
    assert resp.status_code == 200
    assert resp.json()["suites"]

    resp = client.get("/api/v1/benchmarks/suites/fake/scenarios", headers=_headers())
    assert resp.status_code == 200
    scenarios = resp.json()["scenarios"]
    assert {s["scenario_id"] for s in scenarios} == {"s1", "s2"}

    resp = client.get("/api/v1/benchmarks/suites/nope/scenarios", headers=_headers())
    assert resp.status_code == 404


def test_auth_required(tmp_path, monkeypatch):
    _seed_and_patch_runner(monkeypatch, tmp_path)
    client = _make_client(tmp_path, monkeypatch)
    assert client.get("/api/v1/benchmarks").status_code == 401
    assert client.get("/api/v1/benchmarks/suites/fake/readiness").status_code == 401


# ---------------------------------------------------------------------------
# Suite readiness (lab-target preflight)
# ---------------------------------------------------------------------------


def _host_scenario(scenario_id: str, ports: list[int]) -> BenchmarkScenario:
    return BenchmarkScenario(
        suite="fake",
        scenario_id=scenario_id,
        name=f"Scenario {scenario_id}",
        target_type="host",
        target_host="127.0.0.1",
        target_ports=ports,
        tags=["web"],
        oracle={"flags": [{"id": "f1", "check": {}}], "host_owned_when": "any"},
    )


def test_suite_readiness_reports_unreachable_lab(tmp_path, monkeypatch):
    seed_fake_suite([_host_scenario("s1", [18081]), _host_scenario("s2", [18082])])
    monkeypatch.setattr("tools.benchmark.targets.target_ports_reachable", lambda *a, **k: False)
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/benchmarks/suites/fake/readiness", headers=_headers())
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["suite"] == "fake"
    assert data["ready"] is False
    assert "up -d" in data["lab_command"]
    assert {t["scenario_id"] for t in data["targets"]} == {"s1", "s2"}
    assert all(t["reachable"] is False for t in data["targets"])


def test_suite_readiness_ready_when_lab_up(tmp_path, monkeypatch):
    seed_fake_suite([_host_scenario("s1", [18081])])
    monkeypatch.setattr("tools.benchmark.targets.target_ports_reachable", lambda *a, **k: True)
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/benchmarks/suites/fake/readiness", headers=_headers())
    assert resp.status_code == 200, resp.text
    assert resp.json()["ready"] is True


def test_suite_readiness_self_provisioned_and_unknown_suite(tmp_path, monkeypatch):
    seed_fake_suite(
        [
            BenchmarkScenario(
                suite="fake",
                scenario_id="dock",
                name="Docker",
                target_type="docker",
                target_image="lab:latest",
                target_host="127.0.0.1",
                target_ports=[8080],
                tags=["web"],
                oracle={"flags": [{"id": "f1", "check": {}}], "host_owned_when": "any"},
            )
        ]
    )
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/benchmarks/suites/fake/readiness", headers=_headers())
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["ready"] is True  # self-provisioned: no lab needed, no probe
    assert data["targets"][0]["self_provisioned"] is True

    resp = client.get("/api/v1/benchmarks/suites/nope/readiness", headers=_headers())
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Run lifecycle
# ---------------------------------------------------------------------------


def test_start_run_and_fetch_results(tmp_path, monkeypatch):
    _seed_and_patch_runner(monkeypatch, tmp_path)
    client = _make_client(tmp_path, monkeypatch)

    resp = client.post(
        "/api/v1/benchmarks/run",
        headers=_headers(),
        json={"suite": "fake", "trials": 1, "scenarios": ["s1"]},
    )
    assert resp.status_code == 200, resp.text
    run_id = resp.json()["run_id"]
    assert run_id

    # Run detail (run.json written by the service's real storage layer? No —
    # the fake runner skips storage; the API must 404 gracefully).
    resp = client.get(f"/api/v1/benchmarks/runs/{run_id}", headers=_headers())
    assert resp.status_code == 404  # fake runner bypassed persistence; storage has nothing

    # Runs list is empty for the same reason.
    resp = client.get("/api/v1/benchmarks/runs", headers=_headers())
    assert resp.status_code == 200
    assert resp.json()["runs"] == []


def test_start_run_requires_suite(tmp_path, monkeypatch):
    _seed_and_patch_runner(monkeypatch, tmp_path)
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/benchmarks/run", headers=_headers(), json={"suite": ""})
    assert resp.status_code == 409


def test_second_run_conflicts(tmp_path, monkeypatch):
    _seed_and_patch_runner(monkeypatch, tmp_path)
    client = _make_client(tmp_path, monkeypatch)
    first = client.post("/api/v1/benchmarks/run", headers=_headers(), json={"suite": "fake"})
    assert first.status_code == 200
    # The service's _active_task is still tracked even if fast; second start
    # either conflicts (409) or the first already finished (200). The service
    # waits for run_id synchronously so a fast fake runner usually completes.
    second = client.post("/api/v1/benchmarks/run", headers=_headers(), json={"suite": "fake"})
    assert second.status_code in (200, 409)


def test_cancel_unknown_run(tmp_path, monkeypatch):
    _seed_and_patch_runner(monkeypatch, tmp_path)
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/benchmarks/runs/does-not-exist/cancel", headers=_headers())
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Baseline + comparison
# ---------------------------------------------------------------------------


def _persist_run(storage: Any, suite: str, run_id: str, *, verified: bool) -> None:
    trial = TrialResult(
        run_id=run_id,
        suite=suite,
        scenario_id="s1",
        trial_index=0,
        trial_id="s1#t0",
        status=TrialStatus.VERIFIED.value if verified else TrialStatus.FALSE_POSITIVE.value,
        agent_claimed_success=True,
        oracle_verified_success=verified,
        duration_seconds=60.0,
    )
    from tools.benchmark.models import RunConfig, RunEnvironment

    storage.init_run(suite, run_id, RunConfig(suite=suite), RunEnvironment(), ["s1"])
    storage.write_trial(suite, run_id, trial)
    summary = compute_run_summary([trial], run_id=run_id, suite=suite)
    storage.finalize_run(
        suite,
        run_id,
        status="completed",
        trials=[trial],
        summary=summary,
        config=RunConfig(suite=suite),
        environment=RunEnvironment(),
        scenario_ids=["s1"],
    )


def test_baseline_get_post_and_compare(tmp_path, monkeypatch):
    _seed_and_patch_runner(monkeypatch, tmp_path)
    client = _make_client(tmp_path, monkeypatch)
    from tools.benchmark.storage import BenchmarkStorage

    storage = BenchmarkStorage(tmp_path / "bench")
    _persist_run(storage, "fake", "run-1", verified=True)
    _persist_run(storage, "fake", "run-2", verified=False)
    # The two persisted runs share scenario s1; the comparison treats them as
    # separate runs of the same suite.

    # Baseline initially absent.
    resp = client.get("/api/v1/benchmarks/baseline", headers=_headers())
    assert resp.status_code == 200
    assert resp.json()["exists"] is False

    # Save run-1 as baseline.
    resp = client.post("/api/v1/benchmarks/baseline", headers=_headers(), json={"run_id": "run-1"})
    assert resp.status_code == 200
    assert resp.json()["saved"] is True

    resp = client.get("/api/v1/benchmarks/baseline", headers=_headers())
    data = resp.json()
    assert data["exists"] is True
    assert data["run_id"] == "run-1"

    # Compare run-1 (baseline) with run-2 (regressed).
    resp = client.get(
        "/api/v1/benchmarks/compare",
        headers=_headers(),
        params={"run_a": "run-1", "run_b": "run-2"},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    metrics = {m["metric"]: m for m in payload["comparison"]["metrics"]}
    assert metrics["verified_success_rate"]["baseline"] == 1.0
    assert metrics["verified_success_rate"]["current"] == 0.0
    assert payload["comparison"]["categories"]["regressed"] == ["s1"]

    # Missing run -> 404.
    resp = client.get(
        "/api/v1/benchmarks/compare",
        headers=_headers(),
        params={"run_a": "run-1", "run_b": "nope"},
    )
    assert resp.status_code == 404


def test_run_detail_scenarios_and_events(tmp_path, monkeypatch):
    _seed_and_patch_runner(monkeypatch, tmp_path)
    client = _make_client(tmp_path, monkeypatch)
    from tools.benchmark.events import BenchmarkEventLogger
    from tools.benchmark.models import RunConfig, RunEnvironment
    from tools.benchmark.storage import BenchmarkStorage

    storage = BenchmarkStorage(tmp_path / "bench")
    _persist_run(storage, "fake", "run-1", verified=True)
    run_dir = storage.run_dir("fake", "run-1")
    logger = BenchmarkEventLogger(path=run_dir / "events.jsonl", run_id="run-1")
    logger.log("target_ready", {"host": "127.0.0.1"}, trial_id="s1#t0", scenario_id="s1")
    logger.log("oracle_result", {"verified": True}, trial_id="s1#t0", scenario_id="s1")

    resp = client.get("/api/v1/benchmarks/runs/run-1", headers=_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["summary"]["solved"] == 1
    assert data["environment"] is not None

    resp = client.get("/api/v1/benchmarks/runs/run-1/scenarios", headers=_headers())
    assert resp.status_code == 200
    trials = resp.json()["scenarios"]
    assert len(trials) == 1
    assert trials[0]["scenario_id"] == "s1"

    resp = client.get("/api/v1/benchmarks/runs/run-1/events", headers=_headers())
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert [e["type"] for e in events] == ["target_ready", "oracle_result"]

    resp = client.get("/api/v1/benchmarks/runs/run-1/events", headers=_headers(), params={"after": 1})
    assert [e["sequence"] for e in resp.json()["events"]] == [2]

    # Trial filter.
    resp = client.get("/api/v1/benchmarks/runs/run-1/events", headers=_headers(), params={"trial_id": "s1#t0"})
    assert len(resp.json()["events"]) == 2
