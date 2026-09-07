"""Benchmark routes: suites, runs, live events (SSE), baseline, comparison.

All benchmark business logic lives in :mod:`tools.benchmark` (runner/service/
storage/regression) — these handlers are thin transport adapters following the
existing route conventions (bearer auth, stable error shape).
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, TypedDict

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from tools.api.auth import BearerAuth
from tools.benchmark.regression import (
    DEFAULT_BASELINE_PATH,
    compare_summaries_payload,
    load_baseline,
    save_baseline,
)
from tools.benchmark.service import BenchmarkService
from tools.benchmark.storage import BenchmarkStorage


class BenchmarkRunRequest(BaseModel):
    """POST /benchmarks/run body (all optional except suite)."""

    suite: str = Field(..., description="Benchmark suite id (e.g. 'xben')")
    scenarios: list[str] = Field(default_factory=list, description="Restrict to scenario ids")
    tags: list[str] = Field(default_factory=list, description="Restrict to tagged scenarios")
    trials: int | None = Field(None, ge=1, le=20, description="Repeated trials per scenario")
    model: str = Field("", description="Model alias override (recorded, never substituted)")
    reasoning: str = Field("", description="Reasoning profile label for the run")
    sandbox_required: bool | None = Field(None, description="Require the sandbox (default benchmark.sandbox_required)")
    timeout_seconds: int | None = Field(None, ge=30, description="Per-trial mission timeout override")
    save_baseline: bool = Field(False, description="Persist this run as the regression baseline")
    check_regression: bool = Field(False, description="Compare against the saved baseline")


class _SuiteCache(TypedDict):
    """TTL cache for suite discovery (avoids re-parsing manifests on every poll)."""

    expiry: float
    data: list[dict[str, Any]] | None


def create_router(
    auth: BearerAuth, service: BenchmarkService, storage: BenchmarkStorage, config: dict[str, Any]
) -> APIRouter:
    """Create a benchmarks router with isolated dependencies."""
    router = APIRouter(prefix="/api/v1/benchmarks", tags=["benchmarks"])

    # Lightweight TTL cache for suite discovery — per-router so apps don't share.
    _suite_cache: _SuiteCache = {"expiry": 0.0, "data": None}
    _suite_ttl_s = 15.0

    async def _require_auth(request: Request) -> str:
        return await auth(request)

    def _service() -> BenchmarkService:
        return service

    def _storage() -> BenchmarkStorage:
        return storage

    def _resolve_run(run_id: str) -> tuple[str, dict[str, Any]]:
        """Find a run across suites by its id (run ids are globally unique)."""
        st = _storage()
        for suite in st.list_suites():
            run = st.load_run(suite, run_id)
            if run is not None:
                return suite, run
        raise HTTPException(status_code=404, detail="Benchmark run not found")

    def _suite_list() -> list[dict[str, Any]]:
        # Serve from TTL cache when fresh — avoids re-parsing manifests on every overview poll.
        cached_expiry = _suite_cache.get("expiry", 0.0) or 0.0
        if time.monotonic() < cached_expiry and _suite_cache.get("data") is not None:
            return list(_suite_cache["data"] or [])
        from tools.benchmark import register_default_providers
        from tools.benchmark.registry import list_suites as registry_suites

        register_default_providers()
        data = registry_suites()
        _suite_cache["data"] = data
        _suite_cache["expiry"] = time.monotonic() + _suite_ttl_s
        return data

    def _baseline_path() -> Path:
        benchmark_cfg = config.get("benchmark", {}) or {}
        return Path(str(benchmark_cfg.get("baseline_path", "")) or DEFAULT_BASELINE_PATH)

    def _baseline_meta() -> dict[str, Any]:
        baseline = load_baseline(_baseline_path())
        if not baseline:
            return {"exists": False, "path": str(_baseline_path())}
        return {"exists": True, "path": str(_baseline_path()), **baseline}

    # ── discovery ───────────────────────────────────────────────────────────────

    @router.get("")
    async def benchmarks_overview(auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Overview: registered suites, recent runs, active-run status, baseline."""
        svc = _service()
        st = _storage()
        return {
            "suites": _suite_list(),
            "runs": st.list_runs()[:20],
            "active": svc.status(),
            "baseline": _baseline_meta(),
        }

    @router.get("/suites")
    async def list_suites_route(auth: str = Depends(_require_auth)) -> dict[str, Any]:
        return {"suites": _suite_list()}

    @router.get("/suites/{suite_id}/scenarios")
    async def list_scenarios_route(suite_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        from tools.benchmark import register_default_providers
        from tools.benchmark.registry import get_provider
        from tools.benchmark.registry import list_scenarios as registry_scenarios

        register_default_providers()
        try:
            get_provider(suite_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"suite": suite_id, "scenarios": registry_scenarios(suite_id)}

    @router.get("/suites/{suite_id}/readiness")
    async def suite_readiness_route(suite_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Lab-target readiness for a suite (preflight before pressing Run).

        Host-type scenarios are TCP-probed on their declared ports (same probe
        the runner uses to fail fast); docker scenarios with an image are
        self-provisioned by the runner and need no lab. A run started while
        ``ready`` is false finishes instantly with
        ``INFRASTRUCTURE_ERROR/TARGET_PROVISION_FAILED`` — this endpoint lets
        the WebUI say so up front instead of looking like a skipped run.
        """
        from tools.benchmark import register_default_providers
        from tools.benchmark.registry import get_provider
        from tools.benchmark.targets import target_ports_reachable

        register_default_providers()
        try:
            provider = get_provider(suite_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        targets: list[dict[str, Any]] = []
        for scenario in provider.load_scenarios():
            if scenario.target_type == "docker" and scenario.target_image:
                targets.append(
                    {
                        "scenario_id": scenario.scenario_id,
                        "target_type": scenario.target_type,
                        "target_host": scenario.target_host,
                        "target_ports": list(scenario.target_ports),
                        "reachable": True,
                        "self_provisioned": True,
                        "detail": "runner provisions the image per trial (no lab needed)",
                    }
                )
                continue
            if scenario.target_type == "docker":
                targets.append(
                    {
                        "scenario_id": scenario.scenario_id,
                        "target_type": scenario.target_type,
                        "target_host": scenario.target_host,
                        "target_ports": list(scenario.target_ports),
                        "reachable": False,
                        "self_provisioned": False,
                        "detail": "docker target without target_image (provision would fail)",
                    }
                )
                continue
            reachable = (
                target_ports_reachable(scenario.target_host, list(scenario.target_ports), timeout=0.5)
                if scenario.target_ports
                else True
            )
            targets.append(
                {
                    "scenario_id": scenario.scenario_id,
                    "target_type": scenario.target_type,
                    "target_host": scenario.target_host,
                    "target_ports": list(scenario.target_ports),
                    "reachable": reachable,
                    "self_provisioned": False,
                    "detail": "" if reachable else "lab target refused all declared ports",
                }
            )
        ready = all(t["reachable"] for t in targets)
        return {
            "suite": suite_id,
            "ready": ready,
            "lab_command": "docker compose -f eval_targets/docker-compose.yml up -d",
            "targets": targets,
        }

    # ── runs ────────────────────────────────────────────────────────────────────

    @router.get("/runs")
    async def list_runs(
        suite: str | None = Query(None), limit: int = Query(50, ge=1, le=200), auth: str = Depends(_require_auth)
    ) -> dict[str, Any]:
        runs = _storage().list_runs(suite)[:limit]
        return {"runs": runs}

    @router.get("/runs/{run_id}")
    async def get_run(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        suite, run = _resolve_run(run_id)
        run["summary"] = _storage().load_summary(suite, run_id)
        return run

    @router.get("/runs/{run_id}/scenarios")
    async def get_run_scenarios(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        suite, _run = _resolve_run(run_id)
        run_dir = _storage().run_dir(suite, run_id)
        scenarios_dir = run_dir / "scenarios"
        results: list[dict[str, Any]] = []
        if scenarios_dir.exists():
            for scenario_dir in sorted(p for p in scenarios_dir.iterdir() if p.is_dir()):
                for trial_path in sorted(scenario_dir.glob("trial_*.json")):
                    if trial_path.name.endswith("_events.jsonl"):
                        continue
                    try:
                        results.append(json.loads(trial_path.read_text(encoding="utf-8")))
                    except (OSError, json.JSONDecodeError):
                        continue
        return {"run_id": run_id, "scenarios": results}

    @router.get("/runs/{run_id}/events")
    async def get_run_events(
        run_id: str,
        after: int = Query(0, ge=0),
        trial_id: str = Query(""),
        limit: int = Query(1000, ge=1, le=5000),
        auth: str = Depends(_require_auth),
    ) -> dict[str, Any]:
        suite, _run = _resolve_run(run_id)
        events = _storage().load_events(suite, run_id, trial_id=trial_id, after=after, limit=limit)
        latest = max((int(e.get("sequence", 0) or 0) for e in events), default=after)
        return {"run_id": run_id, "events": events, "latest_sequence": latest}

    @router.get("/runs/{run_id}/events/stream")
    async def stream_run_events(
        run_id: str, after: int = Query(0, ge=0), auth: str = Depends(_require_auth)
    ) -> StreamingResponse:
        """SSE stream: replays stored events from ``after``, then streams live."""
        suite, _run = _resolve_run(run_id)
        svc = _service()
        st = _storage()

        async def _gen():
            queue = svc.subscribe()
            try:
                cursor = after
                idle = 0
                while True:
                    events = st.load_events(suite, run_id, after=cursor, limit=500)
                    for event in events:
                        cursor = max(cursor, int(event.get("sequence", 0) or 0))
                        yield f"data: {json.dumps(event, default=str)}\n\n"
                    if events:
                        idle = 0
                        continue
                    idle += 1
                    if idle > 60:  # ~60s without events: close so the client can re-poll
                        break
                    try:
                        live = await asyncio.wait_for(queue.get(), timeout=1.0)
                    except asyncio.TimeoutError:
                        yield ": heartbeat\n\n"
                        continue
                    if live is None:
                        break
            finally:
                svc.unsubscribe(queue)

        return StreamingResponse(_gen(), media_type="text/event-stream")

    @router.post("/run")
    async def start_run(body: BenchmarkRunRequest, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        result = await _service().start_run(body.model_dump(exclude_none=True))
        if "error" in result:
            raise HTTPException(status_code=409, detail=result["error"])
        return result

    @router.post("/runs/{run_id}/cancel")
    async def cancel_run(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        svc = _service()
        if svc.active_run_id != run_id:
            raise HTTPException(status_code=404, detail="Run is not active (only the active run can be cancelled)")
        cancelled = await svc.cancel()
        return {"run_id": run_id, "cancelled": cancelled}

    # ── baseline & comparison ───────────────────────────────────────────────────

    @router.get("/baseline")
    async def get_baseline(auth: str = Depends(_require_auth)) -> dict[str, Any]:
        return _baseline_meta()

    @router.post("/baseline")
    async def save_baseline_route(body: dict[str, Any], auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Persist a completed run's summary as the regression baseline."""
        run_id = str(body.get("run_id", "") or "")
        if not run_id:
            raise HTTPException(status_code=400, detail="run_id is required")
        suite, _run = _resolve_run(run_id)
        summary = _storage().load_summary(suite, run_id)
        if not summary:
            raise HTTPException(status_code=409, detail="Run has no summary yet (still running or failed)")
        from tools.benchmark.metrics import run_summary_from_dict

        path = _baseline_path()
        save_baseline(run_summary_from_dict(summary), path)
        return {"saved": True, "path": str(path), "run_id": run_id}

    @router.get("/compare")
    async def compare_runs(
        run_a: str = Query(..., description="Baseline run id"),
        run_b: str = Query(..., description="Candidate run id"),
        auth: str = Depends(_require_auth),
    ) -> dict[str, Any]:
        suite_a, run_a_payload = _resolve_run(run_a)
        suite_b, run_b_payload = _resolve_run(run_b)
        summary_a = _storage().load_summary(suite_a, run_a)
        summary_b = _storage().load_summary(suite_b, run_b)
        if not summary_a or not summary_b:
            raise HTTPException(status_code=409, detail="Both runs must be completed (summaries required)")
        comparison = compare_summaries_payload(summary_a, summary_b)
        return {
            "run_a": {"run_id": run_a, "suite": suite_a, "summary": summary_a},
            "run_b": {"run_id": run_b, "suite": suite_b, "summary": summary_b},
            "comparison": comparison,
        }

    return router
