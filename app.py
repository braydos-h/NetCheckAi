"""ASGI application factory for the BreachPilot WebUI API daemon.

Called by ``main._run_daemon`` (``--daemon`` (legacy alias: ``--demon``)). Creates a FastAPI
app with all routers mounted under ``/api/v1``, error handlers, CORS/origin
middleware, bearer auth, and a lifespan handler that recovers interrupted runs
on startup and cleans up the active run on shutdown.

The app stays thin — orchestration lives in ``tools/api/`` services so this
file does not become a second copy of ``main.py``.
"""
# BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from tools.api.auth import (
    BearerAuth,
    assert_api_loopback,
    is_loopback_origin,
    load_or_create_token,
)
from tools.api.errors import install_error_handlers, install_middleware
from tools.api.event_broker import EventBrokerRegistry
from tools.api.persistence import ApiPersistence
from tools.api.routes import benchmarks as benchmarks_routes
from tools.api.routes import connections as connections_routes
from tools.api.routes import decisions as decisions_routes
from tools.api.routes import events as events_routes
from tools.api.routes import graph as graph_routes
from tools.api.routes import graph_explorer as graph_explorer_routes
from tools.api.routes import ops as ops_routes
from tools.api.routes import runs as runs_routes
from tools.api.routes import system as system_routes
from tools.api.routes import users as users_routes
from tools.api.run_manager import RunManager
from tools.benchmark.service import BenchmarkService
from tools.benchmark.storage import BenchmarkStorage


def create_app(
    *,
    config_path: Path = Path("config.yaml"),
    callables: Any = None,
    config: dict[str, Any] | None = None,
) -> FastAPI:
    """Create the ASGI application.

    Loads config, generates/loads the bearer token, wires persistence, event
    broker, run manager, and all route modules. Loopback-only bind is enforced
    at startup (``--api-host`` is validated in ``main._run_daemon`` before
    calling ``create_app``; this factory re-validates defensively).

    ``callables`` is an optional ``Callables`` instance for the ``RunManager``
    (used by tests to inject fake routers without hitting Ollama). When None,
    the ``RunManager`` uses ``_DEFAULT_CALLABLES`` (direct imports).

    ``config`` is an optional in-memory config override. When provided, it
    replaces the on-disk load entirely (used by ``--web`` to set
    ``api.serve_webui`` without writing to ``config.yaml``). When None, the
    factory loads from ``config_path`` as before.
    """
    from tools import config_cli as _config_cli

    if config is None:
        config = _config_cli.load_config(config_path)
    api_cfg = config.get("api", {}) or {}
    host = api_cfg.get("host", "127.0.0.1")
    assert_api_loopback(host)

    # Bearer token.
    token = load_or_create_token(
        api_cfg.get("token_file", ".webui_secret_key"),
        env_override=os.environ.get("BREACHPILOT_API_TOKEN", ""),
    )
    auth = BearerAuth(token)

    # Reports dir + persistence.
    reports_dir = Path(config.get("reports_dir", "reports"))
    reports_dir.mkdir(parents=True, exist_ok=True)
    persistence = ApiPersistence(reports_dir)

    # Event broker registry.
    buffer_size = int(api_cfg.get("event_buffer_size", 256))
    if buffer_size < 1:
        raise ValueError("api.event_buffer_size must be at least 1.")
    event_registry = EventBrokerRegistry(reports_dir, buffer_size=buffer_size)

    # Run manager.
    run_manager = RunManager(
        persistence,
        event_registry,
        config=config,
        config_path=config_path,
        callables=callables,
    )

    # Benchmark suite (tools/benchmark/): service owns the active benchmark
    # run; storage reads/writes reports/benchmarks/<suite>/<run_id>/.
    # ponytail: single global cap — runs + benchmarks share max_concurrent_runs,
    # wired via explicit constructor injection (no private cross-link pokes).
    benchmark_cfg = config.get("benchmark", {}) or {}
    benchmark_storage = BenchmarkStorage(
        str(benchmark_cfg.get("output_dir", "reports/benchmarks") or "reports/benchmarks")
    )
    benchmark_service = BenchmarkService(config, config_path, run_manager=run_manager)
    run_manager.benchmark_service = benchmark_service

    # Lifespan: recover interrupted runs on startup; cancel active run on shutdown.
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        persistence.recover_interrupted()
        # Seed built-in demo session (idempotent; tombstone-aware; no network/LLM).
        try:
            from tools.api.demo_seed import ensure_demo_seed

            ensure_demo_seed(persistence, reports_dir)
        except Exception:  # noqa: BLE001 -- demo-seed is best-effort idempotent startup; a seed failure must not block the daemon
            pass
        # Warm process-global caches (plugins/skills/model router) in the
        # background so the first POST /runs doesn't pay cold-start costs.
        from tools.run_service.warmup import start_background_warmup

        start_background_warmup(config)
        yield
        await run_manager.shutdown()
        await benchmark_service.shutdown()

    app = FastAPI(
        title="BreachPilot WebUI API",
        version="v1",
        description="Local WebUI API for AI-driven penetration testing assessments.",
        lifespan=lifespan,
    )

    # CORS: only loopback + configured origins.
    configured_origins = api_cfg.get("allowed_origins", [])
    if not isinstance(configured_origins, list) or not all(isinstance(origin, str) for origin in configured_origins):
        raise ValueError("api.allowed_origins must be a list of loopback origins.")
    allowed_origins = list(dict.fromkeys(configured_origins))
    if any(not is_loopback_origin(origin, allowed_origins) for origin in allowed_origins):
        raise ValueError("api.allowed_origins may contain only loopback HTTP(S) origins.")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins + ["http://127.0.0.1", "http://localhost", "http://[::1]"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Error handlers + request-id middleware.
    install_error_handlers(app)
    install_middleware(app)

    # Build per-app routers via factories (no shared globals).
    system_router = system_routes.create_router(auth, config, config_path, run_manager, persistence)
    runs_router = runs_routes.create_router(auth, persistence, run_manager)
    decisions_router = decisions_routes.create_router(auth, run_manager)
    events_router = events_routes.create_router(auth, event_registry, persistence, token, allowed_origins)
    graph_router = graph_routes.create_router(auth, persistence, config)
    graph_explorer_router = graph_explorer_routes.create_router(auth, persistence, config)
    connections_router = connections_routes.create_router(auth, config, config_path)
    benchmarks_router = benchmarks_routes.create_router(auth, benchmark_service, benchmark_storage, config)
    ops_router = ops_routes.create_router(auth, config)
    users_router = None
    if bool(api_cfg.get("multi_operator", False)):
        users_router = users_routes.create_router(auth, persistence)

    # Mount routers.
    app.include_router(system_router)
    app.include_router(runs_router)
    app.include_router(decisions_router)
    app.include_router(events_router)
    app.include_router(graph_router)
    app.include_router(graph_explorer_router)
    app.include_router(connections_router)
    app.include_router(benchmarks_router)
    app.include_router(ops_router)
    if users_router is not None:
        app.include_router(users_router)

    # Optional: serve the bundled WebUI from webui/dist/ when
    # ``api.serve_webui`` is true and the build exists. Mounted LAST so the
    # /api/v1 routes, /docs, and /openapi.json are never shadowed. The SPA
    # fallback returns index.html for unknown non-API paths so client-side
    # deep links (/runs/:id, /system) work on refresh.
    if bool(api_cfg.get("serve_webui", False)):
        from starlette.responses import FileResponse, PlainTextResponse
        from starlette.routing import Route
        from starlette.staticfiles import StaticFiles

        webui_dist = Path(__file__).resolve().parent / "webui" / "dist"
        index_html = webui_dist / "index.html"
        assets_dir = webui_dist / "assets"
        if index_html.exists():
            if assets_dir.exists():
                app.mount(
                    "/assets",
                    StaticFiles(directory=str(assets_dir)),
                    name="webui-assets",
                )

            # SPA fallback: unknown non-API paths return index.html so
            # client-side deep links work on refresh. Added as a raw Starlette
            # route (not a FastAPI decorator) so it stays out of OpenAPI schema
            # generation. API/docs/openapi routes are matched first by
            # FastAPI's router and never reach here. Resolved-path guard
            # blocks traversal outside webui/dist.
            _webui_dist_resolved = webui_dist.resolve()
            _index_html_resolved = index_html.resolve()

            class _WebuiSpaResponse(PlainTextResponse):
                """Marker response type so FastAPI does not infer a response model."""

            async def _webui_spa(request: Any) -> _WebuiSpaResponse:
                full_path = request.path_params.get("full_path", "")
                if full_path.startswith(("api/", "docs", "openapi.json", "redoc", "assets/")):
                    return _WebuiSpaResponse("Not found", status_code=404)
                if full_path:
                    # Reject traversal probes before touching the filesystem.
                    # On Windows, percent-decoded probes like "//../../../boot.ini"
                    # become "\\..\..\boot.ini" — pathlib treats the leading
                    # backslashes as a rooted UNC path, so (webui_dist / full_path)
                    # discards the base entirely and ntpath.realpath() raises
                    # PermissionError [WinError 31] on the device path. No SPA
                    # deep link ever contains ".." or begins with a separator.
                    segments = full_path.replace("\\", "/").split("/")
                    if (
                        ".." in segments
                        or full_path.startswith(("/", "\\"))
                        or (len(full_path) >= 2 and full_path[1] == ":" and full_path[0].isalpha())
                    ):
                        return _WebuiSpaResponse("Not found", status_code=404)
                    try:
                        candidate = (webui_dist / full_path).resolve()
                        candidate.relative_to(_webui_dist_resolved)
                    except (ValueError, OSError):
                        # ValueError: candidate outside dist; OSError: malformed
                        # path (NUL bytes, exotic reserved names) that realpath
                        # refuses. Either way: not a servable path.
                        return _WebuiSpaResponse("Not found", status_code=404)
                    if candidate.is_file():
                        return FileResponse(str(candidate))  # type: ignore[return-value]
                return FileResponse(str(_index_html_resolved))  # type: ignore[return-value]

            app.router.routes.append(
                Route("/{full_path:path}", endpoint=_webui_spa, name="webui-spa", include_in_schema=False)
            )

            # FastAPI's default openapi() scans all routes, including the raw
            # Starlette SPA route and the /assets Mount above, which break
            # schema generation (FileResponse/StaticFiles have no pydantic
            # model). Override openapi() to temporarily remove the webui-only
            # routes so /openapi.json stays valid. The API routes live inside
            # _IncludedRouter wrappers and are unaffected.
            _webui_route_names = {"webui-spa", "webui-assets"}
            _original_openapi = app.openapi

            def _filtered_openapi():
                # app.routes is a read-only property backed by
                # app.router.routes (the same list object). Temporarily
                # remove the webui-only routes in-place, then restore them.
                original_routes = list(app.router.routes)
                app.router.routes[:] = [
                    r for r in original_routes if getattr(r, "name", None) not in _webui_route_names
                ]
                try:
                    return _original_openapi()
                finally:
                    app.router.routes[:] = original_routes

            app.openapi = _filtered_openapi  # type: ignore[assignment]

    return app
