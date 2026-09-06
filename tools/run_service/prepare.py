"""AssessmentService: transport-neutral preparation and execution of runs.

Split from ``main.async_main`` so the CLI and the WebUI API daemon both drive
assessments through one code path. ``prepare`` resolves target/goal/settings
and returns a ``RunPreview`` (no I/O side effects beyond config reads);
``execute`` opens the MCP session, runs the agent loop, handles swarm, writes
reports, and returns a ``RunResult``.

The CLI supplies ``TerminalDecisionProvider`` / ``TerminalEventSink`` /
``TerminalApprovalProvider`` (backed by ``AttackUi``); the API supplies the
async adapters backed by persisted decisions + WebSocket events. The service
never calls ``AttackUi`` directly -- it emits events and requests decisions
through the provider/sink interfaces.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.attack_ui import get_ui
from tools.goal_engine import GoalEngine
from tools.mcp_session import (
    open_exploit_mcp_session,
)
from tools.model_router import build_router, format_model_choice
from tools.model_telemetry import usage_log_path, workspace_root_from_sources
from tools.run_service.models import (
    RunPreview,
    RunRequest,
)

log = logging.getLogger("breachpilot.run_create")

# Human-readable text for preparation progress events (safe for the UI — no
# targets, config values, or internals; stage ids are what clients key on).
_STAGE_MESSAGES: dict[str, str] = {
    "config": "Loading configuration",
    "plugins": "Loading plugins",
    "router": "Preparing model",
    "model": "Preparing model",
    "target_validate": "Validating target",
    "target_resolve": "Resolving target",
    "goals": "Loading run settings",
    "exploit_settings": "Loading run settings",
    "skills": "Loading skills",
    "filesystem": "Preparing run",
}

# Exploit-action tool names that count toward ``successful_exploits`` in the
# derived campaign_result. Recon/research tools with exit_code==0 are NOT
# exploits. Mirrors the _EXPLOIT_ACTIONS set used by the loop's outcome tracker.
_EXPLOIT_TOOL_ACTIONS = frozenset(
    {
        "run_exploit_terminal",
        "run_python_file",
        "run_msf_module",
        "msf_run_exploit",
        "run_attack_module",
        "lateral_exec",
        "generate_payload",
        "msf_generate_payload",
        "craft_exploit",
    }
)


def _build_campaign_result_from_records(
    result: dict[str, Any],
    target_ip: str,
) -> dict[str, Any] | None:
    """Build a minimal ``campaign_result`` for EnhancedReportGenerator.

    Flow A's run_exploit_agent does not run an AutonomousOrchestrator campaign,
    so it never produced the ``{states: {target: AttackState.to_dict()}}`` shape
    EnhancedReportGenerator consumes. This folds the per-target audit records
    into that shape so the WebUI attack-graph has data to render.

    Returns None when there are no records (e.g. a recon-only run).
    """
    records = result.get("records") or []
    if not records:
        return None
    successful: list[str] = []
    failed: dict[str, list[str]] = {}
    timeline: list[dict[str, Any]] = []
    privilege_level = "none"
    # Closed-loop retest: keep the first successful command per exploit action
    # as the finding's stored verification probe (same shell_command vocabulary
    # as the killchain verify specs). retest_finding re-executes ONLY this.
    exploit_probes: dict[str, dict[str, Any]] = {}
    # ponytail: the verified-compromise signal lives in outcome_summary, not
    # in per-record ``status == "completed"``. A completed exploit-tool call
    # only means the tool ran -- the tightened outcome-truth classifier must
    # confirm a shell/root/SYSTEM/cred-dump marker for it to count as a
    # successful exploit. The old code counted any completed exploit action
    # as successful, inflating ``successful_exploits`` and the WebUI attack
    # graph with runs that never got a shell.
    summary = str(result.get("outcome_summary", "") or "")
    _run_verified_compromise = ("compromises: " in summary and "compromises: 0" not in summary) or (
        "cred dumps: " in summary and "cred dumps: 0" not in summary
    )
    for rec in records:
        if not isinstance(rec, dict):
            continue
        action = str(rec.get("action", "") or "")
        status = str(rec.get("status", "") or "")
        exit_code = rec.get("exit_code")
        ts = str(rec.get("timestamp", "") or "")
        detail = str(rec.get("detail", "") or rec.get("command", "") or "")
        is_exploit = action in _EXPLOIT_TOOL_ACTIONS
        if status in {"blocked", "analyzer_error", "SCOPE_DENIED"} or (exit_code is not None and int(exit_code) != 0):
            failed.setdefault(action, []).append(detail[:200] or status)
            timeline.append(
                {
                    "timestamp": ts,
                    "event_type": "failure",
                    "description": detail[:200] or status,
                    "metadata": {"module": action},
                }
            )
        elif status == "completed" and is_exploit and _run_verified_compromise:
            successful.append(action)
            probe_cmd = str(rec.get("command", "") or detail or "")
            if action not in exploit_probes and probe_cmd.strip():
                exploit_probes[action] = {"type": "shell_command", "exec": probe_cmd[:4000]}
            timeline.append(
                {
                    "timestamp": ts,
                    "event_type": "success",
                    "description": detail[:200] or action,
                    "metadata": {"module": action},
                }
            )
        else:
            timeline.append(
                {
                    "timestamp": ts,
                    "event_type": status or "observation",
                    "description": detail[:200] or action,
                    "metadata": {"module": action},
                }
            )
    # Heuristic privilege level from the outcome summary string if present.
    for label in ("root", "SYSTEM", "system", "admin", "NT AUTHORITY"):
        if label.lower() in summary.lower():
            privilege_level = label.lower() if label != "NT AUTHORITY" else "system"
            break
    return {
        "states": {
            target_ip: {
                "successful_exploits": successful,
                "failed_attempts": failed,
                "privilege_level": privilege_level,
                "timeline": timeline,
                "recon_result": {"services": []},
                "credentials_found": [],
                "exploit_probes": exploit_probes,
            },
        },
    }


class _CreateTimings:
    """Per-stage monotonic timing for one run creation.

    ``mark(stage)`` closes the previous stage and starts the next one; every
    duration is measured with :func:`time.perf_counter`. The summary log line
    carries stage ids + milliseconds only — never targets, hostnames, config
    values, or secrets.
    """

    __slots__ = ("stages", "_start", "_last")

    def __init__(self) -> None:
        self.stages: dict[str, float] = {}
        self._start = time.perf_counter()
        self._last = self._start

    def mark(self, stage: str) -> float:
        now = time.perf_counter()
        ms = (now - self._last) * 1000.0
        self._last = now
        if stage:
            self.stages[stage] = round(ms, 1)
        return ms

    def total_ms(self) -> float:
        return (time.perf_counter() - self._start) * 1000.0

    def summary(self, *, run_id: str = "") -> str:
        lines = [f"  {name}: {ms}ms" for name, ms in self.stages.items()]
        lines.append(f"  total: {self.total_ms():.0f}ms")
        suffix = f" (run {run_id})" if run_id else ""
        return f"run create timing{suffix}:\n" + "\n".join(lines)


def _log_create_timings(timings: _CreateTimings, *, run_id: str = "") -> None:
    """Log the create timing breakdown. INFO when slow, DEBUG when fast."""
    total = timings.total_ms()
    text = timings.summary(run_id=run_id)
    if total >= 1000.0:
        log.info("%s", text)
    else:
        log.debug("%s", text)


ui = get_ui()

# Serializes cold plugin/skill-registry init across concurrent ``prepare``
# calls (which now run on worker threads) so they don't race first-time setup.
_COLD_INIT_LOCK = threading.Lock()


def _llm_usage_line_count() -> int:
    """Line count of the shared llm_usage.jsonl, or 0 if absent."""
    try:
        path = usage_log_path(workspace_root_from_sources())
        if not path.exists():
            return 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def _run_telemetry(start_lines: int) -> dict[str, Any] | None:
    """Aggregate llm_usage.jsonl records appended after ``start_lines``."""
    import json as _json

    try:
        path = usage_log_path(workspace_root_from_sources())
        if not path.exists():
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    new_lines = lines[start_lines:] if start_lines <= len(lines) else lines
    calls = 0
    total_tokens = 0
    ctx_values: list[float] = []
    last_ctx_pct: float | None = None
    last_ctx_window: int | None = None
    last_est_ctx: int | None = None
    for line in new_lines:
        try:
            item = _json.loads(line)
        except _json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        calls += 1
        tok = item.get("total_tokens")
        if isinstance(tok, (int, float)):
            total_tokens += int(tok)
        ctx = item.get("context_usage_pct")
        if isinstance(ctx, (int, float)):
            ctx_values.append(float(ctx))
            last_ctx_pct = float(ctx)
        win = item.get("context_window_tokens")
        if isinstance(win, int):
            last_ctx_window = win
        est = item.get("estimated_context_tokens")
        if isinstance(est, int):
            last_est_ctx = est
    if not calls:
        return None
    avg_ctx = (sum(ctx_values) / len(ctx_values)) if ctx_values else None
    max_ctx = max(ctx_values) if ctx_values else None
    return {
        "calls": calls,
        "total_tokens": total_tokens,
        "avg_ctx": avg_ctx,
        "max_ctx": max_ctx,
        "context_window_tokens": last_ctx_window,
        "last_ctx_pct": last_ctx_pct,
        "last_estimated_context_tokens": last_est_ctx,
    }


class _TelemetryAccumulator:
    """Incremental reader for llm_usage.jsonl.

    Tracks a byte offset into the shared usage log and only parses lines
    appended since the last snapshot, instead of re-reading the whole file on
    every tick. Handles truncation (log rotated/reset) by resetting to zero.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._offset = path.stat().st_size if path.exists() else 0
        self._calls = 0
        self._total_tokens = 0
        self._ctx_values: list[float] = []
        self._last_ctx_pct: float | None = None
        self._last_ctx_window: int | None = None
        self._last_est_ctx: int | None = None

    def snapshot(self) -> dict[str, Any] | None:
        import json as _json

        try:
            size = self._path.stat().st_size
        except OSError:
            return self._aggregate()
        if size < self._offset:
            # Truncated (rotated/reset) — start over.
            self._offset = 0
            self._calls = 0
            self._total_tokens = 0
            self._ctx_values = []
            self._last_ctx_pct = None
            self._last_ctx_window = None
            self._last_est_ctx = None
        if size > self._offset:
            try:
                with self._path.open("rb") as handle:
                    handle.seek(self._offset)
                    data = handle.read()
            except OSError:
                return self._aggregate()
            last_nl = data.rfind(b"\n")
            if last_nl != -1:
                complete = data[: last_nl + 1]
                self._offset += len(complete)
                for raw in complete.splitlines():
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        item = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    if not isinstance(item, dict):
                        continue
                    self._calls += 1
                    tok = item.get("total_tokens")
                    if isinstance(tok, (int, float)):
                        self._total_tokens += int(tok)
                    ctx = item.get("context_usage_pct")
                    if isinstance(ctx, (int, float)):
                        self._ctx_values.append(float(ctx))
                        self._last_ctx_pct = float(ctx)
                    win = item.get("context_window_tokens")
                    if isinstance(win, int):
                        self._last_ctx_window = win
                    est = item.get("estimated_context_tokens")
                    if isinstance(est, int):
                        self._last_est_ctx = est
        return self._aggregate()

    def _aggregate(self) -> dict[str, Any] | None:
        if not self._calls:
            return None
        avg_ctx = (sum(self._ctx_values) / len(self._ctx_values)) if self._ctx_values else None
        max_ctx = max(self._ctx_values) if self._ctx_values else None
        return {
            "calls": self._calls,
            "total_tokens": self._total_tokens,
            "avg_ctx": avg_ctx,
            "max_ctx": max_ctx,
            "context_window_tokens": self._last_ctx_window,
            "last_ctx_pct": self._last_ctx_pct,
            "last_estimated_context_tokens": self._last_est_ctx,
        }


def _read_swarm_snapshot(swarm_workspace: Path) -> str:
    """One-line live progress string from swarm_state.json, or ""."""
    import json as _json

    path = swarm_workspace / "swarm_state.json"
    try:
        if not path.exists():
            return ""
        data = _json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, _json.JSONDecodeError):
        return ""
    agents = data.get("agents", []) if isinstance(data, dict) else []
    counts: dict[str, int] = {}
    for agent in agents:
        if isinstance(agent, dict):
            status = str(agent.get("status", ""))
            counts[status] = counts.get(status, 0) + 1
    parts = []
    for key, label in (("complete", "done"), ("running", "running"), ("blocked", "blocked"), ("failed", "failed")):
        n = counts.get(key, 0)
        if n:
            parts.append(f"{n} {label}")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Callable injection — lets the CLI pass its monkeypatchable module-level
# symbols so existing tests that patch ``main.open_exploit_mcp_session`` etc.
# keep working. The API path leaves these as the direct-import defaults.
# ---------------------------------------------------------------------------


def _run_session_default(**kwargs: Any) -> Any:
    """Default run_exploit_session — imports lazily to avoid cycles."""
    from tools.exploit_session import run_exploit_session

    return run_exploit_session(**kwargs)


def _run_recon_default(**kwargs: Any) -> Any:
    """Default run_recon_assessment — imports lazily."""
    from tools.recon_assessment_cli import run_recon_assessment

    return run_recon_assessment(**kwargs)


def _run_safety_default(*args: Any, **kwargs: Any) -> Any:
    """Default run_safety_review — imports lazily."""
    from tools.safety_review_cli import run_safety_review

    return run_safety_review(*args, **kwargs)


def _witness_agent_default(config: dict[str, Any] | None, **kwargs: Any) -> Any:
    """Default WitnessAgent factory — imports lazily so the prepare path never
    pays the ``tools.swarm`` package import (which pulls every specialist
    agent + the orchestrator)."""
    from tools.swarm.agents.witness_agent import WitnessAgent

    return WitnessAgent(config, **kwargs)


@dataclass
class Callables:
    """Bundle of callables the service uses, overridable by the CLI path."""

    build_router: Callable[..., Any] = field(default=build_router)
    open_session: Callable[..., Any] = field(default=open_exploit_mcp_session)
    run_session: Callable[..., Any] = field(default=_run_session_default)
    goal_engine_cls: type = field(default=GoalEngine)
    run_recon_assessment: Callable[..., Any] = field(default=_run_recon_default)
    run_safety_review: Callable[..., Any] = field(default=_run_safety_default)
    # Advisory witness watcher factory (see tools/swarm/agents/witness_agent.py).
    # Called as ``witness_agent_factory(config, audit_paths=[...],
    # event_callback=...)`` only when ``witness.enabled`` is truthy.
    witness_agent_factory: Callable[..., Any] = field(default=_witness_agent_default)


_DEFAULT_CALLABLES = Callables()


class PrepareMixin:
    """Transport-neutral run preparation and execution.

    The CLI constructs this once per ``async_main`` call; the API constructs one
    per run (the ``RunManager`` owns the single active instance). The service
    holds no run-specific mutable state between ``prepare`` and ``execute`` --
    ``prepare`` returns a ``RunPreview`` that ``execute`` consumes.

    ``callables`` is an optional injection point for the CLI path so existing
    tests that monkeypatch ``main.open_exploit_mcp_session`` /
    ``main.run_exploit_session`` / ``main.build_router`` / ``main.GoalEngine``
    continue to work: ``async_main`` passes its own module-level symbols here,
    and the service uses them instead of its direct imports. The API path
    leaves this None and uses the direct imports from the source modules.
    """

    def __init__(
        self,
        *,
        config: dict[str, Any] | None = None,
        callables: "Callables | None" = None,
    ) -> None:
        self._config = config
        self._c = callables or _DEFAULT_CALLABLES

    # ponytail: one provider-aware router builder for both prepare/execute.
    # The ollama path calls ``self._c.build_router`` with ONLY the original
    # kwargs so test fakes that don't accept the new provider kwargs stay
    # byte-compatible; the chatgpt path forwards the extra kwargs (no test
    # exercises chatgpt with a fake router).
    def _build_router_for_config(self, config: dict[str, Any], req_timeout: float | None) -> Any:
        from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config

        ollama_host = config.get("ollama", {}).get("host", "https://api.ollama.com")
        registry = config.get("models", {}).get("registry")
        provider = get_ai_provider(config)
        if provider == "chatgpt":
            return self._c.build_router(
                registry,
                host=ollama_host,
                request_timeout_seconds=req_timeout,
                provider="chatgpt",
                chatgpt_config=get_chatgpt_config(config),
                config=config,
            )
        if provider == "opencode_go":
            return self._c.build_router(
                registry,
                host=ollama_host,
                request_timeout_seconds=req_timeout,
                provider="opencode_go",
                opencode_go_config=get_opencode_go_config(config),
                config=config,
            )
        return self._c.build_router(registry, host=ollama_host, request_timeout_seconds=req_timeout)

    def _ensure_client_registered(
        self,
        router: Any,
        config: dict[str, Any],
        model_alias: str,
        req_timeout: float | None,
    ) -> None:
        """Register a fallback ModelClient for ``model_alias`` if missing."""
        from tools.config_manager import get_ai_provider

        if model_alias in getattr(router, "_clients", {}):
            return
        try:
            router.get_client(model_alias)
            return
        except KeyError:
            pass
        if get_ai_provider(config) in ("chatgpt", "opencode_go"):
            from tools.model_router import build_model_client_for_provider

            router.register(
                model_alias, build_model_client_for_provider(config, model_alias, request_timeout_seconds=req_timeout)
            )
        else:
            from tools.model_router import _build_model_client

            ollama_host = config.get("ollama", {}).get("host", "https://api.ollama.com")
            router.register(
                model_alias,
                _build_model_client(model_alias, host=ollama_host, request_timeout_seconds=req_timeout),
            )

    def _resolve_model_alias(self, config: dict[str, Any], request: "RunRequest") -> str:
        """Resolve the model alias/id for the active provider.

        For ``chatgpt`` the alias namespace IS the GPT model id space, so an
        absent explicit ``request.model_alias`` falls back to
        ``chatgpt.default_model`` (NOT the ollama ``models.default_alias``,
        which would be an ollama id like ``glm``). For ``ollama`` this is the
        unchanged ``models.default_alias`` resolution.
        """
        if request.model_alias:
            return request.model_alias
        from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config

        provider = get_ai_provider(config)
        if provider == "chatgpt":
            return str(get_chatgpt_config(config).get("default_model") or "gpt-5.2")
        if provider == "opencode_go":
            return str(get_opencode_go_config(config).get("default_model") or "muse-spark-1.2-contributor")
        return config.get("models", {}).get("default_alias", "glm")

    # ------------------------------------------------------------------
    # Prepare: resolve target/goal/settings without I/O side effects
    # ------------------------------------------------------------------

    async def prepare(
        self,
        request: RunRequest,
        *,
        run_id: str | None = None,
        progress: "Callable[[str, str], None] | None" = None,
    ) -> RunPreview:
        """Resolve the target, goal, and effective settings; return a preview.

        Does NOT open the MCP session, does NOT write session_state.json, does
        NOT start any subprocess. The caller (CLI or API) shows the preview to
        the operator and asks for confirmation before calling ``execute``.

        ``run_id`` lets the API pre-allocate the run id (the run row is
        persisted as ``preparing`` before preparation starts); when omitted a
        timestamp id is generated as before (CLI path).

        ``progress(stage, message)`` is invoked synchronously from the worker
        thread at each preparation stage so transport layers (the WebUI API)
        can emit live progress events. Callback failures are swallowed —
        progress reporting must never break preparation.

        The body is synchronous (config load, plugin load, router build, target
        resolve, skill selection, mkdir), so it runs on a worker thread to keep
        the event loop responsive.
        """
        return await asyncio.to_thread(self._prepare_sync, request, run_id, progress)

    def _prepare_sync(
        self,
        request: RunRequest,
        run_id: str | None = None,
        progress: "Callable[[str, str], None] | None" = None,
    ) -> RunPreview:
        """Synchronous body of ``prepare`` (see above).

        Staged with monotonic timing (``_CreateTimings``) so the actual
        create-path bottleneck is measurable rather than guessed:
        config → plugins → router → model → target → goals → exploit_settings
        → skills → filesystem, with a total. The breakdown is logged per run
        (``breachpilot.run_create`` logger).
        """
        from tools import config_cli as _config_cli
        from tools.cli_exploit_settings import build_cli_exploit_settings
        from tools.skills_cli import _build_runtime_skill_selection, apply_skills_cli_overrides
        from tools.validation_utils import resolve_target_bounded as _resolve_target_bounded
        from tools.validation_utils import validate_target as _validate_target

        timings = _CreateTimings()

        def stage(name: str) -> None:
            timings.mark(name)
            if progress is not None:
                try:
                    progress(name, _STAGE_MESSAGES.get(name, name))
                except Exception:  # noqa: BLE001 -- progress never breaks prepare
                    pass

        config_path = request.config_path
        config = copy.deepcopy(self._config if self._config is not None else _config_cli.load_config(config_path))
        # Apply skills CLI overrides to the in-memory config.
        config = apply_skills_cli_overrides(config, _request_to_args(request))
        stage("config")

        # Load plugins (best-effort; failure never blocks boot). Cached by
        # config signature in tools.plugins — warm run creation skips discovery.
        try:
            from tools.plugins import load_plugins

            with _COLD_INIT_LOCK:
                load_plugins(config)
        except Exception:  # noqa: BLE001
            pass
        stage("plugins")

        # Build router + resolve model alias.
        ollama_host = config.get("ollama", {}).get("host", "https://api.ollama.com")
        _long_cfg = config.get("long_session", {}) or {}
        _ls_active = bool(request.long_session or _long_cfg.get("enabled", False))
        _req_timeout = (
            float(_long_cfg["request_timeout_seconds"])
            if (_ls_active and _long_cfg.get("request_timeout_seconds"))
            else None
        )
        router = self._build_router_for_config(config, _req_timeout)
        stage("router")

        model_alias = self._resolve_model_alias(config, request)
        self._ensure_client_registered(router, config, model_alias, _req_timeout)
        model_client = router.get_client(model_alias)
        stage("model")

        # Resolve target (IP or domain). DNS runs on a bounded worker thread —
        # a stalled resolver must never freeze run creation for minutes.
        original_target = request.target.strip()
        if not original_target:
            raise ValueError("Target is required.")
        if not _validate_target(original_target):
            raise ValueError(f"Invalid target (must be an IP or domain): {original_target}")
        stage("target_validate")

        dns_timeout = 5.0
        try:
            api_cfg = config.get("api", {}) or {}
            dns_timeout = float(api_cfg.get("dns_timeout_seconds", 5.0) or 5.0)
        except (TypeError, ValueError):
            dns_timeout = 5.0
        if dns_timeout <= 0:
            dns_timeout = 5.0
        try:
            resolved_ip, resolved_domain = _resolve_target_bounded(original_target, timeout_seconds=dns_timeout)
        except TimeoutError as exc:
            raise ValueError(
                f"Could not resolve target: {exc}. Check the hostname and your DNS settings, then try again."
            ) from exc
        except OSError as exc:
            raise ValueError(f"Could not resolve target: {exc}") from exc
        if resolved_domain and resolved_ip is None:
            raise ValueError(f"Could not resolve domain: {original_target}")
        target_ip = resolved_ip if resolved_ip is not None else original_target
        stage("target_resolve")

        # Determine mode.
        mode = request.mode
        if mode not in ("recon", "attack", "fast"):
            raise ValueError(f"Invalid mode: {mode!r}")

        # Determine goal (preset/custom). Recon-first and goal selection via
        # decision provider happen in ``execute``; here we resolve what we can
        # without I/O.
        goal_engine = self._c.goal_engine_cls()
        goal_name = request.goal_name.strip().lower()
        custom_text = request.custom_goal.strip()
        from tools.run_service.models import is_agent_attack_mode  # local to avoid cycle

        risk_profile = "high_authorized_testing" if is_agent_attack_mode(mode) else "standard_authorized"

        recon_first = request.recon_first
        if recon_first is None:
            recon_first = not goal_name and not custom_text

        # If we already have enough to resolve a goal, do it now.
        if custom_text:
            goal = goal_engine.get("custom", custom_text, risk_profile=risk_profile)
        elif goal_name and goal_engine.is_preset(goal_name):
            goal = goal_engine.get(goal_name, risk_profile=risk_profile)
        else:
            # No goal yet -- will be resolved during execute (recon-first or
            # interactive). Use a placeholder for preview purposes.
            goal = goal_engine.get("custom", goal_name or "recon-first goal selection", risk_profile=risk_profile)
        stage("goals")

        # Build exploit settings (pure data; no I/O).
        multi_model_consult = request.multi_model_consult
        if multi_model_consult is None:
            multi_model_consult = bool((config.get("multi_model", {}) or {}).get("enabled", False))
        exploit_settings = build_cli_exploit_settings(
            mode=mode,
            target_ip=target_ip,
            goal=goal,
            config=config,
            adaptive_exploits=request.adaptive_exploits,
            swarm=request.swarm,
            critic=request.critic,
            reflection=request.reflection,
            multi_model_enabled=bool(multi_model_consult),
            observer_mode=request.observer_mode,
            ultrathink=request.ultrathink,
            debug=request.debug,
            long_session=request.long_session,
        )
        stage("exploit_settings")

        # Skill selection (pure data; registry/embedder/store are process-cached).
        with _COLD_INIT_LOCK:
            skill_selection = _build_runtime_skill_selection(
                config=config,
                goal=goal,
                mode=mode,
                assessment=None,
                is_domain=bool(resolved_domain),
            )
        stage("skills")

        # Run ID + reports dir.
        if not run_id:
            run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        reports_dir = request.reports_dir / run_id
        reports_dir.mkdir(parents=True, exist_ok=True)
        stage("filesystem")

        # Effective settings for preview.
        exploit_cfg = config.get("exploit", {}) or {}
        permission_effective = str(exploit_cfg.get("permission", "read_only"))
        from tools.run_service.models import is_agent_attack_mode as _is_attack

        attack_mode_effective = _is_attack(mode)
        swarm_effective = request.swarm or bool((config.get("swarm", {}) or {}).get("enabled", False))
        parallel_swarm_effective = request.parallel_swarm or bool(
            (config.get("swarm", {}) or {}).get("parallel_enabled", False)
        )
        destructive = permission_effective == "full_access" and _is_attack(mode)
        _models_cfg = config.get("models", {}) if isinstance(config, dict) else {}
        model_label = format_model_choice(
            model_alias, registry=_models_cfg.get("registry", {}), registry_info=_models_cfg.get("info", {})
        )
        http_port = int(config.get("mcp", {}).get("http_port", 8001))

        required_text = ""
        if destructive:
            required_text = f"ALLOW {target_ip}"

        budgets = {
            "commands": getattr(
                exploit_settings, "attack_max_commands" if attack_mode_effective else "max_commands_per_session", "n/a"
            ),
            "rounds": getattr(exploit_settings, "attack_max_rounds" if attack_mode_effective else "max_rounds", "n/a"),
            "duration_minutes": getattr(exploit_settings, "attack_max_duration_minutes", "n/a")
            if attack_mode_effective
            else None,
        }

        timings.mark("")  # close the final stage
        _log_create_timings(timings, run_id=run_id)

        return RunPreview(
            run_id=run_id,
            reports_dir=reports_dir,
            config_path=config_path,
            target_ip=target_ip,
            original_target=original_target,
            resolved_ip=resolved_ip,
            resolved_domain=resolved_domain,
            mode=mode,
            goal_name=goal.name,
            goal_description=goal.description,
            model_alias=model_alias,
            model_label=model_label,
            transport_summary=f"http on port {http_port}",
            permission=permission_effective,
            attack_mode=attack_mode_effective,
            swarm=swarm_effective,
            parallel_swarm=parallel_swarm_effective,
            multi_model=bool(multi_model_consult),
            destructive=destructive,
            required_confirmation_text=required_text,
            budgets=budgets,
            skill_activations=[{"name": a.name, "reason": a.reason} for a in skill_selection.activations],
            skill_errors=list(skill_selection.errors),
            timings=dict(timings.stages),
            resumed_from=request.resume_source,
        )


def _config_cli_load(path: Path) -> dict[str, Any]:
    from tools import config_cli as _config_cli

    return _config_cli.load_config(path)


def _request_to_args(request: RunRequest) -> Any:
    """Build a lightweight argparse.Namespace stand-in from a RunRequest so the
    existing skills/resume/CLI helpers (which take ``args``) work unchanged."""
    import argparse

    ns = argparse.Namespace()
    ns.config = request.config_path
    ns.model = request.model_alias or None
    ns.target = request.target
    ns.mode = request.mode
    ns.goal = request.goal_name
    ns.custom_goal = request.custom_goal
    ns.recon_first = request.recon_first
    ns.no_recon_first = False
    ns.swarm = request.swarm
    ns.parallel_swarm = request.parallel_swarm
    ns.critic = request.critic
    ns.reflection = request.reflection
    ns.adaptive_exploits = request.adaptive_exploits
    ns.long_session = request.long_session
    ns.multi_model_consult = request.multi_model_consult
    ns.observer_mode = request.observer_mode
    ns.ultrathink = request.ultrathink
    ns.debug = request.debug
    ns.plain = request.plain
    ns.json = request.json_output
    ns.quiet = False
    ns.yes = request.yes
    ns.skills = request.skills_mode
    ns.skills_include = request.skills_include or None
    ns.skills_exclude = request.skills_exclude or None
    ns.no_skills_reselect = request.skills_no_reselect
    ns.reports_dir = request.reports_dir
    ns.resume = request.resume_source
    ns.http_port = None
    ns.mcp_transport = None
    ns.api_key_file = Path("secr.json")
    ns.no_api_key_prompt = True
    ns.setup_api_keys = False
    ns.menu = False
    ns.doctor = False
    ns.self_test = False
    ns.eval = False
    ns.demo = False
    ns.skills_list = False
    ns.list_plugins = False
    ns.daemon = False
    ns.api_host = None
    ns.api_port = None
    ns.model_strategy = "default"
    return ns
