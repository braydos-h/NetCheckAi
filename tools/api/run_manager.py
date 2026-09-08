"""RunManager: owns active runs, MCP sessions, and tool-call serialization.

v1 supported one live run at a time (HTTP 409 on a second). This matched the
fixed MCP port, process-global ``EXPLOIT_TARGET`` env, plugin registry, and
shared UI state.

Phase 6.3 (``api.max_concurrent_runs``) lifts the one-active-run limit to N
concurrent runs for authorized wide-scope assessments. The per-run allowlist
lock is the highest-risk safety property here, so it is enforced per-handle,
not globally:

- **Each run carries its own allowlist snapshot** (``RunHandle.allowlist``)
  derived from ``exploit.allowed_targets`` UNION the run's ``--target``. The
  snapshot is frozen at prepare() time so Run A's target never appears in Run
  B's allowlist even if both are live.
- The MCP subprocess for each run gets its own ``env["EXPLOIT_TARGET"]`` (set
  in ``tools/mcp_session.open_exploit_mcp_session``), so the target-IP lock is
  process-isolated by the OS — Run A's subprocess env never leaks into Run B's
  subprocess. The handle-level snapshot is defense-in-depth + the source the
  WebUI's tool-call bridge uses to attribute target ownership.
- Default ``api.max_concurrent_runs: 1`` restores the legacy one-active-run
  behavior byte-for-byte (the 409 still fires on a second run).

The manager:

- Creates a run row + ``start_confirm`` decision on ``POST /runs``.
- Transitions to ``queued`` -> ``running`` when the decision is answered.
- Owns the ``asyncio.Task`` running ``AssessmentService.execute``.
- Serializes manual tool calls (``POST /runs/{id}/tools/{name}/calls``) through
  the live MCP ``ClientSession`` with a per-run ``asyncio.Lock``.
- On cancel/shutdown: deny decisions, cancel the task, close the MCP session,
  terminate the process tree, flush events, mark the run accurately.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.api.decision_broker import DecisionBroker
from tools.api.errors import APIError
from tools.api.event_broker import EventBrokerRegistry, RunEventBroker
from tools.api.persistence import ApiPersistence
from tools.api.session_titler import generate_session_title
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.run_service.models import (
    Decision,
    DecisionKind,
    RunPreview,
    RunRequest,
    RunResult,
    RunState,
)
from tools.run_service.providers import (
    ApiApprovalProvider,
    ApiDecisionProvider,
    ApiEventSink,
    CancellationToken,
)
from tools.validation_utils import resolve_target_to_ip

if TYPE_CHECKING:
    from tools.run_service.service import Callables

log = logging.getLogger(__name__)

# Preparation failures are re-raised as ``failed`` runs. ValueError/OSError
# messages from prepare() are already operator-actionable ("Could not resolve
# domain: ..."), so they pass through; anything else is summarized (full
# detail stays in server logs) so internals/exceptions never leak to the UI.
_PREPARATION_PASS_THROUGH = (ValueError, OSError, TimeoutError)


def _preparation_error_text(exc: BaseException) -> str:
    if isinstance(exc, _PREPARATION_PASS_THROUGH):
        text = str(exc).strip()
        if text:
            return text
    return "Run preparation failed. View server logs for details."


class RunHandle:
    """Runtime state for one active run."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.task: asyncio.Task[Any] | None = None
        # Background preparation task (``preparing`` state). Distinct from
        # ``task`` (execution) so cancel/shutdown can stop either phase.
        self.prep_task: asyncio.Task[Any] | None = None
        self.cancellation = CancellationToken()
        self.decision_broker: DecisionBroker | None = None
        self.event_broker: RunEventBroker | None = None
        self.mcp_session: Any = None
        self.exploit_policy: Any = None
        self.tool_schemas: list[dict[str, Any]] = []
        self.tool_lock = asyncio.Lock()
        self.preview: RunPreview | None = None
        self.request: RunRequest | None = None
        # Frozen config snapshot captured at prepare() time so the preview's
        # permission/budgets/destructive verdicts stay valid even if the
        # operator PATCHes /config between confirmation and execution.
        self.config_snapshot: dict[str, Any] | None = None
        # Per-run allowlist snapshot = config ``exploit.allowed_targets`` UNION
        # this run's ``--target`` (primary + resolved IP + domain). Frozen at
        # prepare() time so Run A's target never leaks into Run B's allowlist
        # when ``api.max_concurrent_runs > 1``. The MCP subprocess also gets
        # its own ``env["EXPLOIT_TARGET"]`` (set in mcp_session.py), so the OS
        # process boundary is the primary isolation; this snapshot is the
        # handle-level source of truth for the WebUI's target attribution.
        self.allowlist: list[str] = []
        # Cached DNS resolution of the run's ``--target`` (set at prepare()
        # time so the hot path never re-resolves; see ``_snapshot_allowlist``).
        self.resolved_ip: str | None = None


def _snapshot_allowlist(config: dict[str, Any], target: str) -> list[str]:
    """Build the per-run allowlist = ``exploit.allowed_targets`` UNION target.

    ``target`` is the run's ``--target`` (IP or domain). When it is a domain,
    the resolved IP is also unioned in (the operator's ``--target`` is the
    primary lock identity; the IP lets IP-based tools target the resolved host).
    This mirrors ``tools/mcp_shared._allowed_target_list`` but is frozen per
    run instead of re-read from the process env on each tool call.
    """
    exploit_cfg = (config or {}).get("exploit", {}) or {}
    allowed = list(exploit_cfg.get("allowed_targets", []) or [])
    target = (target or "").strip()
    if target and target not in allowed:
        allowed.append(target)
    # ponytail: resolve domain → IP best-effort; the MCP subprocess env carries
    # the authoritative resolved IP (set in mcp_session.py). Re-resolving here
    # would add a DNS call per run and could diverge from what the subprocess
    # actually got; the subprocess env is the lock, this snapshot is the
    # handle-level mirror for the WebUI.
    return allowed


class RunManager:
    """Active-run manager. Supports ``api.max_concurrent_runs`` (default 1).

    With ``max_concurrent_runs == 1`` (the default) the behavior is
    byte-for-byte the legacy one-active-run path: the second ``POST /runs``
    gets a 409. With ``max_concurrent_runs > 1`` up to N runs may be live
    concurrently, each carrying its own allowlist snapshot so Run A's target
    never leaks into Run B's allowlist.
    """

    def __init__(
        self,
        persistence: ApiPersistence,
        event_registry: EventBrokerRegistry,
        *,
        config: dict[str, Any],
        config_path: Path,
        callables: "Callables | None" = None,
        benchmark_service: Any = None,
    ) -> None:
        self._persistence = persistence
        self._events = event_registry
        self._config = config
        self._config_path = config_path
        self._callables = callables
        # ponytail: dict keyed by run_id keeps the legacy single-run path O(1)
        # (``has_active`` / ``active`` / 409 check are all ``len()`` / lookup).
        # A list would scan; a dict is the natural shape since run_id is the
        # key every caller already has.
        self._active: dict[str, RunHandle] = {}
        self._lifecycle_lock = asyncio.Lock()
        # Explicit constructor injection (was a private cross-link poked by
        # app.create_app): the benchmark service occupies one concurrency
        # slot via ``max_concurrent_runs``. None = standalone (back-compat).
        self._benchmark_service = benchmark_service

    @property
    def benchmark_service(self) -> Any:
        """The attached benchmark service, if any (explicit wiring, not a poke)."""
        return self._benchmark_service

    @benchmark_service.setter
    def benchmark_service(self, service: Any) -> None:
        self._benchmark_service = service

    @property
    def max_concurrent_runs(self) -> int:
        """Effective concurrent-run cap. ``api.max_concurrent_runs`` (default 1)."""
        api_cfg = (self._config or {}).get("api", {}) or {}
        n = int(api_cfg.get("max_concurrent_runs", 1) or 1)
        return n if n >= 1 else 1

    @property
    def has_active(self) -> bool:
        return bool(self._active)

    @property
    def config(self) -> dict[str, Any]:
        return self._config

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def active(self) -> RunHandle | None:
        """The first active handle (legacy compat for single-run callers).

        With ``max_concurrent_runs == 1`` there is at most one. With N>1 this
        returns *one* live handle but callers that need a specific run should
        use ``active_for(run_id)``.
        """
        return next(iter(self._active.values()), None)

    def active_for(self, run_id: str) -> RunHandle | None:
        """Return the active handle for ``run_id`` or None."""
        return self._active.get(run_id)

    @property
    def active_run_ids(self) -> list[str]:
        return list(self._active.keys())

    async def create_run(self, request: RunRequest) -> tuple[str, RunPreview | None, Decision | None]:
        """Accept a run and start preparation in the background.

        The run row is persisted as ``preparing`` and the call returns
        ``(run_id, None, None)`` immediately — preparation (plugins, model
        router, target resolution, skills) continues on a background task and
        transitions the run to ``awaiting_confirmation`` (or ``queued`` when
        ``request.yes``) when it completes. ``preview``/``decision`` are None
        at return time; clients poll ``GET /runs/{id}`` /
        ``GET /runs/{id}/decisions`` (or subscribe to the run's events) to
        observe the transition. Preparation failures mark the run ``failed``
        with an actionable error.
        """
        async with self._lifecycle_lock:
            # ponytail: single global cap — an active benchmark occupies a slot.
            bench_busy = bool(
                self._benchmark_service is not None and getattr(self._benchmark_service, "is_active", lambda: False)()
            )
            if len(self._active) + (1 if bench_busy else 0) >= self.max_concurrent_runs:
                raise APIError(
                    "conflict",
                    f"{self.max_concurrent_runs} run(s) already active. Cancel one first (api.max_concurrent_runs).",
                    status_code=409,
                )

            request.config_path = self._config_path
            request.reports_dir = self._persistence.reports_dir
            run_id = self._allocate_run_id()

            # Persist the run row up-front so the id exists (and events/WS
            # routes can find it) before preparation finishes.
            self._persistence.create_run(
                run_id=run_id,
                request=_request_to_dict(request),
                preview={},
                state=RunState.PREPARING.value,
            )

            # Create event broker for this run.
            event_broker = self._events.get_or_create(run_id)
            handle = RunHandle(run_id)
            handle.request = request
            # Freeze the config for this run now so execution sees the same
            # permission/budgets/destructive verdict the operator confirmed.
            handle.config_snapshot = copy.deepcopy(self._config)
            # Per-run allowlist snapshot is filled in when prepare() returns.
            handle.event_broker = event_broker
            handle.decision_broker = DecisionBroker(run_id, self._persistence)
            self._active[run_id] = handle

            await event_broker.emit("state", {"state": RunState.PREPARING.value})
            await event_broker.emit(
                "preparing",
                {"stage": "accepted", "message": "Run accepted — preparing"},
            )
            handle.prep_task = asyncio.create_task(self._prepare_run(handle, request))
            return run_id, None, None

    def _allocate_run_id(self) -> str:
        """Timestamp-based run id, uniquified against active + persisted ids."""
        base = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        run_id = base
        counter = 0
        while run_id in self._active or self._persistence.get_run(run_id) is not None:
            counter += 1
            run_id = f"{base}_{counter}"
        return run_id

    def _spawn_preparing_event(self, handle: RunHandle, stage: str, message: str) -> None:
        """Fire-and-forget ``preparing`` stage event from the worker thread."""
        broker = handle.event_broker

        async def _emit() -> None:
            try:
                await broker.emit("preparing", {"stage": stage, "message": message})
            except Exception:  # noqa: BLE001 -- progress events never break prepare
                pass

        asyncio.ensure_future(_emit())

    async def _prepare_run(self, handle: RunHandle, request: RunRequest) -> None:
        """Background preparation: ``AssessmentService.prepare`` + finalize."""
        from tools.run_service import AssessmentService

        service = AssessmentService(config=handle.config_snapshot, callables=self._callables)
        loop = asyncio.get_running_loop()

        def on_stage(stage: str, message: str) -> None:
            loop.call_soon_threadsafe(self._spawn_preparing_event, handle, stage, message)

        try:
            preview = await service.prepare(request, run_id=handle.run_id, progress=on_stage)
        except asyncio.CancelledError:
            # cancel_run()/shutdown() set ``cancelling`` + cancelled the task;
            # settle the run to ``cancelled`` here (mirror _execute_run) and
            # release the event broker so no zombie active handle/broker stays.
            try:
                self._persistence.update_run_state(handle.run_id, RunState.CANCELLED.value)
                await handle.event_broker.emit("state", {"state": RunState.CANCELLED.value})
            except Exception:  # noqa: BLE001 -- broker may already be closed
                pass
            finally:
                handle.event_broker.close()
            raise
        except BaseException as exc:
            # ExceptionGroup included (anyio/MCP surfaces groups, not Exception).
            await self._fail_preparation(handle, exc)
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            return

        async with self._lifecycle_lock:
            # Re-check under the lock: the run may have been cancelled or
            # removed while preparing.
            if self._active.get(handle.run_id) is not handle:
                return
            current = self._persistence.get_run(handle.run_id) or {}
            if current.get("state") == RunState.CANCELLED.value:
                self._active.pop(handle.run_id, None)
                return

            handle.preview = preview
            # Per-run allowlist snapshot — Run A's target never appears in
            # Run B's allowlist even when N runs are live concurrently.
            handle.allowlist = _snapshot_allowlist(
                handle.config_snapshot,
                preview.original_target or preview.target_ip,
            )
            # Persist the prepared preview (target/mode/goal/model/...).
            self._persistence.update_run_preview(handle.run_id, _preview_to_dict(preview))
            try:
                await handle.event_broker.emit(
                    "preparing",
                    {"stage": "done", "message": "Run prepared", "timings": dict(preview.timings or {})},
                )
                if not request.yes:
                    self._persistence.update_run_state(handle.run_id, RunState.AWAITING_CONFIRMATION.value)
                    await handle.event_broker.emit("state", {"state": RunState.AWAITING_CONFIRMATION.value})
                    decision = Decision(
                        id="",
                        run_id=handle.run_id,
                        kind=DecisionKind.START_CONFIRM,
                        prompt_text="Proceed?" if not preview.destructive else "DESTRUCTIVE mode — confirm to proceed.",
                        required_text=preview.required_confirmation_text,
                    )
                    did = await handle.decision_broker.create(decision)
                    await handle.event_broker.emit(
                        "approval",
                        {
                            "decision_id": did,
                            "kind": "start_confirm",
                            "prompt_text": decision.prompt_text,
                            "required_text": decision.required_text,
                        },
                    )
                else:
                    self._persistence.update_run_state(handle.run_id, RunState.QUEUED.value)
                    await handle.event_broker.emit("state", {"state": RunState.QUEUED.value})
                    handle.task = asyncio.create_task(self._execute_run(handle))
            except BaseException:
                handle.decision_broker.cancel_all()
                handle.event_broker.close()
                self._active.pop(handle.run_id, None)
                self._persistence.update_run_state(
                    handle.run_id,
                    RunState.FAILED.value,
                    error="Run setup failed.",
                )
                raise

    async def _fail_preparation(self, handle: RunHandle, exc: BaseException) -> None:
        """Mark a failed preparation: failed state + actionable error + cleanup."""
        async with self._lifecycle_lock:
            if self._active.get(handle.run_id) is handle:
                self._active.pop(handle.run_id, None)
        if handle.decision_broker:
            handle.decision_broker.cancel_all()
        error_text = _preparation_error_text(exc)
        log.exception("run %s preparation failed", handle.run_id)
        try:
            await handle.event_broker.emit("error", {"message": error_text})
            await handle.event_broker.emit("state", {"state": RunState.FAILED.value, "error": error_text})
        except Exception:  # noqa: BLE001 -- broker may already be closed
            pass
        finally:
            handle.event_broker.close()
        self._persistence.update_run_state(handle.run_id, RunState.FAILED.value, error=error_text)

    async def wait_for_prepared(self, run_id: str, timeout: float = 10.0) -> RunHandle:
        """Wait until ``run_id`` leaves the ``preparing`` state (tests + callers).

        Raises :class:`APIError` (``not_found``) when there is no such active
        run, and :class:`TimeoutError` when preparation does not settle in time.
        """
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            handle = self._active.get(run_id)
            if handle is None:
                # Either finished+removed (completed/failed) or never existed.
                raise APIError("not_found", "No active run with that id.", status_code=404)
            if handle.prep_task is None or handle.prep_task.done():
                if handle.prep_task is not None and handle.prep_task.cancelled():
                    raise asyncio.CancelledError
                return handle
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError(f"run {run_id} still preparing after {timeout}s")
            await asyncio.sleep(0.01)

    async def confirm_and_start(self, run_id: str, decision_id: str, answer: str) -> None:
        """Resolve the start_confirm decision and kick off execution."""
        async with self._lifecycle_lock:
            handle = self._require_active(run_id)
            if handle.preview is None:
                raise APIError("conflict", "Run is still preparing.", status_code=409)
            if handle.task is not None:
                raise APIError("conflict", "Run execution has already started.", status_code=409)
            if handle.preview and handle.preview.destructive:
                valid = answer == handle.preview.required_confirmation_text
            else:
                valid = answer.strip().lower() in {"y", "yes"}
            if not valid:
                raise APIError("invalid_confirmation", "Confirmation text does not match.", status_code=400)
            self._persistence.update_run_state(run_id, RunState.QUEUED.value)
            await handle.event_broker.emit("state", {"state": RunState.QUEUED.value})
            if not handle.decision_broker or not handle.decision_broker.resolve(decision_id, answer):
                raise APIError("decision_not_found", "Decision not found or already answered.", status_code=404)
            handle.task = asyncio.create_task(self._execute_run(handle))

    async def _execute_run(self, handle: RunHandle) -> None:
        """Run ``AssessmentService.execute`` in the background."""
        from tools.run_service import AssessmentService

        # Use the frozen config snapshot captured at prepare() time so the
        # confirmed preview (permission/destructive/budgets) stays accurate.
        service = AssessmentService(config=handle.config_snapshot, callables=self._callables)

        decision_provider = ApiDecisionProvider(
            handle.run_id,
            handle.decision_broker,
            handle.event_broker.emit,
        )
        event_sink = ApiEventSink(handle.run_id, handle.event_broker)
        approval_provider = ApiApprovalProvider(
            handle.run_id,
            decision_provider,
            handle.preview.target_ip,
        )

        try:
            self._persistence.update_run_state(handle.run_id, RunState.RUNNING.value)
            await handle.event_broker.emit("state", {"state": RunState.RUNNING.value})
            result = await service.execute(
                handle.request,
                handle.preview,
                decision_provider=decision_provider,
                event_sink=event_sink,
                cancellation=handle.cancellation,
                config=handle.config_snapshot,
                approval_provider=approval_provider,
                session_attach=lambda session, schemas, policy: self.set_mcp_session(
                    handle.run_id,
                    session,
                    schemas,
                    policy,
                ),
            )
            # Operator cancelled at a mid-run checkpoint -> cancelled state
            # (not completed/failed). The service sets RunResult.cancelled when
            # the loop surfaces ``cancelled_by_operator``; this is distinct
            # from RunManager.cancel_run (external cancel) which raises
            # asyncio.CancelledError and lands in the except branch below.
            if getattr(result, "cancelled", False):
                state = RunState.CANCELLED.value
            elif result.error:
                state = RunState.FAILED.value
            else:
                state = RunState.COMPLETED.value
            result_dict = _result_to_dict(result)
            self._persistence.update_run_state(
                handle.run_id,
                state,
                error=result.error,
                result=result_dict,
            )
            await handle.event_broker.emit("state", {"state": state, "result": result_dict})
            await self._maybe_title_run(handle, result_dict)
        except asyncio.CancelledError:
            self._persistence.update_run_state(handle.run_id, RunState.CANCELLED.value)
            await handle.event_broker.emit("state", {"state": RunState.CANCELLED.value})
            raise
        except _EXC_GROUP_CATCH as exc:
            # Catch BaseExceptionGroup too (MCP subprocess death raises it,
            # and it is NOT a subclass of Exception). Without this the run
            # would stay "running" forever. See tools/exceptions.py.
            self._persistence.update_run_state(handle.run_id, RunState.FAILED.value, error=str(exc))
            await handle.event_broker.emit("error", {"message": str(exc)})
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            await self._maybe_title_run(handle, {"error": str(exc)})
        finally:
            if handle.decision_broker:
                handle.decision_broker.cancel_all()
            handle.event_broker.close()
            async with self._lifecycle_lock:
                if self._active.get(handle.run_id) is handle:
                    self._active.pop(handle.run_id, None)

    async def _maybe_title_run(
        self,
        handle: "RunHandle",
        result_dict: dict[str, Any],
    ) -> None:
        """Ask gemma4:31b-cloud for a session title; persist on success.

        Best-effort: any failure (ollama unreachable, missing pkg, parse
        error, empty response) is logged at DEBUG and swallowed. Skips
        runs that already have a title (e.g. resumed runs keep the parent's
        title). Fires after the run state is persisted + emitted so a slow
        or failing titler never delays the state transition.
        """
        try:
            existing = self._persistence.get_run(handle.run_id) or {}
            if existing.get("title"):
                return
            host = str((self._config.get("ollama") or {}).get("host") or "https://api.ollama.com")
            request_dict = _request_to_dict(handle.request) if handle.request else {}
            title = await generate_session_title(
                result_dict,
                request_dict,
                host=host,
                config=self._config,
            )
            if title:
                self._persistence.update_run_title(handle.run_id, title)
                await handle.event_broker.emit("title", {"title": title})
        except Exception as exc:  # best-effort — never propagate
            import logging as _logging

            _logging.getLogger(__name__).debug(
                "session title persistence failed for %s: %s",
                handle.run_id,
                exc,
            )

    async def cancel_run(self, run_id: str) -> None:
        """Cooperative cancellation: set the flag + cancel the task."""
        async with self._lifecycle_lock:
            handle = self._require_active(run_id)
            event_error: Exception | None = None
            try:
                self._persistence.update_run_state(run_id, RunState.CANCELLING.value)
                await handle.event_broker.emit("state", {"state": RunState.CANCELLING.value})
            except Exception as exc:
                event_error = exc
            # A closed broker is expected when Starlette's TestClient (or any
            # request-scoped event-loop host) tears down the loop that created
            # a still-preparing run.  Cancellation must still settle the
            # persisted run instead of turning that lifecycle race into a 500.
            stale_broker = isinstance(event_error, RuntimeError) and str(event_error) == "Event broker is closed."
            handle.cancellation.cancel()
            if handle.decision_broker:
                handle.decision_broker.cancel_all()
            # A run in ``preparing`` has no execution task yet — cancel the
            # preparation task instead so the run settles immediately.
            task = handle.task or handle.prep_task
            if task is None:
                try:
                    self._persistence.update_run_state(run_id, RunState.CANCELLED.value)
                    if event_error is None:
                        await handle.event_broker.emit("state", {"state": RunState.CANCELLED.value})
                finally:
                    handle.event_broker.close()
                    self._active.pop(run_id, None)
                if event_error is not None and not stale_broker:
                    raise event_error
                return
            # TestClient creates a fresh portal per request; the prep_task may be
            # bound to a different (now closed) loop. Detect and avoid
            # ``asyncio.wait`` on a foreign loop which raises "Event loop is closed".
            try:
                cur_loop = asyncio.get_running_loop()
                task_loop = task.get_loop() if hasattr(task, "get_loop") else None
                if task_loop is not None and task_loop is not cur_loop:
                    try:
                        task.cancel()
                    except RuntimeError:
                        pass
                    self._active.pop(run_id, None)
                    try:
                        handle.event_broker.close()
                    except Exception:
                        pass
                    if event_error is not None and not stale_broker:
                        raise event_error
                    return
            except RuntimeError:
                pass
            try:
                task.cancel()
            except RuntimeError:
                # Task from a closed loop — just drop the handle.
                self._active.pop(run_id, None)
                try:
                    handle.event_broker.close()
                except Exception:
                    pass
                if event_error is not None and not stale_broker:
                    raise event_error
                return

        timeout = max(0.0, float(self._config.get("api", {}).get("shutdown_timeout_seconds", 15)))
        try:
            _, pending = await asyncio.wait({task}, timeout=timeout)
        except RuntimeError as exc:
            # Cross-loop or closed-loop wait — treat as cancelled.
            if "Event loop is closed" in str(exc) or "different loop" in str(exc).lower():
                async with self._lifecycle_lock:
                    self._active.pop(run_id, None)
                try:
                    handle.event_broker.close()
                except Exception:
                    pass
                if event_error is not None and not stale_broker:
                    raise event_error
                return
            raise
        if pending:
            raise APIError("cancel_timeout", "Run cancellation timed out.", status_code=504)
        # A task cancelled before its first run (e.g. an immediate cancel after
        # create/confirm) ends cancelled WITHOUT executing its own
        # CancelledError handler — settle the run here so ``cancelling`` never
        # sticks and no zombie handle/broker survives.
        if self._active.get(run_id) is handle:
            async with self._lifecycle_lock:
                if self._active.get(run_id) is handle:
                    self._active.pop(run_id, None)
                    try:
                        self._persistence.update_run_state(run_id, RunState.CANCELLED.value)
                        if event_error is None:
                            await handle.event_broker.emit("state", {"state": RunState.CANCELLED.value})
                    except Exception:  # noqa: BLE001 -- broker may already be closed
                        pass
                    finally:
                        handle.event_broker.close()
        if event_error is not None and not stale_broker:
            raise event_error

    async def answer_decision(self, run_id: str, decision_id: str, answer: str) -> dict[str, Any]:
        """Answer a pending decision (goal_select or tool_approval)."""
        handle = self._require_active(run_id)
        if handle.decision_broker is None:
            raise APIError("no_decisions", "No decision broker for this run.", status_code=400)
        decision = self._persistence.get_decision(decision_id)
        if decision is None or decision["run_id"] != run_id or decision["status"] != "pending":
            raise APIError("decision_not_found", "Decision not found or already answered.", status_code=404)
        if decision["kind"] == DecisionKind.START_CONFIRM.value:
            await self.confirm_and_start(run_id, decision_id, answer)
            return {"decision_id": decision_id, "status": "answered"}
        ok = handle.decision_broker.resolve(decision_id, answer)
        if not ok:
            raise APIError("decision_not_found", "Decision not found or already answered.", status_code=404)
        await handle.event_broker.emit(
            "approval",
            {
                "decision_id": decision_id,
                "status": "answered",
                "answer": answer,
            },
        )
        if not any(row["status"] == "pending" for row in self._persistence.list_decisions(run_id)):
            self._persistence.update_run_state(run_id, RunState.RUNNING.value)
            await handle.event_broker.emit("state", {"state": RunState.RUNNING.value})
        return {"decision_id": decision_id, "status": "answered"}

    async def list_decisions(self, run_id: str) -> list[dict[str, Any]]:
        if self._persistence.get_run(run_id) is None:
            raise APIError("not_found", "Run not found.", status_code=404)
        return self._persistence.list_decisions(run_id)

    async def call_tool(self, run_id: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Policy-gated REST bridge for manual WebUI tool calls."""
        handle = self._require_active(run_id)
        if handle.mcp_session is None:
            raise APIError("no_session", "MCP session is not open.", status_code=409)
        if handle.exploit_policy is None:
            raise APIError("no_policy", "Exploit policy is not available.", status_code=409)
        if not any((schema.get("function") or {}).get("name") == tool_name for schema in handle.tool_schemas):
            raise APIError("tool_not_found", "Unknown MCP tool.", status_code=404)
        async with handle.tool_lock:
            approved = await handle.exploit_policy.approve_action(
                tool_name,
                json.dumps(arguments, sort_keys=True, default=str),
                "Manual WebUI tool call",
            )
            if not approved:
                raise APIError("tool_denied", "Exploit policy denied the tool call.", status_code=403)
            try:
                result = await handle.mcp_session.call_tool(tool_name, arguments=arguments)
            except _EXC_GROUP_CATCH as exc:
                # BaseExceptionGroup from MCP subprocess death is not an Exception.
                if _is_exception_group(exc):
                    _log_nested_exceptions(exc)
                raise APIError("tool_error", "MCP tool call failed.", status_code=500) from exc
        # Extract text content.
        text = _extract_text(result)
        return {"tool": tool_name, "result": text}

    def get_tool_schemas(self, run_id: str) -> list[dict[str, Any]]:
        handle = self._active.get(run_id)
        if handle is None:
            return []
        return handle.tool_schemas

    def set_mcp_session(
        self,
        run_id: str,
        session: Any,
        schemas: list[dict[str, Any]],
        policy: Any,
    ) -> None:
        """Called by the service when the MCP session opens."""
        handle = self._active.get(run_id)
        if handle is not None:
            handle.mcp_session = session
            handle.tool_schemas = schemas
            handle.exploit_policy = policy

    async def shutdown(self) -> None:
        """Clean up on daemon shutdown: cancel all active runs, flush events."""
        try:
            for run_id in list(self._active.keys()):
                handle = self._active.get(run_id)
                if handle is not None and handle.prep_task is not None and not handle.prep_task.done():
                    # In-flight preparation: stop it first so cancel_run's
                    # wait covers the right task.
                    try:
                        handle.prep_task.cancel()
                    except RuntimeError:
                        pass
                try:
                    await self.cancel_run(run_id)
                except Exception:  # noqa: BLE001 -- best-effort, one bad cancel never blocks the rest
                    pass
        finally:
            self._events.close_all()
            # Bounded drain of pending webhook deliveries (outbound-only). The
            # dispatcher queue is best-effort; shutdown waits at most 5 s then
            # logs and discards any remainder so a down webhook (20+ s retry
            # loop per event) never blocks daemon shutdown. See
            # tools/api/event_broker.py module docstring for full semantics.
            try:
                from tools.api.event_broker import shutdown_plugin_dispatcher

                await shutdown_plugin_dispatcher(drain_timeout=5.0)
            except Exception:  # noqa: BLE001 -- shutdown must never block exit
                pass

    def _require_active(self, run_id: str) -> RunHandle:
        handle = self._active.get(run_id)
        if handle is None:
            raise APIError("not_found", "No active run with that id.", status_code=404)
        return handle


def _extract_text(result: Any) -> str:
    """Pull textual content from an MCP call_tool result."""

    def _get(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    blocks = _get(result, "content", []) or []
    parts: list[str] = []
    for block in blocks:
        t = _get(block, "text", None)
        if t is not None:
            parts.append(str(t))
    return "\n".join(p for p in parts if p).strip()


def _request_to_dict(req: RunRequest) -> dict[str, Any]:
    return {
        "target": req.target,
        "mode": req.mode,
        "goal_name": req.goal_name,
        "custom_goal": req.custom_goal,
        "recon_first": req.recon_first,
        "model_alias": req.model_alias,
        "swarm": req.swarm,
        "parallel_swarm": req.parallel_swarm,
        "critic": req.critic,
        "reflection": req.reflection,
        "adaptive_exploits": req.adaptive_exploits,
        "long_session": req.long_session,
        "multi_model_consult": req.multi_model_consult,
        "observer_mode": req.observer_mode,
        "ultrathink": req.ultrathink,
        "skills_mode": req.skills_mode,
        "skills_include": req.skills_include,
        "skills_exclude": req.skills_exclude,
        "skills_no_reselect": req.skills_no_reselect,
        "debug": req.debug,
        "plain": req.plain,
        "json_output": req.json_output,
        "resume_source": req.resume_source,
        "kind": req.kind.value,
    }


def _preview_to_dict(p: RunPreview) -> dict[str, Any]:
    return {
        "run_id": p.run_id,
        "target_ip": p.target_ip,
        "original_target": p.original_target,
        "resolved_ip": p.resolved_ip,
        "resolved_domain": p.resolved_domain,
        "mode": p.mode,
        "goal_name": p.goal_name,
        "goal_description": p.goal_description,
        "model_alias": p.model_alias,
        "model_label": p.model_label,
        "transport_summary": p.transport_summary,
        "permission": p.permission,
        "attack_mode": p.attack_mode,
        "swarm": p.swarm,
        "parallel_swarm": p.parallel_swarm,
        "multi_model": p.multi_model,
        "destructive": p.destructive,
        "required_confirmation_text": p.required_confirmation_text,
        "budgets": p.budgets,
        "skill_activations": p.skill_activations,
        "skill_errors": p.skill_errors,
        "timings": dict(p.timings or {}),
        "resumed_from": p.resumed_from,
    }


def _result_to_dict(r: RunResult) -> dict[str, Any]:
    return {
        "run_id": r.run_id,
        "target_ip": r.target_ip,
        "mode": r.mode,
        "goal_name": r.goal_name,
        "goal_description": r.goal_description,
        "total_actions": r.total_actions,
        "workspace": r.workspace,
        "audit_path": r.audit_path,
        "records": r.records,
        "messages": r.messages,
        "error": r.error,
        "swarm_result": r.swarm_result,
        "active_skills": r.active_skills,
        "outcome_summary": r.outcome_summary,
        "telemetry": r.telemetry,
        "safety_review": r.safety_review,
        "reports_dir": r.reports_dir,
        "summary_path": r.summary_path,
        "run_json_path": r.run_json_path,
        "cancelled": r.cancelled,
        "objective_transitions": r.objective_transitions,
    }
