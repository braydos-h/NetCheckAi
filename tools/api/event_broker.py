"""Per-run event broker: JSONL persistence + in-memory ring + WebSocket pub/sub.

Events are sanitized before persistence. ``sequence`` is monotonically
increasing per run. ``GET /runs/{id}/events?after=<seq>`` replays from JSONL;
``WS /ws/v1/runs/{id}`` pushes live. A browser disconnect does NOT cancel the
run — the ring buffer holds recent events for reconnect.

Plugin dispatch
---------------

``RunEventBroker.emit()`` assigns ``sequence`` under ``_lock``, persists the
event to JSONL off the event-loop thread (open/write/flush/fsync via
``asyncio.to_thread``; the ``_lock`` is held across the await so file order
matches sequence order while the loop stays unblocked), then fans out to WS
subscribers. After the lock is released the event is handed to a bounded
producer/consumer dispatcher for outbound-only plugin subscribers
(``webhook_notify`` etc.).

* The dispatcher queue is bounded (``max_queue_size``) and workers are bounded
  (``max_workers``) — no unbounded ``create_task`` or thread explosion when
  events outpace a down webhook.
* Blocking subscriber code (``urllib.request.urlopen`` + ``time.sleep``
  backoff) executes off the asyncio event-loop thread via
  ``asyncio.to_thread`` inside the worker pool, so ``emit()`` never stalls
  the run (a down webhook with default ``timeout_seconds=5``,
  ``max_retries=3``, ``backoff_seconds=2`` would otherwise stall ``emit()``
  ~20 s).
* Queue-full is explicit: the webhook delivery for that event is dropped
  (persistence already succeeded) and a ``WARNING`` is emitted with
  ``qsize``, ``sequence`` and a cumulative drop counter.
* Subscriber exceptions are caught per-subscriber, logged at ``WARNING`` with
  ``exc_info``, and never propagate to the broker or sibling subscribers.

Shutdown / lifecycle
--------------------

Pending webhook work is best-effort. ``await shutdown_plugin_dispatcher()``
(or ``await dispatcher.shutdown()``) attempts to drain the queue for at most
``drain_timeout`` seconds (default 5 s) via ``queue.join()``. If the drain
deadline expires the remainder is logged and discarded, workers are
cancelled, and the dispatcher resets so the next ``emit()`` lazily restarts
it. With ``drain_timeout=0`` the queue is discarded immediately. This bound
prevents shutdown from blocking on a down webhook's retry loop.
``RunEventBroker.close()`` / ``EventBrokerRegistry.close_all()`` close only
the WS fan-out queues; they do **not** implicitly drain the plugin
dispatcher — call ``await shutdown_plugin_dispatcher()`` at process shutdown
(e.g. ``RunManager.shutdown``) for an explicit bounded drain.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.api.errors import sanitize

log = logging.getLogger("tools.api.event_broker")

_DEFAULT_PLUGIN_QUEUE_SIZE = 100
_DEFAULT_PLUGIN_WORKERS = 2
_DEFAULT_DRAIN_TIMEOUT = 5.0


class _PluginEventDispatcher:
    """Bounded producer/consumer dispatcher for plugin event subscribers.

    See module docstring for architecture and shutdown semantics.
    """

    def __init__(
        self,
        max_queue_size: int = _DEFAULT_PLUGIN_QUEUE_SIZE,
        max_workers: int = _DEFAULT_PLUGIN_WORKERS,
    ) -> None:
        self._max_queue_size = max_queue_size
        self._max_workers = max_workers
        self._queue: asyncio.Queue[dict[str, Any] | None] | None = None
        self._workers: list[asyncio.Task[Any]] = []
        self._started_loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self._closed = False
        self._dropped = 0
        self._enqueued = 0
        self._processed = 0

    @property
    def max_queue_size(self) -> int:
        return self._max_queue_size

    @property
    def max_workers(self) -> int:
        return self._max_workers

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def enqueued(self) -> int:
        return self._enqueued

    @property
    def qsize(self) -> int:
        return self._queue.qsize() if self._queue is not None else 0

    def _ensure_started(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            if self._queue is not None and self._started_loop is loop and self._workers:
                if all(not w.done() for w in self._workers):
                    return
            if self._queue is not None and self._started_loop is not loop:
                stale = list(self._workers)
                self._workers.clear()
                for w in stale:
                    try:
                        if hasattr(w, "get_loop") and w.get_loop() is loop:
                            w.cancel()
                    except Exception:
                        pass
                old_q = self._queue
                self._queue = None
                self._started_loop = None
                if old_q is not None:
                    while True:
                        try:
                            old_q.get_nowait()
                            try:
                                old_q.task_done()
                            except ValueError:
                                pass
                        except asyncio.QueueEmpty:
                            break
                        except Exception:
                            break
            if self._queue is None:
                self._queue = asyncio.Queue(maxsize=self._max_queue_size)
                self._started_loop = loop
            self._workers = [w for w in self._workers if not w.done()]
            needed = self._max_workers - len(self._workers)
            for _ in range(needed):
                idx = len(self._workers)
                task = loop.create_task(self._worker_loop(idx))
                try:
                    task.set_name(f"plugin-event-dispatcher-{idx}")
                except Exception:
                    pass
                self._workers.append(task)

    def enqueue(self, event: dict[str, Any]) -> bool:
        """Non-blocking enqueue; returns True if accepted, False if dropped."""
        if self._closed:
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            log.warning(
                "plugin event dispatcher: no running loop, dropping event %s seq=%s",
                event.get("type"),
                event.get("sequence"),
            )
            return False
        self._ensure_started(loop)
        assert self._queue is not None
        try:
            self._queue.put_nowait(event)
            self._enqueued += 1
            return True
        except asyncio.QueueFull:
            self._dropped += 1
            log.warning(
                "plugin event dispatcher queue full (%d/%d) — dropping webhook delivery for event %s seq=%s (total dropped %d)",
                self._queue.qsize(),
                self._max_queue_size,
                event.get("type"),
                event.get("sequence"),
                self._dropped,
            )
            return False

    async def _worker_loop(self, idx: int) -> None:
        assert self._queue is not None
        q = self._queue
        try:
            worker_loop = asyncio.get_running_loop()
        except RuntimeError:
            worker_loop = None
        while True:
            if q is not self._queue:
                break
            if worker_loop is not None and self._started_loop is not worker_loop:
                break
            try:
                event = await q.get()
                if event is None:
                    q.task_done()
                    break
                try:
                    await self._dispatch_one(event)
                finally:
                    q.task_done()
                    self._processed += 1
            except asyncio.CancelledError:
                break
            except GeneratorExit:
                break
            except RuntimeError as exc:
                if "bound to a different event loop" in str(exc):
                    log.warning("plugin event dispatcher worker %d exiting: queue bound to different loop", idx)
                    break
                if "no running event loop" in str(exc):
                    break
                log.warning("plugin event dispatcher worker %d crashed", idx, exc_info=True)
                try:
                    await asyncio.sleep(0.05)
                except (asyncio.CancelledError, GeneratorExit, RuntimeError):
                    break
                continue
            except BaseException:
                log.warning("plugin event dispatcher worker %d crashed", idx, exc_info=True)
                try:
                    await asyncio.sleep(0.05)
                except (asyncio.CancelledError, GeneratorExit, RuntimeError):
                    break
                continue

    async def _dispatch_one(self, event: dict[str, Any]) -> None:
        try:
            from tools.plugins import PLUGIN_REGISTRY

            subscribers = list(PLUGIN_REGISTRY.event_subscribers)
        except Exception:  # noqa: BLE001
            return
        for fn in subscribers:
            try:
                await asyncio.to_thread(fn, event)
            except BaseException:
                log.warning(
                    "plugin event subscriber %r failed",
                    getattr(fn, "__name__", fn),
                    exc_info=True,
                )

    async def wait_until_empty(self, timeout: float | None = _DEFAULT_DRAIN_TIMEOUT) -> bool:
        """Wait until the queue is empty (all enqueued events processed).

        Returns True if drained within timeout, False on timeout.
        """
        q = self._queue
        if q is None:
            return True
        try:
            if timeout is None:
                await q.join()
                return True
            await asyncio.wait_for(q.join(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def shutdown(self, drain_timeout: float | None = _DEFAULT_DRAIN_TIMEOUT) -> None:
        """Bounded drain then discard and reset dispatcher.

        See module docstring for shutdown semantics.
        """
        self._closed = True
        q = self._queue
        if q is None:
            for w in list(self._workers):
                w.cancel()
            if self._workers:
                await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()
            self._started_loop = None
            self._closed = False
            return
        if drain_timeout is None:
            drain_timeout = _DEFAULT_DRAIN_TIMEOUT
        if drain_timeout > 0:
            try:
                await asyncio.wait_for(q.join(), timeout=drain_timeout)
            except asyncio.TimeoutError:
                pending = q.qsize()
                log.warning(
                    "plugin event dispatcher drain timed out after %.1fs — discarding %d pending webhook events (processed %d, dropped %d)",
                    drain_timeout,
                    pending,
                    self._processed,
                    self._dropped,
                )
                while True:
                    try:
                        q.get_nowait()
                        q.task_done()
                    except asyncio.QueueEmpty:
                        break
                    except Exception:
                        break
        else:
            pending = q.qsize()
            if pending:
                log.warning(
                    "plugin event dispatcher discarding %d pending webhook events on shutdown (drain_timeout=0)",
                    pending,
                )
            while True:
                try:
                    q.get_nowait()
                    q.task_done()
                except asyncio.QueueEmpty:
                    break
                except Exception:
                    break
        for _ in list(self._workers):
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.task_done()
                    q.put_nowait(None)
                except Exception:
                    pass
            except Exception:
                pass
        if self._workers:
            try:
                await asyncio.wait_for(asyncio.gather(*self._workers, return_exceptions=True), timeout=2.0)
            except asyncio.TimeoutError:
                for w in self._workers:
                    w.cancel()
                await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()
        self._queue = None
        self._started_loop = None
        self._closed = False

    def reset_for_tests(self) -> None:
        """Synchronous reset for tests when no loop is running."""
        self._closed = False
        self._dropped = 0
        self._enqueued = 0
        self._processed = 0
        if self._queue is not None:
            while True:
                try:
                    self._queue.get_nowait()
                    try:
                        self._queue.task_done()
                    except ValueError:
                        pass
                except asyncio.QueueEmpty:
                    break
                except RuntimeError:
                    break
                except Exception:
                    break
        for w in list(self._workers):
            try:
                if not w.done():
                    w.cancel()
            except RuntimeError:
                pass
            except Exception:
                pass
        self._workers.clear()
        self._queue = None
        self._started_loop = None


_PLUGIN_DISPATCHER: _PluginEventDispatcher | None = None
_PLUGIN_DISPATCHER_LOCK = threading.Lock()


def _get_plugin_dispatcher() -> _PluginEventDispatcher:
    global _PLUGIN_DISPATCHER
    with _PLUGIN_DISPATCHER_LOCK:
        if _PLUGIN_DISPATCHER is None:
            _PLUGIN_DISPATCHER = _PluginEventDispatcher(
                max_queue_size=_DEFAULT_PLUGIN_QUEUE_SIZE,
                max_workers=_DEFAULT_PLUGIN_WORKERS,
            )
        return _PLUGIN_DISPATCHER


def _set_plugin_dispatcher(dispatcher: _PluginEventDispatcher | None) -> None:
    global _PLUGIN_DISPATCHER
    with _PLUGIN_DISPATCHER_LOCK:
        _PLUGIN_DISPATCHER = dispatcher


def _reset_plugin_dispatcher() -> None:
    global _PLUGIN_DISPATCHER
    with _PLUGIN_DISPATCHER_LOCK:
        if _PLUGIN_DISPATCHER is not None:
            _PLUGIN_DISPATCHER.reset_for_tests()
        _PLUGIN_DISPATCHER = None


def _enqueue_plugin_event(event: dict[str, Any]) -> None:
    try:
        disp = _get_plugin_dispatcher()
        disp.enqueue(event)
    except Exception:  # noqa: BLE001
        log.warning("failed to enqueue plugin event %s", event.get("type"), exc_info=True)


async def shutdown_plugin_dispatcher(drain_timeout: float | None = _DEFAULT_DRAIN_TIMEOUT) -> None:
    """Public shutdown helper: bounded drain of pending webhook deliveries."""
    disp: _PluginEventDispatcher | None
    with _PLUGIN_DISPATCHER_LOCK:
        disp = _PLUGIN_DISPATCHER
    if disp is not None:
        await disp.shutdown(drain_timeout=drain_timeout)


async def wait_for_plugin_dispatcher_empty(timeout: float | None = _DEFAULT_DRAIN_TIMEOUT) -> bool:
    """Wait until the plugin dispatcher queue is drained (for tests)."""
    disp: _PluginEventDispatcher | None
    with _PLUGIN_DISPATCHER_LOCK:
        disp = _PLUGIN_DISPATCHER
    if disp is None:
        return True
    return await disp.wait_until_empty(timeout=timeout)


class RunEventBroker:
    """Per-run event broker: one instance per active run.

    Events are written to ``reports/<run_id>/events.jsonl`` (authoritative)
    and held in a bounded in-memory ring for live WS delivery. Subscribers
    are notified via an ``asyncio.Condition``.
    """

    def __init__(self, run_id: str, reports_dir: Path, *, buffer_size: int = 1000) -> None:
        self._run_id = run_id
        self._reports_dir = reports_dir
        self._events_path = reports_dir / "events.jsonl"
        self._ring: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._seq = 0
        self._lock = asyncio.Lock()
        self._closed = False
        self._subscribers: list[asyncio.Queue[dict[str, Any] | None]] = []

    async def emit(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Emit an event: assign sequence, sanitize, write JSONL, notify subscribers."""
        # ponytail: sanitize (CPU) outside the lock — was holding lock across it.
        clean = sanitize(payload)
        async with self._lock:
            if self._closed:
                raise RuntimeError("Event broker is closed.")
            self._seq += 1
            event = {
                "sequence": self._seq,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "run_id": self._run_id,
                "type": event_type,
                "payload": clean,
            }
            # ponytail: fsync off the event-loop thread — a sync fsync here
            # stalled every emitter/subscriber on the loop. The asyncio lock
            # is held across the await (waiters yield, they don't stall), so
            # sequence order == file order is preserved.
            await asyncio.to_thread(self._append_event_sync, event)
            self._ring.append(event)
            subscribers = tuple(self._subscribers)
        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                async with self._lock:
                    if queue in self._subscribers:
                        self._subscribers.remove(queue)
                self._stop_queue(queue)
        # Bounded dispatch for outbound-only plugin subscribers (webhook/ticketing).
        # Enqueued AFTER JSONL persistence + WS fan-out so a slow/failed webhook
        # never blocks the run or drops the event. The dispatcher runs blocking
        # subscribers off the event-loop thread via ``asyncio.to_thread`` and
        # bounds queue/concurrency. See module docstring for shutdown semantics.
        _enqueue_plugin_event(event)
        return event

    async def replay(self, after: int = 0) -> list[dict[str, Any]]:
        """Replay events with sequence > ``after`` from JSONL."""
        async with self._lock:
            return self._replay_locked(after)

    def _replay_locked(self, after: int) -> list[dict[str, Any]]:
        if self._ring and after >= self._ring[0]["sequence"] - 1:
            return [event for event in self._ring if event["sequence"] > after]
        events: list[dict[str, Any]] = []
        if not self._events_path.exists():
            return events
        with self._events_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sequence = evt.get("sequence")
                if isinstance(sequence, int) and not isinstance(sequence, bool) and sequence > after:
                    events.append(evt)
        return events

    @staticmethod
    def _read_jsonl_events(path: Path) -> list[dict[str, Any]]:
        """Read the full ordered list of parsed events from ``events.jsonl``."""
        events: list[dict[str, Any]] = []
        if not path.exists():
            return events
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                events.append(evt)
        return events

    async def replay_page(
        self,
        after: int = 0,
        *,
        tail: int | None = None,
        before: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Paged replay with cursor metadata.

        Returns ``{"events": [...], "oldest_sequence": int|None,
        "latest_sequence": int|None, "has_more_before": bool,
        "first_returned_sequence": int|None, "last_returned_sequence": int|None,
        "omitted_before": int, "next_before": int|None}``.

        - ``tail=N``: newest N events, ascending by sequence.
        - ``before=X`` + ``limit=N``: up to N events with sequence < X,
          newest-first (descending) so the client can page older.
        - ``after=X``: events with sequence > X, ascending (unchanged).
        """
        async with self._lock:
            if self._ring and self._ring[0]["sequence"] == 1:
                full = list(self._ring)
            else:
                full = await asyncio.to_thread(self._read_jsonl_events, self._events_path)

            oldest = full[0]["sequence"] if full else None
            latest = full[-1]["sequence"] if full else None

            first_returned: int | None = None
            last_returned: int | None = None
            omitted_before = 0
            next_before: int | None = None
            has_more_before = False

            if tail is not None:
                if tail < len(full):
                    events = full[-tail:]
                else:
                    events = list(full)
                if events:
                    first_returned = events[0]["sequence"]  # type: ignore[index]
                    last_returned = events[-1]["sequence"]  # type: ignore[index]
                    omitted_before = len(full) - len(events)
                    has_more_before = omitted_before > 0
                    next_before = first_returned if has_more_before else None
                else:
                    events = []
                    has_more_before = False
                    omitted_before = 0
            elif before is not None:
                older_full = [e for e in full if e["sequence"] < before]  # type: ignore[index]
                if limit is not None:
                    if limit < len(older_full):
                        older = older_full[-limit:]
                    else:
                        older = list(older_full)
                else:
                    older = older_full
                events = list(reversed(older))
                if events:
                    # older is ascending; events is descending.
                    first_returned = older[0]["sequence"]  # oldest in page
                    last_returned = older[-1]["sequence"]  # newest in page
                    omitted_before = len(older_full) - len(older)
                    has_more_before = omitted_before > 0
                    next_before = first_returned if has_more_before else None
                else:
                    has_more_before = False
                    omitted_before = 0
            else:
                events = [e for e in full if e["sequence"] > after]  # type: ignore[index]
                if events:
                    first_returned = events[0]["sequence"]  # type: ignore[index]
                    last_returned = events[-1]["sequence"]  # type: ignore[index]
                has_more_before = False
                omitted_before = 0
                next_before = None

            return {
                "events": events,
                "oldest_sequence": oldest,
                "latest_sequence": latest,
                "has_more_before": has_more_before,
                "first_returned_sequence": first_returned,
                "last_returned_sequence": last_returned,
                "omitted_before": omitted_before,
                "next_before": next_before,
            }

    async def subscribe(self, after: int = 0) -> "EventSubscription":
        """Subscribe to live events. ``after`` replays from that cursor first."""
        async with self._lock:
            subscription = EventSubscription(
                broker=self,
                initial=self._replay_locked(after),
            )
            if not self._closed:
                self._subscribers.append(subscription._queue)
            return subscription

    def close(self) -> None:
        self._closed = True
        for queue in self._subscribers:
            self._stop_queue(queue)
        self._subscribers.clear()

    def reopen(self) -> None:
        """Re-arm a closed broker for post-run operator annotations.

        ``RunManager`` closes a run's broker when the run leaves active
        handling, but operator actions after the run (HITL decisions, …)
        still need a durable, sequenced event. Reopening resumes the stored
        sequence counter, so replay stays monotonic and future subscribers
        (poll/WS/SSE) observe the late event. No-op on an open broker.
        """
        self._closed = False

    @staticmethod
    def _stop_queue(queue: asyncio.Queue[dict[str, Any] | None]) -> None:
        while not queue.empty():
            queue.get_nowait()
        queue.put_nowait(None)


class EventSubscription:
    """A live event subscription backed by an ``asyncio.Queue``."""

    def __init__(self, *, broker: RunEventBroker, initial: list[dict[str, Any]]) -> None:
        self._broker = broker
        self._queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
            maxsize=broker._ring.maxlen or 256,
        )
        self._initial = deque(initial)
        self._closed = False

    def __aiter__(self):
        return self

    async def __anext__(self) -> dict[str, Any]:
        if self._closed:
            raise StopAsyncIteration
        if self._initial:
            return self._initial.popleft()
        if self._broker._closed and self._queue.empty():
            raise StopAsyncIteration
        try:
            event = await asyncio.wait_for(self._queue.get(), timeout=30.0)
        except asyncio.TimeoutError:
            # Heartbeat: keep the WS alive.
            return {"type": "heartbeat", "run_id": self._broker._run_id}
        if event is None:
            self._closed = True
            raise StopAsyncIteration
        return event

    def close(self) -> None:
        self._closed = True
        if self._queue in self._broker._subscribers:
            self._broker._subscribers.remove(self._queue)


class EventBrokerRegistry:
    """Registry of per-run event brokers. One active broker at a time."""

    def __init__(self, reports_dir: Path, *, buffer_size: int = 1000, max_brokers: int = 10) -> None:
        self._reports_dir = reports_dir
        self._buffer_size = buffer_size
        self._max_brokers = max_brokers
        self._brokers: OrderedDict[str, RunEventBroker] = OrderedDict()

    def get_or_create(self, run_id: str, *, reports_dir: Path | None = None) -> RunEventBroker:
        broker = self._brokers.get(run_id)
        if broker is not None:
            self._brokers.move_to_end(run_id)
            return broker
        rd = reports_dir or self._reports_dir / run_id
        broker = RunEventBroker(run_id, rd, buffer_size=self._buffer_size)
        self._brokers[run_id] = broker
        while len(self._brokers) > self._max_brokers:
            _, evicted = self._brokers.popitem(last=False)
            evicted.close()
        return broker

    def get(self, run_id: str) -> RunEventBroker | None:
        return self._brokers.get(run_id)

    def close_all(self) -> None:
        for b in self._brokers.values():
            b.close()
        self._brokers.clear()


def _fire_plugin_event_subscribers(event: dict[str, Any]) -> None:
    """Legacy synchronous fan-out — now enqueues to the bounded dispatcher.

    Preserved for backward compatibility (tests/external callers may import
    this symbol). New code should rely on ``RunEventBroker.emit()`` which
    enqueues via ``_enqueue_plugin_event``. This wrapper still never blocks:
    it hands the event to the dispatcher queue and returns immediately.
    Subscriber exceptions are handled inside the dispatcher workers.
    """
    _enqueue_plugin_event(event)
