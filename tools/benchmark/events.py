"""Structured mission-event logging for benchmark runs.

Writes one JSONL event stream per benchmark run (``events.jsonl``) plus a
per-trial stream, with monotonic ``sequence`` numbers, ISO timestamps, and
secret redaction reused from the project's audit kernel
(:func:`tools.kernel.audit._mask_secret_content`).

Events capture *operational* structure — planner decisions, tool requests and
results, sandbox verdicts, scope decisions, oracle results, phase changes —
never raw chain-of-thought. Long outputs are truncated before storage.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tools.kernel.audit import _mask_secret_content

__all__ = ["BenchmarkEventLogger", "EventSink", "truncate_output"]

#: Maximum stored size for a single string payload field (raw outputs).
_MAX_FIELD = 2000

#: Payload fields whose entire value is truncated to a short marker.
_VERBATIM_FIELDS = frozenset({"stdout", "stderr", "output_text", "reasoning_text"})


def truncate_output(text: str, limit: int = _MAX_FIELD) -> str:
    """Redact secrets then truncate an output string for event storage."""
    masked = _mask_secret_content(str(text or ""))
    if len(masked) <= limit:
        return masked
    return masked[:limit] + f"... [truncated {len(masked) - limit} chars]"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BenchmarkEventLogger:
    """Append-only structured event stream for one benchmark run.

    A single logger instance serves the whole run; ``trial_id`` tagging lets
    the API/WebUI filter the timeline per scenario trial. A write never raises
    to the caller — persistence best-effort, logging failures are swallowed so
    an event hiccup can never abort a benchmark.
    """

    path: Path
    run_id: str = ""
    sink: "EventSink | None" = None  # optional live subscriber fan-out (API)
    _seq: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _start: float = field(default_factory=time.monotonic, repr=False)

    def log(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        trial_id: str = "",
        scenario_id: str = "",
        agent: str = "",
        tool: str = "",
        target: str = "",
        level: str = "info",
    ) -> dict[str, Any]:
        """Append one event; returns the stored event dict."""
        with self._lock:
            self._seq += 1
            event: dict[str, Any] = {
                "sequence": self._seq,
                "timestamp": _now_iso(),
                "elapsed_seconds": round(time.monotonic() - self._start, 3),
                "run_id": self.run_id,
                "type": str(event_type),
                "level": level,
                "trial_id": trial_id,
                "scenario_id": scenario_id,
                "agent": agent,
                "tool": tool,
                "target": target,
                "payload": _redact_payload(payload or {}),
            }
            line = json.dumps(event, sort_keys=False, default=str)
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError:
                pass  # best-effort; never abort a benchmark over event I/O
        if self.sink is not None:
            try:
                self.sink(event)
            except Exception:  # noqa: BLE001 -- subscriber errors are never fatal
                pass
        return event

    @property
    def sequence(self) -> int:
        return self._seq


def _truncate_nested(value: Any) -> Any:
    """Recursively truncate oversized strings inside nested dicts/lists/tuples."""
    if isinstance(value, str):
        return truncate_output(value) if len(value) > _MAX_FIELD else value
    if isinstance(value, dict):
        return {k: _truncate_nested(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate_nested(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_truncate_nested(v) for v in value)
    return value


def _redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Redact secrets + bound sizes in one event payload (fully recursive).

    Reuses the audit kernel's nested redaction (secret-key masking + content
    masking) and additionally truncates oversized string values at any depth
    so a nested stdout/output blob cannot blow up events.jsonl.
    """
    from tools.kernel.audit import _redact_nested

    redacted = _redact_nested(payload)
    return {key: _truncate_nested(value) for key, value in redacted.items()}


#: A live event subscriber: one serialized event dict per call.
EventSink = Callable[[dict[str, Any]], None]
