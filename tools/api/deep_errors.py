"""Shared deep-error record builder + emitter (Deep Run Logs).

Single helper for every deep-error call site (exploit loop, API enrichment,
summary writer): one schema, one redaction path, fail-open by contract —
logging must never break a run.
"""

from __future__ import annotations

import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.api.errors import sanitize
from tools.exceptions import _EXC_GROUP_CATCH
from tools.kernel.audit import _mask_secret_content, _redact_args

DEEP_ERROR_KINDS = frozenset(
    {
        "model_call",
        "circuit_open",
        "mcp_transport",
        "parse",
        "tool_error",
        "preparation",
        "hook_silent",
    }
)

_TRACEBACK_KINDS = frozenset({"model_call", "mcp_transport", "parse", "tool_error", "preparation"})


def build_deep_error_record(run_id: str, *, kind: str, exc: BaseException, ctx: dict[str, Any]) -> dict[str, Any]:
    """Build a DeepErrorRecord dict (pure sync builder: no I/O)."""
    if ctx.get("traceback") or kind in _TRACEBACK_KINDS:
        tb_text: str | None = sanitize("".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[:8000])
    else:
        tb_text = None
    return {
        "type": "error",
        "run_id": run_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "corr_id": ctx.get("corr_id"),
        "kind": kind,
        "phase": ctx.get("phase"),
        "round": ctx.get("round", 0),
        "attempt_id": ctx.get("attempt_id"),
        "retry": ctx.get("retry", 0),
        "hook": ctx.get("hook"),
        "tool": {
            "name": ctx.get("tool_name"),
            "action": ctx.get("action"),
            # ponytail: _redact_args misses non-canonical secret names (e.g.
            # api_token); the sanitize pass normalizes them to [REDACTED].
            "args_redacted": sanitize(_redact_args(ctx.get("args") or {})),
        },
        "model": {
            "prompt_excerpt": sanitize(str(ctx.get("prompt_excerpt", ""))[-2000:]),
            "response_excerpt": sanitize(str(ctx.get("response_excerpt", ""))[-2000:]),
        },
        "error": {
            "class": type(exc).__name__,
            "message": sanitize(_mask_secret_content(str(exc))[:1000]),
            "traceback": tb_text,
        },
        "log_refs": {"session_error.log": True},
    }


async def emit_deep_error(
    sink: Any,
    run_id: str,
    *,
    kind: str,
    exc: BaseException,
    ctx: dict[str, Any],
    reports_dir: str | Path | None = None,
) -> None:
    """Emit the record to ``sink`` (+ optional errors.jsonl mirror). Fail-open: never raises."""
    try:
        record = build_deep_error_record(run_id, kind=kind, exc=exc, ctx=ctx)
        await sink.emit("error", record)
        if reports_dir is not None:
            _mirror = Path(reports_dir) / "errors.jsonl"
            _mirror.parent.mkdir(parents=True, exist_ok=True)
            with open(_mirror, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")
    except _EXC_GROUP_CATCH:
        pass
