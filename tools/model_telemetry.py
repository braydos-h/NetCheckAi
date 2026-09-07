"""Safe LLM usage telemetry for local dashboards.

The telemetry file intentionally stores only numeric/categorical metadata.
Prompts, responses, tool arguments, and raw provider payloads are not persisted.
"""

from __future__ import annotations

import inspect
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a runtime dependency
    yaml = None  # type: ignore


USAGE_LOG_NAME = "llm_usage.jsonl"
_WRITE_LOCK = threading.Lock()
PUBLIC_USAGE_FIELDS = (
    "schema_version",
    "alias",
    "model_id",
    "source",
    "stream",
    "started_at",
    "ended_at",
    "wall_duration_seconds",
    "provider_total_duration_seconds",
    "prompt_eval_duration_seconds",
    "completion_eval_duration_seconds",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "tokens_per_second",
    "prompt_tokens_per_second",
    "completion_tokens_per_second",
    "context_window_tokens",
    "estimated_context_tokens",
    "context_usage_pct",
    "context_remaining_tokens",
    "provider",
    "error",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ns_to_seconds(value: Any) -> float | None:
    raw = _as_float(value)
    if raw is None:
        return None
    return raw / 1_000_000_000


def _rate(tokens: int | None, seconds: float | None) -> float | None:
    if tokens is None or seconds is None or seconds <= 0:
        return None
    return tokens / seconds


def _usage_field(usage: Any, *names: str) -> int | None:
    for name in names:
        found = _as_int(_field(usage, name))
        if found is not None:
            return found
    return None


_CONFIG_CACHE: dict[str, Any] = {"mtime": 0.0, "size": -1, "config": {}}
_CONFIG_CACHE_LOCK = threading.Lock()


def _load_config(config_path: Path = Path("config.yaml")) -> dict[str, Any]:
    if config_path == Path("config.yaml") and not config_path.exists():
        try:
            from tools.paths import load_effective_config

            return load_effective_config(config_path)
        except Exception:
            return {}
    if yaml is None or not config_path.exists():
        return {}
    # ponytail: cache yaml parse by mtime+size — telemetry runs per LLM call.
    try:
        stat = config_path.stat()
        cache_key = (stat.st_mtime_ns, stat.st_size)
        with _CONFIG_CACHE_LOCK:
            if _CONFIG_CACHE.get("key") == cache_key:
                cached = _CONFIG_CACHE.get("config", {})
                return cached if isinstance(cached, dict) else {}
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            return {}
        with _CONFIG_CACHE_LOCK:
            _CONFIG_CACHE["key"] = cache_key
            _CONFIG_CACHE["config"] = loaded
        return loaded
    except Exception:
        with _CONFIG_CACHE_LOCK:
            cached = _CONFIG_CACHE.get("config", {})
        return cached if isinstance(cached, dict) else {}


def workspace_root_from_sources(config_path: Path = Path("config.yaml")) -> Path:
    env = os.environ.get("RESEARCH_WORKSPACE", "").strip()
    if env:
        return Path(env).resolve()

    # ponytail: cache default root — Path.cwd().resolve() per LLM call is waste.
    with _CONFIG_CACHE_LOCK:
        cached_root = _CONFIG_CACHE.get("workspace_root")
        cached_key = _CONFIG_CACHE.get("key")
    # Reuse cached root only when config file unchanged (same mtime key).
    try:
        stat = config_path.stat() if config_path.exists() else None
        current_key = (stat.st_mtime_ns, stat.st_size) if stat else None
    except OSError:
        current_key = None
    if cached_root is not None and cached_key == current_key and current_key is not None:
        return Path(cached_root)

    api_cfg = _load_config(config_path).get("api", {}) or {}
    if isinstance(api_cfg, Mapping):
        configured = str(api_cfg.get("workspace_root", "") or "").strip()
        if configured:
            resolved = Path(configured).resolve()
            with _CONFIG_CACHE_LOCK:
                _CONFIG_CACHE["workspace_root"] = str(resolved)
            return resolved

    resolved = (Path.cwd() / "research_workspace").resolve()
    with _CONFIG_CACHE_LOCK:
        _CONFIG_CACHE["workspace_root"] = str(resolved)
    return resolved


def usage_log_path(workspace_root: Path | None = None) -> Path:
    root = (workspace_root or workspace_root_from_sources()).resolve()
    return root / "logs" / USAGE_LOG_NAME


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 3)


def estimate_context_tokens(messages: Any) -> int | None:
    if not isinstance(messages, list):
        return None

    total = 0
    for msg in messages:
        if not isinstance(msg, Mapping):
            total += estimate_tokens(str(msg))
            continue
        total += estimate_tokens(str(msg.get("content", "") or ""))
        for tool_call in msg.get("tool_calls", []) or []:
            total += estimate_tokens(json.dumps(tool_call, default=str))
        if msg.get("tool_name"):
            total += estimate_tokens(str(msg["tool_name"]))
        total += 4
    return total


def infer_source() -> str:
    known = {
        "exploit_agent.py": "exploit_agent",
        # exploit_agent was split into a package (tools/exploit_agent/*); map
        # each submodule's basename so telemetry still attributes these calls
        # instead of falling through to "unknown" after the refactor.
        "loop.py": "exploit_agent",
        "context.py": "exploit_agent",
        "model_client.py": "exploit_agent",
        "tool_calls.py": "exploit_agent",
        "prompt.py": "exploit_agent",
        "skills.py": "exploit_agent",
        "reflection.py": "exploit_agent",
        "policy.py": "exploit_agent",
        "_common.py": "exploit_agent",
        "payload_crafter.py": "payload_crafter",
        "semantic_memory.py": "semantic_memory",
        "safety_reviewer.py": "safety_review",
        "mcp_exploit_server.py": "peer_consult",
        "critic_agent.py": "swarm_critic",
        "vuln_agent.py": "swarm_vuln",
        "reflection_agent.py": "swarm_reflection",
        "post_exploit_agent.py": "swarm_post_exploit",
        "recon_agent.py": "swarm_recon",
    }
    # ponytail: walk f_back instead of inspect.stack() — stack() builds full
    # FrameInfo records per call; this is per-LLM-call hot path.
    try:
        frame = inspect.currentframe()
        # skip infer_source + its caller (chat wrapper)
        current = frame.f_back.f_back if frame and frame.f_back else None
        depth = 0
        while current is not None and depth < 10:
            name = Path(current.f_code.co_filename).name
            if name in known:
                return known[name]
            current = current.f_back
            depth += 1
    except Exception:
        return "unknown"
    finally:
        del frame
    return "unknown"


def build_usage_record(
    *,
    alias: str,
    model_id: str,
    response: Any | None,
    messages: Any = None,
    stream: bool = False,
    started_at: str,
    ended_at: str,
    wall_duration_seconds: float,
    context_window_tokens: int | None = None,
    source: str = "",
    error: str = "",
    provider: str = "ollama",
) -> dict[str, Any]:
    usage = _field(response, "usage", {}) or {}
    prompt_tokens = _as_int(_field(response, "prompt_eval_count"))
    if prompt_tokens is None:
        prompt_tokens = _usage_field(usage, "prompt_tokens", "input_tokens")

    completion_tokens = _as_int(_field(response, "eval_count"))
    if completion_tokens is None:
        completion_tokens = _usage_field(usage, "completion_tokens", "output_tokens")

    total_tokens = _usage_field(usage, "total_tokens")
    if total_tokens is None and prompt_tokens is not None and completion_tokens is not None:
        total_tokens = prompt_tokens + completion_tokens

    prompt_eval_duration = _ns_to_seconds(_field(response, "prompt_eval_duration"))
    completion_eval_duration = _ns_to_seconds(_field(response, "eval_duration"))
    total_duration = _ns_to_seconds(_field(response, "total_duration"))

    estimated_context = estimate_context_tokens(messages)
    ctx_window = _as_int(context_window_tokens)
    context_usage_pct = None
    context_remaining_tokens = None
    if estimated_context is not None and ctx_window and ctx_window > 0:
        context_usage_pct = (estimated_context / ctx_window) * 100
        context_remaining_tokens = max(0, ctx_window - estimated_context)

    return {
        "schema_version": 1,
        "alias": alias,
        "model_id": model_id,
        "source": source or "unknown",
        "stream": bool(stream),
        "started_at": started_at,
        "ended_at": ended_at,
        "wall_duration_seconds": wall_duration_seconds,
        "provider_total_duration_seconds": total_duration,
        "prompt_eval_duration_seconds": prompt_eval_duration,
        "completion_eval_duration_seconds": completion_eval_duration,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "tokens_per_second": _rate(total_tokens, wall_duration_seconds),
        "prompt_tokens_per_second": _rate(prompt_tokens, prompt_eval_duration),
        "completion_tokens_per_second": _rate(completion_tokens, completion_eval_duration),
        "context_window_tokens": ctx_window,
        "estimated_context_tokens": estimated_context,
        "context_usage_pct": context_usage_pct,
        "context_remaining_tokens": context_remaining_tokens,
        "provider": str(provider or "ollama"),
        "error": str(error or "")[:500],
    }


def record_usage(record: Mapping[str, Any], workspace_root: Path | None = None) -> None:
    path = usage_log_path(workspace_root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(dict(record), sort_keys=True, default=str)
        with _WRITE_LOCK:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except Exception:
        # Telemetry must never break a model call.
        return


def record_model_usage(
    *,
    alias: str,
    model_id: str,
    response: Any | None,
    messages: Any,
    stream: bool,
    started_at: str,
    ended_at: str,
    wall_duration_seconds: float,
    context_window_tokens: int | None,
    source: str = "",
    error: str = "",
    workspace_root: Path | None = None,
    provider: str = "ollama",
) -> dict[str, Any]:
    record = build_usage_record(
        alias=alias,
        model_id=model_id,
        response=response,
        messages=messages,
        stream=stream,
        started_at=started_at,
        ended_at=ended_at,
        wall_duration_seconds=wall_duration_seconds,
        context_window_tokens=context_window_tokens,
        source=source,
        error=error,
        provider=provider,
    )
    record_usage(record, workspace_root)
    return record


def read_usage_records(
    workspace_root: Path,
    *,
    alias: str = "",
    limit: int = 100,
    offset: int = 0,
    max_limit: int = 500,
) -> list[dict[str, Any]]:
    path = usage_log_path(workspace_root)
    if not path.exists() or not path.is_file():
        return []

    capped = max(1, min(int(limit), int(max_limit)))
    start = max(0, int(offset))
    records: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    for line in reversed(lines):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        if alias and str(item.get("alias", "")) != alias:
            continue
        records.append({key: item.get(key) for key in PUBLIC_USAGE_FIELDS if key in item})

    return records[start : start + capped]


def _sum_int(records: Iterable[Mapping[str, Any]], field: str) -> int:
    total = 0
    for item in records:
        value = _as_int(item.get(field))
        if value is not None:
            total += value
    return total


def _average(records: Iterable[Mapping[str, Any]], field: str) -> float | None:
    values = [_as_float(item.get(field)) for item in records]
    present = [value for value in values if value is not None]
    if not present:
        return None
    return sum(present) / len(present)


def usage_summary(workspace_root: Path, *, alias: str = "") -> dict[str, Any]:
    records = read_usage_records(
        workspace_root,
        alias=alias,
        limit=1_000_000,
        offset=0,
        max_limit=1_000_000,
    )
    aliases = sorted({str(item.get("alias", "")) for item in records if item.get("alias")})
    context_values = [
        _as_float(item.get("context_usage_pct"))
        for item in records
        if _as_float(item.get("context_usage_pct")) is not None
    ]
    last_call_at = records[0].get("ended_at", "") if records else ""
    failed = sum(1 for item in records if item.get("error"))

    return {
        "alias": alias,
        "aliases": aliases,
        "calls": len(records),
        "successful_calls": len(records) - failed,
        "failed_calls": failed,
        "prompt_tokens": _sum_int(records, "prompt_tokens"),
        "completion_tokens": _sum_int(records, "completion_tokens"),
        "total_tokens": _sum_int(records, "total_tokens"),
        "average_tokens_per_second": _average(records, "tokens_per_second"),
        "average_completion_tokens_per_second": _average(records, "completion_tokens_per_second"),
        "average_context_usage_pct": _average(records, "context_usage_pct"),
        "max_context_usage_pct": max(context_values) if context_values else None,
        "last_call_at": last_call_at,
    }
