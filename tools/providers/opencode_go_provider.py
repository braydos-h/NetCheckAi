"""OpenCode Go provider adapter — OpenAI Responses API.

Wraps the hosted OpenCode Go Responses endpoint at
``https://opencode.ai/zen/go/v1/responses``.  This adapter speaks the
Responses API but exposes an Ollama-compatible ``.chat()`` surface so the
rest of BreachPilot (exploit agent, swarm, payload crafter, etc.) stays
provider-agnostic.

The injection seam mirrors ``ChatGptProxyClient`` — ``tools/model_router.py``
passes an instance as ``raw_client`` into ``_build_model_client``.

Design notes:

* Only Responses-compatible models should be registered through this client.
  ``muse-spark-1.2-contributor`` is the guaranteed one; additional
  discovered ids are filtered in ``model_router``.
* Ollama-only kwargs (``options``, ``keep_alive``, ``format``, etc.) are
  dropped locally.
* Tool schemas and message history are translated explicitly (see helpers).
"""

from __future__ import annotations

import json
import time
import uuid
from typing import TYPE_CHECKING, Any, Iterator, Mapping

from .base import BaseProvider, make_model_client
from .types import ModelInfo, ProviderCapabilities, ProviderDiscoveryError, ProviderHealth

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tools.model_router import ModelRouter

    from .types import ModelClient

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is a runtime dependency
    httpx = None  # type: ignore

_DEFAULT_BASE_URL = "https://opencode.ai/zen/go/v1"
_DEFAULT_MODEL = "muse-spark-1.2-contributor"
_DEFAULT_TIMEOUT = 300.0
_MODEL_CACHE_SECONDS = 300.0

_SESSION_HEADER = "x-opencode-session"
# ponytail: process-stable UUID satisfies "one stable ID per conversation".
_SESSION_ID = uuid.uuid4().hex


def opencode_session_id() -> str:
    """Stable session ID sent as ``x-opencode-session`` on every OpenCode Go request."""
    return _SESSION_ID


# Ollama-only kwargs that Responses does not understand.
_DROP_KWARGS = ("options", "keep_alive", "format", "suffix", "think", "raw", "num_ctx")

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _opencode_go_defaults() -> dict[str, Any]:
    return {
        "enabled": False,
        "base_url": _DEFAULT_BASE_URL,
        "api_key_env": "OPENCODE_GO_API_KEY",
        "request_timeout_seconds": _DEFAULT_TIMEOUT,
        "default_model": _DEFAULT_MODEL,
        "models": [],
        "context_window": 128000,
        "discover_cache_seconds": _MODEL_CACHE_SECONDS,
    }


def _coalesce(cfg: Mapping[str, Any] | None) -> dict[str, Any]:
    merged = _opencode_go_defaults()
    if cfg:
        for k, v in cfg.items():
            if v is not None:
                merged[k] = v
    # Ensure nested defaults cleanly
    for key, default in _opencode_go_defaults().items():
        if key not in merged:
            merged[key] = default
    return merged


def _get_api_key(cfg: Mapping[str, Any] | None = None, direct_key: str | None = None) -> str:
    """Resolve the API key: direct ``api_key`` kwarg wins, else env var.

    Never logs the key.  Returns empty string when absent.
    """
    if direct_key is not None:
        return str(direct_key).strip()
    merged = _coalesce(cfg) if cfg is not None else _opencode_go_defaults()
    env_name = str(merged.get("api_key_env") or "OPENCODE_GO_API_KEY").strip() or "OPENCODE_GO_API_KEY"
    import os

    return (os.environ.get(env_name, "") or "").strip()


# ---------------------------------------------------------------------------
# Tool schema conversion
# ---------------------------------------------------------------------------


def _convert_tool_schemas(ollama_tools: list[Any] | None) -> list[dict[str, Any]] | None:
    """Convert Ollama tool schemas to Responses API function-tool format.

    Ollama / OpenAI-Chat: ``{"type":"function","function":{"name","description","parameters"}}``
    Responses:            ``{"type":"function","name","description","parameters"}``
    """
    if not ollama_tools:
        return None
    out: list[dict[str, Any]] = []
    for tool in ollama_tools:
        if not isinstance(tool, dict):
            continue
        func = tool.get("function") or {}
        if not isinstance(func, dict):
            continue
        name = str(func.get("name") or "").strip()
        if not name:
            continue
        entry: dict[str, Any] = {"type": "function", "name": name}
        desc = func.get("description")
        if desc:
            entry["description"] = str(desc)
        params = func.get("parameters")
        if params is not None:
            entry["parameters"] = params
        # Preserve strict if present
        if "strict" in func:
            entry["strict"] = bool(func["strict"])
        out.append(entry)
    return out if out else None


# ---------------------------------------------------------------------------
# Message history conversion  (Ollama role list -> Responses input list)
# ---------------------------------------------------------------------------


def _normalize_content(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _convert_messages_to_input(messages: Any) -> list[dict[str, Any]]:
    """Translate Ollama-style messages to Responses ``input`` items.

    Handles:
    * system / developer / user -> {"role":..., "content":...}
    * assistant with plain content
    * assistant with tool_calls -> function_call items (synthetic call_id where needed)
    * tool -> function_call_output items (matched to prior calls in order)

    Well-formedness contract enforced for the hosted Responses gateway:

    * **Adjacency** — every ``function_call`` item is immediately followed by
      its ``function_call_output``. The agent loop appends operator notes
      (service detection, research advisories, replan prompts) between tool
      results; the gateway closes the tool-result block at the first
      non-output item, which orphaned the later calls of the same turn
      ("No tool output found for tool call call_1" 400s from round 2 onward).
      Outputs are therefore attached to their call and emitted adjacent to it.
    * **Totality** — every ``function_call`` gets exactly one output. When a
      tool never returned (interrupted run, exhausted budget), a synthesized
      placeholder output keeps the request valid; orphan tool results with no
      pending call are demoted to user items instead of bare
      ``function_call_output`` items (which strict gateways reject).
    """
    if not messages:
        return []
    if not isinstance(messages, list):
        messages = list(messages)

    # We also need to handle assistant tool_calls that may be dict or object.
    # Helper to get field like chatgpt provider's _get_field.
    def _get(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    # First pass: walk messages in order collecting an op sequence.
    #   ("item", dict)                -> plain role item, emitted verbatim
    #   ("call", entry)               -> function_call; entry holds the output
    #                                    slot so assembly can emit call+output
    #                                    adjacent even when the result arrives
    #                                    later in the walk
    #   ("orphan", (tool_name, text)) -> tool result with no pending call;
    #                                    demoted to a user item at its position
    seq: list[tuple[str, Any]] = []
    pending: list[dict[str, Any]] = []
    counter = 0
    used_ids: set[str] = set()

    def _synthetic_id() -> str:
        nonlocal counter

        while True:
            cid = f"call_{counter}"
            counter += 1
            if cid not in used_ids:
                return cid

    def _new_call_entry(call_id: str, name: str, args_str: str) -> dict[str, Any]:
        entry = {"call_id": call_id, "name": name, "arguments": args_str, "output": None}
        used_ids.add(call_id)
        pending.append(entry)
        seq.append(("call", entry))
        return entry

    def _attach_output(explicit_id: Any, tool_name: str, content: str) -> None:
        entry: dict[str, Any] | None = None
        if explicit_id:
            wanted = str(explicit_id)
            for cand in pending:
                if cand["call_id"] == wanted:
                    entry = cand
                    pending.remove(cand)
                    break
        if entry is None and pending:
            entry = pending.pop(0)
        if entry is not None:
            entry["output"] = content if content else "(empty result)"
        else:
            seq.append(("orphan", (tool_name, content)))

    for msg in messages:
        if not isinstance(msg, dict):
            # Coerce objects with attributes
            try:
                role = str(_get(msg, "role", "") or "user")
                content = _normalize_content(_get(msg, "content", ""))
            except Exception:
                continue
            if role == "tool":
                _attach_output(None, "", content)
            elif role == "assistant":
                if content:
                    seq.append(("item", {"role": "assistant", "content": content}))
            else:
                seq.append(("item", {"role": "system" if role == "system" else "user", "content": content}))
            continue

        role = str(msg.get("role") or "").strip().lower()

        if role in ("system", "developer"):
            content = _normalize_content(msg.get("content"))
            seq.append(("item", {"role": role, "content": content}))
            continue

        if role == "user":
            content = _normalize_content(msg.get("content"))
            seq.append(("item", {"role": "user", "content": content}))
            continue

        if role == "tool":
            tool_name = str(msg.get("tool_name") or msg.get("name") or "").strip()
            content = _normalize_content(msg.get("content"))
            _attach_output(msg.get("tool_call_id") or msg.get("call_id") or msg.get("id"), tool_name, content)
            continue

        if role == "assistant":
            content = _normalize_content(msg.get("content"))
            thinking = _normalize_content(msg.get("thinking"))
            raw_tc = msg.get("tool_calls")
            if raw_tc is None:
                raw_tc = []

            # If no tool calls, emit assistant message if there is text
            if not raw_tc:
                if content:
                    seq.append(("item", {"role": "assistant", "content": content}))
                # thinking is never user-facing for Responses — drop
                continue

            # Assistant text precedes its calls; outputs stay adjacent to calls
            if content:
                seq.append(("item", {"role": "assistant", "content": content}))

            for tc in raw_tc or []:
                func = _get(tc, "function", {}) or {}
                if isinstance(func, dict):
                    name = str(_get(func, "name", "") or "").strip()
                    args = _get(func, "arguments", "")
                else:
                    name = str(_get(tc, "name", "") or "").strip()
                    args = _get(tc, "arguments", "")
                if not name:
                    continue
                # arguments must be JSON string
                if isinstance(args, dict):
                    try:
                        args_str = json.dumps(args, ensure_ascii=False)
                    except Exception:
                        args_str = "{}"
                elif isinstance(args, str):
                    args_str = args
                elif args is None:
                    args_str = "{}"
                else:
                    try:
                        args_str = json.dumps(args, ensure_ascii=False)
                    except Exception:
                        args_str = str(args)

                call_id = _get(tc, "id", None) or _get(tc, "call_id", None) or _get(func, "call_id", None)
                if not call_id or str(call_id) in used_ids:
                    call_id = _synthetic_id()
                else:
                    call_id = str(call_id)
                _new_call_entry(call_id, name, args_str)
            continue

        # Unknown role -> treat as user
        content = _normalize_content(msg.get("content"))
        if content or role:
            seq.append(("item", {"role": "user", "content": content if content else str(msg)}))

    # Second pass: assemble with call -> output adjacency guaranteed.
    input_items: list[dict[str, Any]] = []
    for kind, payload in seq:
        if kind == "item":
            input_items.append(payload)
        elif kind == "orphan":
            tool_name, content = payload
            prefix = f"[{tool_name}] " if tool_name else ""
            text = f"{prefix}{content}" if prefix and content else (content or "(empty tool result)")
            input_items.append({"role": "user", "content": text})
        else:  # call
            output = payload["output"]
            if output is None:
                output = "(no tool result recorded — tool execution was interrupted)"
            input_items.append(
                {
                    "type": "function_call",
                    "call_id": payload["call_id"],
                    "name": payload["name"],
                    "arguments": payload["arguments"],
                }
            )
            input_items.append(
                {
                    "type": "function_call_output",
                    "call_id": payload["call_id"],
                    "output": output,
                }
            )

    return input_items


# ---------------------------------------------------------------------------
# Response normalization (Responses output -> Ollama-shaped)
# ---------------------------------------------------------------------------


def _normalize_usage(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    # Already desired shape
    out: dict[str, Any] = {}
    # Map alternative keys
    if "input_tokens" in raw:
        out["input_tokens"] = raw["input_tokens"]
    elif "prompt_tokens" in raw:
        out["input_tokens"] = raw["prompt_tokens"]
    if "output_tokens" in raw:
        out["output_tokens"] = raw["output_tokens"]
    elif "completion_tokens" in raw:
        out["output_tokens"] = raw["completion_tokens"]
    if "total_tokens" in raw:
        out["total_tokens"] = raw["total_tokens"]
    else:
        # Derive if missing
        inp = out.get("input_tokens")
        oup = out.get("output_tokens")
        if isinstance(inp, int) and isinstance(oup, int):
            out["total_tokens"] = inp + oup
    # Preserve any other numeric usages
    for k in ("prompt_tokens", "completion_tokens"):
        if k in raw and k not in out:
            out[k] = raw[k]
    return out


def _normalize_responses_output(data: dict[str, Any], fallback_model: str) -> dict[str, Any]:
    """Turn a Responses API response body into Ollama-compatible dict."""
    model = str(data.get("model") or fallback_model or _DEFAULT_MODEL)

    # The output array may be under "output" or "data" or top-level "output"
    output = data.get("output")
    if output is None:
        # Some mocked providers may use "data" list
        output = data.get("data")
    if output is None:
        # Fallback: treat single choice style? But spec says output.
        output = []

    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []

    # output may be a string (unlikely) — handle
    if isinstance(output, str):
        text_parts.append(output)
    elif isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            item_type = item.get("type") or ""
            if item_type == "message":
                # Content is list of output_text / refusal blocks
                content_blocks = item.get("content") or []
                if isinstance(content_blocks, str):
                    text_parts.append(content_blocks)
                elif isinstance(content_blocks, list):
                    for block in content_blocks:
                        if not isinstance(block, dict):
                            if isinstance(block, str):
                                text_parts.append(block)
                            continue
                        btype = block.get("type") or ""
                        if btype == "output_text":
                            text_parts.append(str(block.get("text") or ""))
                        elif btype == "refusal":
                            text_parts.append(str(block.get("refusal") or ""))
                        elif btype == "input_text":
                            text_parts.append(str(block.get("text") or ""))
                        elif "text" in block:
                            text_parts.append(str(block.get("text") or ""))
                        else:
                            # Unknown block — try to extract text field
                            for key in ("text", "content", "value"):
                                if key in block and isinstance(block[key], str):
                                    text_parts.append(block[key])
                                    break
                elif isinstance(content_blocks, dict):
                    # Single block
                    if "text" in content_blocks:
                        text_parts.append(str(content_blocks.get("text") or ""))
            elif item_type == "function_call":
                call_id = str(item.get("call_id") or item.get("id") or "")
                name = str(item.get("name") or "")
                arguments = item.get("arguments") or ""
                # Ensure arguments is string for later _normalize_tool_call
                if isinstance(arguments, dict):
                    try:
                        arguments = json.dumps(arguments, ensure_ascii=False)
                    except Exception:
                        arguments = "{}"
                elif arguments is None:
                    arguments = "{}"
                else:
                    arguments = str(arguments)
                # Ollama-shaped tool call (preserve id for downstream where possible)
                entry: dict[str, Any] = {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": arguments},
                }
                # Also preserve call_id explicitly for consumers that read it
                if call_id:
                    entry["call_id"] = call_id
                tool_calls.append(entry)
            elif item_type == "output_text":
                text_parts.append(str(item.get("text") or ""))
            elif item_type == "reasoning":
                # Ignore reasoning content for now (don't leak thinking as content)
                continue
            else:
                # Unknown item type — try to locate text or function info inside
                if item.get("text") and isinstance(item.get("text"), str):
                    text_parts.append(str(item["text"]))
                # Also handle nested 'output' key?
                if item.get("output") and isinstance(item["output"], str):
                    text_parts.append(str(item["output"]))

    # Also handle alternative field "output_text" top-level (some providers)
    if not text_parts and isinstance(data.get("output_text"), str):
        text_parts.append(data["output_text"])
    if not text_parts and isinstance(data.get("text"), str):
        text_parts.append(data["text"])

    # Fallback: if output empty but data has "content" (chat-like), try it (defensive)
    if not text_parts and not tool_calls:
        # Check for chat-style choices (should not happen via /responses, but handle mocks)
        choices = data.get("choices") or []
        if isinstance(choices, list) and choices:
            msg = choices[0].get("message") or {}
            c = msg.get("content")
            if c:
                text_parts.append(str(c))
            tcs = msg.get("tool_calls") or []
            for tc in tcs:
                tool_calls.append(tc)  # pass through

    content_str = "".join(text_parts)

    # Usage normalization
    usage_raw = data.get("usage") or {}
    # Sometimes usage is nested under response
    if not usage_raw and isinstance(data.get("response"), dict):
        usage_raw = data["response"].get("usage") or {}
    usage = _normalize_usage(usage_raw)

    return {
        "model": model,
        "message": {
            "role": "assistant",
            "content": content_str,
            "thinking": "",
            "tool_calls": tool_calls,
        },
        "usage": usage,
    }


# ---------------------------------------------------------------------------
# Streaming SSE helpers (Responses API)
# ---------------------------------------------------------------------------


def _parse_sse_stream(
    response: Any,
) -> Iterator[dict[str, Any]]:
    """Parse Responses SSE lines, yielding Ollama-shaped delta chunks.

    Caller must have already called ``raise_for_status``.
    """
    # Accumulators for function calls fragmented across deltas
    tool_accum: dict[str, dict[str, Any]] = {}
    # Track pending text? We yield deltas immediately.
    final_usage: dict[str, Any] = {}
    last_event: str | None = None

    # Helper to ensure a slot exists
    def _ensure_slot(call_id: str) -> dict[str, Any]:
        if call_id not in tool_accum:
            tool_accum[call_id] = {"id": call_id, "type": "function", "function": {"name": "", "arguments": ""}}
        return tool_accum[call_id]

    for raw_line in response.iter_lines():
        # httpx may return bytes
        if isinstance(raw_line, bytes):
            try:
                line = raw_line.decode("utf-8")
            except Exception:
                line = raw_line.decode("utf-8", errors="replace")
        else:
            line = str(raw_line)
        if not line:
            continue
        if line.startswith(":"):
            # SSE comment / keepalive
            continue
        if line.startswith("event:"):
            last_event = line[len("event:") :].strip()
            continue
        if not line.startswith("data:"):
            continue
        body = line[len("data:") :].strip()
        if body == "[DONE]":
            break
        try:
            chunk = json.loads(body)
        except json.JSONDecodeError:
            # Ignore malformed keepalives
            continue

        ev_type = str(chunk.get("type") or last_event or "").strip()
        # Reset last_event after consuming
        consumed_event = ev_type
        last_event = None

        # Error event
        if "error" in chunk and ev_type in ("error", "response.failed"):
            err = chunk.get("error")
            if isinstance(err, dict):
                msg = err.get("message") or json.dumps(err)
            else:
                msg = str(err)
            raise RuntimeError(f"OpenCode Go error: {msg}")

        # Text delta handling
        # Common deltas: response.output_text.delta with field "delta"
        if consumed_event == "response.output_text.delta" or "output_text.delta" in consumed_event:
            delta = chunk.get("delta")
            if delta is None:
                delta = chunk.get("text")
            if isinstance(delta, dict):
                delta = delta.get("text") or delta.get("delta") or ""
            if isinstance(delta, str) and delta != "":
                yield {"message": {"role": "assistant", "content": delta, "thinking": ""}}
            continue

        # Alternative delta shape: {"delta": {"text": "..."}}
        # Already handled above

        # Function call argument deltas
        if (
            consumed_event == "response.function_call_arguments.delta"
            or "function_call_arguments.delta" in consumed_event
        ):
            call_id = str(chunk.get("call_id") or chunk.get("item_id") or chunk.get("id") or "0")
            delta = chunk.get("delta") or chunk.get("arguments") or ""
            if isinstance(delta, dict):
                try:
                    delta = json.dumps(delta)
                except Exception:
                    delta = str(delta)
            slot = _ensure_slot(call_id)
            # Accumulate
            slot["function"]["arguments"] = str(slot["function"]["arguments"] or "") + str(delta or "")
            # If chunk also carries name, update
            name = chunk.get("name")
            if name:
                slot["function"]["name"] = (
                    str(name) + str(slot["function"]["name"] or "") if slot["function"]["name"] else str(name)
                )
            # Also handle case where delta contains JSON string fragment, we already append
            continue

        # Output item added — signals new function_call start
        if consumed_event == "response.output_item.added" or consumed_event == "response.output_item.done":
            item = chunk.get("item") or {}
            if isinstance(item, dict) and item.get("type") == "function_call":
                call_id = str(item.get("call_id") or item.get("id") or f"call_{len(tool_accum)}")
                name = str(item.get("name") or "")
                args = item.get("arguments") or ""
                if isinstance(args, dict):
                    try:
                        args = json.dumps(args)
                    except Exception:
                        args = str(args)
                if consumed_event.endswith("added"):
                    # Create slot
                    slot = _ensure_slot(call_id)
                    if name:
                        slot["function"]["name"] = name
                    if args:
                        slot["function"]["arguments"] = str(args)
                    # Preserve id
                    slot["id"] = call_id
                else:  # done
                    slot = _ensure_slot(call_id)
                    if name:
                        slot["function"]["name"] = name
                    # For done, arguments may be final complete string
                    if args is not None:
                        # If we have accumulated deltas, keep accumulated unless this is final
                        # Prefer final if slot was empty before
                        if not slot["function"]["arguments"]:
                            slot["function"]["arguments"] = str(args)
                        else:
                            # If final differs, trust final complete
                            if len(str(args)) > len(str(slot["function"]["arguments"])):
                                slot["function"]["arguments"] = str(args)
                    slot["id"] = call_id
            continue

        # Content part events
        if consumed_event in ("response.content_part.added", "response.content_part.done", "response.output_item.done"):
            # No text delta here beyond item handling already above
            continue

        # Completed with usage and possibly final output
        if consumed_event in ("response.completed", "response.done"):
            resp = chunk.get("response") or {}
            if isinstance(resp, dict):
                usage = resp.get("usage") or chunk.get("usage") or {}
                if usage:
                    final_usage = _normalize_usage(usage)
                # Also extract any final tool calls if they weren't streamed piecewise?
                # The response object includes output array similar to non-stream
                output = resp.get("output")
                if isinstance(output, list):
                    for item in output:
                        if isinstance(item, dict) and item.get("type") == "function_call":
                            call_id = str(item.get("call_id") or item.get("id") or f"call_{len(tool_accum)}")
                            if call_id not in tool_accum:
                                name = str(item.get("name") or "")
                                args = item.get("arguments") or ""
                                if isinstance(args, dict):
                                    try:
                                        args = json.dumps(args)
                                    except Exception:
                                        args = str(args)
                                tool_accum[call_id] = {
                                    "id": call_id,
                                    "type": "function",
                                    "function": {"name": name, "arguments": str(args)},
                                }
            else:
                usage = chunk.get("usage")
                if usage:
                    final_usage = _normalize_usage(usage)
            continue

        # Fallback: Chat Completions style streaming (choices)
        if "choices" in chunk:
            choices = chunk.get("choices") or []
            if not choices:
                usage = chunk.get("usage")
                if usage:
                    final_usage = _normalize_usage(usage)
                continue
            delta = choices[0].get("delta") or {}
            content = delta.get("content")
            if content:
                yield {"message": {"role": "assistant", "content": str(content), "thinking": ""}}
            # Tool call fragments (Chat Completions delta format)
            for tc in delta.get("tool_calls") or []:
                idx = str(tc.get("index", 0))
                slot = _ensure_slot(idx)
                # id handling
                if tc.get("id"):
                    slot["id"] = str(tc["id"])
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["function"]["name"] = str(slot["function"]["name"] or "") + str(fn["name"])
                if fn.get("arguments") is not None:
                    slot["function"]["arguments"] = str(slot["function"]["arguments"] or "") + str(fn["arguments"])
            # Final usage chunk (openai-oauth style choices:[] + usage)
            usage = chunk.get("usage")
            if usage:
                final_usage = _normalize_usage(usage)
            continue

        # Generic delta field without type
        if chunk.get("delta") and isinstance(chunk["delta"], str):
            yield {"message": {"role": "assistant", "content": str(chunk["delta"]), "thinking": ""}}
            continue

        # If chunk contains text directly
        if chunk.get("text") and isinstance(chunk.get("text"), str) and consumed_event in ("", "message"):
            yield {"message": {"role": "assistant", "content": str(chunk["text"]), "thinking": ""}}
            continue

        # Unknown event — ignore (lifecycle)

    # After loop, yield final assembled tool_calls + usage
    assembled: list[dict[str, Any]] = []
    # Preserve insertion order
    for slot in tool_accum.values():
        # Ensure arguments is string
        args = slot["function"].get("arguments")
        if not isinstance(args, str):
            try:
                args = json.dumps(args)
            except Exception:
                args = str(args)
            slot["function"]["arguments"] = args
        assembled.append(slot)

    yield {
        "message": {"role": "assistant", "content": "", "thinking": "", "tool_calls": assembled},
        "usage": final_usage,
    }


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------


class OpenCodeGoResponsesClient:
    """Responses API adapter that quacks like an Ollama ``Client.chat``.

    Constructor never logs the key.  All HTTP requests send ``Authorization:
    Bearer <key>`` and ``Content-Type: application/json``.

    Errors are surfaced with sanitized messages (never including the key).
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        api_key: str | None = None,
        timeout: float | None = None,
        default_model: str | None = None,
        api_key_env: str | None = None,
        config: Mapping[str, Any] | None = None,
    ) -> None:
        """Create a client.

        ``base_url`` defaults to ``https://opencode.ai/zen/go/v1`` (or the
        value from ``config`` when supplied).  ``api_key`` may be supplied
        directly (tests) or resolved from ``OPENCODE_GO_API_KEY`` (via
        ``api_key_env``).  ``timeout`` is seconds for the underlying httpx
        client (defaults to ``request_timeout_seconds`` or 300).
        """
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx package not installed")

        # Resolve merged config for defaults
        merged = _coalesce(config)
        # base_url resolution: explicit > merged > default
        raw_base = base_url
        if raw_base is None:
            raw_base = merged.get("base_url") or _DEFAULT_BASE_URL
        self.base_url = str(raw_base).rstrip("/")

        # timeout resolution
        raw_timeout = timeout
        if raw_timeout is None:
            try:
                raw_timeout = float(merged.get("request_timeout_seconds") or _DEFAULT_TIMEOUT)
            except Exception:
                raw_timeout = _DEFAULT_TIMEOUT
        self.timeout = float(raw_timeout) if raw_timeout is not None else _DEFAULT_TIMEOUT

        self.default_model = str(default_model or merged.get("default_model") or _DEFAULT_MODEL)

        # API key resolution: direct api_key > config env > OPENCODE_GO_API_KEY
        if api_key is not None:
            resolved_key = str(api_key).strip()
        elif api_key_env is not None:
            import os

            resolved_key = (os.environ.get(str(api_key_env), "") or "").strip()
        else:
            # Use provided config's api_key_env
            resolved_key = _get_api_key(config=merged, direct_key=None)
            # If merged had no env, _get_api_key will have checked OPENCODE_GO_API_KEY already.
            # Directly also check OPENCODE_GO_API_KEY as fallback if config resolution gave empty.
            if not resolved_key:
                import os

                resolved_key = (os.environ.get("OPENCODE_GO_API_KEY", "") or "").strip()

        # Also honour direct OPENCODE_GO_API_KEY env irrespective of api_key_env alias?
        # The task says api_key_env default is OPENCODE_GO_API_KEY; we already do.
        self._api_key = resolved_key

        # Cache for model discovery (instance-local to avoid cross-test pollution)
        self._models_cache: tuple[float, list[str]] | None = None

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json", _SESSION_HEADER: _SESSION_ID}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _redacted_error(self, msg: str) -> str:
        # Ensure key never appears in error messages
        if self._api_key and self._api_key in msg:
            msg = msg.replace(self._api_key, "[REDACTED]")
        return msg

    def _handle_http_error(self, response: Any) -> None:
        """Raise a sanitized, typed error for status codes."""
        status = getattr(response, "status_code", 0) or 0
        body = ""
        try:
            body = response.text or ""
        except Exception:
            try:
                body = json.dumps(response.json())
            except Exception:
                body = ""
        # Redact key
        body = self._redacted_error(body)

        if status in (401, 403):
            raise RuntimeError(f"OpenCode Go authentication failed ({status}): {body[:500]}")
        if status == 429:
            raise RuntimeError(f"OpenCode Go rate limited (429): {body[:500]}")
        if status >= 400:
            raise RuntimeError(f"OpenCode Go request failed ({status}): {body[:500]}")

    # -------------------------------------------------------------------
    # Payload building
    # -------------------------------------------------------------------

    def _build_payload(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        model = kwargs.get("model") or self.default_model
        payload["model"] = str(model)

        messages = kwargs.get("messages") or []
        payload["input"] = _convert_messages_to_input(messages)

        stream = bool(kwargs.get("stream", False))
        payload["stream"] = stream

        # Tools
        tools = kwargs.get("tools")
        converted = _convert_tool_schemas(tools if isinstance(tools, list) else None)
        if converted:
            payload["tools"] = converted
        # tool_choice mapping: Ollama/OpenAI uses tool_choice; Responses uses tool_choice as well (auto/required/none or {"type":"function"})
        tool_choice = kwargs.get("tool_choice")
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice

        # Generation options — map Ollama/OpenAI names to Responses equivalents
        # Responses uses temperature, top_p, max_output_tokens, top_k etc.
        # We forward only supported keys.
        for key in (
            "temperature",
            "top_p",
            "top_k",
            "seed",
            "stop",
            "presence_penalty",
            "frequency_penalty",
            "n",
            "user",
            "parallel_tool_calls",
        ):
            if key in kwargs and kwargs[key] is not None:
                payload[key] = kwargs[key]

        # Token limit mappings: max_tokens / max_completion_tokens -> max_output_tokens
        for alias in ("max_tokens", "max_completion_tokens", "max_output_tokens", "num_predict"):
            if alias in kwargs and kwargs[alias] is not None:
                try:
                    val = int(kwargs[alias])
                except Exception:
                    continue
                payload["max_output_tokens"] = val
                break

        # Drop Ollama-only keys defensively (already removed at caller, but also here)
        for dropped in _DROP_KWARGS:
            payload.pop(dropped, None)

        return payload

    # -------------------------------------------------------------------
    # Public chat
    # -------------------------------------------------------------------

    def chat(self, *args: Any, **kwargs: Any) -> Any:
        """Ollama-compatible ``chat`` hitting ``POST /responses``.

        Returns an Ollama-shaped dict (non-stream) or an iterator of
        Ollama-shaped chunks (stream).  Never logs the API key.
        """
        # Tolerance for stray positional model/messages (like ChatGptProxyClient)
        raw = dict(kwargs)
        positional = list(args)
        if positional and isinstance(positional[0], str):
            # First positional may be model id
            if "model" not in raw:
                raw["model"] = positional.pop(0)
            else:
                positional.pop(0)
        if positional and "messages" not in raw:
            raw["messages"] = positional.pop(0)

        # Drop Ollama-only kwargs defensively before building payload
        for dropped in _DROP_KWARGS:
            raw.pop(dropped, None)

        if "model" not in raw or raw.get("model") in (None, ""):
            raw["model"] = self.default_model

        # Validate API key presence
        if not self._api_key:
            raise RuntimeError(
                "OpenCode Go API key not configured. Set OPENCODE_GO_API_KEY or configure opencode_go.api_key_env."
            )

        payload = self._build_payload(raw)
        stream = bool(payload.get("stream", False))
        url = f"{self.base_url}/responses"
        timeout = self.timeout if self.timeout is not None else _DEFAULT_TIMEOUT

        if stream:
            return self._stream(url, payload, timeout)
        return self._nonstream(url, payload, timeout)

    def _nonstream(self, url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        # Ensure non-stream flag
        payload = dict(payload)
        payload["stream"] = False
        headers = self._headers()
        try:
            with httpx.Client(timeout=timeout) as client:  # type: ignore[attr-defined]
                response = client.post(url, json=payload, headers=headers)
                if response.status_code >= 400:
                    self._handle_http_error(response)
                data = response.json()
        except httpx.HTTPStatusError as exc:  # type: ignore[attr-defined]
            # Map to typed errors without leaking key
            status = getattr(exc.response, "status_code", 0) if hasattr(exc, "response") else 0
            fake = type("R", (), {"status_code": status, "text": str(exc)})()
            self._handle_http_error(fake)
            raise
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException) as exc:  # type: ignore[attr-defined]
            # Ensure key not in message
            msg = self._redacted_error(str(exc))
            raise RuntimeError(f"OpenCode Go connection failed: {msg}") from exc
        except Exception as exc:
            # Redact key from any exception message
            msg = self._redacted_error(str(exc))
            if msg != str(exc):
                raise RuntimeError(msg) from exc
            raise

        # Validate shape
        if not isinstance(data, dict):
            raise RuntimeError("OpenCode Go returned malformed response (not a JSON object)")
        return _normalize_responses_output(data, str(payload.get("model") or self.default_model))

    def _stream(self, url: str, payload: dict[str, Any], timeout: float) -> Iterator[dict[str, Any]]:
        payload = dict(payload)
        payload["stream"] = True
        headers = self._headers()
        # httpx streaming
        try:
            with httpx.Client(timeout=timeout) as client:  # type: ignore[attr-defined]
                with client.stream("POST", url, json=payload, headers=headers) as response:  # type: ignore[attr-defined]
                    if response.status_code >= 400:
                        self._handle_http_error(response)
                    yield from _parse_sse_stream(response)
        except httpx.HTTPStatusError as exc:  # type: ignore[attr-defined]
            status = getattr(exc.response, "status_code", 0) if hasattr(exc, "response") else 0
            fake = type("R", (), {"status_code": status, "text": str(exc)})()
            self._handle_http_error(fake)
            raise
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException) as exc:  # type: ignore[attr-defined]
            msg = self._redacted_error(str(exc))
            raise RuntimeError(f"OpenCode Go connection failed: {msg}") from exc
        except Exception as exc:
            msg = self._redacted_error(str(exc))
            if msg != str(exc):
                raise RuntimeError(msg) from exc
            raise

    # -------------------------------------------------------------------
    # Model discovery
    # -------------------------------------------------------------------

    def discover_models(self, base_url: str | None = None, cfg: Mapping[str, Any] | None = None) -> list[str]:
        """Return discovered model ids from ``GET {base_url}/models`` (cached)."""
        # Allow cfg to override base_url/discover_cache_seconds
        merged = _coalesce(cfg) if cfg is not None else _coalesce(None)
        url_base = (base_url or self.base_url or merged.get("base_url") or _DEFAULT_BASE_URL).rstrip("/")
        ttl = float(merged.get("discover_cache_seconds") or _MODEL_CACHE_SECONDS)
        with_time = time.monotonic()

        # Cache check (instance-local)
        if self._models_cache is not None:
            fetched_at, ids = self._models_cache
            if with_time - fetched_at < ttl:
                return list(ids)

        if httpx is None:
            return []

        headers = self._headers()
        try:
            with httpx.Client(timeout=5.0) as client:  # type: ignore[attr-defined]
                resp = client.get(f"{url_base}/models", headers=headers)
                if resp.status_code >= 400:
                    # Don't cache failures
                    return []
                data = resp.json()
        except Exception:
            return []

        ids: list[str] = []
        data_list = data.get("data") if isinstance(data, dict) else None
        if isinstance(data_list, list):
            for item in data_list:
                if isinstance(item, dict):
                    model_id = item.get("id")
                    if model_id:
                        ids.append(str(model_id))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get("id"):
                    ids.append(str(item["id"]))

        # Cache success (even if empty? Don't cache empty to allow retry, but we cache non-empty or after success)
        self._models_cache = (with_time, ids)
        return list(ids)

    def invalidate_model_cache(self) -> None:
        self._models_cache = None


# ---------------------------------------------------------------------------
# Legacy alias / thin wrapper for discovery used by model_router (stateless)
# ---------------------------------------------------------------------------


def discover_opencode_go_models(
    base_url: str,
    api_key: str | None = None,
    timeout: float = 5.0,
    cfg: Mapping[str, Any] | None = None,
) -> list[str]:
    """Stateless discovery helper (for tests)."""
    client = OpenCodeGoResponsesClient(base_url=base_url, api_key=api_key or "", timeout=timeout, config=cfg)
    return client.discover_models(base_url, cfg)


# ---------------------------------------------------------------------------
# Responses-model filter + router builder (moved from tools/model_router.py)
# ---------------------------------------------------------------------------


def is_opencode_responses_model(
    model_id: str,
    raw_item: Mapping[str, Any] | None,
    cfg: Mapping[str, Any] | None = None,
) -> bool:
    """True if a discovered model is safe to route through the Responses adapter.

    The hosted catalog mixes providers/protocols.  Our Responses adapter must
    NOT blindly expose ``/chat/completions``-only or Anthropic ``/messages``-only
    models via ``/responses``.  The reliable signal (when present) is an
    explicit protocol hint in the discovery payload (e.g. ``supported_api``,
    ``endpoints``, ``capabilities`` containing ``responses``).  When no hint
    exists we conservatively allow only the known Responses family and the
    configured default.
    """
    cleaned = str(model_id or "").strip()
    if not cleaned:
        return False
    # Always allow the configured default
    default = str((cfg or {}).get("default_model") or "muse-spark-1.2-contributor")
    if cleaned == default:
        return True
    # Known Responses family
    if cleaned == "muse-spark-1.2-contributor":
        return True
    # Heuristic for spark family (future spark releases stay on Responses)
    if "muse-spark" in cleaned or "spark" in cleaned.lower():
        return True
    if raw_item is not None:
        # Look for explicit protocol metadata
        for key in ("supported_api", "api", "protocol", "endpoints", "capabilities", "supported_endpoints", "type"):
            val = raw_item.get(key)  # type: ignore[attr-defined]
            if val is None:
                continue
            text = str(val).lower() if not isinstance(val, list) else " ".join(str(v).lower() for v in val)
            if "response" in text:
                return True
        # Some catalogs nest under metadata
        meta = raw_item.get("metadata") if isinstance(raw_item.get("metadata"), Mapping) else None  # type: ignore[attr-defined]
        if isinstance(meta, Mapping):
            for key in ("supported_api", "protocol", "endpoints"):
                val = meta.get(key)
                if val is None:
                    continue
                text = str(val).lower() if not isinstance(val, list) else " ".join(str(v).lower() for v in val)
                if "response" in text:
                    return True
    return False


def build_opencode_go_router(
    opencode_config: Mapping[str, Any],
    *,
    request_timeout_seconds: float | None = None,
) -> "ModelRouter":
    """Build a router backed by the hosted OpenCode Go Responses API.

    The API key is resolved from ``api_key_env`` (default ``OPENCODE_GO_API_KEY``)
    but a missing key does NOT block router construction — the resulting
    ``OpenCodeGoResponsesClient`` will surface a clear ``API key not configured``
    error on the first ``chat`` call, matching the Ollama Cloud behaviour
    (preview succeeds, auth fails on first generation). This prevents a silent
    ``500`` on ``POST /runs`` when the operator has switched provider but not
    yet set the key.
    """
    from tools.model_router import ModelRouter

    cfg = dict(opencode_config)
    import os

    env_name = str(cfg.get("api_key_env") or "OPENCODE_GO_API_KEY").strip() or "OPENCODE_GO_API_KEY"
    api_key = (os.environ.get(env_name, "") or "").strip()
    # Do NOT raise here — defer to chat-time so run previews still succeed.
    base_url = str(cfg.get("base_url") or _DEFAULT_BASE_URL).rstrip("/")
    timeout = request_timeout_seconds
    if timeout is None and cfg.get("request_timeout_seconds") is not None:
        try:
            timeout = float(cfg["request_timeout_seconds"])
        except (TypeError, ValueError):
            timeout = None
    if timeout is None:
        timeout = 300.0

    shared = OpenCodeGoResponsesClient(
        base_url=base_url,
        api_key=api_key,
        timeout=float(timeout),
        default_model=str(cfg.get("default_model") or _DEFAULT_MODEL),
        config=cfg,
    )

    # Resolve model list: explicit -> discover (filtered) -> fallback
    configured = cfg.get("models") or []
    if configured:
        model_ids = [str(m).strip() for m in configured if str(m).strip()]
    else:
        model_ids = []
        try:
            discovered = shared.discover_models(base_url, cfg)
        except Exception:
            discovered = []
        if discovered:
            # If discovery returned ids but we have no raw metadata, filter by id heuristic
            filtered = [mid for mid in discovered if is_opencode_responses_model(mid, None, cfg)]
            if filtered:
                model_ids = filtered
            else:
                # Discovery contained only non-Responses models; fall back to default
                model_ids = []

    if not model_ids:
        default_model = str(cfg.get("default_model") or _DEFAULT_MODEL)
        model_ids = [default_model]

    # De-duplicate preserving order and ensure default present
    seen: set[str] = set()
    unique: list[str] = []
    for mid in model_ids:
        if mid not in seen:
            seen.add(mid)
            unique.append(mid)
    default_model = str(cfg.get("default_model") or _DEFAULT_MODEL)
    if default_model not in seen:
        unique.append(default_model)

    router = ModelRouter()
    for model_id in unique:
        router.register(
            model_id,
            make_model_client(
                model_id,
                alias=model_id,
                request_timeout_seconds=float(timeout) if timeout is not None else None,
                raw_client=shared,
                provider="opencode_go",
            ),
        )
    return router


class OpenCodeGoProvider(BaseProvider):
    """OpenCode Go provider adapter: hosted OpenAI Responses API.

    The reference non-Ollama provider — sees only the canonical
    ``context_window_tokens`` chat kwarg (dropped here; Responses has no
    context-window override), OpenAI-shaped tool schemas translated by
    ``_convert_tool_schemas``, and BreachPilot-format responses via
    ``_normalize_responses_output``.
    """

    id = "opencode_go"
    display_name = "OpenCode Go"
    capabilities = ProviderCapabilities(
        chat=True,
        streaming=True,
        tool_calls=True,
        embeddings=False,
        model_discovery=True,
        reasoning=True,
    )

    def is_configured(self, cfg: Mapping[str, Any]) -> bool:
        # A missing API key must NOT block router construction / previews —
        # the first chat call surfaces a clear auth error (module contract).
        return bool(cfg) and (bool(cfg.get("enabled")) or bool(cfg.get("base_url")))

    def build_router(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        request_timeout_seconds: float | None = None,
        provider_config: Mapping[str, Any] | None = None,
    ) -> "ModelRouter":
        cfg = dict(provider_config) if provider_config is not None else self.provider_config(config)
        return build_opencode_go_router(cfg, request_timeout_seconds=request_timeout_seconds)

    def build_client(
        self,
        config: Mapping[str, Any] | None = None,
        alias: str = "",
        *,
        request_timeout_seconds: float | None = None,
    ) -> "ModelClient":
        cfg = self.provider_config(config)
        import os

        env_name = str(cfg.get("api_key_env") or "OPENCODE_GO_API_KEY").strip() or "OPENCODE_GO_API_KEY"
        api_key = (os.environ.get(env_name, "") or "").strip()
        timeout = request_timeout_seconds
        if timeout is None and cfg.get("request_timeout_seconds") is not None:
            try:
                timeout = float(cfg["request_timeout_seconds"])
            except (TypeError, ValueError):
                timeout = None
        base_url = str(cfg.get("base_url") or _DEFAULT_BASE_URL).rstrip("/")
        shared = OpenCodeGoResponsesClient(
            base_url=base_url,
            api_key=api_key,
            timeout=float(timeout) if timeout is not None else float(_DEFAULT_TIMEOUT),
            default_model=str(cfg.get("default_model") or alias or _DEFAULT_MODEL),
            config=cfg,
        )
        model_id = str(alias or cfg.get("default_model") or _DEFAULT_MODEL)
        return make_model_client(
            model_id,
            alias=model_id,
            request_timeout_seconds=timeout,
            raw_client=shared,
            provider="opencode_go",
        )

    def list_models(self, config: Mapping[str, Any] | None = None) -> list[ModelInfo]:
        """Live model discovery from ``{base_url}/models``.

        Missing API key and unreachable endpoint raise
        :class:`ProviderDiscoveryError` with the registry-mode fallback
        (``opencode_go.models`` / ``default_model``); a successful probe is
        filtered to Responses-compatible models (falling back to the raw list
        when filtering removes everything). Secrets are redacted from errors.
        """
        cfg = self.provider_config(config)
        configured = [str(m).strip() for m in (cfg.get("models") or []) if str(m).strip()]
        default_model = str(cfg.get("default_model") or _DEFAULT_MODEL)
        context_window = cfg.get("context_window")
        ctx = int(context_window) if isinstance(context_window, (int, float)) else None

        def _infos(ids: list[str]) -> list[ModelInfo]:
            infos: list[ModelInfo] = []
            seen: set[str] = set()
            for model_id in ids:
                if model_id in seen:
                    continue
                seen.add(model_id)
                infos.append(
                    ModelInfo(id=model_id, label=model_id, context_window=ctx, default=(model_id == default_model))
                )
            return infos

        if configured:
            return _infos(configured)
        import os

        base_url = str(cfg.get("base_url") or _DEFAULT_BASE_URL).rstrip("/")
        env_name = str(cfg.get("api_key_env") or "OPENCODE_GO_API_KEY")
        api_key = (os.environ.get(env_name, "") or "").strip()
        if not api_key:
            raise ProviderDiscoveryError(
                f"OpenCode Go API key not set ({env_name}). Set it via secrets or env.",
                fallback_models=[default_model],
            )
        try:
            import httpx

            headers = {"Authorization": f"Bearer {api_key}", _SESSION_HEADER: _SESSION_ID}
            with httpx.Client(timeout=5.0, headers=headers) as client:
                resp = client.get(f"{base_url}/models")
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            err_text = str(exc)
            if api_key and api_key in err_text:
                err_text = err_text.replace(api_key, "[REDACTED]")
            raise ProviderDiscoveryError(
                f"OpenCode Go unreachable: {err_text}", fallback_models=[default_model]
            ) from exc
        raw_data = data.get("data") if isinstance(data, dict) else None
        if isinstance(raw_data, list):
            # Filter to Responses-compatible models when we can reliably tell
            ids = [mid for m in raw_data if isinstance(m, dict) for mid in [str(m.get("id") or "")] if mid]
            filtered = [mid for mid in ids if is_opencode_responses_model(mid, None, cfg)]
            # If filtering removed everything, fall back to raw list (at least show something)
            return _infos(filtered or ids or [default_model])
        # Fallback for non-standard shape
        return _infos(
            [str(m.get("id", "")) for m in (raw_data or []) if isinstance(m, dict) and m.get("id")] or [default_model]
        )

    def title_model(self, config: Mapping[str, Any] | None = None) -> str:
        return str(self.provider_config(config).get("default_model") or _DEFAULT_MODEL)

    def health(self, config: Mapping[str, Any] | None = None) -> ProviderHealth:
        cfg = self.provider_config(config)
        checks: list[dict[str, Any]] = []
        base_ok = bool(cfg.get("base_url"))
        checks.append(
            {
                "name": "opencode_go_endpoint",
                "ok": base_ok,
                "hint": "" if base_ok else "opencode_go.base_url is empty",
            }
        )
        import os

        env_name = str(cfg.get("api_key_env") or "OPENCODE_GO_API_KEY").strip() or "OPENCODE_GO_API_KEY"
        key_present = bool((os.environ.get(env_name, "") or "").strip())
        checks.append(
            {
                "name": "opencode_go_api_key",
                "ok": key_present,
                "hint": "" if key_present else f"${env_name} is not set — runs will fail on first generation",
            }
        )
        return ProviderHealth(checks=checks)
