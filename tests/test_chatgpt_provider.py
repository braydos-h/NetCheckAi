"""Mocked tests for the ChatGPT (openai-oauth) provider integration.

No network, no real ChatGPT account, no OAuth credentials, no live
openai-oauth process, no real Ollama. httpx and subprocess.run are faked.
These tests guard the provider seam in ``tools/model_router`` and the
adapter/manager in ``tools/providers/chatgpt_provider`` without weakening any
target/scope safety (none of that code is touched here).
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest

import tools.providers.chatgpt_provider as cg
from tools.config_manager import get_ai_provider, get_chatgpt_config
from tools.model_router import (
    DEFAULT_MODEL_REGISTRY,
    _build_model_client,
    build_model_client_for_provider,
    build_router,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], *, status: int = 200, text: str = ""):
        self._payload = payload
        self.status_code = status
        self.text = text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise cg.httpx.HTTPStatusError("boom", request=None, response=self)  # type: ignore[arg-type]

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeStreamResponse:
    def __init__(self, lines: list[str], *, status: int = 200):
        self._lines = lines
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise cg.httpx.HTTPStatusError("boom", request=None, response=self)  # type: ignore[arg-type]

    def iter_lines(self):
        for line in self._lines:
            yield line


class _FakeClient:
    """Minimal httpx.Client stand-in: post() + stream() ctx manager."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.calls: list[dict[str, Any]] = []

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def get(self, url: str, **kwargs: Any) -> Any:
        self.calls.append({"method": "GET", "url": url})
        handler = _FAKE_HTTPX.get_handler("GET", url)
        return handler(url)

    def post(self, url: str, *, json: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        self.calls.append({"method": "POST", "url": url, "json": json})
        handler = _FAKE_HTTPX.get_handler("POST", url)
        return handler(url, json or {})

    def stream(self, method: str, url: str, *, json: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        self.calls.append({"method": method, "url": url, "json": json, "stream": True})

        class _Ctx:
            def __enter__(self_) -> Any:
                handler = _FAKE_HTTPX.get_handler("STREAM", url)
                return handler(url, json or {})

            def __exit__(self_, *exc: Any) -> None:
                return None

        return _Ctx()


class _FakeHttpxModule:
    """Module-level fake for ``httpx`` inside the provider."""

    def __init__(self) -> None:
        self.Client = _FakeClient
        self.HTTPStatusError = type("HTTPStatusError", (Exception,), {})
        self._handlers: dict[tuple[str, str], Any] = {}
        self._default: Any = None

    def reset(self) -> None:
        self._handlers.clear()
        self._default = None

    def set(self, method: str, url_substr: str, handler: Any) -> None:
        self._handlers[(method, url_substr)] = handler

    def get_handler(self, method: str, url: str) -> Any:
        for (m, sub), handler in self._handlers.items():
            if m == method and sub in url:
                return handler
        if self._default is not None:
            return self._default
        raise AssertionError(f"no fake httpx handler for {method} {url}")

    def set_default(self, handler: Any) -> None:
        self._default = handler


_FAKE_HTTPX = _FakeHttpxModule()


@pytest.fixture(autouse=True)
def _reset_provider(monkeypatch):
    """Reset the singleton + fake httpx between tests."""
    monkeypatch.setattr(cg, "httpx", _FAKE_HTTPX)
    _FAKE_HTTPX.reset()
    # Fresh singleton each test.
    cg.ChatGptProxyManager._instance = None
    yield
    cg.ChatGptProxyManager._instance = None


def _chatgpt_config(**overrides: Any) -> dict[str, Any]:
    cfg = get_chatgpt_config({"models": {"provider": "chatgpt"}})
    cfg.update(overrides)
    return cfg


def _json_response_lines(chunks: list[dict[str, Any]], *, done: bool = True) -> list[str]:
    lines = [f"data: {json.dumps(c)}" for c in chunks]
    if done:
        lines.append("data: [DONE]")
    return lines


# ---------------------------------------------------------------------------
# 1-3. Config defaults + ollama routing unchanged
# ---------------------------------------------------------------------------


def test_default_config_selects_ollama():
    assert get_ai_provider({}) == "ollama"
    assert get_ai_provider({"models": {}}) == "ollama"
    assert get_ai_provider({"models": {"provider": "ollama"}}) == "ollama"


def test_chatgpt_selectable():
    assert get_ai_provider({"models": {"provider": "chatgpt"}}) == "chatgpt"
    # case-insensitive
    assert get_ai_provider({"models": {"provider": "ChatGPT"}}) == "chatgpt"


def test_ollama_routing_unchanged(monkeypatch):
    """build_router(provider=ollama) is byte-identical to the old path."""
    import tools.model_router as mr

    constructed: list[str] = []

    class _Ollama:
        def __init__(self, host=None, **kw):
            constructed.append(host)
            self.host = host

        def chat(self, *a, **k):
            return {"message": {"content": "ollama"}}

    monkeypatch.setattr(mr, "OllamaClient", _Ollama)
    # Clear raw-client cache so the monkeypatched class is not shadowed by a
    # prior cached real client (ponytail: cache key includes client_cls).
    from tools.providers.ollama_provider import _RAW_CLIENT_CACHE, _RAW_CLIENT_CACHE_LOCK

    with _RAW_CLIENT_CACHE_LOCK:
        _RAW_CLIENT_CACHE.clear()
    # Clear any lingering constructed entries from a prior leaked background
    # task (test_api_run_sandbox's prep_task may still be constructing a client
    # with http://localhost:11434 after the previous test's portal was torn
    # down with a 2 s join timeout). We only care that this build_router call
    # constructs exactly one https://api.ollama.com client.
    constructed.clear()
    router = build_router(DEFAULT_MODEL_REGISTRY, host="https://api.ollama.com")
    client = router.get_client("glm")
    assert client.model_id == "glm-5.2:cloud"
    resp = client.chat(messages=[{"role": "user", "content": "hi"}])
    assert resp["message"]["content"] == "ollama"
    # Raw client is cached per (host, timeout, client_cls) — one construction
    # for all aliases sharing the same host (ponytail: ~600 ms saved per alias).
    assert constructed.count("https://api.ollama.com") == 1
    assert len(router.clients()) == len(DEFAULT_MODEL_REGISTRY)


# ---------------------------------------------------------------------------
# 4. ChatGPT discovery + /v1/models failure fallback
# ---------------------------------------------------------------------------


def test_chatgpt_discovery_from_models_endpoint():
    cfg = _chatgpt_config(auto_start=False)
    manager = cg.ChatGptProxyManager.get()
    # Proxy already up (health ok) so no spawn.
    _FAKE_HTTPX.set("GET", "/health", lambda url: _FakeResponse({"ok": True}))
    _FAKE_HTTPX.set("GET", "/models", lambda url: _FakeResponse({"data": [{"id": "gpt-5.2"}, {"id": "gpt-5.2-mini"}]}))
    models = manager.discover_models("http://127.0.0.1:10531/v1", cfg)
    assert models == ["gpt-5.2", "gpt-5.2-mini"]


def test_chatgpt_discovery_failure_returns_empty():
    cfg = _chatgpt_config()
    manager = cg.ChatGptProxyManager.get()

    def _fail(url):
        raise cg.httpx.HTTPStatusError("nope", request=None, response=None)  # type: ignore[arg-type]

    _FAKE_HTTPX.set("GET", "/models", _fail)
    assert manager.discover_models("http://127.0.0.1:10531/v1", cfg) == []


def test_build_chatgpt_router_falls_back_to_default_model(monkeypatch):
    cfg = _chatgpt_config(models=[], default_model="gpt-5.2")
    # Force ensure_running to succeed without spawning, and discovery to fail.
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: True)
    monkeypatch.setattr(manager, "_health_ok", lambda c: True)
    monkeypatch.setattr(manager, "discover_models", lambda *a, **k: [])
    router = build_router(
        None, provider="chatgpt", chatgpt_config=cfg, config={"models": {"provider": "chatgpt"}, "chatgpt": cfg}
    )
    client = router.get_client("gpt-5.2")
    assert client.model_id == "gpt-5.2"


# ---------------------------------------------------------------------------
# 5. Non-stream normalization
# ---------------------------------------------------------------------------


def _set_nonstream(payload: dict[str, Any]):
    _FAKE_HTTPX.set("POST", "/chat/completions", lambda url, body: _FakeResponse(payload))


def test_nonstream_content_null_becomes_empty():
    _set_nonstream(
        {
            "model": "gpt-5.2",
            "choices": [{"message": {"role": "assistant", "content": None}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        }
    )
    client = cg.ChatGptProxyClient("http://127.0.0.1:10531/v1")
    resp = client.chat(model="gpt-5.2", messages=[{"role": "user", "content": "hi"}])
    assert resp["message"]["content"] == ""
    assert resp["message"]["thinking"] == ""
    assert resp["usage"]["total_tokens"] == 8


def test_nonstream_tool_calls_passed_through_with_json_string_args():
    _set_nonstream(
        {
            "model": "gpt-5.2",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "t1",
                                "type": "function",
                                "function": {"name": "run_exploit_terminal", "arguments": '{"command": "id"}'},
                            }
                        ],
                    }
                }
            ],
            "usage": {},
        }
    )
    client = cg.ChatGptProxyClient("http://127.0.0.1:10531/v1")
    resp = client.chat(model="gpt-5.2", messages=[], tools=[{"type": "function", "function": {"name": "x"}}])
    tc = resp["message"]["tool_calls"][0]
    # arguments stays a JSON string; _normalize_tool_call parses it downstream.
    assert tc["function"]["arguments"] == '{"command": "id"}'
    from tools.exploit_agent.tool_calls import _normalize_tool_call

    norm = _normalize_tool_call(tc)
    assert norm["function"]["name"] == "run_exploit_terminal"
    assert norm["function"]["arguments"] == {"command": "id"}


def test_normalize_tool_call_malformed_json_args_become_empty_dict():
    from tools.exploit_agent.tool_calls import _normalize_tool_call

    norm = _normalize_tool_call({"function": {"name": "x", "arguments": "{not json"}})
    assert norm["function"]["arguments"] == {}


def test_nonstream_drops_ollama_only_options():
    seen: list[dict[str, Any]] = []
    _FAKE_HTTPX.set(
        "POST",
        "/chat/completions",
        lambda url, body: (
            seen.append(body),
            _FakeResponse({"model": "gpt-5.2", "choices": [{"message": {"content": "ok"}}]}),
        )[1],
    )
    client = cg.ChatGptProxyClient("http://127.0.0.1:10531/v1")
    client.chat(model="gpt-5.2", messages=[], options={"num_ctx": 976000}, keep_alive="5m", format="json")
    payload = seen[0]
    assert "options" not in payload
    assert "keep_alive" not in payload
    assert "format" not in payload
    assert payload["model"] == "gpt-5.2"


# ---------------------------------------------------------------------------
# 6-7. Streaming
# ---------------------------------------------------------------------------


def test_stream_text_plus_final_usage_chunk():
    chunks = [
        {"choices": [{"delta": {"content": "Hello"}}]},
        {"choices": [{"delta": {"content": " world"}}]},
        {"choices": [], "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4}},
    ]
    _FAKE_HTTPX.set("STREAM", "/chat/completions", lambda url, body: _FakeStreamResponse(_json_response_lines(chunks)))
    client = cg.ChatGptProxyClient("http://127.0.0.1:10531/v1")
    out = list(client.chat(model="gpt-5.2", messages=[], stream=True))
    contents = [c["message"]["content"] for c in out]
    assert contents == ["Hello", " world", ""]
    assert out[-1]["usage"]["total_tokens"] == 4  # final usage chunk captured


def test_stream_tool_call_fragment_assembly():
    chunks = [
        {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "id": "t1", "type": "function", "function": {"name": "run_", "arguments": ""}}
                        ]
                    }
                }
            ]
        },
        {
            "choices": [
                {"delta": {"tool_calls": [{"index": 0, "function": {"name": "exploit", "arguments": '{"cmd":'}}]}}
            ]
        },
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": '"id"}'}}]}}]},
        {"choices": [], "usage": {"total_tokens": 9}},
    ]
    _FAKE_HTTPX.set("STREAM", "/chat/completions", lambda url, body: _FakeStreamResponse(_json_response_lines(chunks)))
    client = cg.ChatGptProxyClient("http://127.0.0.1:10531/v1")
    out = list(client.chat(model="gpt-5.2", messages=[], stream=True))
    final = out[-1]
    assembled = final["message"]["tool_calls"]
    assert assembled[0]["function"]["name"] == "run_exploit"
    assert assembled[0]["function"]["arguments"] == '{"cmd":"id"}'
    assert final["usage"]["total_tokens"] == 9


def test_stream_stops_on_done_and_ignores_keepalive():
    lines = [": keepalive", 'data: {"choices":[{"delta":{"content":"x"}}]}', "data: [DONE]"]
    _FAKE_HTTPX.set("STREAM", "/chat/completions", lambda url, body: _FakeStreamResponse(lines))
    client = cg.ChatGptProxyClient("http://127.0.0.1:10531/v1")
    out = list(client.chat(model="gpt-5.2", messages=[], stream=True))
    assert [c["message"]["content"] for c in out] == ["x", ""]


# ---------------------------------------------------------------------------
# 8. httpx errors are retryable
# ---------------------------------------------------------------------------


def test_httpx_error_is_retryable():
    from tools.exploit_agent.model_client import _is_retryable_error

    class _HttpxErr(Exception):
        pass

    # Simulate an httpx-namespace exception.
    _HttpxErr.__module__ = "httpx._exceptions"
    assert _is_retryable_error(_HttpxErr()) is True


def test_chatgpt_client_raises_on_http_error():
    def _fail(url, body):
        raise cg.httpx.HTTPStatusError("500", request=None, response=None)  # type: ignore[arg-type]

    _FAKE_HTTPX.set("POST", "/chat/completions", _fail)
    client = cg.ChatGptProxyClient("http://127.0.0.1:10531/v1")
    with pytest.raises(Exception):
        client.chat(model="gpt-5.2", messages=[])


# ---------------------------------------------------------------------------
# 9. is_authenticated (bool only, never reads contents)
# ---------------------------------------------------------------------------


def test_is_authenticated_true_when_auth_file_exists(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p.endswith("auth.json"))
    manager = cg.ChatGptProxyManager.get()
    assert manager.is_authenticated(_chatgpt_config()) is True


def test_is_authenticated_false_when_absent(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    manager = cg.ChatGptProxyManager.get()
    assert manager.is_authenticated(_chatgpt_config()) is False


def test_is_authenticated_never_reads_file_contents(monkeypatch):
    # If it tried to open/read the file, this open() would raise.
    def _exists(p):
        return p.endswith("auth.json")

    monkeypatch.setattr(os.path, "exists", _exists)
    import builtins

    def _no_open(*a, **k):
        raise AssertionError("is_authenticated must not open the auth file")

    monkeypatch.setattr(builtins, "open", _no_open)
    manager = cg.ChatGptProxyManager.get()
    assert manager.is_authenticated(_chatgpt_config()) is True


# ---------------------------------------------------------------------------
# 10-12, 14. Proxy lifecycle
# ---------------------------------------------------------------------------


def _patch_runtime(monkeypatch, runtime="bun"):
    monkeypatch.setattr(cg.shutil, "which", lambda name: "/usr/bin/" + name if name == runtime else None)
    # Path.exists() uses os.stat (not os.path.exists), so patch the Path class
    # so the vendored-cli entry check passes without a real checkout on disk.
    monkeypatch.setattr(cg.Path, "exists", lambda self: True)


def test_proxy_already_running_no_spawn(monkeypatch):
    _patch_runtime(monkeypatch)
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: True)
    monkeypatch.setattr(manager, "_health_ok", lambda c: True)
    spawns: list[Any] = []
    monkeypatch.setattr(cg.subprocess, "run", lambda **k: spawns.append(k) or _Completed(0))
    res = manager.ensure_running(_chatgpt_config())
    assert res["ok"] is True
    assert manager._we_started is False
    assert spawns == []  # did not spawn


def test_proxy_auto_start_uses_detach_and_marks_we_started(monkeypatch):
    _patch_runtime(monkeypatch)
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: True)
    health = {"up": False}
    monkeypatch.setattr(manager, "_health_ok", lambda c: health["up"])
    seen: list[dict[str, Any]] = []

    def _run(**kwargs):
        seen.append(kwargs)
        health["up"] = True  # serve --detach brings it up
        return _Completed(0)

    monkeypatch.setattr(cg.subprocess, "run", _run)
    res = manager.ensure_running(_chatgpt_config())
    assert res["ok"] is True
    assert manager._we_started is True
    args = seen[0]["args"]
    assert args[1].endswith("cli.ts")  # entry path
    assert "serve" in args
    assert "--detach" in args
    assert "--host" in args and "127.0.0.1" in args
    assert "--port" in args and "10531" in args
    assert kwargs_shell_false(seen[0])


def test_not_authenticated_no_spawn(monkeypatch):
    _patch_runtime(monkeypatch)
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: False)
    monkeypatch.setattr(manager, "_health_ok", lambda c: False)
    spawns: list[Any] = []
    monkeypatch.setattr(cg.subprocess, "run", lambda **k: spawns.append(k) or _Completed(0))
    res = manager.ensure_running(_chatgpt_config())
    assert res["ok"] is False
    assert res["reason"] == "not_authenticated"
    assert spawns == []


def test_no_duplicate_starts(monkeypatch):
    _patch_runtime(monkeypatch)
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: True)
    monkeypatch.setattr(manager, "_health_ok", lambda c: True)
    count = {"n": 0}
    monkeypatch.setattr(cg.subprocess, "run", lambda **k: (count.__setitem__("n", count["n"] + 1), _Completed(0))[1])
    manager.ensure_running(_chatgpt_config())
    manager.ensure_running(_chatgpt_config())
    assert count["n"] == 0  # never spawned because already healthy


# ---------------------------------------------------------------------------
# 13. shutdown only when we started
# ---------------------------------------------------------------------------


def test_shutdown_calls_stop_only_when_we_started(monkeypatch):
    _patch_runtime(monkeypatch)
    manager = cg.ChatGptProxyManager.get()
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(cg.subprocess, "run", lambda **k: seen.append(k) or _Completed(0))
    # Not started by us -> shutdown is a no-op.
    manager._we_started = False
    manager._runtime = ("/usr/bin/bun", "/repo/cli.ts")
    manager.shutdown(_chatgpt_config())
    assert seen == []
    # Started by us -> stop is invoked.
    manager._we_started = True
    manager.shutdown(_chatgpt_config())
    assert seen and "stop" in seen[0]["args"]
    assert manager._we_started is False


# ---------------------------------------------------------------------------
# 15-17. login + paths-with-spaces + Windows creationflags
# ---------------------------------------------------------------------------


def test_run_login_invokes_cli_and_returns_url(monkeypatch):
    _patch_runtime(monkeypatch)
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: False)

    def _run(**kwargs):
        return _Completed(0, stdout="OpenAI OAuth login URL: https://chat.openai.com/auth?flow=abc\n")

    monkeypatch.setattr(cg.subprocess, "run", _run)
    res = manager.run_login(_chatgpt_config())
    assert res["ok"] is True
    assert res["url"].startswith("https://chat.openai.com/auth")


def test_run_login_refuses_when_already_authenticated(monkeypatch):
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: True)
    res = manager.run_login(_chatgpt_config())
    assert res["ok"] is False
    assert res["reason"] == "already_authenticated"


def test_paths_with_spaces_use_list_args_no_shell(monkeypatch):
    _patch_runtime(monkeypatch)
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: True)
    health = {"up": False}
    monkeypatch.setattr(manager, "_health_ok", lambda c: health["up"])
    cfg = _chatgpt_config(local_repo="./openai oauth with spaces")
    seen: list[dict[str, Any]] = []

    def _run(**kwargs):
        seen.append(kwargs)
        health["up"] = True
        return _Completed(0)

    monkeypatch.setattr(cg.subprocess, "run", _run)
    res = manager.ensure_running(cfg)
    assert res["ok"] is True
    assert " " in seen[0]["cwd"]
    assert isinstance(seen[0]["args"], list)
    assert seen[0].get("shell") is None
    assert kwargs_shell_false(seen[0])


def test_windows_creationflags_present(monkeypatch):
    _patch_runtime(monkeypatch)
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: True)
    health = {"up": False}
    monkeypatch.setattr(manager, "_health_ok", lambda c: health["up"])
    monkeypatch.setattr(cg.os, "name", "nt")
    monkeypatch.setattr(cg.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    seen: list[dict[str, Any]] = []

    def _run(**kwargs):
        seen.append(kwargs)
        health["up"] = True
        return _Completed(0)

    monkeypatch.setattr(cg.subprocess, "run", _run)
    manager.ensure_running(_chatgpt_config())
    assert seen[0].get("creationflags") == 0x08000000


# ---------------------------------------------------------------------------
# 18. Telemetry provider field
# ---------------------------------------------------------------------------


def test_telemetry_records_provider_field(tmp_path, monkeypatch):
    import tools.model_telemetry as mt

    monkeypatch.setenv("RESEARCH_WORKSPACE", str(tmp_path))
    rec = mt.build_usage_record(
        alias="gpt-5.2",
        model_id="gpt-5.2",
        response={"usage": {"total_tokens": 7}},
        messages=[],
        stream=False,
        started_at="s",
        ended_at="e",
        wall_duration_seconds=1.0,
        context_window_tokens=128000,
        source="test",
        provider="chatgpt",
    )
    assert rec["provider"] == "chatgpt"
    assert rec["total_tokens"] == 7
    # ollama default
    rec2 = mt.build_usage_record(
        alias="glm",
        model_id="glm-5.2:cloud",
        response={"usage": {}},
        messages=[],
        stream=False,
        started_at="s",
        ended_at="e",
        wall_duration_seconds=1.0,
        context_window_tokens=976000,
        source="test",
    )
    assert rec2["provider"] == "ollama"
    # read_usage_records filters by alias and includes provider
    mt.record_usage(rec, tmp_path)
    records = mt.read_usage_records(tmp_path, alias="gpt-5.2")
    assert records and records[0]["provider"] == "chatgpt"


def test_chatgpt_model_client_threads_provider(monkeypatch):
    """A ModelClient built via the chatgpt seam records provider=chatgpt."""
    import tools.model_telemetry as mt

    recorded: dict[str, Any] = {}

    def _fake_record(**kwargs):
        recorded.update(kwargs)
        return {}

    monkeypatch.setattr(mt, "record_model_usage", _fake_record)
    import tools.model_router as mr

    monkeypatch.setattr(mr, "record_model_usage", _fake_record)
    _set_nonstream({"model": "gpt-5.2", "choices": [{"message": {"content": "hi"}}], "usage": {"total_tokens": 3}})
    raw = cg.ChatGptProxyClient("http://127.0.0.1:10531/v1")
    client = _build_model_client("gpt-5.2", alias="gpt-5.2", raw_client=raw, provider="chatgpt")
    client.chat(messages=[{"role": "user", "content": "hi"}])
    assert recorded.get("provider") == "chatgpt"


# ---------------------------------------------------------------------------
# 19. Session titler chatgpt path
# ---------------------------------------------------------------------------


def test_session_titler_chatgpt_drops_options_and_returns_title(monkeypatch):
    _set_nonstream({"model": "gpt-5.2", "choices": [{"message": {"content": "Recon scan of 10.0.0.50"}}], "usage": {}})

    # Route the titler through the chatgpt seam by faking build_model_client_for_provider
    # on the module session_titler imports it from.
    import tools.api.session_titler as st
    import tools.model_router as mr

    raw = cg.ChatGptProxyClient("http://127.0.0.1:10531/v1")
    mc = _build_model_client("gpt-5.2", alias="gpt-5.2", raw_client=raw, provider="chatgpt")
    monkeypatch.setattr(mr, "build_model_client_for_provider", lambda *a, **k: mc)
    config = {"models": {"provider": "chatgpt"}, "chatgpt": {"default_model": "gpt-5.2"}}
    title = st.generate_session_title_sync(
        {"target_ip": "10.0.0.50", "mode": "recon"},
        {"target": "10.0.0.50"},
        config=config,
    )
    assert title == "Recon scan of 10.0.0.50"


def test_session_titler_chatgpt_failure_returns_empty(monkeypatch):
    import tools.api.session_titler as st
    import tools.model_router as mr

    def _boom(*a, **k):
        raise RuntimeError("proxy down")

    monkeypatch.setattr(mr, "build_model_client_for_provider", _boom)
    config = {"models": {"provider": "chatgpt"}, "chatgpt": {"default_model": "gpt-5.2"}}
    title = st.generate_session_title_sync({"target_ip": "1.2.3.4"}, {"target": "1.2.3.4"}, config=config)
    assert title == ""


def test_session_titler_ollama_path_unchanged(monkeypatch):
    """Ollama titler still uses module-level OllamaClient (test guard)."""
    import tools.api.session_titler as st

    class _Ollama:
        def __init__(self, host=None, timeout=None):
            pass

        def chat(self, *a, **k):
            return {"message": {"content": "SMB exploit attempt"}}

    monkeypatch.setattr(st, "OllamaClient", _Ollama)
    title = st.generate_session_title_sync({"target_ip": "1.2.3.4"}, {"target": "1.2.3.4"})
    assert title == "SMB exploit attempt"


# ---------------------------------------------------------------------------
# 20. build_model_client_for_provider
# ---------------------------------------------------------------------------


def test_build_model_client_for_provider_ollama(monkeypatch):
    import tools.model_router as mr

    class _Ollama:
        def __init__(self, host=None, **kw):
            self.host = host

        def chat(self, *a, **k):
            return {"message": {"content": "o"}}

    monkeypatch.setattr(mr, "OllamaClient", _Ollama)
    client = build_model_client_for_provider(
        {"ollama": {"host": "https://api.ollama.com"}, "models": {"provider": "ollama"}},
        "glm",
    )
    assert client.model_id == "glm-5.2:cloud"
    assert client.chat(messages=[])["message"]["content"] == "o"


def test_build_model_client_for_provider_chatgpt(monkeypatch):
    _set_nonstream({"model": "gpt-5.2", "choices": [{"message": {"content": "g"}}], "usage": {}})
    manager = cg.ChatGptProxyManager.get()
    monkeypatch.setattr(manager, "is_authenticated", lambda c: True)
    monkeypatch.setattr(manager, "_health_ok", lambda c: True)
    client = build_model_client_for_provider(
        {"models": {"provider": "chatgpt"}, "chatgpt": {"default_model": "gpt-5.2"}},
        "gpt-5.2",
    )
    assert client.model_id == "gpt-5.2"
    assert client.chat(messages=[])["message"]["content"] == "g"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _Completed:
    def __init__(self, returncode: int, *, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def kwargs_shell_false(kwargs: dict[str, Any]) -> bool:
    return kwargs.get("shell") is None and isinstance(kwargs.get("args"), list)
