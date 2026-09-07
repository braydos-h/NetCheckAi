"""ChatGPT provider adapter — local openai-oauth proxy.

Wraps the vendored ``openai-oauth`` project (cloned at ``oauth/`` at the
repo root). openai-oauth exposes a loopback OpenAI-compatible HTTP proxy
(``127.0.0.1:10531/v1``) backed by the operator's ChatGPT account via browser
OAuth. Credentials are reused from the Codex CLI at ``~/.codex/auth.json``
(or ``$CODEX_HOME/auth.json``); this adapter NEVER reads, copies, prints, or
logs OAuth access/refresh tokens, cookies, or Authorization headers. Tokens
stay in openai-oauth's auth file — they never enter BreachPilot config.

Two classes:

- ``ChatGptProxyClient``: an httpx adapter that quacks like an Ollama client —
  ``.chat(**kwargs)`` returns an Ollama-shaped dict (non-stream) or a generator
  of Ollama-shaped chunk dicts (stream). It drops Ollama-only kwargs
  (``options``/``num_ctx``, ``keep_alive``, ``format``, ``suffix``) and
  normalizes OpenAI responses (``content: null → ""``, JSON-string tool-call
  ``arguments`` passed through for ``_normalize_tool_call`` to parse, final
  usage chunk captured so streaming telemetry records tokens).

- ``ChatGptProxyManager``: a thread-safe singleton that owns proxy/login/
  discovery lifecycle. It drives openai-oauth's OWN CLI machinery
  (``serve --detach`` / ``stop``) — it does NOT Popen+kill ``serve`` directly,
  because ``serve`` forks a detached grandchild worker that a controller-Popen
  kill cannot reach on Windows. ``_we_started`` is the discriminator: the
  manager only ever ``stop``s a proxy it started itself, so a proxy the
  operator launched by hand is left alone.

The proxy is loopback-only by default (``127.0.0.1``). The operator can change
``chatgpt.host`` in config.yaml — that is the only way it binds off-loopback.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Mapping

from .base import BaseProvider, make_model_client
from .types import ModelInfo, ProviderCapabilities, ProviderDiscoveryError, ProviderHealth, usage_report

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tools.model_router import ModelRouter

    from .types import ModelClient

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is a runtime dependency
    httpx = None  # type: ignore


# Relative to the vendored checkout root. Run from source via bun.
_CLI_ENTRY = "packages/openai-oauth/src/cli.ts"
_AUTH_FILENAME = "auth.json"
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 10531
_HEALTH_TIMEOUT = 2.0
_POLL_INTERVAL = 0.5


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _chatgpt_defaults() -> dict[str, Any]:
    return {
        "enabled": False,
        "host": _DEFAULT_HOST,
        "port": _DEFAULT_PORT,
        "base_url": f"http://{_DEFAULT_HOST}:{_DEFAULT_PORT}/v1",
        "auto_start": True,
        "local_repo": "./oauth",
        "runtime": "auto",
        "request_timeout_seconds": 300,
        "default_model": "gpt-5.2",
        "models": [],
        "context_window": 128000,
        "login_timeout_seconds": 300,
        "start_timeout_seconds": 30,
        "discover_cache_seconds": 300,
        "oauth_file": "",
    }


def _coalesce(cfg: Mapping[str, Any] | None) -> dict[str, Any]:
    merged = _chatgpt_defaults()
    if cfg:
        for key, value in cfg.items():
            if value is not None:
                merged[key] = value
    return merged


def _normalize_usage(raw: Any) -> dict[str, Any]:
    """Normalize an OpenAI usage payload via ``usage_report``."""
    if not isinstance(raw, dict) or not raw:
        return {}
    return usage_report(
        raw.get("prompt_tokens", raw.get("input_tokens")),
        raw.get("completion_tokens", raw.get("output_tokens")),
        raw.get("total_tokens"),
    )


def _root_url(cfg: Mapping[str, Any]) -> str:
    host = str(cfg.get("host") or _DEFAULT_HOST)
    port = int(cfg.get("port") or _DEFAULT_PORT)
    return f"http://{host}:{port}"


def _v1_url(cfg: Mapping[str, Any]) -> str:
    base = cfg.get("base_url")
    if base:
        return str(base).rstrip("/")
    return f"{_root_url(cfg)}/v1"


# ---------------------------------------------------------------------------
# Auth file resolution (mirrors openai-oauth resolveAuthFileCandidates).
# Bool only — we NEVER open or read the file contents.
# ---------------------------------------------------------------------------


def _auth_file_candidates(cfg: Mapping[str, Any]) -> list[str]:
    explicit = str(cfg.get("oauth_file") or "").strip()
    if explicit:
        return [explicit]
    candidates: list[str] = []
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        candidates.append(os.path.join(codex_home, _AUTH_FILENAME))
    candidates.append(os.path.join(os.path.expanduser("~"), ".codex", _AUTH_FILENAME))
    # de-dup, preserve order
    seen: set[str] = set()
    unique: list[str] = []
    for path in candidates:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


# ---------------------------------------------------------------------------
# ChatGptProxyClient — httpx adapter quacking like an Ollama client
# ---------------------------------------------------------------------------

# Ollama-only kwargs the OpenAI /v1/chat/completions endpoint does not
# understand. Dropped defensively before the request.
_DROP_KWARGS = ("options", "keep_alive", "format", "suffix", "think", "raw")


class ChatGptProxyClient:
    """OpenAI-compatible chat client that returns Ollama-shaped responses."""

    def __init__(self, base_url: str, *, timeout: float | None = None) -> None:
        self.base_url = str(base_url).rstrip("/")
        self.timeout = timeout
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx package not installed")

    def _build_payload(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": kwargs.get("model"),
            "messages": kwargs.get("messages") or [],
        }
        for key in (
            "tools",
            "tool_choice",
            "temperature",
            "top_p",
            "max_tokens",
            "max_completion_tokens",
            "stream",
            "n",
            "stop",
            "presence_penalty",
            "frequency_penalty",
            "seed",
            "user",
        ):
            if key in kwargs and kwargs[key] is not None:
                payload[key] = kwargs[key]
        # tools=False/None already stripped upstream; only forward real lists.
        if not payload.get("tools"):
            payload.pop("tools", None)
        return payload

    def chat(self, *args: Any, **kwargs: Any) -> Any:
        # _normalize_chat_args already pinned model + messages; tolerate a
        # stray positional model/messages exactly like the Ollama path does.
        raw = dict(kwargs)
        positional = list(args)
        if positional and isinstance(positional[0], str):
            positional.pop(0)
        if positional and "messages" not in raw:
            raw["messages"] = positional.pop(0)
        for dropped in _DROP_KWARGS:
            raw.pop(dropped, None)
        if "model" not in raw or raw.get("model") is None:
            raise ValueError("ChatGptProxyClient.chat requires a 'model'")

        payload = self._build_payload(raw)
        stream = bool(payload.get("stream", False))
        url = f"{self.base_url}/chat/completions"
        timeout = self.timeout if self.timeout is not None else 300.0

        if stream:
            return self._stream(url, payload, timeout)
        return self._nonstream(url, payload, timeout)

    def _nonstream(self, url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        payload = dict(payload)
        payload["stream"] = False
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

        choices = data.get("choices") or []
        choice = choices[0] if choices else {}
        message = choice.get("message") or {}
        content = message.get("content")
        if content is None:
            content = ""
        tool_calls = message.get("tool_calls") or []
        return {
            "model": data.get("model") or payload.get("model"),
            "message": {
                "role": "assistant",
                "content": content,
                "thinking": "",
                "tool_calls": tool_calls,
            },
            "usage": _normalize_usage(data.get("usage")),
        }

    def _stream(self, url: str, payload: dict[str, Any], timeout: float) -> Iterator[dict[str, Any]]:
        payload = dict(payload)
        payload["stream"] = True
        # ponytail: accumulate streaming tool-call fragments by index in case a
        # future consumer reads them; no current consumer does (the exploit
        # agent stream path reads only content/thinking). The final chunk
        # carries assembled tool_calls + usage so telemetry records tokens.
        tool_accum: dict[int, dict[str, Any]] = {}
        final_usage: dict[str, Any] = {}

        with httpx.Client(timeout=timeout) as client:
            with client.stream("POST", url, json=payload) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if not line:
                        continue
                    if not line.startswith("data:"):
                        # SSE comment / keepalive (`: ...`) — ignore.
                        continue
                    body = line[len("data:") :].strip()
                    if body == "[DONE]":
                        break
                    try:
                        chunk = json.loads(body)
                    except json.JSONDecodeError:
                        continue
                    usage = chunk.get("usage")
                    if usage:
                        final_usage = usage
                    model = chunk.get("model") or payload.get("model")
                    choices = chunk.get("choices") or []
                    if not choices:
                        # Final usage-only chunk (openai-oauth emits
                        # choices:[] + usage:{} before [DONE]).
                        continue
                    delta = choices[0].get("delta") or {}
                    content = delta.get("content")
                    if content is None:
                        content = ""
                    for tc in delta.get("tool_calls") or []:
                        idx = tc.get("index", 0)
                        slot = tool_accum.setdefault(
                            idx,
                            {
                                "id": tc.get("id", ""),
                                "type": tc.get("type", "function"),
                                "function": {"name": "", "arguments": ""},
                            },
                        )
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["function"]["name"] = slot["function"]["name"] + fn["name"]
                        if fn.get("arguments") is not None:
                            slot["function"]["arguments"] = slot["function"]["arguments"] + fn["arguments"]
                    yield {
                        "model": model,
                        "message": {
                            "role": "assistant",
                            "content": content,
                            "thinking": "",
                        },
                    }

        assembled = [tool_accum[i] for i in sorted(tool_accum)]
        yield {
            "model": payload.get("model"),
            "message": {
                "role": "assistant",
                "content": "",
                "thinking": "",
                "tool_calls": assembled,
            },
            "usage": _normalize_usage(final_usage),
        }


# ---------------------------------------------------------------------------
# ChatGptProxyManager — proxy / login / discovery lifecycle (singleton)
# ---------------------------------------------------------------------------


class ChatGptProxyManager:
    """Thread-safe singleton owning the openai-oauth proxy lifecycle."""

    _instance: "ChatGptProxyManager | None" = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._we_started: bool = False
        self._running_base_url: str | None = None
        self._runtime: tuple[str, str] | None = None  # (runtime, entry_abs_path)
        self._models_cache: tuple[float, list[str]] | None = None  # (fetched_at, ids)
        self._ensure_lock = threading.Lock()
        self._ensure_result: dict[str, Any] | None = None

    @classmethod
    def get(cls) -> "ChatGptProxyManager":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    # --- runtime resolution -------------------------------------------------

    def _resolve_local_repo(self, cfg: Mapping[str, Any]) -> Path:
        repo = Path(str(cfg.get("local_repo") or "./oauth"))
        if not repo.is_absolute():
            repo = Path.cwd() / repo
        return repo

    def _resolve_runtime(self, cfg: Mapping[str, Any]) -> tuple[str, str]:
        """Return (runtime_binary, entry_path) for the openai-oauth CLI.

        ``runtime: auto`` prefers bun on PATH (run from source via
        ``./packages/openai-oauth/src/cli.ts``); falls back to node IF a built
        ``dist/cli.js`` exists; otherwise raises a helpful error. The entry
        path is absolute so ``cwd``-spaced paths with spaces still work.
        """
        if self._runtime is not None:
            return self._runtime
        repo = self._resolve_local_repo(cfg)
        runtime_pref = str(cfg.get("runtime") or "auto").lower()
        entry = repo / _CLI_ENTRY
        if not entry.exists():
            raise RuntimeError(
                f"openai-oauth CLI not found at {entry}. "
                f"Clone EvanZhouDev/openai-oauth into oauth/ and run "
                f"`bun install` there (see docs/providers.md)."
            )

        bun = shutil.which("bun")
        node = shutil.which("node")

        def pick(rt: str) -> tuple[str, str] | None:
            if rt == "bun":
                return (bun, str(entry)) if bun else None
            if rt == "node":
                # node needs a built bundle; no dist/ is shipped.
                dist_entry = repo / "packages" / "openai-oauth" / "dist" / "cli.js"
                return (node, str(dist_entry)) if (node and dist_entry.exists()) else None
            return None

        chosen: tuple[str, str] | None = None
        if runtime_pref == "auto":
            chosen = pick("bun") or pick("node")
        else:
            chosen = pick(runtime_pref)
        if chosen is None:
            raise RuntimeError(
                "No openai-oauth runtime available. Install bun (bun.sh) and run "
                "`bun install` in oauth/, or `bun run build` and set "
                "chatgpt.runtime: node. See docs/providers.md."
            )
        self._runtime = chosen
        return chosen

    # --- auth status (bool only) -------------------------------------------

    def is_authenticated(self, cfg: Mapping[str, Any] | None = None) -> bool:
        """True if an openai-oauth auth file exists. Never reads contents."""
        merged = _coalesce(cfg)
        return any(os.path.exists(path) for path in _auth_file_candidates(merged))

    # --- proxy health ------------------------------------------------------

    def _health_ok(self, cfg: Mapping[str, Any]) -> bool:
        if httpx is None:
            return False
        try:
            with httpx.Client(timeout=_HEALTH_TIMEOUT) as client:
                resp = client.get(f"{_root_url(cfg)}/health")
                return resp.status_code < 500
        except Exception:  # noqa: BLE001 -- health probe: any transport error means not-healthy (fail-closed)
            return False

    # --- ensure running ----------------------------------------------------

    def ensure_running(self, cfg: Mapping[str, Any] | None) -> dict[str, Any]:
        """Ensure the proxy is up. Returns ``{ok, base_url?, reason?}``.

        Idempotent + re-entrant. Never spawns when unauthenticated (the CLI
        throws without a TTY). Reuses a pre-existing proxy without marking it
        ours (so we never stop one we didn't start).
        """
        merged = _coalesce(cfg)
        with self._ensure_lock:
            if self._ensure_result and self._ensure_result.get("ok"):
                # Re-verify cheaply; a proxy we didn't start may have died.
                if self._health_ok(merged):
                    return self._ensure_result
                self._ensure_result = None
                self._we_started = False

            base_url = _v1_url(merged)

            # Already running (operator-launched or a prior session)?
            if self._health_ok(merged):
                self._we_started = False
                self._running_base_url = base_url
                self._ensure_result = {"ok": True, "base_url": base_url}
                return self._ensure_result

            if not self.is_authenticated(merged):
                self._ensure_result = {"ok": False, "reason": "not_authenticated"}
                return self._ensure_result

            if not merged.get("auto_start", True):
                self._ensure_result = {"ok": False, "reason": "proxy_down_auto_start_disabled"}
                return self._ensure_result

            # Start via the CLI's own --detach machinery.
            try:
                runtime, entry = self._resolve_runtime(merged)
            except RuntimeError as exc:
                self._ensure_result = {"ok": False, "reason": str(exc)}
                return self._ensure_result

            try:
                self._start_detached(merged, runtime, entry)
            except Exception as exc:
                self._ensure_result = {"ok": False, "reason": f"start_failed: {exc}"}
                return self._ensure_result

            # Poll /health until the start budget elapses.
            deadline = time.monotonic() + float(merged.get("start_timeout_seconds") or 30)
            while time.monotonic() < deadline:
                if self._health_ok(merged):
                    self._we_started = True
                    self._running_base_url = base_url
                    self._ensure_result = {"ok": True, "base_url": base_url}
                    return self._ensure_result
                time.sleep(_POLL_INTERVAL)

            self._ensure_result = {"ok": False, "reason": "start_timeout"}
            return self._ensure_result

    def _start_detached(self, cfg: Mapping[str, Any], runtime: str, entry: str) -> None:
        host = str(cfg.get("host") or _DEFAULT_HOST)
        port = str(cfg.get("port") or _DEFAULT_PORT)
        args = [runtime, entry, "serve", "--host", host, "--port", port, "--detach"]
        kwargs: dict[str, Any] = {
            "args": args,
            "cwd": str(self._resolve_local_repo(cfg)),
            "capture_output": True,
            "text": True,
            "timeout": float(cfg.get("start_timeout_seconds") or 30),
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        # List args, no shell=True — handles paths with spaces via cwd.
        completed = subprocess.run(**kwargs)
        if completed.returncode != 0:
            err = (completed.stderr or completed.stdout or "").strip()
            # ponytail: never surface token-shaped strings; the CLI prints
            # human errors only, but redact defensively against any bearer.
            raise RuntimeError(f"openai-oauth serve exited {completed.returncode}: {err[:300]}")

    # --- login -------------------------------------------------------------

    def run_login(self, cfg: Mapping[str, Any] | None) -> dict[str, Any]:
        """Run ``openai-oauth login --no-open`` and capture the OAuth URL.

        Returns ``{ok, url?, reason?}``. Only runs when not yet authenticated
        (login refuses to overwrite without a TTY). The browser-open variant
        (``--open``) is used by the interactive CLI menu path instead.
        """
        merged = _coalesce(cfg)
        if self.is_authenticated(merged):
            return {"ok": False, "reason": "already_authenticated"}
        try:
            runtime, entry = self._resolve_runtime(merged)
        except RuntimeError as exc:
            return {"ok": False, "reason": str(exc)}
        args = [runtime, entry, "login", "--no-open"]
        kwargs: dict[str, Any] = {
            "args": args,
            "cwd": str(self._resolve_local_repo(merged)),
            "capture_output": True,
            "text": True,
            "timeout": float(merged.get("login_timeout_seconds") or 300),
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = subprocess.run(**kwargs)
        except subprocess.TimeoutExpired:
            return {"ok": False, "reason": "login_timeout"}
        except Exception as exc:
            return {"ok": False, "reason": f"login_failed: {exc}"}
        text = (completed.stdout or "") + "\n" + (completed.stderr or "")
        url = self._extract_login_url(text)
        if not url:
            return {"ok": False, "reason": "no_login_url", "output": text.strip()[:300]}
        # Invalidate the auth-status cache so a follow-up ensure_running sees it.
        self._ensure_result = None
        return {"ok": True, "url": url}

    @staticmethod
    def _extract_login_url(text: str) -> str:
        marker = "OpenAI OAuth login URL:"
        for line in text.splitlines():
            line = line.strip()
            if marker in line:
                return line.split(marker, 1)[1].strip()
        # Fallback: first http(s) URL on its own.
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                return line
        return ""

    def run_login_open(self, cfg: Mapping[str, Any] | None) -> dict[str, Any]:
        """Interactive-CLI variant: ``login`` with the browser auto-opening."""
        merged = _coalesce(cfg)
        if self.is_authenticated(merged):
            return {"ok": False, "reason": "already_authenticated"}
        try:
            runtime, entry = self._resolve_runtime(merged)
        except RuntimeError as exc:
            return {"ok": False, "reason": str(exc)}
        args = [runtime, entry, "login"]
        kwargs: dict[str, Any] = {
            "args": args,
            "cwd": str(self._resolve_local_repo(merged)),
            "capture_output": True,
            "text": True,
            "timeout": float(merged.get("login_timeout_seconds") or 300),
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = subprocess.run(**kwargs)
        except subprocess.TimeoutExpired:
            return {"ok": False, "reason": "login_timeout"}
        except Exception as exc:
            return {"ok": False, "reason": f"login_failed: {exc}"}
        self._ensure_result = None
        text = (completed.stdout or "") + (completed.stderr or "")
        return {"ok": True, "url": self._extract_login_url(text), "output": text.strip()[:300]}

    # --- model discovery ---------------------------------------------------

    def discover_models(
        self,
        base_url: str | None = None,
        cfg: Mapping[str, Any] | None = None,
    ) -> list[str]:
        """Return discovered GPT model ids from ``/v1/models`` (cached)."""
        merged = _coalesce(cfg)
        url_base = base_url or _v1_url(merged)
        ttl = float(merged.get("discover_cache_seconds") or 300)
        with self._lock:
            if self._models_cache is not None:
                fetched_at, ids = self._models_cache
                if time.monotonic() - fetched_at < ttl:
                    return list(ids)
        if httpx is None:
            return []
        try:
            with httpx.Client(timeout=_HEALTH_TIMEOUT) as client:
                resp = client.get(f"{url_base}/models")
                resp.raise_for_status()
                data = resp.json()
        except Exception:  # noqa: BLE001 -- model discovery probe: failure degrades to registry mode, never raises
            return []
        ids: list[str] = []
        for item in data.get("data") or []:
            model_id = item.get("id") if isinstance(item, dict) else None
            if model_id:
                ids.append(str(model_id))
        with self._lock:
            self._models_cache = (time.monotonic(), ids)
        return list(ids)

    def invalidate_model_cache(self) -> None:
        with self._lock:
            self._models_cache = None

    # --- shutdown ----------------------------------------------------------

    def shutdown(self, cfg: Mapping[str, Any] | None = None) -> None:
        """Stop the proxy ONLY if we started it. No-op otherwise."""
        with self._lock:
            we_started = self._we_started
            runtime = self._runtime
            self._we_started = False
            self._ensure_result = None
            self._running_base_url = None
        if not we_started or runtime is None:
            return
        merged = _coalesce(cfg)
        runtime_bin, entry = runtime
        args = [runtime_bin, entry, "stop"]
        kwargs: dict[str, Any] = {
            "args": args,
            "cwd": str(self._resolve_local_repo(merged)),
            "capture_output": True,
            "text": True,
            "timeout": 10,
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            subprocess.run(**kwargs)
        except Exception:  # noqa: BLE001 -- best-effort proxy stop; must never raise (called from lifecycle paths)
            pass


def _atexit_shutdown() -> None:
    try:
        ChatGptProxyManager.get().shutdown()
    except Exception:  # noqa: BLE001 -- atexit shutdown must never raise during interpreter teardown
        pass


atexit.register(_atexit_shutdown)


# ---------------------------------------------------------------------------
# Router builder (moved from tools/model_router.py) + provider adapter
# ---------------------------------------------------------------------------


def build_chatgpt_router(
    chatgpt_config: Mapping[str, Any],
    *,
    request_timeout_seconds: float | None = None,
) -> "ModelRouter":
    """Build a router backed by the local openai-oauth ChatGPT proxy."""
    from tools.model_router import ModelRouter

    cfg = dict(chatgpt_config)
    manager = ChatGptProxyManager.get()
    running = manager.ensure_running(cfg)
    if not running.get("ok"):
        reason = running.get("reason") or "unavailable"
        raise RuntimeError(
            f"ChatGPT provider unavailable: {reason}. "
            f"Run 'python main.py --doctor' or sign in via the interactive menu."
        )
    base_url = running["base_url"]

    # Resolve the model list: explicit config override → discover → fallback.
    configured = cfg.get("models") or []
    if configured:
        model_ids = [str(m) for m in configured if str(m).strip()]
    else:
        model_ids = manager.discover_models(base_url, cfg)
    if not model_ids:
        default_model = str(cfg.get("default_model") or "gpt-5.2")
        model_ids = [default_model]

    timeout = cfg.get("request_timeout_seconds")
    client_timeout = request_timeout_seconds
    if client_timeout is None and timeout is not None:
        try:
            client_timeout = float(timeout)
        except (TypeError, ValueError):
            client_timeout = None
    shared = ChatGptProxyClient(base_url, timeout=client_timeout)

    router = ModelRouter()
    for model_id in model_ids:
        router.register(
            model_id,
            make_model_client(
                model_id,
                alias=model_id,
                request_timeout_seconds=client_timeout,
                raw_client=shared,
                provider="chatgpt",
            ),
        )
    return router


def resolve_chatgpt_timeout(cfg: Mapping[str, Any], request_timeout_seconds: float | None = None) -> float | None:
    """Explicit timeout kwarg wins; else ``request_timeout_seconds`` from config."""
    if request_timeout_seconds is not None:
        return request_timeout_seconds
    raw = cfg.get("request_timeout_seconds")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


class ChatGptProvider(BaseProvider):
    """ChatGPT provider adapter: local openai-oauth proxy (loopback).

    Auth is the operator's ChatGPT session via browser OAuth (see module
    docstring — tokens are never read by BreachPilot).  Disabling/replacing
    this provider NEVER touches the target-IP allowlist, permission model,
    MCP target locks, or recon restrictions.
    """

    id = "chatgpt"
    display_name = "ChatGPT (openai-oauth)"
    capabilities = ProviderCapabilities(chat=True, streaming=True, tool_calls=True, model_discovery=True)

    def is_configured(self, cfg: Mapping[str, Any]) -> bool:
        # Enabled + an auth file existing (bool-only check, never a read).
        if not bool(cfg) or not bool(cfg.get("enabled")):
            return False
        return ChatGptProxyManager.get().is_authenticated(cfg)

    def build_router(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        request_timeout_seconds: float | None = None,
        provider_config: Mapping[str, Any] | None = None,
    ) -> "ModelRouter":
        cfg = dict(provider_config) if provider_config is not None else self.provider_config(config)
        return build_chatgpt_router(cfg, request_timeout_seconds=request_timeout_seconds)

    def build_client(
        self,
        config: Mapping[str, Any] | None = None,
        alias: str = "",
        *,
        request_timeout_seconds: float | None = None,
    ) -> "ModelClient":
        cfg = self.provider_config(config)
        manager = ChatGptProxyManager.get()
        running = manager.ensure_running(cfg)
        if not running.get("ok"):
            raise RuntimeError(f"ChatGPT provider unavailable: {running.get('reason') or 'unavailable'}.")
        timeout = resolve_chatgpt_timeout(cfg, request_timeout_seconds)
        shared = ChatGptProxyClient(running["base_url"], timeout=timeout)
        model_id = str(alias or cfg.get("default_model") or "gpt-5.2")
        return make_model_client(
            model_id,
            alias=alias or model_id,
            request_timeout_seconds=timeout,
            raw_client=shared,
            provider="chatgpt",
        )

    def list_models(self, config: Mapping[str, Any] | None = None) -> list[ModelInfo]:
        """Live model discovery, owning the openai-oauth lifecycle.

        Explicitly configured ``chatgpt.models`` short-circuit (no proxy
        spawn). Otherwise auto-starts the local proxy once (idempotent,
        signed-in + auto_start honored) and probes ``/v1/models``. Every
        failure raises :class:`ProviderDiscoveryError` carrying the
        registry-mode fallback so callers degrade identically.
        """
        cfg = self.provider_config(config)
        configured = [str(m) for m in (cfg.get("models") or []) if str(m).strip()]
        default_model = str(cfg.get("default_model") or "gpt-5.2")
        context_window = cfg.get("context_window")
        ctx = int(context_window) if isinstance(context_window, (int, float)) else None

        def _infos(ids: list[str]) -> list[ModelInfo]:
            return [
                ModelInfo(id=m, label=m, context_window=ctx, default=(m == default_model))
                for m in (ids or [default_model])
            ]

        if configured:
            return _infos(configured)
        manager = ChatGptProxyManager.get()
        # Auto-start the openai-oauth proxy (when authenticated + auto_start) so the
        # available-model list populates even before a run is launched. Idempotent:
        # a pre-existing proxy is health-checked and reused (_we_started stays False,
        # so we never stop a proxy we didn't start).
        running = manager.ensure_running(cfg)
        if not running.get("ok"):
            reason = str(running.get("reason") or "proxy_unavailable")
            msg = (
                "Not signed in to ChatGPT — sign in via System → Models."
                if reason == "not_authenticated"
                else f"ChatGPT proxy unavailable: {reason}"
            )
            raise ProviderDiscoveryError(msg, fallback_models=[default_model])
        base_url = str(running.get("base_url") or _v1_url(cfg))
        try:
            import httpx

            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{base_url.rstrip('/')}/models")
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            raise ProviderDiscoveryError(f"ChatGPT proxy unreachable: {exc}", fallback_models=[default_model]) from exc
        ids = [str(m.get("id", "")) for m in data.get("data", []) if isinstance(m, dict) and m.get("id")]
        return _infos(ids)

    def title_model(self, config: Mapping[str, Any] | None = None) -> str:
        return str(self.provider_config(config).get("default_model") or "gpt-5.2")

    def health(self, config: Mapping[str, Any] | None = None) -> ProviderHealth:
        cfg = self.provider_config(config)
        checks: list[dict[str, Any]] = []
        enabled = bool(cfg.get("enabled"))
        checks.append({"name": "chatgpt_enabled", "ok": enabled, "hint": "" if enabled else "chatgpt.enabled is false"})
        authenticated = ChatGptProxyManager.get().is_authenticated(cfg)
        checks.append(
            {
                "name": "chatgpt_authenticated",
                "ok": authenticated,
                "hint": "" if authenticated else "No openai-oauth auth file found — sign in first",
            }
        )
        return ProviderHealth(checks=checks)
