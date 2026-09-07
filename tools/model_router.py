"""Model client abstraction layer — provider-neutral.

Provides:
- ModelClient: the canonical BreachPilot client wrapper (re-exported from
  ``tools.providers.types``, which formally defines the BreachPilot model
  response format). No provider is special-cased here — Ollama is one
  adapter among several (``tools/providers/``).
- ModelRouter: manages multiple backends and distributes calls
- build_router(): factory that dispatches through the provider registry
  (``tools.providers.registry``) for non-Ollama providers and keeps the
  historical per-alias registry path for ``ollama``
- build_model_client_for_provider(): single client for an alias under the
  configured provider
- MODEL_INFO: per-alias metadata (context window, description) so the UI
  can show operators what they're picking and the context compactor can
  size itself correctly.

All Ollama API behavior lives in ``tools/providers/ollama_provider.py``;
this module only keeps the ``OllamaClient`` module symbol as the
historical monkeypatch seam (``monkeypatch.setattr(model_router,
"OllamaClient", Fake)``) and re-exports the Ollama provider helpers.

Usage:
    router = build_router()
    client = router.get_client("deepseek")
    response = client.chat(messages=[...], tools=[...])
"""

from __future__ import annotations

import random
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from tools.model_telemetry import (
    infer_source,
    now_iso,
    record_model_usage,
)
from tools.providers.ollama_provider import (
    DEFAULT_MODEL_REGISTRY,
    OLLAMA_CLOUD_HOST,
    apply_context_window,
    load_client_cls,
)
from tools.providers.types import ModelClient

# Historical monkeypatch seam: tests do ``monkeypatch.setattr(model_router,
# "OllamaClient", Fake)`` and the factory reads this module global at call
# time. ``None`` when the optional ollama package is absent — selecting the
# Ollama provider without it raises the actionable ProviderMissingDependencyError.
OllamaClient = load_client_cls()


# Per-alias model metadata. The ``context_window`` value is the contract
# the adaptive context compactor (``tools.exploit_agent``) uses to
# decide when to summarize; ``description`` is what the UI shows the
# operator when they pick a model. Keep both in sync with config.yaml's
# ``models.info`` block — that file's values are loaded at runtime and
# override the defaults here when present.
MODEL_INFO: dict[str, dict[str, Any]] = {
    "kimi": {
        "label": "Kimi K2.6",
        "context_window": 256_000,
        "description": "Moonshot Kimi K2.6 — strong long-form reasoning, 256K context.",
    },
    "deepseek": {
        "label": "DeepSeek V4 Pro",
        "context_window": 1_000_000,
        "description": "DeepSeek V4 Pro — 1M token context, deep code reasoning.",
    },
    "deepseek_flash": {
        "label": "DeepSeek V4 Flash",
        "context_window": 1_000_000,
        "description": "DeepSeek V4 Flash - 1M token context, fast DeepSeek option for lower-latency work.",
    },
    "glm": {
        "label": "GLM-5.2",
        "context_window": 976_000,
        "description": "Zhipu GLM-5.2 — 976K context, the smartest/newest GLM for deep reasoning + coding.",
    },
    "minimax": {
        "label": "Minimax M3",
        "context_window": 512_000,
        "description": "Minimax M3 (cloud) — 512K context, balanced coding + reasoning.",
    },
    "glm3": {
        "label": "GLM-5.3 Flash",
        "context_window": 128_000,
        "description": "Zhipu GLM-5.3 Flash — fast low-latency GLM option (128K context).",
    },
}

# DEFAULT_MODEL_REGISTRY is imported from tools.providers.ollama_provider
# (the Ollama adapter owns it) and re-exported here for compatibility.


def get_model_info(alias: str, registry_info: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return metadata for a model alias.

    ``registry_info`` is the ``models.info`` block from config.yaml; when
    present, its entries override the in-code defaults so the operator
    can edit context windows and descriptions without code changes.
    Falls back to the in-code default if the alias is unknown.
    """
    default = {
        "label": alias,
        "context_window": 128_000,
        "description": f"Unknown alias '{alias}' - using 128K default context window.",
    }
    override = (registry_info or {}).get(alias)
    if isinstance(override, Mapping):
        base = dict(MODEL_INFO.get(alias, default))
        base.update({k: v for k, v in override.items() if v is not None})
        return base
    return dict(MODEL_INFO.get(alias, default))


def format_context_window(context_window: Any) -> str:
    """Format a token context window for compact operator-facing picker labels."""
    try:
        tokens = int(context_window)
    except (TypeError, ValueError):
        return "?"
    if tokens <= 0:
        return "?"
    if tokens >= 1_000_000:
        if tokens % 1_000_000 == 0:
            return f"{tokens // 1_000_000}M"
        label = f"{tokens / 1_000_000:.1f}".rstrip("0").rstrip(".")
        return f"{label}M"
    if tokens >= 1_000:
        if tokens % 1_000 == 0:
            return f"{tokens // 1_000}K"
        label = f"{tokens / 1_000:.1f}".rstrip("0").rstrip(".")
        return f"{label}K"
    return str(tokens)


def format_model_choice(
    alias: str,
    *,
    registry: Mapping[str, str] | None = None,
    registry_info: Mapping[str, Any] | None = None,
) -> str:
    """Return a consistent model-picker label with alias, label, context, id, and description."""
    info = get_model_info(alias, registry_info)
    label = str(info.get("label") or alias)
    ctx = format_context_window(info.get("context_window"))
    description = str(info.get("description") or "").strip()
    model_id = ""
    if isinstance(registry, Mapping):
        model_id = str(registry.get(alias) or "").strip()

    parts = [f"{alias:<15} | {label:<20} | {ctx:>5} ctx"]
    if model_id:
        parts.append(model_id)
    if description:
        parts.append(description)
    return " | ".join(parts)


def model_choice_items(
    registry: Mapping[str, str] | None = None,
    registry_info: Mapping[str, Any] | None = None,
) -> list[tuple[str, str]]:
    """Return ``(display, alias)`` items for configured model pickers."""
    effective_registry: Mapping[str, str] = registry or DEFAULT_MODEL_REGISTRY
    return [
        (format_model_choice(str(alias), registry=effective_registry, registry_info=registry_info), str(alias))
        for alias in effective_registry.keys()
    ]


# ModelClient is re-exported from tools.providers.types (canonical contract;
# carries an explicit ``provider`` attribution field). It is NOT redefined here.


# Model roles recognized for role-aware routing (models.roles.<role> -> alias).
# Every role defaults to the default alias, so an unconfigured roles block is
# byte-identical to today's behavior; operators point a role at a stronger
# alias only when one is available.
MODEL_ROLES: tuple[str, ...] = (
    "planner",
    "executor",
    "interpreter",
    "code_generator",
    "critic",
    "summarizer",
)


class ModelRouter:
    """Manages multiple Ollama model backends."""

    def __init__(self):
        self._clients: dict[str, ModelClient] = {}

    def register(self, alias: str, client: ModelClient) -> None:
        self._clients[alias] = client

    def get_client(self, alias: str) -> ModelClient:
        # Tolerate callers that pass a concrete model id (e.g. "glm-5.2:cloud")
        # instead of its alias. Reverse-lookup by model_id, then by name, so a
        # stray --model glm-5.2:cloud resolves to the registered "glm" client
        # instead of hard-failing the whole boot.
        if alias in self._clients:
            return self._clients[alias]
        for client in self._clients.values():
            if client.model_id == alias or client.name == alias:
                return client
        raise KeyError(f"Model alias '{alias}' not registered. Available: {list(self._clients)!r}")

    def get_client_for_role(
        self,
        role: str,
        *,
        config: Mapping[str, Any] | None = None,
        fallback_alias: str | None = None,
    ) -> ModelClient:
        """Resolve a model client for a functional role.

        Reads ``config['models']['roles'][role]`` (an alias or model id) and
        resolves it through ``get_client`` (which tolerates concrete model
        ids). Missing role config falls back to ``fallback_alias`` and then to
        the ``models.default_alias`` value in config. Role resolution failures
        fall back the same way -- a typo in a role mapping must never hard-fail
        a run. ``config=None`` and no fallback returns the only client when
        exactly one is registered, else raises (mirrors get_client semantics).
        """
        roles: Mapping[str, Any] = {}
        default_alias: str = ""
        if isinstance(config, Mapping):
            models_cfg = config.get("models", {})
            if isinstance(models_cfg, Mapping):
                roles_raw = models_cfg.get("roles", {})
                roles = roles_raw if isinstance(roles_raw, Mapping) else {}
                default_alias = str(models_cfg.get("default_alias", "") or "")
        candidates = [str(roles.get(role, "") or ""), fallback_alias or "", default_alias]
        for alias in candidates:
            if not alias:
                continue
            try:
                return self.get_client(alias)
            except KeyError:
                continue
        if len(self._clients) == 1:
            return next(iter(self._clients.values()))
        raise KeyError(f"No model client resolvable for role '{role}'.")

    def clients(self) -> list[ModelClient]:
        return list(self._clients.values())

    def random_client(self) -> ModelClient:
        if not self._clients:
            raise RuntimeError("No model clients registered in router.")
        return random.choice(list(self._clients.values()))


# ``_registry_info_from_config`` re-reads + YAML-parses config.yaml on every
# call. ``build_router`` calls ``_context_window_for`` once PER ALIAS, so an
# uncached read cost ~6 YAML parses (~1.4s on Windows) per router build — on
# the synchronous create-run path. Cache the parsed ``models.info`` mapping
# keyed by the config file's mtime+size so warm router builds skip the disk
# entirely and an operator config edit is still picked up immediately.
_REGISTRY_INFO_CACHE: dict[tuple[str, int, int], Mapping[str, Any]] = {}
_REGISTRY_INFO_CACHE_LOCK = threading.Lock()


def _registry_info_cache_key() -> tuple[str, int, int] | None:
    """(resolved path, mtime_ns, size) of the config file, or None when unknown.

    Mirrors ``load_validated_config``'s default ``config.yaml`` lookup (the
    caller passes no explicit path).
    """
    try:
        path = Path("config.yaml")
        stat = path.stat()
        return (str(path.resolve()), stat.st_mtime_ns, stat.st_size)
    except OSError:  # missing/unreadable config = no stable cache key
        return None


def reset_registry_info_cache() -> None:
    """Drop the cached ``models.info`` mapping (tests + config reloads)."""
    with _REGISTRY_INFO_CACHE_LOCK:
        _REGISTRY_INFO_CACHE.clear()


def _registry_info_from_config() -> Mapping[str, Any]:
    key = _registry_info_cache_key()
    if key is not None:
        with _REGISTRY_INFO_CACHE_LOCK:
            cached = _REGISTRY_INFO_CACHE.get(key)
        if cached is not None:
            return cached
    try:
        from tools.config_manager import load_validated_config

        config = load_validated_config()
    except Exception:
        return {}
    models_cfg = config.get("models", {}) if isinstance(config, Mapping) else {}
    info = models_cfg.get("info", {}) if isinstance(models_cfg, Mapping) else {}
    info = info if isinstance(info, Mapping) else {}
    if key is not None:
        with _REGISTRY_INFO_CACHE_LOCK:
            _REGISTRY_INFO_CACHE[key] = info
    return info


def _context_window_for(alias: str, model_name: str) -> int | None:
    info = _registry_info_from_config()
    for key in (alias, model_name):
        model_info = get_model_info(str(key), info)
        context_window = model_info.get("context_window")
        if isinstance(context_window, int) and context_window > 0:
            return context_window
    return None


def _normalize_chat_args(args: tuple[Any, ...], kwargs: dict[str, Any], model_name: str) -> dict[str, Any]:
    raw_kwargs = dict(kwargs)
    positional = list(args)

    # Existing call sites use both client.chat(model, messages=...) and
    # client.chat(messages=...). The wrapped Ollama client always receives the
    # concrete configured model id.
    if positional and isinstance(positional[0], str):
        positional.pop(0)
    if positional and "messages" not in raw_kwargs:
        raw_kwargs["messages"] = positional.pop(0)
    if "model" in raw_kwargs:
        raw_kwargs.pop("model", None)
    raw_kwargs.setdefault("messages", [])
    if not raw_kwargs.get("tools"):
        raw_kwargs.pop("tools", None)
    raw_kwargs["model"] = model_name
    return raw_kwargs


def _stream_with_telemetry(
    stream: Any,
    *,
    alias: str,
    model_name: str,
    messages: Any,
    started_at: str,
    started_monotonic: float,
    context_window_tokens: int | None,
    source: str,
    provider: str = "ollama",
):
    last_chunk: Any | None = None
    error = ""
    try:
        for chunk in stream:
            last_chunk = chunk
            yield chunk
    except Exception as exc:
        error = str(exc)
        raise
    finally:
        record_model_usage(
            alias=alias,
            model_id=model_name,
            response=last_chunk,
            messages=messages,
            stream=True,
            started_at=started_at,
            ended_at=now_iso(),
            wall_duration_seconds=time.monotonic() - started_monotonic,
            context_window_tokens=context_window_tokens,
            source=source,
            error=error,
            provider=provider,
        )


# OLLAMA_CLOUD_HOST ("https://api.ollama.com") is imported from the Ollama
# provider adapter above — cloud-only: the host is set from config.yaml's
# ``ollama.host`` at every call site; the ollama Python client auto-attaches
# ``Authorization: Bearer $OLLAMA_API_KEY`` to every request, so pointing the
# same Client at the cloud host is the whole wiring. No reachability probe,
# no local→cloud fallback — the cloud IS the default. A local-only install
# overrides ``ollama.host`` to point at a local daemon and the same code
# path runs against that.


def _build_model_client(
    model_name: str,
    host: str = OLLAMA_CLOUD_HOST,
    *,
    alias: str = "",
    request_timeout_seconds: float | None = None,
    raw_client: Any = None,
    provider: str = "ollama",
) -> ModelClient:
    """Factory to build a ModelClient for a chat/generate backend.

    Cloud-only by default: ``host`` is ``https://api.ollama.com`` unless
    overridden by config or a caller. The ollama Python client reads
    ``OLLAMA_API_KEY`` from the env on init and adds ``Authorization: Bearer
    <key>`` to every request, so a host swap is sufficient — no extra auth
    plumbing. Override ``ollama.host`` in config.yaml to point at a local
    daemon if you have one; the same code path runs against it.

    Provider seam: pass ``raw_client`` (any object with a ``chat(**kwargs)``
    method returning a BreachPilot model response dict / stream iterable) to
    route through a non-Ollama backend. When ``raw_client is None`` (and
    ``provider == "ollama"``) the Ollama client is constructed exactly as
    before — byte-identical, so every test that monkeypatches
    ``model_router.OllamaClient`` keeps working. Constructing it without the
    optional ollama package raises the actionable
    ``ProviderMissingDependencyError``. ``provider`` is threaded into
    telemetry so records attribute by provider (additive; default
    ``"ollama"`` keeps old records valid).

    Canonical chat kwarg: generic code passes ``context_window_tokens=N``
    (never Ollama's ``options.num_ctx``). The Ollama adapter translates
    (``apply_context_window``); other providers drop it — they have no such
    knob. Generic code must not send ``options={"num_ctx": ...}``.
    """
    if raw_client is None:
        if provider != "ollama":
            raise ValueError(
                f"raw_client is required for non-Ollama providers (got provider={provider!r}); "
                "build it via the provider adapter in tools.providers."
            )
        from tools.providers.ollama_provider import build_ollama_raw_client

        # Reads the module-level OllamaClient (monkeypatch seam) at call time.
        raw_client = build_ollama_raw_client(host, request_timeout_seconds, client_cls=OllamaClient)

    telemetry_alias = alias or model_name
    context_window_tokens = _context_window_for(telemetry_alias, model_name)

    def chat(*args: Any, **kwargs: Any) -> Any:
        source = str(kwargs.pop("telemetry_source", "") or "") or infer_source()
        raw_kwargs = _normalize_chat_args(args, kwargs, model_name)
        # Canonical context-window kwarg: pop it before dispatch. Only the
        # Ollama adapter has a translation (options.num_ctx); other providers
        # simply don't receive Ollama-only kwargs.
        canonical_ctx = raw_kwargs.pop("context_window_tokens", None)
        if provider != "ollama":
            for ollama_only in ("options", "keep_alive", "format", "suffix", "think", "raw", "num_ctx"):
                raw_kwargs.pop(ollama_only, None)
        elif canonical_ctx is not None:
            raw_kwargs = apply_context_window(raw_kwargs, canonical_ctx)
        messages = raw_kwargs.get("messages", [])
        stream = bool(raw_kwargs.get("stream", False))
        started_at = now_iso()
        started_monotonic = time.monotonic()
        error = ""
        try:
            response = raw_client.chat(**raw_kwargs)
            if stream:
                return _stream_with_telemetry(
                    response,
                    alias=telemetry_alias,
                    model_name=model_name,
                    messages=messages,
                    started_at=started_at,
                    started_monotonic=started_monotonic,
                    context_window_tokens=context_window_tokens,
                    source=source,
                    provider=provider,
                )
            record_model_usage(
                alias=telemetry_alias,
                model_id=model_name,
                response=response,
                messages=messages,
                stream=False,
                started_at=started_at,
                ended_at=now_iso(),
                wall_duration_seconds=time.monotonic() - started_monotonic,
                context_window_tokens=context_window_tokens,
                source=source,
                provider=provider,
            )
            return response
        except Exception as exc:
            error = str(exc)
            record_model_usage(
                alias=telemetry_alias,
                model_id=model_name,
                response=None,
                messages=messages,
                stream=stream,
                started_at=started_at,
                ended_at=now_iso(),
                wall_duration_seconds=time.monotonic() - started_monotonic,
                context_window_tokens=context_window_tokens,
                source=source,
                error=error,
                provider=provider,
            )
            raise

    def stream_chat(*args: Any, **kwargs: Any) -> Any:
        kwargs["stream"] = True
        kwargs.setdefault("tools", None)
        return chat(*args, **kwargs)

    return ModelClient(name=model_name, chat=chat, stream=stream_chat, model_id=model_name, provider=provider)


def build_router(
    registry: Mapping[str, str] | None = None,
    host: str = OLLAMA_CLOUD_HOST,
    *,
    request_timeout_seconds: float | None = None,
    provider: str = "ollama",
    chatgpt_config: Mapping[str, Any] | None = None,
    opencode_go_config: Mapping[str, Any] | None = None,
    config: Mapping[str, Any] | None = None,
) -> ModelRouter:
    """Build and return a router from alias -> model name.

    ``provider`` selects the backend. ``"ollama"`` (default) is the unchanged
    per-registry-alias path. Any other provider id resolves through the
    provider registry (``tools.providers.registry``) — there is no if/elif
    chain here: provider #4 is an adapter + registration, no edits to this
    function. ``alias`` == ``model_id`` for providers without an alias
    namespace (chatgpt / opencode_go).

    ``ollama`` semantics are byte-identical: ``build_router(registry,
    host)`` builds one ``ModelClient`` per registry alias whose ids come
    from ``DEFAULT_MODEL_REGISTRY`` / ``config.yaml models.registry``.
    """
    if provider not in (None, "", "ollama"):
        from tools.providers.registry import get_provider

        adapter = get_provider(provider)
        provider_config: Mapping[str, Any] | None = None
        del host, registry
        if provider == "chatgpt" and chatgpt_config is not None:
            provider_config = chatgpt_config
        elif provider == "opencode_go" and opencode_go_config is not None:
            provider_config = opencode_go_config
        return adapter.build_router(
            config,
            request_timeout_seconds=request_timeout_seconds,
            provider_config=provider_config,
        )

    registry = registry or DEFAULT_MODEL_REGISTRY
    router = ModelRouter()
    for alias, model_name in registry.items():
        router.register(
            str(alias),
            _build_model_client(
                str(model_name),
                host=host,
                alias=str(alias),
                request_timeout_seconds=request_timeout_seconds,
            ),
        )
    return router


# ``_build_chatgpt_router`` / ``_build_opencode_go_router`` /
# ``_is_opencode_responses_model`` moved into their provider adapters:
#   tools/providers/chatgpt_provider.py  → build_chatgpt_router
#   tools/providers/opencode_go_provider.py → build_opencode_go_router,
#       is_opencode_responses_model
# Kept here as re-exports for the existing import sites (e.g.
# tools/api/routes/system.py) and tests.


def _build_chatgpt_router(
    chatgpt_config: Mapping[str, Any],
    *,
    request_timeout_seconds: float | None = None,
) -> ModelRouter:
    """Compat re-export — implementation lives in the ChatGPT provider adapter."""
    from tools.providers.chatgpt_provider import build_chatgpt_router

    return build_chatgpt_router(chatgpt_config, request_timeout_seconds=request_timeout_seconds)


def _is_opencode_responses_model(
    model_id: str,
    raw_item: Mapping[str, Any] | None,
    cfg: Mapping[str, Any] | None = None,
) -> bool:
    """Compat re-export — implementation lives in the OpenCode Go adapter."""
    from tools.providers.opencode_go_provider import is_opencode_responses_model

    return is_opencode_responses_model(model_id, raw_item, cfg)


def _build_opencode_go_router(
    opencode_config: Mapping[str, Any],
    *,
    request_timeout_seconds: float | None = None,
) -> ModelRouter:
    """Compat re-export — implementation lives in the OpenCode Go adapter."""
    from tools.providers.opencode_go_provider import build_opencode_go_router

    return build_opencode_go_router(opencode_config, request_timeout_seconds=request_timeout_seconds)


def build_model_client_for_provider(
    config: Mapping[str, Any] | None,
    alias: str,
    *,
    request_timeout_seconds: float | None = None,
) -> ModelClient:
    """Build a single ``ModelClient`` for ``alias`` under the configured provider.

    Root-cause replacement for the duplicated ``_build_model_client(alias,
    host=...)`` fallback call sites: resolves the active provider through
    the registry and asks its adapter for a client — no per-provider
    branches here. For ``ollama`` this is byte-identical to the old direct
    call (``_build_model_client(alias, host=get_ollama_host(cfg), ...)``);
    for other providers the adapter owns auth/endpoint/model resolution.
    """
    from tools.providers.registry import get_provider_from_config

    return get_provider_from_config(config).build_client(
        config,
        alias,
        request_timeout_seconds=request_timeout_seconds,
    )
