"""Provider registry — the single dispatch point for chat/generate providers.

Replaces the old ``if provider == "chatgpt" ... elif provider == "opencode_go" ... else ollama``
chains in ``tools/model_router.py`` (and in run-service / eval / benchmark /
MCP registry call sites) with a registry lookup:

.. code-block:: python

    from tools.providers.registry import get_provider

    provider = get_provider("opencode_go")   # or get_provider_from_config(config)
    router = provider.build_router(config)
    client = provider.build_client(config, alias)

Adding provider #4 = implement an adapter (``BaseProvider``), register it
below (or via ``PROVIDERS.register``), add config metadata, add tests.  No
agent/swarm/run-service edits.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, Mapping

from .base import BaseProvider
from .types import ModelClient, ModelInfo, ProviderCapabilities, ProviderError, ProviderHealth  # noqa: F401

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tools.model_router import ModelRouter  # noqa: F401 -- annotates provider docstrings


class UnknownProviderError(ProviderError):
    """Raised when a config names a provider that is not registered.

    Carries an actionable message listing the registered ids.
    """


class ProviderRegistry:
    """Thread-safe registry of :class:`BaseProvider` instances."""

    def __init__(self) -> None:
        self._providers: dict[str, BaseProvider] = {}
        self._lock = threading.Lock()

    def register(self, provider: BaseProvider) -> None:
        if not getattr(provider, "id", ""):
            raise ValueError("Provider must define a non-empty 'id'.")
        with self._lock:
            key = str(provider.id).lower()
            if key in self._providers and type(self._providers[key]) is not type(provider):
                raise ValueError(
                    f"Provider id '{key}' already registered to {type(self._providers[key]).__name__}; "
                    f"refusing to shadow it with {type(provider).__name__}."
                )
            self._providers[key] = provider

    def get(self, provider_id: str) -> BaseProvider:
        key = str(provider_id or "").strip().lower()
        if not key:
            raise UnknownProviderError(
                "No chat provider selected. Set 'models.provider' in config.yaml "
                f"(available: {', '.join(sorted(self.ids()))})."
            )
        with self._lock:
            provider = self._providers.get(key)
        if provider is None:
            raise UnknownProviderError(
                f"Unknown model provider '{provider_id}'. Available providers: {', '.join(sorted(self.ids()))}. "
                f"Set 'models.provider' in config.yaml to one of them, or register the provider via "
                f"tools.providers.registry."
            )
        return provider

    # Convenience aliases used across the codebase.
    get_provider = get

    def ids(self) -> list[str]:
        with self._lock:
            return list(self._providers.keys())

    def all(self) -> list[BaseProvider]:
        with self._lock:
            return list(self._providers.values())

    def metadata(self, config: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        """Serializable metadata for every registered provider (no secrets)."""
        return [p.metadata(config) for p in self.all()]


PROVIDERS = ProviderRegistry()


class _LazyDefaultRegistry:
    """Registers the built-in providers on first access.

    Built-in adapters import quickly (their third-party SDK imports are
    try/except-guarded), but registration stays lazy so importing the registry
    never touches provider SDKs and ``import tools.providers.registry`` runs
    with zero providers present.
    """

    _done = False
    _lock = threading.Lock()

    @classmethod
    def _ensure(cls) -> None:
        if cls._done:
            return
        with cls._lock:
            if cls._done:
                return
            from .chatgpt_provider import ChatGptProvider
            from .ollama_provider import OllamaProvider
            from .opencode_go_provider import OpenCodeGoProvider

            PROVIDERS.register(OllamaProvider())
            PROVIDERS.register(OpenCodeGoProvider())
            PROVIDERS.register(ChatGptProvider())
            cls._done = True


def get_provider(provider_id: str) -> BaseProvider:
    """Resolve a registered provider by id (builds the default registry)."""
    _LazyDefaultRegistry._ensure()
    return PROVIDERS.get(provider_id)


def get_provider_from_config(config: Mapping[str, Any] | None) -> BaseProvider:
    """Resolve the provider selected by ``models.provider`` (default ``ollama``)."""
    from tools.config.loader import get_ai_provider

    return get_provider(get_ai_provider(config))


def active_provider_metadata(config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Registry-driven provider selection metadata: ids + display names + capabilities.

    UI and API consumers render provider pickers from this instead of
    hard-coding per-provider switch statements.
    """
    _LazyDefaultRegistry._ensure()
    from tools.config.loader import get_ai_provider

    active = get_ai_provider(config)
    return {
        "active": active,
        "providers": PROVIDERS.metadata(config),
    }


# ---------------------------------------------------------------------------
# Default config accessors shared by every call site (single source).
# ---------------------------------------------------------------------------


def resolve_default_model(config: Mapping[str, Any], provider_id: str) -> str:
    """The default concrete model id for ``provider_id`` under ``config``.

    Resolution order: the provider's normalized config block (``providers.<id>``
    > legacy top-level block) ``default_model``, else — for the Ollama
    provider — the ``models.registry`` model bound to ``models.default_alias``.
    """
    cfg = get_provider(provider_id).provider_config(config)
    default = str(cfg.get("default_model", "") or "")
    if provider_id == "ollama" and not default:
        models_cfg = (config or {}).get("models") or {}
        alias = str(models_cfg.get("default_alias", "") or "")
        if alias:
            return str((models_cfg.get("registry") or {}).get(alias) or alias)
    return default


def build_client_for_config(
    config: Mapping[str, Any] | None,
    alias: str,
    *,
    request_timeout_seconds: float | None = None,
) -> Any:
    """Build one client for ``alias`` under the active provider (no branching).

    Root-cause seam for every "missing client" fallback: resolves the active
    provider through the registry and asks its adapter for a client, so
    provider #4 works without touching any caller. Replaces the old
    ``if provider in (...) ... else _build_model_client(...)`` chains.
    """
    return get_provider_from_config(config).build_client(
        config,
        alias,
        request_timeout_seconds=request_timeout_seconds,
    )


def build_router_for_config(
    config: Mapping[str, Any] | None,
    *,
    request_timeout_seconds: float | None = None,
) -> Any:
    """Build the active provider's router from ``config`` (no branching)."""
    return get_provider_from_config(config).build_router(
        config,
        request_timeout_seconds=request_timeout_seconds,
    )
