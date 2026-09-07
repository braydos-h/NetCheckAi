"""Ollama provider adapter.

Owns ALL Ollama-specific behavior:

- the ``from ollama import Client`` SDK import (isolated here, try/except so
  the package is optional — see ``load_client_cls`` for the actionable error);
- Ollama Cloud / local host handling (``ollama.host``);
- the canonical ``context_window_tokens`` -> ``options.num_ctx`` translation
  (``apply_context_window``) — Ollama is the only backend with that knob;
- the ``/api/tags`` model-catalog fetch and the ``models.registry`` auto-bump
  sync (moved here from ``tools/ollama_models.py``, which is now a compat shim);
- Ollama health checks (delegating to doctor's probe helpers).

Everything generic in the engine sees this module only through the
``BaseProvider`` interface or ``tools.model_router``'s re-exports
(``OllamaClient`` symbol kept as the historical monkeypatch seam).
"""

from __future__ import annotations

import logging
import os
import re
import threading
from typing import TYPE_CHECKING, Any, Mapping

from .base import BaseProvider
from .types import (
    ModelClient,
    ModelInfo,
    ProviderCapabilities,
    ProviderDiscoveryError,
    ProviderHealth,
    ProviderMissingDependencyError,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tools.model_router import ModelRouter

logger = logging.getLogger(__name__)

# ponytail: cloud-only. The host (default https://api.ollama.com) is set
# from config.yaml's ``ollama.host`` at every call site; the ollama Python
# client auto-attaches ``Authorization: Bearer $OLLAMA_API_KEY`` to every
# request, so pointing the same Client at the cloud host is the whole
# wiring. No reachability probe, no local→cloud fallback — the cloud IS
# the default. A local-only install overrides ``ollama.host`` to point at
# a local daemon and the same code path runs against that.
OLLAMA_CLOUD_HOST = "https://api.ollama.com"

# Concrete Ollama model ids behind the ``models.registry`` aliases (ollama
# provider only — other providers use their own default_model discovery).
DEFAULT_MODEL_REGISTRY: dict[str, str] = {
    "kimi": "kimi-k2.6:cloud",
    "deepseek": "deepseek-v4-pro:cloud",
    "deepseek_flash": "deepseek-v4-flash:cloud",
    "glm": "glm-5.2:cloud",
    "minimax": "minimax-m3:cloud",
    "glm3": "glm-5.3-flash",
}

_DEFAULT_TITLE_MODEL = "gemma4:31b-cloud"

_MISSING_DEP_MSG = (
    "Ollama provider requires the optional Ollama dependency. "
    "Install BreachPilot with the Ollama extra (pip install -e '.[ollama]') "
    "or set models.provider to another installed provider (see docs/providers.md)."
)


# ---------------------------------------------------------------------------
# SDK isolation — the ONLY place in the engine that imports the ollama package
# on the chat path (tools/web_researcher.py's research provider carries its own
# dynamic import and degrades gracefully when absent).
# ---------------------------------------------------------------------------

try:  # pragma: no cover - import outcome depends on the environment
    from ollama import Client as _OllamaSdkClient
except ImportError:  # pragma: no cover
    _OllamaSdkClient = None  # type: ignore[assignment,misc]


def load_client_cls() -> Any:
    """Return the ollama SDK Client class, or ``None`` when not installed."""
    return _OllamaSdkClient


def require_client_cls() -> Any:
    """Return the ollama SDK Client class or raise an actionable error."""
    if _OllamaSdkClient is None:
        raise ProviderMissingDependencyError(_MISSING_DEP_MSG)
    return _OllamaSdkClient


_RAW_CLIENT_CACHE: dict[tuple[str, float | None, Any], Any] = {}
_RAW_CLIENT_CACHE_LOCK = threading.Lock()


def reset_raw_client_cache() -> None:
    """Drop cached raw Ollama clients (tests that swap the SDK class use this)."""
    with _RAW_CLIENT_CACHE_LOCK:
        _RAW_CLIENT_CACHE.clear()


def build_ollama_raw_client(host: str, request_timeout_seconds: float | None, client_cls: Any = None) -> Any:
    """Build the raw ollama SDK client for the chat path.

    ``client_cls`` lets ``tools.model_router`` keep its historical
    ``monkeypatch.setattr(model_router, "OllamaClient", Fake)`` seam: the
    factory consults that module symbol when supplied.  Without an installed
    SDK (and no override) raises the actionable missing-dependency error.

    ponytail: constructing an httpx-backed client builds a fresh SSL context
    (~600ms on Windows, once per alias) — ``build_router`` used to pay that
    for EVERY registry alias on EVERY router build, which sat directly on the
    synchronous create-run path. Clients are pure (host + timeout only), so
    they are cached per ``(host, timeout, client_cls)`` and shared across
    aliases and builds. The key includes ``client_cls`` so the historical
    monkeypatch seam still gets a fresh client when a test swaps the class.
    """
    if client_cls is None:
        client_cls = require_client_cls()
    key = (str(host), request_timeout_seconds, client_cls)
    with _RAW_CLIENT_CACHE_LOCK:
        cached = _RAW_CLIENT_CACHE.get(key)
        if cached is not None:
            return cached
    # ponytail: pass timeout straight to the httpx-backed Ollama client. A hung
    # generation raises httpx.ReadTimeout, already matched by
    # exploit_agent._is_retryable_error → 3x retry → synthetic error dict, so
    # the attack loop survives without a new error path. None = httpx default.
    if request_timeout_seconds is not None:
        client = client_cls(host=host, timeout=request_timeout_seconds)
    else:
        client = client_cls(host=host)
    with _RAW_CLIENT_CACHE_LOCK:
        _RAW_CLIENT_CACHE[key] = client
    return client


def apply_context_window(raw_kwargs: dict[str, Any], context_window_tokens: Any) -> dict[str, Any]:
    """Ollama adapter translation: canonical ``context_window_tokens`` -> ``options.num_ctx``.

    Only sends ``num_ctx`` when the caller asks (long-session mode), so
    non-long runs stay byte-identical to the pre-registry behavior.
    """
    try:
        tokens = int(context_window_tokens)
    except (TypeError, ValueError):
        return raw_kwargs
    if tokens > 0:
        options = dict(raw_kwargs.get("options") or {})
        options["num_ctx"] = tokens
        return {**raw_kwargs, "options": options}  # never mutate the caller's dict
    return raw_kwargs


# ---------------------------------------------------------------------------
# Model catalog (GET /api/tags) + models.registry auto-bump — moved from
# tools/ollama_models.py (kept there as a compat shim).
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"[-._]?v?(?P<ver>\d+(?:\.\d+)*)$")


def parse_model_spec(spec: str) -> tuple[str, tuple[int, ...] | None]:
    """Split a model spec into ``(family, version)`` (see tools/ollama_models.py)."""
    base = (spec or "").split(":", 1)[0].strip()
    match = _VERSION_RE.search(base)
    if not match:
        return base, None
    version = tuple(int(part) for part in match.group("ver").split("."))
    family = base[: match.start()] or base
    return family, version


def fetch_available_models(host: str, api_key_env: str = "OLLAMA_API_KEY", timeout: float = 5.0) -> list[str]:
    """Return every model name listed by the Ollama API (``GET /api/tags``).

    Cloud hosts require ``Authorization: Bearer $OLLAMA_API_KEY``; local
    daemons ignore the header, so sending it unconditionally is safe (same
    convention as ``tools/doctor.py``). Raises on any network/HTTP error.
    """
    import json
    import urllib.request

    url = f"{host.rstrip('/')}/api/tags"
    req = urllib.request.Request(url)
    api_key = (os.environ.get(api_key_env, "") or "").strip()
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 -- scheme from config (loopback/cloud)
        data = json.loads(resp.read().decode("utf-8"))
    return [str(m.get("name", "")) for m in data.get("models", []) if m.get("name")]


def compute_registry_updates(registry: dict[str, str], available: list[str]) -> dict[str, dict[str, str]]:
    """Compute ``{alias: {old, new}}`` spec bumps for a registry (ollama-only)."""
    family_index: dict[str, list[tuple[tuple[int, ...], str, str]]] = {}
    for name in available:
        family, version = parse_model_spec(name)
        if version is None or not family:
            continue
        tag = name.split(":", 1)[1] if ":" in name else ""
        family_index.setdefault(family, []).append((version, tag, name))

    updates: dict[str, dict[str, str]] = {}
    for alias, spec in (registry or {}).items():
        family, version = parse_model_spec(spec)
        if version is None:
            continue
        candidates = family_index.get(family)
        if candidates is None:
            continue
        best = max(candidates, key=lambda c: c[0])
        if best[0] <= version:
            continue
        tag = spec.split(":", 1)[1] if ":" in spec else ""
        same_tag = [c for c in candidates if c[0] == best[0] and c[1] == tag]
        new_spec = same_tag[0][2] if same_tag else best[2]
        if new_spec != spec:
            updates[alias] = {"old": spec, "new": new_spec}
    return updates


def refresh_model_registry(
    config: dict[str, Any],
    host: str | None = None,
    api_key_env: str = "OLLAMA_API_KEY",
    timeout: float = 5.0,
    config_path: str | os.PathLike[str] = "config.yaml",
    persist: bool = True,
) -> dict[str, Any]:
    """One-shot registry sync against the Ollama API (ollama provider only)."""
    import copy

    ollama_cfg = config.get("ollama") if isinstance(config, dict) else None
    ohost = host or (
        str(ollama_cfg.get("host")) if isinstance(ollama_cfg, dict) and ollama_cfg.get("host") else OLLAMA_CLOUD_HOST
    )
    registry = dict((config.get("models") or {}).get("registry") or {})
    try:
        available = fetch_available_models(ohost, api_key_env=api_key_env, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 -- any transport failure is a soft error
        return {
            "ok": False,
            "host": ohost,
            "available_count": 0,
            "updates": {},
            "error": f"{type(exc).__name__}: {exc}",
        }

    updates = compute_registry_updates(registry, available)
    result: dict[str, Any] = {
        "ok": True,
        "host": ohost,
        "available_count": len(available),
        "updates": updates,
        "registry": registry,
        "persisted": False,
    }
    if updates:
        import copy

        new_config = copy.deepcopy(config)  # never mutate the caller's dict
        models = new_config.setdefault("models", {})
        reg = models.setdefault("registry", {})
        for alias, upd in updates.items():
            reg[alias] = upd["new"]
        if persist:
            _write_validated_config(new_config, config_path)
            result["persisted"] = True
        result["registry"] = dict(reg)
    return result


def _write_validated_config(config: dict[str, Any], config_path: str | os.PathLike[str]) -> None:
    """Validate + atomically write ``config`` (mirrors system.py ``_write_config``)."""
    import uuid
    from pathlib import Path

    import yaml

    from tools.config_manager import ConfigValidator

    path = Path(config_path)
    validator = ConfigValidator(path)
    validator._config = config
    result = validator.validate()
    if not result.is_valid:
        raise ValueError(f"Config validation failed: {result.errors}")
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        tmp.write_text(
            yaml.safe_dump(config, default_flow_style=False, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def auto_refresh_on_startup(
    config: dict[str, Any], config_path: str | os.PathLike[str] = "config.yaml"
) -> dict[str, Any] | None:
    """Boot-time best-effort registry sync. ``None`` when skipped.

    Skips silently (returns ``None``) for non-Ollama providers, when
    ``models.auto_update`` is false, or on any error — startup must never
    fail because the model catalog was unreachable. Also skips when a
    refresh for the same config file succeeded within
    ``_AUTO_REFRESH_MIN_INTERVAL_S``: every daemon restart was paying a
    blocking ``/api/tags`` round-trip (5s timeout) for a registry that only
    changes when Ollama Cloud ships a new same-family model.
    """
    try:
        from tools.config_manager import get_ai_provider

        if get_ai_provider(config) != "ollama":
            return None
        models_cfg = config.get("models") or {}
        if not models_cfg.get("auto_update", True):
            return None
    except Exception as exc:  # noqa: BLE001 -- never block boot on config introspection
        logger.warning("Model auto-update skipped: %s: %s", type(exc).__name__, exc)
        return None
    try:
        if _refresh_stamp_fresh(config_path):
            return None
    except Exception:  # noqa: BLE001 -- stamp check is advisory; a broken stamp must not skip the refresh
        pass
    try:
        result = refresh_model_registry(config, config_path=config_path, persist=True, timeout=5.0)
    except Exception as exc:  # noqa: BLE001 -- advisory only
        logger.warning("Model auto-update failed: %s: %s", type(exc).__name__, exc)
        return None
    if result.get("ok") and result.get("updates"):
        # Mirror the bumps into the caller's config dict so an in-memory
        # consumer (e.g. the WebUI daemon's ``create_app(config=config)``)
        # sees the refreshed registry without a restart.
        reg = (config.get("models") or {}).setdefault("registry", {})
        for alias, upd in result["updates"].items():
            reg[alias] = upd["new"]
    try:
        _write_refresh_stamp(config_path)
    except Exception:  # noqa: BLE001 -- stamp write is advisory
        pass
    return result


# ponytail: throttle file for the boot refresh above. Keyed by sha1 of the
# absolute config path (tests use distinct tmp configs, so no cross-test
# interference); lives in the OS temp dir so no repo/workspace pollution.
_AUTO_REFRESH_MIN_INTERVAL_S = 3600.0


def _refresh_stamp_path(config_path: str | os.PathLike[str]) -> Any:
    import hashlib
    import tempfile
    from pathlib import Path

    digest = hashlib.sha1(os.path.abspath(os.fspath(config_path)).encode()).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"breachpilot-model-refresh-{digest}.stamp"


def _refresh_stamp_fresh(config_path: str | os.PathLike[str]) -> bool:
    import time

    stamp = _refresh_stamp_path(config_path)
    try:
        age = time.time() - stamp.stat().st_mtime
    except OSError:
        return False
    return age < _AUTO_REFRESH_MIN_INTERVAL_S


def _write_refresh_stamp(config_path: str | os.PathLike[str]) -> None:
    import time

    stamp = _refresh_stamp_path(config_path)
    stamp.touch(exist_ok=True)
    try:
        os.utime(stamp, (time.time(), time.time()))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Provider adapter
# ---------------------------------------------------------------------------


class OllamaProvider(BaseProvider):
    """The Ollama adapter — one optional provider among several.

    Holds every Ollama-specific behavior: the SDK seam, the cloud/local host,
    the ``options.num_ctx`` translation, the ``/api/tags`` catalog, and the
    per-alias ``models.registry`` router building.
    """

    id = "ollama"
    display_name = "Ollama"
    capabilities = ProviderCapabilities(
        chat=True,
        streaming=True,
        tool_calls=True,
        embeddings=True,
        model_discovery=True,
    )

    def default_host(self, config: Mapping[str, Any] | None = None) -> str:
        from tools.config.loader import get_ollama_host

        return get_ollama_host(config or {})

    def build_router(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        request_timeout_seconds: float | None = None,
        provider_config: Mapping[str, Any] | None = None,
    ) -> "ModelRouter":
        from tools.model_router import ModelRouter

        cfg = self.provider_config(config)
        del provider_config  # ollama reads its block via provider_config
        registry = dict((config or {}).get("models", {}).get("registry") or {}) or dict(DEFAULT_MODEL_REGISTRY)
        router = ModelRouter()
        for alias in registry:
            router.register(
                str(alias),
                self.build_client(config, str(alias), request_timeout_seconds=request_timeout_seconds),
            )
        return router

    def build_client(
        self,
        config: Mapping[str, Any] | None = None,
        alias: str = "",
        *,
        request_timeout_seconds: float | None = None,
    ) -> ModelClient:
        from tools.model_router import _build_model_client

        registry = dict((config or {}).get("models", {}).get("registry") or {}) or dict(DEFAULT_MODEL_REGISTRY)
        key = str(alias or "").strip()
        if not key:
            models_cfg = (config or {}).get("models") or {}
            key = str(models_cfg.get("default_alias", "") or "").strip() or next(iter(registry), "")
        concrete = str(registry.get(key, key) or key)
        return _build_model_client(
            concrete,
            host=self.default_host(config),
            alias=key or concrete,
            request_timeout_seconds=request_timeout_seconds,
        )

    def list_models(self, config: Mapping[str, Any] | None = None) -> list[ModelInfo]:
        cfg = self.provider_config(config)
        host = str(cfg.get("host") or OLLAMA_CLOUD_HOST)
        api_key_env = str(cfg.get("api_key_env") or "OLLAMA_API_KEY")
        registry = (config or {}).get("models", {}).get("registry", {}) or {}
        try:
            available = fetch_available_models(host, api_key_env=api_key_env, timeout=5.0)
        except Exception as exc:
            # Live discovery failed — the route-level contract degrades to the
            # static models.registry aliases ("registry" source). The fallback
            # list rides on the error so every caller degrades identically.
            fallback = [str(v) for v in registry.values() if v]
            raise ProviderDiscoveryError(f"Ollama unreachable: {exc}", fallback_models=fallback) from exc
        infos: list[ModelInfo] = []
        seen: set[str] = set()
        for spec in available:
            seen.add(spec)
            family, version = parse_model_spec(spec)
            infos.append(
                ModelInfo(
                    id=spec,
                    label=spec,
                    context_window=None,
                    description=(f"family={family}" + (f" v{version}" if version else "")),
                )
            )
        # Include configured registry ids (e.g. checked-in aliases) not present live.
        for model_id in registry.values():
            if model_id not in seen:
                infos.append(ModelInfo(id=str(model_id), label=str(model_id)))
        return infos

    def title_model(self, config: Mapping[str, Any] | None = None) -> str:
        cfg = self.provider_config(config)
        return str(cfg.get("title_model") or _DEFAULT_TITLE_MODEL)

    def health(self, config: Mapping[str, Any] | None = None) -> ProviderHealth:
        """Ollama health = /api/tags reachability + configured-model check.

        Probes live in ``tools/doctor.py`` (kept there so the doctor's mock
        points stay untouched); this adapter owns WHICH probes run.
        """
        from tools.doctor import _check_models, _check_ollama

        full_config = config or {}
        host = self.default_host(full_config)
        registry = dict(full_config.get("models", {}).get("registry") or {})
        checks = [_check_ollama(host), _check_models(host, list(registry.values()))]
        return ProviderHealth(checks=checks)
