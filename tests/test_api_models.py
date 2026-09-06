"""Tests for model registry management endpoints: add/remove/provider switch."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="test-token-0123456789abcdef01234567"):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from app import create_app

    return TestClient(create_app(config_path=config_path))


def _auth(token="test-token-0123456789abcdef01234567"):
    return {"Authorization": f"Bearer {token}"}


def test_add_model_persists(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/models", json={"alias": "llama", "model": "llama3.1:8b"}, headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["registry"]["llama"] == "llama3.1:8b"
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert listed["registry"]["llama"] == "llama3.1:8b"


def test_remove_model(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    client.post("/api/v1/models", json={"alias": "llama", "model": "llama3.1:8b"}, headers=_auth())
    resp = client.delete("/api/v1/models/llama", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert "llama" not in listed["registry"]


def test_remove_default_alias_rejected(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.delete("/api/v1/models/glm", headers=_auth())
    assert resp.status_code == 400


def test_remove_missing_alias_404(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.delete("/api/v1/models/nope", headers=_auth())
    assert resp.status_code == 404


def test_switch_provider(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/models/provider", json={"provider": "chatgpt"}, headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["provider"] == "chatgpt"
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert listed["provider"] == "chatgpt"


def test_switch_provider_invalid(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/models/provider", json={"provider": "bogus"}, headers=_auth())
    assert resp.status_code == 400


# ── POST /models/refresh (Ollama API registry sync) ─────────────────────────


def _mock_fetch(monkeypatch, available):
    # The implementation lives in the Ollama provider module now
    # (tools/ollama_models.py is a compat shim), so patch there.
    from tools.providers import ollama_provider

    monkeypatch.setattr(
        ollama_provider,
        "fetch_available_models",
        lambda host, api_key_env="OLLAMA_API_KEY", timeout=5.0: list(available),
    )
    return ollama_provider


def test_refresh_models_updates_registry_and_persists(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    _mock_fetch(monkeypatch, ["glm-5.2:cloud", "glm-5.3:cloud"])
    resp = client.post("/api/v1/models/refresh", headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["updates"] == {"glm": {"old": "glm-5.2:cloud", "new": "glm-5.3:cloud"}}
    assert body["persisted"] is True
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert listed["registry"]["glm"] == "glm-5.3:cloud"
    assert "glm-5.3:cloud" in (tmp_path / "config.yaml").read_text(encoding="utf-8")


def test_refresh_models_no_updates_is_noop(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    _mock_fetch(monkeypatch, ["glm-5.2:cloud"])
    resp = client.post("/api/v1/models/refresh", headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert body["updates"] == {}
    assert body["persisted"] is False
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert listed["registry"]["glm"] == "glm-5.2:cloud"


def test_refresh_models_unreachable_503(tmp_path, monkeypatch):
    import urllib.error

    client = _make_client(tmp_path, monkeypatch)
    ollama_provider = _mock_fetch(monkeypatch, [])

    def _boom(host, api_key_env="OLLAMA_API_KEY", timeout=5.0):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(ollama_provider, "fetch_available_models", _boom)
    resp = client.post("/api/v1/models/refresh", headers=_auth())
    assert resp.status_code == 503
    assert resp.json()["ok"] is False


def test_refresh_models_rejected_for_chatgpt(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    client.post("/api/v1/models/provider", json={"provider": "chatgpt"}, headers=_auth())
    resp = client.post("/api/v1/models/refresh", headers=_auth())
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_provider"


# ── Provider-aware model picking (single source of truth) ─────────────────


def test_models_includes_active_provider_block(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    body = client.get("/api/v1/models", headers=_auth()).json()
    assert body["provider"] == "ollama"
    assert body["active_provider"]["id"] == "ollama"
    assert body["active_provider"]["default_model"] == "glm-5.2:cloud"
    assert "glm-5.2:cloud" in body["active_provider"]["configured_models"]


def test_models_active_provider_block_for_chatgpt(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    client.post("/api/v1/models/provider", json={"provider": "chatgpt"}, headers=_auth())
    body = client.get("/api/v1/models", headers=_auth()).json()
    assert body["provider"] == "chatgpt"
    assert body["active_provider"]["id"] == "chatgpt"
    assert body["active_provider"]["default_model"] == "gpt-5.2"
    assert "gpt-5.2" in body["active_provider"]["configured_models"]
    # Legacy block still present for back-compat.
    assert body["chatgpt"]["default_model"] == "gpt-5.2"


def test_models_live_generic_error_uses_provider_fallback(tmp_path, monkeypatch):
    """A non-discovery crash must not leak Ollama registry ids for chatgpt."""
    from tools.providers import chatgpt_provider

    client = _make_client(tmp_path, monkeypatch)
    client.post("/api/v1/models/provider", json={"provider": "chatgpt"}, headers=_auth())

    def _boom(config=None):
        raise RuntimeError("proxy exploded")

    monkeypatch.setattr(chatgpt_provider.ChatGptProvider, "list_models", _boom)
    resp = client.get("/api/v1/models/live", headers=_auth())
    assert resp.status_code == 503
    data = resp.json()
    assert data["source"] == "registry"
    assert "gpt-5.2" in data["models"]
    assert "glm-5.2:cloud" not in data["models"]


def test_provider_four_needs_no_route_change(tmp_path, monkeypatch):
    """A registry-only adapter gets working /models + /models/live with zero route edits."""
    from tools.providers.base import BaseProvider
    from tools.providers.registry import PROVIDERS, _LazyDefaultRegistry
    from tools.providers.types import ModelInfo

    _LazyDefaultRegistry._ensure()

    class _FourthProvider(BaseProvider):
        id = "fourth"
        display_name = "Fourth"

        def provider_config(self, config=None):
            return {"default_model": "fourth-1", "models": ["fourth-1", "fourth-2"]}

        def build_router(self, config=None, **kwargs):
            raise NotImplementedError

        def list_models(self, config=None):
            cfg = self.provider_config(config)
            return [ModelInfo(id=m, label=m) for m in cfg["models"]]

    try:
        PROVIDERS.register(_FourthProvider())
    except ValueError:
        pass  # already registered by an earlier run in this session
    try:
        client = _make_client(tmp_path, monkeypatch)
        resp = client.post("/api/v1/models/provider", json={"provider": "fourth"}, headers=_auth())
        assert resp.status_code == 200
        body = client.get("/api/v1/models", headers=_auth()).json()
        assert body["provider"] == "fourth"
        assert body["active_provider"]["default_model"] == "fourth-1"
        assert body["active_provider"]["configured_models"] == ["fourth-1", "fourth-2"]
        live = client.get("/api/v1/models/live", headers=_auth()).json()
        assert live["source"] == "fourth"
        assert live["models"] == ["fourth-1", "fourth-2"]
    finally:
        # Never leak the fake adapter into other tests (registry is global).
        PROVIDERS._providers.pop("fourth", None)
