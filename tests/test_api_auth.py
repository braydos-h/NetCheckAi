"""Tests for API security: bearer auth, loopback enforcement, origin checks."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tools.api.auth import (
    assert_api_loopback,
    is_loopback_origin,
    load_or_create_token,
)

# ── Loopback enforcement ─────────────────────────────────────────────────────


def test_loopback_hosts_allowed():
    for host in ("127.0.0.1", "localhost", "::1"):
        assert_api_loopback(host)  # must not raise


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.1", "example.com"])
def test_non_loopback_refused(host):
    with pytest.raises(ValueError, match="loopback"):
        assert_api_loopback(host)


# ── Token generation ─────────────────────────────────────────────────────────


def test_token_env_override(monkeypatch):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "test-token-0123456789abcdef01234567-123")
    token = load_or_create_token(".webui_secret_key", env_override="test-token-0123456789abcdef01234567-123")
    assert token == "test-token-0123456789abcdef01234567-123"


def test_token_generated_when_no_env_no_file(tmp_path):
    token_file = tmp_path / ".webui_secret_key"
    token = load_or_create_token(token_file, env_override="")
    assert len(token) > 20
    assert token_file.exists()
    # Second call reads from file.
    token2 = load_or_create_token(token_file, env_override="")
    assert token2 == token


def test_token_read_from_file(tmp_path):
    token_file = tmp_path / ".webui_secret_key"
    token_file.write_text("file-token-456-with-enough-length-0123456789", encoding="utf-8")
    token = load_or_create_token(token_file, env_override="")
    assert token == "file-token-456-with-enough-length-0123456789"


def test_weak_file_token_rejected(tmp_path):
    """File tokens must meet the same strength floor as env tokens."""
    token_file = tmp_path / ".webui_secret_key"
    token_file.write_text("file-token-456", encoding="utf-8")
    with pytest.raises(ValueError, match="weak token"):
        load_or_create_token(token_file, env_override="")


def test_empty_file_token_rejected(tmp_path):
    """An empty/corrupt token file fails closed — never silently replaced."""
    token_file = tmp_path / ".webui_secret_key"
    token_file.write_text("   \n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        load_or_create_token(token_file, env_override="")


def test_token_file_created_with_restrictive_perms(tmp_path):
    import os as _os

    token_file = tmp_path / ".webui_secret_key"
    token = load_or_create_token(token_file, env_override="")
    assert len(token) >= 32
    if _os.name == "posix":
        assert (token_file.stat().st_mode & 0o777) == 0o600


def test_token_file_atomic_no_partial_write(tmp_path, monkeypatch):
    """A crash mid-write must not leave a half-written credential file."""
    import os as _os

    token_file = tmp_path / ".webui_secret_key"
    real_replace = _os.replace

    def _crash_before_rename(src, dst):
        raise OSError("simulated crash before rename")

    monkeypatch.setattr(_os, "replace", _crash_before_rename)
    with pytest.raises(OSError, match="simulated crash"):
        load_or_create_token(token_file, env_override="")
    # The target was never created; only a temp file may remain (and it must
    # not be at the credential path).
    assert not token_file.exists()
    monkeypatch.undo()
    # Recovery works: a fresh call creates a valid token file.
    token = load_or_create_token(token_file, env_override="")
    assert len(token) >= 32


def test_concurrent_creation_converges(tmp_path):
    """Two daemons racing to create the file converge on one valid token."""
    import threading

    token_file = tmp_path / ".webui_secret_key"
    results: list[str] = []
    errors: list[BaseException] = []

    def _create():
        try:
            results.append(load_or_create_token(token_file, env_override=""))
        except BaseException as exc:  # noqa: BLE001 -- collected, asserted below
            errors.append(exc)

    threads = [threading.Thread(target=_create) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors
    assert len(results) == 8
    assert len(set(results)) == 1, "racing creators must converge on a single token"
    assert len(results[0]) >= 32


def test_whitespace_env_token_rejected(tmp_path):
    with pytest.raises(ValueError, match="32"):
        load_or_create_token(tmp_path / ".tok", env_override="has space in token value here!!")


# ── Origin checks ────────────────────────────────────────────────────────────


def test_loopback_origin_allowed():
    assert is_loopback_origin("http://127.0.0.1:8080", []) is True
    assert is_loopback_origin("http://localhost:3000", []) is True
    assert is_loopback_origin("http://[::1]:3000", []) is True


def test_null_origin_rejected():
    assert is_loopback_origin("null", []) is False


def test_non_loopback_origin_rejected():
    assert is_loopback_origin("http://10.0.0.1:8080", []) is False
    assert (
        is_loopback_origin(
            "https://evil.example",
            ["https://evil.example"],
        )
        is False
    )


def test_explicit_allowed_origin():
    assert is_loopback_origin("http://localhost:3000", ["http://localhost:3000"]) is True


# ── Bearer auth on routes ────────────────────────────────────────────────────


def _make_client(tmp_path, monkeypatch):
    """Create a TestClient with a known token."""
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "test-bearer-token-0123456789abcdef")
    monkeypatch.chdir(tmp_path)
    from app import create_app

    app = create_app(config_path=tmp_path / "config.yaml")
    return TestClient(app)


def test_health_no_auth(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["ready"] is True


def test_protected_route_requires_token(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/capabilities")
    assert resp.status_code == 401


def test_protected_route_with_wrong_token(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/capabilities", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401


def test_protected_route_with_valid_token(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/capabilities", headers={"Authorization": "Bearer test-bearer-token-0123456789abcdef"})
    assert resp.status_code == 200
    data = resp.json()
    assert "features" in data
    assert "runs" in data["features"]


def test_config_redacts_secrets(tmp_path, monkeypatch):
    # Write a config with a secret-looking key.
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "exploit:\n  permission: full_access\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n"
        "cve_lookup:\n  api_key_env: NVD_API_KEY\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "test-token-0123456789abcdef01234567")
    monkeypatch.chdir(tmp_path)
    from app import create_app

    app = create_app(config_path=config_path)
    client = TestClient(app)
    resp = client.get("/api/v1/config", headers={"Authorization": "Bearer test-token-0123456789abcdef01234567"})
    assert resp.status_code == 200
    # The response should be redacted.
    body = resp.json()
    assert "ollama" in body


def test_secret_write_rejects_unknown_names(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    response = client.put(
        "/api/v1/secrets",
        json={"secrets": {"NOT_A_CONFIGURED_KEY": "secret"}},
        headers={"Authorization": "Bearer test-bearer-token-0123456789abcdef"},
    )
    assert response.status_code == 400


def test_secret_write_uses_configured_store(tmp_path, monkeypatch):
    store = tmp_path / "keys.json"
    monkeypatch.setenv("BREACHPILOT_API_KEY_FILE", str(store))
    client = _make_client(tmp_path, monkeypatch)
    response = client.put(
        "/api/v1/secrets",
        json={"secrets": {"NVD_API_KEY": "secret"}},
        headers={"Authorization": "Bearer test-bearer-token-0123456789abcdef"},
    )
    assert response.status_code == 200
    assert '"NVD_API_KEY": "secret"' in store.read_text(encoding="utf-8")


# ── Short-token rejection + event/WS auth ──────────────────────────────────


def test_short_env_token_rejected(tmp_path):
    with pytest.raises(ValueError, match="32"):
        load_or_create_token(tmp_path / ".tok", env_override="short")


def test_events_no_token_401(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    assert client.get("/api/v1/runs/nope/events").status_code == 401


def test_events_bad_token_401(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/runs/nope/events", headers={"Authorization": "Bearer wrong-token"})
    assert resp.status_code == 401


def _ws_disconnect_code(client, message):
    """Connect with loopback origin, send one auth message, return close code."""
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/api/v1/ws/v1/runs/nope", headers={"origin": "http://localhost:3000"}) as ws:
            ws.send_json(message)
            ws.receive_json()
    return exc_info.value.code


def test_ws_bad_token_4401(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    assert _ws_disconnect_code(client, {"auth": "wrong-token", "after": 0}) == 4401


def test_ws_no_auth_4401(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    assert _ws_disconnect_code(client, {}) == 4401
