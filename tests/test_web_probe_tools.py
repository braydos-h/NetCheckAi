"""Tests for the web-probe MCP tools (``tools/mcp_tools/modules/web.py``).

Covers the family hardening: port range (1-65535), CR/LF rejection on
``target_ip``/``endpoint``, concurrent fan-out cap (2-100), per-tool
timeout/deadline handling, socket cleanup (context-manager close),
IPv6/domain targets, and sprayed-password redaction. All network I/O is
mocked (``socket.create_connection``); ``time.sleep`` is stubbed so the
paced sweeps run instantly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


class _FakeSock:
    """Minimal socket stub usable as a context manager (tracks close + bytes sent)."""

    instances: list["_FakeSock"] = []

    def __init__(self, recv_bytes: bytes = b"HTTP/1.0 200 OK\r\n\r\nnothing interesting"):
        self._recv = recv_bytes
        self.sent = b""
        self.closed = False
        _FakeSock.instances.append(self)

    def __enter__(self) -> "_FakeSock":
        return self

    def __exit__(self, *args: Any) -> bool:
        self.close()
        return False

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, n: int) -> bytes:
        chunk, self._recv = self._recv[:n], self._recv[n:]
        return chunk

    def close(self) -> None:
        self.closed = True


def _make_server(tmp_path: Path, *, require_allowlist: bool = False):
    """Build an MCP server with the web-probe tools registered (allowlist off by default)."""
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        {
            "exploit": {
                "require_explicit_allowlist": require_allowlist,
                "allowed_targets": ["10.0.0.50"],
            },
            "skills": {"enabled": False},
            "multi_model": {"enabled": False},
        },
    )


def _text(result: Any) -> str:
    """Extract text from an MCP CallToolResult (tuple or object form)."""
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts = []
    for c in content:
        t = getattr(c, "text", None)
        if t is None and isinstance(c, dict):
            t = c.get("text")
        if t is None:
            t = str(c)
        parts.append(t)
    return "".join(parts)


@pytest.fixture(autouse=True)
def _no_sleep():
    with patch("time.sleep", return_value=None):
        yield


@pytest.fixture(autouse=True)
def _clear_socks():
    _FakeSock.instances.clear()
    yield
    _FakeSock.instances.clear()


def _conn(recv: bytes = b"HTTP/1.0 200 OK\r\n\r\nnothing interesting"):
    return patch("socket.create_connection", side_effect=lambda *a, **k: _FakeSock(recv))


# ── port range ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ssti_probe_rejects_port_zero(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("ssti_probe", {"target_ip": "10.0.0.50", "port": 0}))
    assert text.startswith("BLOCKED:")
    assert "port" in text


@pytest.mark.asyncio
async def test_ssti_probe_rejects_port_above_max(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("ssti_probe", {"target_ip": "10.0.0.50", "port": 70000}))
    assert text.startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_ssti_probe_rejects_non_numeric_port(tmp_path: Path):
    """A non-numeric port never reaches the tool body: the FastMCP/pydantic
    schema layer rejects it fail-closed first (ToolError, no socket opened)."""
    from mcp.server.fastmcp.exceptions import ToolError

    mcp = _make_server(tmp_path)
    with pytest.raises(ToolError):
        await mcp.call_tool("ssti_probe", {"target_ip": "10.0.0.50", "port": "abc"})


@pytest.mark.asyncio
async def test_graphql_rejects_port_out_of_range(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("graphql_introspect", {"target_ip": "10.0.0.50", "port": 65536}))
    assert text.startswith("BLOCKED:")


# ── CR/LF rejection ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_target_ip_crlf_rejected_without_socket(tmp_path: Path):
    mcp = _make_server(tmp_path)
    with patch("socket.create_connection") as mock_conn:
        text = _text(
            await mcp.call_tool("ssti_probe", {"target_ip": "10.0.0.50\r\n evil", "port": 80, "timeout": 5})
        )
    assert text.startswith("BLOCKED:")
    assert "CR/LF" in text
    mock_conn.assert_not_called()


@pytest.mark.asyncio
async def test_race_endpoint_crlf_rejected(tmp_path: Path):
    mcp = _make_server(tmp_path)
    with patch("socket.create_connection") as mock_conn:
        text = _text(
            await mcp.call_tool(
                "race_request",
                {"target_ip": "10.0.0.50", "port": 80, "endpoint": "/api/x\r\nInjected: 1"},
            )
        )
    assert text.startswith("BLOCKED:")
    mock_conn.assert_not_called()


@pytest.mark.asyncio
async def test_race_endpoint_must_be_absolute_path(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "race_request",
            {"target_ip": "10.0.0.50", "port": 80, "endpoint": "http://evil.example/"},
        )
    )
    assert text.startswith("BLOCKED:")


# ── concurrent cap ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_race_rejects_concurrent_below_min(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("race_request", {"target_ip": "10.0.0.50", "concurrent": 1}))
    assert text.startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_race_rejects_concurrent_above_max(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("race_request", {"target_ip": "10.0.0.50", "concurrent": 200}))
    assert text.startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_race_happy_path_small_fanout(tmp_path: Path):
    mcp = _make_server(tmp_path)
    with _conn(b"HTTP/1.0 200 OK\r\n\r\n{}"):
        text = _text(
            await mcp.call_tool(
                "race_request",
                {"target_ip": "10.0.0.50", "port": 80, "endpoint": "/api/redeem", "concurrent": 2},
            )
        )
    assert "RACE_REQUEST_RESULTS:" in text
    assert "Success: 2" in text


# ── IPv6 / domain targets + socket cleanup ────────────────────────────────────


@pytest.mark.asyncio
async def test_graphql_domain_target_and_sockets_closed(tmp_path: Path):
    mcp = _make_server(tmp_path)
    body = b'HTTP/1.0 200 OK\r\n\r\n{"data":{"__schema":{"queryType":{"name":"Q"},"types":[{"name":"User"}]}}}'
    with _conn(body):
        text = _text(
            await mcp.call_tool("graphql_introspect", {"target_ip": "example.com", "port": 80, "timeout": 10})
        )
    assert "GRAPHQL_INTROSPECT_RESULTS: example.com:80" in text
    assert "Introspection ENABLED" in text
    assert _FakeSock.instances, "expected at least one socket to have opened"
    assert all(s.closed for s in _FakeSock.instances), "every socket must be closed (context manager)"


@pytest.mark.asyncio
async def test_ssti_ipv6_target_bracketed_host_header(tmp_path: Path):
    mcp = _make_server(tmp_path)
    with _conn(b"HTTP/1.0 200 OK\r\n\r\n49"):
        text = _text(await mcp.call_tool("ssti_probe", {"target_ip": "::1", "port": 80, "timeout": 10}))
    assert "SSTI_PROBE_RESULTS: ::1:80" in text
    assert _FakeSock.instances
    assert b"Host: [::1]" in _FakeSock.instances[0].sent
    assert all(s.closed for s in _FakeSock.instances)


@pytest.mark.asyncio
async def test_invalid_target_rejected(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("timing_oracle", {"target_ip": "not a target!!", "port": 80}))
    assert text.startswith("BLOCKED:")


# ── password redaction ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_password_spray_redacts_password(tmp_path: Path):
    mcp = _make_server(tmp_path)
    secret = "Sup3rS3cretPw-9z"
    with _conn(b"HTTP/1.0 401 Unauthorized\r\n\r\nno"):
        text = _text(
            await mcp.call_tool(
                "password_spray",
                {"target_ip": "10.0.0.50", "port": 80, "password": secret, "timeout": 60},
            )
        )
    assert "PASSWORD_SPRAY_RESULTS:" in text
    assert secret not in text, "sprayed password must never appear in display output"
    assert "[redacted]" in text


@pytest.mark.asyncio
async def test_password_spray_success_lists_user_not_password(tmp_path: Path):
    mcp = _make_server(tmp_path)
    secret = "An0therS3cret-42"
    with _conn(b"HTTP/1.0 200 OK\r\n\r\n{\"token\": \"abc\"}"):
        text = _text(
            await mcp.call_tool(
                "password_spray",
                {"target_ip": "10.0.0.50", "port": 80, "password": secret, "timeout": 120},
            )
        )
    assert "SUCCESS" in text
    assert secret not in text


# ── timeout / deadline ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_timing_oracle_reports_insufficient_samples_at_deadline(tmp_path: Path, monkeypatch):
    """With the clock already past the deadline, sampling stops immediately."""
    import tools.mcp_tools.modules.web as web_mod

    mcp = _make_server(tmp_path)
    real_monotonic = web_mod.time.monotonic
    start = real_monotonic()
    # First call (deadline computation) uses the real clock; every later call
    # reports a time far in the future so every sample loop exits at once.
    calls = {"n": 0}

    def _fake() -> float:
        calls["n"] += 1
        if calls["n"] <= 1:
            return start
        return start + 10_000.0

    monkeypatch.setattr(web_mod.time, "monotonic", _fake)
    with _conn():
        text = _text(await mcp.call_tool("timing_oracle", {"target_ip": "10.0.0.50", "timeout": 60}))
    assert "TIMING_ORACLE_RESULTS:" in text
    assert "Insufficient samples." in text


@pytest.mark.asyncio
async def test_jwt_tamper_rejects_invalid_format(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("jwt_tamper", {"target_ip": "10.0.0.50", "jwt_token": "not-a-jwt"}))
    assert "Invalid JWT format" in text


@pytest.mark.asyncio
async def test_jwt_tamper_requires_target(tmp_path: Path):
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("jwt_tamper", {"target_ip": "", "jwt_token": "a.b.c"}))
    assert text.startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_request_smuggling_baseline_envelope(tmp_path: Path):
    mcp = _make_server(tmp_path)
    with _conn(b"HTTP/1.0 200 OK\r\n\r\nbaseline"):
        text = _text(
            await mcp.call_tool("request_smuggling_probe", {"target_ip": "10.0.0.50", "port": 80, "timeout": 30})
        )
    assert "REQUEST_SMUGGLING_RESULTS: 10.0.0.50:80" in text
    assert "Baseline:" in text
    assert all(s.closed for s in _FakeSock.instances)
