"""Tier 1 regression tests: tool-layer IP-scope enforcement on the
``@audit_tool``-only offensive MCP tools (msfconsole_command,
msf_interact_session, msf_run_resource_script, msf_generate_payload,
generate_payload).

These tools take free-text command strings (or an ``lhost`` callback host)
instead of a structured ``target_ip`` arg, so ``@require_allowlist`` (which
inspects ``target_ip``) does not fit them. Previously they were decorated
``@audit_tool`` only -- audit writes, never a block -- so a direct MCP client
bypassing the agent loop's ``ExploitPolicy.approve_action`` could target an
out-of-scope host. The fix extracts RHOSTS/RHOST (or lhost) and runs them
through ``check_targets_allowlist`` at the top of each tool, returning a
``BLOCKED:`` marker for any host outside ``exploit.allowed_targets``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools.mcp_shared import _extract_msf_rhosts, check_targets_allowlist

# ── Unit: extraction + allowlist helper ───────────────────────────────────────


def test_extract_msf_rhosts_finds_rhosts_and_rhost():
    assert _extract_msf_rhosts("set RHOSTS 10.0.0.99") == ["10.0.0.99"]
    assert _extract_msf_rhosts("set RHOST 10.0.0.99") == ["10.0.0.99"]
    # setg (global set) too
    assert _extract_msf_rhosts("setg RHOSTS 10.0.0.99") == ["10.0.0.99"]
    # multiple, with quotes -- quotes are stripped so the bare IP reaches the
    # allowlist matcher (a quoted token would never match is_target_in_allowlist).
    out = _extract_msf_rhosts('set RHOSTS "10.0.0.99"; set RHOST 10.0.0.50')
    assert out == ["10.0.0.99", "10.0.0.50"]


def test_extract_msf_rhosts_empty_when_no_rhosts():
    # ``sessions -l`` names no host -> nothing to scope-check.
    assert _extract_msf_rhosts("sessions -l") == []
    assert _extract_msf_rhosts("") == []


def test_check_targets_allowlist_allowlist_not_required():
    # Empty union + flag off: nothing to enforce against (permissive).
    cfg = {"exploit": {"require_explicit_allowlist": False, "allowed_targets": []}}
    allowed, reason = check_targets_allowlist(["10.0.0.99"], cfg)
    assert allowed is True
    assert "no allowlist configured" in reason


def test_check_targets_allowlist_empty_targets_allowed():
    cfg = {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.50"]}}
    # A tool call naming no host touches no target -> allowed.
    allowed, _ = check_targets_allowlist([], cfg)
    assert allowed is True


def test_check_targets_allowlist_blocks_out_of_scope():
    cfg = {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.50"]}}
    allowed, reason = check_targets_allowlist(["10.0.0.99"], cfg)
    assert allowed is False
    assert "10.0.0.99" in reason


def test_check_targets_allowlist_allows_in_scope():
    cfg = {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.50"]}}
    allowed, _ = check_targets_allowlist(["10.0.0.50"], cfg)
    assert allowed is True


def test_check_targets_allowlist_empty_allowed_targets_blocks():
    cfg = {"exploit": {"require_explicit_allowlist": True, "allowed_targets": []}}
    allowed, reason = check_targets_allowlist(["10.0.0.50"], cfg)
    assert allowed is False
    assert "allowed_targets is empty" in reason


# ── Integration: registered tools block out-of-scope hosts ─────────────────────


def _make_server(
    tmp_path: Path,
    *,
    require_allowlist: bool = True,
    allowed_targets: list[str] | None = None,
):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": require_allowlist,
            "allowed_targets": allowed_targets if allowed_targets is not None else ["10.0.0.50"],
        }
    }
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
    )


def _text(result) -> str:
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


@pytest.mark.asyncio
async def test_msfconsole_command_blocks_out_of_scope_rhosts(tmp_path: Path):
    mcp = _make_server(tmp_path, allowed_targets=["10.0.0.50"])
    text = _text(
        await mcp.call_tool(
            "msfconsole_command",
            {"command": "use exploit/multi/handler; set RHOSTS 10.0.0.99; run"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "10.0.0.99" in text


@pytest.mark.asyncio
async def test_msfconsole_command_blocks_out_of_scope_rhost(tmp_path: Path):
    mcp = _make_server(tmp_path, allowed_targets=["10.0.0.50"])
    text = _text(
        await mcp.call_tool(
            "msfconsole_command",
            {"command": "set RHOST 10.0.0.99"},
        )
    )
    assert text.startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_msf_run_resource_script_blocks_out_of_scope_rhosts(tmp_path: Path):
    mcp = _make_server(tmp_path, allowed_targets=["10.0.0.50"])
    text = _text(
        await mcp.call_tool(
            "msf_run_resource_script",
            {"script_content": "use auxiliary/scanner/portscan/tcp\nset RHOSTS 10.0.0.99\nrun"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "10.0.0.99" in text


@pytest.mark.asyncio
async def test_msf_generate_payload_blocks_out_of_scope_lhost(tmp_path: Path):
    mcp = _make_server(tmp_path, allowed_targets=["10.0.0.50"])
    text = _text(
        await mcp.call_tool(
            "msf_generate_payload",
            {"payload_type": "windows/x64/meterpreter/reverse_tcp", "lhost": "10.0.0.99", "lport": 4444, "fmt": "exe"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "10.0.0.99" in text


@pytest.mark.asyncio
async def test_generate_payload_blocks_out_of_scope_lhost(tmp_path: Path):
    mcp = _make_server(tmp_path, allowed_targets=["10.0.0.50"])
    text = _text(
        await mcp.call_tool(
            "generate_payload",
            {
                "payload_type": "reverse_tcp",
                "lhost": "10.0.0.99",
                "lport": 4444,
                "format": "raw",
                "platform": "linux",
                "arch": "x64",
            },
        )
    )
    assert text.startswith("BLOCKED:")
    assert "10.0.0.99" in text


@pytest.mark.asyncio
async def test_msfconsole_command_passes_scope_when_no_rhosts(tmp_path: Path, monkeypatch):
    """A command that names no host (e.g. ``sessions -l``) touches no target and
    must pass the scope gate (then proceed to the bridge, which we mock)."""
    mcp = _make_server(tmp_path, allowed_targets=["10.0.0.50"])

    class _FakeBridge:
        def console_command(self, command, wait_seconds, read_lines):
            return {"success": True, "output": "mocked"}

    import tools.mcp_tools.metasploit as msf_mod

    monkeypatch.setattr(msf_mod, "get_metasploit_bridge", lambda ws: _FakeBridge())

    text = _text(
        await mcp.call_tool(
            "msfconsole_command",
            {"command": "sessions -l"},
        )
    )
    assert text.startswith("MSFCONSOLE_COMMAND:")
    assert "BLOCKED:" not in text
