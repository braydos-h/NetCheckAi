"""Tests for the ``run_hash_crack`` MCP tool (idea 8) and the extracted
``_identify_hash_modes`` helper (single source of truth shared with
``hash_crack_identify``).

Covers: the helper's hash-type mapping, registration, auto mode resolution,
the happy path with ``--show`` parsing, and the not-installed friendly message.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from tools.mcp_tools.attack_modules import _identify_hash_modes

# ── Unit: _identify_hash_modes (shared with hash_crack_identify) ──────────────


def test_identify_ntlm_32hex():
    ids = _identify_hash_modes("b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e")
    assert (
        "NTLM",
        "1000",
    )[:2] in [(n, m) for n, m, _ in ids]
    assert any(n == "NTLM" and m == "1000" for n, m, _ in ids)


def test_identify_bcrypt():
    ids = _identify_hash_modes("$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890")
    assert any(n == "bcrypt" and m == "3200" for n, m, _ in ids)


def test_identify_kerberos_tgs():
    ids = _identify_hash_modes("$krb5tgs$23$*user$realm$*hash*")
    assert any(n == "Kerberos 5 TGS-REP" and m == "13100" for n, m, _ in ids)


def test_identify_kerberos_asrep():
    ids = _identify_hash_modes("$krb5asrep$23$user@realm:hash")
    assert any(n == "Kerberos 5 AS-REP" and m == "18200" for n, m, _ in ids)


def test_identify_sha256():
    ids = _identify_hash_modes("a" * 64)
    assert any(n == "SHA2-256" and m == "1400" for n, m, _ in ids)


def test_identify_unknown_returns_empty():
    assert _identify_hash_modes("not-a-real-hash") == []


def test_identify_32hex_reports_ntlm_not_md5():
    """Order matters: a 32-hex hash is NTLM, not MD5 (the MD5 branch only
    fires when nothing earlier matched)."""
    ids = _identify_hash_modes("b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e")
    names = [n for n, _, _ in ids]
    assert "NTLM" in names
    assert "MD5" not in names


# ── Integration: run_hash_crack tool ───────────────────────────────────────────


def _make_server(tmp_path: Path, *, wordlist: str | None = None):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {"exploit": {"require_explicit_allowlist": False}}
    if wordlist is not None:
        config["exploit"]["wordlist"] = wordlist
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
    )


def _make_wordlist(tmp_path: Path) -> str:
    """Create a small wordlist file and return its path (mocked envs lack rockyou)."""
    wl = tmp_path / "wordlist.txt"
    wl.write_text("password\npassword123\nletmein!\n", encoding="utf-8")
    return str(wl)


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


def _patch_pgrp_seq(monkeypatch, returns):
    """Patch ``_run_with_pgrp_timeout`` to pop successive return tuples.

    ``returns`` is a list of ``(returncode, out, err)``; the crack call gets
    the first, the ``--show`` call gets the second (if present).
    """
    import mcp_exploit_server as mes

    seq = list(returns)

    def _fake(args, timeout, stdout=None, stderr=None, cwd=None, env=None, input_text=None, **popen_kwargs):
        if not seq:
            return 0, "", ""
        return seq.pop(0)

    monkeypatch.setattr(mes, "_run_with_pgrp_timeout", _fake)


@pytest.mark.asyncio
async def test_run_hash_crack_is_registered(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    names = {tool.name for tool in await mcp.list_tools()}
    assert "run_hash_crack" in names


@pytest.mark.asyncio
async def test_run_hash_crack_auto_resolves_ntlm_mode(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, wordlist=_make_wordlist(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    captured: list[Any] = []
    import mcp_exploit_server as mes

    def _fake(args, timeout, stdout=None, stderr=None, cwd=None, env=None, input_text=None, **popen_kwargs):
        captured.append(list(args))
        return 0, "", ""

    monkeypatch.setattr(mes, "_run_with_pgrp_timeout", _fake)

    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {"hash_value": "b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e", "tool": "hashcat"},
        )
    )
    assert "CRACK_RESULT:" in text
    # The crack argv auto-resolved the NTLM mode (hashcat -m 1000).
    assert captured, "_run_with_pgrp_timeout was not invoked"
    crack_argv = captured[0]
    assert "-m" in crack_argv
    assert crack_argv[crack_argv.index("-m") + 1] == "1000"
    assert "HASH_TYPE: NTLM" in text


@pytest.mark.asyncio
async def test_run_hash_crack_parses_show_output(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, wordlist=_make_wordlist(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    hash_val = "b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e"
    _patch_pgrp_seq(
        monkeypatch,
        [
            (0, "Session... completed", ""),
            (0, f"{hash_val}:password123\n", ""),
        ],
    )

    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {"hash_value": hash_val, "tool": "hashcat"},
        )
    )
    assert "CRACKED: 1" in text
    assert "password123" in text


@pytest.mark.asyncio
async def test_run_hash_crack_blocks_unidentifiable_hash(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {"hash_value": "zzz-not-a-real-hash", "tool": "hashcat"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "identify" in text


@pytest.mark.asyncio
async def test_run_hash_crack_rejects_unsupported_tool(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {"hash_value": "b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e", "tool": "oclhashcat"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "unsupported tool" in text


@pytest.mark.asyncio
async def test_run_hash_crack_not_installed(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {"hash_value": "b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e", "tool": "hashcat"},
        )
    )
    assert text.startswith("CRACKER_NOT_INSTALLED:")


@pytest.mark.asyncio
async def test_run_hash_crack_john_parses_show(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, wordlist=_make_wordlist(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    _patch_pgrp_seq(
        monkeypatch,
        [
            (0, "Loaded 1 password hash", ""),
            (0, "admin:letmein!\n2g 0:00:00:00 DONE\n", ""),
        ],
    )
    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {"hash_value": "admin:$2a$10$abcdef", "tool": "john", "hash_mode": "3200"},
        )
    )
    assert "CRACKED: 1" in text
    assert "letmein!" in text


@pytest.mark.asyncio
async def test_run_hash_crack_rejects_nondigit_hash_mode(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, wordlist=_make_wordlist(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {
                "hash_value": "b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e",
                "tool": "hashcat",
                "hash_mode": "1000; rm -rf /",
            },
        )
    )
    assert text.startswith("BLOCKED:")
    assert "numeric" in text


@pytest.mark.asyncio
async def test_run_hash_crack_missing_wordlist(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, wordlist=str(tmp_path / "no-such-wordlist.txt"))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {"hash_value": "b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e", "tool": "hashcat"},
        )
    )
    assert text.startswith("WORDLIST_NOT_FOUND:")


@pytest.mark.asyncio
async def test_run_hash_crack_missing_rules_file(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, wordlist=_make_wordlist(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {
                "hash_value": "b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e",
                "tool": "hashcat",
                "rules": str(tmp_path / "no-such-rule.rule"),
            },
        )
    )
    assert text.startswith("RULES_NOT_FOUND:")


@pytest.mark.asyncio
async def test_run_hash_crack_clamps_timeout(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, wordlist=_make_wordlist(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    captured: list[Any] = []
    import mcp_exploit_server as mes

    timeouts: list[Any] = []

    def _fake(args, timeout, stdout=None, stderr=None, cwd=None, env=None, input_text=None, **popen_kwargs):
        captured.append(list(args))
        timeouts.append(timeout)
        return 0, "", ""

    monkeypatch.setattr(mes, "_run_with_pgrp_timeout", _fake)

    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {
                "hash_value": "b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e",
                "tool": "hashcat",
                "timeout": 99999,
            },
        )
    )
    assert "CRACK_RESULT:" in text
    assert captured, "_run_with_pgrp_timeout was not invoked"
    assert timeouts[0] == 3600


@pytest.mark.asyncio
async def test_run_hash_crack_john_unmapped_mode_warns(tmp_path: Path, monkeypatch) -> None:
    mcp = _make_server(tmp_path, wordlist=_make_wordlist(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    captured: list[Any] = []
    import mcp_exploit_server as mes

    def _fake(args, timeout, stdout=None, stderr=None, cwd=None, env=None, input_text=None, **popen_kwargs):
        captured.append(list(args))
        return 0, "", ""

    monkeypatch.setattr(mes, "_run_with_pgrp_timeout", _fake)

    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {
                "hash_value": "b7e4b90b1d8f4a9c3d2e1f0a5b6c7d8e",
                "tool": "john",
                "hash_mode": "22321",
            },
        )
    )
    assert "CRACK_RESULT:" in text
    assert "WARN:" in text
    assert "auto-detect" in text
    # Unmapped mode: no --format flag reaches john (auto-detect instead).
    assert not any(a.startswith("--format=") for a in captured[0])


@pytest.mark.asyncio
async def test_run_hash_crack_caps_hash_value(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, wordlist=_make_wordlist(tmp_path))
    text = _text(
        await mcp.call_tool(
            "run_hash_crack",
            {"hash_value": "a" * 1_000_001, "tool": "hashcat"},
        )
    )
    assert text.startswith("BLOCKED:")
    assert "exceeds" in text
