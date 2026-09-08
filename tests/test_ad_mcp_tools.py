"""Phase 1 — Active Directory / Kerberos MCP tools (tools/mcp_tools/ad.py).

Every tool is target-IP-locked (@require_allowlist + check_targets_allowlist
for any off-target DC) and config-gated (exploit.ad_kerberos.enabled AND the
per-tool flag must both be true, else BLOCKED: ... disabled before the
allowlist). Commands run as argv lists (no shell) via _run_with_pgrp_timeout.
No live network: subprocess.run and shutil.which are monkeypatched.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

_AD_ON = {
    "enabled": True,
    "asrep_roast": True,
    "pass_the_hash": True,
    "adcs_enum": True,
    "bloodhound": True,
    "responder_relay": True,
    "golden_ticket": True,
    "smb_signing_check": True,
}


def _make_server(
    tmp_path: Path,
    *,
    require_allowlist: bool = False,
    allowed_targets: list[str] | None = None,
    ad_kerberos: dict[str, Any] | None = _AD_ON,
):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": require_allowlist,
            "allowed_targets": allowed_targets or [],
        }
    }
    if ad_kerberos is not None:
        config["exploit"]["ad_kerberos"] = ad_kerberos
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


def _capture_run():
    """subprocess.run mock that records argv and returns a successful proc."""
    captured: dict[str, Any] = {}

    def _run(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args")
        captured["argv"] = list(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="ok", stderr="")

    return _run, captured


# ── config-off gate ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_asrep_roast_disabled_when_master_off(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, ad_kerberos={"enabled": False, "asrep_roast": True})
    text = _text(await mcp.call_tool("asrep_roast", {"target_ip": "10.0.0.1", "domain": "corp"}))
    assert "BLOCKED" in text and "asrep_roast disabled" in text


@pytest.mark.asyncio
async def test_asrep_roast_disabled_when_per_tool_off(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, ad_kerberos={"enabled": True, "asrep_roast": False})
    text = _text(await mcp.call_tool("asrep_roast", {"target_ip": "10.0.0.1", "domain": "corp"}))
    assert "BLOCKED" in text and "asrep_roast disabled" in text


# ── asrep_roast ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_asrep_roast_missing_domain(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("asrep_roast", {"target_ip": "10.0.0.1", "domain": ""}))
    assert "BLOCKED" in text and "domain is required" in text


@pytest.mark.asyncio
async def test_asrep_roast_missing_secret_without_usersfile(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("asrep_roast", {"target_ip": "10.0.0.1", "domain": "corp", "username": "u"}))
    assert "BLOCKED" in text and "password or ntlm_hash" in text


@pytest.mark.asyncio
async def test_asrep_roast_offlist_dc_blocked(tmp_path: Path) -> None:
    """A DC other than the runtime target must be allowlist-gated."""
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.1"])
    text = _text(
        await mcp.call_tool(
            "asrep_roast",
            {"target_ip": "10.0.0.1", "domain": "corp", "username": "u", "password": "p", "dc_ip": "10.0.0.99"},
        )
    )
    assert "10.0.0.99" in text and "not in the explicit allowlist" in text


@pytest.mark.asyncio
async def test_asrep_roast_valid_argv(monkeypatch, tmp_path: Path) -> None:
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "asrep_roast",
            {"target_ip": "10.0.0.1", "domain": "corp", "username": "u", "password": "p"},
        )
    )
    assert "ASREP_ROAST_RESULT: completed" in text
    argv = cap["argv"]
    assert argv[0] == "impacket-GetNPUsers"
    assert "-dc-ip" in argv and "10.0.0.1" in argv
    assert "-request" in argv and "-format" in argv and "hashcat" in argv
    assert "corp/u:p@10.0.0.1" in argv
    assert "-outputfile" in argv
    assert "bash" not in argv and "-c" not in argv


# ── pass_the_hash ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pass_the_hash_invalid_hash(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool("pass_the_hash", {"target_ip": "10.0.0.1", "username": "admin", "ntlm_hash": "zzz"})
    )
    assert "BLOCKED" in text and "32 hex chars" in text


@pytest.mark.asyncio
async def test_pass_the_hash_wmiexec_fallback_argv(monkeypatch, tmp_path: Path) -> None:
    """No nxc/crackmapexec on PATH -> impacket-wmiexec fallback (argv list)."""
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "pass_the_hash",
            {
                "target_ip": "10.0.0.1",
                "username": "admin",
                "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "command": "whoami",
            },
        )
    )
    assert "PASS_THE_HASH_RESULT: completed" in text
    argv = cap["argv"]
    assert argv[0] == "impacket-wmiexec"
    assert "-hashes" in argv
    idx = argv.index("-hashes")
    assert argv[idx + 1] == ":31d6cfe0d16ae931b73c59d7e0c089c0"
    assert "admin@10.0.0.1" in argv
    assert "whoami" in argv
    assert "bash" not in argv


@pytest.mark.asyncio
async def test_pass_the_hash_nxc_argv(monkeypatch, tmp_path: Path) -> None:
    """nxc on PATH -> NetExec argv with -H <nt> -x <cmd>."""
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nxc" if name == "nxc" else None)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "pass_the_hash",
            {
                "target_ip": "10.0.0.1",
                "username": "admin",
                "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "command": "whoami",
            },
        )
    )
    assert "PASS_THE_HASH_RESULT: completed" in text
    argv = cap["argv"]
    assert argv[0] == "/usr/bin/nxc"
    assert "smb" in argv and "10.0.0.1" in argv
    assert "-H" in argv and "31d6cfe0d16ae931b73c59d7e0c089c0" in argv
    assert "-x" in argv and "whoami" in argv


# ── smb_signing_check (detection-only, default ON) ──────────────────────────


@pytest.mark.asyncio
async def test_smb_signing_check_disabled_when_master_off(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, ad_kerberos={"enabled": False, "smb_signing_check": True})
    text = _text(await mcp.call_tool("smb_signing_check", {"target_ip": "10.0.0.1"}))
    assert "BLOCKED" in text and "smb_signing_check disabled" in text


@pytest.mark.asyncio
async def test_smb_signing_check_nmap_fallback_argv(monkeypatch, tmp_path: Path) -> None:
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("smb_signing_check", {"target_ip": "10.0.0.1"}))
    assert "SMB_SIGNING_CHECK_RESULT: completed" in text
    argv = cap["argv"]
    assert argv[0] == "nmap"
    assert "--script" in argv and "smb2-security-mode" in argv
    assert "10.0.0.1" in argv


# ── responder_relay (targets from allowlist only) ────────────────────────────


@pytest.mark.asyncio
async def test_responder_relay_targets_built_from_allowlist(monkeypatch, tmp_path: Path) -> None:
    """The relay target file must contain ONLY allowlisted hosts + the runtime target."""
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.1", "10.0.0.2"])
    text = _text(await mcp.call_tool("responder_relay", {"target_ip": "10.0.0.1", "iface": "eth0"}))
    assert "RESPONDER_RELAY_RESULT: completed" in text
    argv = cap["argv"]
    assert argv[0] == "ntlmrelayx.py"
    assert "-tf" in argv
    tf = argv[argv.index("-tf") + 1]
    tf_content = Path(tf).read_text()
    assert "10.0.0.1" in tf_content and "10.0.0.2" in tf_content
    assert "10.0.0.99" not in tf_content  # no off-list host injected
    assert "-smb2support" in argv
    assert "-i" in argv and "eth0" in argv


# ── golden_ticket ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_golden_ticket_missing_sid(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "golden_ticket",
            {
                "target_ip": "10.0.0.1",
                "domain": "corp",
                "username": "admin",
                "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            },
        )
    )
    assert "BLOCKED" in text and "sid" in text.lower()


@pytest.mark.asyncio
async def test_golden_ticket_invalid_krbtgt_hash(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "golden_ticket",
            {"target_ip": "10.0.0.1", "domain": "corp", "username": "admin", "krbtgt_hash": "zz", "sid": "S-1-5-21-1"},
        )
    )
    assert "BLOCKED" in text and "32 hex chars" in text


@pytest.mark.asyncio
async def test_golden_ticket_valid_argv(monkeypatch, tmp_path: Path) -> None:
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "golden_ticket",
            {
                "target_ip": "10.0.0.1",
                "domain": "corp",
                "username": "Administrator",
                "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "sid": "S-1-5-21-1-2-3",
                "duration": "10d",
            },
        )
    )
    assert "GOLDEN_TICKET_RESULT: completed" in text
    argv = cap["argv"]
    assert argv[0] == "impacket-ticketer"
    assert "-nthash" in argv and "31d6cfe0d16ae931b73c59d7e0c089c0" in argv
    assert "-domain" in argv and "corp" in argv
    assert "-domain-sid" in argv and "S-1-5-21-1-2-3" in argv
    assert "-user" in argv and "Administrator" in argv
    assert "-duration" in argv and "10d" in argv
    assert "bash" not in argv


# ── bloodhound_collect ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bloodhound_valid_argv(monkeypatch, tmp_path: Path) -> None:
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "bloodhound_collect",
            {"target_ip": "10.0.0.1", "domain": "corp", "username": "u", "password": "p"},
        )
    )
    assert "BLOODHOUND_COLLECT_RESULT: completed" in text
    argv = cap["argv"]
    assert argv[0] == "bloodhound-python"
    assert "-u" in argv and "u" in argv
    assert "-d" in argv and "corp" in argv
    assert "-dc" in argv and "10.0.0.1" in argv
    assert "-c" in argv and "All" in argv
    assert "--zip" in argv
    assert "bash" not in argv


@pytest.mark.asyncio
async def test_bloodhound_offlist_dc_blocked(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path, require_allowlist=True, allowed_targets=["10.0.0.1"])
    text = _text(
        await mcp.call_tool(
            "bloodhound_collect",
            {"target_ip": "10.0.0.1", "domain": "corp", "username": "u", "password": "p", "dc_ip": "10.0.0.50"},
        )
    )
    assert "10.0.0.50" in text and "not in the explicit allowlist" in text


# ── adcs_enum ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_adcs_enum_valid_argv(monkeypatch, tmp_path: Path) -> None:
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "adcs_enum",
            {"target_ip": "10.0.0.1", "domain": "corp", "username": "u", "password": "p"},
        )
    )
    assert "ADCS_ENUM_RESULT: completed" in text
    argv = cap["argv"]
    assert argv[0] == "certipy"
    assert "find" in argv
    assert "-u" in argv and "u@corp" in argv
    assert "-dc-ip" in argv and "10.0.0.1" in argv
    assert "-target" in argv and "10.0.0.1" in argv
    assert "bash" not in argv


# ── output-tail truncation marker (RULE-LOCK-FIRST output side) ─────────────


def test_tail_marks_only_trimmed_output() -> None:
    from tools.mcp_tools.ad import _OUTPUT_CHARS, _tail

    short = "ok"
    assert _tail(short) == short
    exact = "A" * _OUTPUT_CHARS
    assert _tail(exact) == exact
    long = "A" * (_OUTPUT_CHARS + 100)
    marked = _tail(long)
    assert marked.endswith("\n[truncated]")
    assert len(marked) == _OUTPUT_CHARS + len("\n[truncated]")


@pytest.mark.asyncio
async def test_long_tool_output_carries_truncated_marker(monkeypatch, tmp_path: Path) -> None:
    def _run_long(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args")
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="A" * 6000, stderr="")

    monkeypatch.setattr(subprocess, "run", _run_long)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("smb_signing_check", {"target_ip": "10.0.0.1"}))
    assert "SMB_SIGNING_CHECK_RESULT: completed" in text
    assert "[truncated]" in text


@pytest.mark.asyncio
async def test_short_tool_output_has_no_truncated_marker(monkeypatch, tmp_path: Path) -> None:
    run, _ = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("smb_signing_check", {"target_ip": "10.0.0.1"}))
    assert "[truncated]" not in text


@pytest.mark.asyncio
async def test_failed_rc_preserved_in_result(monkeypatch, tmp_path: Path) -> None:
    def _run_fail(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args")
        return subprocess.CompletedProcess(args=argv, returncode=3, stdout="nope", stderr="")

    monkeypatch.setattr(subprocess, "run", _run_fail)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("smb_signing_check", {"target_ip": "10.0.0.1"}))
    assert "SMB_SIGNING_CHECK_RESULT: failed" in text
    assert "EXIT_CODE: 3" in text


# ── iface / command caps / duration / sid / users_file ──────────────────────


@pytest.mark.asyncio
async def test_responder_relay_invalid_iface(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("responder_relay", {"target_ip": "10.0.0.1", "iface": "eth0; rm -rf /"}))
    assert "BLOCKED" in text and "iface" in text


@pytest.mark.asyncio
async def test_responder_relay_command_over_cap(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(await mcp.call_tool("responder_relay", {"target_ip": "10.0.0.1", "command": "x" * 2001}))
    assert "BLOCKED" in text and "2000" in text


@pytest.mark.asyncio
async def test_pass_the_hash_command_over_cap(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "pass_the_hash",
            {
                "target_ip": "10.0.0.1",
                "username": "admin",
                "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "command": "y" * 2001,
            },
        )
    )
    assert "BLOCKED" in text and "2000" in text


@pytest.mark.asyncio
async def test_asrep_roast_users_file_not_found(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "asrep_roast",
            {"target_ip": "10.0.0.1", "domain": "corp", "users_file": str(tmp_path / "nope.txt")},
        )
    )
    assert "BLOCKED" in text and "users_file not found" in text


@pytest.mark.asyncio
async def test_golden_ticket_rejects_non_domain_sid(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "golden_ticket",
            {
                "target_ip": "10.0.0.1",
                "domain": "corp",
                "username": "admin",
                "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "sid": "S-1-5-32-544",
            },
        )
    )
    assert "BLOCKED" in text and "sid" in text.lower()


@pytest.mark.asyncio
async def test_golden_ticket_invalid_duration(tmp_path: Path) -> None:
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "golden_ticket",
            {
                "target_ip": "10.0.0.1",
                "domain": "corp",
                "username": "admin",
                "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "sid": "S-1-5-21-1-2-3",
                "duration": "ten-days",
            },
        )
    )
    assert "BLOCKED" in text and "duration" in text.lower()


@pytest.mark.asyncio
async def test_golden_ticket_duration_clamped(monkeypatch, tmp_path: Path) -> None:
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "golden_ticket",
            {
                "target_ip": "10.0.0.1",
                "domain": "corp",
                "username": "Administrator",
                "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "sid": "S-1-5-21-1-2-3",
                "duration": "99999d",
            },
        )
    )
    assert "GOLDEN_TICKET_RESULT: completed" in text
    argv = cap["argv"]
    idx = argv.index("-duration")
    assert argv[idx + 1] == "3650d"


@pytest.mark.asyncio
async def test_golden_ticket_ccache_rooted_at_attempt_dir(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def _run_kw(*args, **kwargs):
        captured["argv"] = list(args[0] if args else kwargs.get("args"))
        captured["cwd"] = kwargs.get("cwd")
        captured["env"] = kwargs.get("env") or {}
        argv = captured["argv"]
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", _run_kw)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(tmp_path)
    text = _text(
        await mcp.call_tool(
            "golden_ticket",
            {
                "target_ip": "10.0.0.1",
                "domain": "corp",
                "username": "Administrator",
                "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "sid": "S-1-5-21-1-2-3",
            },
        )
    )
    assert "GOLDEN_TICKET_RESULT: completed" in text
    assert captured["cwd"] and "KRB5CCNAME" in captured["env"]
    assert captured["env"]["KRB5CCNAME"].startswith(captured["cwd"])
    assert captured["env"]["KRB5CCNAME"].endswith(".ccache")


@pytest.mark.asyncio
async def test_responder_relay_keeps_domain_cidr_verbatim(monkeypatch, tmp_path: Path) -> None:
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda name: None)
    mcp = _make_server(
        tmp_path,
        require_allowlist=True,
        allowed_targets=["corp.example.com", "10.0.1.0/24"],
    )
    text = _text(await mcp.call_tool("responder_relay", {"target_ip": "10.0.1.5"}))
    assert "RESPONDER_RELAY_RESULT: completed" in text
    argv = cap["argv"]
    tf = argv[argv.index("-tf") + 1]
    tf_content = Path(tf).read_text()
    tf_lines = {line.strip() for line in tf_content.splitlines() if line.strip()}
    assert "corp.example.com" in tf_lines
    assert "10.0.1.0/24" in tf_lines
    assert "10.0.1.5" in tf_lines


# ── registration ─────────────────────────────────────────────────────────────


def test_ad_modules_registered() -> None:
    from tools.attack_modules import registry

    for name in ("ADCSEnum", "BloodHoundCollect", "ResponderRelay", "GoldenTicket", "SMBSigningCheck"):
        assert registry.get_module(name) is not None, f"{name} not registered"


# ── P3-12: canary-secret audit proof ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_asrep_roast_password_never_reaches_audit_log(monkeypatch, tmp_path: Path) -> None:
    """P3-12 exit proof: a canary password passed to an effects-path tool
    must not appear in exploit_audit.jsonl (arg redaction at the audit
    layer). The tool itself still receives the real secret (argv proves it)."""
    run, cap = _capture_run()
    monkeypatch.setattr(subprocess, "run", run)
    mcp = _make_server(tmp_path)
    canary = "CANARY-P3-12-hunter2-secret"
    text = _text(
        await mcp.call_tool(
            "asrep_roast",
            {"target_ip": "10.0.0.1", "domain": "corp", "username": "u", "password": canary},
        )
    )
    assert "ASREP_ROAST_RESULT: completed" in text
    # The tool got the real secret (functional path intact).
    assert any(canary in str(a) for a in cap["argv"])
    # The audit trail did not.
    audit = tmp_path / "exploit_audit.jsonl"
    assert audit.exists()
    raw = audit.read_text(encoding="utf-8")
    assert canary not in raw
