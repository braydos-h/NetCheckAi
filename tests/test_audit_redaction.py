"""Regression tests for audit-log credential redaction (Tier 0 item 0.3, Phase A).

The exploit audit trail (``exploit_audit.jsonl``) is append-only plaintext on the
operator's host. Before this fix, any ``password`` / ``ntlm_hash`` the LLM
supplied to ``lateral_exec`` / ``dump_credentials`` / ``kerberoast`` landed in
that file in cleartext. These tests pin the contract:

1. ``_redact_args`` masks secret-named values, preserves everything else, is
   case-insensitive, and walks one level into dict-valued args.
2. The ``make_require_allowlist`` / ``make_audit_tool`` decorators route their
   ``bound.arguments`` through ``_redact_args`` on *every* audit write (started,
   completed, and blocked), so a synthetic tool with secret params writes
   ``***REDACTED***`` to disk -- never the cleartext.
3. End-to-end: the real ``dump_credentials`` MCP tool, blocked at preflight by an
   empty explicit allowlist, still logs its (redacted) args -- proving the real
   tool path can't leak credentials even when the call is denied.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.mcp_shared import (
    _REDACTED,
    _mask_secret_content,
    _redact_args,
    _redact_nested,
    make_audit_tool,
    make_require_allowlist,
)

# ── 1. _redact_args unit coverage ───────────────────────────────────────────


def test_redact_password_and_ntlm_hash():
    out = _redact_args(
        {"target_ip": "10.0.0.50", "username": "admin", "password": "S3cr3t!", "ntlm_hash": "aad3b435:31d6..."}
    )
    assert out["password"] == _REDACTED
    assert out["ntlm_hash"] == _REDACTED
    # non-secret context preserved for forensics
    assert out["target_ip"] == "10.0.0.50"
    assert out["username"] == "admin"


def test_redact_token_apikey_credential_private_key():
    out = _redact_args(
        {"api_key": "AKIA...", "token": "Bearer xyz", "credentials": "creds-blob", "private_key": "-----BEGIN"}
    )
    assert out["api_key"] == _REDACTED
    assert out["token"] == _REDACTED
    assert out["credentials"] == _REDACTED
    assert out["private_key"] == _REDACTED


def test_redact_is_case_insensitive():
    out = _redact_args({"Password": "p", "NTLM_HASH": "h", "ApiKey": "k", "Ntlm": "n", "HASH": "x"})
    assert out["Password"] == _REDACTED
    assert out["NTLM_HASH"] == _REDACTED
    assert out["ApiKey"] == _REDACTED
    assert out["Ntlm"] == _REDACTED
    assert out["HASH"] == _REDACTED


def test_preserves_benign_args_intact():
    args = {
        "target_ip": "10.0.0.50",
        "command": "nmap -sV 10.0.0.50",
        "domain": "CORP",
        "dc_ip": "10.0.0.50",
        "method": "psexec",
        "filename": "loot.py",
        "port": 445,
        "options": {"LHOST": "1.2.3.4"},
    }
    out = _redact_args(args)
    for k in args:
        assert out[k] == args[k], k


def test_nested_dict_options_masks_secret_key():
    # run_msf_module / generate_payload take an options dict that may carry
    # PASSWORD/PASS keys -- the one-level walk must mask those, keep the rest.
    out = _redact_args({"options": {"LHOST": "10.0.0.50", "LPORT": 4444, "PASSWORD": "hunter2", "pass": "x"}})
    opts = out["options"]
    assert opts["LHOST"] == "10.0.0.50"
    assert opts["LPORT"] == 4444
    assert opts["PASSWORD"] == _REDACTED
    assert opts["pass"] == _REDACTED


def test_redact_nested_directly():
    assert _redact_nested({"PASSWORD": "x", "y": 1})["PASSWORD"] == _REDACTED
    assert _redact_nested({"PASSWORD": "x", "y": 1})["y"] == 1
    assert _redact_nested("plain") == "plain"
    assert _redact_nested(42) == 42


def test_none_and_empty_return_empty_dict():
    assert _redact_args(None) == {}
    assert _redact_args({}) == {}


def test_returns_independent_copy():
    args = {"password": "p", "target_ip": "1.2.3.4"}
    out = _redact_args(args)
    assert out is not args
    args["target_ip"] = "9.9.9.9"
    assert out["target_ip"] == "1.2.3.4"  # copy, not a reference


# ── 2. Decorator-level integration (synthetic tools) ─────────────────────────


def _read_audit(workspace: Path) -> list[dict[str, Any]]:
    audit = workspace / "exploit_audit.jsonl"
    if not audit.exists():
        return []
    return [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.mark.asyncio
async def test_require_allowlist_redacts_secret_on_async_started(tmp_path: Path):
    workspace = tmp_path
    config = {"exploit": {"require_explicit_allowlist": False, "allowed_targets": []}}
    require = make_require_allowlist(workspace, config)

    @require(target_param="target_ip")
    async def cred_tool(target_ip: str, password: str, ntlm_hash: str, command: str) -> str:
        return "ok"

    await cred_tool(target_ip="10.0.0.50", password="cleartext-secret", ntlm_hash="aad3:31d6", command="whoami")
    records = _read_audit(workspace)
    started = [r for r in records if r["status"] == "started"]
    completed = [r for r in records if r["status"] == "completed"]
    assert started and completed
    for rec in started + completed:
        assert rec["args"]["password"] == _REDACTED
        assert rec["args"]["ntlm_hash"] == _REDACTED
        assert rec["args"]["target_ip"] == "10.0.0.50"
        assert rec["args"]["command"] == "whoami"


def test_require_allowlist_redacts_secret_on_sync_blocked(tmp_path: Path):
    # When the call is DENIED at preflight the args are still logged (status
    # "blocked") -- they must still be redacted.
    workspace = tmp_path
    config = {"exploit": {"require_explicit_allowlist": True, "allowed_targets": []}}
    require = make_require_allowlist(workspace, config)

    @require(target_param="target_ip")
    def cred_tool(target_ip: str, password: str, ntlm_hash: str) -> str:
        return "should-not-run"

    out = cred_tool(target_ip="10.0.0.50", password="denied-secret", ntlm_hash="hashval")
    assert "BLOCKED" in out
    records = _read_audit(workspace)
    blocked = [r for r in records if r["status"] == "blocked"]
    assert blocked, "blocked preflight must still write an audit record"
    assert blocked[0]["args"]["password"] == _REDACTED
    assert blocked[0]["args"]["ntlm_hash"] == _REDACTED


@pytest.mark.asyncio
async def test_audit_tool_redacts_secret_for_non_targeted_tool(tmp_path: Path):
    # make_audit_tool has no target_ip -- still routes args through _redact_args.
    workspace = tmp_path
    audit_tool = make_audit_tool(workspace)

    @audit_tool
    async def store_credential(api_key: str, label: str) -> str:
        return "stored"

    await store_credential(api_key="AKIA-plaintext", label="aws-prod")
    records = _read_audit(workspace)
    for rec in records:
        assert rec["args"]["api_key"] == _REDACTED
        assert rec["args"]["label"] == "aws-prod"


# ── M9: make_audit_tool is result-aware (blocked marker -> approved=False) ──


@pytest.mark.asyncio
async def test_audit_tool_records_blocked_on_blocked_result_async(tmp_path: Path):
    """An async tool returning a BLOCKED marker is audited approved=False / blocked."""
    workspace = tmp_path
    audit_tool = make_audit_tool(workspace)

    @audit_tool
    async def blocked_tool(cmd: str) -> str:
        return "BLOCKED: destructive action denied\nATTEMPT_ID: preflight"

    out = await blocked_tool(cmd="rm -rf /")
    assert "BLOCKED" in out
    records = _read_audit(workspace)
    started = [r for r in records if r["status"] == "started"]
    completed = [r for r in records if r["status"] == "completed"]
    blocked = [r for r in records if r["status"] == "blocked"]
    assert started, "started record always written"
    assert not completed, "a blocked result must NOT be recorded as completed"
    assert blocked, "a blocked result must write a blocked completion record"
    assert blocked[0]["approved"] is False
    assert blocked[0]["tool_name"] == "blocked_tool"


@pytest.mark.asyncio
async def test_audit_tool_records_completed_on_normal_result_async(tmp_path: Path):
    """An async tool returning a normal (non-blocked) result is audited approved=True."""
    workspace = tmp_path
    audit_tool = make_audit_tool(workspace)

    @audit_tool
    async def ok_tool(cmd: str) -> str:
        return "ok"

    await ok_tool(cmd="ls")
    records = _read_audit(workspace)
    completed = [r for r in records if r["status"] == "completed"]
    blocked = [r for r in records if r["status"] == "blocked"]
    assert completed and not blocked
    assert completed[0]["approved"] is True


def test_audit_tool_records_blocked_on_blocked_result_sync(tmp_path: Path):
    """A sync tool returning a BLOCKED marker is audited approved=False / blocked."""
    workspace = tmp_path
    audit_tool = make_audit_tool(workspace)

    @audit_tool
    def blocked_tool(cmd: str) -> str:
        return "TERMINAL_RESULT: BLOCKED by safety reviewer"

    out = blocked_tool(cmd="dd if=/dev/zero of=/dev/sda")
    assert "BLOCKED" in out
    records = _read_audit(workspace)
    blocked = [r for r in records if r["status"] == "blocked"]
    completed = [r for r in records if r["status"] == "completed"]
    assert blocked and not completed
    assert blocked[0]["approved"] is False


def test_audit_tool_records_blocked_on_root_cmd_result_marker(tmp_path: Path):
    """The ROOT_CMD_RESULT: marker is treated as blocked (per plan M9)."""
    from tools.mcp_shared import _result_is_blocked

    assert _result_is_blocked("ROOT_CMD_RESULT: blocked destructive")
    assert _result_is_blocked("  blocked: lowercase prefix still matched")
    assert not _result_is_blocked("ok")
    assert not _result_is_blocked("")
    assert not _result_is_blocked(None)
    assert not _result_is_blocked(123)


# ── 3. End-to-end: the real dump_credentials MCP tool ─────────────────────────


def _make_server(tmp_path: Path, *, require_allowlist: bool = True):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {"exploit": {"require_explicit_allowlist": require_allowlist, "allowed_targets": []}}
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
    )


@pytest.mark.asyncio
async def test_real_dump_credentials_cleartext_never_reaches_audit(tmp_path: Path):
    """The real cred-harvest tool, denied at preflight, must still log redacted args."""
    mcp = _make_server(tmp_path)  # require_explicit_allowlist=True, empty allowlist -> blocked
    result = await mcp.call_tool(
        "dump_credentials",
        {
            "target_ip": "10.0.0.50",
            "method": "sam",
            "username": "admin",
            "password": "REAL-NTLM-SECRET-123",
            "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee",
            "domain": "CORP",
        },
    )
    text = "".join(
        getattr(c, "text", str(c)) for c in (result[0].content if hasattr(result[0], "content") else result[0])
    )
    assert "BLOCKED" in text  # denied preflight (no binary runs)

    audit_text = (tmp_path / "exploit_audit.jsonl").read_text(encoding="utf-8")
    # The cleartext credential must NEVER appear in the audit file.
    assert "REAL-NTLM-SECRET-123" not in audit_text
    assert "aad3b435b51404eeaad3b435b51404ee" not in audit_text
    # ...but the redacted marker and the preserved context do.
    assert _REDACTED in audit_text
    records = _read_audit(tmp_path)
    blocked = [r for r in records if r["status"] == "blocked" and r["tool_name"] == "dump_credentials"]
    assert blocked
    assert blocked[0]["args"]["password"] == _REDACTED
    assert blocked[0]["args"]["ntlm_hash"] == _REDACTED
    assert blocked[0]["args"]["username"] == "admin"  # non-secret preserved
    assert blocked[0]["args"]["domain"] == "CORP"


# ── 4. Inline-secret content masking (Tier 0 item 0.3, Phase A extension) ────
#
# Name-based redaction cannot see a credential embedded *inside* a free-text
# command/options/code value (the parameter name is ``command``, not ``password``).
# ``_mask_secret_content`` scans the value for inline-credential shapes. These
# tests pin each verified leak shape (Angle 5 of the adversarial audit) plus the
# false-positive guards that keep benign commands intact.


def _masked(secret: str, text: str) -> str:
    """Assert ``secret`` does not survive masking of ``text``; return masked."""
    out = _mask_secret_content(text)
    assert secret not in out, f"secret {secret!r} leaked through: {out!r}"
    return out


def test_mask_url_basic_auth():
    out = _masked("s3cret", "http://admin:s3cret@host/path")
    assert out == "http://***REDACTED***@host/path"
    assert "://" in out and "@host" in out  # structure preserved


def test_mask_curl_user_password_flag():
    out = _masked("s3cret", "curl -u admin:s3cret http://10.0.0.50/")
    assert out == "curl -u ***REDACTED*** http://10.0.0.50/"


def test_mask_long_password_flags():
    for cmd, secret in [
        ("smbclient --password hunter2 -L //10.0.0.50", "hunter2"),
        ("openssl enc -pass pass:s3cret -d", "s3cret"),
        ("mysql --password=p@ss -h 10.0.0.50", "p@ss"),
    ]:
        _masked(secret, cmd)


def test_mask_hydra_password_not_port():
    out = _masked("s3cret", "hydra -l admin -p s3cret 10.0.0.50 ssh")
    assert out == "hydra -l admin -p ***REDACTED*** 10.0.0.50 ssh"


def test_mask_crackmapexec_password():
    out = _masked("P@ss", "crackmapexec smb 10.0.0.50 -u admin -p P@ss --local-auth")
    assert "-p ***REDACTED***" in out and "P@ss" not in out


def test_mask_impacket_hashes():
    nt = "aad3b435b51404eeaad3b435b51404ee"
    # empty-LM form (:NT)
    out = _masked(nt, f"impacket-secretsdump CORP/admin -hashes :{nt} 10.0.0.50")
    assert out == "impacket-secretsdump CORP/admin -hashes ***REDACTED*** 10.0.0.50"
    # full LM:NT form
    lm = "31d6cfe0d16ae931b73c59d7e0c089c0"
    out2 = _masked(nt, f"secretsdump -hashes {lm}:{nt} host")
    assert lm not in out2 and nt not in out2


def test_mask_msf_options_smbpass():
    out = _masked("hunter2", "LHOST=10.0.0.50 SMBPass=hunter2 LPORT=4444")
    assert out == "LHOST=10.0.0.50 SMBPass=***REDACTED*** LPORT=4444"
    assert "LHOST=10.0.0.50" in out  # non-secret option preserved


def test_mask_msf_resource_script_set():
    # ``set SMBPass value`` (space-separated, not =) in a msf .rc script
    out = _masked("hunter2", "set SMBPass hunter2\nexploit")
    assert out == "set SMBPass ***REDACTED***\nexploit"


def test_mask_authorization_header():
    out = _masked("eyJabc123", '-H "Authorization: Bearer eyJabc123"')
    assert "Authorization: Bearer ***REDACTED***" in out
    assert "eyJabc123" not in out


def test_mask_python_requests_auth_tuple():
    out = _masked("s3cret", 'requests.get(url, auth=("admin","s3cret"))')
    assert "auth=(***REDACTED***" in out
    assert "s3cret" not in out


def test_mask_python_code_hardcoded_password():
    # code field carrying a hardcoded secret assignment
    out = _masked("s3cret", 'password = "s3cret"\nprint("hi")')
    assert "s3cret" not in out
    assert 'password = "***REDACTED***"' == out.splitlines()[0] or "password = ***REDACTED***" in out


# ── 4b. False-positive guards (benign commands must NOT be altered) ──────────


@pytest.mark.parametrize(
    "cmd",
    [
        "nmap -sV 10.0.0.50",  # benign recon, no creds
        "ssh -p 2222 user@10.0.0.50",  # -p is a port, not a password
        "nc -lvnp 4444",  # -lvnp, no -p flag
        "cp -p loot.txt /tmp/",  # -p preserve, not a password
        "nmap -p 80,443 10.0.0.50",  # -p ports
        "the password is secret here",  # prose, no key=value
        "SMBPass=",  # key with no value -- not masked
        "export DB_PASSWORD_FILE=/etc/passwd",  # *_FILE suffix, value is a path
    ],
)
def test_mask_does_not_alter_benign(cmd):
    assert _mask_secret_content(cmd) == cmd, f"benign command altered: {cmd!r}"


# ── 4c. End-to-end through _redact_args + the audit log ─────────────────────


def test_redact_args_masks_inline_creds_in_command_field():
    out = _redact_args({"command": "curl -u admin:s3cret http://10.0.0.50/"})
    assert out["command"] == "curl -u ***REDACTED*** http://10.0.0.50/"
    assert "s3cret" not in out["command"]


def test_redact_args_masks_inline_creds_in_options_string():
    out = _redact_args({"options": "LHOST=10.0.0.50 SMBPass=hunter2"})
    assert "hunter2" not in out["options"]
    assert "SMBPass=***REDACTED***" in out["options"]
    assert "LHOST=10.0.0.50" in out["options"]


def test_redact_args_masks_inline_creds_in_code_field():
    out = _redact_args({"code": 'password = "s3cret"\nprint("ok")'})
    assert "s3cret" not in out["code"]


def test_redact_args_wholesale_masks_input_text():
    # send_to_session input_text is bare credential lines that can't be parsed
    # for which token is the secret -- the whole value is masked in the audit.
    out = _redact_args({"input_text": "admin\ns3cret\nenable"})
    assert out["input_text"] == _REDACTED
    assert "s3cret" not in str(out)


def test_redact_args_masks_inline_creds_in_dict_options_value():
    # an options dict whose value is itself a cred-bearing string (not a secret
    # key) is walked and content-masked.
    out = _redact_args({"options": {"PASSWORD": "hunter2", "notes": "SMBPass=leaked"}})
    opts = out["options"]
    assert opts["PASSWORD"] == _REDACTED
    assert "leaked" not in opts["notes"]
    assert "SMBPass=***REDACTED***" in opts["notes"]


@pytest.mark.asyncio
async def test_audit_log_masks_free_text_command_field(tmp_path: Path):
    # The standalone ``command`` param of _audit_log (used by some direct call
    # sites) must also be content-masked, not written raw.
    from tools.mcp_shared import _audit_log

    audit = tmp_path / "exploit_audit.jsonl"
    _audit_log(
        audit,
        target_ip="10.0.0.50",
        tool_name="x",
        approved=True,
        status="completed",
        command="curl -u admin:s3cret http://10.0.0.50/",
    )
    text = audit.read_text(encoding="utf-8")
    assert "s3cret" not in text
    assert "admin:***REDACTED***" not in text  # the user:pass is fully replaced
    assert _REDACTED in text


@pytest.mark.asyncio
async def test_run_as_root_no_longer_double_logs_raw_command(tmp_path: Path):
    # run_as_root was @audit_tool-decorated (logs the masked command arg) AND
    # manually called _audit_log(command=original_command) with the RAW command
    # -- a credential leak. The manual call is removed; only the decorator logs.
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {"exploit": {"require_explicit_allowlist": False, "allowed_targets": []}}
    mcp = create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
    )
    # Monkeypatch subprocess.run so nothing actually executes (bash/sudo are
    # not invoked); we only care that the audit trail never holds the raw inline
    # secret and that the manual "running" double-log is gone.
    import unittest.mock as _mock

    with _mock.patch("mcp_exploit_server.subprocess.run") as _r:
        _r.return_value = _mock.MagicMock(stdout="", stderr="", returncode=0)
        await mcp.call_tool("run_as_root", {"command": 'echo "-H Authorization: Bearer s3cret123"'})
    audit_text = (tmp_path / "exploit_audit.jsonl").read_text(encoding="utf-8")
    assert "s3cret123" not in audit_text  # raw inline secret never logged
    assert _REDACTED in audit_text
    records = _read_audit(tmp_path)
    rr = [r for r in records if r["tool_name"] == "run_as_root"]
    statuses = {r["status"] for r in rr}
    assert "running" not in statuses  # the manual double-log is removed
    # A successful ROOT_CMD_RESULT is a normal completion; only the explicit
    # ``ROOT_CMD_RESULT: blocked`` prefix is classified as blocked.
    assert statuses == {"started", "completed"}
    completed = [r for r in rr if r["status"] == "completed"]
    assert completed[0]["approved"] is True


# ── Live terminal results are secret-masked before return/emit (Fix 6) ────────


@pytest.mark.asyncio
async def test_run_exploit_terminal_masks_secret_command_and_output(tmp_path: Path):
    """COMMAND_ORIGINAL/SANITIZED + OUTPUT tails must be masked in the live
    result — not just in the persisted terminal.log."""
    # Mock the host-path Popen funnel: the "command" carries a bearer token,
    # the "output" carries an NTLM hash + a second token.
    import subprocess as _subprocess
    import unittest.mock as _mock

    class _FakeProc:
        returncode = 0
        pid = 12345

        def communicate(self, timeout=None):
            return (
                b"uid=0(root)\nNTLM: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
                b"Authorization: Bearer live-output-token-abc123\n",
                None,
            )

    leaked = "live-output-token-abc123"
    token = "live-command-token-xyz789"
    mcp = _make_server(tmp_path, require_allowlist=False)
    with _mock.patch.object(_subprocess, "Popen", lambda *a, **k: _FakeProc()):
        result = await mcp.call_tool(
            "run_exploit_terminal",
            {"command": f"echo 10.0.0.5 && curl -H 'Authorization: Bearer {token}' http://10.0.0.5/"},
        )
    text = "".join(
        getattr(c, "text", str(c)) for c in (result[0].content if hasattr(result[0], "content") else result[0])
    )
    assert "TERMINAL_RESULT" in text
    assert token not in text  # secret-bearing command masked in COMMAND_* lines
    assert leaked not in text  # secret-bearing output masked in OUTPUT tail
    assert "aad3b435b51404ee" not in text  # dumped hash masked
    assert _REDACTED in text
    assert "10.0.0.5" in text  # the allowlisted target itself is not a secret


@pytest.mark.asyncio
async def test_tool_result_event_masks_secrets(tmp_path: Path):
    """The loop's ``tool_result`` WS event payload must be masked even when the
    tool itself returned verbatim text (defense in depth at the emit layer)."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

    secret_out = (
        "TERMINAL_RESULT: completed\nCOMMAND_ORIGINAL: echo hi\nOUTPUT:\n"
        "Authorization: Bearer event-token-999\nNTLM: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
    )
    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=1,
        attack_max_commands=5,
        outcome_judgment_flow_a=False,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    policy = ExploitPolicy(settings, tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        {
            "message": {
                "content": "",
                "tool_calls": [{"function": {"name": "run_exploit_terminal", "arguments": {"command": "exploit"}}}],
            }
        },
        {"message": {"content": "done", "tool_calls": []}},
    ]
    session = AsyncMock()
    session.call_tool.return_value = MagicMock(content=[MagicMock(text=secret_out)])
    emitted: list[tuple[str, dict]] = []

    class _Sink:
        async def emit(self, event_type: str, payload: dict) -> None:
            emitted.append((event_type, payload))

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            reports_dir=tmp_path / "reports",
            config={"agent": {"decision_log_enabled": False}, "outcome_judgment": {"flow_a": False}},
            event_sink=_Sink(),
        )
    results = [p for t, p in emitted if t == "tool_result"]
    assert results, "expected a tool_result event"
    assert "event-token-999" not in results[0]["result"]
    assert "aad3b435b51404ee" not in results[0]["result"]
    assert _REDACTED in results[0]["result"]
