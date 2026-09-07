"""Tests for defensive sanitization of audit ``extra`` fields.

``_audit_log`` merges caller-supplied ``extra`` into the JSONL record. Callers
are told to keep secrets out, but the audit layer must not trust that: every
``extra`` value is sanitized with the same credential-redaction pipeline as
ordinary argument logging (secret-named keys + secret-shaped strings, at any
nesting depth including inside lists). No network, no MCP server.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.mcp_shared import _REDACTED, _audit_log, _redact_nested


def _write(extra: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    _audit_log(
        tmp_path / "audit.jsonl",
        target_ip="10.0.0.50",
        tool_name="t",
        approved=True,
        status="completed",
        extra=extra,
    )
    return json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip())


def _raw(tmp_path: Path) -> str:
    return (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


# ── Secret-named keys at every depth ─────────────────────────────────────


def test_extra_password_redacted(tmp_path: Path):
    rec = _write({"password": "hunter2"}, tmp_path)
    assert rec["password"] == _REDACTED
    assert "hunter2" not in _raw(tmp_path)


def test_extra_token_redacted(tmp_path: Path):
    rec = _write({"session": {"token": "abc123", "other": "kept"}}, tmp_path)
    assert rec["session"] == {"token": _REDACTED, "other": "kept"}


def test_extra_cookies_redacted(tmp_path: Path):
    rec = _write({"cookies": "sessionid=deadbeef"}, tmp_path)
    assert rec["cookies"] == _REDACTED
    assert "deadbeef" not in _raw(tmp_path)


def test_extra_authorization_header_redacted(tmp_path: Path):
    rec = _write({"headers": {"Authorization": "Bearer xyzzy"}}, tmp_path)
    assert rec["headers"] == {"Authorization": _REDACTED}
    assert "xyzzy" not in _raw(tmp_path)


def test_extra_api_key_redacted(tmp_path: Path):
    rec = _write({"config": {"api_key": "AKIAEXAMPLE"}}, tmp_path)
    assert rec["config"] == {"api_key": _REDACTED}


def test_extra_ntlm_hash_redacted(tmp_path: Path):
    rec = _write({"auth": {"ntlm_hash": "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"}}, tmp_path)
    assert rec["auth"] == {"ntlm_hash": _REDACTED}
    assert "aad3b435" not in _raw(tmp_path)


def test_extra_private_key_redacted(tmp_path: Path):
    rec = _write({"deploy": {"private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----"}}, tmp_path)
    assert rec["deploy"] == {"private_key": _REDACTED}
    assert "BEGIN PRIVATE KEY" not in _raw(tmp_path)


def test_extra_credential_dicts_redacted(tmp_path: Path):
    rec = _write(
        {"creds": {"username": "admin", "password": "s3cr3t", "credentials": {"token": "t"}}},
        tmp_path,
    )
    assert rec["creds"]["username"] == "admin"
    assert rec["creds"]["password"] == _REDACTED
    assert rec["creds"]["credentials"] == {"token": _REDACTED}
    assert "s3cr3t" not in _raw(tmp_path)


# ── Secrets nested inside lists ──────────────────────────────────────────


def test_extra_list_of_credential_dicts_redacted(tmp_path: Path):
    rec = _write(
        {"found": [{"username": "a", "password": "p1"}, {"username": "b", "ntlm_hash": "h2"}]},
        tmp_path,
    )
    assert rec["found"] == [
        {"username": "a", "password": _REDACTED},
        {"username": "b", "ntlm_hash": _REDACTED},
    ]
    assert "p1" not in _raw(tmp_path) or '"p1"' not in _raw(tmp_path)


def test_extra_secret_shaped_strings_in_list_redacted(tmp_path: Path):
    rec = _write({"notes": ["password=hunter2", "plain note"]}, tmp_path)
    assert rec["notes"][0] == f"password={_REDACTED}"
    assert rec["notes"][1] == "plain note"
    assert "hunter2" not in _raw(tmp_path)


# ── Non-secrets preserved ────────────────────────────────────────────────


def test_extra_benign_values_preserved(tmp_path: Path):
    extra = {
        "container_id": "abc123",
        "exit_code": 0,
        "ports": [80, 443],
        "network": {"allow_dns": "controlled"},
        "fingerprint": "deadbeef",
    }
    rec = _write(extra, tmp_path)
    assert rec["container_id"] == "abc123"
    assert rec["exit_code"] == 0
    assert rec["ports"] == [80, 443]
    assert rec["network"] == {"allow_dns": "controlled"}
    assert rec["fingerprint"] == "deadbeef"


def test_extra_none_values_still_skipped(tmp_path: Path):
    rec = _write({"present": "yes", "absent": None}, tmp_path)
    assert rec["present"] == "yes"
    assert "absent" not in rec


# ── _redact_nested unit coverage ─────────────────────────────────────────


def test_redact_nested_tuple_becomes_list():
    assert _redact_nested(("a", {"password": "x"})) == ["a", {"password": _REDACTED}]


def test_redact_nested_scalars_pass_through():
    assert _redact_nested(42) == 42
    assert _redact_nested(None) is None
    assert _redact_nested("plain") == "plain"
