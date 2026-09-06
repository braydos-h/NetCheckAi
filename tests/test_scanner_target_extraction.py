"""Regression tests for ``_extract_scanner_targets`` (the target-IP lock's
scanner-destination extractor).

Background: the old ``_SCANNER_TARGET_RE`` treated every ``-flag`` as value-less,
so a space-separated value flag like nmap ``-p 445,139,135,389`` had its *port
list* captured as the scan "target" and the whole command was blocked by the
allowlist even when the real target was authorized (seen in the ``main.py --web``
log). The replacement is an argv-walk that skips value-flags + their value and
keeps only host-shaped positionals.
"""

from __future__ import annotations

from tools.mcp_tools.registry import _extract_scanner_targets

# ── pure-function extraction ────────────────────────────────────────────────


def test_nmap_p_portspec_not_captured_as_target() -> None:
    """The log bug: ``-p 445,139,135,389`` must NOT be the extracted target."""
    cmd = "nmap -p 445,139,135,389 --script smb-vuln-ms17-010 -Pn --open 209.38.90.131"
    assert _extract_scanner_targets(cmd) == ["209.38.90.131"]


def test_fqdn_target_after_value_flag_is_still_checked() -> None:
    """No FQDN bypass: the real FQDN target after ``-p`` must be captured (the
    old single-positional regex would have missed it after a non-host first
    positional)."""
    assert _extract_scanner_targets("nmap -p 445 evil.example.com") == ["evil.example.com"]


def test_output_file_value_not_captured_as_target() -> None:
    """``-oN scan.txt`` -- ``scan.txt`` is dotted/host-shaped but is an output
    file, not a target. The value-flag set skips it."""
    assert _extract_scanner_targets("nmap -oN scan.txt 10.0.0.5") == ["10.0.0.5"]


def test_source_ip_flag_value_not_captured() -> None:
    """``-S 10.0.0.1`` is a source IP (host-shaped but not a target)."""
    assert _extract_scanner_targets("nmap -S 10.0.0.1 10.0.0.5") == ["10.0.0.5"]


def test_interface_value_not_host_shaped() -> None:
    """``-e eth0`` -- ``eth0`` is bare (no dots) so the host-shape predicate
    drops it; no need for ``-e`` in the value-flag set."""
    assert _extract_scanner_targets("nmap -e eth0 10.0.0.5") == ["10.0.0.5"]


def test_cidr_target_is_captured() -> None:
    assert _extract_scanner_targets("nmap 192.168.1.0/24") == ["192.168.1.0/24"]


def test_multiple_targets_captured() -> None:
    """All host-shaped positionals are captured, not just the first."""
    assert _extract_scanner_targets("masscan 10.0.0.5 10.0.0.6 -p 445") == [
        "10.0.0.5",
        "10.0.0.6",
    ]


def test_attached_value_flags_not_split() -> None:
    """``--script=foo`` and ``-p445`` carry their value inline -- the value is
    not a separate positional and must not be captured."""
    assert _extract_scanner_targets("nmap --script=smb-vuln 10.0.0.5") == ["10.0.0.5"]
    assert _extract_scanner_targets("nmap -p445 10.0.0.5") == ["10.0.0.5"]


def test_full_path_scanner_basename_recognized() -> None:
    """``/usr/bin/nmap`` is recognized via basename (matches the old word-boundary
    regex behavior); ``nmap.py`` is not."""
    assert _extract_scanner_targets("/usr/bin/nmap -p 445 10.0.0.5") == ["10.0.0.5"]
    assert _extract_scanner_targets("nmap.py -p 445 10.0.0.5") == []


def test_stops_at_shell_separator() -> None:
    """A piped non-scanner command (``| grep open``) must not contribute
    targets."""
    assert _extract_scanner_targets("nmap 10.0.0.5 | grep open") == ["10.0.0.5"]


def test_non_scanner_command_returns_empty() -> None:
    assert _extract_scanner_targets("curl http://10.0.0.5:8080") == []
    assert _extract_scanner_targets("ls -la") == []


# ── end-to-end through _target_lock_block ───────────────────────────────────


def test_target_lock_allows_authorized_nmap_p_scan(monkeypatch) -> None:
    """The exact log command is no longer blocked when the real target is
    authorized."""
    from tools.mcp_tools.terminal import _target_lock_block

    monkeypatch.delenv("EXPLOIT_TARGET", raising=False)
    monkeypatch.delenv("EXPLOIT_TARGET_IP", raising=False)
    monkeypatch.delenv("EXPLOIT_TARGET_DOMAIN", raising=False)
    monkeypatch.delenv("EXPLOIT_DISCOVERED_TARGETS", raising=False)
    config = {
        "exploit": {
            "require_explicit_allowlist": True,
            "allowed_targets": ["209.38.90.131"],
        }
    }
    cmd = "nmap -p 445,139,135,389 --script smb-vuln-ms17-010 -Pn --open 209.38.90.131"
    assert _target_lock_block(cmd, config) is None


def test_target_lock_blocks_unauthorized_fqdn_after_p(monkeypatch) -> None:
    """The lock still fires for an unauthorized FQDN target after ``-p`` -- the
    fix must not weaken the lock into a bypass."""
    from tools.mcp_tools.terminal import _target_lock_block

    monkeypatch.delenv("EXPLOIT_TARGET", raising=False)
    monkeypatch.delenv("EXPLOIT_TARGET_IP", raising=False)
    monkeypatch.delenv("EXPLOIT_TARGET_DOMAIN", raising=False)
    monkeypatch.delenv("EXPLOIT_DISCOVERED_TARGETS", raising=False)
    config = {
        "exploit": {
            "require_explicit_allowlist": True,
            "allowed_targets": ["10.0.0.5"],
        }
    }
    block = _target_lock_block("nmap -p 445 evil.example.com", config)
    assert block is not None
    assert "evil.example.com" in block


# ── Python-source body scans: loopback/bind + attribute FPs ─────────────────
# (test.log: legit recon scripts were blocked as "Target 0.0.0.0 ..." from a
# bind() call and "Target s.settimeout ..." from an nmap mention in a comment
# plus s.settimeout(...). The shell lock stays strict; the Python body scan
# skips the shell-oriented scanner-verb heuristic and loopback tokens.)


def _lock_config(*allowed: str) -> dict:
    return {"exploit": {"require_explicit_allowlist": True, "allowed_targets": list(allowed)}}


def _clear_target_env(monkeypatch) -> None:
    for var in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN", "EXPLOIT_DISCOVERED_TARGETS"):
        monkeypatch.delenv(var, raising=False)


def test_python_body_scan_ignores_bind_all_and_loopback(monkeypatch) -> None:
    """bind(('0.0.0.0', ...)) listens, it does not pivot -- must not block."""
    from tools.mcp_tools.terminal import _target_lock_block

    _clear_target_env(monkeypatch)
    body = "import socket\ns = socket.socket()\ns.bind(('0.0.0.0', 4444))\ns.connect(('127.0.0.1', 8081))\n"
    assert _target_lock_block(body, _lock_config("127.0.0.1"), allow_empty=True) is None


def test_python_body_scan_ignores_scanner_mention_plus_settimeout(monkeypatch) -> None:
    """An 'nmap -sV' mention in a comment plus s.settimeout(...) must not
    extract 's.settimeout' as a scan target in Python-source scans."""
    from tools.mcp_tools.terminal import _target_lock_block

    _clear_target_env(monkeypatch)
    body = (
        "# like nmap -sV but in python\nimport socket\ns = socket.socket()\n"
        "s.settimeout(2)\ns.connect(('127.0.0.1', 8081))\n"
    )
    assert _target_lock_block(body, _lock_config("127.0.0.1"), allow_empty=True, include_scanner_targets=False) is None


def test_python_body_scan_still_blocks_off_target_ip(monkeypatch) -> None:
    """The lock is not weakened: a literal off-target IP in Python source
    still blocks, with or without the scanner heuristic."""
    from tools.mcp_tools.terminal import _target_lock_block

    _clear_target_env(monkeypatch)
    body = "import socket\ns = socket.socket()\ns.connect(('10.0.0.99', 4444))\n"
    for kw in ({}, {"include_scanner_targets": False}):
        block = _target_lock_block(body, _lock_config("127.0.0.1"), allow_empty=True, **kw)
        assert block is not None
        assert "10.0.0.99" in block
