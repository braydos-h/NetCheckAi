"""Tests for command allowlisting."""

import pytest

from tools.nmap_tools import classify_safe_nmap_command


def test_ping_sweep_allowed():
    cmd = classify_safe_nmap_command("nmap -sn 192.168.1.0/24")
    assert cmd.kind == "ping_sweep"
    assert cmd.target == "192.168.1.0/24"


def test_basic_scan_allowed():
    cmd = classify_safe_nmap_command("nmap -sV --top-ports 1000 192.168.1.5")
    assert cmd.kind == "basic_scan"
    assert cmd.target == "192.168.1.5"


def test_triage_scan_allowed():
    cmd = classify_safe_nmap_command("nmap -sV --top-ports 100 --open 192.168.1.0/24")
    assert cmd.kind == "triage_scan"


def test_service_scan_allowed():
    cmd = classify_safe_nmap_command("nmap -sV -sC -O 192.168.1.5")
    assert cmd.kind == "service_scan"


def test_vuln_scan_allowed():
    cmd = classify_safe_nmap_command("nmap --script vuln -sV 192.168.1.5")
    assert cmd.kind == "vuln_scan"


def test_blocked_metacharacters():
    with pytest.raises(ValueError, match="shell metacharacters"):
        classify_safe_nmap_command("nmap -sn 192.168.1.0/24; rm -rf /")


def test_blocked_curl():
    with pytest.raises(ValueError, match="blocked term"):
        classify_safe_nmap_command("curl http://example.com")


def test_blocked_ssh():
    with pytest.raises(ValueError, match="blocked term"):
        classify_safe_nmap_command("ssh root@192.168.1.1")
