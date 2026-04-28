"""Tests for triage parsing and scoring."""

from tools.nmap_tools import build_triage_hints, extract_triage_ranked, parse_nmap_hosts


SAMPLE_TRIAGE_OUTPUT = """
Nmap scan report for 192.168.1.10
Host is up (0.00032s latency).
Not shown: 99 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2
80/tcp open  http    Apache httpd 2.4.41

Nmap scan report for 192.168.1.20
Host is up (0.00045s latency).
Not shown: 99 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
23/tcp  open  telnet  Linux telnetd
445/tcp open  microsoft-ds Microsoft Windows 10 microsoft-ds
"""


def test_parse_nmap_hosts_finds_services():
    hosts = parse_nmap_hosts(SAMPLE_TRIAGE_OUTPUT)
    assert "192.168.1.10" in hosts
    assert "192.168.1.20" in hosts
    assert len(hosts["192.168.1.10"]) == 2
    assert hosts["192.168.1.10"][0]["port"] == "22/tcp"


def test_triage_hints_rank_telnet_high():
    hints = build_triage_hints(SAMPLE_TRIAGE_OUTPUT)
    assert "192.168.1.20: high triage score" in hints
    assert "telnet" in hints.lower()


def test_triage_hints_rank_ssh_lower():
    hints = build_triage_hints(SAMPLE_TRIAGE_OUTPUT)
    lines = hints.splitlines()
    ssh_line = [l for l in lines if "192.168.1.10" in l]
    assert ssh_line
    assert "low triage score" in ssh_line[0] or "medium triage score" in ssh_line[0]


def test_triage_scores_remote_admin_surfaces_consistently():
    output = """
Nmap scan report for 192.168.1.30
Host is up.
PORT     STATE SERVICE VERSION
7070/tcp open  realserver AnyDesk Client TLS

Nmap scan report for 192.168.1.1
Host is up.
PORT     STATE SERVICE VERSION
9000/tcp open  grpc    router management gRPC
22/tcp   open  ssh     OpenSSH 8.4
"""

    ranked = extract_triage_ranked(output)

    assert ranked[0].score >= 4
    assert any("remote access tooling" in reason or "management or gRPC" in reason for reason in ranked[0].reasons)
    assert {host.ip for host in ranked} == {"192.168.1.30", "192.168.1.1"}
