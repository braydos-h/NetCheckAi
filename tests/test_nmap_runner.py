"""Tests for SafeNmapRunner command construction."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from tools.nmap_tools import SCAN_PROFILES, SafeNmapRunner, SafeNmapSettings


class RecordingNmapRunner(SafeNmapRunner):
    def __init__(
        self,
        settings: SafeNmapSettings,
        *,
        output: str = "EXIT_CODE: 0\nSTDOUT:\nNmap done: 1 IP address (0 hosts up) scanned\nSTDERR:",
        xml_text: str = "<nmaprun></nmaprun>",
    ) -> None:
        super().__init__(settings)
        self.last_argv: tuple[str, ...] | None = None
        self.calls: list[tuple[str, ...]] = []
        self.output = output
        self.xml_text = xml_text

    def _nmap_binary(self) -> str:
        return "nmap"

    def _run_nmap(
        self,
        argv: tuple[str, ...],
        *,
        timeout: int,
        xml_path: Path | None = None,
    ) -> str:
        self.last_argv = argv
        self.calls.append(argv)
        if xml_path is not None:
            xml_path.write_text(self.xml_text, encoding="utf-8")
        return self.output


@pytest.mark.parametrize("profile", SCAN_PROFILES)
def test_ping_sweep_is_discovery_only_for_all_profiles(tmp_path: Path, profile: str) -> None:
    subnet = ipaddress.ip_network("192.168.1.0/24")
    settings = SafeNmapSettings(
        approved_subnets=(subnet,),
        reports_dir=tmp_path,
        scan_profile=profile,
    )
    runner = RecordingNmapRunner(settings)

    runner.run_nmap_ping_sweep(str(subnet))

    assert runner.last_argv == ("nmap", "-sn", "192.168.1.0/24")


def test_triage_targets_only_hosts_discovered_alive(tmp_path: Path) -> None:
    subnet = ipaddress.ip_network("192.168.1.0/24")
    settings = SafeNmapSettings(approved_subnets=(subnet,), reports_dir=tmp_path)
    output = """EXIT_CODE: 0
STDOUT:
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0010s latency).
Nmap scan report for laptop.local (192.168.1.130)
Host is up (0.0020s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned
STDERR:"""
    xml_text = """<nmaprun>
<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="192.168.1.130" addrtype="ipv4"/></host>
</nmaprun>"""
    runner = RecordingNmapRunner(settings, output=output, xml_text=xml_text)

    runner.run_nmap_ping_sweep(str(subnet))
    runner.run_nmap_triage_scan(str(subnet))

    assert runner.calls[1] == (
        "nmap",
        "-sV",
        "--top-ports",
        "100",
        "--open",
        "192.168.1.1",
        "192.168.1.130",
    )


def test_triage_skips_port_scan_when_no_hosts_are_alive(tmp_path: Path) -> None:
    subnet = ipaddress.ip_network("192.168.1.0/24")
    settings = SafeNmapSettings(approved_subnets=(subnet,), reports_dir=tmp_path)
    runner = RecordingNmapRunner(settings)

    runner.run_nmap_ping_sweep(str(subnet))
    result = runner.run_nmap_triage_scan(str(subnet))

    assert len(runner.calls) == 1
    assert "No triage port scan was run." in result
    assert str(subnet) in runner.triaged_subnets


def test_host_scan_blocks_ip_not_seen_alive(tmp_path: Path) -> None:
    subnet = ipaddress.ip_network("192.168.1.0/24")
    settings = SafeNmapSettings(approved_subnets=(subnet,), reports_dir=tmp_path)
    runner = RecordingNmapRunner(settings)

    runner.run_nmap_ping_sweep(str(subnet))
    result = runner.run_nmap_basic_scan("192.168.1.1")

    assert result.startswith("BLOCKED:")
    assert "not reported alive" in result
    assert len(runner.calls) == 1
