"""Tests for report generation."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

import main
from main import ControllerPolicy
from tools.report_generator import (
    Finding,
    compare_findings,
    findings_from_parsed_hosts,
    generate_csv,
    generate_html,
    generate_markdown,
    write_reports as write_structured_reports,
)
from tools.nmap_tools import ParsedHost, ParsedPort
from tools.sub_agents import StructuredFinding


def test_findings_from_parsed_hosts_creates_finding():
    host = ParsedHost(
        ip="192.168.1.10",
        hostname="router",
        ports=[
            ParsedPort(
                protocol="tcp",
                portid="23",
                state="open",
                service_name="telnet",
                service_version="",
            ),
        ],
    )
    findings = findings_from_parsed_hosts([host])
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].host == "192.168.1.10"


def test_compare_findings_detects_new():
    old = [Finding(title="old finding", severity="medium", host="192.168.1.1", port="80/tcp")]
    new = [
        Finding(title="old finding", severity="medium", host="192.168.1.1", port="80/tcp"),
        Finding(title="new finding", severity="high", host="192.168.1.2", port="23/tcp"),
    ]
    comp = compare_findings(new, old)
    assert len(comp["new"]) == 1
    assert len(comp["open"]) == 1
    assert len(comp["resolved"]) == 0


def test_compare_findings_detects_resolved():
    old = [Finding(title="resolved finding", severity="low", host="192.168.1.1", port="21/tcp")]
    new = []
    comp = compare_findings(new, old)
    assert len(comp["resolved"]) == 1


def test_generate_csv_contains_header():
    csv_out = generate_csv([])
    assert "severity" in csv_out
    assert "title" in csv_out


def test_generate_markdown_contains_summary():
    md = generate_markdown([], "run_001", ["192.168.1.0/24"])
    assert "Network Assessment Report" in md
    assert "run_001" in md


def test_generate_html_contains_table():
    html = generate_html([], "run_001", ["192.168.1.0/24"])
    assert "<table>" in html
    assert "run_001" in html


def test_structured_write_reports_does_not_create_nested_run_dir(tmp_path: Path):
    run_dir = tmp_path / "20260428_000000"
    written = write_structured_reports(
        reports_dir=run_dir,
        run_id="20260428_000000",
        subnets=["192.168.1.0/24"],
        findings=[],
        formats={"markdown", "csv", "html"},
    )

    assert run_dir / "network_summary.md" in written
    assert (run_dir / "network_summary.md").exists()
    assert (run_dir / "findings.csv").exists()
    assert (run_dir / "network_summary.html").exists()
    assert not (run_dir / "20260428_000000").exists()


def test_deterministic_network_report_has_evidence_sections_and_no_fence(tmp_path: Path):
    policy = sample_policy()
    write_sample_xml(tmp_path)

    written = main.write_reports(
        client=object(),
        model="unused",
        reports_dir=tmp_path,
        policy=policy,
        transcript=[],
        max_report_input_chars=1000,
        run_id="run_001",
        subnets=["192.168.1.0/24"],
        output_formats={"markdown", "csv", "html"},
        sub_findings=[],
    )

    summary = (tmp_path / "network_summary.md").read_text(encoding="utf-8")
    assert tmp_path / "network_summary.md" in written
    assert "```markdown" not in summary
    assert not summary.lstrip().startswith("```")
    assert "## Executive Summary" in summary
    assert "## Scope And Coverage" in summary
    assert "## Findings By Priority" in summary
    assert "## Host Inventory" in summary
    assert "## Limitations And Follow-Up" in summary
    assert "| Scan Type | Target | Status | Evidence Source |" in summary
    assert "| Host | Open Ports | Scan Depth | Selection / Skip Reason |" in summary
    assert "associated with publicly disclosed vulnerabilities" not in summary
    assert "No known CVEs" not in summary
    assert "CVE" not in summary


def test_skipped_live_host_is_not_reported_as_deeply_scanned(tmp_path: Path):
    policy = sample_policy()
    write_sample_xml(tmp_path)

    main.write_reports(
        client=object(),
        model="unused",
        reports_dir=tmp_path,
        policy=policy,
        transcript=[],
        max_report_input_chars=1000,
        run_id="run_001",
        subnets=["192.168.1.0/24"],
        output_formats={"markdown"},
        sub_findings=[],
    )

    summary = (tmp_path / "network_summary.md").read_text(encoding="utf-8")
    skipped_rows = [
        line
        for line in summary.splitlines()
        if line.startswith("| 192.168.1.20 |") and "Selection / Skip" not in line
    ]
    assert skipped_rows
    assert any("Skipped: no open TCP ports observed during triage" in row for row in skipped_rows)
    assert all("Basic" not in row and "Sub-agent" not in row for row in skipped_rows)


def test_concrete_cves_only_appear_when_sub_agent_returns_cve(tmp_path: Path):
    policy = sample_policy()
    write_sample_xml(tmp_path)
    finding = StructuredFinding(
        host="192.168.1.1",
        risk_level="medium",
        title="SSH service requires owner review",
        open_ports=[{"port": "22/tcp", "service": "ssh", "version": "OpenSSH 8.4"}],
        evidence="OpenSSH 8.4 was observed on 22/tcp.",
        remediation="Restrict SSH and patch through the vendor.",
        cves_found=["CVE-2024-6387"],
    )

    main.write_reports(
        client=object(),
        model="unused",
        reports_dir=tmp_path,
        policy=policy,
        transcript=[],
        max_report_input_chars=1000,
        run_id="run_001",
        subnets=["192.168.1.0/24"],
        output_formats={"markdown"},
        sub_findings=[finding],
    )

    summary = (tmp_path / "network_summary.md").read_text(encoding="utf-8")
    assert "CVE-2024-6387" in summary


@pytest.mark.asyncio
async def test_sub_agent_mode_hands_off_after_triage_without_main_basic_scan(monkeypatch):
    subnet = ipaddress.ip_network("192.168.1.0/24")
    policy = ControllerPolicy(
        approved_subnets=(subnet,),
        allowed_private_cidrs=(subnet,),
        max_subnet_addresses=256,
        max_hosts=4,
        max_tool_calls=10,
        max_searches=0,
    )
    responses = [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "run_nmap_ping_sweep", "arguments": {"subnet": "192.168.1.0/24"}}}
            ],
        },
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "run_nmap_triage_scan", "arguments": {"subnet": "192.168.1.0/24"}}},
                {"function": {"name": "run_nmap_basic_scan", "arguments": {"ip": "192.168.1.1"}}},
            ],
        },
    ]

    def fake_stream(*args, **kwargs):
        return responses.pop(0)

    async def fake_spawn_sub_agents(**kwargs):
        return []

    monkeypatch.setattr(main, "stream_ollama_chat", fake_stream)
    monkeypatch.setattr(main, "spawn_sub_agents", fake_spawn_sub_agents)

    session = FakeSession()
    runner = FakeRunner()
    await main.run_agent_loop(
        client=object(),
        model="unused",
        session=session,
        ollama_tools=[],
        policy=policy,
        approved_subnets=(subnet,),
        ui=main.Ui(plain=True),
        runner=runner,
        search=object(),
        nvd=object(),
        use_sub_agents=True,
        sub_agent_concurrency=1,
        max_sub_agent_rounds=1,
    )

    assert session.calls == ["run_nmap_ping_sweep", "run_nmap_triage_scan"]
    assert "192.168.1.1" not in policy.basic_scanned_hosts


class FakeSession:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def call_tool(self, name: str, arguments: dict[str, str]):
        self.calls.append(name)
        if name == "run_nmap_ping_sweep":
            return {"content": [{"text": PING_RESULT}]}
        if name == "run_nmap_triage_scan":
            return {"content": [{"text": TRIAGE_RESULT}]}
        return {"content": [{"text": "COMMAND: nmap\nTARGET: 192.168.1.1\nOUTPUT:\nEXIT_CODE: 0"}]}


class FakeRunner:
    def __init__(self) -> None:
        self.completed_ping_sweeps: set[str] = set()
        self.triaged_subnets: set[str] = set()
        self.live_hosts_by_subnet: dict[str, set[str]] = {}


def sample_policy() -> ControllerPolicy:
    subnet = ipaddress.ip_network("192.168.1.0/24")
    policy = ControllerPolicy(
        approved_subnets=(subnet,),
        allowed_private_cidrs=(subnet,),
        max_subnet_addresses=256,
        max_hosts=4,
        max_tool_calls=10,
        max_searches=0,
    )
    policy.completed_ping_sweeps.add(str(subnet))
    policy.triaged_subnets.add(str(subnet))
    policy.live_hosts_by_subnet[str(subnet)] = {"192.168.1.1", "192.168.1.20"}
    policy.basic_scanned_hosts.add("192.168.1.1")
    return policy


def write_sample_xml(reports_dir: Path) -> None:
    xml_dir = reports_dir / "xml_nmap"
    xml_dir.mkdir(parents=True)
    (xml_dir / "192.168.1.0_24_ping_sweep.xml").write_text(
        """<nmaprun>
<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/></host>
</nmaprun>""",
        encoding="utf-8",
    )
    (xml_dir / "192.168.1.0_24_triage_scan.xml").write_text(
        """<nmaprun>
<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.4"/></port></ports>
</host>
<host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/><ports></ports></host>
</nmaprun>""",
        encoding="utf-8",
    )
    (xml_dir / "192.168.1.1_basic_scan.xml").write_text(
        """<nmaprun>
<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.4"/></port></ports>
</host>
</nmaprun>""",
        encoding="utf-8",
    )


PING_RESULT = """COMMAND: nmap -sn 192.168.1.0/24
TARGET: 192.168.1.0/24
OUTPUT:
EXIT_CODE: 0
STDOUT:
Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).
Nmap done: 256 IP addresses (1 host up) scanned
STDERR:

LIVE_HOSTS:
1 live host(s) discovered in 192.168.1.0/24:
- 192.168.1.1"""


TRIAGE_RESULT = """COMMAND: nmap -sV --top-ports 100 --open 192.168.1.1
TARGET: 192.168.1.0/24
OUTPUT:
EXIT_CODE: 0
STDOUT:
Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4
Nmap done: 1 IP address (1 host up) scanned
STDERR:

TRIAGE_HINTS:
- 192.168.1.1: medium triage score 2; remote login surface: 22/tcp ssh OpenSSH 8.4"""
