"""Tests for report generation."""

from tools.report_generator import (
    Finding,
    compare_findings,
    findings_from_parsed_hosts,
    generate_csv,
    generate_html,
    generate_markdown,
)
from tools.nmap_tools import ParsedHost, ParsedPort


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
