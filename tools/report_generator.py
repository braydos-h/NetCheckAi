"""Report generators for defensive Nmap assessments.

Produces network_summary.html, findings.csv, and improved Markdown
with severity, evidence, affected host/port, confidence, remediation,
and next-scan recommendations.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from tools.nmap_tools import ParsedHost, ParsedPort


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    """A single defensive finding."""

    title: str
    severity: str  # critical, high, medium, low, info
    host: str
    port: str = ""
    service: str = ""
    evidence: str = ""
    confidence: str = "likely"  # confirmed, likely, possible
    remediation: str = ""
    next_scan: str = ""
    cve_refs: list[str] = field(default_factory=list)

    @property
    def sort_key(self):
        return (SEVERITY_ORDER.get(self.severity.lower(), 99), self.host, self.port)


def findings_from_parsed_hosts(hosts: Iterable[ParsedHost]) -> list[Finding]:
    """Derive findings from structured Nmap XML hosts."""
    findings: list[Finding] = []
    for host in hosts:
        if host.os_name:
            findings.append(
                Finding(
                    title=f"OS detected: {host.os_name}",
                    severity="info",
                    host=host.ip,
                    evidence=f"OS fingerprint: {host.os_name}",
                    confidence="likely",
                    remediation="Verify OS inventory accuracy; patch accordingly.",
                )
            )
        for port in host.ports:
            if port.state != "open":
                continue
            sev, reason = _score_port(port)
            findings.append(
                Finding(
                    title=f"{port.service_name or 'unknown'} on {port.portid}/{port.protocol}",
                    severity=sev,
                    host=host.ip,
                    port=f"{port.portid}/{port.protocol}",
                    service=port.service_name or "unknown",
                    evidence=_build_evidence(port, reason),
                    confidence="confirmed" if port.service_version else "likely",
                    remediation=_default_remediation(port),
                    next_scan=_next_scan_hint(port),
                    cve_refs=list(port.cpe),
                )
            )
    findings.sort(key=lambda f: f.sort_key)
    return findings


def _score_port(port: ParsedPort) -> tuple[str, str]:
    name = (port.service_name or "").lower()
    product = (port.product or "").lower()
    version = (port.service_version or "").lower()
    portid = port.portid

    if name in {"telnet", "ftp", "tftp"} or portid in {"23", "21", "69"}:
        return ("high", "cleartext protocol")
    if name in {"microsoft-ds", "netbios-ssn", "smb"} or portid in {"139", "445"}:
        return ("high", "SMB/NetBIOS exposure")
    if name in {"ms-wbt-server", "rdp"} or portid == "3389":
        return ("high", "RDP exposure")
    if name in {"vnc", "snmp", "redis", "mongodb", "elasticsearch", "mysql", "postgresql"}:
        return ("medium", "sensitive service exposed")
    if name in {"http", "https", "http-proxy"}:
        return ("low", "web surface")
    if name in {"ssh"}:
        return ("low", "remote login surface")
    if "unknown" in name or "unknown" in version:
        return ("medium", "unknown service/version")
    return ("info", "open port")


def _build_evidence(port: ParsedPort, reason: str) -> str:
    parts = [f"Port {port.portid}/{port.protocol} is {port.state}"]
    if port.service_name:
        parts.append(f"Service: {port.service_name}")
    if port.product:
        parts.append(f"Product: {port.product}")
    if port.service_version:
        parts.append(f"Version: {port.service_version}")
    if port.extrainfo:
        parts.append(f"Extra: {port.extrainfo}")
    if reason:
        parts.append(f"Risk indicator: {reason}")
    return "; ".join(parts)


def _default_remediation(port: ParsedPort) -> str:
    name = (port.service_name or "").lower()
    if name in {"telnet", "ftp", "tftp"}:
        return "Disable or replace with encrypted alternative (SFTP/SSH)."
    if name in {"microsoft-ds", "netbios-ssn", "smb"}:
        return "Restrict SMB to authenticated hosts; enable SMB signing & encryption."
    if name in {"ms-wbt-server", "rdp"}:
        return "Use Network Level Authentication; restrict by IP; enable MFA."
    if name in {"vnc"}:
        return "Require strong password or disable VNC; use jump host."
    if name in {"redis", "mongodb", "elasticsearch", "mysql", "postgresql"}:
        return "Bind to localhost or enforce authentication/encryption."
    if name in {"http", "https", "http-proxy"}:
        return "Keep software updated; remove default credentials; audit exposed paths."
    if name in {"ssh"}:
        return "Use key-based auth; disable root login; keep OpenSSH updated."
    return "Review necessity; restrict by firewall; apply vendor patches."


def _next_scan_hint(port: ParsedPort) -> str:
    name = (port.service_name or "").lower()
    if name in {"http", "https"}:
        return "Consider --script http-enum,http-vuln-* or manual app scan."
    if name in {"ssh"}:
        return "Consider ssh-audit or version-specific CVE lookup."
    if name in {"microsoft-ds", "netbios-ssn", "smb"}:
        return "Consider smb-vuln-* scripts if approved."
    if name in {"ms-wbt-server", "rdp"}:
        return "Consider ssl-enum-ciphers and rdp-enum-encryption."
    return ""


def compare_findings(
    current: list[Finding], previous: list[Finding]
) -> dict[str, list[Finding]]:
    """Classify findings as new, open, or resolved compared to a previous run."""
    prev_keys = {
        (f.host, f.port, f.title)
        for f in previous
    }
    curr_keys = {
        (f.host, f.port, f.title)
        for f in current
    }
    new = [f for f in current if (f.host, f.port, f.title) not in prev_keys]
    resolved = [f for f in previous if (f.host, f.port, f.title) not in curr_keys]
    open_items = [f for f in current if (f.host, f.port, f.title) in prev_keys]
    return {"new": new, "open": open_items, "resolved": resolved}


def generate_markdown(
    findings: list[Finding],
    run_id: str,
    subnets: list[str],
    comparison: dict[str, list[Finding]] | None = None,
) -> str:
    """Generate improved Markdown report."""
    lines = [
        "# Network Assessment Report",
        f"\n**Run ID:** {run_id}",
        f"**Scope:** {', '.join(subnets)}",
        f"**Generated:** {datetime.now(timezone.utc).isoformat().replace("+00:00", "")}Z\n",
    ]

    if comparison:
        lines.extend(
            [
                "## Findings Summary",
                f"- **New:** {len(comparison['new'])}",
                f"- **Open:** {len(comparison['open'])}",
                f"- **Resolved:** {len(comparison['resolved'])}\n",
            ]
        )
    else:
        lines.extend(
            [
                "## Findings Summary",
                f"- **Total:** {len(findings)}\n",
            ]
        )

    lines.append("## Detailed Findings\n")
    if not findings:
        lines.append("No findings reported.\n")
    for f in findings:
        lines.append(f"### {f.title}")
        lines.append(f"- **Severity:** {f.severity.upper()}")
        lines.append(f"- **Host:** {f.host}")
        if f.port:
            lines.append(f"- **Port:** {f.port}")
        if f.service:
            lines.append(f"- **Service:** {f.service}")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append(f"- **Evidence:** {f.evidence}")
        if f.cve_refs:
            lines.append(f"- **CPE:** {', '.join(f.cve_refs)}")
        lines.append(f"- **Remediation:** {f.remediation}")
        if f.next_scan:
            lines.append(f"- **Next Scan Recommended:** {f.next_scan}")
        lines.append("")
    return "\n".join(lines)


def generate_csv(findings: list[Finding]) -> str:
    """Generate CSV report."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        ["severity", "title", "host", "port", "service", "confidence", "evidence", "remediation", "next_scan"]
    )
    for f in findings:
        writer.writerow(
            [
                f.severity,
                f.title,
                f.host,
                f.port,
                f.service,
                f.confidence,
                f.evidence,
                f.remediation,
                f.next_scan,
            ]
        )
    return out.getvalue()


def generate_html(
    findings: list[Finding],
    run_id: str,
    subnets: list[str],
    comparison: dict[str, list[Finding]] | None = None,
) -> str:
    """Generate HTML network_summary report."""
    total = len(findings)
    new_count = len(comparison["new"]) if comparison else 0
    open_count = len(comparison["open"]) if comparison else total
    resolved_count = len(comparison["resolved"]) if comparison else 0

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity.lower()] = sev_counts.get(f.severity.lower(), 0) + 1

    rows = []
    for f in findings:
        badge_class = f"badge-{f.severity.lower()}"
        rows.append(
            f"""<tr>
            <td><span class=\"badge {badge_class}\">{f.severity.upper()}</span></td>
            <td>{f.title}</td>
            <td>{f.host}</td>
            <td>{f.port}</td>
            <td>{f.service}</td>
            <td>{f.confidence}</td>
            <td>{f.evidence}</td>
            <td>{f.remediation}</td>
            <td>{f.next_scan}</td>
            </tr>"""
        )

    comparison_html = ""
    if comparison:
        comparison_html = f"""<div class=\"summary-cards\">
        <div class=\"card new\"><h3>{new_count}</h3><p>New</p></div>
        <div class=\"card open\"><h3>{open_count}</h3><p>Open</p></div>
        <div class=\"card resolved\"><h3>{resolved_count}</h3><p>Resolved</p></div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\">
<title>Network Assessment {run_id}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem; background:#f8f9fa; }}
  h1 {{ color:#212529; }}
  .meta {{ color:#6c757d; margin-bottom:1rem; }}
  .summary-cards {{ display:flex; gap:1rem; margin:1rem 0; }}
  .card {{ background:#fff; padding:1rem; border-radius:0.5rem; box-shadow:0 1px 3px rgba(0,0,0,0.1); flex:1; text-align:center; }}
  .card.new {{ border-top:4px solid #dc3545; }}
  .card.open {{ border-top:4px solid #fd7e14; }}
  .card.resolved {{ border-top:4px solid #28a745; }}
  table {{ width:100%; border-collapse:collapse; margin-top:1rem; background:#fff; }}
  th, td {{ padding:0.6rem; border:1px solid #dee2e6; text-align:left; font-size:0.9rem; }}
  th {{ background:#e9ecef; }}
  .badge {{ padding:0.2rem 0.5rem; border-radius:0.25rem; font-size:0.75rem; font-weight:700; text-transform:uppercase; color:#fff; }}
  .badge-critical {{ background:#6f42c1; }}
  .badge-high {{ background:#dc3545; }}
  .badge-medium {{ background:#fd7e14; }}
  .badge-low {{ background:#0dcaf0; color:#000; }}
  .badge-info {{ background:#6c757d; }}
</style>
</head>
<body>
<h1>Network Assessment Report</h1>
<div class=\"meta\">
  <strong>Run ID:</strong> {run_id}<br>
  <strong>Scope:</strong> {', '.join(subnets)}<br>
  <strong>Generated:</strong> {datetime.now(timezone.utc).isoformat().replace("+00:00", "")}Z
</div>
{comparison_html}
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Finding</th><th>Host</th><th>Port</th>
      <th>Service</th><th>Confidence</th><th>Evidence</th>
      <th>Remediation</th><th>Next Scan</th>
    </tr>
  </thead>
  <tbody>
    {"\n    ".join(rows) if rows else '<tr><td colspan="9">No findings</td></tr>'}
  </tbody>
</table>
</body>
</html>"""


def write_reports(
    reports_dir: Path,
    run_id: str,
    subnets: list[str],
    findings: list[Finding],
    comparison: dict[str, list[Finding]] | None = None,
    formats: set[str] | None = None,
) -> list[Path]:
    """Write all requested report formats and return written paths."""
    if formats is None:
        formats = {"markdown"}
    run_dir = reports_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    latest_link = reports_dir / "latest"
    if latest_link.exists() or latest_link.is_symlink():
        latest_link.unlink()
    try:
        latest_link.symlink_to(run_dir, target_is_directory=True)
    except OSError:
        # Windows may need admin for symlinks; fallback to junction or skip
        import platform
        if platform.system() == "Windows":
            import subprocess as sp
            sp.run(["cmd", "/c", "mklink", "/J", str(latest_link), str(run_dir)], check=False, capture_output=True)
        else:
            raise

    written: list[Path] = []
    if "markdown" in formats or "all" in formats:
        md_path = run_dir / "network_summary.md"
        md_path.write_text(generate_markdown(findings, run_id, subnets, comparison), encoding="utf-8")
        written.append(md_path)
    if "csv" in formats or "all" in formats:
        csv_path = run_dir / "findings.csv"
        csv_path.write_text(generate_csv(findings), encoding="utf-8")
        written.append(csv_path)
    if "html" in formats or "all" in formats:
        html_path = run_dir / "network_summary.html"
        html_path.write_text(generate_html(findings, run_id, subnets, comparison), encoding="utf-8")
        written.append(html_path)
    return written
