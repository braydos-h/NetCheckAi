"""Recon-first assessment helpers for the CLI."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.attack_ui import AttackUi
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.goal_suggester import ReconAssessment, build_assessment_from_mcp_results

ui = AttackUi(plain=False)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tools.runtime_context import RuntimeContext


_GENERIC_SERVICE_NAMES = frozenset(
    {
        "dns",
        "ftp",
        "http",
        "https",
        "imap",
        "pop3",
        "smtp",
        "ssh",
        "telnet",
    }
)


def _cve_query_from_banner(banner: str) -> tuple[str, str] | None:
    """Return a product/version pair suitable for a CVE search.

    A port/service name is not proof of a particular implementation or version.
    In particular, querying NVD for just ``ssh`` returns broad historical results
    that are not attributable to the host.  Only search when the banner identifies
    a concrete product and version.
    """
    if not banner:
        return None

    # SSH banners commonly start with a protocol identifier (``SSH-2.0-``).
    # Match OpenSSH first so we do not mistake the protocol version for the
    # server version.
    openssh_match = re.search(
        r"\b(?P<product>OpenSSH)[_\s/-]*v?(?P<version>\d+(?:\.\d+)+(?:p\d+)?)",
        banner,
        re.IGNORECASE,
    )
    if openssh_match:
        return "OpenSSH", openssh_match.group("version")

    for match in re.finditer(
        r"\b(?P<product>[A-Za-z][A-Za-z0-9_.+-]*)[\s/_-]+v?"
        r"(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._+-]*)?)",
        banner,
    ):
        product = match.group("product")
        if product.lower() not in _GENERIC_SERVICE_NAMES:
            return product, match.group("version")
    return None


async def run_recon_assessment(
    *,
    session: Any,
    target_ip: str,
    reports_dir: Path,
    ctx: "RuntimeContext | None" = None,
) -> ReconAssessment:
    """Run quick recon against target and build a structured assessment.

    Executes check_os, quick_scan, and search_cve_intel for each discovered
    service. Returns a ReconAssessment ready for goal suggestion.
    """
    _ui = ctx.ui if ctx is not None else ui
    _ui.status("Running reconnaissance assessment...")
    _ui.divider()

    # ── Step 1: OS detection ──
    with _ui.spinner("Probing OS via TTL and port analysis...", soft_fail=True):
        try:
            os_raw = await session.call_tool("check_os", {"target_ip": target_ip})
            os_result = _extract_tool_text(os_raw)
        except _EXC_GROUP_CATCH as exc:
            # ``BaseExceptionGroup`` is *not* an ``Exception`` subclass — must be
            # listed explicitly or the spinner exits with a confusing [ERROR] line
            # and the user sees no underlying cause.
            _ui.warning(f"OS detection failed: {exc}")
            os_result = f"OS_CHECK_RESULTS:\nTARGET: {target_ip}\nOS_VERDICT: UNKNOWN\nHINTS: Error: {exc}"
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)

    _ui.result("OS Detection", os_result[:800])

    # ── Step 2: Quick port scan ──
    with _ui.spinner("Scanning top 24 ports...", soft_fail=True):
        try:
            scan_raw = await session.call_tool(
                "quick_scan",
                {
                    "target_ip": target_ip,
                    "ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,9000,27017,6379",
                },
            )
            scan_result = _extract_tool_text(scan_raw)
        except _EXC_GROUP_CATCH as exc:
            _ui.warning(f"Port scan failed: {exc}")
            scan_result = f"QUICK_SCAN_RESULTS: {target_ip}\nSUMMARY: 0/0 ports open\nNOTE: Scan error: {exc}"
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)

    _ui.result("Port Scan", scan_result[:1200])

    # ── Step 3: CVE lookup per discovered service ──
    cve_results: list[dict[str, Any]] = []
    open_ports: list[tuple[str, str, str, str]] = []
    for line in scan_result.splitlines():
        port_match = re.match(
            r"\s*Port\s+(\d+)/(tcp|udp)\s+OPEN\s*\((\w*)\)\s*-\s*(.*)",
            line,
        )
        if port_match:
            open_ports.append(port_match.groups())

    if open_ports:
        # ponytail: pre-filter to the queryable subset (banner identifies a
        # concrete product+version). The skip predicate is a pure function of
        # the banner already in hand, so we compute it once instead of
        # iterating all 23 ports and logging "Skipping..." 22 times. Also
        # makes the announcement count honest ("N of M") instead of
        # implying all M will be queried.
        queryable: list[tuple[str, str, str, tuple[str, str]]] = []
        for port, proto, service, banner in open_ports:
            b = "" if banner.strip() == "(no banner)" else banner.strip()
            qv = _cve_query_from_banner(b)
            if qv is not None:
                queryable.append((port, proto, service, qv))
        _ui.info(f"Looking up CVEs for {len(queryable)} of {len(open_ports)} discovered service(s)...")
        for port, proto, service, (product, version) in queryable:
            query = f"{product} {version}"
            with _ui.spinner(f"Looking up CVEs for {product} {version} on port {port}..."):
                try:
                    cve_raw = await session.call_tool("search_cve_intel", {"query": query})
                    cve_text = _extract_tool_text(cve_raw)
                    cve_results.append(
                        {
                            "service": service,
                            "product": product,
                            "version": version,
                            "port": port,
                            "results": cve_text[:2000],
                        }
                    )
                    _ui.result(f"CVEs for {product} {version}", cve_text[:600])
                except _EXC_GROUP_CATCH as exc:
                    _ui.warning(f"CVE lookup skipped for {service}: {exc}")
                    if _is_exception_group(exc):
                        _log_nested_exceptions(exc)

    # ── Build assessment ──
    assessment = build_assessment_from_mcp_results(
        target_ip=target_ip,
        os_result=os_result,
        scan_result=scan_result,
        cve_results=cve_results,
    )

    # ── Persist to reports dir ──
    assessment_path = reports_dir / "recon_assessment.json"
    assessment_path.write_text(json.dumps(assessment.to_dict(), indent=2), encoding="utf-8")
    _ui.info(f"Recon assessment saved to: {assessment_path}")

    return assessment


def _extract_tool_text(raw: Any) -> str:
    """Extract text content from an MCP tool call result."""
    if isinstance(raw, str):
        return raw
    if hasattr(raw, "content"):
        content = raw.content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if hasattr(item, "text"):
                    parts.append(item.text)
                elif isinstance(item, dict) and "text" in item:
                    parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)
            return "\n".join(parts)
        if isinstance(content, str):
            return content
    return str(raw)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
