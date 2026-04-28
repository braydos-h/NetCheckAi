"""MCP server exposing a restricted Nmap-only tool interface."""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from tools.nmap_tools import (
    RFC1918_NETWORKS,
    SCAN_PROFILES,
    SafeNmapRunner,
    SafeNmapSettings,
    ScanProfileName,
    parse_ipv4_networks,
    validate_subnet,
)
from tools.search_tools import SearchSettings, VulnerabilitySearch
from tools.cve_lookup import CVESearchSettings, NVDClient, format_cve_results


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping.")
    return loaded


def build_runner(args: argparse.Namespace) -> SafeNmapRunner:
    config = load_config(args.config)
    safety = config.get("safety", {}) or {}
    nmap_config = config.get("nmap", {}) or {}
    reports_config = config.get("reports", {}) or {}

    allowed_private = parse_ipv4_networks(
        safety.get(
            "allowed_private_cidrs",
            [str(network) for network in RFC1918_NETWORKS],
        )
    )
    max_subnet_addresses = int(safety.get("max_subnet_addresses", 1024))

    approved_values = args.approved_subnets or os.environ.get("APPROVED_SUBNETS", "")
    approved_subnets = []
    for raw_value in approved_values.split(","):
        value = raw_value.strip()
        if not value:
            continue
        approved_subnets.append(
            validate_subnet(value, allowed_private, max_subnet_addresses)
        )

    if not approved_subnets:
        raise ValueError(
            "No approved subnets were provided. Pass --approved-subnets or set APPROVED_SUBNETS."
        )

    reports_dir = Path(
        args.reports_dir
        or os.environ.get("REPORTS_DIR", "")
        or reports_config.get("base_dir", "reports")
    )

    profile_name: ScanProfileName = args.profile or str(nmap_config.get("default_profile", "standard"))
    if profile_name not in SCAN_PROFILES:
        profile_name = "standard"

    settings = SafeNmapSettings(
        approved_subnets=tuple(approved_subnets),
        allowed_private_cidrs=tuple(allowed_private),
        reports_dir=reports_dir,
        nmap_path=str(nmap_config.get("path", "nmap")),
        nmap_timeout_seconds=int(nmap_config.get("timeout_seconds", 180)),
        vuln_timeout_seconds=int(nmap_config.get("vuln_timeout_seconds", 300)),
        triage_top_ports=int(nmap_config.get("triage_top_ports", 100)),
        max_output_chars=int(nmap_config.get("max_output_chars", 60_000)),
        max_subnet_addresses=max_subnet_addresses,
        scan_profile=profile_name,
    )
    return SafeNmapRunner(settings)


def build_search(config: dict[str, Any]) -> VulnerabilitySearch:
    search_config = config.get("search", {}) or {}
    enabled = bool(search_config.get("enabled", True))
    if os.environ.get("DISABLE_VULN_SEARCH") == "1":
        enabled = False
    settings = SearchSettings(
        enabled=enabled,
        endpoint=str(search_config.get("endpoint", "https://serpapi.com/search.json")),
        engine=str(search_config.get("engine", "duckduckgo")),
        region=str(search_config.get("region", "us-en")),
        api_key_env=str(search_config.get("api_key_env", "SERPAPI_API_KEY")),
        timeout_seconds=int(search_config.get("timeout_seconds", 20)),
        max_results=int(search_config.get("max_results", 5)),
    )
    return VulnerabilitySearch(settings)


def build_cve_search(config: dict[str, Any]) -> NVDClient:
    cve_config = config.get("cve_lookup", {}) or {}
    enabled = bool(cve_config.get("enabled", True))
    settings = CVESearchSettings(
        enabled=enabled,
        timeout_seconds=int(cve_config.get("timeout_seconds", 30)),
        max_results=int(cve_config.get("max_results", 5)),
        cache_ttl_seconds=int(cve_config.get("cache_ttl_seconds", 3600)),
        cache_max_entries=int(cve_config.get("cache_max_entries", 100)),
        rate_limit_seconds=float(cve_config.get("rate_limit_seconds", 6.0)),
        api_key_env=str(cve_config.get("api_key_env", "NVD_API_KEY")),
    )
    return NVDClient(settings)


def create_mcp_server(runner: SafeNmapRunner, search: VulnerabilitySearch, nvd: NVDClient):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "The MCP Python SDK is not installed. Run: python -m pip install -r requirements.txt"
        ) from exc

    mcp = FastMCP(
        "Defensive Local Nmap Tools",
        instructions=(
            "Restricted Nmap tools for defensive local-network assessment only. "
            "All scan targets must be runtime-approved RFC1918 IPv4 ranges. "
            "The search tools are for defensive vulnerability advisories and remediation only."
        ),
        json_response=True,
    )

    @mcp.tool()
    def run_nmap_ping_sweep(subnet: str) -> str:
        """Run only `nmap -sn <subnet>` against an approved private subnet."""
        return runner.run_nmap_ping_sweep(subnet)

    @mcp.tool()
    def run_nmap_triage_scan(subnet: str) -> str:
        """Run only `nmap -sV --top-ports 100 --open <subnet>` after discovery."""
        return runner.run_nmap_triage_scan(subnet)

    @mcp.tool()
    def run_nmap_basic_scan(ip: str) -> str:
        """Run only `nmap -sV --top-ports 1000 <ip>` after discovery."""
        return runner.run_nmap_basic_scan(ip)

    @mcp.tool()
    def run_nmap_service_scan(ip: str) -> str:
        """Run only `nmap -sV -sC -O <ip>` after the basic scan."""
        return runner.run_nmap_service_scan(ip)

    @mcp.tool()
    def run_nmap_vuln_scan(ip: str) -> str:
        """Run only `nmap --script vuln -sV <ip>` after the service scan."""
        return runner.run_nmap_vuln_scan(ip)

    @mcp.tool()
    def run_limited_terminal(command: str) -> str:
        """Run an allowlisted Nmap command; all other commands are blocked."""
        return runner.run_limited_terminal(command)

    @mcp.tool()
    def search_vulnerability_intel(query: str) -> str:
        """Search public vulnerability advisories and remediation notes for service/version evidence."""
        return search.search_vulnerability_intel(query)

    @mcp.tool()
    def search_cve_intel(query: str) -> str:
        """Look up CVEs in the NVD database for a known product/version string. Do not use for unknown services."""
        entries = nvd.search_sync(query)
        return format_cve_results(entries, query)

    return mcp


def run_http_server(mcp: Any, host: str, port: int) -> None:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("HTTP transport may only bind to 127.0.0.1/localhost.")

    try:
        import uvicorn
        from starlette.applications import Starlette
        from starlette.routing import Mount
    except ImportError as exc:
        raise RuntimeError(
            "HTTP MCP transport needs uvicorn and starlette. "
            "Run: python -m pip install -r requirements.txt"
        ) from exc

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette):
        async with mcp.session_manager.run():
            yield

    app = Starlette(routes=[Mount("/", app=mcp.streamable_http_app())], lifespan=lifespan)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--approved-subnets", default="")
    parser.add_argument("--reports-dir", default="")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--profile", choices=tuple(SCAN_PROFILES.keys()), default=None, help="Scan profile")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    config = load_config(args.config)
    runner = build_runner(args)
    search = build_search(config)
    nvd = build_cve_search(config)
    mcp = create_mcp_server(runner, search, nvd)
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        run_http_server(mcp, args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
