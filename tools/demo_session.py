"""Mock MCP session for demo mode.

Acts like a real MCP ClientSession but returns pre-crafted fake results
so the AI processes them as if they were real scan output.
"""

from __future__ import annotations

import json
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator

from tools import demo_data


class _FakeMcpResult:
    """Drop-in replacement for MCP tool-call result objects."""

    def __init__(self, text: str, is_error: bool = False):
        self._text = text
        self._is_error = is_error

    @property
    def isError(self) -> bool:
        return self._is_error

    @property
    def is_error(self) -> bool:
        return self._is_error

    @property
    def content(self) -> list[dict[str, Any]]:
        return [{"type": "text", "text": self._text}]


@dataclass
class DemoSessionState:
    """Tracks which fake results have already been returned so we can vary responses."""

    ping_done: set[str] = field(default_factory=set)
    triage_done: set[str] = field(default_factory=set)
    basic_done: set[str] = field(default_factory=set)
    service_done: set[str] = field(default_factory=set)
    vuln_done: set[str] = field(default_factory=set)


class DemoSession:
    """Async mock MCP session that returns synthetic scan results."""

    DEMO_TOOLS: list[dict[str, Any]] = [
        {
            "name": "run_nmap_ping_sweep",
            "description": "Run nmap -sn <subnet> against an approved private subnet.",
            "inputSchema": {
                "type": "object",
                "properties": {"subnet": {"type": "string"}},
                "required": ["subnet"],
            },
        },
        {
            "name": "run_nmap_triage_scan",
            "description": "Run triage port checks only against hosts found alive.",
            "inputSchema": {
                "type": "object",
                "properties": {"subnet": {"type": "string"}},
                "required": ["subnet"],
            },
        },
        {
            "name": "run_nmap_basic_scan",
            "description": "Run nmap -sV --top-ports 1000 on an in-scope host.",
            "inputSchema": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
        {
            "name": "run_nmap_service_scan",
            "description": "Run nmap -sV -sC -O on an in-scope host.",
            "inputSchema": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
        {
            "name": "run_nmap_vuln_scan",
            "description": "Run nmap --script vuln -sV on an in-scope host.",
            "inputSchema": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
        {
            "name": "run_limited_terminal",
            "description": "Run a pre-approved terminal command with no shell injection.",
            "inputSchema": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
        {
            "name": "search_vulnerability_intel",
            "description": "Search public vulnerability advisories for a service/version string.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
        {
            "name": "search_cve_intel",
            "description": "Look up CVEs in the NVD database for a known product/version string.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    ]

    def __init__(self, reports_dir: Path, state: DemoSessionState | None = None):
        self._reports_dir = reports_dir
        self._state = state or DemoSessionState()

    # --- Minimal async context manager ---

    async def __aenter__(self) -> "DemoSession":
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    # --- Public MCP-like API ---

    async def initialize(self) -> None:
        # Write fake XML files so downstream parsing works
        xml_dir = self._reports_dir / "xml_nmap"
        raw_dir = self._reports_dir / "raw_nmap"
        xml_dir.mkdir(parents=True, exist_ok=True)
        raw_dir.mkdir(parents=True, exist_ok=True)

        # Pre-write discovery + triage XML
        _write(xml_dir / "10.0.0.0_24_ping_sweep.xml", demo_data.nmap_xml_for_scan("10.0.0.0_24_ping_sweep"))
        _write(raw_dir / "10.0.0.0_24_ping_sweep.txt", demo_data.raw_ping_sweep())
        _write(xml_dir / "10.0.0.0_24_triage_scan.xml", demo_data.nmap_xml_for_scan("triage"))
        _write(raw_dir / "10.0.0.0_24_triage_scan.txt", demo_data.raw_triage_scan())

    async def list_tools(self) -> Any:
        """Return an object compatible with main.py mcp_tools_to_ollama."""
        return _FakeToolsResponse(self.DEMO_TOOLS)

    async def call_tool(self, name: str, *, arguments: dict[str, Any]) -> Any:
        text = self._dispatch(name, arguments)
        self._maybe_write_artifact(name, arguments, text)
        return _FakeMcpResult(text)

    # --- Internal dispatch ---

    def _dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        if name == "run_nmap_ping_sweep":
            subnet = str(arguments.get("subnet", ""))
            if "10.0.0" in subnet:
                self._state.ping_done.add(subnet)
                return demo_data.raw_ping_sweep()
            return f"ERROR: subnet {subnet} not supported in demo."

        if name == "run_nmap_triage_scan":
            subnet = str(arguments.get("subnet", ""))
            if "10.0.0" in subnet:
                self._state.triage_done.add(subnet)
                return demo_data.raw_triage_scan()
            return f"ERROR: subnet {subnet} not supported in demo."

        if name == "run_nmap_basic_scan":
            ip = str(arguments.get("ip", ""))
            self._state.basic_done.add(ip)
            return demo_data.raw_basic_scan(ip)

        if name == "run_nmap_service_scan":
            ip = str(arguments.get("ip", ""))
            self._state.service_done.add(ip)
            return demo_data.raw_service_scan(ip)

        if name == "run_nmap_vuln_scan":
            ip = str(arguments.get("ip", ""))
            self._state.vuln_done.add(ip)
            return demo_data.raw_vuln_scan(ip)

        if name == "run_limited_terminal":
            return demo_data.raw_terminal(str(arguments.get("command", "")))

        if name == "search_vulnerability_intel":
            return demo_data.search_intel(str(arguments.get("query", "")))

        if name == "search_cve_intel":
            return demo_data.cve_intel(str(arguments.get("query", "")))

        return f"ERROR: DemoSession does not implement tool {name!r}."

    def _maybe_write_artifact(self, name: str, arguments: dict[str, Any], text: str) -> None:
        """Write fake XML / raw text files so report parsing sees artifacts."""
        xml_dir = self._reports_dir / "xml_nmap"
        raw_dir = self._reports_dir / "raw_nmap"
        xml_dir.mkdir(parents=True, exist_ok=True)
        raw_dir.mkdir(parents=True, exist_ok=True)

        if name == "run_nmap_ping_sweep":
            return
        if name == "run_nmap_triage_scan":
            return

        safe_name = _safe(str(arguments.get("ip", arguments.get("subnet", "unknown"))))

        if name == "run_nmap_basic_scan":
            ip = str(arguments.get("ip", ""))
            xml = demo_data.nmap_xml_for_scan(ip + "_basic_scan")
            _write(xml_dir / f"{safe_name}_basic_scan.xml", xml)
            _write(raw_dir / f"{safe_name}_basic_scan.txt", text)
        elif name == "run_nmap_service_scan":
            ip = str(arguments.get("ip", ""))
            xml = demo_data.nmap_xml_for_scan(ip + "_service_scan")
            _write(xml_dir / f"{safe_name}_service_scan.xml", xml)
            _write(raw_dir / f"{safe_name}_service_scan.txt", text)
        elif name == "run_nmap_vuln_scan":
            ip = str(arguments.get("ip", ""))
            xml = demo_data.nmap_xml_for_scan(ip + "_vuln_scan")
            _write(xml_dir / f"{safe_name}_vuln_scan.xml", xml)
            _write(raw_dir / f"{safe_name}_vuln_scan.txt", text)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeToolsResponse:
    def __init__(self, tools: list[dict[str, Any]]):
        self.tools = tools


def _safe(name: str) -> str:
    return name.replace("/", "_").replace("\\", "_")


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def create_demo_session(reports_dir: Path, state: DemoSessionState | None = None) -> DemoSession:
    return DemoSession(reports_dir=reports_dir, state=state)
