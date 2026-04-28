"""Parallel sub-agents that run focused LLM assessment loops per suspicious host."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.nmap_tools import (
    SafeNmapRunner,
    build_compact_summary,
    nmap_completed,
    parse_nmap_xml,
)
from tools.search_tools import VulnerabilitySearch, sanitize_query
from tools.cve_lookup import CVESearchSettings, NVDClient, format_cve_results


if TYPE_CHECKING:
    from tools.activity_log import ActivityLog


SUB_AGENT_SYSTEM_PROMPT = """You are a focused defensive security assessor assigned to a single host.

Rules:
- You may only use the provided tools for your assigned host IP.
- Run scans in order: basic_scan, then service_scan, then optionally vuln_scan if evidence supports it.
- Use search_vulnerability_intel for service/version strings found on your host.
- Do not scan other IPs, exploit, brute force, or weaponize anything.
- Return your findings as a structured JSON report at the end.
- Keep all advice remediation-focused.
"""

SUB_AGENT_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_nmap_basic_scan",
            "description": "Run nmap -sV --top-ports 1000 on the assigned host.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_nmap_service_scan",
            "description": "Run nmap -sV -sC -O on the assigned host after basic scan.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_nmap_vuln_scan",
            "description": "Run nmap --script vuln -sV on the assigned host after service scan.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_vulnerability_intel",
            "description": "Search public vulnerability advisories for a service/version string.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Service and version to search."}
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_cve_intel",
            "description": "Look up CVEs in the NVD database for a known product/version string (e.g. 'Apache HTTPD 2.4.41'). Do not use for unknown services.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Known product and version to search."}
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish_assessment",
            "description": "Finish the assessment and submit structured findings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "string",
                        "description": (
                            "JSON string with keys: risk_level (low/medium/high/critical), "
                            "title, open_ports (list of dicts with port, service, version), "
                            "evidence, severity_reason, remediation, services_researched (list)."
                        ),
                    }
                },
                "required": ["findings"],
            },
        },
    },
]


@dataclass
class StructuredFinding:
    risk_level: str = "low"
    title: str = ""
    open_ports: list[dict[str, str]] = field(default_factory=list)
    evidence: str = ""
    severity_reason: str = ""
    remediation: str = ""
    services_researched: list[str] = field(default_factory=list)
    host: str = ""
    service_versions: list[str] = field(default_factory=list)
    cves_found: list[str] = field(default_factory=list)


class AgentBudget:
    """Shared async-safe budget for sub-agent tool and search calls."""

    def __init__(
        self,
        *,
        max_tool_calls: int,
        max_searches: int,
        max_hosts: int,
    ):
        self._max_tool = max_tool_calls
        self._max_search = max_searches
        self._max_hosts = max_hosts
        self._tool_used = 0
        self._search_used = 0
        self._lock = asyncio.Lock()
        self._search_cache: OrderedDict[str, str] = OrderedDict()
        self._host_finished: set[str] = set()

    async def try_claim_host(self, ip: str) -> bool:
        async with self._lock:
            if ip in self._host_finished or len(self._host_finished) >= self._max_hosts:
                return False
            self._host_finished.add(ip)
            return True

    async def try_tool(self) -> bool:
        async with self._lock:
            if self._tool_used >= self._max_tool:
                return False
            self._tool_used += 1
            return True

    async def try_search(self, query: str) -> tuple[bool, str | None]:
        """Return (ok, cached_result). If ok and cached_result is None, caller should search."""
        async with self._lock:
            if query in self._search_cache:
                return True, self._search_cache[query]
            if self._search_used >= self._max_search:
                return False, None
            self._search_used += 1
            return True, None

    def cache_search(self, query: str, result: str) -> None:
        self._search_cache[query] = result


class SubAgentTools:
    """Lightweight tool executor used by HostSubAgent (no MCP overhead)."""

    def __init__(
        self,
        ip: str,
        runner: SafeNmapRunner,
        search: VulnerabilitySearch,
        budget: AgentBudget,
        nvd: NVDClient,
        activity_log: Any | None = None,
    ):
        self.ip = ip
        self.runner = runner
        self.search = search
        self.nvd = nvd
        self.budget = budget
        self.activity_log = activity_log
        self.transcript: list[dict[str, Any]] = []

    async def run_nmap_basic_scan(self) -> str:
        if not await self.budget.try_tool():
            if self.activity_log:
                self.activity_log.budget_warning(0, "tool calls")
            return "BLOCKED: global tool-call budget exhausted."
        if self.activity_log:
            self.activity_log.agent_scan(self.ip, "basic")
        result = await self.runner.run_nmap_basic_scan_async(self.ip)
        self.transcript.append({"tool": "run_nmap_basic_scan", "result": result})
        return result

    async def run_nmap_service_scan(self) -> str:
        if not await self.budget.try_tool():
            if self.activity_log:
                self.activity_log.budget_warning(0, "tool calls")
            return "BLOCKED: global tool-call budget exhausted."
        if self.activity_log:
            self.activity_log.agent_scan(self.ip, "service")
        result = await self.runner.run_nmap_service_scan_async(self.ip)
        self.transcript.append({"tool": "run_nmap_service_scan", "result": result})
        return result

    async def run_nmap_vuln_scan(self) -> str:
        if not await self.budget.try_tool():
            if self.activity_log:
                self.activity_log.budget_warning(0, "tool calls")
            return "BLOCKED: global tool-call budget exhausted."
        if self.activity_log:
            self.activity_log.agent_scan(self.ip, "vuln")
        result = await self.runner.run_nmap_vuln_scan_async(self.ip)
        self.transcript.append({"tool": "run_nmap_vuln_scan", "result": result})
        return result

    async def search_vulnerability_intel(self, query: str) -> str:
        try:
            sanitize_query(query)
        except ValueError as exc:
            return f"BLOCKED: {exc}"
        ok, cached = await self.budget.try_search(query)
        if not ok:
            if self.activity_log:
                self.activity_log.budget_warning(0, "searches")
            return "BLOCKED: global search budget exhausted; continue from Nmap evidence."
        if cached is not None:
            return f"CACHED:\n{cached}"
        if self.activity_log:
            self.activity_log.agent_search(self.ip, query)
        result = await self.search.search_vulnerability_intel_async(query)
        self.budget.cache_search(query, result)
        self.transcript.append({"tool": "search_vulnerability_intel", "query": query, "result": result})
        return result

    async def search_cve_intel(self, query: str) -> str:
        """Look up CVEs via NVD for a known product/version string."""
        try:
            sanitize_query(query)
        except ValueError as exc:
            return f"BLOCKED: {exc}"
        ok, cached = await self.budget.try_search(query)
        if not ok:
            if self.activity_log:
                self.activity_log.budget_warning(0, "searches")
            return "BLOCKED: global search budget exhausted; continue from Nmap evidence."
        if cached is not None:
            return f"CACHED:\n{cached}"
        if self.activity_log:
            self.activity_log.agent_search(self.ip, query)
        try:
            entries = await self.nvd.search(query)
            result = format_cve_results(entries, query)
        except Exception as exc:
            result = f"ERROR: CVE lookup failed: {exc}"
        self.budget.cache_search(query, result)
        self.transcript.append({"tool": "search_cve_intel", "query": query, "result": result})
        return result


class HostSubAgent:
    """Per-host focused LLM assessment worker."""

    def __init__(
        self,
        ip: str,
        triage_context: str,
        client: Any,
        model: str,
        tools: SubAgentTools,
        max_sub_agent_rounds: int = 8,
    ):
        self.ip = ip
        self.triage_context = triage_context
        self.client = client
        self.model = model
        self.tools = tools
        self.max_rounds = max_sub_agent_rounds
        self.finding = StructuredFinding(host=ip)
        self.finished = False

    async def run(self) -> StructuredFinding:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SUB_AGENT_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Your assigned host is {self.ip}.\n"
                    f"Triage summary for this host:\n{self.triage_context}\n\n"
                    "Available tools:\n"
                    "- run_nmap_basic_scan (always start here)\n"
                    "- run_nmap_service_scan (after basic scan)\n"
                    "- run_nmap_vuln_scan (only if evidence suggests risk)\n"
                    "- search_vulnerability_intel (use for service/version strings, not IPs)\n"
                    "- search_cve_intel (use only when a known product/version is found; not for unknown services)\n"
                    "- finish_assessment (submit your structured JSON findings)\n\n"
                    "Run the scans in order, researching services as you go. "
                    "Then call finish_assessment with a JSON string like:\n"
                    '{"risk_level":"high","title":"Exposed SMB on Windows Server...",'
                    '"open_ports":[{"port":"445/tcp","service":"microsoft-ds","version":"..."}],'
                    '"evidence":"Nmap found ...","severity_reason":"SMB is exposed with old version...",'
                    '"remediation":"Disable NetBIOS/SMB if unused...","services_researched":["SMB ..."]}'
                ),
            },
        ]

        for _ in range(self.max_rounds):
            if self.finished:
                break
            assistant = await self._chat(messages)
            messages.append(assistant)
            calls = assistant.get("tool_calls", [])
            if not calls:
                # Model didn't call a tool and didn't finish; coerce finish
                messages.append({
                    "role": "user",
                    "content": (
                        "You must call finish_assessment now with your structured JSON findings. "
                        "If there is no risk, use risk_level='low' and a concise explanation."
                    ),
                })
                continue
            for call in calls:
                result = await self._execute_tool_call(call)
                messages.append({"role": "tool", "tool_name": call.get("function", {}).get("name", ""), "content": result})
                if self.finished:
                    break

        return self.finding

    async def _chat(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._sync_chat, messages
        )

    def _sync_chat(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        compacted = self._compact_messages(messages)
        kwargs: dict[str, Any] = {"messages": compacted, "stream": False, "tools": SUB_AGENT_TOOL_SCHEMAS}
        response = self.client.chat(self.model, **kwargs)
        message = get_field(response, "message", {}) or {}
        content = get_field(message, "content", "") or ""
        thinking = get_field(message, "thinking", "") or ""
        response_tool_calls = get_field(message, "tool_calls", []) or []
        tool_calls: list[dict[str, Any]] = []
        for call in response_tool_calls:
            tool_calls.append(self._normalize_call(call))

        out: dict[str, Any] = {"role": "assistant", "content": str(content)}
        if thinking:
            out["thinking"] = str(thinking)
        if tool_calls:
            out["tool_calls"] = tool_calls
        return out

    @staticmethod
    def _compact_messages(messages: list[dict[str, Any]], keep_full_tool_results: int = 3) -> list[dict[str, Any]]:
        """Trim older tool results to reduce LLM token usage while keeping full context for recent rounds."""
        if len(messages) <= keep_full_tool_results + 2:
            return messages
        compacted: list[dict[str, Any]] = []
        tool_result_count = 0
        for msg in reversed(messages):
            if msg.get("role") == "tool":
                tool_result_count += 1
                if tool_result_count > keep_full_tool_results:
                    # Replace bulky result with a summary placeholder
                    name = msg.get("tool_name", "tool")
                    compacted.append({
                        "role": "tool",
                        "tool_name": name,
                        "content": f"[{name} result omitted to save context; see later full results.]",
                    })
                    continue
            compacted.append(msg)
        return list(reversed(compacted))

    def _normalize_call(self, call: Any) -> dict[str, Any]:
        function = get_field(call, "function", {}) or {}
        name = get_field(function, "name", "") or ""
        arguments = get_field(function, "arguments", {}) or {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {}
        return {"type": "function", "function": {"name": name, "arguments": arguments}}

    async def _execute_tool_call(self, call: dict[str, Any]) -> str:
        function = call.get("function", {})
        name = function.get("name", "")
        arguments = function.get("arguments", {}) or {}

        if name == "run_nmap_basic_scan":
            return await self.tools.run_nmap_basic_scan()
        if name == "run_nmap_service_scan":
            return await self.tools.run_nmap_service_scan()
        if name == "run_nmap_vuln_scan":
            return await self.tools.run_nmap_vuln_scan()
        if name == "search_vulnerability_intel":
            return await self.tools.search_vulnerability_intel(arguments.get("query", ""))
        if name == "search_cve_intel":
            return await self.tools.search_cve_intel(arguments.get("query", ""))
        if name == "finish_assessment":
            self._finish(arguments.get("findings", "{}"))
            return "Assessment finished."
        return f"ERROR: unknown tool {name!r}."

    def _finish(self, findings_json: str) -> None:
        self.finished = True
        if not findings_json or findings_json.strip() in ("{}", ""):
            self.finding.title = f"No clear findings from sub-agent for {self.ip}"
            self.finding.risk_level = "low"
            return
        # Sanitize: strip markdown fences if the model added them
        cleaned = findings_json.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            # Fallback: store raw text as evidence
            self.finding.evidence = cleaned[:2000]
            self.finding.title = f"Sub-agent raw assessment for {self.ip}"
            self.finding.risk_level = "low"
            return

        self.finding.risk_level = str(data.get("risk_level", "low")).lower()
        self.finding.title = str(data.get("title", "")) or f"Assessment for {self.ip}"
        self.finding.open_ports = data.get("open_ports", []) or []
        self.finding.evidence = str(data.get("evidence", ""))[:4000]
        self.finding.severity_reason = str(data.get("severity_reason", ""))[:2000]
        self.finding.remediation = str(data.get("remediation", ""))[:4000]
        self.finding.services_researched = data.get("services_researched", []) or []
        self.finding.cves_found = data.get("cves_found", []) or []
        self.finding.service_versions = data.get("service_versions", []) or []


def get_field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


async def spawn_sub_agents(
    *,
    ranked_hosts: list[Any],
    runner: SafeNmapRunner,
    search: VulnerabilitySearch,
    nvd: NVDClient,
    client: Any,
    model: str,
    budget: AgentBudget,
    concurrency: int,
    max_sub_agent_rounds: int,
    activity_log: Any | None = None,
) -> list[StructuredFinding]:
    """Spawn sub-agent tasks for each suspicious host, respecting budgets."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks: list[asyncio.Task[StructuredFinding]] = []

    async def _work(ip: str, triage_context: str) -> StructuredFinding:
        async with semaphore:
            claimed = await budget.try_claim_host(ip)
            if not claimed:
                if activity_log:
                    activity_log.agent_fail(ip, "host budget exhausted")
                return StructuredFinding(host=ip, title=f"Skipped {ip}: host budget exhausted", risk_level="low")
            if activity_log:
                activity_log.agent_spawn(ip, triage_context[:120])
            tools = SubAgentTools(
                ip=ip,
                runner=runner,
                search=search,
                budget=budget,
                nvd=nvd,
                activity_log=activity_log,
            )
            agent = HostSubAgent(
                ip=ip,
                triage_context=triage_context,
                client=client,
                model=model,
                tools=tools,
                max_sub_agent_rounds=max_sub_agent_rounds,
            )
            try:
                result = await agent.run()
            except Exception as exc:
                if activity_log:
                    activity_log.agent_fail(ip, str(exc))
                return StructuredFinding(host=ip, title=f"Error on {ip}: {exc}", risk_level="low")
            if activity_log:
                activity_log.agent_done(ip, result)
            return result

    for host in ranked_hosts:
        ip = str(getattr(host, "ip", host))
        score = getattr(host, "score", 0)
        severity = getattr(host, "severity", "low")
        reasons = getattr(host, "reasons", [])
        services = getattr(host, "services", [])
        triage_context = (
            f"IP: {ip}\nScore: {score}\nSeverity: {severity}\n"
            f"Reasons: {'; '.join(reasons)}\n"
            f"Services: {json.dumps(services)}"
        )
        tasks.append(asyncio.create_task(_work(ip, triage_context)))

    if not tasks:
        return []
    return await asyncio.gather(*tasks)
