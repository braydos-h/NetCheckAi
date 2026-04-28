"""Tests for sub-agent Ollama response handling."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools.sub_agents import AgentBudget, HostSubAgent, spawn_sub_agents


class DictResponseClient:
    def chat(self, model: str, **kwargs):
        return {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "finish_assessment",
                            "arguments": {
                                "findings": (
                                    '{"risk_level":"low","title":"No exposed services",'
                                    '"open_ports":[],"evidence":"No actionable exposure."}'
                                )
                            },
                        }
                    }
                ],
            }
        }


class ObjectResponseClient:
    def chat(self, model: str, **kwargs):
        return SimpleNamespace(
            message=SimpleNamespace(
                content="",
                tool_calls=[
                    SimpleNamespace(
                        function=SimpleNamespace(
                            name="finish_assessment",
                            arguments='{"findings":"{\\"risk_level\\":\\"low\\",\\"title\\":\\"Object response parsed\\"}"}',
                        )
                    )
                ],
            )
        )


class ScanThenFinishClient:
    def __init__(self) -> None:
        self.calls = 0

    def chat(self, model: str, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return {
                "message": {
                    "content": "",
                    "tool_calls": [{"function": {"name": "run_nmap_basic_scan", "arguments": {}}}],
                }
            }
        return {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "finish_assessment",
                            "arguments": {
                                "findings": '{"risk_level":"low","title":"Scan tool completed"}'
                            },
                        }
                    }
                ],
            }
        }


class FakeRunner:
    def __init__(self) -> None:
        self.basic_scans: list[str] = []

    async def run_nmap_basic_scan_async(self, ip: str) -> str:
        self.basic_scans.append(ip)
        return f"COMMAND: nmap -sV --top-ports 1000 {ip}\nOUTPUT:\nEXIT_CODE: 0"


class FakeSearch:
    def search_vulnerability_intel(self, query: str) -> str:
        return "Search disabled in test."


class FakeNVD:
    async def search(self, query: str) -> list[object]:
        return []


@pytest.mark.asyncio
async def test_host_sub_agent_handles_non_streaming_dict_response() -> None:
    agent = HostSubAgent(
        ip="192.168.1.10",
        triage_context="IP: 192.168.1.10",
        client=DictResponseClient(),
        model="test-model",
        tools=object(),
    )

    finding = await agent.run()

    assert finding.risk_level == "low"
    assert finding.title == "No exposed services"


@pytest.mark.asyncio
async def test_host_sub_agent_handles_object_tool_calls() -> None:
    agent = HostSubAgent(
        ip="192.168.1.10",
        triage_context="IP: 192.168.1.10",
        client=ObjectResponseClient(),
        model="test-model",
        tools=object(),
    )

    finding = await agent.run()

    assert finding.title == "Object response parsed"


@pytest.mark.asyncio
async def test_spawn_sub_agents_wires_budget_before_nvd_for_scan_tools() -> None:
    runner = FakeRunner()

    findings = await spawn_sub_agents(
        ranked_hosts=[
            SimpleNamespace(
                ip="192.168.1.10",
                score=1,
                severity="low",
                reasons=[],
                services=[],
            )
        ],
        runner=runner,
        search=FakeSearch(),
        nvd=FakeNVD(),
        client=ScanThenFinishClient(),
        model="test-model",
        budget=AgentBudget(max_tool_calls=1, max_searches=0, max_hosts=1),
        concurrency=1,
        max_sub_agent_rounds=2,
    )

    assert runner.basic_scans == ["192.168.1.10"]
    assert findings[0].title == "Scan tool completed"
