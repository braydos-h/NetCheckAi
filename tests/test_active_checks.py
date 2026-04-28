"""Tests for user-approved active check execution policy."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from tools.active_checks import (
    ActiveCheckPolicy,
    ActiveCheckSettings,
    TerminalExecution,
    read_active_check_records,
)


class RecordingTerminalRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        command: str | list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        log_path: Path,
        timeout_seconds: int,
        title: str,
    ) -> TerminalExecution:
        self.calls.append(
            {
                "command": command,
                "cwd": cwd,
                "env": env,
                "log_path": log_path,
                "timeout_seconds": timeout_seconds,
                "title": title,
            }
        )
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("active check output\n", encoding="utf-8")
        return TerminalExecution(
            status="completed",
            exit_code=0,
            log_path=log_path,
            duration_seconds=0.01,
        )


def make_policy(
    tmp_path: Path,
    *,
    enabled: bool = True,
    prompt: str | list[str] = "ALLOW 192.168.1.10",
    runner: RecordingTerminalRunner | None = None,
) -> ActiveCheckPolicy:
    subnet = ipaddress.ip_network("192.168.1.0/24")
    if isinstance(prompt, list):
        answers = iter(prompt)
        prompt_func = lambda _: next(answers)
    else:
        prompt_func = lambda _: prompt
    return ActiveCheckPolicy(
        settings=ActiveCheckSettings(enabled=enabled, command_timeout_seconds=5),
        reports_dir=tmp_path,
        approved_subnets=(subnet,),
        completed_ping_sweeps={str(subnet)},
        live_hosts_by_subnet={str(subnet): {"192.168.1.10"}},
        triaged_subnets={str(subnet)},
        runner=runner or RecordingTerminalRunner(),
        prompt_func=prompt_func,
    )


@pytest.mark.asyncio
async def test_active_checks_disabled_by_default_blocks_session(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, enabled=False)

    result = await policy.request_host_session("192.168.1.10", "validate exposed service")

    assert result.startswith("BLOCKED:")
    assert "disabled" in result


@pytest.mark.asyncio
async def test_host_must_be_discovered_and_triaged(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)

    result = await policy.request_host_session("192.168.1.11", "validate exposed service")

    assert result.startswith("BLOCKED:")
    assert "not reported alive" in result


@pytest.mark.asyncio
async def test_python_active_check_requires_session_and_command_approval(tmp_path: Path) -> None:
    runner = RecordingTerminalRunner()
    policy = make_policy(tmp_path, runner=runner)

    session = await policy.request_host_session("192.168.1.10", "validate HTTP behavior")
    result = await policy.propose_active_python(
        ip="192.168.1.10",
        filename="check_http.py",
        code=(
            "import argparse\n"
            "parser = argparse.ArgumentParser()\n"
            "parser.add_argument('--target', required=True)\n"
            "args = parser.parse_args()\n"
            "print(args.target)\n"
        ),
        command="python check_http.py --target 192.168.1.10",
        purpose="Validate service behavior with a short Python connection check.",
        risk_note="Single target only and no authentication attempts.",
    )

    assert "approved" in session
    assert "ACTIVE_CHECK_RESULT: completed" in result
    assert len(runner.calls) == 1
    command = runner.calls[0]["command"]
    assert isinstance(command, list)
    assert command[-2:] == ["--target", "192.168.1.10"]
    records = read_active_check_records(tmp_path)
    assert records[0]["approved"] is True
    assert records[0]["status"] == "completed"
    assert Path(records[0]["script_path"]).is_file()


@pytest.mark.asyncio
async def test_command_approval_denial_never_runs(tmp_path: Path) -> None:
    runner = RecordingTerminalRunner()
    policy = make_policy(tmp_path, prompt=["ALLOW 192.168.1.10", "no"], runner=runner)

    await policy.request_host_session("192.168.1.10", "validate HTTP behavior")
    result = await policy.propose_active_shell(
        ip="192.168.1.10",
        command="ping 192.168.1.10",
        purpose="Confirm host responsiveness.",
        risk_note="Single ICMP request.",
    )

    assert "ACTIVE_CHECK_RESULT: denied" in result
    assert runner.calls == []


@pytest.mark.asyncio
async def test_shell_command_cannot_reference_other_ips(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    await policy.request_host_session("192.168.1.10", "validate host")

    result = await policy.propose_active_shell(
        ip="192.168.1.10",
        command="ping 192.168.1.11",
        purpose="Confirm host responsiveness.",
        risk_note="Single ICMP request.",
    )

    assert "ACTIVE_CHECK_RESULT: blocked" in result
    assert "target IP 192.168.1.10" in result


@pytest.mark.asyncio
async def test_shell_command_blocks_inline_python_bypass(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    await policy.request_host_session("192.168.1.10", "validate host")

    result = await policy.propose_active_shell(
        ip="192.168.1.10",
        command="python -c print(192.168.1.10)",
        purpose="Run inline script.",
        risk_note="Single target only.",
    )

    assert "ACTIVE_CHECK_RESULT: blocked" in result
    assert "not allowed" in result
