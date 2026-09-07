"""OPSEC AI-awareness regression tests.

Covers the two AI-facing OPSEC surfaces added so the LLM can deliberately use
the OPSEC system instead of having it applied invisibly:

1. ``tools.exploit_agent.prompt.build_opsec_briefing`` -- a target-aware,
   advisory OPSEC posture block injected into the system prompt (wired in
   ``tools/exploit_agent/runner/_impl.py``). Empty for local/private targets or when
   OPSEC is off, so the AI is never told OPSEC is "on" for the operator's own box.
2. ``tools.mcp_tools.terminal._opsec_advisory_block`` -- a per-command advisory
   block appended to every ``run_exploit_terminal`` result, surfacing a live
   noise score, a suggested quieter rewrite, and the pacing posture. Advisory
   only -- it never gates the command; ``is_quiet_blocked`` and ``noise_budget``
   stay dormant (no attack-path gate re-added).

Plain pytest, no fixtures. Hermetic: subprocess is stubbed, EXPLOIT_TARGET is
monkeypatched, OpsecManager I/O is injectable.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

# ── Harness helpers ─────────────────────────────────────────────────────────


def _make_server(tmp_path: Path, *, opsec: dict[str, Any] | None = None, require_allowlist: bool = False) -> Any:
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {"require_explicit_allowlist": require_allowlist},
        "opsec": opsec or {},
    }
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
    )


def _text(result) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts = []
    for c in content:
        t = getattr(c, "text", None)
        if t is None and isinstance(c, dict):
            t = c.get("text")
        if t is None:
            t = str(c)
        parts.append(t)
    return "".join(parts)


class _Popen(subprocess.Popen):
    """Subscriptable Popen stub (inherits ``__class_getitem__`` from Popen so
    the MCP SDK's ``subprocess.Popen[bytes]`` annotation stays valid during its
    lazy import inside ``call_tool``). Forces the Linux ``communicate`` path.
    """

    def __init__(self, argv, **kwargs):
        self.argv = argv
        self.returncode = 0
        self.stdout = None
        self.stderr = None
        self.pid = 12345
        self._stdout = b"scan complete\n"

    def communicate(self, input=None, timeout=None):
        return self._stdout, b""

    def kill(self):
        self.returncode = -9


# ── TestOpsecBriefing: prompt surface ───────────────────────────────────────


class TestOpsecBriefing:
    def test_public_target_briefing_non_empty(self) -> None:
        from tools.exploit_agent.prompt import build_opsec_briefing
        from tools.opsec import OpsecProfile

        briefing = build_opsec_briefing(OpsecProfile(enabled=True), "8.8.8.8")
        assert briefing  # non-empty for a public target with OPSEC on
        assert "OPSEC is ON" in briefing
        # noisy vocabulary the scorer already counts
        assert "masscan" in briefing
        # a concrete low-noise rewrite from the shared table
        assert "-T2" in briefing

    def test_local_target_briefing_empty(self) -> None:
        from tools.exploit_agent.prompt import build_opsec_briefing
        from tools.opsec import OpsecProfile

        # local_targets_off defaults True -> 127.0.0.1 resolves to OPSEC OFF
        briefing = build_opsec_briefing(OpsecProfile(enabled=True), "127.0.0.1")
        assert briefing == ""

    def test_disabled_briefing_empty(self) -> None:
        from tools.exploit_agent.prompt import build_opsec_briefing
        from tools.opsec import OpsecProfile

        # OPSEC off even for a public target -> no briefing
        assert build_opsec_briefing(OpsecProfile(enabled=False), "8.8.8.8") == ""

    def test_prompt_renders_briefing_only_when_nonempty(self) -> None:
        from tools.exploit_agent.prompt import build_exploit_system_prompt

        with_block = build_exploit_system_prompt(
            attacker_os="Linux",
            target_ip="8.8.8.8",
            opsec_context="OPSEC POSTURE: advisory",
        )
        without_block = build_exploit_system_prompt(
            attacker_os="Linux",
            target_ip="8.8.8.8",
            opsec_context="",
        )
        assert "OPSEC POSTURE" in with_block
        assert "OPSEC POSTURE" not in without_block

    def test_rewrite_table_is_single_source_of_truth(self) -> None:
        from tools.opsec import OpsecManager

        # The class attr and the per-command rewriter share one table: a known
        # rewrite round-trips through both.
        assert ("-t5", "-T2") in OpsecManager._LOW_NOISE_REWRITES
        mgr = OpsecManager.__new__(OpsecManager)  # bypass __init__ (no I/O needed)
        # suggest_low_noise_alternative only reads self._LOW_NOISE_REWRITES:
        mgr._LOW_NOISE_REWRITES = OpsecManager._LOW_NOISE_REWRITES
        assert mgr.suggest_low_noise_alternative("nmap -t5 -sV 1.2.3.4") == "nmap -T2 -sV 1.2.3.4"


# ── TestTerminalAdvisory: per-command feedback surface ───────────────────────


class TestTerminalAdvisory:
    @pytest.mark.asyncio
    async def test_public_noisy_command_gets_advisory_and_executes(self, monkeypatch, tmp_path: Path) -> None:
        import tools.mcp_tools.terminal as term

        monkeypatch.setattr(term, "_platform_system", lambda: "Linux")
        monkeypatch.setattr(subprocess, "Popen", _Popen)
        monkeypatch.setenv("EXPLOIT_TARGET", "8.8.8.8")

        mcp = _make_server(tmp_path, opsec={"enabled": True})
        text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "nmap -T5 -sV 8.8.8.8"}))
        # The command executed (advisory never gates).
        assert "TERMINAL_RESULT: completed" in text
        # And the AI got live OPSEC feedback.
        assert "OPSEC_ADVISORY:" in text
        assert "Noise score:" in text
        # -T5 is noisy -> a quieter rewrite is offered.
        assert "-T2" in text

    @pytest.mark.asyncio
    async def test_quiet_command_advisory_score_zero(self, monkeypatch, tmp_path: Path) -> None:
        import tools.mcp_tools.terminal as term

        monkeypatch.setattr(term, "_platform_system", lambda: "Linux")
        monkeypatch.setattr(subprocess, "Popen", _Popen)
        monkeypatch.setenv("EXPLOIT_TARGET", "8.8.8.8")

        mcp = _make_server(tmp_path, opsec={"enabled": True})
        # The target-IP lock requires destination-less commands to declare
        # scope literally (fail-closed even when the flag is off but a union
        # exists) -- so the quiet command names the target up front.
        text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "echo 8.8.8.8 && ls -la"}))
        assert "OPSEC_ADVISORY:" in text
        assert "Noise score: 0" in text
        assert "no rewrite available" in text

    @pytest.mark.asyncio
    async def test_quiet_command_pattern_match_still_executes(self, monkeypatch, tmp_path: Path) -> None:
        """REGRESSION: a command matching a quiet_command_patterns substring
        STILL executes. is_quiet_blocked / noise_budget must NOT be re-gated
        onto the attack path -- the advisory is informational only."""
        import tools.mcp_tools.terminal as term

        # Sanity: the dormant gate would block this if it were wired.
        from tools.opsec import OpsecManager, OpsecProfile

        blocking = OpsecManager(OpsecProfile(enabled=True, quiet_command_patterns=("nmap",)))
        assert blocking.is_quiet_blocked("nmap -T5 -sV 8.8.8.8") is True

        monkeypatch.setattr(term, "_platform_system", lambda: "Linux")
        monkeypatch.setattr(subprocess, "Popen", _Popen)
        monkeypatch.setenv("EXPLOIT_TARGET", "8.8.8.8")

        mcp = _make_server(
            tmp_path,
            opsec={
                "enabled": True,
                "quiet_command_patterns": ["nmap"],
            },
        )
        text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "nmap -T5 -sV 8.8.8.8"}))
        # Command executed (NOT blocked) despite matching the quiet pattern.
        assert "TERMINAL_RESULT: completed" in text
        assert "BLOCKED_REASON" not in text
        assert "not in the explicit allowlist" not in text

    @pytest.mark.asyncio
    async def test_local_target_no_advisory(self, monkeypatch, tmp_path: Path) -> None:
        import tools.mcp_tools.terminal as term

        monkeypatch.setattr(term, "_platform_system", lambda: "Linux")
        monkeypatch.setattr(subprocess, "Popen", _Popen)
        monkeypatch.setenv("EXPLOIT_TARGET", "127.0.0.1")

        mcp = _make_server(
            tmp_path,
            opsec={
                "enabled": True,
                "local_targets_off": True,
            },
        )
        text = _text(await mcp.call_tool("run_exploit_terminal", {"command": "nmap -T5 -sV 127.0.0.1"}))
        assert "TERMINAL_RESULT: completed" in text
        # Local target -> OPSEC OFF -> no advisory block.
        assert "OPSEC_ADVISORY:" not in text


if __name__ == "__main__":
    # Ponytail self-check: run the pure-logic tests without pytest.
    import sys

    t = TestOpsecBriefing()
    t.test_public_target_briefing_non_empty()
    t.test_local_target_briefing_empty()
    t.test_disabled_briefing_empty()
    t.test_prompt_renders_briefing_only_when_nonempty()
    t.test_rewrite_table_is_single_source_of_truth()
    print("OPSEC AI-awareness self-check: OK")
    sys.exit(0)
