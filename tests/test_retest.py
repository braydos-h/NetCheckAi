"""Closed-loop retest tests (mocked probe execution — no live network).

Covers the retest_finding MCP tool end to end through FakeMCP/FakeCtx:
STILL_OPEN / FIXED / INCONCLUSIVE verdicts, allowlist denial, asset
mismatch, missing-PoC graceful handling, missing finding, latest-run
defaulting, persistence into the existing run artifact JSON (+ sibling
Markdown regeneration), and probe capture in the campaign builder.
"""

from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

import tools.mcp_tools.retest as retest_mod
from tools.kernel.audit import make_audit_tool, make_require_allowlist
from tools.mcp_tools.retest import (
    FIXED,
    INCONCLUSIVE,
    STILL_OPEN,
    classify_retest_output,
    locate_finding,
    persist_retest,
    record_retest,
    resolve_probe,
)

TARGET = "10.0.0.50"
FINDING_ID = "F-10-0-0-50-run_exploit_terminal"
PROBE = {"type": "shell_command", "exec": "curl -s http://10.0.0.50/poc"}

ALLOW_CONFIG = {
    "exploit": {"require_explicit_allowlist": True, "allowed_targets": [TARGET]},
}


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self):  # noqa: ANN001, ANN202 — mirrors the FastMCP decorator shape
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn

        return deco


class FakeCtx:
    def __init__(self, workspace: Path, config: dict[str, Any]) -> None:
        self.workspace = workspace
        self.config = config
        self.audit_tool = make_audit_tool(workspace)
        self.require_allowlist = make_require_allowlist(workspace, config)


def _write_report(root: Path, run_id: str, findings: list[dict[str, Any]]) -> Path:
    run_dir = root / run_id
    (run_dir / "enhanced").mkdir(parents=True, exist_ok=True)
    path = run_dir / "enhanced" / "enhanced_report.json"
    path.write_text(
        json.dumps({"report_metadata": {"mission_id": run_id}, "technical_findings": findings}, indent=2),
        encoding="utf-8",
    )
    return path


def _finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "finding_id": FINDING_ID,
        "title": "demo finding",
        "affected_asset": TARGET,
        "verification_probe": dict(PROBE),
        "retest_status": "",
        "retest_history": [],
    }
    base.update(overrides)
    return base


def _register(
    tmp_path: Path,
    terminal_output: str = "",
    *,
    config: dict[str, Any] | None = None,
    terminal_raises: bool = False,
) -> tuple[FakeMCP, FakeCtx]:
    """Register retest tools with a canned run_exploit_terminal (no network)."""
    cfg = copy.deepcopy(config if config is not None else ALLOW_CONFIG)
    cfg["reports_dir"] = str(tmp_path)
    mcp, ctx = FakeMCP(), FakeCtx(tmp_path, cfg)

    def run_exploit_terminal(command: str) -> str:
        if terminal_raises:
            raise RuntimeError("boom")
        assert TARGET in command  # ONLY the finding's probe is re-executed
        return terminal_output

    mcp.tools["run_exploit_terminal"] = run_exploit_terminal
    retest_mod.register_retest_tools(mcp, ctx=ctx)
    return mcp, ctx


def _call(mcp: FakeMCP, **kwargs: Any) -> str:
    return str(mcp.tools["retest_finding"](**kwargs))


# ── verdict paths ──────────────────────────────────────────────────────────


def test_still_open_when_poc_lands(tmp_path: Path) -> None:
    path = _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx = _register(tmp_path, "exploit ok\nuid=0(root) gid=0(root)")
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert f"VERDICT: {STILL_OPEN}" in out
    saved = json.loads(path.read_text(encoding="utf-8"))["technical_findings"][0]
    assert saved["retest_status"] == STILL_OPEN
    assert saved["retest_history"][-1]["verdict"] == STILL_OPEN


def _write_full_report(root: Path, run_id: str) -> tuple[Path, str]:
    """Write a production-shaped report (via the real generator) + md/html siblings."""
    from tools.enhanced_reporting import EnhancedReportGenerator

    run_dir = root / run_id
    gen = EnhancedReportGenerator(db=None, mission_id=run_id, workspace=run_dir)
    exploit = "run_exploit_terminal"
    campaign = {
        "states": {
            TARGET: {
                "successful_exploits": [exploit],
                "failed_attempts": {},
                "privilege_level": "none",
                "timeline": [],
                "recon_result": {"services": []},
                "credentials_found": [],
                "exploit_probes": {exploit: dict(PROBE)},
            }
        }
    }
    data = gen._build_report_data(campaign)
    finding_id = data["technical_findings"][0]["finding_id"]
    assert data["technical_findings"][0]["verification_probe"] == PROBE
    enhanced = run_dir / "enhanced"
    path = enhanced / "enhanced_report.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    (enhanced / "enhanced_report.md").write_text(gen._generate_markdown(data), encoding="utf-8")
    (enhanced / "enhanced_report.html").write_text(gen._generate_html(data), encoding="utf-8")
    return path, finding_id


def test_fixed_when_poc_fails(tmp_path: Path) -> None:
    path, finding_id = _write_full_report(tmp_path, "run1")
    assert "not retested" in (path.parent / "enhanced_report.md").read_text(encoding="utf-8")
    mcp, _ctx = _register(tmp_path, "curl: (7) Failed to connect: connection refused")
    out = _call(mcp, target_ip=TARGET, finding_id=finding_id)
    assert f"VERDICT: {FIXED}" in out
    saved = json.loads(path.read_text(encoding="utf-8"))["technical_findings"][0]
    assert saved["retest_status"] == FIXED
    # Sibling Markdown + HTML reports regenerate with the verdict.
    assert FIXED in (path.parent / "enhanced_report.md").read_text(encoding="utf-8")
    assert FIXED in (path.parent / "enhanced_report.html").read_text(encoding="utf-8")


def test_inconclusive_on_ambiguous_output(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx = _register(tmp_path, "hello world, nothing recognizable here")
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert f"VERDICT: {INCONCLUSIVE}" in out


def test_inconclusive_on_sandbox_block(tmp_path: Path) -> None:
    """Sandbox failures fail closed → INCONCLUSIVE, never a pass or FIXED."""
    _write_report(tmp_path, "run1", [_finding()])
    block = "TERMINAL_RESULT: BLOCKED\nSANDBOX_UNAVAILABLE\ndocker daemon unreachable\nTOOL: run_exploit_terminal"
    mcp, _ctx = _register(tmp_path, block)
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert f"VERDICT: {INCONCLUSIVE}" in out
    assert "SANDBOX_UNAVAILABLE" in out


def test_inconclusive_on_executor_crash(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx = _register(tmp_path, terminal_raises=True)
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert f"VERDICT: {INCONCLUSIVE}" in out


def test_missing_probe_is_graceful_inconclusive(tmp_path: Path) -> None:
    """Findings without a stored probe (old runs) → INCONCLUSIVE, no crash."""
    path = _write_report(tmp_path, "run1", [_finding(verification_probe={})])
    mcp, _ctx = _register(tmp_path, "uid=0(root)")
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert f"VERDICT: {INCONCLUSIVE}" in out
    assert "no stored verification probe" in out
    saved = json.loads(path.read_text(encoding="utf-8"))["technical_findings"][0]
    assert saved["retest_status"] == INCONCLUSIVE


# ── gating ─────────────────────────────────────────────────────────────────


def test_allowlist_denial(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_finding(affected_asset="10.0.0.99")])
    denied_cfg = copy.deepcopy(ALLOW_CONFIG)
    denied_cfg["exploit"] = {"require_explicit_allowlist": True, "allowed_targets": [TARGET]}
    mcp, _ctx = _register(tmp_path, "uid=0(root)", config=denied_cfg)
    out = _call(mcp, target_ip="10.0.0.99", finding_id=FINDING_ID)
    assert "BLOCKED" in out
    assert STILL_OPEN not in out


def test_asset_mismatch_blocked(tmp_path: Path) -> None:
    """An allowlisted target that is NOT the finding's asset is refused."""
    wide_cfg = copy.deepcopy(ALLOW_CONFIG)
    wide_cfg["exploit"] = {"require_explicit_allowlist": True, "allowed_targets": [TARGET, "10.0.0.51"]}
    _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx = _register(tmp_path, "uid=0(root)", config=wide_cfg)
    out = _call(mcp, target_ip="10.0.0.51", finding_id=FINDING_ID)
    assert "BLOCKED" in out
    assert "affected_asset" in out


def test_missing_finding_errors(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx = _register(tmp_path, "uid=0(root)")
    out = _call(mcp, target_ip=TARGET, finding_id="F-nope")
    assert out.startswith("ERROR:")
    out = _call(mcp, target_ip=TARGET, finding_id="")
    assert out.startswith("BLOCKED:")


# ── run resolution ─────────────────────────────────────────────────────────


def test_run_id_defaults_to_latest_containing_run(tmp_path: Path) -> None:
    old = _write_report(tmp_path, "run_old", [_finding(retest_status=FIXED)])
    new = _write_report(tmp_path, "run_new", [_finding()])
    os.utime(old, (time.time() - 100, time.time() - 100))
    mcp, _ctx = _register(tmp_path, "uid=0(root)")
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert "RUN: run_new" in out
    assert json.loads(new.read_text(encoding="utf-8"))["technical_findings"][0]["retest_status"] == STILL_OPEN


def test_explicit_run_id_honored(tmp_path: Path) -> None:
    _write_report(tmp_path, "run_old", [_finding()])
    _write_report(tmp_path, "run_new", [_finding()])
    mcp, _ctx = _register(tmp_path, "connection refused")
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID, run_id="run_old")
    assert "RUN: run_old" in out
    assert f"VERDICT: {FIXED}" in out


# ── pure helpers ───────────────────────────────────────────────────────────


def test_classify_retest_output_matrix() -> None:
    assert classify_retest_output("uid=0(root)")[0] == STILL_OPEN
    assert classify_retest_output("credentials: admin:deadbeef")[0] == STILL_OPEN
    assert classify_retest_output("connection refused")[0] == FIXED
    assert classify_retest_output("exploit failed")[0] == FIXED
    assert classify_retest_output("some ambiguous prose")[0] == INCONCLUSIVE
    assert classify_retest_output("")[0] == INCONCLUSIVE
    assert classify_retest_output("BLOCKED: off-allowlist")[0] == INCONCLUSIVE


def test_resolve_probe_rejects_empty() -> None:
    assert resolve_probe({"verification_probe": {"type": "shell_command", "exec": "id"}}) is not None
    assert resolve_probe({"verification_probe": {}}) is None
    assert resolve_probe({}) is None
    assert resolve_probe({"verification_probe": "id"}) is None


def test_record_retest_appends_history() -> None:
    finding = _finding()
    record_retest(finding, FIXED, "ev1", now="2026-01-01T00:00:00+00:00")
    record_retest(finding, STILL_OPEN, "ev2", now="2026-01-02T00:00:00+00:00")
    assert finding["retest_status"] == STILL_OPEN
    assert [h["verdict"] for h in finding["retest_history"]] == [FIXED, STILL_OPEN]
    with pytest.raises(ValueError):
        record_retest(finding, "BOGUS", "ev")


def test_locate_finding_missing_run(tmp_path: Path) -> None:
    with pytest.raises(LookupError):
        locate_finding(tmp_path, FINDING_ID, "nope")
    with pytest.raises(LookupError):
        locate_finding(tmp_path, FINDING_ID)


def test_persist_retest_roundtrip(tmp_path: Path) -> None:
    path = _write_report(tmp_path, "run1", [_finding()])
    finding = persist_retest(path, FINDING_ID, FIXED, "ev", now="2026-01-01T00:00:00+00:00")
    assert finding["retest_status"] == FIXED
    assert finding["retest_history"] == [{"timestamp": "2026-01-01T00:00:00+00:00", "verdict": FIXED, "evidence": "ev"}]
    with pytest.raises(LookupError):
        persist_retest(path, "F-nope", FIXED, "ev")


# ── report + probe wiring ──────────────────────────────────────────────────


def test_finding_schema_and_report_rendering() -> None:
    from tools.enhanced_reporting import EnhancedReportGenerator, TechnicalFinding

    finding = TechnicalFinding(
        finding_id=FINDING_ID,
        title="t",
        affected_asset=TARGET,
        vuln_class="c",
        severity="High",
        cvss=__import__("tools.enhanced_reporting", fromlist=["CVSSScore"]).CVSSScore(base_score=9.0),
        confidence=0.9,
        summary="s",
        verification_probe=dict(PROBE),
    )
    data = finding.to_dict()
    assert data["verification_probe"] == PROBE
    assert data["retest_status"] == ""
    assert data["retest_history"] == []

    gen = EnhancedReportGenerator(db=None, mission_id="m", workspace=Path("."))
    record_retest(data, FIXED, "ev")
    md = gen._generate_markdown(
        {
            "report_metadata": {"mission_id": "m", "generated_at": "t", "total_targets": 1},
            "executive_summary": "e",
            "attack_timeline": [],
            "exploitation_chains": [],
            "technical_findings": [data],
            "failure_analysis": [],
        }
    )
    assert FIXED in md
    html = gen._generate_findings_html([data])
    assert FIXED in html


def test_prepare_captures_exploit_probes() -> None:
    from tools.run_service.prepare import _build_campaign_result_from_records

    result = {
        "outcome_summary": "compromises: 1, cred dumps: 0",
        "records": [
            {
                "action": "run_exploit_terminal",
                "status": "completed",
                "exit_code": 0,
                "timestamp": "t",
                "command": "curl -s http://10.0.0.50/poc",
                "detail": "uid=0(root)",
            }
        ],
    }
    campaign = _build_campaign_result_from_records(result, TARGET)
    assert campaign is not None
    probes = campaign["states"][TARGET]["exploit_probes"]
    assert probes["run_exploit_terminal"]["exec"] == "curl -s http://10.0.0.50/poc"
    assert probes["run_exploit_terminal"]["type"] == "shell_command"
