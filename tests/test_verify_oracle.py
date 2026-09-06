"""Verify-or-it-didn't-happen tests (mocked probe execution — no live network).

Covers the deterministic oracle (VERIFIED only on N/N machine proof via
outcome_truth; flaky -> HOLDING; SANDBOX/block/ambiguous -> INCONCLUSIVE),
the replayable proof capsule, the verify_finding MCP tool end to end through
FakeMCP/FakeCtx, persistence into the existing run artifact JSON, and the
require_signoff report/ticketing gate.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import tools.mcp_tools.verify as verify_mod
from tools.kernel.audit import make_audit_tool, make_require_allowlist
from tools.mcp_tools.verify import (
    HOLDING,
    INCONCLUSIVE,
    VERIFIED,
    persist_verify,
    record_verify,
)
from tools.verify_oracle import (
    VerifyOracle,
    classify_verify_output,
    judge_outputs,
    proof_sha256,
)

TARGET = "10.0.0.50"
FINDING_ID = "F-10-0-0-50-run_exploit_terminal"
PROBE = {"type": "shell_command", "exec": "curl -s http://10.0.0.50/poc"}

GOOD = "exploit ok\nuid=0(root) gid=0(root)"
CRED = "credentials: admin:aad3b435b51404eeaad3b435b51404ee"
BAD = "curl: (7) Failed to connect: connection refused"
AMBIGUOUS = "hello world, nothing recognizable here"
SANDBOX = "TERMINAL_RESULT: BLOCKED\nSANDBOX_UNAVAILABLE\ndocker daemon unreachable"

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
        "verify_status": HOLDING,
        "verify_history": [],
    }
    base.update(overrides)
    return base


def _register(
    tmp_path: Path,
    terminal_outputs: list[str],
    *,
    config: dict[str, Any] | None = None,
    terminal_raises: bool = False,
) -> tuple[FakeMCP, FakeCtx, list[str]]:
    """Register verify tools with canned run_exploit_terminal outputs (no network)."""
    cfg = copy.deepcopy(config if config is not None else ALLOW_CONFIG)
    cfg["reports_dir"] = str(tmp_path)
    mcp, ctx = FakeMCP(), FakeCtx(tmp_path, cfg)
    calls: list[str] = []
    outputs = list(terminal_outputs)

    def run_exploit_terminal(command: str) -> str:
        if terminal_raises:
            raise RuntimeError("boom")
        assert TARGET in command  # ONLY the finding's probe is re-executed
        calls.append(command)
        return outputs.pop(0) if outputs else AMBIGUOUS

    mcp.tools["run_exploit_terminal"] = run_exploit_terminal
    verify_mod.register_verify_tools(mcp, ctx=ctx)
    return mcp, ctx, calls


def _call(mcp: FakeMCP, **kwargs: Any) -> str:
    return str(mcp.tools["verify_finding"](**kwargs))


# ── oracle verdicts ──────────────────────────────────────────────────────


def test_verified_on_n_over_n_proof() -> None:
    oracle = VerifyOracle(lambda _cmd: GOOD)
    outcome = oracle.verify_sync({"exec": "id"}, repeats=2)
    assert outcome.verdict == VERIFIED
    assert outcome.proof_capsule.n == 2
    assert outcome.proof_capsule.outputs == [GOOD, GOOD]
    assert outcome.proof_capsule.sha256 == proof_sha256("id", [GOOD, GOOD])


def test_cred_dump_counts_as_proof() -> None:
    assert judge_outputs([CRED, CRED])[0] == VERIFIED
    assert judge_outputs([GOOD, CRED])[0] == VERIFIED


def test_flaky_proof_holds() -> None:
    assert judge_outputs([GOOD, BAD])[0] == HOLDING
    assert judge_outputs([GOOD, AMBIGUOUS])[0] == INCONCLUSIVE  # ambiguous poisons the capsule
    calls = [GOOD, BAD]

    def _flaky(_cmd: str) -> str:
        return calls.pop(0)

    outcome = VerifyOracle(_flaky).verify_sync({"exec": "id"}, repeats=2)
    assert outcome.verdict == HOLDING
    assert "1/2" in outcome.detail


def test_all_failure_holds() -> None:
    assert judge_outputs([BAD, BAD])[0] == HOLDING


def test_sandbox_block_is_inconclusive() -> None:
    assert judge_outputs([GOOD, SANDBOX])[0] == INCONCLUSIVE
    assert judge_outputs(["BLOCKED: off-allowlist"])[0] == INCONCLUSIVE
    assert judge_outputs(["TOOL_EXECUTION_ERROR: boom"])[0] == INCONCLUSIVE


def test_ambiguous_is_inconclusive() -> None:
    assert judge_outputs([AMBIGUOUS, AMBIGUOUS])[0] == INCONCLUSIVE
    assert judge_outputs([""])[0] == INCONCLUSIVE
    assert judge_outputs([])[0] == INCONCLUSIVE


def test_executor_crash_is_inconclusive() -> None:
    def _boom(_cmd: str) -> str:
        raise RuntimeError("boom")

    outcome = VerifyOracle(_boom).verify_sync({"exec": "id"}, repeats=2)
    assert outcome.verdict == INCONCLUSIVE


def test_missing_probe_or_executor_is_inconclusive() -> None:
    assert VerifyOracle(lambda _c: GOOD).verify_sync({}).verdict == INCONCLUSIVE
    assert VerifyOracle(lambda _c: GOOD).verify_sync({"verification_probe": {}}).verdict == INCONCLUSIVE
    assert VerifyOracle(None).verify_sync({"exec": "id"}).verdict == INCONCLUSIVE


def test_classify_verify_output_matrix() -> None:
    assert classify_verify_output(GOOD)[:2] == (True, False)
    assert classify_verify_output(CRED)[:2] == (True, False)
    assert classify_verify_output(BAD)[:2] == (False, False)
    assert classify_verify_output(AMBIGUOUS)[:2] == (False, True)
    assert classify_verify_output("")[:2] == (False, True)
    assert classify_verify_output(SANDBOX)[:2] == (False, True)


def test_capsule_sha_replays() -> None:
    blob = "id\n" + GOOD + "\n" + GOOD
    assert proof_sha256("id", [GOOD, GOOD]) == hashlib.sha256(blob.encode()).hexdigest()
    capsule = VerifyOracle(lambda _c: GOOD).verify_sync({"exec": "id"}, repeats=2, run_ids=["run1"]).proof_capsule
    assert capsule.run_ids == ["run1"]
    assert capsule.to_dict()["sha256"] == capsule.sha256


# ── MCP tool ─────────────────────────────────────────────────────────────


def test_verify_finding_verified_on_n_over_n(tmp_path: Path) -> None:
    path = _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx, calls = _register(tmp_path, [GOOD, GOOD])
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert "VERIFY_VERDICT:" in out
    assert f"VERDICT: {VERIFIED}" in out
    assert len(calls) == 2  # the stored probe ran N times, nothing else
    saved = json.loads(path.read_text(encoding="utf-8"))["technical_findings"][0]
    assert saved["verify_status"] == VERIFIED
    assert saved["verify_history"][-1]["proof_capsule"]["n"] == 2
    assert saved["verify_history"][-1]["proof_capsule"]["sha256"]


def test_verify_finding_holding_when_flaky(tmp_path: Path) -> None:
    path = _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx, calls = _register(tmp_path, [GOOD, BAD])
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert f"VERDICT: {HOLDING}" in out
    assert len(calls) == 2
    saved = json.loads(path.read_text(encoding="utf-8"))["technical_findings"][0]
    assert saved["verify_status"] == HOLDING


def test_verify_finding_inconclusive_on_sandbox(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx, _calls = _register(tmp_path, [GOOD, SANDBOX])
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert f"VERDICT: {INCONCLUSIVE}" in out
    assert "SANDBOX_UNAVAILABLE" in out


def test_verify_finding_inconclusive_on_crash(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx, _calls = _register(tmp_path, [], terminal_raises=True)
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert f"VERDICT: {INCONCLUSIVE}" in out


def test_verify_finding_missing_probe(tmp_path: Path) -> None:
    path = _write_report(tmp_path, "run1", [_finding(verification_probe={})])
    mcp, _ctx, calls = _register(tmp_path, [GOOD])
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID)
    assert f"VERDICT: {INCONCLUSIVE}" in out
    assert "no stored verification probe" in out
    assert calls == []
    saved = json.loads(path.read_text(encoding="utf-8"))["technical_findings"][0]
    assert saved["verify_status"] == INCONCLUSIVE


def test_verify_finding_repeats_honored(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx, calls = _register(tmp_path, [GOOD, GOOD, GOOD])
    out = _call(mcp, target_ip=TARGET, finding_id=FINDING_ID, repeats=3)
    assert f"VERDICT: {VERIFIED}" in out
    assert len(calls) == 3


def test_verify_finding_asset_mismatch_and_allowlist(tmp_path: Path) -> None:
    wide_cfg = copy.deepcopy(ALLOW_CONFIG)
    wide_cfg["exploit"] = {"require_explicit_allowlist": True, "allowed_targets": [TARGET, "10.0.0.51"]}
    _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx, _calls = _register(tmp_path, [GOOD, GOOD], config=wide_cfg)
    out = _call(mcp, target_ip="10.0.0.51", finding_id=FINDING_ID)
    assert "BLOCKED" in out
    assert "affected_asset" in out

    denied_cfg = copy.deepcopy(ALLOW_CONFIG)
    mcp2, _ctx2, _calls2 = _register(tmp_path, [GOOD, GOOD], config=denied_cfg)
    out = _call(mcp2, target_ip="10.0.0.99", finding_id=FINDING_ID)
    assert "BLOCKED" in out
    assert VERIFIED not in out


def test_verify_finding_missing_finding(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_finding()])
    mcp, _ctx, _calls = _register(tmp_path, [GOOD])
    assert _call(mcp, target_ip=TARGET, finding_id="F-nope").startswith("ERROR:")
    assert _call(mcp, target_ip=TARGET, finding_id="").startswith("BLOCKED:")


def test_record_verify_appends_history() -> None:
    finding = _finding()
    record_verify(finding, HOLDING, "ev1", now="2026-01-01T00:00:00+00:00")
    record_verify(finding, VERIFIED, "ev2", now="2026-01-02T00:00:00+00:00", proof_capsule={"n": 2})
    assert finding["verify_status"] == VERIFIED
    assert [h["verdict"] for h in finding["verify_history"]] == [HOLDING, VERIFIED]
    assert finding["verify_history"][-1]["proof_capsule"] == {"n": 2}
    with pytest.raises(ValueError):
        record_verify(finding, "BOGUS", "ev")


def test_persist_verify_roundtrip(tmp_path: Path) -> None:
    path = _write_report(tmp_path, "run1", [_finding()])
    finding = persist_verify(path, FINDING_ID, VERIFIED, "ev", now="2026-01-01T00:00:00+00:00")
    assert finding["verify_status"] == VERIFIED
    with pytest.raises(LookupError):
        persist_verify(path, "F-nope", VERIFIED, "ev")


# ── require_signoff gate ─────────────────────────────────────────────────


def test_signoff_gate_excludes_holding_from_md_html() -> None:
    from tools.enhanced_reporting import EnhancedReportGenerator

    gen = EnhancedReportGenerator(db=None, mission_id="m", workspace=Path("."))
    holding = _finding(
        severity="High",
        vuln_class="Other",
        cvss={"base_score": 7.5},
        confidence=0.5,
        summary="candidate",
        remediation="patch",
    )
    verified = _finding(
        finding_id="F-verified",
        title="verified finding",
        verify_status=VERIFIED,
        severity="High",
        vuln_class="Other",
        cvss={"base_score": 7.5},
        confidence=0.95,
        summary="confirmed",
        remediation="patch",
    )
    report = {
        "report_metadata": {"mission_id": "m", "generated_at": "t", "total_targets": 1},
        "executive_summary": "e",
        "attack_timeline": [],
        "exploitation_chains": [],
        "technical_findings": [holding, verified],
        "failure_analysis": [],
    }
    md = gen._generate_markdown(report)
    assert "demo finding" in md and "verified finding" in md  # gate off: everything renders

    gated = dict(report, report_metadata={**report["report_metadata"], "require_signoff": True})
    md = gen._generate_markdown(gated)
    assert "verified finding" in md
    assert "demo finding" not in md
    html = gen._generate_html(gated)
    assert "verified finding" in html
    assert "demo finding" not in html


def test_signoff_gate_holds_tickets() -> None:
    from tools.ticketing import create_ticket

    assert create_ticket(_finding(), {}, require_signoff=True)["created"] is False
    assert "held" in create_ticket(_finding(), {}, require_signoff=True)["status"]
    # Gate off: legacy behavior untouched (falls through to disabled without config).
    assert create_ticket(_finding(), {}) == {"created": False, "status": "disabled", "url": ""}
