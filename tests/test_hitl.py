"""Proxy-backed HITL evidence loop tests (mocked I/O — no live network).

Covers the hitl MCP tools end to end through FakeMCP/FakeCtx:
propose→approve→APPROVED, propose→reject→hidden, LLM self-approval
refusal (helper + tool layers), list_proposed scoping, the hitl.enabled
gate, the approved_findings final-report filter, and proof-capsule
read-back from stored machine evidence.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

import tools.mcp_tools.hitl as hitl_mod
from tools.enhanced_reporting import approved_findings
from tools.kernel.audit import make_audit_tool
from tools.mcp_tools.hitl import (
    APPROVED,
    PROPOSED,
    REJECTED,
    list_proposed_findings,
    persist_hitl_decision,
    proof_capsule,
    propose_new_finding,
    record_hitl_decision,
)

TARGET = "10.0.0.50"

HITL_CONFIG = {
    "exploit": {"require_explicit_allowlist": True, "allowed_targets": [TARGET]},
    "hitl": {"enabled": True},
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
        self.require_allowlist = None


def _write_report(root: Path, run_id: str, findings: list[dict[str, Any]]) -> Path:
    run_dir = root / run_id
    (run_dir / "enhanced").mkdir(parents=True, exist_ok=True)
    path = run_dir / "enhanced" / "enhanced_report.json"
    path.write_text(
        json.dumps({"report_metadata": {"mission_id": run_id}, "technical_findings": findings}, indent=2),
        encoding="utf-8",
    )
    return path


def _proposed_finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "finding_id": "F-10-0-0-50-demo",
        "title": "demo candidate",
        "affected_asset": TARGET,
        "verification_probe": {"type": "shell_command", "exec": "curl -s http://10.0.0.50/poc"},
        "verify_status": "VERIFIED",
        "verify_history": [
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "verdict": "VERIFIED",
                "evidence": "probe output: uid=0(root)",
                "proof_capsule": {
                    "probe_exec": "curl -s http://10.0.0.50/poc",
                    "n": 2,
                    "outputs": ["uid=0(root)", "uid=0(root)"],
                    "sha256": "abc123",
                    "run_ids": ["run1"],
                },
            }
        ],
        "retest_status": "",
        "retest_history": [],
        "hitl_status": PROPOSED,
        "hitl_history": [
            {"timestamp": "2026-01-01T00:00:00+00:00", "decision": PROPOSED, "note": "agent proposal", "actor": "agent"}
        ],
    }
    base.update(overrides)
    return base


def _register(tmp_path: Path, *, config: dict[str, Any] | None = None) -> FakeMCP:
    cfg = copy.deepcopy(config if config is not None else HITL_CONFIG)
    cfg["reports_dir"] = str(tmp_path)
    mcp, ctx = FakeMCP(), FakeCtx(tmp_path, cfg)
    hitl_mod.register_hitl_tools(mcp, ctx=ctx)
    return mcp


def _read_finding(path: Path, finding_id: str) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data["technical_findings"]:
        if item["finding_id"] == finding_id:
            return item
    raise AssertionError(f"{finding_id} missing from {path}")


# ── propose → decide ─────────────────────────────────────────────────────


def test_propose_approve_report_shows_approved(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [])
    mcp = _register(tmp_path)
    out = str(
        mcp.tools["propose_finding"](
            run_id="run1",
            title="RCE via upload",
            affected_asset=TARGET,
            summary="agent claims RCE",
            probe_exec="curl -s http://10.0.0.50/poc",
        )
    )
    assert "HITL_PROPOSED" in out
    assert PROPOSED in out
    assert APPROVED not in out
    finding_id = next(
        item["finding_id"]
        for item in json.loads((tmp_path / "run1" / "enhanced" / "enhanced_report.json").read_text())[
            "technical_findings"
        ]
    )
    out = str(mcp.tools["hitl_decide"](finding_id=finding_id, decision="approved", actor="human", run_id="run1"))
    assert "DECISION: APPROVED" in out
    path = tmp_path / "run1" / "enhanced" / "enhanced_report.json"
    saved = _read_finding(path, finding_id)
    assert saved["hitl_status"] == APPROVED
    assert saved["hitl_history"][-1] == {
        "timestamp": saved["hitl_history"][-1]["timestamp"],
        "decision": APPROVED,
        "note": "",
        "actor": "human",
    }
    # Final-report filter surfaces it; report renderers carry the badge.
    assert [
        f["finding_id"] for f in approved_findings(json.loads(path.read_text(encoding="utf-8"))["technical_findings"])
    ] == [finding_id]


def test_propose_reject_hidden_from_approved(tmp_path: Path) -> None:
    path = _write_report(tmp_path, "run1", [_proposed_finding()])
    mcp = _register(tmp_path)
    out = str(
        mcp.tools["hitl_decide"](
            finding_id="F-10-0-0-50-demo", decision="REJECTED", note="false positive", actor="human"
        )
    )
    assert "DECISION: REJECTED" in out
    saved = _read_finding(path, "F-10-0-0-50-demo")
    assert saved["hitl_status"] == REJECTED
    assert saved["hitl_history"][-1]["note"] == "false positive"
    assert saved["hitl_history"][-1]["actor"] == "human"
    assert approved_findings(json.loads(path.read_text(encoding="utf-8"))["technical_findings"]) == []


def test_list_proposed_hides_decided(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_proposed_finding(), _proposed_finding(finding_id="F-other")])
    mcp = _register(tmp_path)
    assert "2 awaiting review" in str(mcp.tools["list_proposed"](run_id="run1"))
    mcp.tools["hitl_decide"](finding_id="F-10-0-0-50-demo", decision="APPROVED", actor="human", run_id="run1")
    out = str(mcp.tools["list_proposed"](run_id="run1"))
    assert "1 awaiting review" in out
    assert "F-other" in out
    assert "F-10-0-0-50-demo" not in out


# ── LLM cannot self-approve ──────────────────────────────────────────────


def test_agent_actor_refused_at_helper() -> None:
    finding = _proposed_finding()
    for actor in ("", "agent", "llm", "system"):
        with pytest.raises(PermissionError):
            record_hitl_decision(dict(finding), APPROVED, actor=actor)
    assert finding["hitl_status"] == PROPOSED
    # Human (case-insensitive, padded) is the only accepted actor.
    record_hitl_decision(finding, APPROVED, actor="HUMAN ")
    assert finding["hitl_status"] == APPROVED


def test_agent_actor_blocked_at_tool(tmp_path: Path) -> None:
    path = _write_report(tmp_path, "run1", [_proposed_finding()])
    mcp = _register(tmp_path)
    for actor in ("", "agent", "llm"):
        out = str(mcp.tools["hitl_decide"](finding_id="F-10-0-0-50-demo", decision="APPROVED", actor=actor))
        assert out.startswith("BLOCKED:"), out
    assert _read_finding(path, "F-10-0-0-50-demo")["hitl_status"] == PROPOSED


def test_unknown_decision_rejected(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [_proposed_finding()])
    mcp = _register(tmp_path)
    out = str(mcp.tools["hitl_decide"](finding_id="F-10-0-0-50-demo", decision="MAYBE", actor="human"))
    assert out.startswith("ERROR:")
    with pytest.raises(ValueError):
        record_hitl_decision(_proposed_finding(), "BOGUS", actor="human")


# ── validation / gating ──────────────────────────────────────────────────


def test_propose_validates_input(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [])
    mcp = _register(tmp_path)
    assert str(mcp.tools["propose_finding"](run_id="", title="t", affected_asset=TARGET, summary="s")).startswith(
        "BLOCKED:"
    )
    assert str(mcp.tools["propose_finding"](run_id="run1", title="", affected_asset=TARGET, summary="s")).startswith(
        "BLOCKED:"
    )
    assert str(mcp.tools["propose_finding"](run_id="nope", title="t", affected_asset=TARGET, summary="s")).startswith(
        "ERROR:"
    )
    assert str(mcp.tools["hitl_decide"](finding_id="", decision="APPROVED", actor="human")).startswith("BLOCKED:")
    assert str(mcp.tools["hitl_decide"](finding_id="F-nope", decision="APPROVED", actor="human")).startswith("ERROR:")


def test_propose_never_approves_and_ids_unique(tmp_path: Path) -> None:
    _write_report(tmp_path, "run1", [])
    mcp = _register(tmp_path)
    ids = set()
    for _ in range(2):
        mcp.tools["propose_finding"](run_id="run1", title="Same title", affected_asset=TARGET, summary="s")
        data = json.loads((tmp_path / "run1" / "enhanced" / "enhanced_report.json").read_text())
        for item in data["technical_findings"]:
            assert item["hitl_status"] == PROPOSED
            ids.add(item["finding_id"])
    assert len(ids) == 2


def test_hitl_disabled_registers_nothing(tmp_path: Path) -> None:
    off = copy.deepcopy(HITL_CONFIG)
    off["hitl"] = {"enabled": False}
    mcp = _register(tmp_path, config=off)
    assert "propose_finding" not in mcp.tools
    assert "hitl_decide" not in mcp.tools
    assert "list_proposed" not in mcp.tools


# ── proof capsule + report surface ───────────────────────────────────────


def test_proof_capsule_from_stored_evidence() -> None:
    capsule = proof_capsule(_proposed_finding())
    assert capsule["probe_exec"] == "curl -s http://10.0.0.50/poc"
    assert capsule["output_excerpt"] == "uid=0(root)"
    assert capsule["proof_sha256"] == "abc123"
    assert capsule["proof_runs"] == 2
    assert capsule["verify_status"] == "VERIFIED"


def test_proof_capsule_empty_finding_never_raises() -> None:
    capsule = proof_capsule({})
    assert capsule["probe_exec"] == ""
    assert capsule["output_excerpt"] == ""


def test_finding_schema_and_report_rendering() -> None:
    from tools.enhanced_reporting import EnhancedReportGenerator

    finding = propose_new_finding({"technical_findings": []}, title="t", affected_asset=TARGET, summary="s")
    assert finding["hitl_status"] == PROPOSED
    assert finding["hitl_history"][0]["actor"] == "agent"
    record_hitl_decision(finding, APPROVED, "looks real", actor="human", now="2026-01-01T00:00:00+00:00")
    assert finding["hitl_status"] == APPROVED

    gen = EnhancedReportGenerator(db=None, mission_id="m", workspace=Path("."))
    report = {
        "report_metadata": {"mission_id": "m", "generated_at": "t", "total_targets": 1},
        "executive_summary": "e",
        "attack_timeline": [],
        "exploitation_chains": [],
        "technical_findings": [finding],
        "failure_analysis": [],
    }
    assert "APPROVED" in gen._generate_markdown(report)
    assert "APPROVED" in gen._generate_findings_html([finding])


def test_persist_decision_roundtrip(tmp_path: Path) -> None:
    path = _write_report(tmp_path, "run1", [_proposed_finding()])
    finding = persist_hitl_decision(
        path, "F-10-0-0-50-demo", REJECTED, "nope", actor="human", now="2026-01-01T00:00:00+00:00"
    )
    assert finding["hitl_status"] == REJECTED
    assert finding["hitl_history"][-1] == {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "decision": REJECTED,
        "note": "nope",
        "actor": "human",
    }
    with pytest.raises(LookupError):
        persist_hitl_decision(path, "F-nope", APPROVED, actor="human")
    with pytest.raises(PermissionError):
        persist_hitl_decision(path, "F-10-0-0-50-demo", APPROVED, actor="agent")


def test_list_proposed_across_runs(tmp_path: Path) -> None:
    _write_report(tmp_path, "run_old", [_proposed_finding()])
    _write_report(tmp_path, "run_new", [_proposed_finding(finding_id="F-new")])
    cfg = copy.deepcopy(HITL_CONFIG)
    cfg["reports_dir"] = str(tmp_path)
    proposed, _ = list_proposed_findings(tmp_path, "")
    assert {f["finding_id"] for f in proposed} == {"F-10-0-0-50-demo", "F-new"}
    proposed, resolved = list_proposed_findings(tmp_path, "run_new")
    assert [f["finding_id"] for f in proposed] == ["F-new"]
    assert resolved == "run_new"
    with pytest.raises(LookupError):
        list_proposed_findings(tmp_path, "nope")


# ── REST human path (WebUI Evidence tab) ───────────────────────────────


def _make_client(tmp_path: Path, monkeypatch, token: str = "test-token-0123456789abcdef01234567"):
    """TestClient with known token + minimal config (the test_api_frontend precedent)."""
    from unittest.mock import MagicMock

    from fastapi.testclient import TestClient

    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from tools.run_service.service import Callables

    class _FakeRouter:
        _clients = {"glm": MagicMock()}

        def get_client(self, name):
            return self._clients[name]

    async def _fake_run_session(**kwargs):
        return {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""}

    callables = Callables(
        build_router=lambda *a, **kw: _FakeRouter(), run_session=_fake_run_session
    )
    from app import create_app

    return TestClient(create_app(config_path=config_path, callables=callables)), token


def _seed_run_with_proposal(client, token: str, tmp_path: Path) -> str:
    resp = client.post(
        "/api/v1/runs",
        json={"target": TARGET, "mode": "attack", "goal": "recon_only"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    run_id = resp.json()["run_id"]
    _write_report(tmp_path / "reports", run_id, [_proposed_finding()])
    return run_id


def test_api_proposed_and_decide_live(tmp_path: Path, monkeypatch) -> None:
    client, token = _make_client(tmp_path, monkeypatch)
    auth = {"Authorization": f"Bearer {token}"}
    run_id = _seed_run_with_proposal(client, token, tmp_path)

    resp = client.get(f"/api/v1/runs/{run_id}/proposed", headers=auth)
    assert resp.status_code == 200
    proposed = resp.json()["proposed"]
    assert [f["finding_id"] for f in proposed] == ["F-10-0-0-50-demo"]
    assert proposed[0]["proof"]["probe_exec"] == "curl -s http://10.0.0.50/poc"

    # The REST decide route takes no actor — the server stamps human.
    resp = client.post(
        f"/api/v1/runs/{run_id}/decide",
        json={"finding_id": "F-10-0-0-50-demo", "decision": "APPROVED", "note": "confirmed"},
        headers=auth,
    )
    assert resp.status_code == 200
    assert resp.json()["finding"]["hitl_status"] == APPROVED

    resp = client.get(f"/api/v1/runs/{run_id}/proposed", headers=auth)
    assert resp.json()["proposed"] == []

    # Live update: the decision was emitted on the run event stream.
    resp = client.get(f"/api/v1/runs/{run_id}/events?after=0", headers=auth)
    assert resp.status_code == 200
    hitl_events = [e for e in resp.json()["events"] if e["type"] == "hitl_decision"]
    assert hitl_events and hitl_events[0]["payload"]["decision"] == APPROVED
    assert hitl_events[0]["payload"]["actor"] == "human"


def test_api_decide_validation(tmp_path: Path, monkeypatch) -> None:
    client, token = _make_client(tmp_path, monkeypatch)
    auth = {"Authorization": f"Bearer {token}"}
    run_id = _seed_run_with_proposal(client, token, tmp_path)

    resp = client.post(
        f"/api/v1/runs/{run_id}/decide",
        json={"finding_id": "F-10-0-0-50-demo", "decision": "MAYBE"},
        headers=auth,
    )
    assert resp.status_code == 400
    resp = client.post(
        f"/api/v1/runs/{run_id}/decide",
        json={"finding_id": "F-nope", "decision": "APPROVED"},
        headers=auth,
    )
    assert resp.status_code == 404
    resp = client.get("/api/v1/runs/does-not-exist/proposed", headers=auth)
    assert resp.status_code == 404
