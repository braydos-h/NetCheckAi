"""Proxy-backed HITL evidence loop ("agents propose, human decides").

Agent candidates land as ``PROPOSED`` findings in the run artifact
(``reports/<run_id>/enhanced/enhanced_report.json``); only a human decision
(``APPROVED``/``REJECTED`` via ``hitl_decide`` or ``POST /runs/{id}/decide``)
promotes them. LLM verdicts (``verify_poc``/``verify_finding``/
``retest_finding``) never write ``hitl_status`` — they stay machine evidence
(``verify_status``/``retest_status``) until a human signs off.

Reuse (no new execution paths, no new stores):

- finding lookup + reports-root resolution from ``tools/mcp_tools/retest.py``
  (``locate_finding`` / ``_reports_root`` / ``_finding_file``);
- ``record_*``/``persist_*`` shape from ``retest.py``/``verify.py``
  (status stamp + ``history[]`` append, sibling ``.md``/``.html``
  regenerated when present);
- the proof capsule shown to the human is read-only from the existing
  ``verification_probe`` + ``verify_history[]`` + ``retest_history[]`` —
  this module executes NOTHING (all three tools are local-only
  ``@audit_tool``; probe re-exec stays inside ``verify_finding`` /
  ``retest_finding`` via ``run_exploit_terminal``).

Self-approval guard: ``record_hitl_decision`` raises ``PermissionError``
unless ``actor == "human"``; the MCP ``hitl_decide`` wrapper refuses any
other actor (BLOCKED). The REST decide route hardcodes ``actor="human"``
(the bearer-gated WebUI IS the human path) and never accepts it from the
client. Every decision lands in ``hitl_history[]`` and the JSONL audit
trail with its actor.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.enhanced_reporting import EnhancedReportGenerator, approved_findings
from tools.mcp_tools.registry import ToolContext
from tools.mcp_tools.retest import (
    _find_in_report,
    _finding_file,
    _read_report_json,
    _reports_root,
    locate_finding,
)

PROPOSED = "PROPOSED"
APPROVED = "APPROVED"
REJECTED = "REJECTED"

HITL_STATUSES = frozenset({PROPOSED, APPROVED, REJECTED})
HITL_DECISIONS = frozenset({APPROVED, REJECTED})

_HUMAN_ACTOR = "human"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(text: str, *, limit: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (text or "").strip().lower()).strip("-")
    return (slug or "finding")[:limit].rstrip("-") or "finding"


def record_hitl_decision(
    finding: dict[str, Any],
    decision: str,
    note: str = "",
    *,
    actor: str = "",
    now: str = "",
) -> dict[str, Any]:
    """Stamp ``hitl_status`` + append ``hitl_history[]`` (mutates, returns finding).

    Only ``actor == "human"`` may decide — any other actor (``""``,
    ``"agent"``, ``"llm"``, …) raises ``PermissionError`` so an LLM can
    never self-approve its own proposal. Unknown decisions raise
    ``ValueError``.
    """
    verdict = (decision or "").strip().upper()
    if verdict not in HITL_DECISIONS:
        raise ValueError(f"unknown HITL decision {decision!r} (want APPROVED|REJECTED)")
    if (actor or "").strip().lower() != _HUMAN_ACTOR:
        raise PermissionError("HITL decisions require actor='human' (operator-only; agents cannot self-approve)")
    finding["hitl_status"] = verdict
    history = finding.get("hitl_history")
    if not isinstance(history, list):
        history = []
        finding["hitl_history"] = history
    history.append(
        {
            "timestamp": now or _now_iso(),
            "decision": verdict,
            "note": str(note or ""),
            "actor": _HUMAN_ACTOR,
        }
    )
    return finding


def _refresh_siblings(json_path: Path, data: dict[str, Any]) -> None:
    """Best-effort sibling .md/.html regeneration (the persist_retest precedent)."""
    try:
        renderer = EnhancedReportGenerator(db=None, mission_id="", workspace=json_path.parent.parent)
        for suffix, method in ((".md", "_generate_markdown"), (".html", "_generate_html")):
            sibling = json_path.with_suffix(suffix)
            if sibling.is_file():
                sibling.write_text(getattr(renderer, method)(data), encoding="utf-8")
    except Exception:  # noqa: BLE001 -- report refresh is best-effort; the JSON above is the record
        pass


def persist_hitl_decision(
    json_path: Path | str,
    finding_id: str,
    decision: str,
    note: str = "",
    *,
    actor: str = "",
    now: str = "",
) -> dict[str, Any]:
    """Persist one human decision into the existing run artifact JSON.

    Updates ``technical_findings[]`` in place and regenerates the sibling
    ``.md``/``.html`` reports when they sit next to the JSON (same stem).
    Returns the updated finding dict. Raises ``PermissionError`` for
    non-human actors, ``LookupError`` for unknown findings.
    """
    path = Path(json_path)
    data = _read_report_json(path)
    finding = _find_in_report(data, (finding_id or "").strip())
    if finding is None:
        raise LookupError(f"finding {finding_id!r} not present in {path}")
    record_hitl_decision(finding, decision, note, actor=actor, now=now)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    _refresh_siblings(path, data)
    return finding


def _new_finding_id(data: dict[str, Any], asset: str, title: str) -> str:
    stem = f"F-{_slug(asset, limit=24)}-{_slug(title)}"
    taken = {
        str(item.get("finding_id", "")) for item in (data.get("technical_findings") or []) if isinstance(item, dict)
    }
    candidate, suffix = stem, 1
    while candidate in taken:
        suffix += 1
        candidate = f"{stem}-{suffix}"
    return candidate


def propose_new_finding(
    data: dict[str, Any],
    *,
    title: str,
    affected_asset: str,
    summary: str,
    probe_exec: str = "",
    evidence: str = "",
    severity: str = "Medium",
    vuln_class: str = "",
    now: str = "",
) -> dict[str, Any]:
    """Append a PROPOSED candidate finding to report ``data`` (mutates, returns it).

    Never writes APPROVED — every proposal starts life awaiting a human.
    """
    finding_id = _new_finding_id(data, affected_asset, title)
    probe = {"type": "shell_command", "exec": probe_exec.strip()} if probe_exec.strip() else {}
    finding: dict[str, Any] = {
        "finding_id": finding_id,
        "title": title.strip(),
        "affected_asset": affected_asset.strip(),
        "vuln_class": (vuln_class or "").strip() or "Unclassified",
        "severity": (severity or "").strip() or "Medium",
        "cvss": {
            "base_score": 0.0,
            "temporal_score": None,
            "environmental_score": None,
            "vector_string": "",
            "severity": (severity or "").strip() or "Medium",
        },
        "confidence": 0.5,
        "summary": summary.strip(),
        "reproduction_steps": [],
        "evidence_refs": [evidence.strip()] if evidence.strip() else [],
        "exploitation_result": "",
        "persistence_achieved": False,
        "privilege_level_gained": "",
        "attack_chain": None,
        "remediation": "",
        "references": [],
        "verification_probe": probe,
        "retest_status": "",
        "retest_history": [],
        "verify_status": "HOLDING",
        "verify_history": [],
        "hitl_status": PROPOSED,
        "hitl_history": [
            {
                "timestamp": now or _now_iso(),
                "decision": PROPOSED,
                "note": "agent proposal — awaiting human review",
                "actor": "agent",
            }
        ],
    }
    findings = data.get("technical_findings")
    if not isinstance(findings, list):
        findings = []
        data["technical_findings"] = findings
    findings.append(finding)
    return finding


def _blank_report(run_id: str) -> dict[str, Any]:
    return {
        "report_metadata": {
            "generated_at": _now_iso(),
            "mission_id": run_id,
            "generator_version": "2.0",
            "total_targets": 0,
            "total_exploits": 0,
            "total_failures": 0,
        },
        "executive_summary": "",
        "attack_timeline": [],
        "exploitation_chains": [],
        "failure_analysis": [],
        "technical_findings": [],
    }


def list_proposed_findings(reports_root: Path | str, run_id: str = "") -> tuple[list[dict[str, Any]], str]:
    """Return ``(proposed_findings, resolved_run_id)`` for one run (or every run).

    With ``run_id`` set, reads only that run (LookupError when it has no
    enhanced report). Empty ``run_id`` scans all runs (newest first) and
    aggregates their PROPOSED findings. Never raises on malformed entries.
    """
    root = Path(reports_root)
    if run_id.strip():
        path = _finding_file(root / run_id.strip())
        if not path.is_file():
            raise LookupError(f"run {run_id.strip()!r} has no enhanced report ({path})")
        data = _read_report_json(path)
        proposed = [
            f
            for f in (data.get("technical_findings") or [])
            if isinstance(f, dict) and str(f.get("hitl_status") or "") == PROPOSED
        ]
        return proposed, run_id.strip()
    out: list[dict[str, Any]] = []
    if root.is_dir():
        for run_dir in sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True):
            path = _finding_file(run_dir)
            if not path.is_file():
                continue
            try:
                data = _read_report_json(path)
            except LookupError:
                continue
            for item in data.get("technical_findings") or []:
                if isinstance(item, dict) and str(item.get("hitl_status") or "") == PROPOSED:
                    out.append({**item, "_run_id": run_dir.name})
    return out, ""


def proof_capsule(finding: dict[str, Any]) -> dict[str, Any]:
    """Read-only evidence bundle for the human reviewer (never executes).

    Surfaces the stored probe exec, the latest machine re-proof capsule
    (``verify_history[]``), and the latest retest verdict — everything the
    Evidence tab needs without touching the target.
    """
    probe = finding.get("verification_probe") if isinstance(finding.get("verification_probe"), dict) else {}
    verify_history = finding.get("verify_history") if isinstance(finding.get("verify_history"), list) else []
    last_verify = verify_history[-1] if verify_history and isinstance(verify_history[-1], dict) else {}
    retest_history = finding.get("retest_history") if isinstance(finding.get("retest_history"), list) else []
    last_retest = retest_history[-1] if retest_history and isinstance(retest_history[-1], dict) else {}
    capsule = last_verify.get("proof_capsule") if isinstance(last_verify.get("proof_capsule"), dict) else {}
    outputs = capsule.get("outputs") if isinstance(capsule.get("outputs"), list) else []
    return {
        "finding_id": str(finding.get("finding_id", "")),
        "probe_exec": str(probe.get("exec", "") or capsule.get("probe_exec", "") or ""),
        "output_excerpt": str(outputs[-1] or "")[:2000]
        if outputs
        else str(last_retest.get("evidence", "") or "")[:2000],
        "proof_sha256": str(capsule.get("sha256", "") or ""),
        "proof_runs": capsule.get("n", 0),
        "verify_status": str(finding.get("verify_status") or "HOLDING"),
        "verify_detail": str(last_verify.get("evidence", "") or last_verify.get("verdict", "") or ""),
        "retest_status": str(finding.get("retest_status") or ""),
        "retest_detail": str(last_retest.get("evidence", "") or last_retest.get("verdict", "") or ""),
    }


def register_hitl_tools(mcp: Any, *, ctx: ToolContext) -> None:
    config = ctx.config
    audit_tool = ctx.audit_tool
    if not bool((config or {}).get("hitl", {}).get("enabled", True)):
        return

    @mcp.tool()
    @audit_tool
    def propose_finding(
        run_id: str,
        title: str,
        affected_asset: str,
        summary: str,
        probe_exec: str = "",
        evidence: str = "",
        severity: str = "Medium",
        vuln_class: str = "",
    ) -> str:
        """Propose a candidate finding for human review (agents propose, human decides). Appends a PROPOSED finding to reports/<run_id>/enhanced/enhanced_report.json — never APPROVED. A human promotes it via hitl_decide (operator path) or the WebUI Evidence tab. Zero target touch — pure local artifact write.

        Args:
            run_id: Run to attach the proposal to (must exist under the reports dir).
            title: Short finding title.
            affected_asset: Target IP/hostname the evidence concerns.
            summary: What the agent claims, in one or two sentences.
            probe_exec: Replayable probe command backing the claim (stored, NOT executed here).
            evidence: Output excerpt or evidence ref backing the claim.
            severity: Informational/Low/Medium/High/Critical.
            vuln_class: Vulnerability class (e.g. Known CVE, Weak Credentials).
        """
        if not (run_id or "").strip():
            return "BLOCKED: run_id is required."
        if not (title or "").strip() or not (affected_asset or "").strip() or not (summary or "").strip():
            return "BLOCKED: title, affected_asset, and summary are required."
        root = _reports_root(config)
        run_dir = root / run_id.strip()
        if not run_dir.is_dir():
            return f"ERROR: propose_finding: unknown run {run_id.strip()!r} under {root}"
        path = _finding_file(run_dir)
        try:
            data = _read_report_json(path) if path.is_file() else _blank_report(run_id.strip())
        except LookupError as exc:
            return f"ERROR: propose_finding: {exc}"
        finding = propose_new_finding(
            data,
            title=title,
            affected_asset=affected_asset,
            summary=summary,
            probe_exec=probe_exec,
            evidence=evidence,
            severity=severity,
            vuln_class=vuln_class,
        )
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        except OSError as exc:
            return f"ERROR: propose_finding: cannot persist {path}: {exc}"
        _refresh_siblings(path, data)
        return (
            "HITL_PROPOSED:\n"
            f"FINDING: {finding['finding_id']}\n"
            f"RUN: {run_id.strip()}\n"
            f"STATUS: {PROPOSED} (awaiting human Approve/Reject in the Evidence tab)\n"
            f"TITLE: {finding['title']}"
        )

    @mcp.tool()
    @audit_tool
    def hitl_decide(finding_id: str, decision: str, note: str = "", run_id: str = "", actor: str = "") -> str:
        """Record a human Approve/Reject decision on a proposed finding (operator-only human path — no target touch). Persists APPROVED/REJECTED + hitl_history[] (with actor) into the run artifact JSON. Only actor='human' is accepted — any other actor (including the agent itself) is BLOCKED so an LLM can never self-approve: agents propose via propose_finding, humans decide here or in the WebUI Evidence tab.

        Args:
            finding_id: Proposed finding to decide on.
            decision: APPROVED or REJECTED.
            note: Reviewer note recorded in hitl_history[].
            run_id: Run holding the finding; empty = latest run containing it.
            actor: Must be 'human' (the operator); anything else is refused.
        """
        if not (finding_id or "").strip():
            return "BLOCKED: finding_id is required."
        if (actor or "").strip().lower() != _HUMAN_ACTOR:
            return "BLOCKED: hitl_decide requires actor='human' (operator-only; agents cannot self-approve)."
        try:
            _data, _finding, json_path, resolved_run = locate_finding(
                _reports_root(config), finding_id.strip(), (run_id or "").strip()
            )
        except LookupError as exc:
            return f"ERROR: hitl_decide: {exc}"
        try:
            persist_hitl_decision(json_path, finding_id.strip(), decision, note, actor=_HUMAN_ACTOR)
        except PermissionError as exc:
            return f"BLOCKED: hitl_decide: {exc}"
        except (ValueError, LookupError) as exc:
            return f"ERROR: hitl_decide: {exc}"
        except OSError as exc:
            return f"ERROR: hitl_decide: cannot persist {json_path}: {exc}"
        verdict = (decision or "").strip().upper()
        return f"HITL_DECIDED:\nFINDING: {finding_id.strip()}\nRUN: {resolved_run}\nDECISION: {verdict} (actor=human)"

    @mcp.tool()
    @audit_tool
    def list_proposed(run_id: str = "") -> str:
        """List findings awaiting human review (hitl_status=PROPOSED). Empty run_id scans all runs (newest first). Zero target touch — reads the run artifact JSON only. Approved/rejected findings are hidden here; the final report surfaces APPROVED findings only (see approved_findings)."""
        try:
            proposed, resolved = list_proposed_findings(_reports_root(config), (run_id or "").strip())
        except LookupError as exc:
            return f"ERROR: list_proposed: {exc}"
        scope = resolved or "all runs"
        if not proposed:
            return f"HITL_PROPOSED (run: {scope}): none awaiting review."
        lines = [f"HITL_PROPOSED (run: {scope}): {len(proposed)} awaiting review."]
        for item in proposed[:50]:
            rid = str(item.get("_run_id", "") or resolved)
            lines.append(
                f"- {item.get('finding_id', '?')} [{rid}] {item.get('title', '')} on {item.get('affected_asset', '')}"
            )
        if len(proposed) > 50:
            lines.append(f"... and {len(proposed) - 50} more")
        return "\n".join(lines)


__all__ = [
    "APPROVED",
    "HITL_DECISIONS",
    "HITL_STATUSES",
    "PROPOSED",
    "REJECTED",
    "_slug",
    "approved_findings",
    "list_proposed_findings",
    "persist_hitl_decision",
    "proof_capsule",
    "propose_new_finding",
    "record_hitl_decision",
    "register_hitl_tools",
]
