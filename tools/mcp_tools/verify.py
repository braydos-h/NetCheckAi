"""Verify-or-it-didn't-happen MCP tool ("machine re-proof").

``verify_finding`` reloads a CANDIDATE finding's stored verification probe
from the run artifacts (``reports/<run_id>/enhanced/enhanced_report.json``)
and re-executes ONLY that probe N times (default 2) through the
already-registered ``run_exploit_terminal`` tool function in-process, so the
target-IP allowlist lock, the JSONL audit trail, and the sandbox funnel apply
unchanged — sandbox failures surface as ``SANDBOX_*`` text and fail closed to
``INCONCLUSIVE`` (never a host fallback).

The verdict comes solely from :class:`tools.verify_oracle.VerifyOracle`
(N/N ``outcome_truth`` compromise proof); LLM text, OutcomeJudge text, and
exit codes never decide. Results persist into the EXISTING run artifact JSON
(``verify_status`` + ``verify_history[]`` on the finding; sibling
``.md``/``.html`` regenerated when present). No new DB, no migration.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.enhanced_reporting import EnhancedReportGenerator
from tools.mcp_tools.registry import ToolContext
from tools.mcp_tools.retest import (
    _find_in_report,
    _read_report_json,
    _reports_root,
    _run_probe_in_process,
    locate_finding,
    resolve_exec,
    resolve_probe,
)
from tools.verify_oracle import HOLDING, INCONCLUSIVE, VERIFIED, VerifyOracle

VERIFY_VERDICTS = frozenset({VERIFIED, HOLDING, INCONCLUSIVE})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_verify(
    finding: dict[str, Any],
    verdict: str,
    evidence: str,
    *,
    now: str = "",
    proof_capsule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Stamp ``verify_status`` + append ``verify_history[]`` (mutates, returns finding)."""
    if verdict not in VERIFY_VERDICTS:
        raise ValueError(f"unknown verify verdict {verdict!r}")
    finding["verify_status"] = verdict
    history = finding.get("verify_history")
    if not isinstance(history, list):
        history = []
        finding["verify_history"] = history
    entry: dict[str, Any] = {"timestamp": now or _now_iso(), "verdict": verdict, "evidence": str(evidence or "")}
    if proof_capsule is not None:
        entry["proof_capsule"] = proof_capsule
    history.append(entry)
    return finding


def persist_verify(
    json_path: Path | str,
    finding_id: str,
    verdict: str,
    evidence: str,
    *,
    now: str = "",
    proof_capsule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist one verify verdict into the existing run artifact JSON.

    Updates ``technical_findings[]`` in place and regenerates the sibling
    ``.md``/``.html`` reports when they sit next to the JSON (same stem).
    Returns the updated finding dict.
    """
    path = Path(json_path)
    data = _read_report_json(path)
    finding = _find_in_report(data, (finding_id or "").strip())
    if finding is None:
        raise LookupError(f"finding {finding_id!r} not present in {path}")
    record_verify(finding, verdict, evidence, now=now, proof_capsule=proof_capsule)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    # ponytail: reuse the existing renderers so the verdict lands in the
    # report the operator already reads; only touch siblings that exist.
    # Best-effort: a partial/hand-written JSON must never break persistence.
    try:
        renderer = EnhancedReportGenerator(db=None, mission_id="", workspace=path.parent.parent)
        for suffix, method in ((".md", "_generate_markdown"), (".html", "_generate_html")):
            sibling = path.with_suffix(suffix)
            if sibling.is_file():
                sibling.write_text(getattr(renderer, method)(data), encoding="utf-8")
    except Exception:  # noqa: BLE001 -- report refresh is best-effort; the JSON above is the record
        pass
    return finding


def format_verify_block(
    *,
    finding_id: str,
    target_ip: str,
    run_id: str,
    verdict: str,
    probe_excerpt: str,
    evidence: str,
    detail: str,
    proof_sha: str = "",
    n: int = 0,
) -> str:
    lines = [
        "VERIFY_VERDICT:",
        f"FINDING: {finding_id}",
        f"TARGET: {target_ip}",
        f"RUN: {run_id}",
        f"VERDICT: {verdict}",
        f"PROOF_RUNS: {n}",
        f"PROOF_SHA256: {proof_sha}",
        f"PROBE: {probe_excerpt[:300]}",
        f"EVIDENCE: {evidence}",
        f"DETAIL: {detail[:500]}",
    ]
    return "\n".join(lines)


def register_verify_tools(mcp: Any, *, ctx: ToolContext) -> None:
    config = ctx.config
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def verify_finding(target_ip: str, finding_id: str, run_id: str = "", repeats: int = 2) -> str:
        """Re-prove a candidate finding N times via its stored verification probe (verify-or-it-didn't-happen). Reloads the finding's verification_probe from reports/<run_id>/enhanced/enhanced_report.json (latest run containing it when run_id is empty) and re-executes ONLY that probe N times via run_exploit_terminal, so the target-IP allowlist, audit trail, and sandbox funnel apply unchanged. Returns VERIFY_VERDICT: with VERIFIED (all N runs show machine compromise proof) | HOLDING (flaky or failing proof — stays a candidate) | INCONCLUSIVE (no probe, blocked/sandbox-failed run, or ambiguous output), and persists the verdict plus the replayable proof capsule into the finding's verify_status/verify_history.

        Args:
            target_ip: Current address of the finding's asset (must equal the finding's affected_asset and be allowlisted).
            finding_id: Candidate finding to verify (e.g. ``F-10-0-0-50-run_exploit_terminal``).
            run_id: Run holding the finding; empty = latest run containing it.
            repeats: Proof runs N (default 2, clamped 1-5); ALL must show compromise proof.
        """
        if not finding_id or not finding_id.strip():
            return "BLOCKED: finding_id is required."
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        target = target_ip.strip()
        fid = finding_id.strip()
        try:
            _data, finding, json_path, resolved_run = locate_finding(_reports_root(config), fid, (run_id or "").strip())
        except LookupError as exc:
            return f"ERROR: verify_finding: {exc}"
        asset = str(finding.get("affected_asset", "") or "").strip()
        if asset.lower() != target.lower():
            return (
                f"BLOCKED: target_ip {target!r} does not match the finding's affected_asset "
                f"{asset!r} — verify runs ONLY against the finding's own asset."
            )
        probe = resolve_probe(finding)
        if probe is None:
            verdict, detail, capsule = INCONCLUSIVE, "no stored verification probe for this finding", None
            try:
                persist_verify(json_path, fid, verdict, detail)
            except (OSError, ValueError, LookupError):
                pass
            return format_verify_block(
                finding_id=fid,
                target_ip=target,
                run_id=resolved_run,
                verdict=verdict,
                probe_excerpt="(none stored)",
                evidence=str(json_path),
                detail=detail,
                n=0,
            )
        command = resolve_exec(probe, target)
        try:
            n = max(1, min(int(repeats or 2), 5))
        except (TypeError, ValueError):
            n = 2

        def _run_once(cmd: str) -> str:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return str(asyncio.run(_run_probe_in_process(mcp, cmd)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return str(pool.submit(asyncio.run, _run_probe_in_process(mcp, cmd)).result())

        oracle = VerifyOracle(_run_once)
        outcome = oracle.verify_sync({"exec": command}, repeats=n, run_ids=[resolved_run])
        capsule = outcome.proof_capsule.to_dict()
        history_evidence = f"probe output: {str(outcome.proof_capsule.outputs[-1]).strip()[:300] if outcome.proof_capsule.outputs else '(empty)'}"
        try:
            persist_verify(json_path, fid, outcome.verdict, history_evidence, proof_capsule=capsule)
            evidence = str(json_path)
        except (OSError, ValueError, LookupError):
            evidence = f"{json_path} (persistence failed — verdict not saved)"
        probe_id = str(probe.get("id", "") or probe.get("type", "shell_command"))
        return format_verify_block(
            finding_id=fid,
            target_ip=target,
            run_id=resolved_run,
            verdict=outcome.verdict,
            probe_excerpt=f"[{probe_id}] {command}",
            evidence=evidence,
            detail=outcome.detail,
            proof_sha=outcome.proof_capsule.sha256,
            n=n,
        )


__all__ = [
    "HOLDING",
    "INCONCLUSIVE",
    "VERIFIED",
    "VERIFY_VERDICTS",
    "format_verify_block",
    "persist_verify",
    "record_verify",
    "register_verify_tools",
]
