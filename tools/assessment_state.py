"""Per-run assessment state: hypotheses, notes, and cross-store aggregation.

This module owns exactly one NEW store -- ``<workspace>/plans/<ip>_assessment.json``
carrying the AI's hypotheses and operator-visible notes for a run. Everything
else (plans, recon results, credentials, audit trail, campaigns) already has a
home; ``aggregate_state`` reads those stores and merges them with the owned
state so the AI gets ONE compact snapshot instead of reconstructing state from
conversation history.

Deliberate constraints:
- Compact by construction: raw tool output stays in workspace artifacts; the
  snapshot carries counts, names, and stable references
  (``exploit_audit:<target>:<attempt_id>``, plan step indices, artifact paths).
- Tolerant readers: every external file is optional; a missing/corrupt one
  degrades to empty sections, never an exception.
- The store file is LLM-writable (via the record_hypothesis/update_task MCP
  tools); any consumer that ACTS on its contents must re-validate targets
  against the allowlist (the run_campaign_step precedent).
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_HYPO_STATUSES = ("open", "confirmed", "refuted", "obsolete")


@dataclass
class Hypothesis:
    """One tracked belief about the target the AI is testing."""

    id: str
    statement: str
    status: str = "open"  # open|confirmed|refuted|obsolete
    confidence: float = 0.5
    expected_evidence: list[str] = field(default_factory=list)
    created_from: str = ""  # task id / step index / "planner" / "operator"
    result_note: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class AssessmentState:
    """The part of assessment state this module OWNS (rest is aggregated)."""

    target_ip: str
    goal: str = ""
    phase: str = ""
    hypotheses: list[Hypothesis] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def add_hypothesis(
        self,
        statement: str,
        *,
        confidence: float = 0.5,
        expected_evidence: list[str] | None = None,
        created_from: str = "",
    ) -> Hypothesis:
        hyp = Hypothesis(
            id=f"H-{len(self.hypotheses) + 1:03d}",
            statement=statement.strip()[:500],
            confidence=max(0.0, min(1.0, confidence)),
            expected_evidence=list(expected_evidence or []),
            created_from=created_from,
        )
        self.hypotheses.append(hyp)
        self.updated_at = time.time()
        return hyp

    def set_hypothesis_status(self, hyp_id: str, status: str, note: str = "") -> bool:
        if status not in _HYPO_STATUSES:
            return False
        for hyp in self.hypotheses:
            if hyp.id == hyp_id:
                hyp.status = status
                if note:
                    hyp.result_note = note[:500]
                hyp.updated_at = time.time()
                self.updated_at = time.time()
                return True
        return False

    def find_hypothesis(self, hyp_id: str) -> Hypothesis | None:
        return next((h for h in self.hypotheses if h.id == hyp_id), None)

    def summary_lines(self) -> list[str]:
        open_h = [h for h in self.hypotheses if h.status == "open"]
        lines = [f"HYPOTHESES: {len(open_h)} open / {len(self.hypotheses)} total"]
        for h in self.hypotheses:
            lines.append(f"  [{h.id}] {h.status} ({h.confidence:.2f}) {h.statement[:80]}")
        return lines


def _safe_target_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", target)


class AssessmentStateStore:
    """Load/save AssessmentState as ``<workspace>/plans/<target>_assessment.json``."""

    def __init__(self, workspace: Path | str) -> None:
        self.workspace = Path(workspace)
        (self.workspace / "plans").mkdir(parents=True, exist_ok=True)

    def path_for(self, target: str) -> Path:
        return self.workspace / "plans" / f"{_safe_target_name(target)}_assessment.json"

    def load(self, target: str) -> AssessmentState:
        path = self.path_for(target)
        state = AssessmentState(target_ip=target)
        if not path.exists():
            return state
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return state
        state.goal = str(data.get("goal", ""))
        state.phase = str(data.get("phase", ""))
        state.notes = [str(n) for n in data.get("notes", [])]
        state.created_at = float(data.get("created_at", time.time()))
        state.updated_at = float(data.get("updated_at", time.time()))
        for h in data.get("hypotheses", []):
            if not isinstance(h, dict):
                continue
            hyp = Hypothesis(
                id=str(h.get("id", f"H-{len(state.hypotheses) + 1:03d}")),
                statement=str(h.get("statement", "")),
                status=str(h.get("status", "open")),
                confidence=float(h.get("confidence", 0.5)),
                expected_evidence=[str(e) for e in h.get("expected_evidence", [])],
                created_from=str(h.get("created_from", "")),
                result_note=str(h.get("result_note", "")),
                created_at=float(h.get("created_at", time.time())),
                updated_at=float(h.get("updated_at", time.time())),
            )
            if hyp.status not in _HYPO_STATUSES:
                hyp.status = "open"
            state.hypotheses.append(hyp)
        return state

    def save(self, state: AssessmentState) -> Path:
        """Atomic write (tmp + os.replace) so a kill mid-write never corrupts."""
        state.updated_at = time.time()
        path = self.path_for(state.target_ip)
        payload = {
            "target_ip": state.target_ip,
            "goal": state.goal,
            "phase": state.phase,
            "hypotheses": [asdict(h) for h in state.hypotheses],
            "notes": state.notes,
            "created_at": state.created_at,
            "updated_at": state.updated_at,
        }
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return path


def aggregate_state(target: str, workspace: Path | str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compact cross-store snapshot for one target.

    Reads (all best-effort): the attack plan (DAG state), the owned assessment
    file (hypotheses/notes), the newest recon_result.json (services/CVEs), the
    credential vault (count only -- secrets never leave the store here), and an
    audit-trail rollup (tool-call tallies + recent evidence refs).
    """
    ws = Path(workspace)
    snap: dict[str, Any] = {"target": target}

    # Assessment-owned state (hypotheses/notes/goal/phase).
    store = AssessmentStateStore(ws)
    state = store.load(target)
    snap["goal"] = state.goal
    snap["phase"] = state.phase
    snap["hypotheses"] = [
        {
            "id": h.id,
            "statement": h.statement,
            "status": h.status,
            "confidence": h.confidence,
            "expected_evidence": h.expected_evidence,
        }
        for h in state.hypotheses
    ]
    snap["notes"] = state.notes[-20:]

    # Plan / task graph.
    try:
        from tools.attack_planner import AttackPlanner

        planner = AttackPlanner(ws)
        plan = planner.load_plan(target)
    except Exception:  # noqa: BLE001 -- snapshot never raises
        plan = None
    if plan is not None:
        snap["plan"] = {
            "current_phase": plan.current_phase.value,
            "total_steps": len(plan.steps),
            "completed": sum(1 for s in plan.steps if s.completed),
            "successful": sum(1 for s in plan.steps if s.completed and s.success),
            "ready": [i for i, _s in plan.ready_steps()],
            "blocked": [i for i, _s, _r in plan.blocked_steps()],
            "failed": [i for i, s in enumerate(plan.steps) if s.status == "failed"],
        }
        # The assessment store's goal/phase are only set when something writes
        # them -- fall back to the live plan so snapshots never report
        # GOAL/PHASE (unset) mid-run when a plan already exists.
        if not snap["goal"]:
            snap["goal"] = str(getattr(plan, "goal", "") or "")
        if not snap["phase"]:
            snap["phase"] = str(plan.current_phase.value or "")

    # Newest recon result.
    recon = _newest_recon(ws, target)
    if recon is not None:
        snap["recon"] = recon

    # Credential vault: counts only.
    creds_dir = ws / "credentials" / _safe_target_name(target)
    snap["credentials_available"] = sum(1 for p in creds_dir.glob("*.jsonl")) if creds_dir.is_dir() else 0

    # Audit rollup (last entries for this target).
    snap["activity"] = _audit_rollup(ws, target)

    return snap


def _newest_recon(ws: Path, target: str) -> dict[str, Any] | None:
    """Summarize the newest recon_result.json under workspace attempt dirs."""
    try:
        candidates = sorted(ws.rglob("recon_result.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return None
    target_cf = target.casefold()
    for path in candidates[:20]:
        # Prefer a path whose attempt lineage names the target.
        if target_cf not in str(path).casefold() and len(candidates) > 1:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        services = data.get("services") or []
        cves = data.get("cves") or data.get("known_cves") or []
        return {
            "artifact": str(path),
            "os": data.get("os") or data.get("os_guess") or "",
            "service_count": len(services),
            "services": [
                {
                    "service": s.get("service", ""),
                    "port": s.get("port", ""),
                    "version": s.get("version", ""),
                }
                for s in services[:25]
                if isinstance(s, dict)
            ],
            "cves": [str(c) for c in cves[:25]],
        }
    return None


def _audit_rollup(ws: Path, target: str, limit: int = 25) -> dict[str, Any]:
    """Tally audit entries for the target; return compact refs, not raw output."""
    audit = ws / "exploit_audit.jsonl"
    out: dict[str, Any] = {"tool_calls": 0, "blocked": 0, "by_tool": {}, "recent": []}
    if not audit.exists():
        return out
    try:
        with audit.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(rec.get("target_ip", "")) != target:
                    continue
                if rec.get("status") == "started":
                    continue
                # Some audit rows (capability discovery, sandbox scope gates)
                # carry no tool_name -- fall back to the action so BY_TOOL
                # never reports an empty-name bucket.
                tool = str(rec.get("tool_name", "") or rec.get("action", ""))
                out["tool_calls"] += 1
                if rec.get("status") == "blocked" or rec.get("approved") is False:
                    out["blocked"] += 1
                out["by_tool"][tool] = out["by_tool"].get(tool, 0) + 1
                out["recent"].append(
                    f"exploit_audit:{target}:{rec.get('attempt_id', '')} tool={tool} status={rec.get('status', '')}"
                )
    except OSError:
        return out
    out["recent"] = out["recent"][-limit:]
    return out
