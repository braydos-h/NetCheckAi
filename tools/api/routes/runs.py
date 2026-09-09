"""Assessment run routes: POST /runs, GET /runs (sort+title), GET /runs/{id},
cancel, resume, POST /runs/{id}/title (AI retitle), tools, artifacts, logs,
audit, swarm, campaign, credentials, loot."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from tools.api.auth import BearerAuth
from tools.api.errors import APIError
from tools.api.persistence import ApiPersistence
from tools.api.run_manager import RunManager, _preview_to_dict
from tools.run_service.models import RunKind, RunRequest

_ARTIFACT_WHITELIST = frozenset(
    {
        "session_summary.md",
        "run.json",
        "recon_assessment.json",
        "fast_recon.json",
        "goal_suggestions.json",
        "activity.jsonl",
        "exploit_audit.jsonl",
        "events.jsonl",
        "errors.jsonl",
        "session_error.log",
        "recon_first_error.log",
    }
)

_LOG_WHITELIST = frozenset(
    {
        "mcp_exploit_server.log",
        "session_error.log",
        "recon_first_error.log",
    }
)

_CONTENT_TYPES = {
    ".md": "text/markdown; charset=utf-8",
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".html": "text/html; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    # Browser-agent screenshots (workspace/browser/<session>/*.png) must render
    # inline in the WebUI Browser tab — octet-stream would force a download.
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
}


def _safe_child(parent: Path, name: str, *, allow_subdirs: bool = False) -> Path:
    """Resolve ``name`` under ``parent`` and refuse path traversal.

    ``allow_subdirs`` permits a single subdirectory level (e.g. ``enhanced/foo.json``)
    but still rejects ``..``, absolute paths, and deeper nesting.
    """
    if not name or name in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid name")
    parts = [p for p in name.replace("\\", "/").split("/") if p and p != "."]
    if not parts:
        raise HTTPException(status_code=400, detail="Invalid name")
    if ".." in parts:
        raise HTTPException(status_code=400, detail="Invalid name")
    if not allow_subdirs and len(parts) != 1:
        raise HTTPException(status_code=400, detail="Invalid name")
    candidate = (parent / Path(*parts)).resolve()
    if parent.resolve() not in candidate.parents and candidate != parent.resolve():
        raise HTTPException(status_code=400, detail="Invalid name")
    if not str(candidate).startswith(str(parent.resolve())):
        raise HTTPException(status_code=400, detail="Invalid name")
    return candidate


def _safe_workspace_path(ws_root: Path, rel_path: str) -> Path:
    """Resolve a workspace-relative path and refuse traversal outside ``ws_root``.

    Unlike ``_safe_child`` this permits arbitrary nesting depth (workspace files
    live under ``exploit_workspace/<ip>/<attempt>/...``) while still rejecting
    ``..``, absolute paths, and empty segments.
    """
    if not rel_path or rel_path in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid path")
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p and p != "."]
    if not parts or ".." in parts:
        raise HTTPException(status_code=400, detail="Invalid path")
    candidate = (ws_root / Path(*parts)).resolve()
    if ws_root.resolve() not in candidate.parents and candidate != ws_root.resolve():
        raise HTTPException(status_code=400, detail="Invalid path")
    return candidate


# ── Request models ──────────────────────────────────────────────────────────


class RunCreateRequest(BaseModel):
    target: str = Field(..., description="Target IP or domain")
    mode: str = Field("attack", pattern="^(recon|attack|fast)$")
    goal: str = ""
    custom_goal: str = ""
    recon_first: bool | None = None
    model: str | None = None
    swarm: bool = False
    parallel_swarm: bool = False
    critic: bool = False
    reflection: bool = False
    adaptive_exploits: bool = False
    long_session: bool = False
    multi_model_consult: bool | None = None
    observer_mode: str = "hybrid"
    ultrathink: bool = False
    skills: str | None = None
    skills_include: list[str] = Field(default_factory=list)
    skills_exclude: list[str] = Field(default_factory=list)
    resume: str = ""
    kind: str = Field("agent", pattern="^agent$")
    yes: bool = False


class DecisionAnswerRequest(BaseModel):
    answer: str


class TitleRequest(BaseModel):
    """Body for POST /runs/{id}/title — manual retitle or regen trigger."""

    title: str | None = None  # explicit title; if None + regen=true, AI-generate
    regen: bool = False  # force AI regeneration even if a title exists


class ToolCallRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


class HitlDecideRequest(BaseModel):
    finding_id: str = ""
    decision: str = ""
    note: str = ""


def create_router(auth: BearerAuth, persistence: ApiPersistence, run_manager: RunManager) -> APIRouter:
    """Create a runs router with isolated dependencies."""
    router = APIRouter(prefix="/api/v1", tags=["runs"])

    async def _require_auth(request: Request) -> str:
        return await auth(request)

    def _rm() -> RunManager:
        return run_manager

    def _ps() -> ApiPersistence:
        return persistence

    def _run_dir(run_id: str) -> Path:
        """Resolve the reports/<run_id>/ directory, refusing path escapes."""
        base = _ps().reports_dir.resolve()
        candidate = (base / run_id).resolve()
        if base not in candidate.parents and candidate != base:
            raise HTTPException(status_code=400, detail="Invalid run id")
        return candidate

    def _exploit_workspace(run_id: str) -> Path:
        return _run_dir(run_id) / "exploit_workspace"

    def _credential_access_log(run_id: str) -> Path:
        return _run_dir(run_id) / "credential_access.jsonl"

    def _find_credential_stores(ws: Path) -> list[Path]:
        """Find credential.jsonl files under exploit_workspace/credentials/<target>/."""
        stores: list[Path] = []
        cred_root = ws / "credentials"
        if cred_root.is_dir():
            for child in sorted(cred_root.iterdir()):
                p = child / "credentials.jsonl"
                if p.is_file():
                    stores.append(p)
        legacy = ws / "credentials.jsonl"
        if legacy.is_file():
            stores.append(legacy)
        return stores

    def _find_audit_file(run_id: str) -> Path | None:
        """Locate the run's exploit_audit.jsonl (reports/ root first, workspace fallback)."""
        run_dir = _run_dir(run_id)
        audit_path = run_dir / "exploit_audit.jsonl"
        if not audit_path.exists():
            audit_path = run_dir / "exploit_workspace" / "exploit_audit.jsonl"
        return audit_path if audit_path.exists() else None

    def _read_jsonl_dicts(path: Path) -> Iterator[dict[str, Any]]:
        """Yield parsed JSON objects from a JSONL file, skipping bad/blank lines."""
        if not path.is_file():
            return
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    yield record

    # Sandbox helpers (pure, but need to be inside closure for _run_dir)
    _SANDBOX_CODE_RE = re.compile(r"SANDBOX_[A-Z_]+")
    _BLOCK_MESSAGE_STOP = ("TOOL:", "EXECUTED:", "REMEDIATION:", "ATTEMPT_ID:", "TARGET:")
    _RECENT_BLOCK_LIMIT = 5

    def _sandbox_block_message(result_text: str, code: str) -> str:
        """First human-readable line after the SANDBOX_* code line, clipped."""
        lines = [ln.strip() for ln in result_text.splitlines() if ln.strip()]
        for idx, line in enumerate(lines):
            if code in line and idx + 1 < len(lines):
                nxt = lines[idx + 1]
                if nxt.startswith(_BLOCK_MESSAGE_STOP):
                    return ""
                return nxt[:200]
        return ""

    def _run_sandbox_summary(run_id: str) -> dict[str, Any]:
        """Assemble the per-run sandbox picture from on-disk run artifacts."""
        summary: dict[str, Any] = {
            "run_id": run_id,
            "found": False,
            "config": {},
            "container": {},
            "network": {},
            "executions": {"started": 0, "completed": 0, "failed": 0, "timed_out": 0, "total": 0},
            "blocked": {"total": 0, "recent": []},
            "last_activity": "",
        }
        audit_path = _find_audit_file(run_id)
        counts = summary["executions"]
        if audit_path is not None:
            for row in _read_jsonl_dicts(audit_path):
                ts = str(row.get("timestamp") or "")
                if ts:
                    summary["last_activity"] = ts
                if str(row.get("status") or "") == "blocked":
                    summary["blocked"]["total"] += 1
                payload = row.get("sandbox")
                if not isinstance(payload, dict):
                    continue
                tool_name = str(row.get("tool_name") or "")
                if tool_name.endswith("cleanup"):
                    continue
                summary["found"] = True
                status = str(row.get("status") or "")
                if status in ("started", "completed", "failed", "timed_out"):
                    counts[status] += 1
                summary["config"] = {
                    "enabled": payload.get("enabled"),
                    "backend": payload.get("backend"),
                    "image": payload.get("image"),
                    "user": payload.get("user"),
                }
                summary["container"] = {
                    "id": payload.get("container_id"),
                    "sandbox_run_id": payload.get("run_id"),
                }
                network = payload.get("network")
                if isinstance(network, dict):
                    summary["network"] = {
                        "enforced": network.get("enforced"),
                        "fingerprint": network.get("fingerprint"),
                        "authorized_destinations": network.get("authorized_destinations") or [],
                        "explicitly_blocked": network.get("explicitly_blocked") or [],
                        "resolved_domains": network.get("resolved_domains") or {},
                        "unresolved_targets": network.get("unresolved_targets") or [],
                        "allow_dns": network.get("allow_dns"),
                    }
        counts["total"] = counts["completed"] + counts["failed"] + counts["timed_out"]
        # Collapsed audit (no manager "started" rows on new trails): attempts
        # is the max of started-rows and terminal-rows. Legacy trails carry
        # 1:1 started:terminal rows (max = either); new trails carry terminal
        # rows only (max = total). Never the sum (that would double-count).
        summary["executions"] = {"attempts": max(counts.pop("started"), counts["total"]), **counts}
        events_path = _run_dir(run_id) / "events.jsonl"
        blocks: list[dict[str, Any]] = []
        for event in _read_jsonl_dicts(events_path):
            if str(event.get("type") or "") != "tool_result":
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            result_text = str(payload.get("result") or "")
            match = _SANDBOX_CODE_RE.search(result_text)
            if not match:
                continue
            code = match.group(0)
            blocks.append(
                {
                    "timestamp": event.get("timestamp") or "",
                    "tool": payload.get("name") or "",
                    "code": code,
                    "message": _sandbox_block_message(result_text, code),
                }
            )
        if blocks:
            summary["found"] = True
            summary["blocked"]["recent"] = blocks[-_RECENT_BLOCK_LIMIT:]
            summary["blocked"]["total"] = max(int(summary["blocked"]["total"]), len(blocks))
        return summary

    def _read_state_json(run_id: str, filename: str, *, subdir: str = "") -> dict[str, Any]:
        """Read a JSON state file under reports/<run_id>/swarm_workspace/[subdir/]."""
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        base = _run_dir(run_id) / "swarm_workspace"
        state_path = base / subdir / filename if subdir else base / filename
        if not state_path.exists() or not state_path.is_file():
            raise HTTPException(status_code=404, detail=f"{filename} not found")
        try:
            return json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=500, detail=f"Could not parse {filename}")

    # ── Routes ──────────────────────────────────────────────────────────────────

    @router.post("/runs", status_code=201)
    async def create_run(body: RunCreateRequest, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Create a run. Returns immediately with ``state: "preparing"``; the run
        row is persisted up-front and preparation (plugins, model, target
        resolution, skills) continues in the background, transitioning the run to
        ``awaiting_confirmation``/``queued`` (events stream via
        ``GET /runs/{id}/events``). ``preview``/``decision`` are null until
        preparation completes — poll ``GET /runs/{id}`` for the filled preview
        and ``GET /runs/{id}/decisions`` for the start_confirm decision."""
        request = RunRequest(
            target=body.target,
            mode=body.mode,
            goal_name=body.goal,
            custom_goal=body.custom_goal,
            recon_first=body.recon_first,
            model_alias=body.model or "",
            swarm=body.swarm,
            parallel_swarm=body.parallel_swarm,
            critic=body.critic,
            reflection=body.reflection,
            adaptive_exploits=body.adaptive_exploits,
            long_session=body.long_session,
            multi_model_consult=body.multi_model_consult,
            observer_mode=body.observer_mode,
            ultrathink=body.ultrathink,
            skills_mode=body.skills,
            skills_include=body.skills_include,
            skills_exclude=body.skills_exclude,
            resume_source=body.resume,
            kind=RunKind(body.kind),
            yes=body.yes,
        )
        run_id, preview, decision = await _rm().create_run(request)
        if preview is not None:
            state = "awaiting_confirmation" if decision else "queued"
        else:
            state = "preparing"
        result: dict[str, Any] = {
            "run_id": run_id,
            "preview": _preview_to_dict(preview) if preview is not None else None,
            "state": state,
        }
        if decision:
            result["decision"] = {
                "id": decision.id,
                "kind": decision.kind.value,
                "required_text": decision.required_text,
                "prompt_text": decision.prompt_text,
            }
        return result

    @router.post("/runs/demo/restore")
    async def restore_demo(auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Explicitly recreate the built-in demo session (clears the tombstone).

        Idempotent: when the demo already exists it just ensures artifacts are
        present and returns the existing id. The tombstone ``demo_deleted`` is
        cleared so future restarts keep the demo.
        """
        from tools.api.demo_seed import DEMO_RUN_ID
        from tools.api.demo_seed import restore_demo as _restore

        persistence = _ps()
        reports_dir = persistence.reports_dir
        # restore_demo clears the tombstone and seeds if missing.
        _restore(persistence, reports_dir)
        return {"run_id": DEMO_RUN_ID, "restored": True}

    @router.get("/runs")
    async def list_runs(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        sort: str = Query(
            "created_desc",
            pattern="^(created_desc|created_asc|title_asc|title_desc|state_asc|state_desc)$",
        ),
        q: str = Query("", max_length=200),
        state: str = Query("", max_length=32),
        auth: str = Depends(_require_auth),
    ) -> dict[str, Any]:
        """List run history with target/mode/goal/model/title summary (no N+1).

        ``q`` filters on title/target/mode/goal; ``state`` filters on the exact
        run state. ``total`` is the filtered count (for pagination).
        """
        runs = _ps().list_runs(limit=limit, offset=offset, sort=sort, q=q, state=state)
        total = _ps().count_runs(q=q, state=state)
        out: list[dict[str, Any]] = []
        for r in runs:
            req = r.get("request_json", {}) or {}
            prev = r.get("preview_json", {}) or {}
            is_demo = bool(r.get("is_demo"))
            # Fallback for pre-migrated rows where is_demo not yet backfilled but
            # the preview carries the marker.
            if not is_demo and (prev.get("is_demo") is True or prev.get("source") == "demo"):
                is_demo = True
            out.append(
                {
                    "id": r["id"],
                    "state": r["state"],
                    "created_at": r["created_at"],
                    "target": req.get("target", ""),
                    "mode": req.get("mode", ""),
                    "goal_name": req.get("goal_name", ""),
                    "target_ip": prev.get("target_ip", ""),
                    "model_alias": prev.get("model_alias", ""),
                    "title": r.get("title", "") or "",
                    "is_demo": is_demo,
                }
            )
        return {"runs": out, "sort": sort, "total": total}

    @router.get("/runs/{run_id}")
    async def get_run(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Get run details: effective state, progress, pending decisions, artifacts, result, errors."""
        run = _ps().get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        decisions = _ps().list_decisions(run_id)
        is_demo = bool(run.get("is_demo"))
        # Backfill for pre-migrated rows
        if not is_demo:
            preview_tmp = run.get("preview_json") or {}
            if isinstance(preview_tmp, dict) and (
                preview_tmp.get("is_demo") is True or preview_tmp.get("source") == "demo"
            ):
                is_demo = True
        return {
            "id": run["id"],
            "state": run["state"],
            "created_at": run["created_at"],
            "updated_at": run["updated_at"],
            "request": run.get("request_json", {}),
            "preview": run.get("preview_json", {}),
            "result": run.get("result_json", {}),
            "error": run.get("error", ""),
            "title": run.get("title", "") or "",
            "cancelled_at": run.get("cancelled_at", ""),
            "resumed_from": run.get("resumed_from", ""),
            "is_demo": is_demo,
            "decisions": [
                {"id": d["id"], "kind": d["kind"], "status": d["status"], "answer": d["answer"]} for d in decisions
            ],
        }

    @router.post("/runs/{run_id}/cancel")
    async def cancel_run(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Cooperative cancellation + guaranteed MCP/swarm child cleanup."""
        await _rm().cancel_run(run_id)
        return {"run_id": run_id, "state": "cancelled"}

    @router.post("/runs/{run_id}/resume")
    async def resume_run(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Create a new execution record linked by resumed_from, reusing existing report/session state."""
        original = _ps().get_run(run_id)
        if original is None:
            raise HTTPException(status_code=404, detail="Original run not found")
        req_data = original.get("request_json", {})
        request_fields = {key: value for key, value in req_data.items() if key in RunRequest.__dataclass_fields__}
        request_fields.update(
            resume_source=run_id,
            kind=RunKind(req_data.get("kind", "agent")),
            yes=False,
        )
        request = RunRequest(**request_fields)
        new_id, _preview, _decision = await _rm().create_run(request)
        return {
            "run_id": new_id,
            "resumed_from": run_id,
        }

    @router.post("/runs/{run_id}/title")
    async def set_run_title(
        run_id: str,
        body: TitleRequest,
        auth: str = Depends(_require_auth),
    ) -> dict[str, Any]:
        """Set or AI-regenerate a run's title.

        - ``{"title": "..."}`` — persist the explicit title (max 200 chars).
        - ``{"regen": true}`` — ask ``gemma4:31b-cloud`` for a fresh title from
          the run's result/request; ignored if ``title`` is also set.
        - ``{}`` — no-op; returns the current title.

        Best-effort: a titler failure (ollama unreachable, empty response) returns
        the current title unchanged with a 200, never 5xx.
        """
        run = _ps().get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        current = run.get("title", "") or ""
        new_title = (body.title or "").strip()[:200]
        if not new_title and body.regen:
            from tools.api.session_titler import generate_session_title_sync

            cfg = _rm().config
            host = str((cfg.get("ollama") or {}).get("host") or "https://api.ollama.com")
            new_title = await asyncio.to_thread(
                generate_session_title_sync,
                run.get("result_json", {}) or {},
                run.get("request_json", {}) or {},
                host=host,
                config=cfg,
            )
        if new_title and new_title != current:
            _ps().update_run_title(run_id, new_title)
            return {"run_id": run_id, "title": new_title, "regenerated": body.regen and not body.title}
        return {"run_id": run_id, "title": current, "regenerated": False}

    @router.get("/runs/{run_id}/tools")
    async def get_tools(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Return the live MCP tool schemas (including plugin-contributed tools)."""
        schemas = _rm().get_tool_schemas(run_id)
        return {"tools": schemas}

    @router.post("/runs/{run_id}/tools/{tool_name}/calls")
    async def call_tool(
        run_id: str, tool_name: str, body: ToolCallRequest, auth: str = Depends(_require_auth)
    ) -> dict[str, Any]:
        """Policy-gated REST bridge for manual WebUI tool calls."""
        return await _rm().call_tool(run_id, tool_name, body.arguments)

    # ── Artifacts (B2-B3) ───────────────────────────────────────────────────────

    @router.get("/runs/{run_id}/artifacts")
    async def list_artifacts(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """List known run-level artifacts present on disk."""
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        run_dir = _run_dir(run_id)
        artifacts: list[dict[str, Any]] = []
        for name in sorted(_ARTIFACT_WHITELIST):
            p = run_dir / name
            if p.exists() and p.is_file():
                artifacts.append({"name": name, "bytes": p.stat().st_size, "exists": True})
        enhanced = run_dir / "enhanced"
        if enhanced.exists() and enhanced.is_dir():
            for child in sorted(enhanced.iterdir()):
                if child.is_file():
                    artifacts.append(
                        {
                            "name": f"enhanced/{child.name}",
                            "bytes": child.stat().st_size,
                            "exists": True,
                        }
                    )
        return {"artifacts": artifacts}

    @router.get("/runs/{run_id}/artifacts/{name:path}")
    async def get_artifact(run_id: str, name: str, auth: str = Depends(_require_auth)) -> Any:
        """Serve one artifact's content. Whitelist-bound; path-traversal-safe."""
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        run_dir = _run_dir(run_id)
        is_enhanced = name.startswith("enhanced/")
        bare = name.split("/", 1)[-1] if is_enhanced else name
        if is_enhanced:
            enhanced = run_dir / "enhanced"
            # Guard the directory before iterdir(): is_dir() returns False (no raise)
            # for a missing path, so a run that never produced an enhanced report
            # resolves to a clean 404 instead of FileNotFoundError -> 500.
            if not enhanced.is_dir() or bare not in {child.name for child in enhanced.iterdir()}:
                raise HTTPException(status_code=404, detail="Artifact not found")
            path = _safe_child(run_dir, name, allow_subdirs=True)
        elif name in _ARTIFACT_WHITELIST:
            path = _safe_child(run_dir, name)
        else:
            raise HTTPException(status_code=404, detail="Artifact not found")
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=404, detail="Artifact not found")
        content_type = _CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")
        from fastapi import Response

        return Response(content=path.read_bytes(), media_type=content_type)

    # ── Workspace file browser (C10) ─────────────────────────────────────────────

    @router.get("/runs/{run_id}/workspace")
    async def list_workspace(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """List files under the run's exploit_workspace/ (recursive, relative paths)."""
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        ws = _exploit_workspace(run_id)
        if not ws.is_dir():
            return {"files": []}
        files: list[dict[str, Any]] = []
        for p in sorted(ws.rglob("*")):
            if p.is_file():
                files.append({"path": p.relative_to(ws).as_posix(), "bytes": p.stat().st_size})
        return {"files": files}

    @router.get("/runs/{run_id}/workspace/{path:path}")
    async def get_workspace_file(run_id: str, path: str, auth: str = Depends(_require_auth)) -> Any:
        """Read one file under the run's exploit_workspace/ (path-traversal-safe)."""
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        ws = _exploit_workspace(run_id)
        target = _safe_workspace_path(ws, path)
        if not target.is_file():
            raise HTTPException(status_code=404, detail="File not found")
        content_type = _CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream")
        from fastapi import Response

        return Response(content=target.read_bytes(), media_type=content_type)

    # ── Audit trail (C6) ────────────────────────────────────────────────────────

    @router.get("/runs/{run_id}/audit")
    async def get_audit(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Read the tamper-evident exploit audit log + verify the hash chain."""
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        audit_path = _find_audit_file(run_id)
        records: list[dict[str, Any]] = list(_read_jsonl_dicts(audit_path)) if audit_path else []
        chain_valid, chain_reason = (True, "no audit log")
        if audit_path is not None:
            try:
                from tools.exploit_agent.policy import verify_audit_chain

                chain_valid, chain_reason = verify_audit_chain(audit_path)
            except Exception as exc:
                chain_valid, chain_reason = False, f"verification error: {exc}"
        return {"records": records, "chain_valid": chain_valid, "chain_reason": chain_reason}

    # ── Deep error records (Deep Run Logs) ────────────────────────────────────

    @router.get("/runs/{run_id}/errors")
    async def get_errors(
        run_id: str,
        kind: str = Query("", description="Filter by deep-error kind (e.g. stuck_loop, tool_error)"),
        tail: int = Query(200, ge=1, le=2000),
        auth: str = Depends(_require_auth),
    ) -> dict[str, Any]:
        """Read the run's deep-error records (errors.jsonl), newest last.

        Each record carries kind/phase/round/tool/traceback/corr_id so a later
        fixer-agent can diagnose a stuck run without replaying the transcript.
        200 with an empty list when the run wrote no deep errors; 404 for
        unknown runs. The file is also in the artifact whitelist.
        """
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        errors_path = _run_dir(run_id) / "errors.jsonl"
        records: list[dict[str, Any]] = list(_read_jsonl_dicts(errors_path)) if errors_path.is_file() else []
        kinds = sorted({str(r.get("kind") or "") for r in records if r.get("kind")})
        if kind:
            records = [r for r in records if str(r.get("kind") or "") == kind]
        return {
            "run_id": run_id,
            "records": records[-tail:],
            "total_records": len(records),
            "kinds": kinds,
        }

    # ── Per-run sandbox summary (WebUI Sandbox tab) ─────────────────────────────

    @router.get("/runs/{run_id}/sandbox")
    async def get_run_sandbox(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Read-only per-run sandbox summary for the WebUI Sandbox tab.

        Derived entirely from run artifacts (exploit_audit.jsonl + events.jsonl):
        container identity, last network-authorization policy, execution status
        counts, and recent SANDBOX_* blocked-command reasons. 200 with empty
        structures when the run has no sandbox data; 404 for unknown runs. No
        Docker exec/remove controls -- live worker state stays manager-side.
        """
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return _run_sandbox_summary(run_id)

    # ── HITL evidence loop (Flow A: agents propose, human decides) ──────────

    @router.get("/runs/{run_id}/proposed")
    async def list_proposed(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """List findings awaiting human review (hitl_status=PROPOSED) for a run.

        Each entry embeds its read-only ``proof`` capsule (stored probe exec +
        output excerpt + machine retest/verify verdicts) — no target touch.
        """
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        from tools.mcp_tools.hitl import list_proposed_findings, proof_capsule

        try:
            proposed, _resolved = list_proposed_findings(_ps().reports_dir, run_id)
        except LookupError:
            return {"run_id": run_id, "proposed": []}
        return {
            "run_id": run_id,
            "proposed": [{**finding, "proof": proof_capsule(finding)} for finding in proposed],
        }

    @router.post("/runs/{run_id}/decide")
    async def decide_finding(
        run_id: str, body: HitlDecideRequest, auth: str = Depends(_require_auth)
    ) -> dict[str, Any]:
        """Record a human Approve/Reject decision (actor is always ``human``).

        The bearer-gated WebUI IS the human path, so the actor is hardcoded
        server-side and never accepted from the client — an LLM cannot
        self-approve. Persists into the run artifact JSON and emits a
        ``hitl_decision`` event for live WebUI refresh.
        """
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        if not (body.finding_id or "").strip():
            raise HTTPException(status_code=400, detail="finding_id is required")
        from tools.mcp_tools.hitl import persist_hitl_decision
        from tools.mcp_tools.retest import _finding_file

        json_path = _finding_file(_ps().reports_dir / run_id)
        if not json_path.is_file():
            raise HTTPException(status_code=404, detail="Run has no enhanced report")
        try:
            finding = persist_hitl_decision(json_path, body.finding_id.strip(), body.decision, body.note, actor="human")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        broker_registry = getattr(_rm(), "_events", None)
        if broker_registry is not None:
            hitl_event = {
                "finding_id": body.finding_id.strip(),
                "decision": str(finding.get("hitl_status") or ""),
                "note": body.note or "",
                "actor": "human",
            }
            try:
                broker = broker_registry.get_or_create(run_id)
                try:
                    await broker.emit("hitl_decision", hitl_event)
                except RuntimeError:
                    # Broker closed when the run left active handling (review
                    # happens post-run) — re-arm it for this annotation, then emit.
                    broker.reopen()
                    await broker.emit("hitl_decision", hitl_event)
            except Exception:  # noqa: BLE001 -- persistence won; a dropped live event heals via polling
                pass
        return {"run_id": run_id, "finding_id": body.finding_id.strip(), "finding": finding}

    # ── Swarm + campaign state (C7-C8) ──────────────────────────────────────────

    @router.get("/runs/{run_id}/witness")
    async def get_witness_flags(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Read the advisory witness log (reports/witness.jsonl by default).

        The witness agent (``tools/swarm/agents/witness_agent.py``) is an advisory
        audit-stream watcher that flags anomalies (allowlist breach, PoC escape,
        permission escalation, prompt-injection, DoS drift) to a JSONL log. The
        log path is configured via ``witness.log_path`` (default
        ``reports/witness.jsonl``) and is process-global, not per-run. Returns the
        parsed flag records; 404 when the log is absent so the WebUI no-retries.
        """
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        cfg = _rm().config or {}
        witness_cfg = cfg.get("witness", {}) or {}
        log_path = str(witness_cfg.get("log_path", "reports/witness.jsonl") or "reports/witness.jsonl")
        path = Path(log_path)
        if not path.is_file():
            raise HTTPException(status_code=404, detail="witness log not found")
        flags: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                flags.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"flags": flags}

    @router.get("/runs/{run_id}/swarm")
    async def get_swarm_state(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Read the swarm orchestrator state (swarm_state.json)."""
        return {"state": _read_state_json(run_id, "swarm_state.json")}

    @router.get("/runs/{run_id}/campaign")
    async def get_campaign_state(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """Read the autonomous orchestrator campaign state (attack_states.json).

        The autonomous orchestrator runs under ``swarm_workspace/autonomous/`` so
        the state file lives there, not at the swarm_workspace root.
        """
        return {"state": _read_state_json(run_id, "attack_states.json", subdir="autonomous")}

    # ── Log tailing (C9) ────────────────────────────────────────────────────────

    @router.get("/runs/{run_id}/logs/{name}")
    async def get_log(
        run_id: str,
        name: str,
        tail: int = Query(200, ge=1, le=2000),
        attempt_id: str = "",
        target_ip: str = "",
        auth: str = Depends(_require_auth),
    ) -> dict[str, Any]:
        """Tail a run log. ``name`` must be in the whitelist; per-attempt logs need
        ``attempt_id`` + ``target_ip`` to resolve under exploit_workspace/<ip>/<id>/.
        """
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        run_dir = _run_dir(run_id)
        per_attempt = {"terminal.log", "python_run.log", "msf_output.log", "run_active_check.ps1"}
        recognized = _LOG_WHITELIST | per_attempt
        if name not in recognized:
            raise HTTPException(status_code=404, detail="Log not found")
        if name in per_attempt:
            if not attempt_id or not target_ip:
                raise HTTPException(
                    status_code=400,
                    detail="This log requires attempt_id and target_ip query params",
                )
            ip_dir = _safe_child(run_dir / "exploit_workspace", target_ip, allow_subdirs=True)
            attempt_dir = _safe_child(ip_dir, attempt_id, allow_subdirs=True)
            log_path = _safe_child(attempt_dir, name)
            candidates = [log_path]
        else:
            candidates = [run_dir / name]
            if name == "mcp_exploit_server.log":
                candidates.append(run_dir / "exploit_workspace" / "mcp_exploit_server.log")
        log_path = next((p for p in candidates if p.exists() and p.is_file()), None)
        if log_path is None:
            raise HTTPException(status_code=404, detail="Log not found")
        all_lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        returned = all_lines[-tail:]
        return {
            "name": name,
            "lines": returned,
            "total_lines_returned": len(returned),
            "total_lines_in_file": len(all_lines),
        }

    # ── Credentials + loot (C3-C5) ──────────────────────────────────────────────

    @router.get("/runs/{run_id}/credentials")
    async def list_credentials(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """List credentials harvested during the run. Passwords are NEVER returned."""
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        ws = _exploit_workspace(run_id)
        stores = _find_credential_stores(ws)
        if not stores:
            return {"credentials": []}
        try:
            from tools.credential_store import CredentialStore

            out: list[dict[str, Any]] = []
            idx = 0
            for store_path in stores:
                store = CredentialStore(store_path.parent)
                for rec in store.all_credentials():
                    data = rec.to_json()
                    data["password"] = "[REDACTED]"
                    data["index"] = idx
                    out.append(data)
                    idx += 1
            return {"credentials": out}
        except Exception:
            raise HTTPException(status_code=500, detail="Could not read credentials")

    @router.post("/runs/{run_id}/credentials/{index}/reveal")
    async def reveal_credential(
        run_id: str,
        index: int,
        auth: str = Depends(_require_auth),
    ) -> dict[str, Any]:
        """Reveal one credential's plaintext password. Audited."""
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        ws = _exploit_workspace(run_id)
        stores = _find_credential_stores(ws)
        if not stores:
            raise HTTPException(status_code=404, detail="No credentials for this run")
        try:
            from tools.credential_store import CredentialStore

            records: list[Any] = []
            store_paths: list[Path] = []
            for store_path in stores:
                store = CredentialStore(store_path.parent)
                for rec in store.all_credentials():
                    records.append(rec)
                    store_paths.append(store_path)
        except Exception:
            raise HTTPException(status_code=500, detail="Could not read credentials")
        if index < 0 or index >= len(records):
            raise HTTPException(status_code=404, detail="Credential index out of range")
        rec = records[index]
        access_entry = {
            "run_id": run_id,
            "index": index,
            "username": rec.username,
            "target_host": rec.target_host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with _credential_access_log(run_id).open("a", encoding="utf-8") as f:
            f.write(json.dumps(access_entry, default=str) + "\n")
        return {
            "index": index,
            "username": rec.username,
            "target_host": rec.target_host,
            "password": rec.password,
        }

    @router.post("/runs/{run_id}/credentials/{index}/confirm")
    async def confirm_credential(
        run_id: str,
        index: int,
        auth: str = Depends(_require_auth),
    ) -> dict[str, Any]:
        """Mark a harvested credential ``confirmed`` after validated reuse. Audited.

        The operator asserts (via the UI) that the credential was reused successfully;
        this is the only path to ``confirmed=True`` (``validated=True`` is required by
        ``CredentialStore.confirm_credential``). Passwords are never returned.
        """
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        ws = _exploit_workspace(run_id)
        stores = _find_credential_stores(ws)
        if not stores:
            raise HTTPException(status_code=404, detail="No credentials for this run")
        try:
            from tools.credential_store import CredentialStore

            records: list[Any] = []
            store_paths: list[Path] = []
            for store_path in stores:
                store = CredentialStore(store_path.parent)
                for rec in store.all_credentials():
                    records.append(rec)
                    store_paths.append(store_path)
        except Exception:
            raise HTTPException(status_code=500, detail="Could not read credentials")
        if index < 0 or index >= len(records):
            raise HTTPException(status_code=404, detail="Credential index out of range")
        rec = records[index]
        store = CredentialStore(store_paths[index].parent)
        changed = store.confirm_credential(
            username=rec.username,
            target_host=rec.target_host,
            credential_type=rec.credential_type,
            validated=True,
        )
        access_entry = {
            "run_id": run_id,
            "index": index,
            "username": rec.username,
            "target_host": rec.target_host,
            "action": "confirm",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with _credential_access_log(run_id).open("a", encoding="utf-8") as f:
            f.write(json.dumps(access_entry, default=str) + "\n")
        return {
            "index": index,
            "username": rec.username,
            "target_host": rec.target_host,
            "confirmed": changed,
        }

    @router.get("/runs/{run_id}/loot")
    async def list_loot(run_id: str, auth: str = Depends(_require_auth)) -> dict[str, Any]:
        """List loot captured during the run."""
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        ws = _exploit_workspace(run_id)
        # LootStore is constructed with a workspace dir and reads <dir>/loot.jsonl.
        # post_exploit uses LootStore(workspace / "loot") -> exploit_workspace/loot/loot.jsonl.
        # Fall back to the root-level exploit_workspace/loot.jsonl for older runs.
        candidates = [ws / "loot", ws]
        for cand in candidates:
            loot_path = cand / "loot.jsonl"
            if loot_path.exists():
                try:
                    from tools.credential_store import LootStore

                    store = LootStore(cand)
                    return {"loot": [item.to_json() for item in store._items]}
                except Exception:
                    raise HTTPException(status_code=500, detail="Could not read loot")
        return {"loot": []}

    # ── DELETE run history (D1) ─────────────────────────────────────────────────

    @router.delete("/runs/{run_id}")
    async def delete_run(
        run_id: str,
        purge: bool = Query(False),
        auth: str = Depends(_require_auth),
    ) -> dict[str, Any]:
        """Delete a run from the DB. Refuses active runs. ``?purge=true`` also
        removes the reports/<run_id>/ directory.
        """
        if _ps().get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        if _rm().active_for(run_id) is not None:
            raise APIError("conflict", "Cannot delete an active run.", status_code=409)
        purged = False
        if purge:
            run_dir = _run_dir(run_id)
            if run_dir.exists():
                import shutil

                shutil.rmtree(run_dir, ignore_errors=True)
                purged = True
        _ps().delete_run(run_id)
        return {"run_id": run_id, "deleted": True, "purged": purged}

    return router
