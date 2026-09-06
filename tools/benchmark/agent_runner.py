"""Benchmark mission runner: drives one BreachPilot attack mission per trial.

Thin adapter around :func:`tools.exploit_session.run_exploit_session` (the same
entry the ``--eval`` graded loop uses), plus:

- per-trial token/model-call accounting from the shared ``llm_usage.jsonl``
  telemetry log (the ``run_service`` delta pattern — only records appended
  during this trial are counted);
- structured claimed-success detection via
  :func:`tools.eval_harness.compute_metrics` (the agent's own structured
  outcome counts — used ONLY for claimed-vs-verified contrast, never as
  ground truth);
- sandbox facts extraction from the trial's ``exploit_audit.jsonl`` rows;
- post-run conversion of the audit trail into benchmark events
  (tool_request / tool_result / model_usage) so runs are comparable without
  parsing terminal transcripts.

``run_session`` is injectable so tests run fake missions without a model.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.benchmark.events import BenchmarkEventLogger
from tools.benchmark.models import BenchmarkScenario, SandboxSnapshot, TrialTelemetry
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
from tools.exploit_agent import ExploitPermission, ExploitSettings

__all__ = ["MissionResult", "MissionRunner"]

_MAX_ERRORS = 20


class _MissionEventSink:
    """Bridges run_exploit_agent's live events into the benchmark event log.

    The exploit loop emits ``phase`` / ``assistant`` / ``tool_request`` /
    ``tool_start`` / ``tool_result`` events (structured payloads, never raw
    chain-of-thought) — exactly the operational timeline the benchmark wants.
    """

    def __init__(self, logger: BenchmarkEventLogger, scenario_id: str, trial_id: str) -> None:
        self._logger = logger
        self._scenario_id = scenario_id
        self._trial_id = trial_id

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        tool = str(payload.get("tool", "") or "")
        self._logger.log(
            f"agent_{event_type}",
            dict(payload),
            trial_id=self._trial_id,
            scenario_id=self._scenario_id,
            agent="exploit",
            tool=tool,
        )


@dataclass
class MissionResult:
    """Everything the benchmark needs from one agent mission."""

    final_result: dict[str, Any] = field(default_factory=dict)
    agent_claimed_success: bool = False
    claimed_summary: str = ""
    total_actions: int = 0
    telemetry: TrialTelemetry = field(default_factory=TrialTelemetry)
    sandbox: SandboxSnapshot = field(default_factory=SandboxSnapshot)
    audit_path: str = ""
    workspace: str = ""
    errors: list[str] = field(default_factory=list)
    timed_out: bool = False
    aborted: bool = False
    duration_seconds: float = 0.0


def _extract_sandbox_facts(workspace: Path, required: bool) -> SandboxSnapshot:
    """Parse the trial workspace audit JSONL for sandbox rows (best-effort)."""
    snapshot = SandboxSnapshot(enabled=False, required=required)
    audit_path = workspace / "exploit_audit.jsonl"
    if not audit_path.exists():
        return snapshot
    blocked = 0
    failures = 0
    authorized: list[str] = []
    last_error = ""
    try:
        lines = audit_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return snapshot
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        sandbox = row.get("sandbox")
        if isinstance(sandbox, dict):
            snapshot.enabled = bool(sandbox.get("enabled", snapshot.enabled))
            snapshot.image = str(sandbox.get("image", snapshot.image) or snapshot.image)
            snapshot.container_id = str(sandbox.get("container_id", "") or snapshot.container_id)
            network = sandbox.get("network")
            if isinstance(network, dict):
                snapshot.network_policy_fingerprint = str(network.get("fingerprint", "") or "")
                dests = network.get("authorized")
                if isinstance(dests, list):
                    authorized = [str(d) for d in dests]
            if str(row.get("status", "")) == "failed":
                failures += 1
                detail = row.get("detail") or row.get("command") or ""
                if detail:
                    last_error = str(detail)[:300]
        status = str(row.get("status", "") or "").lower()
        action = str(row.get("action", "") or "")
        if "sandbox" in action and ("blocked" in status or "denied" in status or "error" in status):
            blocked += 1
    snapshot.authorized_destinations = authorized
    snapshot.blocked_events = blocked
    snapshot.failures = failures
    snapshot.last_error = last_error
    return snapshot


class MissionRunner:
    """Runs one agent mission against one scenario target."""

    def __init__(
        self,
        config: dict[str, Any],
        config_path: Path,
        *,
        model_alias: str = "",
        run_session: Any = None,
    ) -> None:
        self.config = config
        self.config_path = Path(config_path)
        self.model_alias = model_alias or str((config.get("models", {}) or {}).get("default_alias", "") or "glm")
        self._run_session = run_session  # None = the real run_exploit_session

    # ------------------------------------------------------------- telemetry

    def _telemetry_delta(self, start_lines: int) -> TrialTelemetry:
        """Aggregate llm_usage.jsonl records appended after ``start_lines``."""
        telemetry = TrialTelemetry()
        try:
            from tools.model_telemetry import usage_log_path, workspace_root_from_sources

            path = usage_log_path(workspace_root_from_sources())
            if not path.exists():
                return telemetry
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:  # noqa: BLE001 -- telemetry is additive metadata
            return telemetry
        new_lines = lines[start_lines:] if start_lines <= len(lines) else lines
        for line in new_lines:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            telemetry.model_calls += 1
            tok = item.get("total_tokens")
            if isinstance(tok, (int, float)):
                telemetry.total_tokens += int(tok)
            ptok = item.get("prompt_tokens")
            if isinstance(ptok, (int, float)):
                telemetry.prompt_tokens += int(ptok)
            ctok = item.get("completion_tokens")
            if isinstance(ctok, (int, float)):
                telemetry.completion_tokens += int(ctok)
        return telemetry

    @staticmethod
    def _llm_usage_line_count() -> int:
        try:
            from tools.model_telemetry import usage_log_path, workspace_root_from_sources

            path = usage_log_path(workspace_root_from_sources())
            if not path.exists():
                return 0
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                return sum(1 for _ in handle)
        except Exception:  # noqa: BLE001
            return 0

    # ------------------------------------------------------------ audit rows

    @staticmethod
    def _audit_counters(final_result: dict[str, Any]) -> tuple[int, int, int]:
        """(tool_calls, tool_errors, sandbox_blocked) from final-result records."""
        records = final_result.get("records")
        if not isinstance(records, list):
            return 0, 0, 0
        calls = errors = blocked = 0
        for row in records:
            if not isinstance(row, dict):
                continue
            action = str(row.get("action", "") or "")
            if not action or action in {"session", "session_start"}:
                continue
            calls += 1
            status = str(row.get("status", "") or "").lower()
            if status in {"failed", "error", "blocked", "denied"} or "sandbox" in action and "error" in status:
                errors += 1
            if "sandbox" in action and ("blocked" in status or "denied" in status):
                blocked += 1
        return calls, errors, blocked

    # ------------------------------------------------------------------ main

    async def run_mission(
        self,
        scenario: BenchmarkScenario,
        *,
        workspace: Path,
        trial_id: str,
        event_logger: BenchmarkEventLogger | None = None,
        goal: Any = None,
        timeout_seconds: int | None = None,
    ) -> MissionResult:
        """Run one attack mission. Never raises: failures land in MissionResult."""
        result = MissionResult()
        timeout = int(timeout_seconds or scenario.timeout_seconds or 1800)
        workspace.mkdir(parents=True, exist_ok=True)
        start_lines = self._llm_usage_line_count()

        settings = ExploitSettings(
            enabled=True,
            mode="attack",
            permission=ExploitPermission.FULL_ACCESS,
            attack_mode=True,
            workspace_root=workspace,
            target_ip=scenario.target_host,
        )
        if goal is None:
            from tools.goal_engine import GoalEngine

            goal = GoalEngine().get(scenario.goal, risk_profile="high_authorized_testing")

        # Persist the mission goal into the assessment store so
        # get_assessment_state never reports GOAL (unset) mid-run.
        try:
            from tools.assessment_state import AssessmentStateStore

            _store = AssessmentStateStore(workspace)
            _state = _store.load(scenario.target_host)
            if not _state.goal:
                _state.goal = str(getattr(goal, "name", "") or scenario.goal or "")
                _store.save(_state)
        except Exception:  # noqa: BLE001 -- snapshot metadata is best-effort
            pass

        model_client = None
        session_error = ""
        try:
            model_client = self._build_model_client()
        except Exception as exc:  # noqa: BLE001 -- model/router failure is a MODEL_FAILED trial
            session_error = f"model client build failed: {exc}"
            result.errors.append(session_error)
            result.telemetry.model_calls = 0
            return result

        event_logger and event_logger.log(
            "mission_start",
            {"goal": getattr(goal, "name", str(goal)), "model_alias": self.model_alias, "timeout_seconds": timeout},
            trial_id=trial_id,
            scenario_id=scenario.scenario_id,
            target=scenario.target_host,
        )
        start = time.monotonic()
        run_session = self._run_session
        if run_session is None:
            from tools.exploit_session import run_exploit_session as run_session  # noqa: PLC0415

        final: dict[str, Any] = {}
        sink = _MissionEventSink(event_logger, scenario.scenario_id, trial_id) if event_logger is not None else None
        try:
            final = await asyncio.wait_for(
                run_session(
                    client=model_client,
                    model=self.model_alias,
                    target_ip=scenario.target_host,
                    mode="attack",
                    goal=goal,
                    exploit_settings=settings,
                    config_path=self.config_path,
                    mcp_transport="stdio",
                    exploit_port=int(self.config.get("mcp", {}).get("http_port", 8001) or 8001),
                    reports_dir=workspace,
                    event_sink=sink,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            result.timed_out = True
            result.errors.append(f"mission timeout after {timeout}s")
        except _EXC_GROUP_CATCH as exc:
            if _is_exception_group(exc):
                _log_nested_exceptions(exc)
            session_error = f"exploit session failed: {exc}"
            result.errors.append(session_error)
        except Exception as exc:  # noqa: BLE001 -- one trial failure never aborts the run
            session_error = f"exploit session failed: {exc}"
            result.errors.append(session_error)

        result.duration_seconds = round(time.monotonic() - start, 3)
        result.final_result = final if isinstance(final, dict) else {}
        result.audit_path = str(result.final_result.get("audit_path", "") or "")
        result.workspace = str(workspace)
        result.total_actions = int(result.final_result.get("total_actions", 0) or 0)

        # Structured claim detection (tool-outcome counters, not LLM prose).
        try:
            from tools.eval_harness import compute_metrics

            metrics = compute_metrics(
                result.final_result,
                run_id=trial_id,
                target=scenario.target_host,
                duration_seconds=result.duration_seconds,
            )
            result.agent_claimed_success = metrics.verdict in {"compromised", "cred_dump"}
            result.claimed_summary = metrics.outcome_summary
        except Exception as exc:  # noqa: BLE001 -- claim detection is best-effort
            result.errors.append(f"claim detection failed: {exc}")

        result.telemetry = self._telemetry_delta(start_lines)
        tool_calls, tool_errors, sandbox_blocked = self._audit_counters(result.final_result)
        result.telemetry.tool_calls = tool_calls
        result.telemetry.tool_errors = tool_errors
        result.telemetry.sandbox_blocked_actions = sandbox_blocked
        result.sandbox = _extract_sandbox_facts(
            workspace, required=bool((self.config.get("benchmark", {}) or {}).get("sandbox_required", True))
        )

        if event_logger is not None:
            self._emit_mission_events(event_logger, scenario, trial_id, result)
        return result

    # -------------------------------------------------------------- plumbing

    def _build_model_client(self) -> Any:
        """Build the model client for the recorded alias (provider-aware)."""
        from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config
        from tools.model_router import build_router

        ollama_host = self.config.get("ollama", {}).get("host", "https://api.ollama.com")
        registry = self.config.get("models", {}).get("registry")
        provider = get_ai_provider(self.config)
        if provider == "chatgpt":
            router = build_router(
                registry,
                host=ollama_host,
                provider="chatgpt",
                chatgpt_config=get_chatgpt_config(self.config),
                config=self.config,
            )
        elif provider == "opencode_go":
            router = build_router(
                registry,
                host=ollama_host,
                provider="opencode_go",
                opencode_go_config=get_opencode_go_config(self.config),
                config=self.config,
            )
        else:
            router = build_router(registry, host=ollama_host)
        try:
            return router.get_client(self.model_alias)
        except KeyError:
            if provider in ("chatgpt", "opencode_go"):
                from tools.model_router import build_model_client_for_provider

                router.register(
                    self.model_alias,
                    build_model_client_for_provider(self.config, self.model_alias, request_timeout_seconds=None),
                )
            else:
                from tools.model_router import _build_model_client

                router.register(
                    self.model_alias,
                    _build_model_client(self.model_alias, host=ollama_host, request_timeout_seconds=None),
                )
            return router.get_client(self.model_alias)

    def _emit_mission_events(
        self,
        logger: BenchmarkEventLogger,
        scenario: BenchmarkScenario,
        trial_id: str,
        result: MissionResult,
    ) -> None:
        """Convert the audit trail into benchmark events (post-run, structured)."""
        for row in result.final_result.get("records", []) or []:
            if not isinstance(row, dict):
                continue
            action = str(row.get("action", "") or "")
            if not action or action in {"session", "session_start"}:
                continue
            status = str(row.get("status", "") or "")
            event_type = "tool_result" if status else "tool_request"
            logger.log(
                event_type,
                {
                    "status": status,
                    "exit_code": row.get("exit_code"),
                    "duration_seconds": row.get("duration_seconds", 0.0),
                    "attempt_id": row.get("attempt_id", ""),
                    "scope_check": row.get("scope_check_result", ""),
                    "approved": bool(row.get("approved", False)),
                    "command": str(row.get("command", "") or "")[:500],
                },
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                agent="exploit",
                tool=action,
                target=str(row.get("target_ip", "") or scenario.target_host),
            )
        if result.telemetry.model_calls or result.telemetry.total_tokens:
            logger.log(
                "model_usage",
                {
                    "model_calls": result.telemetry.model_calls,
                    "total_tokens": result.telemetry.total_tokens,
                    "prompt_tokens": result.telemetry.prompt_tokens,
                    "completion_tokens": result.telemetry.completion_tokens,
                },
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                agent="planner",
            )
        for error in result.errors[:_MAX_ERRORS]:
            logger.log(
                "mission_error",
                {"error": error[:500]},
                trial_id=trial_id,
                scenario_id=scenario.scenario_id,
                level="error",
            )
