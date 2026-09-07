"""AI Target Exploitation Engine — autonomous penetration testing AI.

Usage:
    python main.py                          # WebUI daemon (default; opens a browser)
    python main.py --menu                   # legacy interactive terminal menu
    python main.py --target 10.0.0.50 --mode attack --goal backdoor
    python main.py --target 10.0.0.50 --mode recon --goal initial_access
"""

# BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
from __future__ import annotations

__version__ = "0.49.12"

import argparse
import asyncio
import contextlib
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from tools.api_key_store import DEFAULT_API_KEY_FILE
from tools.attack_ui import get_ui
from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group
from tools.exploit_agent import (
    ExploitSettings,
    run_exploit_agent,
)
from tools.goal_engine import AttackGoal, GoalEngine
from tools.goal_suggester import ReconAssessment
from tools.model_router import build_router
from tools.model_telemetry import usage_log_path, workspace_root_from_sources
from tools.safety_reviewer import SafetyReview
from tools.swarm_bridge import SwarmMcpBridge as SwarmMcpBridge  # noqa: F401 - re-export for tests/back-compat

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

ui = get_ui()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

from tools import config_cli as _config_cli
from tools.config_cli import load_config


def bootstrap_startup_api_keys(args: argparse.Namespace, *, prompt: bool = False) -> None:
    _config_cli.ui = ui
    _config_cli.bootstrap_startup_api_keys(args, prompt=prompt)


from tools.cli_exploit_settings import (
    _compute_swarm_timeout as _compute_swarm_timeout,  # noqa: F401 - re-export for tests/back-compat
)
from tools.cli_exploit_settings import (
    build_cli_exploit_settings as build_cli_exploit_settings,  # noqa: F401 - re-export for tests/back-compat
)
from tools.resume_state import _load_resume_state as _load_resume_state  # noqa: F401 - re-export for tests/back-compat
from tools.skills_cli import (
    _apply_runtime_skill_selection as _apply_runtime_skill_selection,  # noqa: F401 - re-export for tests/back-compat
)
from tools.skills_cli import (
    apply_skills_cli_overrides,
    print_skills_catalog,
)


def _log_nested_exceptions(exc: BaseException, *, prefix: str = "") -> None:
    """Recursively log every exception inside an ExceptionGroup / BaseExceptionGroup."""
    if _is_exception_group(exc):
        group = exc  # type: ignore[union-attr]
        for i, nested in enumerate(group.exceptions):
            _log_nested_exceptions(nested, prefix=f"{prefix}  [{i}] ")
    else:
        try:
            lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
        except Exception as fmt_exc:  # pragma: no cover - defensive
            # Last-ditch fallback: a misbehaving exception's __traceback__ or
            # __str__ can itself raise. Don't let the *logging* of the failure
            # become a second failure.
            ui.error(f"{prefix}<unformattable exception {type(exc).__name__}: {fmt_exc!r}>")
            return
        for line in lines:
            ui.error(f"{prefix}{line.rstrip()}")


# ---------------------------------------------------------------------------
# MCP Exploit Session
# ---------------------------------------------------------------------------

from tools import mcp_session as _mcp_session
from tools.mcp_session import (
    MCP_BOOT_TIMEOUT_SECONDS as _DEFAULT_MCP_BOOT_TIMEOUT_SECONDS,
)
from tools.runtime_context import RuntimeContext

MCP_BOOT_TIMEOUT_SECONDS: float = _DEFAULT_MCP_BOOT_TIMEOUT_SECONDS


def get_runtime_context() -> RuntimeContext:
    """Build this process's runtime context from main.py's locals.

    The single place where CLI runtime dependencies are bundled — passed
    explicitly into ``tools.*`` via ``ctx=`` instead of mutating imported
    module globals per call (which broke concurrent runs sharing the
    process). Tests keep patching ``main.*`` symbols; the context reads
    them lazily here so patched values flow through.
    """
    return RuntimeContext(
        ui=ui,
        config_loader=load_config,
        mcp_boot_timeout_seconds=MCP_BOOT_TIMEOUT_SECONDS,
        open_mcp_session=open_exploit_mcp_session,
        run_exploit_agent_fn=run_exploit_agent,
        build_router_fn=build_router,
    )


@contextlib.asynccontextmanager
async def open_exploit_mcp_session(
    *,
    transport: str,
    config_path: Path,
    target_ip: str,
    exploit_port: int,
    workspace: Path,
    multi_model_enabled: bool | None = None,
    active_model_alias: str = "",
    soft_fail: bool = False,
    original_target: str | None = None,
    resolved_ip: str | None = None,
) -> AsyncIterator[Any]:
    async with _mcp_session.open_exploit_mcp_session(
        transport=transport,
        config_path=config_path,
        target_ip=target_ip,
        exploit_port=exploit_port,
        workspace=workspace,
        multi_model_enabled=multi_model_enabled,
        active_model_alias=active_model_alias,
        soft_fail=soft_fail,
        original_target=original_target,
        resolved_ip=resolved_ip,
        ctx=get_runtime_context(),
    ) as session:
        yield session


async def _elapsed_ticker(
    label: str,
    *,
    interval: float = 15.0,
    heartbeat: "_mcp_session._RunHeartbeat | None" = None,
) -> None:
    await _mcp_session._elapsed_ticker(label, interval=interval, heartbeat=heartbeat, ctx=get_runtime_context())


# ---------------------------------------------------------------------------
# Single-model exploit session (legacy compatible)
# ---------------------------------------------------------------------------

from tools import exploit_session as _exploit_session


async def run_exploit_session(
    *,
    client: Any,
    model: str,
    target_ip: str,
    mode: str,
    goal: AttackGoal,
    exploit_settings: ExploitSettings,
    config_path: Path,
    mcp_transport: str,
    exploit_port: int,
    reports_dir: Path,
    assessment: ReconAssessment | None = None,
    approval_prompt: Callable[[str], str] | None = None,
    approval_provider: Any = None,
    swarm_attach: Callable[..., None] | None = None,
    heartbeat: "_mcp_session._RunHeartbeat | None" = None,
    original_target: str | None = None,
    resolved_ip: str | None = None,
) -> dict[str, Any]:
    return await _exploit_session.run_exploit_session(
        client=client,
        model=model,
        target_ip=target_ip,
        mode=mode,
        goal=goal,
        exploit_settings=exploit_settings,
        config_path=config_path,
        mcp_transport=mcp_transport,
        exploit_port=exploit_port,
        reports_dir=reports_dir,
        assessment=assessment,
        approval_prompt=approval_prompt,
        approval_provider=approval_provider,
        swarm_attach=swarm_attach,
        heartbeat=heartbeat,
        original_target=original_target,
        resolved_ip=resolved_ip,
        ctx=get_runtime_context(),
    )


# ---------------------------------------------------------------------------
# Safety review phase for recon mode
# ---------------------------------------------------------------------------

from tools import safety_review_cli as _safety_review_cli


async def run_safety_review(
    client: Any,
    model: str,
    result: dict[str, Any],
    target_ip: str,
    goal: AttackGoal,
) -> SafetyReview:
    return await _safety_review_cli.run_safety_review(client, model, result, target_ip, goal, ctx=get_runtime_context())


from tools import recon_assessment_cli as _recon_assessment_cli


def _llm_usage_line_count() -> int:
    """Line count of the shared llm_usage.jsonl, or 0 if absent.

    Used to snapshot the offset before a run so end-of-run telemetry reports
    only THIS run's model calls (model_router appends every chat to one
    cumulative file).
    """
    try:
        path = usage_log_path(workspace_root_from_sources())
        if not path.exists():
            return 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def _read_swarm_snapshot(swarm_workspace: Path) -> str:
    """One-line live progress string from swarm_state.json, or "" if unavailable.

    Counts agents by status (complete/running/blocked/failed) so the swarm
    wait loop can show live progress instead of a frozen "elapsed 0s" label.
    This is a tiny inline json.loads reader for the snapshot shape written by
    ``tools/swarm/orchestrator.py:_persist_state``.
    """
    import json as _json

    path = swarm_workspace / "swarm_state.json"
    try:
        if not path.exists():
            return ""
        data = _json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, _json.JSONDecodeError):
        return ""
    agents = data.get("agents", []) if isinstance(data, dict) else []
    counts: dict[str, int] = {}
    for agent in agents:
        if isinstance(agent, dict):
            status = str(agent.get("status", ""))
            counts[status] = counts.get(status, 0) + 1
    parts = []
    for key, label in (("complete", "done"), ("running", "running"), ("blocked", "blocked"), ("failed", "failed")):
        n = counts.get(key, 0)
        if n:
            parts.append(f"{n} {label}")
    return ", ".join(parts)


def _run_telemetry(start_lines: int) -> dict[str, Any] | None:
    """Aggregate llm_usage.jsonl records appended after ``start_lines``.

    Returns per-run totals (calls, total_tokens, avg/max context_usage_pct) by
    parsing only the new lines since the snapshot, so the number is this run's
    model usage rather than the all-history cumulative file. None if no new
    records or the log can't be read.
    """
    import json as _json

    try:
        path = usage_log_path(workspace_root_from_sources())
        if not path.exists():
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    new_lines = lines[start_lines:] if start_lines <= len(lines) else lines
    calls = 0
    total_tokens = 0
    ctx_values: list[float] = []
    for line in new_lines:
        try:
            item = _json.loads(line)
        except _json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        calls += 1
        tok = item.get("total_tokens")
        if isinstance(tok, (int, float)):
            total_tokens += int(tok)
        ctx = item.get("context_usage_pct")
        if isinstance(ctx, (int, float)):
            ctx_values.append(float(ctx))
    if not calls:
        return None
    avg_ctx = (sum(ctx_values) / len(ctx_values)) if ctx_values else None
    max_ctx = max(ctx_values) if ctx_values else None
    return {
        "calls": calls,
        "total_tokens": total_tokens,
        "avg_ctx": avg_ctx,
        "max_ctx": max_ctx,
    }


async def run_recon_assessment(
    *,
    session: Any,
    target_ip: str,
    reports_dir: Path,
) -> ReconAssessment:
    return await _recon_assessment_cli.run_recon_assessment(
        session=session,
        target_ip=target_ip,
        reports_dir=reports_dir,
        ctx=get_runtime_context(),
    )


def _extract_tool_text(raw: Any) -> str:
    return _recon_assessment_cli._extract_tool_text(raw)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "BreachPilot — autonomous penetration testing AI. Run with no arguments "
            "to start the WebUI daemon (http://127.0.0.1:8765); use --menu for the "
            "legacy interactive terminal menu."
        ),
        epilog=(
            "examples:\n"
            "  python main.py                                          WebUI daemon + browser (default)\n"
            "  python main.py --menu                                   legacy interactive terminal menu\n"
            "  python main.py --target 10.0.0.50 --mode attack --goal backdoor\n"
            "  python main.py --target 10.0.0.50 --mode recon --goal initial_access\n"
            "  python main.py --target 10.0.0.50 --ctf --ctf-flag-path /root/flag.txt\n"
            "  python main.py --doctor                                  environment self-check\n"
            "  python main.py --self-test                                safe localhost smoke test\n"
            "  python main.py --web                                     WebUI + API daemon\n"
            "  python main.py --resume <run_id>                          resume a prior run\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"BreachPilot {__version__}")

    core = parser.add_argument_group("targeting")
    core.add_argument("--target", default="", help="Target IP address or domain to attack or recon")
    core.add_argument(
        "--mode",
        choices=("recon", "attack", "fast"),
        default="",
        help="recon = gather intel, attack = full exploitation, fast = parallel recon preset then attack",
    )
    core.add_argument(
        "--goal", default="", help="Preset goal name (e.g. backdoor, initial_access, privilege_escalation)"
    )
    core.add_argument("--custom-goal", default="", help="Custom goal description")
    core.add_argument("--config", type=Path, default=Path("config.yaml"), help="Config file (default: config.yaml)")
    core.add_argument(
        "--model", default=None, help="Override default model alias (glm/kimi/deepseek/deepseek_flash/minimax)"
    )
    core.add_argument(
        "--model-strategy",
        choices=("default", "round-robin", "random", "specific"),
        default="default",
        help="How to pick model across targets",
    )
    core.add_argument(
        "--mcp-transport",
        choices=("stdio", "http"),
        default=None,
        help="MCP transport (ignored on the run path: always forced to http so the target-IP lock reaches the server)",
    )
    core.add_argument("--http-port", type=int, default=None, help="MCP HTTP port")
    core.add_argument(
        "--reports-dir", type=Path, default=Path("reports"), help="Where run artifacts are written (default: reports/)"
    )

    keys = parser.add_argument_group("api keys")
    keys.add_argument(
        "--setup-api-keys", action="store_true", help="Prompt for provider API keys and save them to secr.json"
    )
    keys.add_argument(
        "--api-key-file", type=Path, default=DEFAULT_API_KEY_FILE, help="Local JSON file for saved provider API keys"
    )
    keys.add_argument("--no-api-key-prompt", action="store_true", help="Skip the interactive startup API-key prompt")

    out = parser.add_argument_group("output")
    out.add_argument("--plain", action="store_true", help="Disable color output")
    out.add_argument("--menu", action="store_true", help="Force interactive menu mode even with other args")
    out.add_argument("--json", action="store_true", help="Emit machine-readable JSON to stdout where supported")
    out.add_argument("--quiet", action="store_true", help="Reduce output to warnings/errors only")
    out.add_argument("--debug", action="store_true", help="Enable verbose debug output")

    swarm = parser.add_argument_group("swarm & reasoning")
    swarm.add_argument(
        "--swarm",
        action="store_true",
        help="Enable multi-agent swarm mode: six specialists decompose a single target "
        "(parallel recon + vuln research, critic pre-check, reflection). Without it, "
        "attack mode runs the persistent autonomous campaign queue (resume + checkpoints). "
        "Combine both on high-value targets. See docs/swarm.md.",
    )
    swarm.add_argument(
        "--parallel-swarm",
        action="store_true",
        help="Enable parallel sub-agents (route_parallel + spawn_subagent MCP tool). "
        "Off by default; flips swarm.parallel_enabled to true. Recon-first: "
        "recon + vuln-research parallelize; exploit/post_exploit stay sequential "
        "unless swarm.exploit_parallel is also true.",
    )
    swarm.add_argument("--critic", action="store_true", help="Enable critic agent pre-approval (requires --swarm)")
    swarm.add_argument("--reflection", action="store_true", help="Enable reflection agent (requires --swarm)")
    swarm.add_argument(
        "--adaptive-exploits", action="store_true", help="Enable adaptive exploit generation with mutation"
    )
    swarm.add_argument(
        "--long-session",
        dest="long_session",
        action="store_true",
        help="Raise context window (num_ctx), LLM call timeout, round/command/duration budgets, "
        "and the swarm cap for a multi-hour attack run; checkpoints compacted messages for crash-safe resume",
    )
    swarm.add_argument(
        "--multi-model-consult",
        dest="multi_model_consult",
        action="store_true",
        default=None,
        help="Allow the agent to ask configured peer models for advisory help",
    )
    swarm.add_argument(
        "--no-multi-model-consult",
        dest="multi_model_consult",
        action="store_false",
        help="Disable peer-model consultation for this run",
    )
    swarm.add_argument(
        "--observer-mode",
        choices=("heuristic", "llm", "hybrid"),
        default="hybrid",
        help="Observer mode for fact extraction",
    )
    swarm.add_argument(
        "--recon-first",
        action="store_true",
        default=None,
        help="Force recon-first mode: scan target, suggest rated goals, then ask for goal selection",
    )
    swarm.add_argument(
        "--no-recon-first",
        action="store_false",
        dest="recon_first",
        help="Skip recon-first mode; go directly to goal selection",
    )
    swarm.add_argument(
        "--ultrathink",
        action="store_true",
        help="Enable deep reasoning mode: verbose chain-of-thought and frequent reflection",
    )

    ops = parser.add_argument_group("operational")
    ops.add_argument("--doctor", action="store_true", help="Run a self-check (Python, nmap, Ollama, config) and exit")
    ops.add_argument("--demo", action="store_true", help="Run against a local sandbox target (DVWA-style)")
    ops.add_argument("--resume", type=str, default="", help="Resume a prior run by run_id or session_id")
    ops.add_argument("--yes", action="store_true", help="Skip the ready-to-begin confirmation gate (use with caution)")
    ops.add_argument(
        "--self-test", action="store_true", help="Run a safe localhost smoke test against 127.0.0.1 and exit"
    )
    evalgrp = parser.add_argument_group("eval & regression")
    evalgrp.add_argument(
        "--eval",
        nargs="*",
        default=None,
        metavar="TARGET",
        help="Run the graded eval suite (oracle v2) against eval_targets/ — no target ids = all "
        "targets, or pass specific ids (e.g. --eval dvwa juice_shop). With --target <ip>, runs the "
        "legacy single-target benchmark instead and writes reports/eval/<run_id>/",
    )
    evalgrp.add_argument(
        "--eval-list",
        dest="eval_list",
        action="store_true",
        help="List graded-eval oracle targets (id + flag count) and exit",
    )
    evalgrp.add_argument(
        "--save-baseline",
        dest="save_baseline",
        action="store_true",
        help="With --eval: persist the graded report as the regression baseline (eval.baseline_path)",
    )
    evalgrp.add_argument(
        "--check-regression",
        dest="check_regression",
        action="store_true",
        help="With --eval/--benchmark: exit 1 on hard regressions vs the saved baseline",
    )
    benchgrp = parser.add_argument_group("benchmark suite")
    benchgrp.add_argument(
        "--benchmark",
        nargs="*",
        default=None,
        metavar="SUITE",
        help="Run a benchmark suite (e.g. --benchmark xben). With --trials N runs repeated trials; "
        "filters via --scenario/--tag. Use --save-baseline/--check-regression for baseline workflows.",
    )
    benchgrp.add_argument(
        "--benchmark-list",
        dest="benchmark_list",
        action="store_true",
        help="List registered benchmark suites (id, scenario count, tags) and exit",
    )
    benchgrp.add_argument(
        "--scenario",
        action="append",
        default=None,
        metavar="ID",
        help="With --benchmark: restrict to specific scenario ids (repeatable)",
    )
    benchgrp.add_argument(
        "--tag",
        action="append",
        default=None,
        metavar="TAG",
        help="With --benchmark: restrict to scenarios carrying a tag (repeatable)",
    )
    benchgrp.add_argument(
        "--trials",
        type=int,
        default=None,
        metavar="N",
        help="With --benchmark: repeated trials per scenario (default benchmark.trials, 1-20)",
    )

    ctf = parser.add_argument_group("ctf autopilot")
    ctf.add_argument(
        "--ctf",
        action="store_true",
        help="CTF autopilot: run against --target and stop when the goal is heuristically met "
        "(flag marker / uid=0 / port-marker). Target-locked via the normal allowlist.",
    )
    ctf.add_argument(
        "--ctf-flag-path",
        dest="ctf_flag_path",
        default="",
        help="CTF goal: flag file path on the target (e.g. /root/flag.txt)",
    )
    ctf.add_argument(
        "--ctf-root-shell",
        dest="ctf_root_shell",
        action="store_true",
        default=False,
        help="CTF goal: treat uid=0 in any output as goal-met (default False)",
    )
    ctf.add_argument(
        "--ctf-port", dest="ctf_port", type=int, default=0, help="CTF goal: port to probe for the known-string marker"
    )
    ctf.add_argument(
        "--ctf-marker", dest="ctf_marker", default="", help="CTF goal: known-string marker expected from --ctf-port"
    )

    skills = parser.add_argument_group("runtime skills")
    skills.add_argument(
        "--skills",
        choices=("on", "off", "hints", "lookup"),
        default=None,
        help="Override runtime-skills behavior for this run: on=startup context injected, "
        "hints=hints only (default), lookup=MCP tools only, off=skills disabled",
    )
    skills.add_argument(
        "--skills-list", action="store_true", help="Print the runtime-skill catalog and exit (read-only)"
    )
    skills.add_argument(
        "--skills-include",
        action="append",
        default=None,
        metavar="NAME",
        help="Force-include a skill by name for this run (sticky across re-selection). Repeatable.",
    )
    skills.add_argument(
        "--skills-exclude",
        action="append",
        default=None,
        metavar="NAME",
        help="Exclude a skill by name for this run. Repeatable.",
    )
    skills.add_argument(
        "--no-skills-reselect", action="store_true", help="Disable mid-run skill re-selection for this run"
    )

    plugins = parser.add_argument_group("plugins")
    plugins.add_argument(
        "--list-plugins",
        dest="list_plugins",
        action="store_true",
        help="Print discovered plugins (name/version/capabilities/loaded) and exit",
    )

    webui = parser.add_argument_group("webui")
    webui.add_argument(
        "--demon",
        "--daemon",
        dest="daemon",
        action="store_true",
        help="Start the local WebUI API server instead of the terminal menu",
    )
    webui.add_argument(
        "--web",
        dest="web",
        action="store_true",
        help="Build the WebUI if needed, serve it from the daemon at /, and open a browser",
    )
    webui.add_argument("--api-host", default=None, help="API daemon bind host (loopback only; default 127.0.0.1)")
    webui.add_argument("--api-port", type=int, default=None, help="API daemon port (default 8765)")
    parsed = parser.parse_args(argv)
    return parsed


def _ensure_webui_build(ui: Any) -> int:
    """Build webui/dist/ if missing. Returns 0 on success, non-zero on failure."""
    webui_dir = Path(__file__).resolve().parent / "webui"
    dist_index = webui_dir / "dist" / "index.html"
    if dist_index.exists():
        return 0
    npm_cmd = shutil.which("npm.cmd") or shutil.which("npm")
    node_cmd = shutil.which("node") or shutil.which("nodejs")
    if not npm_cmd or not node_cmd:
        ui.error("Node/npm not found on PATH. Install Node.js, or build the WebUI manually:")
        ui.error(f"  cd {webui_dir} && npm install && npm run build")
        return 1
    ui.status("Building the WebUI (first run only)...")
    for step in (("install", [npm_cmd, "install", "--no-audit", "--no-fund"]), ("build", [npm_cmd, "run", "build"])):
        label, argv = step
        ui.status(f"  npm {label}...")
        try:
            result = subprocess.run(argv, cwd=str(webui_dir), capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            ui.error(f"npm {label} timed out.")
            return 1
        except OSError as exc:
            ui.error(f"npm {label} failed: {exc}")
            return 1
        if result.returncode != 0:
            ui.error(f"npm {label} exited {result.returncode}.")
            stderr_tail = (result.stderr or "")[-1500:]
            if stderr_tail:
                ui.error(stderr_tail)
            return 1
    if not dist_index.exists():
        ui.error(f"Build finished but {dist_index} was not produced.")
        return 1
    ui.status("WebUI build complete.")
    return 0


def _install_bun(ui: Any) -> bool:
    """Install the pinned bun release (ChatGPT provider). Returns True on success.

    Thin back-compat wrapper around :mod:`tools.chatgpt_bootstrap` — see
    that module for the pinned ``BUN_VERSION`` and the safety rationale (no
    remote-script piping, pinned npm package only, actionable manual
    message when automatic install is unavailable).
    """
    from tools.chatgpt_bootstrap import install_bun

    return install_bun(ui)


def _ensure_chatgpt_runtime(args: argparse.Namespace) -> int:
    """Ensure the ChatGPT (openai-oauth) provider is runnable.

    Thin back-compat wrapper around
    :func:`tools.chatgpt_bootstrap.ensure_chatgpt_runtime` — see that module
    for the pinned ``BUN_VERSION`` / ``OPENAI_OAUTH_*`` revisions and the
    safety rationale (no remote-script piping, HEAD verified before anything
    runs, ``--frozen-lockfile``, no ``shell=True``).

    Returns 0 on success or when the ChatGPT provider is not active; non-zero
    only when a required step fails AND the operator is about to use the
    ChatGPT provider.
    """
    from tools.chatgpt_bootstrap import ensure_chatgpt_runtime
    from tools.config_manager import get_ai_provider, get_chatgpt_config

    try:
        config = load_config(args.config)
    except Exception:
        config = {}
    if get_ai_provider(config) != "chatgpt":
        return 0

    chatgpt_cfg = get_chatgpt_config(config)
    return ensure_chatgpt_runtime(
        provider="chatgpt",
        local_repo=str(chatgpt_cfg.get("local_repo") or "./oauth"),
        ui=ui,
    )


def _open_browser_when_ready(host: str, port: int, ui: Any) -> None:
    """Poll the health endpoint, then open the browser. Daemon thread."""
    import urllib.request

    base = f"http://{host}:{port}/" if host != "::1" else f"http://[::1]:{port}/"
    health_url = f"{base}api/v1/health"
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(health_url, timeout=2) as resp:  # noqa: S310 -- loopback only
                if resp.status == 200:
                    break
        except OSError:
            time.sleep(0.5)
    else:
        ui.warning("Could not confirm the API was ready; open the browser manually.")
        return
    try:
        webbrowser.open(base)
    except Exception as exc:  # noqa: BLE001 -- headless/text browsers
        ui.warning(f"Could not open the browser automatically: {exc}")
        ui.status(f"  Open {base} manually.")


def _api_daemon_ready(host: str, port: int) -> bool:
    """Return whether a BreachPilot API daemon already owns this endpoint."""
    import urllib.request

    base = f"http://{host}:{port}/" if host != "::1" else f"http://[{host}]:{port}/"
    try:
        with urllib.request.urlopen(f"{base}api/v1/health", timeout=1) as response:  # noqa: S310 -- loopback only
            return response.status == 200
    except OSError:
        return False


def _find_port_listener_pid(port: int) -> int | None:
    """Best-effort PID of the process listening on TCP ``port`` (None if unknown)."""
    if sys.platform == "win32":
        try:
            proc = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return None
        for line in proc.stdout.splitlines():
            # TCP    127.0.0.1:8765    0.0.0.0:0    LISTENING    <pid>
            fields = line.split()
            if len(fields) >= 5 and fields[3].upper() == "LISTENING" and fields[1].endswith(f":{port}"):
                try:
                    return int(fields[4])
                except ValueError:
                    return None
        return None
    for cmd in (["lsof", "-nP", f"-tiTCP:{port}", "-sTCP:LISTEN"], ["ss", "-ltnp"]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode != 0:
            continue
        for line in proc.stdout.splitlines():
            if cmd[0] == "lsof":
                try:
                    return int(line.strip().split()[0])
                except (IndexError, ValueError):
                    continue
            fields = line.split()
            if len(fields) >= 4 and fields[0] == "LISTEN" and fields[3].endswith(f":{port}"):
                match = re.search(r"pid=(\d+)", line)
                if match:
                    return int(match.group(1))
    return None


def _stop_running_daemon(host: str, port: int) -> bool:
    """Terminate the process owning ``port``; True once the endpoint stops answering."""
    pid = _find_port_listener_pid(port)
    if pid is None:
        return False
    cmd = ["taskkill", "/F", "/PID", str(pid)] if sys.platform == "win32" else ["kill", str(pid)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode != 0:
        return False
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        if not _api_daemon_ready(host, port):
            return True
        time.sleep(0.3)
    return False


def _offer_daemon_kill() -> bool:
    """TTY-only prompt for the already-running-daemon case. Returns True on K."""
    try:
        if not sys.stdin.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    try:
        return input("  Press K to kill it and start fresh, or Enter to keep it: ").strip().lower() == "k"
    except (EOFError, KeyboardInterrupt):
        return False


def _copy_to_clipboard(text: str) -> bool:
    """Best-effort copy ``text`` to the system clipboard. Returns True on success.

    Tries, in order: 1) ``pyperclip`` if installed, 2) OS-native commands
    (``clip``/PowerShell on Windows, ``pbcopy`` on macOS, ``wl-copy``/``xclip``/``xsel``
    on Linux), 3) ``tkinter`` as a stdlib fallback. Never raises — a failure is
    just ``False`` so the daemon can still print the token for manual copy.
    """
    clipped = text.strip()
    if not clipped:
        return False
    # 1) Optional pyperclip dep (no hard requirement).
    try:
        import pyperclip  # type: ignore

        pyperclip.copy(clipped)
        return True
    except Exception:
        pass
    # 2) Native OS commands (lightweight, no window).
    try:
        if sys.platform == "win32":
            # clip.exe is built into Windows; PowerShell Set-Clipboard is the fallback
            # that also works when clip is absent or stdin handling differs.
            if shutil.which("clip"):
                try:
                    proc = subprocess.run(
                        ["clip"], input=clipped, text=True, timeout=5, capture_output=True, check=False
                    )
                    if proc.returncode == 0:
                        return True
                except Exception:
                    pass
            if shutil.which("powershell") or shutil.which("pwsh"):
                pwsh = shutil.which("pwsh") or shutil.which("powershell")
                try:
                    # Feed via stdin to avoid quoting issues: $input | Set-Clipboard
                    proc = subprocess.run(
                        [pwsh, "-NoProfile", "-Command", "$input | Set-Clipboard"],
                        input=clipped,
                        text=True,
                        timeout=5,
                        capture_output=True,
                        check=False,
                    )
                    if proc.returncode == 0:
                        return True
                except Exception:
                    pass
        elif sys.platform == "darwin":
            if shutil.which("pbcopy"):
                try:
                    proc = subprocess.run(
                        ["pbcopy"], input=clipped, text=True, timeout=5, capture_output=True, check=False
                    )
                    return proc.returncode == 0
                except Exception:
                    pass
        else:
            for cmd in (
                ["wl-copy"],
                ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"],
            ):
                if shutil.which(cmd[0]):
                    try:
                        proc = subprocess.run(
                            cmd, input=clipped, text=True, timeout=5, capture_output=True, check=False
                        )
                        if proc.returncode == 0:
                            return True
                    except Exception:
                        continue
    except Exception:
        pass
    # 3) tkinter fallback (stdlib, but may need a display).
    try:
        import tkinter  # type: ignore

        root = tkinter.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(clipped)
        root.update()
        root.destroy()
        return True
    except Exception:
        pass
    return False


def _auto_update_models(config: dict[str, Any], config_path: str) -> None:
    """Best-effort ``models.registry`` sync against the Ollama API (boot hook).

    Gated by ``models.auto_update`` (default true, ollama provider only); never
    raises. Bumps each registry alias to the newest same-family version the
    Ollama host lists (``glm-5.2:cloud`` -> ``glm-5.3:cloud``) — no pulls, the
    registry stores ids. See ``tools/ollama_models.py``.
    """
    try:
        from tools.ollama_models import auto_refresh_on_startup

        result = auto_refresh_on_startup(config, config_path=config_path)
    except Exception as exc:  # noqa: BLE001 -- advisory only, never blocks the daemon
        ui.warning(f"Model auto-update skipped: {type(exc).__name__}: {exc}")
        return
    if not result:
        return
    updates = result.get("updates") or {}
    if updates:
        ui.status("Model auto-update: " + ", ".join(f"{a}: {u['old']} -> {u['new']}" for a, u in updates.items()))
    else:
        ui.status(
            f"Model registry current ({result.get('available_count', 0)} models on {result.get('host', 'Ollama')})."
        )


def _run_daemon(args: argparse.Namespace) -> int:
    """Start the local WebUI API server (``--demon`` / ``--daemon`` / ``--web``)."""
    config = load_config(args.config)
    api_cfg = config.setdefault("api", {})
    host = args.api_host or api_cfg.get("host", "127.0.0.1")
    port = int(args.api_port or api_cfg.get("port", 8765))
    shutdown_timeout = int(api_cfg.get("shutdown_timeout_seconds", 15))
    # v1: loopback-only. Refuse any non-loopback bind (no public override).
    if host not in ("127.0.0.1", "localhost", "::1"):
        ui.error(
            f"--api-host must be loopback (127.0.0.1/localhost/::1); got {host!r}. Public binds are not supported in v1."
        )
        return 2
    status_host = f"[{host}]" if host == "::1" else host
    web_mode = getattr(args, "web", False)
    if _api_daemon_ready(host, port):
        ui.status(f"WebUI API daemon is already running on http://{status_host}:{port}")
        restarted = False
        if _offer_daemon_kill():
            if _stop_running_daemon(host, port):
                ui.status("Stopped the previous WebUI API daemon; starting a fresh one.")
                restarted = True
            else:
                ui.error("Could not stop the running daemon; keeping it.")
        if not restarted:
            if web_mode:
                threading.Thread(target=_open_browser_when_ready, args=(host, port, ui), daemon=True).start()
            return 0
    try:
        import uvicorn  # noqa: F401 -- import gate
    except ImportError:
        ui.error("uvicorn is not installed. Run: python -m pip install -r requirements.txt")
        return 1
    try:
        from app import create_app
    except ImportError as exc:
        ui.error(f"Could not import the ASGI app factory (app.py): {exc}")
        return 1

    if web_mode:
        build_rc = _ensure_webui_build(ui)
        if build_rc != 0:
            return build_rc
        # In-memory override only; never persisted to config.yaml.
        api_cfg["serve_webui"] = True

    # Auto-update the model registry against the live Ollama API before the
    # app factory snapshots the config (models.auto_update, default true).
    _auto_update_models(config, args.config)

    ui.banner()
    base = f"http://{status_host}:{port}"
    print(f"  {ui._c('green')}*{ui._c('reset')} API ready  {ui._c('blue')}{base}{ui._c('reset')}")
    print(f"    {ui._c('gray')}{'docs':<7}{ui._c('reset')} {ui._c('blue')}{base}/docs{ui._c('reset')}")
    print(f"    {ui._c('gray')}{'openapi':<7}{ui._c('reset')} {ui._c('blue')}{base}/openapi.json{ui._c('reset')}")
    if web_mode:
        print(f"    {ui._c('gray')}{'webui':<7}{ui._c('reset')} {ui._c('blue')}{base}/{ui._c('reset')}")
    print(f"  {ui._c('gray')}{'-' * 46}{ui._c('reset')}")
    # ponytail: print the bearer token here (create_app re-reads the same file;
    # one extra read beats threading the token back through the factory).
    from tools.api.auth import load_or_create_token

    token = load_or_create_token(
        api_cfg.get("token_file", ".webui_secret_key"),
        env_override=os.environ.get("BREACHPILOT_API_TOKEN", ""),
    )
    # Single prompt — reveal token (and open browser in --web mode) so the
    # user isn't hit with two sequential "press Enter" pauses.
    if web_mode:
        print(f"  {ui._c('gray')}Press Enter to reveal API token and open browser...{ui._c('reset')}")
    else:
        print(f"  {ui._c('gray')}Press Enter to reveal API token...{ui._c('reset')}")
    try:
        input(f"  {ui._c('gray')}>{ui._c('reset')} ")
    except KeyboardInterrupt:
        return 130
    except EOFError:
        pass
    print(f"  {ui._c('gray')}token{ui._c('reset')}   {token}")
    if _copy_to_clipboard(token):
        print(f"  {ui._c('green')}copied to clipboard{ui._c('reset')} {ui._c('gray')}(Ctrl+V to paste){ui._c('reset')}")
    app = create_app(config_path=args.config, config=config)

    if web_mode:
        browser_thread = threading.Thread(
            target=_open_browser_when_ready,
            args=(host, port, ui),
            daemon=True,
        )
        browser_thread.start()

    print(f"  {ui._c('gray')}{'-' * 46}{ui._c('reset')}")
    print(f"  {ui._c('gray')}Logs and agent output will stream here - leave this running.{ui._c('reset')}")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning" if not getattr(args, "debug", False) else "info",
        access_log=bool(getattr(args, "debug", False)),
        timeout_graceful_shutdown=shutdown_timeout,
    )
    return 0


async def async_main(args: argparse.Namespace) -> int:
    """CLI adapter over ``AssessmentService``.

    Builds a ``RunRequest`` from CLI args, calls ``AssessmentService.prepare``
    to get a preview, renders it via ``AttackUi``, asks the ready-to-begin
    confirmation via ``TerminalDecisionProvider``, then calls
    ``AssessmentService.execute`` with terminal event/approval adapters.

    The ``Callables`` bundle passes ``main``'s module-level symbols
    (``open_exploit_mcp_session``, ``run_exploit_session``, ``build_router``,
    ``GoalEngine``) into the service so existing tests that monkeypatch
    ``main_mod.*`` continue to drive the service through the patched symbols.
    """
    from tools.run_service import (
        AssessmentService,
        Callables,
        CancellationToken,
        RunRequest,
        TerminalDecisionProvider,
        TerminalEventSink,
    )

    # --debug / --ultrathink signals.
    if getattr(args, "debug", False):
        os.environ["AI_NMAP_DEBUG"] = "1"
        ui.info("Debug mode enabled (verbose logging; tracebacks will be printed to stderr on error).")
    if getattr(args, "ultrathink", False):
        ui.info("ULTRATHINK mode enabled: verbose chain-of-thought and frequent reflection.")

    config_path = args.config
    config = load_config(config_path)
    config = apply_skills_cli_overrides(config, args)
    # Load plugins before the MCP exploit server is created.
    try:
        from tools.plugins import load_plugins

        load_plugins(config)
    except Exception as exc:  # noqa: BLE001 -- plugin load must not block boot
        ui.info(f"Plugin load skipped: {type(exc).__name__}: {exc}")
        if getattr(args, "debug", False):
            ui.info(traceback.format_exc().strip())

    multi_model_cfg = config.get("multi_model", {}) or {}
    if getattr(args, "multi_model_consult", None) is None:
        args.multi_model_consult = bool(multi_model_cfg.get("enabled", False))

    ui.banner()
    ui.info(f"Config: {config_path} ({'found' if config_path.exists() else 'not found; using defaults'})")

    # Interactive session: ask advanced settings.
    interactive_session = not getattr(args, "target", "").strip()
    if interactive_session:
        try:
            args = await ui.ask_advanced_settings(None, args)
            ui.plain = bool(
                getattr(args, "plain", False) or getattr(args, "quiet", False) or getattr(args, "json", False)
            )
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1

    # Build the RunRequest from args. ponytail: default recon — attack needs explicit --mode attack.
    request = RunRequest(
        target=args.target.strip(),
        mode=getattr(args, "mode", "").strip().lower() or "recon",
        goal_name=getattr(args, "goal", "").strip().lower(),
        custom_goal=getattr(args, "custom_goal", "").strip(),
        recon_first=getattr(args, "recon_first", None),
        model_alias=getattr(args, "model", None) or "",
        config_path=config_path,
        reports_dir=getattr(args, "reports_dir", Path("reports")),
        swarm=bool(getattr(args, "swarm", False)),
        parallel_swarm=bool(getattr(args, "parallel_swarm", False)),
        critic=bool(getattr(args, "critic", False)),
        reflection=bool(getattr(args, "reflection", False)),
        adaptive_exploits=bool(getattr(args, "adaptive_exploits", False)),
        long_session=bool(getattr(args, "long_session", False)),
        multi_model_consult=getattr(args, "multi_model_consult", None),
        observer_mode=getattr(args, "observer_mode", "hybrid"),
        ultrathink=bool(getattr(args, "ultrathink", False)),
        debug=bool(getattr(args, "debug", False)),
        plain=bool(getattr(args, "plain", False)),
        json_output=bool(getattr(args, "json", False)),
        yes=bool(getattr(args, "yes", False)),
        skills_mode=getattr(args, "skills", None),
        skills_include=list(getattr(args, "skills_include", None) or []),
        skills_exclude=list(getattr(args, "skills_exclude", None) or []),
        skills_no_reselect=bool(getattr(args, "no_skills_reselect", False)),
        resume_source=(getattr(args, "resume", "") or "").strip(),
        interactive=interactive_session,
    )

    # If no target, ask interactively (preserves the existing menu flow).
    if not request.target:
        try:
            request.target = ui.ask_target()
        except (EOFError, KeyboardInterrupt):
            ui.error("Aborted.")
            return 1
    if not request.target:
        ui.error("No target provided.")
        return 1

    # Construct the service with CLI-patchable callables.
    callables = Callables(
        build_router=build_router,
        open_session=open_exploit_mcp_session,
        run_session=run_exploit_session,
        goal_engine_cls=GoalEngine,
        run_recon_assessment=run_recon_assessment,
        run_safety_review=run_safety_review,
    )
    service = AssessmentService(config=config, callables=callables)

    # Prepare (resolve target/goal/settings without I/O side effects).
    try:
        preview = await service.prepare(request)
    except ValueError as exc:
        ui.error(str(exc))
        return 1

    # Interactive target entered via menu: persist to allowlist.
    if interactive_session:
        try:
            from tools import config_cli as _config_cli

            added = _config_cli.add_target_to_allowlist(config_path, preview.original_target)
            if added:
                ui.status(f"Saved {preview.original_target} to {config_path} exploit.allowed_targets.")
        except (OSError, ValueError) as exc:
            ui.error(f"Could not save {preview.original_target} to the config allowlist: {exc}")
            return 1

    # Warn on public targets.
    _privacy_ip = preview.resolved_ip or preview.target_ip
    try:
        if not ipaddress.ip_address(_privacy_ip).is_private:
            ui.status("WARNING: Target is a PUBLIC IP. Ensure you OWN this infrastructure.")
    except ValueError:
        pass
    if preview.resolved_domain:
        ui.status(f"Domain target {preview.resolved_domain} resolved to {preview.resolved_ip}.")

    # Render run summary.
    if not request.resume_source:
        ui.info(f"Reports root: {args.reports_dir}")
        ui.info(f"This run will write to: {preview.reports_dir}  (run_id={preview.run_id})")
    ui.status(f"Target: {preview.target_ip}")
    ui.status(f"Mode: {preview.mode}")
    ui.status(f"Goal: {preview.goal_name}")
    ui.divider()
    ui.status("Run summary:")
    ui.status(f"  Config:      {config_path}")
    ui.status(f"  Reports root:{args.reports_dir}")
    ui.status(f"  Run ID:      {preview.run_id}")
    ui.status(f"  Target:      {preview.target_ip}")
    ui.status(f"  Mode:        {preview.mode}")
    ui.status(f"  Goal:        {preview.goal_name}")
    ui.status(f"  Model:       {preview.model_label}")
    ui.status(f"  Transport:   {preview.transport_summary}")
    ui.status(f"  Reports:     {preview.reports_dir}")
    if preview.destructive:
        ui.status(
            f"  {ui._c('red')}[!] DESTRUCTIVE: permission=full_access, attack_mode={preview.attack_mode}{ui._c('reset')}"
        )
    ui.status(f"  Permission:  {preview.permission}")
    ui.status(f"  Attack mode: {preview.attack_mode}")
    ui.status(f"  Swarm:       {preview.swarm}")
    if preview.swarm or preview.parallel_swarm:
        ui.status(f"  Parallel:   {preview.parallel_swarm}")
    ui.status(f"  Peer models: {preview.multi_model}")
    try:
        ui.status(
            f"  Budget:      {preview.budgets.get('commands', 'n/a')} commands, "
            f"{preview.budgets.get('rounds', 'n/a')} rounds, "
            f"{preview.budgets.get('duration_minutes', 'n/a')} min."
        )
    except Exception:
        pass
    ui.skills([f"{a['name']} - {a['reason']}" for a in preview.skill_activations])
    if preview.skill_errors:
        ui.warning(f"Skill registry loaded with {len(preview.skill_errors)} warning(s):")
        for err in preview.skill_errors:
            ui.warning(f"  - {err}")
    ui.divider()

    # Ready-to-begin gate. ponytail: --yes never skips typed ALLOW on destructive runs.
    if (not getattr(args, "yes", False)) or preview.destructive:
        decision_provider = TerminalDecisionProvider(ui)
        from tools.run_service.models import Decision, DecisionKind

        confirm_decision = Decision(
            id="",
            run_id=preview.run_id,
            kind=DecisionKind.START_CONFIRM,
            prompt_text="Proceed? [Y/n]",
            required_text=preview.required_confirmation_text,
        )
        answer = await decision_provider.request(confirm_decision)
        if preview.destructive:
            if answer != preview.required_confirmation_text:
                ui.info("Aborted by user.")
                return 0
        else:
            if not answer:
                ui.info("Aborted by user.")
                return 0

    # Execute.
    cancellation = CancellationToken()
    event_sink = TerminalEventSink()
    try:
        result = await service.execute(
            request,
            preview,
            decision_provider=TerminalDecisionProvider(ui),
            event_sink=event_sink,
            cancellation=cancellation,
            config=config,
        )
    except RuntimeError as exc:
        ui.error(f"Exploitation session failed: {exc}")
        return 1
    except _EXC_GROUP_CATCH as exc:
        log_path = preview.reports_dir / "session_error.log"
        try:
            log_path.write_text(
                "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                encoding="utf-8",
            )
        except OSError:
            pass
        ui.error(f"Exploitation session failed unexpectedly: {exc}")
        ui.error(f"  See {log_path} for the full traceback.")
        if _is_exception_group(exc):
            ui.error("Detected ExceptionGroup / BaseExceptionGroup. Unpacking nested exceptions:")
            _log_nested_exceptions(exc)
        if getattr(args, "debug", False):
            traceback.print_exc()
        return 1

    if result.error:
        ui.error(f"Run failed: {result.error}")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv if argv is not None else sys.argv[1:])

        # Apply output flags to the shared UI instance. --quiet and --json both
        # suppress ANSI color (so logs/JSON pipelines stay clean); --plain does
        # the same explicitly. Done once here so every downstream call site
        # (ui.status, ui.error, ui.spinner, etc.) honors them.
        ui.plain = bool(args.plain or args.quiet or args.json)
        raw_argv = argv if argv is not None else sys.argv[1:]
        # ponytail: --eval is nargs="*" (default None), so a bare "--eval" is an
        # empty list — falsy. Every gate below that used to truthy-test --eval
        # now goes through _eval_active instead.
        _eval_active = getattr(args, "eval", None) is not None or getattr(args, "eval_list", False)
        _benchmark_active = getattr(args, "benchmark", None) is not None or getattr(args, "benchmark_list", False)
        # ponytail: prompt only in the terminal menu (--menu). The no-args
        # default now launches the WebUI daemon, not the terminal menu, so the
        # interactive key prompt should not fire there. --setup-api-keys still
        # forces the prompt via force_prompt below.
        interactive_startup = bool(args.menu)
        bootstrap_startup_api_keys(
            args,
            prompt=interactive_startup
            and not args.doctor
            and not getattr(args, "self_test", False)
            and not _eval_active
            and not _benchmark_active,
        )
        setup_only = bool(args.setup_api_keys) and not any(
            [
                args.target.strip(),
                args.mode.strip(),
                args.goal.strip(),
                args.custom_goal.strip(),
                args.menu,
                args.doctor,
                getattr(args, "self_test", False),
                _eval_active,
                args.demo,
                getattr(args, "daemon", False),
                getattr(args, "web", False),
            ]
        )
        if setup_only:
            return 0

        # ChatGPT provider: ensure bun + the vendored openai-oauth checkout +
        # `bun install` are all in place before any runtime path can hit the
        # proxy. Surfaces the fix (install/clone/install-deps) up front instead
        # of letting the proxy's own RuntimeError fire mid-run. Skipped for
        # --doctor/--self-test/--eval/--benchmark, which intentionally probe a partial state.
        if (
            not _eval_active
            and not _benchmark_active
            and not any(getattr(args, flag, False) for flag in ("doctor", "self_test", "skills_list", "list_plugins"))
        ):
            rc = _ensure_chatgpt_runtime(args)
            if rc != 0:
                return rc

        # --demon / --daemon / --web: start the local WebUI API server and exit.
        # Checked BEFORE --doctor/--self-test/etc. so the mutual-exclusion
        # gate fires even when one of those flags is also set. --web implies
        # daemon mode and additionally builds/serves/opens the WebUI.
        if getattr(args, "daemon", False) or getattr(args, "web", False):
            _conflicting = []
            for flag in ("target", "mode", "goal", "custom_goal"):
                if getattr(args, flag, "").strip():
                    _conflicting.append(f"--{flag.replace('_', '-')}")
            for flag in (
                "menu",
                "doctor",
                "demo",
                "self_test",
                "skills_list",
                "list_plugins",
                "setup_api_keys",
            ):
                if getattr(args, flag, False):
                    _conflicting.append(f"--{flag.replace('_', '-')}")
            if _eval_active:
                _conflicting.append("--eval")
            if _benchmark_active:
                _conflicting.append("--benchmark")
            if _conflicting:
                ui.error(
                    (
                        "--demon/--daemon/--web cannot be combined with: "
                        if getattr(args, "web", False)
                        else "--demon/--daemon cannot be combined with: "
                    )
                    + ", ".join(_conflicting)
                )
                return 2
            return _run_daemon(args)

        # --doctor: run a self-check and exit. No exploit session starts.
        if args.doctor:
            from tools.doctor import run_doctor

            return run_doctor(args.config, json_output=bool(getattr(args, "json", False)))

        # --self-test: run a safe localhost smoke test and exit.
        if getattr(args, "self_test", False):
            from tools.self_test import run_self_test

            return asyncio.run(run_self_test(args))

        # --eval-list: print the graded-eval oracle targets (id + flag count) and exit.
        if getattr(args, "eval_list", False):
            import json as _json

            for oracle_path in sorted(Path("eval_targets").glob("*.oracle.json")):
                target_id = oracle_path.name.removesuffix(".oracle.json")
                flag_count = 0
                try:
                    oracle = _json.loads(oracle_path.read_text(encoding="utf-8"))
                    target_id = str(oracle.get("target_id") or target_id)
                    flag_count = len(oracle.get("flags") or [])
                except (OSError, ValueError):
                    pass
                print(f"{target_id}\t{flag_count} flags")
            return 0

        # --save-baseline/--check-regression compose with --eval or --benchmark.
        if (
            (getattr(args, "save_baseline", False) or getattr(args, "check_regression", False))
            and getattr(args, "eval", None) is None
            and getattr(args, "benchmark", None) is None
        ):
            ui.error("--save-baseline/--check-regression require --eval or --benchmark.")
            return 2

        # --benchmark / --benchmark-list: the reproducible benchmark suite
        # (tools/benchmark/). A bare --benchmark defaults to the xben suite.
        if getattr(args, "benchmark", None) is not None or getattr(args, "benchmark_list", False):
            from tools.benchmark_cli import run_benchmark_cli

            return run_benchmark_cli(args)

        # --eval: with --target, the legacy single-target benchmark harness;
        # without, the graded eval suite (oracle v2) across all/specified targets.
        if getattr(args, "eval", None) is not None:
            if args.target.strip():
                from tools.eval_harness import run_eval

                return asyncio.run(run_eval(args))
            from tools.eval_harness import check_regression, run_graded_eval, save_baseline

            config = load_config(args.config)
            eval_cfg = (config.get("eval", {}) or {}) if isinstance(config, dict) else {}
            baseline_path = Path(str(eval_cfg.get("baseline_path", "reports/eval/baseline.json")))
            report = asyncio.run(run_graded_eval(list(args.eval) or None, config))
            print(report.render_markdown())
            exit_code = 0
            if getattr(args, "check_regression", False):
                passed, messages = check_regression(
                    report, baseline_path, float(eval_cfg.get("regression_tolerance", 0.05) or 0.05)
                )
                for message in messages:
                    print(message)
                if not passed:
                    exit_code = 1
            if getattr(args, "save_baseline", False):
                save_baseline(report, baseline_path)
            return exit_code

        # --ctf: CTF autopilot with goal-completion detection.
        if getattr(args, "ctf", False):
            from tools.ctf_mode import run_ctf

            return run_ctf(args)

        # --demo: run against a local sandbox target (DVWA-style).
        if args.demo:
            from tools.demo_mode import run_demo

            return run_demo(args)

        # --skills-list: print the read-only runtime-skill catalog and exit.
        if getattr(args, "skills_list", False):
            config = load_config(args.config)
            return print_skills_catalog(config)

        # --list-plugins: print discovered plugins and exit.
        if getattr(args, "list_plugins", False):
            from tools.plugins import list_discovered_plugins

            config = load_config(args.config)
            try:
                from tools.plugins import load_plugins

                load_plugins(config, entry_point_loader=lambda group: [])
            except Exception:  # noqa: BLE001 -- listing must not crash boot
                pass
            plugins = list_discovered_plugins()
            if not plugins:
                ui.info("No plugins discovered.")
                return 0
            ui.info(f"Discovered {len(plugins)} plugin(s):")
            for p in plugins:
                state = "loaded" if p.get("loaded") else "discovered"
                caps = ",".join(p.get("capabilities", []) or []) or "-"
                print(f"  {p['name']} v{p.get('version', '?')} [{state}] caps={caps} - {p.get('description', '')}")
            return 0

        # --menu flag: explicitly force the terminal interactive menu.
        if args.menu:
            from tools.interactive_menu import run_interactive_menu

            return run_interactive_menu()

        # No arguments: launch the WebUI daemon (default interface). --menu
        # still forces the terminal menu; --demon/--daemon give the API alone.
        if len(raw_argv) == 0 and not args.target.strip():
            args.web = True
            return _run_daemon(args)

        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        ui.error("Aborted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
