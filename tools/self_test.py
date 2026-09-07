"""`--self-test` localhost smoke test (Phase 2.6).

Runs a safe, read-only diagnostic routine against ``127.0.0.1``:

1. Environment checks (Python, imports, nmap, Ollama, ports).
2. Config validation.
3. Boot the MCP exploit server over stdio with ``soft_fail=True``.
4. Call a fixed allow-list of introspection/scan tools against localhost:
   ``check_os``, ``quick_scan``, ``search_cve_intel``, ``list_workspace``.
5. Capture outputs and any ``BaseExceptionGroup`` safely.
6. Write ``self_test_report.json`` plus a Markdown summary.

The routine is hard-coded to reject any target that is not ``127.0.0.1`` or
``localhost`` and forces ``read_only`` permission. No write/run/exploit tools are
ever invoked.
"""

from __future__ import annotations

import json
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Reuse MCP lifecycle helpers from main.py. main.py only imports this module at
# runtime inside ``main()``, so there is no import cycle at module load.
from main import (
    _EXC_GROUP_CATCH,
    _extract_tool_text,
    _is_exception_group,
    _log_nested_exceptions,
    open_exploit_mcp_session,
    ui,
)
from tools.config_manager import load_validated_config
from tools.doctor import (
    _check_config,
    _check_imports,
    _check_models,
    _check_nmap,
    _check_ollama,
    _check_port,
    _check_python,
    _check_workspace,
)

_SELF_TEST_ALLOWED_TOOLS = {
    "check_os",
    "quick_scan",
    "search_cve_intel",
    "list_workspace",
}

# Repo root (tools/ lives one level below it). CWD-relative probe paths are
# anchored here so `--self-test` writes to the repo even when invoked from a
# different working directory. Absolute paths pass through untouched.
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _anchor_to_repo_root(path: Path) -> Path:
    """Prefix CWD-relative paths with the repo root; leave absolute ones alone."""
    if path.is_absolute():
        return path
    return _REPO_ROOT / path


class SelfTestError(Exception):
    """Raised when a self-test stage fails in a non-recoverable way."""


async def run_self_test(args: Any) -> int:
    """Execute the full localhost self-test and write a report.

    Returns 0 when every stage passes, 1 otherwise.
    """
    import sys

    # Windows cp1252 cannot encode ✓/✗; ensure stdout/stderr handle utf-8 gracefully.
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    target_ip = getattr(args, "target", "").strip() or "127.0.0.1"
    if target_ip not in ("127.0.0.1", "localhost", "::1"):
        ui.error(f"--self-test only supports 127.0.0.1/localhost; got {target_ip}")
        return 1

    config_path = Path(getattr(args, "config", "config.yaml"))
    reports_dir = _anchor_to_repo_root(Path(getattr(args, "reports_dir", "reports")))
    reports_dir.mkdir(parents=True, exist_ok=True)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    workspace = reports_dir / f"self_test_{run_id}"
    workspace.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  BreachPilot — Self-Test (`--self-test`)")
    print(f"  Target: {target_ip} (localhost only)")
    print(f"  Workspace: {workspace}")
    print("=" * 60)

    stages: list[dict[str, Any]] = []
    overall_ok = True

    # ── Stage 1: Environment diagnostics ──
    config: dict[str, Any] = {}
    try:
        config = load_validated_config(config_path)
    except Exception as exc:
        overall_ok = False
        stages.append({"name": "config_load", "ok": False, "error": str(exc)})
        print(f"  [!] Could not load/validate config: {exc}")

    ollama_host = config.get("ollama", {}).get("host", "https://api.ollama.com")
    models_cfg = config.get("models", {}).get("registry", {}) or {}
    # Pass registry *values* (model specs), not alias keys -- see
    # tools.doctor._check_models docstring.
    configured_models = list(models_cfg.values())
    mcp_http = int(config.get("mcp", {}).get("http_port", 8001))
    # Only probe Ollama when it is actually selected (chat or embeddings) --
    # a zero-Ollama install on another provider must not fail self-test.
    try:
        from tools.config_manager import get_ai_provider

        _active_provider = get_ai_provider(config)
    except Exception:
        _active_provider = "ollama"
    _embeddings_provider = str((config.get("embeddings", {}) or {}).get("provider") or "none").lower()
    _needs_ollama = _active_provider == "ollama" or _embeddings_provider == "ollama"

    env_checks = [
        _check_python(),
        _check_imports(config),
        _check_nmap(),
        _check_workspace(Path("reports")),
        _check_config(config_path),
        *([_check_ollama(ollama_host), _check_models(ollama_host, configured_models)] if _needs_ollama else []),
        _check_port("127.0.0.1", mcp_http),
        _check_port("127.0.0.1", 8000),
    ]
    for c in env_checks:
        stages.append(c)
        if not c.get("ok"):
            overall_ok = False
            err = c.get("error") or c.get("missing") or c.get("issues") or ""
            print(f"  [✗] {c.get('name')}: {err}")
        else:
            print(f"  [✓] {c.get('name')}")

    # ── Stage 2: Boot MCP exploit server and call safe tools ──
    tool_results: list[dict[str, Any]] = []
    session_ok = False
    try:
        async with open_exploit_mcp_session(
            transport="stdio",
            config_path=config_path,
            target_ip=target_ip,
            exploit_port=mcp_http,
            workspace=workspace,
            soft_fail=True,
        ) as session:
            if session is None:
                overall_ok = False
                stages.append({"name": "mcp_boot", "ok": False, "error": "MCP server failed to boot"})
                print("  [✗] MCP exploit server did not boot")
            else:
                stages.append({"name": "mcp_boot", "ok": True})
                session_ok = True
                print("  [✓] MCP exploit server booted")

                tools_response = await session.list_tools()
                available_tools: set[str] = set()
                for t in getattr(tools_response, "tools", []):
                    tool_name = getattr(t, "name", None)
                    if isinstance(tool_name, str):
                        available_tools.add(tool_name)
                stages.append({"name": "mcp_list_tools", "ok": True, "tool_count": len(available_tools)})

                for tool_name in _SELF_TEST_ALLOWED_TOOLS:
                    if tool_name not in available_tools:
                        tool_results.append(
                            {
                                "tool": tool_name,
                                "ok": False,
                                "skipped": True,
                                "reason": "tool not registered",
                            }
                        )
                        continue

                    arguments: dict[str, Any] = {"target_ip": target_ip}
                    if tool_name == "quick_scan":
                        arguments["ports"] = "22,80,443,8080"
                    if tool_name == "search_cve_intel":
                        arguments = {"query": "openssh 8.5"}

                    start = time.monotonic()
                    try:
                        raw = await session.call_tool(tool_name, arguments)
                        text = _extract_tool_text(raw)
                        tool_results.append(
                            {
                                "tool": tool_name,
                                "ok": True,
                                "duration_seconds": round(time.monotonic() - start, 3),
                                "text": text[:1000],
                            }
                        )
                        print(f"  [✓] Tool call {tool_name} ({len(text)} chars)")
                    except _EXC_GROUP_CATCH as exc:
                        overall_ok = False
                        err = f"{type(exc).__name__}: {exc}"
                        tool_results.append(
                            {
                                "tool": tool_name,
                                "ok": False,
                                "duration_seconds": round(time.monotonic() - start, 3),
                                "error": err,
                            }
                        )
                        print(f"  [✗] Tool call {tool_name}: {err}")
                        if _is_exception_group(exc):
                            _log_nested_exceptions(exc)
    except _EXC_GROUP_CATCH as exc:
        overall_ok = False
        stages.append({"name": "mcp_session", "ok": False, "error": f"{type(exc).__name__}: {exc}"})
        print(f"  [✗] MCP session failed: {exc}")
        if _is_exception_group(exc):
            _log_nested_exceptions(exc)
    except Exception as exc:
        overall_ok = False
        stages.append({"name": "mcp_session", "ok": False, "error": f"{type(exc).__name__}: {exc}"})
        print(f"  [✗] MCP session failed: {exc}")
        traceback.print_exc()

    # ── Stage 3: Write reports ──
    report = {
        "mode": "self_test",
        "target_ip": target_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_ok": overall_ok,
        "stages": stages,
        "tool_results": tool_results,
        "workspace": str(workspace),
    }

    json_path = workspace / "self_test_report.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    md_lines = [
        "# Self-Test Report",
        "",
        f"- **Target**: {target_ip}",
        f"- **Timestamp**: {report['timestamp']}",
        f"- **Overall**: {'PASS' if overall_ok else 'FAIL'}",
        "",
        "## Environment Checks",
        "",
    ]
    for stage in stages:
        status = "PASS" if stage.get("ok") else "FAIL"
        md_lines.append(f"- [{status}] `{stage.get('name')}`")
        if not stage.get("ok"):
            err = stage.get("error") or stage.get("missing") or stage.get("issues") or ""
            md_lines.append(f"  - {err}")
    md_lines.extend(
        [
            "",
            "## Tool Calls",
            "",
        ]
    )
    for tr in tool_results:
        status = "PASS" if tr.get("ok") else "FAIL"
        md_lines.append(f"- [{status}] `{tr.get('tool')}`")
        if tr.get("duration_seconds") is not None:
            md_lines.append(f"  - duration: {tr['duration_seconds']}s")
        if not tr.get("ok"):
            md_lines.append(f"  - error: {tr.get('error') or tr.get('reason')}")

    md_path = workspace / "self_test_report.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    print(f"  [i] JSON report: {json_path}")
    print(f"  [i] Markdown report: {md_path}")
    print("=" * 60)
    if overall_ok:
        print("  All self-test stages passed.")
        return 0
    print("  One or more self-test stages failed.")
    return 1


if __name__ == "__main__":
    import asyncio
    from argparse import Namespace

    class _Args(Namespace):
        target = "127.0.0.1"
        config = Path("config.yaml")
        reports_dir = Path("reports")

    raise SystemExit(asyncio.run(run_self_test(_Args())))
