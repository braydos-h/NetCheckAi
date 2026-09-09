"""Hot-path slice tests: single-parse lock threading, batched probes, collapsed audit.

- The lock gate + sandbox funnel + loopback hint share ONE extractor pass
  (``_extract_lock_targets``); the funnel's ``targets=`` kwarg skips re-parsing
  while the manager scope gate still checks every destination.
- ``run_exploit_terminals`` runs N probes in ONE sandbox round-trip with the
  lock gated on the FULL joined text (RULE-LOCK-FIRST).
- The manager writes NO ``started`` row (collapsed audit) but always a
  terminal completed/failed/timed_out row with duration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.mcp_tools.sandbox_exec import run_command_in_sandbox
from tools.mcp_tools.terminal import execute as execute_mod
from tools.mcp_tools.terminal.allowlist import _extract_lock_targets, _target_lock_block
from tools.sandbox.models import SandboxResult


def _cfg(*allowed: str) -> dict:
    return {"exploit": {"require_explicit_allowlist": True, "allowed_targets": list(allowed)}}


# ── single-parse lock ──────────────────────────────────────────────────


def test_extract_lock_targets_matches_gate_inputs() -> None:
    cmd = "echo 10.0.0.5; nmap -sV 10.0.0.5; curl http://10.0.0.5/x"
    targets = _extract_lock_targets(cmd)
    assert "10.0.0.5" in targets
    # Gating the same list is identical to gating the raw command.
    assert _target_lock_block(cmd, _cfg("10.0.0.5")) is None
    assert _target_lock_block(cmd, _cfg("10.0.0.5"), targets=targets) is None


def test_gate_targets_kwarg_blocks_off_list() -> None:
    cmd = "curl http://1.2.3.4/x"
    targets = _extract_lock_targets(cmd)
    assert "1.2.3.4" in targets
    assert _target_lock_block(cmd, _cfg("10.0.0.5")) is not None
    assert _target_lock_block(cmd, _cfg("10.0.0.5"), targets=targets) is not None


def test_gate_targets_kwarg_file_indirection_still_denied() -> None:
    # The file: pre-gate runs on the raw command even with pre-parsed targets.
    cmd = "msfconsole -x 'set RHOSTS file:/tmp/hosts'"
    assert _target_lock_block(cmd, _cfg("10.0.0.5"), targets=[]) is not None


def test_funnel_targets_kwarg_skips_reparse_but_still_gates() -> None:
    import tools.mcp_tools.sandbox_exec as funnel

    seen: list[str] = []
    real_collect = funnel.collect_command_targets

    def _spy(command: str) -> list[str]:
        seen.append(command)
        return real_collect(command)

    class _Mgr:
        def execute(self, command, **kwargs):
            return SandboxResult(exit_code=0, stdout="ok", stderr="", timed_out=False, duration_seconds=0.1)

        def container_path(self, host_path):
            return "/workspace/x"

    class _Ctx:
        sandbox = _Mgr()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(funnel, "collect_command_targets", _spy)
    monkeypatch.setattr(funnel, "_enforce_full_scope", lambda manager, targets: seen.append(("scope", list(targets))))
    try:
        ran, _ = run_command_in_sandbox(_Ctx(), "nmap 10.0.0.5", timeout=30, targets=["10.0.0.5"])
        assert ran is True
        # collect_command_targets never ran; the scope gate still saw the list.
        assert seen == [("scope", ["10.0.0.5"])]
    finally:
        monkeypatch.undo()


def test_run_as_root_threads_single_parse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """run_as_root parses once: the funnel must receive the gate's list."""
    import tools.mcp_tools.sandbox_exec as funnel
    import tools.mcp_tools.terminal.allowlist as lock

    parses = 0
    real_extract = lock._extract_lock_targets

    def _counting_extract(command: str, **kwargs: Any) -> list[str]:
        nonlocal parses
        parses += 1
        return real_extract(command, **kwargs)

    received: dict[str, Any] = {}
    real_funnel = funnel.run_command_in_sandbox

    def _capture(ctx: Any, command: str, **kwargs: Any) -> tuple[bool, Any]:
        received.update(kwargs)
        return True, SandboxResult(exit_code=0, stdout="ok", stderr="", timed_out=False, duration_seconds=0.1)

    monkeypatch.setattr(lock, "_extract_lock_targets", _counting_extract)
    monkeypatch.setattr(execute_mod, "_extract_lock_targets", _counting_extract)
    monkeypatch.setattr(execute_mod, "run_command_in_sandbox", _capture)
    monkeypatch.setattr("tools.env_probe._can_passwordless_sudo", lambda: True)
    tools = _register(tmp_path, _cfg("10.0.0.5"), object())
    out = tools["run_as_root"]("nmap -sV 10.0.0.5")
    assert "ROOT_CMD_RESULT:" in out
    assert parses == 1, f"expected exactly one extractor pass, got {parses}"
    assert received.get("targets") == ["10.0.0.5"]
    assert real_funnel is not None  # silence linters about the import


# ── batched probes ─────────────────────────────────────────────────────


class _FakeMcp:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self):  # matches the FakeMcp pattern used across the suite
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class _FakeCtx:
    def __init__(self, workspace: Path, config: dict, manager: Any = None) -> None:
        self.workspace = workspace
        self.config = config
        self.sandbox = manager
        # Direct-decoration shape like make_audit_tool(fn): @audit_tool calls
        # this with the function itself (NOT a bound method -- that would
        # swallow the function as an arg and replace it with the inner deco).
        self.audit_tool = lambda fn: fn


class _FakeManager:
    def __init__(self) -> None:
        self.round_trips = 0

    def execute(self, command, **kwargs):
        self.round_trips += 1
        return SandboxResult(
            exit_code=0, stdout=f"ran: {command[:40]}", stderr="", timed_out=False, duration_seconds=0.1
        )

    def container_path(self, host_path):
        return "/workspace/x"

    def status(self):
        return {"run_id": "r", "container_id": "c" * 12, "network_locked": True, "image": "img"}


def _register(tmp_path: Path, config: dict, manager: Any = None) -> dict[str, Any]:
    mcp = _FakeMcp()
    execute_mod._register_execute_tools(mcp, ctx=_FakeCtx(tmp_path / "ws", config, manager))
    return mcp.tools


def test_batch_runs_once_for_n_probes(tmp_path: Path) -> None:
    mgr = _FakeManager()
    tools = _register(tmp_path, _cfg("10.0.0.5"), mgr)
    out = tools["run_exploit_terminals"](["echo 10.0.0.5", "nmap -sV 10.0.0.5"])
    assert mgr.round_trips == 1
    assert "BATCH_TERMINAL_RESULT: completed" in out
    assert "--- probe #0 ---" in out or "probe" in out.lower()


def test_batch_blocks_off_target_past_join_boundary(tmp_path: Path) -> None:
    mgr = _FakeManager()
    tools = _register(tmp_path, _cfg("10.0.0.5"), mgr)
    out = tools["run_exploit_terminals"](["echo 10.0.0.5", "curl http://1.2.3.4/x"])
    assert mgr.round_trips == 0
    assert "blocked" in out.lower()
    assert "1.2.3.4" in out


def test_batch_rejects_empty_overcap_and_nonlist(tmp_path: Path) -> None:
    tools = _register(tmp_path, _cfg("10.0.0.5"), _FakeManager())
    assert "BLOCKED" in tools["run_exploit_terminals"]([])
    assert "BLOCKED" in tools["run_exploit_terminals"](["ok 10.0.0.5", ""])
    assert "BLOCKED" in tools["run_exploit_terminals"](["x 10.0.0.5"] * 21)
    assert "BLOCKED" in tools["run_exploit_terminals"]("not-a-list")


def test_batch_registered_with_audit_gate() -> None:
    from tools.mcp_tools.registry import _validate_mcp_tool_decorators

    assert _validate_mcp_tool_decorators() == []


# ── collapsed audit ────────────────────────────────────────────────────


class _HotpathBackend:
    """Recording lifecycle backend mirroring test_sandbox_manager.FakeBackend; never touches Docker."""

    def ensure_docker(self) -> None:
        pass

    def ensure_image(self, image: str) -> None:
        pass

    def create_network(self, name: str) -> str:
        return name

    def create_worker(self, spec: Any, *, read_only_rootfs: bool) -> str:
        return spec.sandbox_id

    def exec(self, cid, argv, **kwargs):
        return 0, "ok", ""

    def stop(self, cid: str) -> None:
        pass

    def destroy(self, cid: str, network: str) -> dict[str, bool]:
        return {"container_removed": True, "network_removed": True}


def test_manager_writes_terminal_row_without_started(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.sandbox.manager import SandboxManager
    from tools.sandbox.models import SandboxConfig

    # Policy install is a no-op (sidecar install is covered by network tests).
    monkeypatch.setattr("tools.sandbox.manager.apply_network_policy", lambda *a, **k: True)
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_network_gateway", lambda *a, **k: "172.30.0.1")
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_inspect_state", lambda *a, **k: "running")
    config: dict[str, Any] = {
        "exploit": {"allowed_targets": ["192.0.2.5"], "require_explicit_allowlist": True},
        "sandbox": {"enabled": True, "network": {"allow_research_hosts": False}},
    }
    cfg = SandboxConfig.from_config(config)
    assert cfg.enabled
    (tmp_path / "ws").mkdir(parents=True, exist_ok=True)
    mgr = SandboxManager(cfg, tmp_path / "ws", config_dict=config, backend=_HotpathBackend())
    result = mgr.execute("id", target_ip="192.0.2.5", tool_name="run_exploit_terminal")
    assert result.exit_code == 0
    rows = [
        json.loads(line)
        for line in (tmp_path / "ws" / "exploit_audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    statuses = [r["status"] for r in rows if r.get("tool_name") == "sandbox.run_exploit_terminal"]
    assert "started" not in statuses
    assert statuses == ["completed"]
    assert rows[-1]["duration_seconds"] >= 0
