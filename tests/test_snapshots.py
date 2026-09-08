"""Snapshot + rollback + counterfactual replay tests (design §snapshots).

Covers:

  1. ``tools.snapshots`` unit layer — SnapshotRef round-trip, the pure
     ``should_snapshot`` decision rule, ``_vm_id_for_target`` mapping, the
     provider factory, Docker provider behavior against MOCKED named wrappers
     (never real subprocess), the Hyper-V argv construction, and the
     ``SnapshotManager`` gates (enabled, cap delete-oldest, fail-open, index).
  2. The ``snapshot_*`` MCP family — conditional registration, allowlist
     gating (the allowlist IS the lock), create/revert/list blocks.
  3. The runner hooks — snapshot-before-destructive in the exploit loop and
     the counterfactual (revert + one variant-B retry) with BOTH outcomes
     recorded in ``final_result["counterfactual"]``.
  4. A composition test: the Feature-1 eval oracle flag vocabulary and the
     Feature-3 counterfactual config coexist in one config dict (the two
     features must not interfere).

All subprocess/hypervisor/docker access is mocked at the named wrapper seams;
no test touches a real container, VM, network, or the exploit loop's model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.snapshots import (
    SnapshotManager,
    SnapshotRef,
    _vm_id_for_target,
    autonomy_pack_guidance,
    get_provider,
    should_snapshot,
)

# ── Fakes ──────────────────────────────────────────────────────────────────


class FakeProvider:
    """In-memory SnapshotProvider recording every call (the contract fake)."""

    def __init__(self, *, fail_create: bool = False, fail_revert: bool = False) -> None:
        self.calls: list[tuple[str, str, str]] = []  # (op, vm_id, snapshot_id)
        self.reverted_with: list[SnapshotRef] = []
        self.fail_create = fail_create
        self.fail_revert = fail_revert
        self._counter = 0
        self._known: set[str] = set()

    def create(self, vm_id: str, label: str) -> SnapshotRef:
        self.calls.append(("create", vm_id, label))
        if self.fail_create:
            raise RuntimeError("hypervisor exploded")
        self._counter += 1
        snap_id = f"snap-{self._counter}"
        self._known.add(snap_id)
        return SnapshotRef(
            provider="fake",
            vm_id=vm_id,
            snapshot_id=snap_id,
            label=label,
            created_at="2026-01-01T00:00:00Z",
        )

    def revert(self, vm_id: str, ref: SnapshotRef) -> None:
        self.calls.append(("revert", vm_id, ref.snapshot_id))
        self.reverted_with.append(ref)
        # Real providers refuse a snapshot id they never took (mirrors docker
        # run from a nonexistent image) — this is what makes an unknown-id
        # revert surface as an ERROR block at the MCP layer.
        if self.fail_revert or (ref.snapshot_id and ref.snapshot_id not in self._known):
            raise RuntimeError("rollback refused")

    def list(self, vm_id: str) -> list[SnapshotRef]:
        self.calls.append(("list", vm_id, ""))
        return [
            SnapshotRef(provider="fake", vm_id=vm_id, snapshot_id=f"snap-{i}", label=f"l{i}")
            for i in range(1, self._counter + 1)
        ]

    def delete(self, vm_id: str, ref: SnapshotRef) -> None:
        self.calls.append(("delete", vm_id, ref.snapshot_id))


def _cfg(**snap_over: Any) -> dict[str, Any]:
    snap = {"enabled": True, "auto_before_destructive": True, "provider": "fake", "max_snapshots_per_target": 3}
    snap.update(snap_over)
    return {"snapshots": snap, "replay_simulator": {"enabled": True, "counterfactual": False}}


# ── 1a. SnapshotRef + decision rule + vm map ───────────────────────────────


def test_snapshot_ref_roundtrip() -> None:
    ref = SnapshotRef(
        provider="docker",
        vm_id="web",
        snapshot_id="breachpilot-snap-web-pre1",
        label="pre1",
        metadata={"ports": ["-p", "8080:80"]},
    )
    restored = SnapshotRef.from_dict(ref.to_dict())
    assert restored == ref
    assert restored.metadata["ports"] == ["-p", "8080:80"]


def test_should_snapshot_destructive_vs_benign() -> None:
    cfg = _cfg()
    # Destructive text trips the rule for any tool.
    assert should_snapshot("run_exploit_terminal", "rm -rf /tmp/loot", cfg) is True
    # Benign text + a tool with no intrusive category -> no snapshot.
    assert should_snapshot("check_os", "uname -a", cfg) is False


def test_should_snapshot_intrusive_category_without_destructive_text() -> None:
    cfg = _cfg()
    # Credential/lateral tools are intrusive even when the text looks calm.
    assert should_snapshot("dump_credentials", "ls", cfg) is True
    assert should_snapshot("lateral_exec", "whoami", cfg) is True


def test_should_snapshot_disabled_and_gate_off() -> None:
    # Feature disabled -> always False, even for destructive payloads.
    assert should_snapshot("run_exploit_terminal", "rm -rf /", _cfg(enabled=False)) is False
    assert should_snapshot("run_exploit_terminal", "rm -rf /", None) is False
    # auto_before_destructive off -> the auto path is off too.
    assert should_snapshot("run_exploit_terminal", "rm -rf /", _cfg(auto_before_destructive=False)) is False


def test_vm_id_for_target_map_env_and_fallback(monkeypatch, tmp_path: Path) -> None:
    cfg = {"snapshots": {"vm_map": {"10.0.0.50": "breachpilot-metasploitable2"}}}
    assert _vm_id_for_target("10.0.0.50", cfg) == "breachpilot-metasploitable2"
    # Unmapped target falls back to the raw string.
    assert _vm_id_for_target("10.0.0.99", cfg) == "10.0.0.99"
    # Env map wins over nothing (no config entry).
    monkeypatch.setenv("SNAPSHOT_VM_MAP", "10.0.0.77=container-x")
    assert _vm_id_for_target("10.0.0.77", {"snapshots": {}}) == "container-x"


def test_get_provider_unknown_and_known() -> None:
    with pytest.raises(ValueError, match="unknown snapshot provider"):
        get_provider("vsphere", {})
    assert type(get_provider("docker", {})).__name__ == "DockerProvider"


# ── 1c. P3-11 autonomy pack gate ────────────────────────────────────────────


def test_pack_guidance_empty_when_coherent() -> None:
    """Snapshots on, or no destructive-autonomy member on, means no gate."""
    assert autonomy_pack_guidance(_cfg()) == ""
    assert autonomy_pack_guidance(_cfg(enabled=False)) == ""
    assert autonomy_pack_guidance(None) == ""
    assert autonomy_pack_guidance({}) == ""
    assert autonomy_pack_guidance({"killchain": {"enabled": False}}) == ""


def test_pack_guidance_names_each_offender() -> None:
    """Each destructive-autonomy flag without snapshots fails fast w/ guidance."""
    base = {"snapshots": {"enabled": False}}
    for flag in (
        {"killchain": {"enabled": True}},
        {"replay_simulator": {"counterfactual": True}},
        {"autonomous": {"persistence_phase": True}},
    ):
        guidance = autonomy_pack_guidance({**base, **flag})
        assert guidance.startswith("BLOCKED:"), flag
        assert "snapshots.enabled" in guidance, flag
    # Combined offenders are all named in one message.
    both = autonomy_pack_guidance(
        {**base, "killchain": {"enabled": True}, "replay_simulator": {"counterfactual": True}}
    )
    assert "killchain.enabled" in both and "replay_simulator.counterfactual" in both
    # Snapshots on clears every offender.
    assert autonomy_pack_guidance({"snapshots": {"enabled": True}, "killchain": {"enabled": True}}) == ""


# ── 1b. Docker provider against mocked named wrappers ─────────────────────


def _fake_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> Any:
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def test_docker_create_commit_tag_and_port_capture(monkeypatch) -> None:
    import tools.snapshots as snaps

    commits: list[tuple[str, str]] = []
    inspect_calls: list[str] = []

    def fake_commit(container: str, tag: str) -> Any:
        commits.append((container, tag))
        return _fake_proc(0)

    def fake_inspect(container: str) -> Any:
        inspect_calls.append(container)
        return _fake_proc(
            0,
            stdout=json.dumps(
                [
                    {
                        "HostConfig": {
                            "PortBindings": {
                                "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
                                "443/tcp": [{"HostPort": "8443"}],
                            }
                        }
                    }
                ]
            ),
        )

    monkeypatch.setattr(snaps, "docker_commit", fake_commit)
    monkeypatch.setattr(snaps, "docker_inspect", fake_inspect)

    provider = snaps.DockerProvider({})
    ref = provider.create("breachpilot-metasploitable2", "pre-attack-1")

    assert commits == [("breachpilot-metasploitable2", ref.snapshot_id)]
    assert ref.snapshot_id.startswith("breachpilot-snap-breachpilot-metasploitable2-pre-attack-1")
    assert ref.metadata["image"] == ref.snapshot_id
    # Ports captured as "-p host:container" args for the re-create.
    assert ref.metadata["ports"] == ["-p", "8080:80", "-p", "8443:443"]
    assert inspect_calls == ["breachpilot-metasploitable2"]


def test_docker_create_commit_failure_raises(monkeypatch) -> None:
    import tools.snapshots as snaps

    monkeypatch.setattr(snaps, "docker_commit", lambda c, t: _fake_proc(1, stderr="no such container"))
    with pytest.raises(RuntimeError, match="docker commit failed"):
        snaps.DockerProvider({}).create("c1", "lbl")


def test_docker_revert_stop_rm_then_run_with_ports(monkeypatch) -> None:
    import tools.snapshots as snaps

    calls: list[tuple[str, Any]] = []

    def fake_stop_rm(container: str) -> Any:
        calls.append(("stop_rm", container))
        return _fake_proc(0)

    def fake_run(image: str, name: str, port_args: list[str]) -> Any:
        calls.append(("run", (image, name, tuple(port_args))))
        return _fake_proc(0)

    monkeypatch.setattr(snaps, "docker_stop_rm", fake_stop_rm)
    monkeypatch.setattr(snaps, "docker_run_from_snapshot", fake_run)

    ref = SnapshotRef(
        provider="docker",
        vm_id="web",
        snapshot_id="snapimg",
        label="l",
        metadata={"image": "snapimg", "ports": ["-p", "8080:80"]},
    )
    snaps.DockerProvider({}).revert("web", ref)

    assert calls[0] == ("stop_rm", "web")
    assert calls[1] == ("run", ("snapimg", "web", ("-p", "8080:80")))


def test_docker_revert_rm_failure_raises(monkeypatch) -> None:
    import tools.snapshots as snaps

    monkeypatch.setattr(snaps, "docker_stop_rm", lambda c: _fake_proc(1, stderr="busy"))
    ref = SnapshotRef(provider="docker", vm_id="web", snapshot_id="s", label="l", metadata={"image": "s"})
    with pytest.raises(RuntimeError, match="docker rm failed"):
        snaps.DockerProvider({}).revert("web", ref)


def test_docker_list_filters_by_prefix(monkeypatch) -> None:
    import tools.snapshots as snaps

    monkeypatch.setattr(
        snaps,
        "docker_images",
        lambda: _fake_proc(
            0,
            stdout="\n".join(
                [
                    "breachpilot-snap-web-pre1",
                    "breachpilot-snap-other-pre9",
                    "nginx:latest",
                    "breachpilot-snap-web-pre2",
                ]
            ),
        ),
    )
    refs = snaps.DockerProvider({}).list("web")
    assert [r.snapshot_id for r in refs] == [
        "breachpilot-snap-web-pre1",
        "breachpilot-snap-web-pre2",
    ]


# ── 1c. Hyper-V: argv construction only (no execution) ────────────────────


def test_hyperv_argv_construction(monkeypatch) -> None:
    import tools.snapshots as snaps

    seen_argv: list[list[str]] = []

    def fake_run(argv: list[str]) -> Any:
        seen_argv.append(argv)
        return _fake_proc(0)

    prov = snaps.HyperVProvider({"powershell_command": "pwsh"})
    monkeypatch.setattr(prov, "_run", fake_run)

    ref = prov.create("METASPLOITABLE", "pre-attack")
    assert ref.snapshot_id == "pre-attack"
    assert seen_argv[-1][:4] == ["pwsh", "-NoProfile", "-NonInteractive", "-Command"]
    assert "Checkpoint-VM -Name 'METASPLOITABLE' -SnapshotName 'pre-attack'" in seen_argv[-1][-1]

    prov.revert("METASPLOITABLE", ref)
    assert "Restore-VMCheckpoint -Name 'METASPLOITABLE' -SnapshotName 'pre-attack'" in seen_argv[-1][-1]

    empty = SnapshotRef(provider="hyperv", vm_id="M", snapshot_id="", label="")
    prov.revert("METASPLOITABLE", empty)
    assert "Restore-VMCheckpoint -Name 'METASPLOITABLE' -Latest" in seen_argv[-1][-1]


# ── 1d. SnapshotManager gates ──────────────────────────────────────────────


def test_manager_disabled_is_full_noop(tmp_path: Path) -> None:
    prov = FakeProvider()
    mgr = SnapshotManager(_cfg(enabled=False), provider=prov, index_dir=tmp_path)
    assert mgr.before_destructive("10.0.0.50", "pre") is None
    assert mgr.revert("10.0.0.50", "snap-1") is None
    assert mgr.delete("10.0.0.50", "snap-1") is False
    assert prov.calls == []


def test_manager_records_and_reverts_by_ref_and_id(tmp_path: Path) -> None:
    prov = FakeProvider()
    mgr = SnapshotManager(_cfg(), provider=prov, index_dir=tmp_path)
    ref = mgr.before_destructive("10.0.0.50", "pre-1")
    assert ref is not None and ref.snapshot_id == "snap-1"
    # Persisted in the index for cross-restart revert.
    assert [r.snapshot_id for r in mgr.list("10.0.0.50")] == ["snap-1"]
    # Revert by the ref object.
    assert mgr.revert("10.0.0.50", ref) is ref
    # Revert by snapshot id string (index resolution, fresh manager instance).
    mgr2 = SnapshotManager(_cfg(), provider=prov, index_dir=tmp_path)
    used = mgr2.revert("10.0.0.50", "snap-1")
    assert used is not None and used.snapshot_id == "snap-1"
    assert prov.reverted_with[-1].snapshot_id == "snap-1"


def test_manager_cap_deletes_oldest(tmp_path: Path) -> None:
    prov = FakeProvider()
    mgr = SnapshotManager(_cfg(max_snapshots_per_target=2), provider=prov, index_dir=tmp_path)
    for i in range(3):
        mgr.before_destructive("10.0.0.50", f"pre-{i}")
    # Oldest deleted at the provider AND dropped from the index.
    deletes = [c for c in prov.calls if c[0] == "delete"]
    assert [d[2] for d in deletes] == ["snap-1"]
    assert [r.snapshot_id for r in mgr.list("10.0.0.50")] == ["snap-2", "snap-3"]


def test_manager_fail_open_on_provider_errors(tmp_path: Path) -> None:
    prov = FakeProvider(fail_create=True, fail_revert=True)
    mgr = SnapshotManager(_cfg(), provider=prov, index_dir=tmp_path)
    # A broken hypervisor never breaks the attack path: None, not a raise.
    assert mgr.before_destructive("10.0.0.50", "pre") is None
    assert mgr.revert("10.0.0.50", "snap-1") is None


# ── 2. MCP snapshot_* family ───────────────────────────────────────────────


class _StubMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, *args: Any, **kwargs: Any) -> Any:
        def decorator(fn: Any) -> Any:
            self.tools[fn.__name__] = fn
            return fn

        return decorator


def _build_ctx(tmp_path: Path, *, enabled: bool, allowed: tuple[str, ...] = ("10.0.0.50",)) -> Any:
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.mcp_shared import make_audit_tool, make_require_allowlist
    from tools.mcp_tools.registry import ToolContext
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "snapshots": {
            "enabled": enabled,
            "auto_before_destructive": True,
            "provider": "fake",
            "vm_map": {"10.0.0.50": "breachpilot-metasploitable2"},
            "max_snapshots_per_target": 3,
        },
        "exploit": {
            "require_explicit_allowlist": True,
            "allowed_targets": list(allowed),
        },
    }
    return ToolContext(
        workspace=tmp_path,
        config=config,
        search=ExploitSearch(ExploitSearchSettings()),
        nvd=NVDClient(CVESearchSettings()),
        researcher=WebResearcher(WebResearcherSettings()),
        audit_tool=make_audit_tool(tmp_path),
        require_allowlist=make_require_allowlist(tmp_path, config),
    )


def _register_with_fake_provider(tmp_path: Path, *, enabled: bool) -> tuple[Any, FakeProvider, dict[str, Any]]:
    """Register the family with the provider factory faked out."""
    import tools.mcp_tools.snapshots as snap_tools
    import tools.snapshots as snaps

    prov = FakeProvider()
    ctx = _build_ctx(tmp_path, enabled=enabled)
    mcp = _StubMCP()
    with patch.object(snaps, "get_provider", return_value=prov):
        snap_tools.register_snapshot_tools(mcp, ctx=ctx)
    return mcp, prov, ctx.config


def test_snapshot_family_not_registered_when_disabled(tmp_path: Path) -> None:
    mcp, _prov, _cfg_out = _register_with_fake_provider(tmp_path, enabled=False)
    assert mcp.tools == {}, "snapshot tools must not register when snapshots.enabled is false"


def test_snapshot_family_registers_three_tools(tmp_path: Path) -> None:
    mcp, _prov, _cfg_out = _register_with_fake_provider(tmp_path, enabled=True)
    assert set(mcp.tools) == {"snapshot_create", "snapshot_revert", "snapshot_list"}


def test_snapshot_create_blocked_for_unallowlisted_vm(tmp_path: Path) -> None:
    mcp, prov, _cfg_out = _register_with_fake_provider(tmp_path, enabled=True)
    out = mcp.tools["snapshot_create"](vm_id="10.9.9.9", label="pre")
    assert out.startswith("BLOCKED:")
    assert prov.calls == []


def test_snapshot_create_maps_target_to_vm_and_records(tmp_path: Path) -> None:
    mcp, prov, _cfg_out = _register_with_fake_provider(tmp_path, enabled=True)
    out = mcp.tools["snapshot_create"](vm_id="10.0.0.50", label="pre-attack")
    assert out.startswith("SNAPSHOT_CREATED:")
    assert "breachpilot-metasploitable2" in out  # vm_map resolved
    assert ("create", "breachpilot-metasploitable2", "pre-attack") in prov.calls


def test_snapshot_revert_latest_and_unknown(tmp_path: Path) -> None:
    mcp, prov, _cfg_out = _register_with_fake_provider(tmp_path, enabled=True)
    mcp.tools["snapshot_create"](vm_id="10.0.0.50", label="pre-1")
    # Empty ref = latest recorded.
    out = mcp.tools["snapshot_revert"](vm_id="10.0.0.50", ref="")
    assert out.startswith("SNAPSHOT_REVERTED:")
    assert prov.reverted_with and prov.reverted_with[-1].snapshot_id == "snap-1"
    # Unknown ref -> ERROR block.
    out2 = mcp.tools["snapshot_revert"](vm_id="10.0.0.50", ref="nope")
    assert out2.startswith("ERROR:")


def test_snapshot_list_block(tmp_path: Path) -> None:
    mcp, _prov, _cfg_out = _register_with_fake_provider(tmp_path, enabled=True)
    mcp.tools["snapshot_create"](vm_id="10.0.0.50", label="pre-1")
    out = mcp.tools["snapshot_list"](vm_id="10.0.0.50")
    assert out.startswith("SNAPSHOT_LIST:")
    assert "COUNT: 1" in out


# ── 3. Runner hooks: snapshot-before-destructive + counterfactual ─────────


def _tool_call_msg(name: str = "run_exploit_terminal", args: Any = None) -> dict[str, Any]:
    return {
        "message": {
            "content": "running exploit",
            "tool_calls": [{"function": {"name": name, "arguments": args or {"command": "exploit"}}}],
        }
    }


def _done_msg() -> dict[str, Any]:
    return {"message": {"content": "done", "tool_calls": []}}


def _llm_script_msg() -> dict[str, Any]:
    """LLM response shape the payload crafter's craft_initial consumes (the
    pre-loop adaptive-exploits craft calls client.chat before round 1)."""
    return {"message": {"content": "print('crafted exploit')"}}


def _llm_mutation_msg() -> dict[str, Any]:
    """LLM response for the post-failure _llm_mutate_script call (consumed
    between variant A and variant B; >100 chars so it is accepted)."""
    body = "# mutated exploit script\n" + ("# padding line so the mutation passes the length gate\n" * 6)
    return {"message": {"content": body}}


def _chat_script(*messages: dict[str, Any]) -> Any:
    """Side-effect fn: pops scripted messages in order, then always done."""

    seq = list(messages)

    def side_effect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        if seq:
            return seq.pop(0)
        return _done_msg()

    return side_effect


def _tool_result(text: str) -> Any:
    return MagicMock(content=[MagicMock(text=text)])


def _policy(tmp_path: Path, *, rounds: int = 1, commands: int = 5) -> Any:
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=rounds,
        attack_max_commands=commands,
        adaptive_exploits_enabled=True,
        outcome_judgment_flow_a=False,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    return ExploitPolicy(settings, tmp_path)


class _RecordingSnapshotManager:
    """Duck-typed SnapshotManager the loop reaches through the patchable seam."""

    def __init__(self) -> None:
        self.created: list[tuple[str, str]] = []
        self.reverted: list[str] = []

    def before_destructive(self, vm_id: str, label: str) -> SnapshotRef | None:
        self.created.append((vm_id, label))
        return SnapshotRef(provider="fake", vm_id=vm_id, snapshot_id=f"snap-{len(self.created)}", label=label)

    def revert(self, vm_id: str, ref: Any) -> SnapshotRef | None:
        self.reverted.append(ref.snapshot_id)
        return (
            ref
            if isinstance(ref, SnapshotRef)
            else SnapshotRef(provider="fake", vm_id=vm_id, snapshot_id=str(ref), label="")
        )


@pytest.mark.asyncio
async def test_runner_snapshots_before_destructive_and_reverts_counterfactual(tmp_path: Path) -> None:
    """Two-variant scripted sequence: round 1 destructive command fails ->
    auto-snapshot taken -> adaptive mutation schedules variant B -> counterfactual
    revert fires -> round 2 succeeds -> BOTH outcomes recorded."""
    from tools.exploit_agent import (
        _build_snapshot_manager,
        _InMemoryExperienceStore,
        _should_snapshot_for_action,
        run_exploit_agent,
    )

    policy = _policy(tmp_path, rounds=3, commands=5)
    mgr = _RecordingSnapshotManager()

    client = MagicMock()
    client.chat.side_effect = _chat_script(
        _llm_script_msg(),  # consumed by the pre-loop craft_initial LLM call
        _tool_call_msg(args={"command": "rm -rf /opt/app"}),
        _llm_mutation_msg(),  # consumed by the post-failure _llm_mutate_script call
        _tool_call_msg(args={"command": "rm -rf /opt/app --mutated"}),
    )
    session = AsyncMock()
    session.call_tool.side_effect = [
        _tool_result("VULN_NOT_CONFIRMED: exploit failed\nexit code: 1"),
        _tool_result("COMPROMISE: shell gained target=10.0.0.50"),
    ]

    cfg: dict[str, Any] = {
        "snapshots": {"enabled": True, "auto_before_destructive": True},
        "replay_simulator": {"enabled": True, "counterfactual": True},
        "outcome_judgment": {"flow_a": False},
        # Keep the research assistant off: its startup CVE research would
        # consume scripted client.chat messages before round 1.
        "research": {"assistant": {"enabled": False}},
    }
    with (
        patch("tools.exploit_agent._should_snapshot_for_action", return_value=True),
        patch("tools.exploit_agent._build_snapshot_manager", return_value=mgr),
        patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream,
    ):
        stream.return_value = {"role": "assistant", "content": "..."}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            target_cve="CVE-2024-1234",  # so the mutator crafts the initial payload
            reports_dir=tmp_path / "reports",
            experience_store=_InMemoryExperienceStore(),
            semantic_memory=object(),  # truthy -> no semantic rebuild
            config=cfg,
        )

    # Snapshot taken before the destructive round-1 action...
    assert mgr.created, "snapshot-before-destructive never fired"
    assert mgr.created[0][0] == "10.0.0.50"
    # ...and the counterfactual revert fired after the variant-A failure.
    assert mgr.reverted, "counterfactual revert never fired"
    # Both outcomes recorded: A failed, B verified on the reverted target.
    rows = result.get("counterfactual")
    assert rows, "final_result is missing the counterfactual rows"
    row = rows[-1]
    assert row["payload_a_outcome"] == "failed"
    assert row["payload_b_outcome"] == "verified"
    assert row["reverted"] is True
    assert row["payload_b_strategy"]


@pytest.mark.asyncio
async def test_runner_no_counterfactual_when_disabled(tmp_path: Path) -> None:
    """snapshots on but replay_simulator.counterfactual off -> snapshot fires,
    NO revert, no counterfactual rows."""
    from tools.exploit_agent import _InMemoryExperienceStore, run_exploit_agent

    policy = _policy(tmp_path, rounds=2, commands=5)
    mgr = _RecordingSnapshotManager()

    client = MagicMock()
    client.chat.side_effect = _chat_script(
        _llm_script_msg(),  # consumed by the pre-loop craft_initial LLM call
        _tool_call_msg(args={"command": "rm -rf /opt/app"}),
        _llm_mutation_msg(),  # consumed by the post-failure _llm_mutate_script call
    )
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("VULN_NOT_CONFIRMED: exploit failed\nexit code: 1")

    cfg: dict[str, Any] = {
        "snapshots": {"enabled": True, "auto_before_destructive": True},
        "replay_simulator": {"enabled": True, "counterfactual": False},
        "outcome_judgment": {"flow_a": False},
        # Keep the research assistant off (see the counterfactual test above).
        "research": {"assistant": {"enabled": False}},
    }
    with (
        patch("tools.exploit_agent._should_snapshot_for_action", return_value=True),
        patch("tools.exploit_agent._build_snapshot_manager", return_value=mgr),
        patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream,
    ):
        stream.return_value = {"role": "assistant", "content": "..."}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            target_cve="CVE-2024-1234",
            reports_dir=tmp_path / "reports",
            experience_store=_InMemoryExperienceStore(),
            semantic_memory=object(),
            config=cfg,
        )

    assert mgr.created, "snapshot should still fire with counterfactual off"
    assert mgr.reverted == []
    assert not result.get("counterfactual")


@pytest.mark.asyncio
async def test_runner_no_snapshot_when_feature_disabled(tmp_path: Path) -> None:
    """snapshots.enabled false -> the hook is fully inert (default state)."""
    from tools.exploit_agent import _InMemoryExperienceStore, run_exploit_agent

    policy = _policy(tmp_path, rounds=2, commands=5)
    mgr = _RecordingSnapshotManager()

    client = MagicMock()
    client.chat.side_effect = _chat_script(
        _tool_call_msg(args={"command": "rm -rf /opt/app"}),
    )
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("VULN_NOT_CONFIRMED: exploit failed\nexit code: 1")

    cfg: dict[str, Any] = {
        "snapshots": {"enabled": False},
        "replay_simulator": {"enabled": True, "counterfactual": True},
        "outcome_judgment": {"flow_a": False},
        # Keep the research assistant off (see the counterfactual test above).
        "research": {"assistant": {"enabled": False}},
    }
    with (
        patch("tools.exploit_agent._should_snapshot_for_action", return_value=False),
        patch("tools.exploit_agent._build_snapshot_manager", return_value=mgr),
        patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream,
    ):
        stream.return_value = {"role": "assistant", "content": "..."}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            target_cve="CVE-2024-1234",
            reports_dir=tmp_path / "reports",
            experience_store=_InMemoryExperienceStore(),
            semantic_memory=object(),
            config=cfg,
        )

    assert mgr.created == []
    assert mgr.reverted == []


# ── 4. Path-B funnel (campaign executor) ───────────────────────────────────


@pytest.mark.asyncio
async def test_executor_snapshots_before_destructive_dispatch(tmp_path: Path) -> None:
    """AttackModuleExecutor._dispatch_module_artifact snapshots before a
    destructive suggested_command (fail-open, timeline event recorded)."""
    from tools.campaign.executor import AttackModuleExecutor
    from tools.campaign.state import AttackState

    state = AttackState(target="10.0.0.50")
    mgr = _RecordingSnapshotManager()
    cfg = _cfg()
    cfg["workspace"] = str(tmp_path)

    execr = AttackModuleExecutor(mission_config=cfg)
    execr._snapshot_mgr = mgr

    module = MagicMock()
    module.name = "TestModule"
    mresult = MagicMock()
    mresult.suggested_command = "rm -rf /opt/app && whoami"
    mresult.script = ""

    task = MagicMock()
    task.target = "10.0.0.50"
    task.module_name = "TestModule"
    task.retry_count = 0

    async def fake_executor(command: str, args: dict[str, Any]) -> str:
        return "COMPROMISE: uid=0(root)"

    execr._tool_executor = fake_executor

    with patch("tools.snapshots.should_snapshot", return_value=True):
        out = await execr._dispatch_module_artifact(module, mresult, MagicMock(), task, state)

    assert out is not None
    assert mgr.created, "executor funnel did not snapshot before the destructive dispatch"
    assert mgr.created[0][0] == "10.0.0.50"
    kinds = [e.get("event_type") for e in state.timeline]
    assert "snapshot_taken" in kinds


# ── 5. Feature-1 x Feature-3 composition ───────────────────────────────────


def test_eval_oracle_and_snapshot_config_coexist(tmp_path: Path) -> None:
    """One config dict carries the Feature-1 eval block AND the Feature-3
    snapshots/counterfactual blocks without interfering; the decision rule
    and the counterfactual toggle both read their own block only."""
    from tools.exploit_agent import _counterfactual_enabled

    cfg: dict[str, Any] = {
        "eval": {
            "enabled": True,
            "output_dir": str(tmp_path / "eval"),
            "baseline_path": str(tmp_path / "baseline.json"),
        },
        "snapshots": {"enabled": True, "auto_before_destructive": True},
        "replay_simulator": {"enabled": True, "counterfactual": True},
    }
    # Feature-1 seam still resolves its block (module imports cleanly with
    # the combined config present)...
    import tools.eval_harness as _eval  # noqa: F401

    # ...and the Feature-3 decision rule + toggle read theirs.
    assert should_snapshot("dump_credentials", "ls", cfg) is True
    assert should_snapshot("check_os", "uname -a", cfg) is False
    assert _counterfactual_enabled(cfg) is True
    assert _counterfactual_enabled({"replay_simulator": {"counterfactual": False}}) is False


def test_snapshot_index_survives_manager_reconstruction(tmp_path: Path) -> None:
    """The JSON index lets a fresh process (new manager) revert by id — the
    persistence contract the counterfactual flow relies on across restarts."""
    prov = FakeProvider()
    SnapshotManager(_cfg(), provider=prov, index_dir=tmp_path).before_destructive("10.0.0.50", "pre-1")
    index = json.loads((tmp_path / "snapshots_index.json").read_text(encoding="utf-8"))
    assert index["10.0.0.50"][0]["snapshot_id"] == "snap-1"
