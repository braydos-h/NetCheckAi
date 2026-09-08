"""Snapshot + rollback infrastructure (design §snapshots / counterfactual).

Snapshot-before-destructive support for the lab build: a pluggable provider
layer (Docker commit/rollback is the mandatory, fully-implemented path;
Proxmox / libvirt / Hyper-V / VMware are best-effort wrappers) plus a
``SnapshotManager`` that enforces the config gates and keeps a JSON index so
snapshot refs survive process restarts.

Design rules:
- **Default OFF**: ``snapshots.enabled`` is false in schema + config.yaml;
  every consumer treats "no snapshot" as a no-op and a snapshot FAILURE must
  never break the attack path (fail-open, logged).
- **Named wrapper seams**: all subprocess/HTTP calls live behind module-level
  named wrapper functions (``docker_commit``, ``docker_run_from_snapshot``,
  ``_docker``, ...) — tests monkeypatch the wrappers, never ``subprocess``
  (house convention: docker_suite_up/down in tools/eval_harness.py).
- **The allowlist is untouched**: snapshotting infrastructure (a VM/container)
  is authorized by the MCP layer's allowlist gate on the snapshot_* tools;
  this module adds no authorization of its own.
- The counterfactual re-run flow does NOT live here (replay_simulator is a
  PLAN critic and never re-runs exploits); the loop's mutation/feedback path
  drives revert-and-retry (see tools/exploit_agent/runner/_impl.py).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

_SUBPROCESS_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


@dataclass
class SnapshotRef:
    """One restorable snapshot, provider-tagged."""

    provider: str
    vm_id: str
    snapshot_id: str
    label: str
    created_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SnapshotRef":
        return cls(
            provider=str(data.get("provider", "")),
            vm_id=str(data.get("vm_id", "")),
            snapshot_id=str(data.get("snapshot_id", "")),
            label=str(data.get("label", "")),
            created_at=str(data.get("created_at", "")),
            metadata=dict(data.get("metadata", {}) or {}),
        )


class SnapshotProvider(Protocol):
    """Provider surface: create / revert / list / delete."""

    def create(self, vm_id: str, label: str) -> SnapshotRef: ...

    def revert(self, vm_id: str, ref: SnapshotRef) -> None: ...

    def list(self, vm_id: str) -> list[SnapshotRef]: ...

    def delete(self, vm_id: str, ref: SnapshotRef) -> None: ...


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", (text or "").strip()).strip("-")[:60] or "snap"


# ---------------------------------------------------------------------------
# Docker provider (MANDATORY — stdlib only, fully implemented)
# ---------------------------------------------------------------------------


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    """Named wrapper: run a docker CLI command (the test seam)."""
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
        check=False,
    )


def docker_commit(container: str, tag: str) -> subprocess.CompletedProcess[str]:
    """Named wrapper: ``docker commit <container> <repo:tag>``."""
    return _docker("commit", container, tag)


def docker_inspect(container: str) -> subprocess.CompletedProcess[str]:
    """Named wrapper: ``docker inspect <container>`` (raw JSON text)."""
    return _docker("inspect", container)


def docker_run_from_snapshot(image: str, name: str, port_args: list[str]) -> subprocess.CompletedProcess[str]:
    """Named wrapper: re-create the container from a committed image."""
    return _docker("run", "-d", "--name", name, *port_args, image)


def docker_stop_rm(container: str) -> subprocess.CompletedProcess[str]:
    """Named wrapper: stop + rm the live container before a snapshot restore."""
    subprocess.run(
        ["docker", "stop", container], capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT, check=False
    )
    return _docker("rm", "-f", container)


def docker_rmi(image: str) -> subprocess.CompletedProcess[str]:
    """Named wrapper: remove a committed snapshot image."""
    return _docker("rmi", "-f", image)


def docker_images() -> subprocess.CompletedProcess[str]:
    """Named wrapper: list images (repo:tag per line)."""
    return _docker("images", "--format", "{{.Repository}}:{{.Tag}}")


class DockerProvider:
    """Snapshot a container via ``docker commit``; revert = rm + re-create.

    ``vm_id`` is a container name (e.g. ``breachpilot-metasploitable2`` from
    eval_targets/docker-compose.yml). Port maps are captured from
    ``docker inspect`` at create time so the re-created container exposes the
    same services.
    """

    prefix = "breachpilot-snap"

    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        self.cfg = cfg or {}

    def create(self, vm_id: str, label: str) -> SnapshotRef:
        tag = f"{self.prefix}-{_slug(vm_id)}-{_slug(label)}"
        proc = docker_commit(vm_id, tag)
        if proc.returncode != 0:
            raise RuntimeError(f"docker commit failed: {(proc.stderr or proc.stdout).strip()[:300]}")
        port_args = self._capture_ports(vm_id)
        return SnapshotRef(
            provider="docker",
            vm_id=vm_id,
            snapshot_id=tag,
            label=label,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metadata={"image": tag, "ports": port_args},
        )

    def _capture_ports(self, vm_id: str) -> list[str]:
        proc = docker_inspect(vm_id)
        if proc.returncode != 0:
            return []
        try:
            spec = json.loads(proc.stdout or "[]")
            bindings = ((spec[0] or {}).get("HostConfig", {}) or {}).get("PortBindings", {}) or {}
        except (ValueError, IndexError, KeyError):
            return []
        args: list[str] = []
        for container_port, entries in bindings.items():
            for entry in entries or []:
                host_port = str(entry.get("HostPort", "") or "")
                if host_port:
                    args.extend(["-p", f"{host_port}:{container_port.split('/')[0]}"])
        return args

    def revert(self, vm_id: str, ref: SnapshotRef) -> None:
        image = str(ref.metadata.get("image") or ref.snapshot_id)
        ports = [str(p) for p in (ref.metadata.get("ports") or [])]
        stop = docker_stop_rm(vm_id)
        if stop.returncode != 0:
            raise RuntimeError(f"docker rm failed: {(stop.stderr or stop.stdout).strip()[:300]}")
        run = docker_run_from_snapshot(image, vm_id, ports)
        if run.returncode != 0:
            raise RuntimeError(f"docker run from snapshot failed: {(run.stderr or run.stdout).strip()[:300]}")

    def list(self, vm_id: str) -> list[SnapshotRef]:
        proc = docker_images()
        if proc.returncode != 0:
            return []
        prefix = f"{self.prefix}-{_slug(vm_id)}-"
        refs: list[SnapshotRef] = []
        for line in (proc.stdout or "").splitlines():
            image = line.strip()
            if image.startswith(prefix):
                label = image[len(prefix) :]
                refs.append(
                    SnapshotRef(
                        provider="docker",
                        vm_id=vm_id,
                        snapshot_id=image,
                        label=label,
                        metadata={"image": image, "ports": []},
                    )
                )
        return refs

    def delete(self, vm_id: str, ref: SnapshotRef) -> None:
        proc = docker_rmi(ref.snapshot_id)
        if proc.returncode != 0:
            raise RuntimeError(f"docker rmi failed: {(proc.stderr or proc.stdout).strip()[:300]}")


# ---------------------------------------------------------------------------
# Hypervisor providers (best-effort; feature-detect, never import errors)
# ---------------------------------------------------------------------------


class ProxmoxProvider:
    """Proxmox VE qm snapshot/rollback over the HTTP API.

    Auth is an API token from ``PROXMOX_API_TOKEN`` (env only — never config,
    never logged). ``PROXMOX_NODE`` picks the node; ``PROXMOX_VMID_MAP``
    maps targets to VMIDs (``10.0.0.50=101,10.0.0.51=102``).
    """

    name = "proxmox"

    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        cfg = cfg or {}
        self.host = str(cfg.get("host") or "").strip()
        self.node = str(cfg.get("node") or os.environ.get("PROXMOX_NODE", "")).strip()
        self.token = os.environ.get("PROXMOX_API_TOKEN", "")
        self._vmid_map: dict[str, str] = {}
        for pair in os.environ.get("PROXMOX_VMID_MAP", "").split(","):
            if "=" in pair:
                key, _, val = pair.partition("=")
                if key.strip() and val.strip():
                    self._vmid_map[key.strip()] = val.strip()

    def _vmid(self, vm_id: str) -> str:
        return self._vmid_map.get(vm_id, vm_id)

    def _api(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        """Named wrapper: POST to the Proxmox API (the test seam)."""
        url = f"{self.host}/api2/json{path}"
        req = urllib.request.Request(url, method="POST")
        # Authorization header only; the token is never logged or returned.
        req.add_header("Authorization", f"PVE {self.token}")
        data = json.dumps(body or {}).encode("utf-8")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, data=data, timeout=_SUBPROCESS_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _require(self) -> None:
        if not self.host or not self.node or not self.token:
            raise RuntimeError("proxmox provider needs host, node (PROXMOX_NODE) and PROXMOX_API_TOKEN")

    def create(self, vm_id: str, label: str) -> SnapshotRef:
        self._require()
        snapname = f"{_slug(label)}"
        self._api(f"/nodes/{self.node}/qemu/{self._vmid(vm_id)}/snapshot", {"snapname": snapname})
        return SnapshotRef(
            provider=self.name,
            vm_id=vm_id,
            snapshot_id=snapname,
            label=label,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metadata={"node": self.node, "vmid": self._vmid(vm_id)},
        )

    def revert(self, vm_id: str, ref: SnapshotRef) -> None:
        self._require()
        self._api(f"/nodes/{self.node}/qemu/{self._vmid(vm_id)}/snapshot/{ref.snapshot_id}/rollback")

    def list(self, vm_id: str) -> list[SnapshotRef]:
        self._require()
        data = self._api(f"/nodes/{self.node}/qemu/{self._vmid(vm_id)}/snapshot")
        return [
            SnapshotRef(
                provider=self.name, vm_id=vm_id, snapshot_id=str(s.get("name", "")), label=str(s.get("name", ""))
            )
            for s in (data.get("data") or [])
            if isinstance(s, dict) and s.get("name") and s.get("name") != "current"
        ]

    def delete(self, vm_id: str, ref: SnapshotRef) -> None:
        self._require()
        self._api(f"/nodes/{self.node}/qemu/{self._vmid(vm_id)}/snapshot/{ref.snapshot_id}")


class _CommandProvider:
    """Shared shape for CLI-driven providers (virsh / PowerShell / vmrun)."""

    name = "command"

    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        self.cfg = cfg or {}

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        """Named wrapper: execute the provider CLI (the test seam)."""
        return subprocess.run(argv, capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT, check=False)

    def _which(self, binary: str) -> bool:
        return shutil.which(binary) is not None

    def _fail(self, argv: list[str], proc: subprocess.CompletedProcess[str]) -> RuntimeError:
        return RuntimeError(f"{self.name}: {' '.join(argv[:2])} failed: {(proc.stderr or proc.stdout).strip()[:300]}")


class LibvirtProvider(_CommandProvider):
    """libvirt snapshots via ``virsh`` (snapshot-create-as / snapshot-revert)."""

    name = "libvirt"

    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        super().__init__(cfg)
        self.virsh = str(self.cfg.get("virsh_path") or "virsh")

    def _require(self) -> None:
        if not self._which(self.virsh):
            raise RuntimeError(f"libvirt provider: {self.virsh!r} not found on PATH")

    def create(self, vm_id: str, label: str) -> SnapshotRef:
        self._require()
        snapname = _slug(label)
        argv = [self.virsh, "snapshot-create-as", vm_id, snapname]
        proc = self._run(argv)
        if proc.returncode != 0:
            raise self._fail(argv, proc)
        return SnapshotRef(
            provider=self.name,
            vm_id=vm_id,
            snapshot_id=snapname,
            label=label,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    def revert(self, vm_id: str, ref: SnapshotRef) -> None:
        self._require()
        argv = [self.virsh, "snapshot-revert", vm_id, "--snapshotname", ref.snapshot_id]
        proc = self._run(argv)
        if proc.returncode != 0:
            raise self._fail(argv, proc)

    def list(self, vm_id: str) -> list[SnapshotRef]:
        self._require()
        proc = self._run([self.virsh, "snapshot-list", vm_id, "--name"])
        if proc.returncode != 0:
            return []
        return [
            SnapshotRef(provider=self.name, vm_id=vm_id, snapshot_id=line.strip(), label=line.strip())
            for line in (proc.stdout or "").splitlines()
            if line.strip()
        ]

    def delete(self, vm_id: str, ref: SnapshotRef) -> None:
        self._require()
        proc = self._run([self.virsh, "snapshot-delete", vm_id, ref.snapshot_id])
        if proc.returncode != 0:
            raise self._fail([self.virsh, "snapshot-delete", vm_id], proc)


class HyperVProvider(_CommandProvider):
    """Hyper-V checkpoints via PowerShell (Windows-dev-friendly default).

    ``create`` builds the argv list; execution goes through the ``_run``
    wrapper (tests assert construction only).
    """

    name = "hyperv"

    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        super().__init__(cfg)
        self.powershell = str(self.cfg.get("powershell_command") or "powershell")

    def _ps_argv(self, script: str) -> list[str]:
        return [self.powershell, "-NoProfile", "-NonInteractive", "-Command", script]

    def create(self, vm_id: str, label: str) -> SnapshotRef:
        argv = self._ps_argv(f"Checkpoint-VM -Name '{vm_id}' -SnapshotName '{label}'")
        proc = self._run(argv)
        if proc.returncode != 0:
            raise self._fail(argv, proc)
        return SnapshotRef(
            provider=self.name,
            vm_id=vm_id,
            snapshot_id=label,
            label=label,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    def revert(self, vm_id: str, ref: SnapshotRef) -> None:
        if ref.snapshot_id:
            script = f"Restore-VMCheckpoint -Name '{vm_id}' -SnapshotName '{ref.snapshot_id}'"
        else:
            script = f"Restore-VMCheckpoint -Name '{vm_id}' -Latest"
        argv = self._ps_argv(script)
        proc = self._run(argv)
        if proc.returncode != 0:
            raise self._fail(argv, proc)

    def list(self, vm_id: str) -> list[SnapshotRef]:
        argv = self._ps_argv(f"Get-VMSnapshot -VMName '{vm_id}' | Select-Object -ExpandProperty Name")
        proc = self._run(argv)
        if proc.returncode != 0:
            return []
        return [
            SnapshotRef(provider=self.name, vm_id=vm_id, snapshot_id=line.strip(), label=line.strip())
            for line in (proc.stdout or "").splitlines()
            if line.strip()
        ]

    def delete(self, vm_id: str, ref: SnapshotRef) -> None:
        argv = self._ps_argv(f"Remove-VMSnapshot -VMName '{vm_id}' -Name '{ref.snapshot_id}'")
        proc = self._run(argv)
        if proc.returncode != 0:
            raise self._fail(argv, proc)


class VMwareProvider(_CommandProvider):
    """VMware Workstation snapshots via ``vmrun`` (vCenter = follow-up stub)."""

    name = "vmware"

    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        super().__init__(cfg)
        self.vmrun = str(self.cfg.get("vmrun_path") or "vmrun")

    def _require(self) -> None:
        if not self._which(self.vmrun):
            raise RuntimeError(f"vmware provider: {self.vmrun!r} not found on PATH")

    def create(self, vm_id: str, label: str) -> SnapshotRef:
        if vm_id.startswith("vi://"):
            raise NotImplementedError("vCenter (vi://) snapshots are a documented follow-up; use Workstation VMX paths")
        self._require()
        snapname = _slug(label)
        argv = [self.vmrun, "snapshot", vm_id, snapname]
        proc = self._run(argv)
        if proc.returncode != 0:
            raise self._fail(argv, proc)
        return SnapshotRef(
            provider=self.name,
            vm_id=vm_id,
            snapshot_id=snapname,
            label=label,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    def revert(self, vm_id: str, ref: SnapshotRef) -> None:
        self._require()
        argv = [self.vmrun, "revertToSnapshot", vm_id, ref.snapshot_id]
        proc = self._run(argv)
        if proc.returncode != 0:
            raise self._fail(argv, proc)

    def list(self, vm_id: str) -> list[SnapshotRef]:
        self._require()
        proc = self._run([self.vmrun, "listSnapshots", vm_id])
        if proc.returncode != 0:
            return []
        lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
        return [SnapshotRef(provider=self.name, vm_id=vm_id, snapshot_id=s, label=s) for s in lines[1:]]

    def delete(self, vm_id: str, ref: SnapshotRef) -> None:
        self._require()
        proc = self._run([self.vmrun, "deleteSnapshot", vm_id, ref.snapshot_id])
        if proc.returncode != 0:
            raise self._fail([self.vmrun, "deleteSnapshot", vm_id], proc)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDERS: dict[str, type] = {
    "docker": DockerProvider,
    "proxmox": ProxmoxProvider,
    "libvirt": LibvirtProvider,
    "hyperv": HyperVProvider,
    "vmware": VMwareProvider,
}


def get_provider(name: str, config: dict[str, Any] | None = None) -> SnapshotProvider:
    """Build a provider by name from the ``snapshots.providers`` config block."""
    cfg = config or {}
    provider_cfg = ((cfg.get("snapshots", {}) or {}).get("providers", {}) or {}).get(name, {}) or {}
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ValueError(f"unknown snapshot provider {name!r} (known: {', '.join(sorted(_PROVIDERS))})")
    instance = cls(provider_cfg)
    return instance  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Decision helper (pure; unit-tested without the loop)
# ---------------------------------------------------------------------------

_SNAPSHOT_CATEGORIES = {"credential_dumping", "exploit_execution", "lateral_movement"}


def should_snapshot(tool_name: str, payload: str, config: dict[str, Any] | None) -> bool:
    """Conservative documented rule for snapshot-before-destructive.

    True when (a) the payload trips ``command_analyzer._has_destructive``, OR
    (b) the tool's action category is one of credential_dumping /
    exploit_execution / lateral_movement (intrusive even when the text alone
    does not look destructive). Always False when ``snapshots.enabled`` is
    false or ``auto_before_destructive`` is off — never a gate, purely an
    extra safety net.
    """
    snap_cfg = (config or {}).get("snapshots", {}) or {}
    if not (bool(snap_cfg.get("enabled", False)) and bool(snap_cfg.get("auto_before_destructive", True))):
        return False
    from tools.command_analyzer import _has_destructive

    if _has_destructive(payload or "")[0]:
        return True
    from tools.exploit_agent.policy import _TOOL_ACTION_CATEGORY

    return _TOOL_ACTION_CATEGORY.get(tool_name) in _SNAPSHOT_CATEGORIES


def autonomy_pack_guidance(config: dict[str, Any] | None) -> str:
    """Fail-fast guidance when destructive autonomy is on without snapshots.

    P3-11 pack gate: killchain execution, counterfactual replay, and the
    persistence phase all run destructive steps that the snapshot safety
    net must cover. Returns "" when the pack is coherent (snapshots
    enabled, or no destructive-autonomy member on); otherwise a
    human-readable guidance string naming the offending flags and the fix.
    Pure; never raises. Callers (killchain_attempt, _phase_killchain,
    validator) refuse or warn on a non-empty return.
    """
    cfg = config or {}
    try:
        snap_cfg = cfg.get("snapshots", {}) or {}
        if bool(snap_cfg.get("enabled", False)):
            return ""
        offenders: list[str] = []
        kc_cfg = cfg.get("killchain", {}) or {}
        if isinstance(kc_cfg, dict) and bool(kc_cfg.get("enabled", False)):
            offenders.append("killchain.enabled")
        replay_cfg = cfg.get("replay_simulator", {}) or {}
        if isinstance(replay_cfg, dict) and bool(replay_cfg.get("counterfactual", False)):
            offenders.append("replay_simulator.counterfactual")
        auto_cfg = cfg.get("autonomous", {}) or {}
        if isinstance(auto_cfg, dict) and bool(auto_cfg.get("persistence_phase", False)):
            offenders.append("autonomous.persistence_phase")
        if not offenders:
            return ""
        return (
            "BLOCKED: destructive autonomy requires the snapshot safety net "
            f"({', '.join(offenders)} on but snapshots.enabled is false). "
            "Set snapshots.enabled: true with a snapshots.vm_map entry for "
            "each target (or SNAPSHOT_VM_MAP env), or turn the offending "
            "flags off. Snapshot failures are fail-open (log + proceed); "
            "running destructive autonomy with no net at all is not."
        )
    except Exception:  # ponytail: bare except intentional — malformed config means no gate
        return ""


def _vm_id_for_target(target: str, config: dict[str, Any] | None) -> str:
    """Map an attack target to a snapshottable vm_id (injectable seam).

    Reads ``snapshots.vm_map`` (``{"10.0.0.50": "breachpilot-metasploitable2"}``)
    then ``SNAPSHOT_VM_MAP`` env (``10.0.0.50=container``), falling back to
    the raw target string.
    """
    cfg = config or {}
    mapping = ((cfg.get("snapshots", {}) or {}).get("vm_map", {}) or {}) or {}
    if target in mapping:
        return str(mapping[target])
    for pair in os.environ.get("SNAPSHOT_VM_MAP", "").split(","):
        key, _, val = pair.partition("=")
        if key.strip() == target and val.strip():
            return val.strip()
    return target


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class SnapshotManager:
    """Gate-keeping wrapper around one provider.

    - Fails open: every method returns ``None``/``[]``/swallows errors — a
      broken hypervisor must never break the attack path.
    - Enforces ``max_snapshots_per_target`` (delete-oldest beyond cap).
    - Persists refs in ``snapshots_index.json`` under ``index_dir`` so refs
      survive process restarts.
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        provider: SnapshotProvider | None = None,
        index_dir: str | Path = ".",
        now_fn: Any = None,
    ) -> None:
        self.config = config or {}
        snap_cfg = (self.config.get("snapshots", {}) or {}) or {}
        self.enabled = bool(snap_cfg.get("enabled", False))
        self.auto_before_destructive = bool(snap_cfg.get("auto_before_destructive", True))
        self.max_per_target = max(0, int(snap_cfg.get("max_snapshots_per_target", 3) or 0))
        self.provider = provider or get_provider(str(snap_cfg.get("provider", "docker")), self.config)
        self.index_path = Path(index_dir) / "snapshots_index.json"
        self._now_fn = now_fn or (lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    # -- index ---------------------------------------------------------------

    def _read_index(self) -> dict[str, list[dict[str, Any]]]:
        try:
            return json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _write_index(self, index: dict[str, list[dict[str, Any]]]) -> None:
        try:
            self.index_path.parent.mkdir(parents=True, exist_ok=True)
            self.index_path.write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            pass

    def _record(self, ref: SnapshotRef) -> None:
        index = self._read_index()
        rows = index.setdefault(ref.vm_id, [])
        rows.append(ref.to_dict())
        index[ref.vm_id] = rows[-50:]
        self._write_index(index)

    # -- API -----------------------------------------------------------------

    def before_destructive(self, vm_id: str, label: str) -> SnapshotRef | None:
        """Take a pre-destructive snapshot (None when disabled/failed = no-op)."""
        if not (self.enabled and self.auto_before_destructive):
            return None
        try:
            ref = self.provider.create(vm_id, label)
        except Exception as exc:  # noqa: BLE001 -- fail-open, never break the attack
            # ponytail: fail-open contract kept — only a warning log is added.
            logging.getLogger(__name__).warning("snapshot before %s failed (continuing): %s", label, exc)
            return None
        self._record(ref)
        self._enforce_cap(vm_id)
        return ref

    def _enforce_cap(self, vm_id: str) -> None:
        if self.max_per_target <= 0:
            return
        index = self._read_index()
        rows = index.get(vm_id, [])
        while len(rows) > self.max_per_target:
            oldest = rows.pop(0)
            try:
                self.provider.delete(vm_id, SnapshotRef.from_dict(oldest))
            except Exception:  # noqa: BLE001
                pass
        index[vm_id] = rows
        self._write_index(index)

    def revert(self, vm_id: str, ref: SnapshotRef | str) -> SnapshotRef | None:
        """Revert to a ref (or snapshot id); returns the ref used, None on failure."""
        if not self.enabled:
            return None
        if isinstance(ref, str):
            match = [SnapshotRef.from_dict(r) for r in self._read_index().get(vm_id, []) if r.get("snapshot_id") == ref]
            if not match:
                match = [SnapshotRef(provider="", vm_id=vm_id, snapshot_id=ref, label=ref)]
            resolved: SnapshotRef = match[-1]
        else:
            resolved = ref
        try:
            self.provider.revert(vm_id, resolved)
        except Exception:  # noqa: BLE001
            return None
        return resolved

    def list(self, vm_id: str) -> list[SnapshotRef]:
        rows = self._read_index().get(vm_id, [])
        return [SnapshotRef.from_dict(r) for r in rows]

    def delete(self, vm_id: str, ref: SnapshotRef | str) -> bool:
        if not self.enabled:
            return False
        target_ref = (
            ref
            if isinstance(ref, SnapshotRef)
            else SnapshotRef(provider="", vm_id=vm_id, snapshot_id=str(ref), label="")
        )
        try:
            self.provider.delete(vm_id, target_ref)
        except Exception:  # noqa: BLE001
            return False
        index = self._read_index()
        index[vm_id] = [r for r in index.get(vm_id, []) if r.get("snapshot_id") != target_ref.snapshot_id]
        self._write_index(index)
        return True
