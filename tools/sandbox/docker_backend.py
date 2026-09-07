"""Docker backend for the disposable worker sandbox.

House convention (mirrors ``tools/snapshots.py``): every Docker CLI call goes
through a NAMED module-level wrapper function; tests monkeypatch the wrappers,
never ``subprocess``. The ``DockerBackend`` class composes the wrappers and is
the only Docker-aware component the rest of the codebase touches -- nothing
outside ``tools/sandbox`` may see raw Docker internals.

Worker hardening is enforced in ``_build_create_args``:

- ``--cap-drop ALL`` with only ``NET_RAW`` added back (no ``NET_ADMIN``: the
  worker can never edit its own netns firewall; that grant belongs exclusively
  to the ephemeral firewall sidecar in ``tools/sandbox/network.py``)
- ``--security-opt no-new-privileges``, no ``--privileged``
- ``--read-only`` rootfs (when configured) + ``--tmpfs /tmp``
- ``--memory`` / ``--memory-swap`` / ``--cpus`` / ``--pids-limit``
- dedicated per-run bridge network (never ``host``, never a shared network)
- NO docker.sock, NO host mounts other than the validated run workspace,
  no devices, no host pid/ipc namespaces
- labels ``breachpilot=true`` / ``run_id=<id>`` -- stale cleanup and audits
  identify OUR resources only; existing containers are NEVER reused
"""

from __future__ import annotations

import logging
import subprocess
import time
from typing import Any

from tools.sandbox.exceptions import SandboxUnavailableError
from tools.sandbox.models import SandboxSpec

logger = logging.getLogger(__name__)

__all__ = [
    "_docker",
    "DockerCommandTimeout",
    "docker_version",
    "docker_image_exists",
    "docker_network_create",
    "docker_network_inspect",
    "docker_network_gateway",
    "docker_network_list_stale",
    "docker_container_list_stale",
    "docker_running_containers",
    "docker_inspect_state",
    "docker_rm",
    "docker_network_rm",
    "run_netns_sidecar",
    "DockerBackend",
    "_build_create_args",
    "DOCKER_TIMEOUT",
]

DOCKER_TIMEOUT = 60
# Host-side hard stop runs this much beyond the container-inner `timeout` TERM.
EXEC_KILL_GRACE_SECONDS = 10


class DockerCommandTimeout(SandboxUnavailableError, TimeoutError):
    """``docker`` CLI call exceeded its host-side timeout.

    Dual-typed on purpose: verb wrappers treat it as ``SandboxUnavailableError``
    (fail closed), while ``DockerBackend.exec`` re-raises it as a bare
    ``TimeoutError`` so the manager can report a normal command timeout (the
    agent's command ran long) instead of claiming the sandbox broke.
    """


def _docker(*args: str, timeout: int = DOCKER_TIMEOUT, input_text: str = "") -> tuple[int, str, str]:
    """Named seam: single Docker CLI call. Returns (rc, stdout, stderr).

    All sandbox Docker access MUST go through here (or a verb wrapper below);
    tests monkeypatch this module's wrapper functions, never subprocess.
    Missing CLI / daemon down raise ``SandboxUnavailableError`` so every caller
    fail-closes; a host-side timeout raises ``DockerCommandTimeout``.
    """
    try:
        # Binary mode on purpose: text-mode pipes translate "\n" to os.linesep
        # ("\r\n" on Windows), which corrupts iptables-restore rulesets fed on
        # stdin ("table name 'filter' invalid", Windows-only failure).
        proc = subprocess.run(  # noqa: S603 -- fixed binary, args fully constructed
            ["docker", *args],
            capture_output=True,
            timeout=timeout,
            input=input_text.encode("utf-8") if input_text else None,
        )
        out = proc.stdout.decode("utf-8", errors="replace") if isinstance(proc.stdout, bytes) else (proc.stdout or "")
        err = proc.stderr.decode("utf-8", errors="replace") if isinstance(proc.stderr, bytes) else (proc.stderr or "")
        return proc.returncode, out, err
    except FileNotFoundError:
        raise SandboxUnavailableError(
            "Docker CLI not found on PATH. Install Docker Desktop (Windows/macOS) or "
            "'docker.io'/'docker-ce' (Linux), or set sandbox.enabled: false to keep the "
            "legacy (uncontained) host-execution mode."
        ) from None
    except subprocess.TimeoutExpired:
        raise DockerCommandTimeout(f"docker {' '.join(args[:2])} timed out after {timeout}s") from None
    except OSError as exc:
        raise SandboxUnavailableError(f"docker {' '.join(args[:2])} failed: {exc}") from None


def docker_version() -> tuple[bool, str]:
    """(daemon_reachable, version_or_error) probe."""
    try:
        rc, out, err = _docker("version", "--format", "{{.Server.Version}}", timeout=20)
    except SandboxUnavailableError as exc:
        return False, str(exc)
    if rc != 0:
        return False, (err or out or "docker daemon unreachable").strip()[:200]
    return True, out.strip()


def docker_image_exists(image: str) -> bool:
    try:
        rc, _out, _err = _docker("image", "inspect", image)
    except SandboxUnavailableError:
        raise
    return rc == 0


def docker_network_create(name: str) -> str:
    rc, _out, err = _docker("network", "create", "--driver", "bridge", name)
    if rc != 0:
        raise SandboxUnavailableError(f"docker network create failed: {err.strip()[:200]}")
    return name


def docker_network_inspect(name: str) -> dict[str, Any] | None:
    rc, out, _err = _docker("network", "inspect", name, "--format", "{{json .}}", timeout=30)
    if rc != 0:
        return None
    try:
        import json

        return dict(json.loads(out))
    except (ValueError, TypeError):
        return None


def docker_network_gateway(name: str) -> str:
    info = docker_network_inspect(name)
    if not info:
        return ""
    ipam = (info.get("IPAM") or {}).get("Config") or []
    for cfg in ipam:
        gw = str(cfg.get("Gateway", "") or "")
        if gw:
            return gw
    return ""


def docker_network_list_stale(*, label: str = "breachpilot=true") -> list[str]:
    rc, out, _err = _docker("network", "ls", "--filter", f"label={label}", "--format", "{{.Name}}", timeout=30)
    if rc != 0:
        return []
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def docker_container_list_stale(*, label: str = "breachpilot=true") -> list[str]:
    rc, out, _err = _docker("ps", "-a", "--filter", f"label={label}", "--format", "{{.Names}}", timeout=30)
    if rc != 0:
        return []
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def docker_running_containers() -> list[str] | None:
    """Return running container IDs, or ``None`` when Docker is unreachable."""
    try:
        rc, out, _err = _docker("ps", "-q", timeout=30)
    except SandboxUnavailableError:
        return None
    if rc != 0:
        return None
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def docker_inspect_state(container_id: str) -> str:
    rc, out, _err = _docker("inspect", "-f", "{{.State.Status}}", container_id, timeout=20)
    return out.strip() if rc == 0 else ""


def docker_rm(name: str) -> bool:
    try:
        rc, _out, _err = _docker("rm", "-f", name, timeout=90)
    except SandboxUnavailableError:
        return False
    return rc == 0


def docker_network_rm(name: str) -> bool:
    try:
        rc, _out, _err = _docker("network", "rm", name, timeout=60)
    except SandboxUnavailableError:
        return False
    return rc == 0


def run_netns_sidecar(container_id: str, image: str, binary: str, rules_text: str) -> tuple[int, str, str]:
    """Named seam: firewall installer.

    Runs an ephemeral sidecar sharing the WORKER's network namespace with a
    temporary ``NET_ADMIN`` grant (docker removes the netns grant when it
    exits). The ruleset arrives on stdin; the sidecar is ``--rm``. The worker
    itself never receives NET_ADMIN, so agent commands cannot undo this.
    """
    return _docker(
        "run",
        "--rm",
        "-i",
        "--network",
        f"container:{container_id}",
        "--cap-add",
        "NET_ADMIN",
        "--entrypoint",
        binary,
        image,
        timeout=90,
        input_text=rules_text,
    )


def _validate_container_id(container_id: str) -> str:
    cid = str(container_id).strip()
    if not cid or any(c in cid for c in " ;|`$\n\r\\\"'"):
        raise SandboxUnavailableError("invalid sandbox container id")
    return cid


def _build_create_args(spec: SandboxSpec, *, cap_raw: bool, read_only_rootfs: bool) -> list[str]:
    """The hardened ``docker create`` argv. Pure function -- fully unit-tested.

    Host-protection invariants asserted here: no docker.sock, no host root /
    home / arbitrary host dirs, no devices, no privileged/host pid/ipc, only
    the validated run workspace is bound (rw), everything else denied.
    """
    image = str(spec.image or "").strip()
    if not image or any(c in image for c in ";|`$\n\r") or image.startswith("-"):
        raise SandboxUnavailableError(f"invalid sandbox image {image!r}")
    cver = _validate_container_id(spec.sandbox_id)
    user = str(spec.user or "sandbox").strip()
    src = str(spec.workspace_src or "").strip()
    if not src:
        raise SandboxUnavailableError("worker requires a validated workspace bind")
    args = [
        "create",
        "--name",
        cver,
        "--network",
        str(spec.network_name),
        "--label",
        "breachpilot=true",
        "--label",
        f"run_id={spec.labels.get('run_id', '')}",
        # Capabilities: drop everything; NET_RAW only when configured for raw
        # packet scanning. NET_ADMIN is deliberately NEVER granted here.
        "--cap-drop",
        "ALL",
    ]
    if cap_raw:
        args += ["--cap-add", "NET_RAW"]
    args += [
        "--security-opt",
        "no-new-privileges",
        "--user",
        user,
        "--memory",
        f"{int(spec.memory_mb)}m",
        "--memory-swap",
        f"{int(spec.memory_mb)}m",
        "--cpus",
        str(spec.cpus),
        "--pids-limit",
        str(int(spec.pids_limit)),
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "-v",
        f"{src}:/workspace:rw",
        "-w",
        "/workspace",
    ]
    if read_only_rootfs:
        args.append("--read-only")
    args.append(image)
    # Keepalive: the worker must stay alive for `docker exec` and netns firewall.
    # The image's CMD is /bin/bash (exits immediately when not interactive), so
    # the manager must override it with a long-lived process. `sleep infinity`
    # is tiny, handles SIGTERM cleanly, and exists in the debian image.
    args += ["sleep", "infinity"]
    return args


class DockerBackend:
    """Composes the wrapper seams; one method per lifecycle step.

    All failures raise ``SandboxUnavailableError`` so the manager fail-closes
    (offensive execution blocked; never a silent host fallback).
    """

    def __init__(self, *, cap_raw: bool = True, exec_seam: Any = None) -> None:
        self.cap_raw = cap_raw
        # exec_seam allows callers (tests) to swap the docker-exec wrapper.
        self._exec_seam = exec_seam

    def ensure_docker(self) -> None:
        ok, reason = docker_version()
        if not ok:
            raise SandboxUnavailableError(
                f"Docker daemon unreachable: {reason}. Offensive execution is blocked "
                "(fail-closed); start Docker or set sandbox.enabled: false."
            )

    def ensure_image(self, image: str) -> None:
        if not docker_image_exists(image):
            raise SandboxUnavailableError(
                f"sandbox image {image!r} not found. Build it with: 'docker build -t <image> docker/sandbox'."
            )

    def create_network(self, name: str) -> str:
        return docker_network_create(name)

    def create_worker(self, spec: SandboxSpec, *, read_only_rootfs: bool) -> str:
        argv = _build_create_args(spec, cap_raw=self.cap_raw, read_only_rootfs=read_only_rootfs)
        rc, out, err = _docker(*argv)
        if rc != 0:
            raise SandboxUnavailableError(f"docker create failed: {(err or out).strip()[:300]}")
        container = out.strip()
        rc2, _o2, err2 = _docker("start", container)
        if rc2 != 0:
            docker_rm(container)
            raise SandboxUnavailableError(f"docker start failed: {err2.strip()[:300]}")
        # The worker's keepalive (sleep infinity) must be observed as running
        # before the caller joins its netns. Poll briefly; fail closed if it
        # never reaches running (exited / dead).
        for _ in range(30):
            state = docker_inspect_state(container)
            if state == "running":
                break
            if state in ("exited", "dead"):
                docker_rm(container)
                raise SandboxUnavailableError(f"sandbox worker {container} exited immediately (state={state})")
            time.sleep(0.1)
        else:
            docker_rm(container)
            raise SandboxUnavailableError(f"sandbox worker {container} not running after start")
        return container

    def render_firewall(self, container_id: str, image: str, binary: str, rules_text: str) -> tuple[int, str, str]:
        return run_netns_sidecar(container_id, image, binary, rules_text)

    def exec(
        self,
        container_id: str,
        argv: list[str],
        *,
        timeout: int,
        user: str = "",
        env: dict[str, str] | None = None,
        input_text: str = "",
        workdir: str = "",
    ) -> tuple[int, str, str]:
        """Run a command inside the running worker. Returns (rc, stdout, stderr).

        The container-inner ``timeout`` (TERM→KILL) is the primary bound; the
        host-side timeout is the hard stop. Environment is allowlisted by the
        manager, never a copy of the host environment. ``workdir`` must be an
        absolute container path (the manager maps host workspace paths onto
        ``/workspace``); anything else is rejected.
        """
        cid = _validate_container_id(container_id)
        workdir = str(workdir or "").strip()
        if workdir and (not workdir.startswith("/") or ".." in workdir.split("/")):
            raise SandboxUnavailableError(f"invalid sandbox workdir {workdir!r}")
        docker_argv: list[str] = ["exec"]
        if workdir:
            docker_argv += ["-w", workdir]
        if user:
            docker_argv += ["--user", user]
        for key, value in (env or {}).items():
            _validate_env_key(key)
            docker_argv += ["--env", f"{key}={value}"]
        docker_argv += [cid, *argv]
        if self._exec_seam is not None:
            return self._exec_seam(docker_argv, timeout, input_text=input_text)
        try:
            return _docker(*docker_argv, timeout=timeout)
        except DockerCommandTimeout as exc:
            # A long-running agent command is a normal timeout, not sandbox breakage.
            raise TimeoutError(str(exc)) from None

    def stop(self, container_id: str) -> None:
        _validate_container_id(container_id)
        try:
            _docker("stop", "-t", "5", container_id, timeout=30)
        except SandboxUnavailableError:
            logger.warning("sandbox stop %s failed", container_id)

    def destroy(self, container_id: str, network_name: str) -> dict[str, bool]:
        """Terminate + remove the worker and its dedicated network (best per-op answer)."""
        results = {"container_removed": docker_rm(container_id), "network_removed": docker_network_rm(network_name)}
        if not all(results.values()):
            logger.warning("sandbox destroy incomplete: %s", results)
        return results


def _validate_env_key(key: str) -> None:
    if not str(key).strip() or any(c in str(key) for c in "= \n\r") or str(key).startswith("-"):
        raise SandboxUnavailableError(f"invalid sandbox env key {key!r}")
