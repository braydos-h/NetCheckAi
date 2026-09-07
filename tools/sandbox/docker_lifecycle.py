"""Opt-in Docker daemon lifecycle for BreachPilot sandbox sessions.

The sandbox worker is a per-session resource, but the Docker daemon is a
machine-level service. This module lets an operator keep Docker stopped while
BreachPilot is idle and temporarily start it for a sandboxed session.

The lifecycle is deliberately conservative:

* it is disabled unless ``sandbox.auto_manage_docker`` is true;
* an already-running daemon is never claimed or stopped by BreachPilot;
* Linux startup uses ``sudo -n`` so a background MCP server never hangs on a
  password prompt (``sudo -v`` before starting BP can cache authorization);
* shutdown is skipped when any Docker container is still running; and
* a daemon-start failure is returned to the existing fail-closed/fallback boot
  decision rather than changing execution posture mid-session.
"""

from __future__ import annotations

import atexit
import logging
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

from tools.sandbox import docker_backend as _db

logger = logging.getLogger(__name__)

Probe = Callable[[], tuple[bool, str]]
Runner = Callable[[list[str], int], tuple[int, str, str]]
Sleeper = Callable[[float], None]

_DEFAULT_START_TIMEOUT_SECONDS = 60.0
_DEFAULT_STOP_TIMEOUT_SECONDS = 30.0
_POLL_SECONDS = 0.5


def _run(argv: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a fixed platform-service argv without a shell."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)  # noqa: S603 -- fixed argv
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, "", f"timed out after {timeout}s: {exc}"
    except OSError as exc:
        return 127, "", str(exc)


def _platform_name() -> str:
    value = platform.system().lower()
    if value.startswith("win"):
        return "windows"
    if value == "darwin":
        return "darwin"
    if value == "linux":
        return "linux"
    return value or "unknown"


def _service_method(platform_name: str) -> str | None:
    if platform_name == "linux":
        if shutil.which("systemctl"):
            return "systemctl"
        if shutil.which("service"):
            return "service"
        return None
    if platform_name == "darwin":
        return "open" if shutil.which("open") else None
    if platform_name == "windows":
        return "powershell" if shutil.which("powershell") else None
    return None


def _service_argv(platform_name: str, method: str, action: str) -> list[str] | None:
    if platform_name == "linux":
        if method == "systemctl":
            return ["sudo", "-n", "systemctl", action, "docker"]
        if method == "service":
            return ["sudo", "-n", "service", "docker", action]
        return None
    if platform_name == "darwin":
        if action == "start" and method == "open":
            return ["open", "-a", "Docker"]
        if action == "stop" and method == "open":
            return ["osascript", "-e", 'tell application "Docker" to quit']
        return None
    if platform_name == "windows" and method == "powershell":
        if action == "start":
            return [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Process 'Docker Desktop'",
            ]
        if action == "stop":
            return [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue | Stop-Process",
            ]
    return None


def _short_error(stdout: str, stderr: str) -> str:
    text = (stderr or stdout or "service command failed").strip()
    return text[:300]


@dataclass
class DockerLifecycle:
    """Acquire/release ownership of a Docker daemon for one BP process."""

    enabled: bool = False
    start_timeout_seconds: float = _DEFAULT_START_TIMEOUT_SECONDS
    stop_timeout_seconds: float = _DEFAULT_STOP_TIMEOUT_SECONDS
    probe: Probe | None = None
    runner: Runner = _run
    sleeper: Sleeper = time.sleep
    platform_name: str | None = None
    service_method: str | None = None
    started_by_us: bool = False
    _released: bool = False
    _atexit_registered: bool = False

    @classmethod
    def from_config(
        cls,
        config: dict[str, object] | None,
        *,
        probe: Probe | None = None,
        runner: Runner = _run,
        sleeper: Sleeper = time.sleep,
    ) -> "DockerLifecycle":
        section = (config or {}).get("sandbox")
        sandbox = section if isinstance(section, dict) else {}

        def positive_float(name: str, default: float) -> float:
            try:
                value = float(sandbox.get(name, default))
            except (TypeError, ValueError):
                return default
            return value if value >= 1.0 else default

        return cls(
            enabled=bool(sandbox.get("auto_manage_docker", False)),
            start_timeout_seconds=positive_float("docker_start_timeout_seconds", _DEFAULT_START_TIMEOUT_SECONDS),
            stop_timeout_seconds=positive_float("docker_stop_timeout_seconds", _DEFAULT_STOP_TIMEOUT_SECONDS),
            probe=probe,
            runner=runner,
            sleeper=sleeper,
        )

    def acquire(self) -> tuple[bool, str]:
        """Ensure Docker is reachable, starting it only when explicitly enabled."""
        ok, reason = self._probe()
        if ok:
            return True, ""
        if not self.enabled:
            return False, reason

        platform_name = self.platform_name or _platform_name()
        method = self.service_method or _service_method(platform_name)
        argv = _service_argv(platform_name, method or "", "start") if method else None
        if not argv:
            return False, f"Docker is unavailable and no supported automatic start method exists ({platform_name})"

        rc, stdout, stderr = self.runner(argv, 30)
        command_error = _short_error(stdout, stderr) if rc != 0 else ""
        if rc != 0:
            return False, f"automatic Docker start failed: {command_error}"
        deadline = time.monotonic() + self.start_timeout_seconds
        last_reason = command_error or reason or "Docker daemon not ready"
        while time.monotonic() < deadline:
            ok, probe_reason = self._probe()
            if ok:
                self.started_by_us = True
                if not self._atexit_registered:
                    atexit.register(self.release)
                    self._atexit_registered = True
                logger.info("Docker daemon started by BreachPilot (%s)", platform_name)
                return True, ""
            last_reason = probe_reason or last_reason
            remaining = max(0.0, deadline - time.monotonic())
            self.sleeper(min(_POLL_SECONDS, remaining))

        return False, f"Docker daemon did not become ready within {self.start_timeout_seconds:.0f}s: {last_reason}"

    def release(self) -> dict[str, object]:
        """Stop Docker only when BP started it and the daemon is idle."""
        if self._released:
            return {"stopped": False, "reason": "already released"}
        self._released = True
        if not self.started_by_us:
            return {"stopped": False, "reason": "Docker was already running or auto-management was disabled"}

        running = _db.docker_running_containers()
        if running is None:
            return {"stopped": False, "reason": "Docker became unreachable; left service state unchanged"}
        if running:
            logger.info("Leaving Docker running; %d container(s) are still active", len(running))
            return {"stopped": False, "reason": "running containers remain", "containers": len(running)}

        platform_name = self.platform_name or _platform_name()
        method = self.service_method or _service_method(platform_name)
        argv = _service_argv(platform_name, method or "", "stop") if method else None
        if not argv:
            return {"stopped": False, "reason": f"no supported automatic stop method exists ({platform_name})"}
        rc, stdout, stderr = self.runner(argv, int(self.stop_timeout_seconds))
        if rc != 0:
            reason = _short_error(stdout, stderr)
            logger.warning("Automatic Docker stop failed: %s", reason)
            return {"stopped": False, "reason": reason}
        logger.info("Docker daemon stopped by BreachPilot")
        return {"stopped": True, "reason": "stopped because BP owned the daemon and it was idle"}

    def _probe(self) -> tuple[bool, str]:
        try:
            return (self.probe or _db.docker_version)()
        except Exception as exc:  # noqa: BLE001 -- lifecycle must feed the existing boot decision
            return False, f"Docker probe failed: {exc}"


__all__ = ["DockerLifecycle"]
