"""Docker sandbox remediation: plan + execution.

This module implements the host-level fix flow for the sandbox warning shown on
the Home page (mode native_fallback / blocked). It runs entirely server-side
(Browser -> enum job, not arbitrary commands) and is localhost/auth protected
via the existing API conventions.

Invariants:
- Never download and execute arbitrary shell scripts.
- Never use shell=True with untrusted strings.
- All subprocess calls use explicit argv arrays + timeouts + capture.
- The browser never sends arbitrary paths/package names/commands.
- The Docker build always uses the server's known repo root (docker/sandbox).
- Errors are sanitized/truncated (no host secrets).
- sandbox.enabled:false is never treated as success.
"""

from __future__ import annotations

import asyncio
import platform
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.sandbox import docker_backend as _db

# ── constants ─────────────────────────────────────────────────────────────────

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
DOCKER_SANDBOX_DIR: Path = REPO_ROOT / "docker" / "sandbox"
IMAGE_NAME = "breachpilot-sandbox:latest"
MAX_OUTPUT = 4000  # per step output truncation
POLL_INTERVAL = 2.0
DAEMON_POLL_TIMEOUT = 60  # seconds to wait for daemon after start
BUILD_TIMEOUT = 600  # docker build can be slow


def _sanitize(text: str, limit: int = 2000) -> str:
    """Truncate + strip. No secrets are expected here but we keep output bounded."""
    if not text:
        return ""
    t = str(text).strip()
    if len(t) > limit:
        t = t[:limit] + "\n…[truncated]"
    # Avoid leaking absolute user paths excessively? keep as-is but truncated.
    return t


def _which(cmd: str) -> str | None:
    return shutil.which(cmd)


def _platform() -> str:
    sys = platform.system().lower()
    if sys.startswith("win"):
        return "windows"
    if sys == "darwin":
        return "darwin"
    if sys == "linux":
        return "linux"
    return sys or "unknown"


def _run(argv: list[str], *, timeout: int = 30, cwd: Path | None = None) -> tuple[int, str, str]:
    """Run argv array, capture output. No shell. Timeout guards all calls."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "" if isinstance(exc.stdout, str) else "", f"timed out after {timeout}s: {exc}"
    except OSError as exc:
        return 127, "", str(exc)


def _detect_install_method(platform_name: str) -> str | None:
    if platform_name == "linux":
        for pm in ("apt-get", "apt", "dnf", "yum", "pacman", "zypper", "apk"):
            if _which(pm):
                return pm
        return None
    if platform_name == "windows":
        return "winget" if _which("winget") else None
    if platform_name == "darwin":
        return "brew" if _which("brew") else None
    return None


def _detect_service_method(platform_name: str) -> str | None:
    if platform_name == "linux":
        if _which("systemctl"):
            return "systemctl"
        if _which("service"):
            return "service"
        return None
    if platform_name == "windows":
        # Docker Desktop presence check – best effort
        candidates = [
            Path("C:/Program Files/Docker/Docker/Docker Desktop.exe"),
            Path("C:/Program Files/Docker/Docker/resources/bin/docker.exe"),
        ]
        if any(p.exists() for p in candidates) or _which("docker"):
            return "docker_desktop"
        return "docker_desktop"
    if platform_name == "darwin":
        if _which("open"):
            return "open"
        return None
    return None


def _image_name_from_config(config: dict[str, Any] | None) -> str:
    try:
        from tools.sandbox.models import SandboxConfig

        cfg = SandboxConfig.from_config(config)
        if cfg.image:
            return cfg.image
    except Exception:  # noqa: BLE001 -- config probe fallback to default image; boot must not fail on unreadable config
        pass
    return IMAGE_NAME


# ── plan model ────────────────────────────────────────────────────────────────


@dataclass
class PlanStep:
    id: str
    title: str
    description: str
    command_preview: str | None
    requires_admin: bool = False
    manual: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "command_preview": self.command_preview,
            "requires_admin": self.requires_admin,
        }
        if self.manual:
            d["manual"] = True
        return d


def _is_permission_error(reason: str) -> bool:
    low = reason.lower()
    return "permission denied" in low or "permissiondenied" in low or "access is denied" in low


def build_plan(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the remediation plan (read-only). No side effects.

    Returns dict matching the suggested response shape:
    {
      platform, reason, docker_cli_present, docker_daemon_running,
      image_present, requires_admin, steps[]
    }
    Plus mode/disabled metadata for frontend gating.
    """
    from tools.sandbox.models import SandboxConfig

    platform_name = _platform()
    cfg = SandboxConfig.from_config(config)
    image = _image_name_from_config(config)

    # If sandbox intentionally disabled, no fix is offered.
    if not cfg.enabled:
        return {
            "platform": platform_name,
            "reason": "Sandbox is intentionally disabled (sandbox.enabled: false). Enable it in config.yaml to use containment.",
            "docker_cli_present": bool(_which("docker")),
            "docker_daemon_running": False,
            "image_present": None,
            "requires_admin": False,
            "steps": [],
            "mode": "disabled",
            "manual": False,
        }

    docker_cli_present = bool(_which("docker"))
    docker_daemon_running = False
    daemon_reason = ""
    image_present: bool | None = None
    docker_error = ""

    if docker_cli_present:
        try:
            ok, reason = _db.docker_version()
            docker_daemon_running = bool(ok)
            if ok:
                daemon_reason = reason.strip()
            else:
                docker_error = _sanitize(reason, 800)
                daemon_reason = docker_error
        except Exception as exc:  # noqa: BLE001 — probe must never break plan
            docker_daemon_running = False
            docker_error = _sanitize(str(exc), 800)
            daemon_reason = docker_error
        if docker_daemon_running:
            try:
                image_present = bool(_db.docker_image_exists(image))
            except Exception as exc:  # noqa: BLE001
                image_present = False
                docker_error = _sanitize(str(exc), 800)
        else:
            image_present = None
    else:
        docker_error = (
            "Docker CLI not found on PATH. Install Docker Desktop (Windows/macOS) or docker.io/docker-ce (Linux)."
        )
        daemon_reason = docker_error
        image_present = False

    # Determine overall reason for banner/dialog top explain
    # Prefer boot state reason if available? But plan is live probe; we surface daemon_reason or image missing.
    reason = ""
    if not docker_cli_present:
        reason = docker_error
    elif not docker_daemon_running:
        reason = daemon_reason or docker_error or "Docker daemon is not running."
        if _is_permission_error(reason):
            reason = reason + " (permission denied – current user may not be in the docker group)"
    elif image_present is False:
        reason = f"sandbox image '{image}' not built"
    else:
        reason = daemon_reason or "Docker and sandbox image are ready."

    steps: list[PlanStep] = []

    # 1. Detect OS
    steps.append(
        PlanStep(
            id="detect_os",
            title="Detect operating system",
            description=f"Detected platform: {platform_name} ({platform.platform()}).",
            command_preview=None,
            requires_admin=False,
        )
    )

    # 2. Check Docker CLI
    steps.append(
        PlanStep(
            id="check_docker_cli",
            title="Check whether the Docker CLI is installed",
            description="Verify that the 'docker' command is available on PATH."
            if docker_cli_present
            else "The Docker CLI was not found on PATH.",
            command_preview="docker --version",
            requires_admin=False,
        )
    )

    install_method = _detect_install_method(platform_name)
    service_method = _detect_service_method(platform_name)

    # 3. Install Docker if missing
    if not docker_cli_present:
        if install_method:
            if platform_name == "linux":
                if install_method in ("apt-get", "apt"):
                    preview = "sudo apt-get update && sudo apt-get install -y docker.io"
                    desc = "Install Docker using apt (requires administrator privileges via sudo)."
                elif install_method == "dnf":
                    preview = "sudo dnf install -y docker"
                    desc = "Install Docker using dnf (requires administrator privileges)."
                elif install_method == "yum":
                    preview = "sudo yum install -y docker"
                    desc = "Install Docker using yum (requires administrator privileges)."
                elif install_method == "pacman":
                    preview = "sudo pacman -S --noconfirm docker"
                    desc = "Install Docker using pacman (requires administrator privileges)."
                elif install_method == "zypper":
                    preview = "sudo zypper install -y docker"
                    desc = "Install Docker using zypper (requires administrator privileges)."
                elif install_method == "apk":
                    preview = "sudo apk add docker"
                    desc = "Install Docker using apk (requires administrator privileges)."
                else:
                    preview = f"{install_method} install docker"
                    desc = f"Install Docker using {install_method} (requires administrator privileges)."
            elif platform_name == "windows":
                preview = "winget install -e --id Docker.DockerDesktop"
                desc = (
                    "Install Docker Desktop using winget (requires administrator privileges and may require a restart)."
                )
            elif platform_name == "darwin":
                preview = "brew install --cask docker"
                desc = "Install Docker Desktop using Homebrew (requires administrator privileges)."
            else:
                preview = None
                desc = f"Automatic Docker installation is not supported on {platform_name}."
            steps.append(
                PlanStep(
                    id="install_docker",
                    title="Install Docker",
                    description=desc,
                    command_preview=preview,
                    requires_admin=True,
                    manual=preview is None,
                )
            )
        else:
            if platform_name == "linux":
                desc = "No supported package manager detected (apt/dnf/yum/pacman/zypper/apk). Please install Docker manually from https://docs.docker.com/engine/install/."
            elif platform_name == "windows":
                desc = "winget not found. Please install Docker Desktop manually from https://docs.docker.com/desktop/install/windows-install/."
            elif platform_name == "darwin":
                desc = "Homebrew not found. Please install Docker Desktop manually from https://docs.docker.com/desktop/install/mac-install/."
            else:
                desc = f"Automatic Docker installation is not supported on {platform_name}. Please install Docker manually."
            steps.append(
                PlanStep(
                    id="install_docker",
                    title="Install Docker",
                    description=desc,
                    command_preview=None,
                    requires_admin=True,
                    manual=True,
                )
            )

    # 4. Check daemon
    steps.append(
        PlanStep(
            id="check_daemon",
            title="Check whether the Docker daemon / Docker Desktop is running",
            description="Probe the Docker daemon with 'docker version' to ensure the server side responds."
            if docker_daemon_running
            else "Docker daemon does not appear to be running.",
            command_preview="docker version --format '{{.Server.Version}}'",
            requires_admin=False,
        )
    )

    # Permission handling note as a step if detected
    if _is_permission_error(daemon_reason):
        steps.append(
            PlanStep(
                id="check_permissions",
                title="Check Docker socket permissions",
                description="Docker is installed but the current user lacks permission to access the Docker socket (permission denied). On Linux, add your user to the docker group with 'sudo usermod -aG docker $USER' and then log out and back in. BreachPilot will not change group membership automatically without explicit disclosure.",
                command_preview="sudo usermod -aG docker $USER",
                requires_admin=True,
                manual=False,
            )
        )

    # 5. Start Docker if daemon not running
    if not docker_daemon_running:
        if platform_name == "linux":
            if service_method == "systemctl":
                preview = "sudo systemctl start docker"
                desc = "Start and enable the Docker daemon using systemd (requires administrator privileges). BreachPilot will then poll until the daemon becomes responsive."
            elif service_method == "service":
                preview = "sudo service docker start"
                desc = "Start the Docker daemon using service (requires administrator privileges). BreachPilot will then poll until the daemon becomes responsive."
            else:
                preview = None
                desc = "No supported service manager found (systemctl/service). Please start Docker manually (e.g., sudo systemctl start docker)."
            steps.append(
                PlanStep(
                    id="start_docker",
                    title="Start Docker",
                    description=desc,
                    command_preview=preview,
                    requires_admin=preview is not None,
                    manual=preview is None,
                )
            )
        elif platform_name == "windows":
            preview = "powershell -Command \"Start-Process 'C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe'\""
            desc = "Start Docker Desktop (BreachPilot will poll until the Docker daemon becomes available; this may take 30–60 seconds)."
            steps.append(
                PlanStep(
                    id="start_docker",
                    title="Start Docker",
                    description=desc,
                    command_preview=preview,
                    requires_admin=False,
                    manual=False,
                )
            )
        elif platform_name == "darwin":
            preview = "open -a Docker"
            desc = "Start Docker Desktop (BreachPilot will poll until the Docker daemon becomes available)."
            steps.append(
                PlanStep(
                    id="start_docker",
                    title="Start Docker",
                    description=desc,
                    command_preview=preview,
                    requires_admin=False,
                    manual=False,
                )
            )
        else:
            steps.append(
                PlanStep(
                    id="start_docker",
                    title="Start Docker",
                    description=f"Automatic Docker start is not supported on {platform_name}. Please start Docker manually.",
                    command_preview=None,
                    requires_admin=False,
                    manual=True,
                )
            )

    # 6. Verify daemon after start
    steps.append(
        PlanStep(
            id="verify_docker",
            title="Verify Docker can actually run containers",
            description="Run 'docker version' again and ensure the daemon/server side responds.",
            command_preview="docker version",
            requires_admin=False,
        )
    )

    # 7. Check image
    steps.append(
        PlanStep(
            id="check_image",
            title=f"Check whether {image} exists",
            description=f"Check if the required image '{image}' is present using 'docker image inspect'."
            if image_present
            else f"The sandbox image '{image}' was not found.",
            command_preview=f"docker image inspect {image}",
            requires_admin=False,
        )
    )

    # 8. Build image if missing
    if image_present is False:
        preview = f"docker build -t {image} docker/sandbox"
        desc = f"Build the BreachPilot sandbox image from docker/sandbox (command: 'docker build -t {image} docker/sandbox' run from the BreachPilot repository root; may take several minutes)."
        # Only offer auto build when docker/sandbox Dockerfile exists
        if not DOCKER_SANDBOX_DIR.exists():
            desc = f"Build step cannot run automatically: docker/sandbox directory not found at {DOCKER_SANDBOX_DIR}. Please ensure the BreachPilot repository is intact."
            steps.append(
                PlanStep(
                    id="build_image",
                    title="Build BreachPilot sandbox image",
                    description=desc,
                    command_preview=None,
                    requires_admin=False,
                    manual=True,
                )
            )
        else:
            steps.append(
                PlanStep(
                    id="build_image",
                    title="Build BreachPilot sandbox image",
                    description=desc,
                    command_preview=preview,
                    requires_admin=False,
                    manual=False,
                )
            )
    elif image_present is None and not docker_daemon_running:
        # Daemon down so image status unknown; still need build step after daemon up
        # We already know image_present is None when daemon down; we should include build as conditional
        # But we don't know if image missing; plan should still include build as potential step
        # For simplicity, if daemon down and we haven't checked image, include build as conditional with note
        preview = f"docker build -t {image} docker/sandbox"
        desc = f"After Docker is running, BreachPilot will check for '{image}' and build it if missing (docker build -t {image} docker/sandbox)."
        steps.append(
            PlanStep(
                id="build_image",
                title="Build BreachPilot sandbox image",
                description=desc,
                command_preview=preview,
                requires_admin=False,
                manual=False,
            )
        )

    # 9. Verify sandbox final
    steps.append(
        PlanStep(
            id="verify_sandbox",
            title="Verify the sandbox image exists and Docker is usable",
            description="Final verification: 'docker version' and 'docker image inspect' must both succeed before the sandbox can be used (a BreachPilot restart will still be required to switch from native fallback to contained mode).",
            command_preview=f"docker version && docker image inspect {image}",
            requires_admin=False,
        )
    )

    requires_admin = any(s.requires_admin for s in steps)

    return {
        "platform": platform_name,
        "reason": reason,
        "docker_cli_present": docker_cli_present,
        "docker_daemon_running": docker_daemon_running,
        "image_present": image_present,
        "requires_admin": requires_admin,
        "steps": [s.to_dict() for s in steps],
        "image": image,
        # extra for tests
        "docker_error": docker_error,
    }


# ── job management ────────────────────────────────────────────────────────────


@dataclass
class JobStepState:
    id: str
    title: str
    description: str
    command_preview: str | None
    requires_admin: bool
    manual: bool
    status: str = "pending"  # pending | running | succeeded | failed | skipped
    output: str = ""
    error: str = ""


@dataclass
class Job:
    job_id: str
    platform: str
    reason: str
    docker_cli_present: bool
    docker_daemon_running: bool
    image_present: bool | None
    requires_admin: bool
    steps: list[JobStepState] = field(default_factory=list)
    status: str = "pending"  # pending | running | succeeded | failed
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    error: str = ""
    docker_ready: bool = False
    requires_restart: bool = False


_JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()  # protects _JOBS dict (thread-safe for background jobs)


def _job_to_dict(job: Job) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "status": job.status,
        "platform": job.platform,
        "reason": job.reason,
        "docker_cli_present": job.docker_cli_present,
        "docker_daemon_running": job.docker_daemon_running,
        "image_present": job.image_present,
        "requires_admin": job.requires_admin,
        "steps": [
            {
                "id": s.id,
                "title": s.title,
                "description": s.description,
                "command_preview": s.command_preview,
                "requires_admin": s.requires_admin,
                "manual": s.manual,
                "status": s.status,
                "output": _sanitize(s.output, 2000),
                "error": _sanitize(s.error, 1000),
            }
            for s in job.steps
        ],
        "error": _sanitize(job.error, 2000),
        "docker_ready": job.docker_ready,
        "requires_restart": job.requires_restart,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "current_step": next((s.id for s in job.steps if s.status == "running"), None),
    }


def create_job_sync(config: dict[str, Any] | None = None) -> Job:
    plan = build_plan(config)
    job_id = uuid.uuid4().hex[:12]
    job = Job(
        job_id=job_id,
        platform=plan["platform"],
        reason=plan["reason"],
        docker_cli_present=plan["docker_cli_present"],
        docker_daemon_running=plan["docker_daemon_running"],
        image_present=plan["image_present"],
        requires_admin=plan["requires_admin"],
        steps=[
            JobStepState(
                id=s["id"],
                title=s["title"],
                description=s["description"],
                command_preview=s["command_preview"],
                requires_admin=s.get("requires_admin", False),
                manual=s.get("manual", False),
            )
            for s in plan["steps"]
        ],
        status="pending",
    )
    # Refuse if disabled
    from tools.sandbox.models import SandboxConfig

    cfg = SandboxConfig.from_config(config)
    if not cfg.enabled:
        job.status = "failed"
        job.error = "Sandbox is intentionally disabled (sandbox.enabled: false). No fix is needed."
        for s in job.steps:
            s.status = "skipped"
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    return job


async def create_job(config: dict[str, Any] | None = None) -> Job:
    return create_job_sync(config)


def get_job_sync(job_id: str) -> Job | None:
    return _JOBS.get(job_id)


async def get_job(job_id: str) -> Job | None:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def get_job_blocking(job_id: str) -> Job | None:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


# ── execution helpers ─────────────────────────────────────────────────────────


def _poll_docker_daemon(timeout: int = DAEMON_POLL_TIMEOUT) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        try:
            ok, reason = _db.docker_version()
            if ok:
                return True, reason.strip()
            last_err = reason
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
        time.sleep(POLL_INTERVAL)
    return False, last_err or f"Docker daemon did not become ready within {timeout}s"


def _install_docker_for_platform(platform_name: str, method: str | None) -> tuple[int, str, str]:
    """Execute the platform-specific install. Returns (rc, out, err)."""
    if platform_name == "linux":
        if method in ("apt-get", "apt"):
            # apt-get update
            rc, out, err = _run(["sudo", "apt-get", "update"], timeout=300)
            if rc != 0:
                return rc, out, err
            return _run(["sudo", "apt-get", "install", "-y", "docker.io"], timeout=600)
        if method == "dnf":
            return _run(["sudo", "dnf", "install", "-y", "docker"], timeout=600)
        if method == "yum":
            return _run(["sudo", "yum", "install", "-y", "docker"], timeout=600)
        if method == "pacman":
            return _run(["sudo", "pacman", "-S", "--noconfirm", "docker"], timeout=600)
        if method == "zypper":
            return _run(["sudo", "zypper", "install", "-y", "docker"], timeout=600)
        if method == "apk":
            return _run(["sudo", "apk", "add", "docker"], timeout=300)
        return 1, "", f"Unsupported package manager {method} for linux"
    if platform_name == "windows":
        if method == "winget":
            # Try silent machine-scope install first; winget will request UAC.
            # If that fails with exit 1 (common for UAC denial or existing install),
            # the caller will surface a helpful message with manual fallback.
            return _run(
                [
                    "winget",
                    "install",
                    "-e",
                    "--id",
                    "Docker.DockerDesktop",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                    "--silent",
                ],
                timeout=600,
            )
        return 1, "", "winget not found"
    if platform_name == "darwin":
        if method == "brew":
            return _run(["brew", "install", "--cask", "docker"], timeout=600)
        return 1, "", "brew not found"
    return 1, "", f"Unsupported platform {platform_name}"


def _start_docker_for_platform(platform_name: str, method: str | None) -> tuple[int, str, str]:
    if platform_name == "linux":
        if method == "systemctl":
            return _run(["sudo", "systemctl", "start", "docker"], timeout=30)
        if method == "service":
            return _run(["sudo", "service", "docker", "start"], timeout=30)
        return 1, "", "No service manager found"
    if platform_name == "windows":
        # Try to start Docker Desktop via powershell
        # Prefer known path if exists
        candidates = [
            "C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe",
            "C:/Program Files/Docker/Docker/Docker Desktop.exe",
        ]
        for cand in candidates:
            if Path(cand).exists():
                # Use powershell Start-Process
                return _run(["powershell", "-Command", f'Start-Process "{cand}"'], timeout=30)
        # Fallback: try start via explorer association or winget location
        # Last resort: attempt to run Docker Desktop if on PATH? docker itself doesn't start daemon on windows (it auto-starts with Desktop)
        # Try generic powershell start
        return _run(["powershell", "-Command", 'Start-Process "Docker Desktop"'], timeout=30)
    if platform_name == "darwin":
        if method == "open":
            return _run(["open", "-a", "Docker"], timeout=30)
        return 1, "", "open not found"
    return 1, "", f"Unsupported platform {platform_name}"


async def _execute_job_async(job_id: str, config: dict[str, Any] | None) -> None:
    # Retrieve job
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        if job.status == "failed" and not job.steps:
            return
        job.status = "running"
        job.updated_at = time.time()

    image = _image_name_from_config(config)
    platform_name = job.platform

    # Copy steps to avoid mutation while iterating? We'll update in place.
    for step in job.steps:
        # Skip already processed
        if step.status in ("succeeded", "failed", "skipped"):
            continue
        # Mark running
        with _JOBS_LOCK:
            step.status = "running"
            job.updated_at = time.time()

        # Manual steps are not auto-executable: fail with guidance
        if step.manual and step.command_preview is None:
            # This is a guidance-only step that cannot be auto-fixed
            step.output = step.description
            step.error = "Manual installation required – see guidance."
            with _JOBS_LOCK:
                step.status = "failed"
                job.status = "failed"
                job.error = step.error
                job.updated_at = time.time()
            return

        try:
            if step.id == "detect_os":
                step.output = f"Detected platform: {platform_name} ({platform.platform()})"
                step.status = "succeeded"

            elif step.id == "check_docker_cli":
                cli = _which("docker")
                if cli:
                    # Verify version quickly
                    rc, out, err = await asyncio.to_thread(_run, ["docker", "--version"], timeout=10)
                    if rc == 0:
                        step.output = _sanitize(out.strip() or "Docker CLI present")
                        step.status = "succeeded"
                    else:
                        step.output = _sanitize(err or out, 1000)
                        # If CLI present but version fails, treat as failed but not fatal? Mark failed but allow next steps?
                        # For check step, we still mark succeeded as we detected state, but note error
                        step.output = f"Docker CLI found at {cli} but 'docker --version' failed: {step.output}"
                        step.status = "succeeded"
                else:
                    step.output = "Docker CLI not found on PATH"
                    step.status = "succeeded"

            elif step.id == "install_docker":
                method = _detect_install_method(platform_name)
                rc, out, err = await asyncio.to_thread(_install_docker_for_platform, platform_name, method)
                combined = _sanitize((out or "") + "\n" + (err or ""), MAX_OUTPUT)
                step.output = combined.strip() or f"install exit {rc}"
                # Winget exit 1 on Windows is common: UAC denied, already installed,
                # or WSL2/Hyper-V prerequisite missing. Check if docker now present
                # as a fallback success, and otherwise surface actionable guidance.
                if rc == 0:
                    step.status = "succeeded"
                else:
                    # Handle "already installed" as success (winget reports non-zero for no-op)
                    lower_combined = combined.lower()
                    already_installed = any(
                        s in lower_combined
                        for s in [
                            "already installed",
                            "already exists",
                            "no available upgrade",
                            "no newer version",
                        ]
                    )
                    docker_now_present = bool(_which("docker"))
                    if platform_name == "windows" and (already_installed or docker_now_present):
                        step.output += (
                            "\nNote: winget reported non-zero but Docker CLI is now present – treating as success."
                        )
                        step.status = "succeeded"
                    elif platform_name == "windows":
                        # Provide Windows-specific remediation hint
                        hint = (
                            "Docker Desktop install via winget failed (exit 1). "
                            "This usually means: the UAC prompt was dismissed/denied, the installer needs a reboot, "
                            "or WSL2/Hyper-V is not enabled. "
                            "Try: 1) Right-click PowerShell -> Run as Administrator and retry the fix, "
                            "2) Accept the UAC prompt when it appears, "
                            "3) Or install manually from https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe "
                            "(then enable WSL2: wsl --install). "
                            "After manual install, click Retry."
                        )
                        step.error = _sanitize(hint + "\n\nRaw output: " + (err or out or combined)[-800:], 1500)
                        step.output += "\n" + hint
                        step.status = "failed"
                        with _JOBS_LOCK:
                            job.status = "failed"
                            job.error = step.error
                            job.updated_at = time.time()
                        return
                    else:
                        step.error = _sanitize(err or out or f"install failed rc={rc}", 1000)
                        step.status = "failed"
                        with _JOBS_LOCK:
                            job.status = "failed"
                            job.error = step.error
                            job.updated_at = time.time()
                        return

            elif step.id == "check_daemon":
                ok, reason = await asyncio.to_thread(_db.docker_version)
                # _db.docker_version is sync
                if ok:
                    step.output = _sanitize(reason or "Docker daemon reachable", 1000) or "Docker daemon reachable"
                    step.status = "succeeded"
                else:
                    step.output = _sanitize(reason, 1000) or "Docker daemon not running"
                    # Check step always succeeds as detection; repair is next step
                    step.status = "succeeded"

            elif step.id == "check_permissions":
                # This step is informational; we don't auto-fix permissions without telling user
                # But we have disclosed command_preview sudo usermod -aG docker $USER
                # We could attempt to check groups, but for now just warn and succeed,
                # leaving verification to later step.
                step.output = "Permission check: Docker socket not accessible to current user."
                step.status = "succeeded"

            elif step.id == "start_docker":
                method = _detect_service_method(platform_name)
                rc, out, err = await asyncio.to_thread(_start_docker_for_platform, platform_name, method)
                combined = _sanitize((out or "") + "\n" + (err or ""), MAX_OUTPUT)
                step.output = combined.strip() or f"start exit {rc}"
                if rc != 0:
                    step.error = _sanitize(err or out or f"start failed rc={rc}", 1000)
                    step.status = "failed"
                    with _JOBS_LOCK:
                        job.status = "failed"
                        job.error = step.error
                        job.updated_at = time.time()
                    return
                # Poll for daemon to become ready
                step.output += "\nWaiting for Docker daemon to become ready…"
                ok, reason = await asyncio.to_thread(_poll_docker_daemon, DAEMON_POLL_TIMEOUT)
                if ok:
                    step.output += f"\nDaemon ready: {reason}"
                    step.status = "succeeded"
                else:
                    step.error = _sanitize(reason, 1000)
                    step.output += f"\nFailed: {reason}"
                    step.status = "failed"
                    with _JOBS_LOCK:
                        job.status = "failed"
                        job.error = step.error
                        job.updated_at = time.time()
                    return

            elif step.id == "verify_docker":
                ok, reason = await asyncio.to_thread(_poll_docker_daemon, 10)
                # quick poll 10s
                if ok:
                    step.output = _sanitize(reason or "Docker daemon responsive", 1000)
                    step.status = "succeeded"
                else:
                    # try one direct call for error detail
                    try:
                        ok2, r2 = _db.docker_version()
                        detail = r2
                    except Exception as exc:  # noqa: BLE001
                        detail = str(exc)
                    step.error = _sanitize(detail or reason, 1000)
                    step.output = _sanitize(detail or reason, 1000)
                    step.status = "failed"
                    with _JOBS_LOCK:
                        job.status = "failed"
                        job.error = step.error
                        job.updated_at = time.time()
                    return

            elif step.id == "check_image":
                try:
                    present = await asyncio.to_thread(_db.docker_image_exists, image)
                except Exception as exc:  # noqa: BLE001
                    if "unavailable" in str(exc).lower() or "daemon" in str(exc).lower():
                        present = False
                        step.output = _sanitize(str(exc), 1000)
                    else:
                        present = False
                        step.output = _sanitize(str(exc), 1000)
                    step.status = "succeeded"
                    continue
                if present:
                    step.output = f"Image {image} is present."
                    step.status = "succeeded"
                else:
                    step.output = f"Image {image} not found."
                    step.status = "succeeded"

            elif step.id == "build_image":
                # Ensure repo root docker/sandbox exists
                if not DOCKER_SANDBOX_DIR.exists():
                    step.error = f"Dockerfile directory not found at {DOCKER_SANDBOX_DIR}"
                    step.output = step.error
                    step.status = "failed"
                    with _JOBS_LOCK:
                        job.status = "failed"
                        job.error = step.error
                        job.updated_at = time.time()
                    return
                rc, out, err = await asyncio.to_thread(
                    _run, ["docker", "build", "-t", image, "docker/sandbox"], timeout=BUILD_TIMEOUT, cwd=REPO_ROOT
                )
                combined = _sanitize((out or "")[-2000:] + "\n" + (err or "")[-2000:], MAX_OUTPUT)
                step.output = combined.strip() or f"build exit {rc}"
                if rc == 0:
                    step.status = "succeeded"
                else:
                    step.error = _sanitize(err or out or f"build failed rc={rc}", 1000)
                    step.status = "failed"
                    with _JOBS_LOCK:
                        job.status = "failed"
                        job.error = step.error
                        job.updated_at = time.time()
                    return

            elif step.id == "verify_sandbox":
                # Final verification: docker version + image inspect
                ok, reason = await asyncio.to_thread(_db.docker_version)
                if not ok:
                    step.error = _sanitize(reason, 1000)
                    step.output = _sanitize(reason, 1000)
                    step.status = "failed"
                    with _JOBS_LOCK:
                        job.status = "failed"
                        job.error = step.error
                        job.updated_at = time.time()
                    return
                try:
                    present = await asyncio.to_thread(_db.docker_image_exists, image)
                except Exception as exc:  # noqa: BLE001
                    present = False
                    step.error = _sanitize(str(exc), 1000)
                    step.output = step.error
                    step.status = "failed"
                    with _JOBS_LOCK:
                        job.status = "failed"
                        job.error = step.error
                        job.updated_at = time.time()
                    return
                if not present:
                    step.error = f"Image {image} still not present after build."
                    step.output = step.error
                    step.status = "failed"
                    with _JOBS_LOCK:
                        job.status = "failed"
                        job.error = step.error
                        job.updated_at = time.time()
                    return
                step.output = f"Docker daemon responsive and image {image} present. Docker is ready – restart BreachPilot to activate containment."
                step.status = "succeeded"

            else:
                # Unknown step: mark skipped
                step.output = f"Unknown step {step.id} – skipped."
                step.status = "skipped"

        except Exception as exc:  # noqa: BLE001 — step must never throw unhandled
            step.error = _sanitize(str(exc), 1000)
            step.output = step.error
            step.status = "failed"
            with _JOBS_LOCK:
                job.status = "failed"
                job.error = step.error
                job.updated_at = time.time()
            return

        with _JOBS_LOCK:
            if step.status == "failed":
                job.status = "failed"
                job.error = step.error or step.output
                job.updated_at = time.time()
                return
            else:
                # Keep succeed
                if step.status == "pending":
                    step.status = "succeeded"
                job.updated_at = time.time()

    # All steps succeeded
    with _JOBS_LOCK:
        job.status = "succeeded"
        job.docker_ready = True
        job.requires_restart = True
        job.updated_at = time.time()


def _start_background_job(job_id: str, config: dict[str, Any] | None) -> None:
    import threading

    def _runner():
        asyncio.run(_execute_job_async(job_id, config))

    t = threading.Thread(target=_runner, daemon=True)
    t.start()


# Public helpers for tests / routes
__all__ = [
    "REPO_ROOT",
    "DOCKER_SANDBOX_DIR",
    "IMAGE_NAME",
    "build_plan",
    "create_job",
    "get_job",
    "get_job_sync",
    "_job_to_dict",
    "_which",
    "_run",
    "_platform",
    "_detect_install_method",
    "_detect_service_method",
    "_poll_docker_daemon",
]
