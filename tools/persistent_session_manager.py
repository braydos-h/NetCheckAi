"""Persistent session manager for long-running interactive processes on Kali Linux.

Provides:
- TmuxSession: named tmux sessions for interactive shells, msfconsole, ssh, etc.
- BackgroundJob: nohup-based background processes
- Listener: network listener management (nc, socat, python http.server)
- ProcessTracker: track PIDs and allow listing/killing
- Output capture via tmux capture-pane or log files
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.kernel.workspace import _is_inside_workspace as _kernel_is_inside

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Name / path validation helpers
# ---------------------------------------------------------------------------

# Model-supplied `name` is interpolated directly into log/script filenames
# (``f"job_{name}.sh"``, ``f"listener_{name}.log"``). An unvalidated name lets
# the AI inject path separators / ``..`` to escape the workspace
# (e.g. ``name="../../etc/x"`` writes ``job_../../etc/x.sh``). Restrict to a
# conservative identifier set; reject anything that could traverse.
_VALID_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}\Z")


def _validate_name(name: str) -> str:
    """Return ``name`` if it is a safe job/listener identifier, else raise ValueError.

    Rejects empty, over-long, and any name containing path separators, ``..``,
    or other shell-significant characters.
    """
    if not isinstance(name, str) or not _VALID_NAME_RE.fullmatch(name):
        raise ValueError(
            f"invalid session name {name!r}: must match [A-Za-z0-9._-]{{1,64}} and contain no path separators or '..'"
        )
    # Belt-and-suspenders: '..' already excluded by the charset, but be explicit.
    if ".." in name:
        raise ValueError(f"invalid session name {name!r}: '..' is not permitted")
    return name


def _is_inside_workspace(path: Path, workspace: Path) -> bool:
    """True if ``path`` (resolved) is equal to or nested under ``workspace``.

    Ponytail: wrapper for backwards compat — old signature was (path, workspace)
    while ``tools.kernel.workspace._is_inside_workspace`` is (workspace, target).
    Delegates to the kernel and preserves call sites (e.g. ``_is_inside_workspace(serve_dir, self.workspace)``).
    """
    return _kernel_is_inside(workspace, path)


def _terminate_proc_tree(proc: subprocess.Popen[str]) -> None:
    """Best-effort teardown of a helper subprocess and its process group.

    Every ``BackgroundJobHelper`` / ``ListenerHelper`` spawn uses
    ``start_new_session=True``, so ``proc.pid`` leads its own process group and
    ``os.killpg`` reaps the whole tree (wrapper shell plus children), not just
    the parent. Any group-kill failure (mock procs without a real pid,
    already-reaped groups, ``EPERM``) falls back to plain ``proc.terminate()``
    / ``proc.kill()`` with the same 5s waits. Never raises — teardown must not
    break ``stop()`` bookkeeping. Windows has no ``killpg`` path here, so it
    uses direct ``terminate()`` / ``kill()``.
    """
    if sys.platform == "win32":
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass
        except Exception:
            pass
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
    except Exception:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SessionInfo:
    name: str
    session_type: str  # 'tmux', 'background', 'listener', 'msfconsole', 'ssh', 'vpn'
    command: str
    pid: int | None = None
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    workspace: Path = field(default_factory=lambda: Path("exploit_workspace"))
    log_file: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = "running"  # running, stopped, error

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "session_type": self.session_type,
            "command": self.command,
            "pid": self.pid,
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "workspace": str(self.workspace),
            "log_file": str(self.log_file) if self.log_file else None,
            "metadata": self.metadata,
            "status": self.status,
        }


# ---------------------------------------------------------------------------
# Tmux helper
# ---------------------------------------------------------------------------


class TmuxHelper:
    """Low-level tmux interaction."""

    def __init__(self) -> None:
        self._tmux = shutil.which("tmux") or "tmux"
        self._lock = threading.Lock()

    def _run(self, *args: str, timeout: int = 10) -> subprocess.CompletedProcess[str]:
        cmd = [self._tmux, *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def is_available(self) -> bool:
        return shutil.which("tmux") is not None

    def session_exists(self, name: str) -> bool:
        result = self._run("has-session", "-t", name)
        return result.returncode == 0

    def create_session(self, name: str, command: str, cwd: Path | None = None) -> bool:
        """Create a new detached tmux session running the given command."""
        if self.session_exists(name):
            return False
        env = os.environ.copy()
        if cwd:
            env["TMUX_CWD"] = str(cwd)
        # Use bash -c to run the command so we can chain multiple commands
        cmd = [self._tmux, "new-session", "-d", "-s", name]
        if cwd:
            cmd += ["-c", str(cwd)]
        cmd += ["bash", "-c", command]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=env)
        return result.returncode == 0

    def send_keys(self, name: str, keys: str) -> bool:
        """Send keystrokes to a tmux session."""
        if not self.session_exists(name):
            return False
        # Escape special characters for tmux send-keys
        result = self._run("send-keys", "-t", name, keys)
        return result.returncode == 0

    def send_enter(self, name: str) -> bool:
        """Send Enter key to a tmux session."""
        return self.send_keys(name, "C-m")

    def capture_pane(self, name: str, lines: int = 100) -> str:
        """Capture the last N lines from a tmux pane."""
        if not self.session_exists(name):
            return f"ERROR: tmux session '{name}' does not exist."
        result = self._run("capture-pane", "-t", name, "-p", "-S", f"-{lines}")
        if result.returncode != 0:
            return f"ERROR capturing pane: {result.stderr}"
        return result.stdout

    def kill_session(self, name: str) -> bool:
        """Kill a tmux session."""
        if not self.session_exists(name):
            return False
        result = self._run("kill-session", "-t", name)
        return result.returncode == 0

    def list_sessions(self) -> list[dict[str, str]]:
        """List all tmux sessions."""
        result = self._run("list-sessions", "-F", "#{session_name}|#{session_created}|#{session_attached}")
        if result.returncode != 0:
            return []
        sessions = []
        for line in result.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|")
                sessions.append(
                    {
                        "name": parts[0],
                        "created": parts[1] if len(parts) > 1 else "",
                        "attached": parts[2] if len(parts) > 2 else "0",
                    }
                )
        return sessions

    def get_pid(self, name: str) -> int | None:
        """Get the PID of the process in a tmux session."""
        if not self.session_exists(name):
            return None
        result = self._run("list-panes", "-t", name, "-F", "#{pane_pid}")
        if result.returncode == 0 and result.stdout.strip():
            try:
                return int(result.stdout.strip().split("\n")[0])
            except ValueError:
                pass
        return None


# ---------------------------------------------------------------------------
# Background job helper
# ---------------------------------------------------------------------------


class BackgroundJobHelper:
    """Manage nohup background jobs with log capture."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, subprocess.Popen[str]] = {}
        self._lock = threading.Lock()

    def start(self, name: str, command: str, cwd: Path | None = None) -> tuple[bool, int | None]:
        """Start a background job using nohup. Returns (success, pid)."""
        try:
            _validate_name(name)
        except ValueError:
            return False, None
        log_path = self.workspace / f"job_{name}.log"
        wrapper = self.workspace / f"job_{name}.sh"
        wrapper.write_text(
            f"#!/bin/bash\ncd {cwd or self.workspace}\n{command}\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

        with open(log_path, "w", encoding="utf-8") as log_f:
            proc = subprocess.Popen(
                ["nohup", "bash", str(wrapper)],
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=str(cwd or self.workspace),
                start_new_session=True,
            )

        with self._lock:
            self._jobs[name] = proc

        # Give it a moment to start
        time.sleep(0.2)
        return proc.poll() is None, proc.pid

    def stop(self, name: str) -> bool:
        """Stop a background job by name."""
        with self._lock:
            proc = self._jobs.get(name)
            if proc is None:
                return False
            _terminate_proc_tree(proc)
            del self._jobs[name]
            return True

    def read_log(self, name: str, lines: int = 100) -> str:
        """Read the last N lines from a job's log file."""
        try:
            _validate_name(name)
        except ValueError:
            return f"INVALID_NAME: {name}"
        log_path = self.workspace / f"job_{name}.log"
        if not log_path.exists():
            return f"LOG_NOT_FOUND: {log_path}"
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
            all_lines = text.splitlines()
            return "\n".join(all_lines[-lines:])
        except Exception as exc:
            return f"ERROR reading log: {exc}"

    def is_running(self, name: str) -> bool:
        """Check if a background job is still running."""
        with self._lock:
            proc = self._jobs.get(name)
            if proc is None:
                return False
            return proc.poll() is None

    def list_jobs(self) -> list[dict[str, Any]]:
        """List all background jobs."""
        result = []
        with self._lock:
            for name, proc in list(self._jobs.items()):
                result.append(
                    {
                        "name": name,
                        "pid": proc.pid,
                        "running": proc.poll() is None,
                        "log": str(self.workspace / f"job_{name}.log"),
                    }
                )
        return result


# ---------------------------------------------------------------------------
# Listener helper
# ---------------------------------------------------------------------------


class ListenerHelper:
    """Manage network listeners (nc, socat, python http.server)."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._listeners: dict[str, subprocess.Popen[str]] = {}
        self._lock = threading.Lock()

    def start_netcat(self, name: str, port: int, protocol: str = "tcp") -> tuple[bool, int | None]:
        """Start a netcat listener."""
        try:
            _validate_name(name)
        except ValueError:
            return False, None
        if shutil.which("nc"):
            nc_cmd = ["nc", "-lvnp", str(port)]
        elif shutil.which("ncat"):
            nc_cmd = ["ncat", "-lvnp", str(port)]
        elif shutil.which("netcat"):
            nc_cmd = ["netcat", "-lvnp", str(port)]
        else:
            return False, None

        log_path = self.workspace / f"listener_{name}.log"
        with open(log_path, "w", encoding="utf-8") as log_f:
            proc = subprocess.Popen(
                nc_cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )

        with self._lock:
            self._listeners[name] = proc

        time.sleep(0.2)
        return proc.poll() is None, proc.pid

    def start_socat(self, name: str, port: int, protocol: str = "tcp") -> tuple[bool, int | None]:
        """Start a socat listener."""
        try:
            _validate_name(name)
        except ValueError:
            return False, None
        if not shutil.which("socat"):
            return False, None
        log_path = self.workspace / f"listener_{name}.log"
        with open(log_path, "w", encoding="utf-8") as log_f:
            proc = subprocess.Popen(
                ["socat", f"{protocol}-LISTEN:{port},fork", "STDIO"],
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )

        with self._lock:
            self._listeners[name] = proc

        time.sleep(0.2)
        return proc.poll() is None, proc.pid

    def start_http_server(self, name: str, port: int = 80, directory: str = "") -> tuple[bool, int | None]:
        """Start a Python HTTP server."""
        try:
            _validate_name(name)
        except ValueError:
            return False, None
        serve_dir = Path(directory) if directory else self.workspace
        # Containment: a model-supplied ``directory`` must stay inside the
        # per-target workspace. Reject serving arbitrary host paths
        # (e.g. ``directory='/etc'``) — mirrors read_workspace_file/git_clone.
        if not _is_inside_workspace(serve_dir, self.workspace):
            return False, None
        serve_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.workspace / f"listener_{name}.log"
        with open(log_path, "w", encoding="utf-8") as log_f:
            proc = subprocess.Popen(
                [sys.executable, "-m", "http.server", str(port), "--directory", str(serve_dir)],
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )

        with self._lock:
            self._listeners[name] = proc

        time.sleep(0.2)
        return proc.poll() is None, proc.pid

    # ── Phase 3: TLS / DNS / HTTPS-beacon / SOCKS-pivot listeners ──
    # Each is a new ``listener_type`` branch for ``start_listener``. They probe
    # the optional Kali binary via ``shutil.which`` and fall back to a stdlib
    # tool (socat/openssl) or a clean ``False`` when nothing is available —
    # never raise. ``socks_pivot`` takes an upstream host the caller must have
    # allowlist-gated at the MCP tool layer (the allowlist is the pivot lock).

    def _tls_cert(self, port: int) -> tuple[Path, Path] | None:
        """Generate (or reuse) a self-signed cert+key for a TLS listener."""
        cert = self.workspace / f"tls_listener_{port}.crt"
        key = self.workspace / f"tls_listener_{port}.key"
        if cert.exists() and key.exists():
            return cert, key
        openssl = shutil.which("openssl")
        if not openssl:
            return None
        try:
            proc = subprocess.run(
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "365",
                    "-subj",
                    "/CN=localhost",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode != 0 or not cert.exists() or not key.exists():
                return None
        except Exception:
            return None
        return cert, key

    def start_tls(self, name: str, port: int, protocol: str = "tcp") -> tuple[bool, int | None]:
        """Start a TLS-wrapped listener (openssl s_server, socat fallback)."""
        try:
            _validate_name(name)
        except ValueError:
            return False, None
        ck = self._tls_cert(port)
        if ck is None:
            return False, None
        cert, _key = ck
        log_path = self.workspace / f"listener_{name}.log"
        with open(log_path, "w", encoding="utf-8") as log_f:
            if shutil.which("openssl"):
                argv = [
                    "openssl",
                    "s_server",
                    "-accept",
                    str(port),
                    "-cert",
                    str(cert),
                    "-key",
                    str(ck[1]),
                    "-naccept",
                    "1",
                ]
            elif shutil.which("socat"):
                argv = ["socat", f"OPENSSL-LISTEN:{port},cert={cert},key={ck[1]},fork", "STDIO"]
            else:
                return False, None
            proc = subprocess.Popen(
                argv,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        with self._lock:
            self._listeners[name] = proc
        time.sleep(0.2)
        return proc.poll() is None, proc.pid

    def start_dns(self, name: str, port: int = 53) -> tuple[bool, int | None]:
        """Start a DNS C2 listener (dnscat2). Clean fail when not installed."""
        try:
            _validate_name(name)
        except ValueError:
            return False, None
        if not shutil.which("dnscat2"):
            return False, None
        log_path = self.workspace / f"listener_{name}.log"
        with open(log_path, "w", encoding="utf-8") as log_f:
            proc = subprocess.Popen(
                ["dnscat2", "--listen", str(port)],
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        with self._lock:
            self._listeners[name] = proc
        time.sleep(0.2)
        return proc.poll() is None, proc.pid

    def start_https_beacon(self, name: str, port: int) -> tuple[bool, int | None]:
        """Start a TLS HTTP beacon listener (socat OPENSSL-LISTEN -> cat)."""
        try:
            _validate_name(name)
        except ValueError:
            return False, None
        if not shutil.which("socat"):
            return False, None
        ck = self._tls_cert(port)
        if ck is None:
            return False, None
        cert, key = ck
        log_path = self.workspace / f"listener_{name}.log"
        with open(log_path, "w", encoding="utf-8") as log_f:
            proc = subprocess.Popen(
                ["socat", f"OPENSSL-LISTEN:{port},cert={cert},key={key},fork", "SYSTEM:cat"],
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        with self._lock:
            self._listeners[name] = proc
        time.sleep(0.2)
        return proc.poll() is None, proc.pid

    def start_socks_pivot(
        self, name: str, port: int, upstream_host: str = "", upstream_port: int = 0
    ) -> tuple[bool, int | None]:
        """Start a SOCKS/pivot listener (chisel/ligolo-ng if present, else
        socat TCP-LISTEN:<port>,fork TCP:<upstream>). The caller MUST allowlist-
        gate ``upstream_host`` (the allowlist is the pivot lock)."""
        try:
            _validate_name(name)
        except ValueError:
            return False, None
        log_path = self.workspace / f"listener_{name}.log"
        argv: list[str] | None = None
        if shutil.which("chisel"):
            argv = ["chisel", "server", "--reverse", "--port", str(port)]
        elif shutil.which("ligolo-ng") or shutil.which("ligolo"):
            bin_ = shutil.which("ligolo-ng") or shutil.which("ligolo")
            argv = [bin_, "selfserve", "--bind", f"0.0.0.0:{port}"]
        elif shutil.which("socat") and upstream_host and upstream_port:
            argv = ["socat", f"TCP-LISTEN:{port},fork", f"TCP:{upstream_host}:{upstream_port}"]
        else:
            return False, None
        with open(log_path, "w", encoding="utf-8") as log_f:
            proc = subprocess.Popen(
                argv,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        with self._lock:
            self._listeners[name] = proc
        time.sleep(0.2)
        return proc.poll() is None, proc.pid

    def stop(self, name: str) -> bool:
        """Stop a listener."""
        with self._lock:
            proc = self._listeners.get(name)
            if proc is None:
                return False
            _terminate_proc_tree(proc)
            del self._listeners[name]
            return True

    def read_log(self, name: str, lines: int = 100) -> str:
        """Read the last N lines from a listener's log file."""
        try:
            _validate_name(name)
        except ValueError:
            return f"INVALID_NAME: {name}"
        log_path = self.workspace / f"listener_{name}.log"
        if not log_path.exists():
            return f"LOG_NOT_FOUND: {log_path}"
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
            all_lines = text.splitlines()
            return "\n".join(all_lines[-lines:])
        except Exception as exc:
            return f"ERROR reading log: {exc}"

    def is_running(self, name: str) -> bool:
        """Check if a listener is still running."""
        with self._lock:
            proc = self._listeners.get(name)
            if proc is None:
                return False
            return proc.poll() is None

    def list_listeners(self) -> list[dict[str, Any]]:
        """List all listeners."""
        result = []
        with self._lock:
            for name, proc in list(self._listeners.items()):
                result.append(
                    {
                        "name": name,
                        "pid": proc.pid,
                        "running": proc.poll() is None,
                        "log": str(self.workspace / f"listener_{name}.log"),
                    }
                )
        return result


# ---------------------------------------------------------------------------
# Process tracker
# ---------------------------------------------------------------------------


class ProcessTracker:
    """Track and manage system processes relevant to the engagement."""

    def __init__(self) -> None:
        self._tracked: dict[str, int] = {}  # name -> pid
        self._lock = threading.Lock()

    def track(self, name: str, pid: int) -> None:
        with self._lock:
            self._tracked[name] = pid

    def untrack(self, name: str) -> None:
        with self._lock:
            self._tracked.pop(name, None)

    def list_tracked(self) -> list[dict[str, Any]]:
        result = []
        with self._lock:
            for name, pid in list(self._tracked.items()):
                running = self._is_running(pid)
                result.append({"name": name, "pid": pid, "running": running})
        return result

    def kill(self, name: str) -> bool:
        with self._lock:
            pid = self._tracked.get(name)
            if pid is None:
                return False
        try:
            os.kill(pid, signal.SIGTERM)
            # Wait a bit
            for _ in range(50):
                if not self._is_running(pid):
                    with self._lock:
                        self._tracked.pop(name, None)
                    return True
                time.sleep(0.1)
            os.kill(pid, signal.SIGKILL)
            with self._lock:
                self._tracked.pop(name, None)
            return True
        except ProcessLookupError:
            with self._lock:
                self._tracked.pop(name, None)
            return True
        except PermissionError:
            return False

    def kill_pid(self, pid: int) -> bool:
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(50):
                if not self._is_running(pid):
                    return True
                time.sleep(0.1)
            os.kill(pid, signal.SIGKILL)
            return True
        except ProcessLookupError:
            return True
        except PermissionError:
            return False

    @staticmethod
    def _is_running(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    @staticmethod
    def list_system_processes(pattern: str = "") -> list[dict[str, str]]:
        """List system processes matching a pattern."""
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            lines = result.stdout.splitlines()
            if pattern:
                lines = [line for line in lines if pattern.lower() in line.lower()]
            processes = []
            for line in lines[1:]:  # Skip header
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    processes.append(
                        {
                            "user": parts[0],
                            "pid": parts[1],
                            "cpu": parts[2],
                            "mem": parts[3],
                            "command": parts[10],
                        }
                    )
            return processes
        except Exception as exc:
            return [{"error": str(exc)}]


# ---------------------------------------------------------------------------
# Main PersistentSessionManager
# ---------------------------------------------------------------------------


class PersistentSessionManager:
    """Unified manager for all persistent session types on Kali Linux."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._state_path = workspace / "persistent_sessions.json"
        self._tmux = TmuxHelper()
        self._jobs = BackgroundJobHelper(workspace)
        self._listeners = ListenerHelper(workspace)
        self._processes = ProcessTracker()
        self._sessions: dict[str, SessionInfo] = {}
        self._lock = threading.Lock()
        self._load_state()

    # ── State persistence ──

    def _load_state(self) -> None:
        if not self._state_path.exists():
            return
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            for name, info in data.get("sessions", {}).items():
                self._sessions[name] = SessionInfo(
                    name=name,
                    session_type=info.get("session_type", "unknown"),
                    command=info.get("command", ""),
                    pid=info.get("pid"),
                    created_at=info.get("created_at", 0),
                    last_accessed=info.get("last_accessed", 0),
                    workspace=Path(info.get("workspace", str(self.workspace))),
                    log_file=Path(info["log_file"]) if info.get("log_file") else None,
                    metadata=info.get("metadata", {}),
                    status=info.get("status", "running"),
                )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            # A bare pass here would silently reset the in-memory session set to
            # empty, and the next _save_state() would then overwrite the corrupt
            # file with that empty state -- destroying whatever was recoverable
            # and dropping every tracked session with no signal to the operator.
            _LOG.warning(
                "Persistent session state at %s is corrupt (%s); starting with "
                "no tracked sessions. The file will be overwritten on the next "
                "state save.",
                self._state_path,
                exc,
            )

    def _save_state(self) -> None:
        data = {
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "sessions": {name: info.to_dict() for name, info in self._sessions.items()},
        }
        # Atomic write (temp + os.replace, same directory => same filesystem):
        # a plain write_text truncates first, so a crash mid-write would leave
        # the session-tracking state empty/corrupt instead of the prior good copy.
        tmp_path = self._state_path.with_name(self._state_path.name + ".tmp")
        tmp_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        os.replace(tmp_path, self._state_path)

    def _register(self, info: SessionInfo) -> None:
        with self._lock:
            self._sessions[info.name] = info
            self._save_state()

    def _unregister(self, name: str) -> None:
        with self._lock:
            self._sessions.pop(name, None)
            self._save_state()

    def _update_status(self, name: str, status: str) -> None:
        with self._lock:
            if name in self._sessions:
                self._sessions[name].status = status
                self._save_state()

    # ── Session lifecycle ──

    def start_tmux_session(self, name: str, command: str, cwd: Path | None = None) -> dict[str, Any]:
        """Start a named tmux session for interactive use."""
        if not self._tmux.is_available():
            return {"success": False, "error": "tmux is not installed. Install with: apt install tmux"}

        if self._tmux.session_exists(name):
            return {"success": False, "error": f"tmux session '{name}' already exists."}

        success = self._tmux.create_session(name, command, cwd=cwd)
        if not success:
            return {"success": False, "error": f"Failed to create tmux session '{name}'."}

        pid = self._tmux.get_pid(name)
        info = SessionInfo(
            name=name,
            session_type="tmux",
            command=command,
            pid=pid,
            workspace=cwd or self.workspace,
            metadata={"tmux": True},
        )
        self._register(info)
        if pid:
            self._processes.track(name, pid)

        return {
            "success": True,
            "name": name,
            "type": "tmux",
            "pid": pid,
            "command": command,
        }

    def send_to_session(self, name: str, input_text: str) -> dict[str, Any]:
        """Send text/keystrokes to a tmux session."""
        if not self._tmux.session_exists(name):
            return {"success": False, "error": f"tmux session '{name}' does not exist."}

        # Send the text followed by Enter
        success = self._tmux.send_keys(name, input_text)
        if success:
            self._tmux.send_enter(name)

        with self._lock:
            if name in self._sessions:
                self._sessions[name].last_accessed = time.time()

        return {
            "success": success,
            "name": name,
            "sent": input_text,
        }

    def read_session_output(self, name: str, lines: int = 100) -> dict[str, Any]:
        """Read the last N lines from a tmux session."""
        if not self._tmux.session_exists(name):
            return {"success": False, "error": f"tmux session '{name}' does not exist."}

        output = self._tmux.capture_pane(name, lines=lines)

        with self._lock:
            if name in self._sessions:
                self._sessions[name].last_accessed = time.time()

        return {
            "success": True,
            "name": name,
            "lines": lines,
            "output": output,
        }

    def kill_session(self, name: str) -> dict[str, Any]:
        """Kill a tmux session."""
        success = self._tmux.kill_session(name)
        self._processes.untrack(name)
        self._unregister(name)
        return {
            "success": success,
            "name": name,
            "message": "Session killed." if success else "Session not found.",
        }

    # ── Background jobs ──

    def start_background_job(self, name: str, command: str, cwd: Path | None = None) -> dict[str, Any]:
        """Start a background job (nohup)."""
        try:
            _validate_name(name)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        success, pid = self._jobs.start(name, command, cwd=cwd)
        if not success:
            return {"success": False, "error": f"Failed to start background job '{name}'."}

        info = SessionInfo(
            name=name,
            session_type="background",
            command=command,
            pid=pid,
            workspace=cwd or self.workspace,
            log_file=self.workspace / f"job_{name}.log",
            metadata={"nohup": True},
        )
        self._register(info)
        if pid:
            self._processes.track(name, pid)

        return {
            "success": True,
            "name": name,
            "type": "background",
            "pid": pid,
            "command": command,
            "log": str(info.log_file),
        }

    def read_job_output(self, name: str, lines: int = 100) -> dict[str, Any]:
        """Read output from a background job's log."""
        output = self._jobs.read_log(name, lines=lines)
        running = self._jobs.is_running(name)
        return {
            "success": True,
            "name": name,
            "running": running,
            "lines": lines,
            "output": output,
        }

    def stop_background_job(self, name: str) -> dict[str, Any]:
        """Stop a background job."""
        info = self._sessions.get(name)
        success = self._jobs.stop(name)
        if not success and info is not None and info.pid:
            # Helper lost the handle (e.g. process already reaped); fall back
            # to the recorded PID so a failed stop does not leak the process.
            success = self._processes.kill_pid(info.pid)
        if success:
            self._processes.untrack(name)
            self._unregister(name)
        else:
            self._update_status(name, "error")
        return {
            "success": success,
            "name": name,
            "message": "Job stopped." if success else "Job not found.",
        }

    # ── Listeners ──

    def start_listener(
        self,
        name: str,
        port: int,
        listener_type: str = "netcat",
        protocol: str = "tcp",
        directory: str = "",
        upstream_host: str = "",
        upstream_port: int = 0,
    ) -> dict[str, Any]:
        """Start a network listener."""
        try:
            _validate_name(name)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        success = False
        pid = None

        if listener_type == "netcat":
            success, pid = self._listeners.start_netcat(name, port, protocol)
        elif listener_type == "socat":
            success, pid = self._listeners.start_socat(name, port, protocol)
        elif listener_type == "http":
            if directory and not _is_inside_workspace(Path(directory), self.workspace):
                return {
                    "success": False,
                    "error": (
                        f"refusing to serve directory {directory!r}: must be inside "
                        f"the target workspace {self.workspace}"
                    ),
                }
            success, pid = self._listeners.start_http_server(name, port, directory)
        elif listener_type == "tls":
            success, pid = self._listeners.start_tls(name, port, protocol)
        elif listener_type == "dns":
            success, pid = self._listeners.start_dns(name, port)
        elif listener_type == "https-beacon":
            success, pid = self._listeners.start_https_beacon(name, port)
        elif listener_type == "socks_pivot":
            success, pid = self._listeners.start_socks_pivot(name, port, upstream_host, upstream_port)
        else:
            return {
                "success": False,
                "error": f"Unknown listener_type: {listener_type}. Use: netcat, socat, http, tls, dns, https-beacon, socks_pivot",
            }

        if not success:
            return {"success": False, "error": f"Failed to start {listener_type} listener on port {port}."}

        info = SessionInfo(
            name=name,
            session_type="listener",
            command=f"{listener_type} on port {port}/{protocol}",
            pid=pid,
            workspace=self.workspace,
            log_file=self.workspace / f"listener_{name}.log",
            metadata={"listener_type": listener_type, "port": port, "protocol": protocol},
        )
        self._register(info)
        if pid:
            self._processes.track(name, pid)

        return {
            "success": True,
            "name": name,
            "type": "listener",
            "listener_type": listener_type,
            "port": port,
            "protocol": protocol,
            "pid": pid,
            "log": str(info.log_file),
        }

    def read_listener_output(self, name: str, lines: int = 100) -> dict[str, Any]:
        """Read output from a listener's log."""
        output = self._listeners.read_log(name, lines=lines)
        running = self._listeners.is_running(name)
        return {
            "success": True,
            "name": name,
            "running": running,
            "lines": lines,
            "output": output,
        }

    def stop_listener(self, name: str) -> dict[str, Any]:
        """Stop a listener."""
        info = self._sessions.get(name)
        success = self._listeners.stop(name)
        if not success and info is not None and info.pid:
            # Helper lost the handle (e.g. process already reaped); fall back
            # to the recorded PID so a failed stop does not leak the process.
            success = self._processes.kill_pid(info.pid)
        if success:
            self._processes.untrack(name)
            self._unregister(name)
        else:
            self._update_status(name, "error")
        return {
            "success": success,
            "name": name,
            "message": "Listener stopped." if success else "Listener not found.",
        }

    # ── Process management ──

    def list_processes(self, pattern: str = "") -> list[dict[str, Any]]:
        """List system processes."""
        return ProcessTracker.list_system_processes(pattern)

    def kill_process(self, name_or_pid: str | int) -> dict[str, Any]:
        """Kill a process by tracked name or raw PID."""
        if isinstance(name_or_pid, int) or name_or_pid.isdigit():
            pid = int(name_or_pid)
            success = self._processes.kill_pid(pid)
            return {
                "success": success,
                "pid": pid,
                "message": "Process killed." if success else "Failed to kill process.",
            }

        success = self._processes.kill(name_or_pid)
        if success:
            self._unregister(name_or_pid)
        return {
            "success": success,
            "name": name_or_pid,
            "message": "Process killed." if success else "Process not found or permission denied.",
        }

    # ── Unified listing ──

    def list_all_sessions(self) -> list[dict[str, Any]]:
        """List all managed sessions (tmux, background, listeners)."""
        result = []
        with self._lock:
            for name, info in self._sessions.items():
                # Check if still running
                running = False
                if info.pid:
                    running = ProcessTracker._is_running(info.pid)
                result.append(
                    {
                        "name": name,
                        "type": info.session_type,
                        "command": info.command,
                        "pid": info.pid,
                        "running": running,
                        "status": "running" if running else "stopped",
                        "created": datetime.fromtimestamp(info.created_at, tz=timezone.utc).isoformat(),
                        "last_accessed": datetime.fromtimestamp(info.last_accessed, tz=timezone.utc).isoformat(),
                        "log": str(info.log_file) if info.log_file else None,
                        "metadata": info.metadata,
                    }
                )
        return result

    def get_session(self, name: str) -> dict[str, Any] | None:
        """Get details for a specific session."""
        with self._lock:
            info = self._sessions.get(name)
            if not info:
                return None
            running = False
            if info.pid:
                running = ProcessTracker._is_running(info.pid)
            return {
                "name": info.name,
                "type": info.session_type,
                "command": info.command,
                "pid": info.pid,
                "running": running,
                "status": "running" if running else "stopped",
                "created": datetime.fromtimestamp(info.created_at, tz=timezone.utc).isoformat(),
                "last_accessed": datetime.fromtimestamp(info.last_accessed, tz=timezone.utc).isoformat(),
                "log": str(info.log_file) if info.log_file else None,
                "metadata": info.metadata,
            }

    def cleanup_stopped(self) -> int:
        """Remove stopped sessions from tracking. Returns count removed."""
        removed = 0
        with self._lock:
            to_remove = []
            for name, info in self._sessions.items():
                if info.pid and not ProcessTracker._is_running(info.pid):
                    to_remove.append(name)
            for name in to_remove:
                self._sessions.pop(name, None)
                removed += 1
            if removed:
                self._save_state()
        return removed


# ---------------------------------------------------------------------------
# Singleton / module-level instance
# ---------------------------------------------------------------------------

_session_manager_instance: PersistentSessionManager | None = None


def get_session_manager(workspace: Path | None = None) -> PersistentSessionManager:
    """Get or create the global PersistentSessionManager instance."""
    global _session_manager_instance
    if _session_manager_instance is None:
        ws = workspace or Path("exploit_workspace")
        _session_manager_instance = PersistentSessionManager(ws)
    return _session_manager_instance


def reset_session_manager() -> None:
    """Reset the global instance (mainly for testing)."""
    global _session_manager_instance
    _session_manager_instance = None
