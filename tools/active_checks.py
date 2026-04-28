"""User-approved active check execution for scan-discovered hosts.

This module is intentionally separate from the MCP server and Nmap wrapper.
It gives host sub-agents a narrow path for generated validation code while
keeping target approval, command review, artifact storage, and audit logs in
normal Python policy code.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import hashlib
import ipaddress
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from tools.nmap_tools import safe_name


ACTIVE_AUDIT_FILENAME = "active_checks.jsonl"

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://([^/\s:]+)", re.IGNORECASE)
SHELL_METACHARS = set("&;|<>`$\\\n\r")

BLOCKED_ACTIVE_TERMS = {
    "brute force",
    "bruteforce",
    "password spray",
    "credential dump",
    "credential theft",
    "dump hashes",
    "mimikatz",
    "reverse shell",
    "bind shell",
    "persistence",
    "backdoor",
    "ransom",
    "exfil",
    "exfiltrate",
    "data theft",
    "rm -rf",
    "format ",
    "shutdown ",
    "reboot ",
    "del /",
    "erase ",
    "schtasks",
    "reg add",
    "reg delete",
    "invoke-expression",
    "iex ",
    "powershell -enc",
    "downloadstring",
}

BLOCKED_SHELL_EXECUTABLES = {
    "bash",
    "bash.exe",
    "cmd",
    "cmd.exe",
    "curl",
    "curl.exe",
    "hydra",
    "msfconsole",
    "nc",
    "nc.exe",
    "netcat",
    "powershell",
    "powershell.exe",
    "pwsh",
    "python",
    "python.exe",
    "python3",
    "py",
    "ssh",
    "ssh.exe",
    "wget",
    "wget.exe",
}

ALLOWED_PYTHON_IMPORTS = {
    "argparse",
    "asyncio",
    "base64",
    "binascii",
    "errno",
    "http",
    "ipaddress",
    "json",
    "re",
    "select",
    "socket",
    "ssl",
    "struct",
    "sys",
    "time",
    "urllib",
}

BLOCKED_PYTHON_CALLS = {
    "__import__",
    "breakpoint",
    "compile",
    "eval",
    "exec",
    "globals",
    "input",
    "locals",
    "open",
}


@dataclass(frozen=True)
class ActiveCheckSettings:
    enabled: bool = False
    terminal: str = "visible"
    review: str = "summary_command"
    consent_mode: str = "per_command"
    workspace_dir: Path = Path("active_checks")
    command_timeout_seconds: int = 90
    max_commands_per_host: int = 3
    max_code_chars: int = 20_000
    max_command_chars: int = 500

    @property
    def preapproved(self) -> bool:
        return self.consent_mode == "preapproved"


@dataclass(frozen=True)
class TerminalExecution:
    status: str
    exit_code: int | None
    log_path: Path
    duration_seconds: float


@dataclass
class ActiveCommandResult:
    host: str
    attempt_id: str
    kind: str
    approved: bool
    status: str
    command: str
    purpose: str
    risk_note: str
    workspace: Path
    log_path: Path | None = None
    script_path: Path | None = None
    exit_code: int | None = None
    code_sha256: str = ""
    error: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "host": self.host,
            "attempt_id": self.attempt_id,
            "kind": self.kind,
            "approved": self.approved,
            "status": self.status,
            "exit_code": self.exit_code,
            "command": self.command,
            "purpose": self.purpose,
            "risk_note": self.risk_note,
            "workspace": str(self.workspace),
            "log_path": str(self.log_path) if self.log_path else "",
            "script_path": str(self.script_path) if self.script_path else "",
            "code_sha256": self.code_sha256,
            "error": self.error,
        }

    def summary(self, *, log_tail: str = "") -> str:
        lines = [
            f"ACTIVE_CHECK_RESULT: {self.status}",
            f"HOST: {self.host}",
            f"ATTEMPT_ID: {self.attempt_id}",
            f"KIND: {self.kind}",
            f"APPROVED: {self.approved}",
            f"EXIT_CODE: {self.exit_code if self.exit_code is not None else 'n/a'}",
            f"COMMAND: {self.command}",
            f"WORKSPACE: {self.workspace}",
        ]
        if self.script_path:
            lines.append(f"SCRIPT: {self.script_path}")
        if self.log_path:
            lines.append(f"LOG: {self.log_path}")
        if self.error:
            lines.append(f"ERROR: {self.error}")
        if log_tail:
            lines.extend(["LOG_TAIL:", log_tail])
        return "\n".join(lines)


class VisibleTerminalRunner:
    """Run approved commands in a separate console where supported."""

    def run(
        self,
        command: str | list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        log_path: Path,
        timeout_seconds: int,
        title: str,
    ) -> TerminalExecution:
        start = time.monotonic()
        cwd.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        merged_env = os.environ.copy()
        merged_env.update(env)

        if platform.system() == "Windows":
            return self._run_windows(
                command,
                cwd=cwd,
                env=merged_env,
                log_path=log_path,
                timeout_seconds=timeout_seconds,
                title=title,
                started_at=start,
            )
        return self._run_headless(
            command,
            cwd=cwd,
            env=merged_env,
            log_path=log_path,
            timeout_seconds=timeout_seconds,
            started_at=start,
        )

    def _run_windows(
        self,
        command: str | list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        log_path: Path,
        timeout_seconds: int,
        title: str,
        started_at: float,
    ) -> TerminalExecution:
        wrapper = cwd / "run_active_check.ps1"
        wrapper.write_text(
            build_powershell_wrapper(command, cwd=cwd, log_path=log_path, title=title),
            encoding="utf-8",
        )
        try:
            proc = subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(wrapper),
                ],
                cwd=str(cwd),
                env=env,
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
            try:
                exit_code = proc.wait(timeout=timeout_seconds)
                status = "completed" if exit_code == 0 else "failed"
            except subprocess.TimeoutExpired:
                proc.kill()
                exit_code = None
                status = "timed_out"
                append_text(log_path, f"\nACTIVE CHECK TIMED OUT after {timeout_seconds} seconds.\n")
        except FileNotFoundError:
            return self._run_headless(
                command,
                cwd=cwd,
                env=env,
                log_path=log_path,
                timeout_seconds=timeout_seconds,
                started_at=started_at,
            )
        ensure_log_exists(log_path)
        return TerminalExecution(
            status=status,
            exit_code=exit_code,
            log_path=log_path,
            duration_seconds=time.monotonic() - started_at,
        )

    def _run_headless(
        self,
        command: str | list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        log_path: Path,
        timeout_seconds: int,
        started_at: float,
    ) -> TerminalExecution:
        with log_path.open("w", encoding="utf-8", errors="replace") as handle:
            handle.write(f"COMMAND: {command_to_display(command)}\n\n")
            try:
                proc = subprocess.Popen(
                    command,
                    cwd=str(cwd),
                    env=env,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    shell=isinstance(command, str),
                    text=True,
                )
                try:
                    exit_code = proc.wait(timeout=timeout_seconds)
                    status = "completed" if exit_code == 0 else "failed"
                except subprocess.TimeoutExpired:
                    proc.kill()
                    exit_code = None
                    status = "timed_out"
                    handle.write(f"\nACTIVE CHECK TIMED OUT after {timeout_seconds} seconds.\n")
            except FileNotFoundError as exc:
                exit_code = None
                status = "failed"
                handle.write(f"ERROR: {exc}\n")
        return TerminalExecution(
            status=status,
            exit_code=exit_code,
            log_path=log_path,
            duration_seconds=time.monotonic() - started_at,
        )


class ActiveCheckPolicy:
    """Approval and execution policy for one assessment run."""

    def __init__(
        self,
        *,
        settings: ActiveCheckSettings,
        reports_dir: Path,
        approved_subnets: Iterable[ipaddress.IPv4Network],
        completed_ping_sweeps: Iterable[str],
        live_hosts_by_subnet: dict[str, set[str]],
        triaged_subnets: Iterable[str],
        runner: VisibleTerminalRunner | None = None,
        prompt_func: Callable[[str], str] | None = None,
        activity_log: Any | None = None,
    ) -> None:
        self.settings = settings
        self.reports_dir = reports_dir
        self.workspace_root = self._workspace_root(reports_dir, settings.workspace_dir)
        self.approved_subnets = tuple(approved_subnets)
        self.completed_ping_sweeps = set(completed_ping_sweeps)
        self.live_hosts_by_subnet = {subnet: set(hosts) for subnet, hosts in live_hosts_by_subnet.items()}
        self.triaged_subnets = set(triaged_subnets)
        self.runner = runner or VisibleTerminalRunner()
        self.prompt_func = prompt_func or input
        self.activity_log = activity_log
        self._host_sessions: dict[str, bool] = {}
        self._commands_by_host: dict[str, int] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _workspace_root(reports_dir: Path, configured: Path) -> Path:
        return configured if configured.is_absolute() else reports_dir / configured

    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    async def request_host_session(self, ip: str, reason: str) -> str:
        async with self._lock:
            return await asyncio.to_thread(self._request_host_session_sync, ip, reason)

    async def propose_active_python(
        self,
        *,
        ip: str,
        filename: str,
        code: str,
        command: str,
        purpose: str,
        risk_note: str,
    ) -> str:
        async with self._lock:
            return await asyncio.to_thread(
                self._propose_active_python_sync,
                ip,
                filename,
                code,
                command,
                purpose,
                risk_note,
            )

    async def propose_active_shell(
        self,
        *,
        ip: str,
        command: str,
        purpose: str,
        risk_note: str,
    ) -> str:
        async with self._lock:
            return await asyncio.to_thread(
                self._propose_active_shell_sync,
                ip,
                command,
                purpose,
                risk_note,
            )

    def _request_host_session_sync(self, ip: str, reason: str) -> str:
        allowed, message = self._host_is_eligible(ip)
        if not allowed:
            return f"BLOCKED: {message}"
        host = str(ipaddress.ip_address(ip))
        if self._host_sessions.get(host):
            return f"ACTIVE_SESSION: {host} is already approved for active checks in this run."
        if self.settings.preapproved:
            self._host_sessions[host] = True
            self._log(
                "active_approval",
                f"Active host preapproved: {host}",
                detail="active_checks.consent_mode=preapproved",
                host=host,
            )
            return f"ACTIVE_SESSION: preapproved for {host}."

        prompt = (
            "\n[ACTIVE HOST APPROVAL REQUIRED]\n"
            f"Target: {host}\n"
            f"Reason: {trim_for_prompt(reason)}\n"
            "This allows the model to propose custom active checks for this host only.\n"
            f"Type ALLOW {host} to approve this host session: "
        )
        if self._ask(prompt, host):
            self._host_sessions[host] = True
            self._log("active_approval", f"Active host approved: {host}", detail=reason, host=host)
            return f"ACTIVE_SESSION: approved for {host}."
        self._host_sessions[host] = False
        self._log("blocked", f"Active host denied: {host}", detail=reason, host=host)
        return "BLOCKED: user declined active host approval."

    def _propose_active_python_sync(
        self,
        ip: str,
        filename: str,
        code: str,
        command: str,
        purpose: str,
        risk_note: str,
    ) -> str:
        allowed, message = self._can_run_command(ip)
        if not allowed:
            return f"BLOCKED: {message}"
        host = str(ipaddress.ip_address(ip))

        try:
            filename = validate_python_filename(filename)
            validate_common_text("purpose", purpose, self.settings.max_command_chars)
            validate_common_text("risk_note", risk_note, self.settings.max_command_chars)
            validate_python_source(code, target_ip=host, max_chars=self.settings.max_code_chars)
            if command:
                validate_common_text("command", command, self.settings.max_command_chars)
                validate_text_scope(command, target_ip=host)
        except ValueError as exc:
            result = self._record_rejected(host, "python", purpose, risk_note, command, str(exc))
            return result.summary()

        attempt_dir, attempt_id = self._attempt_dir(host)
        script_path = ensure_within(attempt_dir / filename, attempt_dir)
        script_path.write_text(code, encoding="utf-8")
        code_sha = hashlib.sha256(code.encode("utf-8")).hexdigest()
        argv = [sys.executable, str(script_path), "--target", host]
        command_display = command_to_display(argv)
        log_path = attempt_dir / "active_check.log"

        if not self._approve_command(host, purpose, risk_note, command_display, script_path):
            result = ActiveCommandResult(
                host=host,
                attempt_id=attempt_id,
                kind="python",
                approved=False,
                status="denied",
                command=command_display,
                purpose=purpose,
                risk_note=risk_note,
                workspace=attempt_dir,
                log_path=log_path,
                script_path=script_path,
                code_sha256=code_sha,
                error="user declined command approval",
            )
            self._write_record(result)
            return result.summary()

        self._commands_by_host[host] = self._commands_by_host.get(host, 0) + 1
        execution = self.runner.run(
            argv,
            cwd=attempt_dir,
            env={"ACTIVE_CHECK_TARGET": host, "ACTIVE_CHECK_WORKSPACE": str(attempt_dir)},
            log_path=log_path,
            timeout_seconds=self.settings.command_timeout_seconds,
            title=f"NetCheckAI active check {host}",
        )
        result = ActiveCommandResult(
            host=host,
            attempt_id=attempt_id,
            kind="python",
            approved=True,
            status=execution.status,
            command=command_display,
            purpose=purpose,
            risk_note=risk_note,
            workspace=attempt_dir,
            log_path=execution.log_path,
            script_path=script_path,
            exit_code=execution.exit_code,
            code_sha256=code_sha,
        )
        self._write_record(result)
        self._log("active_check", f"Active Python check {execution.status}: {host}", detail=command_display, host=host)
        return result.summary(log_tail=read_tail(execution.log_path, 4000))

    def _propose_active_shell_sync(
        self,
        ip: str,
        command: str,
        purpose: str,
        risk_note: str,
    ) -> str:
        allowed, message = self._can_run_command(ip)
        if not allowed:
            return f"BLOCKED: {message}"
        host = str(ipaddress.ip_address(ip))

        try:
            validate_shell_command(command, target_ip=host, max_chars=self.settings.max_command_chars)
            validate_common_text("purpose", purpose, self.settings.max_command_chars)
            validate_common_text("risk_note", risk_note, self.settings.max_command_chars)
        except ValueError as exc:
            result = self._record_rejected(host, "shell", purpose, risk_note, command, str(exc))
            return result.summary()

        attempt_dir, attempt_id = self._attempt_dir(host)
        command_path = attempt_dir / "approved_command.txt"
        command_path.write_text(command, encoding="utf-8")
        log_path = attempt_dir / "active_check.log"

        if not self._approve_command(host, purpose, risk_note, command, command_path):
            result = ActiveCommandResult(
                host=host,
                attempt_id=attempt_id,
                kind="shell",
                approved=False,
                status="denied",
                command=command,
                purpose=purpose,
                risk_note=risk_note,
                workspace=attempt_dir,
                log_path=log_path,
                script_path=command_path,
                error="user declined command approval",
            )
            self._write_record(result)
            return result.summary()

        self._commands_by_host[host] = self._commands_by_host.get(host, 0) + 1
        execution = self.runner.run(
            command,
            cwd=attempt_dir,
            env={"ACTIVE_CHECK_TARGET": host, "ACTIVE_CHECK_WORKSPACE": str(attempt_dir)},
            log_path=log_path,
            timeout_seconds=self.settings.command_timeout_seconds,
            title=f"NetCheckAI active command {host}",
        )
        result = ActiveCommandResult(
            host=host,
            attempt_id=attempt_id,
            kind="shell",
            approved=True,
            status=execution.status,
            command=command,
            purpose=purpose,
            risk_note=risk_note,
            workspace=attempt_dir,
            log_path=execution.log_path,
            script_path=command_path,
            exit_code=execution.exit_code,
        )
        self._write_record(result)
        self._log("active_check", f"Active shell command {execution.status}: {host}", detail=command, host=host)
        return result.summary(log_tail=read_tail(execution.log_path, 4000))

    def _host_is_eligible(self, ip: str) -> tuple[bool, str]:
        if not self.settings.enabled:
            return False, "active checks are disabled for this run."
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"{ip!r} is not a valid IP address."
        if target.version != 4:
            return False, "only IPv4 active checks are supported."
        if not any(target in subnet for subnet in self.approved_subnets):
            return False, f"{target} is outside the approved scan scope."

        matching_subnets = [
            subnet
            for subnet in self.completed_ping_sweeps
            if target in ipaddress.ip_network(subnet)
        ]
        if not matching_subnets:
            return False, f"ping sweep must complete before active checks for {target}."
        if not any(str(target) in self.live_hosts_by_subnet.get(subnet, set()) for subnet in matching_subnets):
            return False, f"{target} was not reported alive by discovery."
        if not any(target in ipaddress.ip_network(subnet) for subnet in self.triaged_subnets):
            return False, f"triage must complete before active checks for {target}."
        return True, ""

    def _can_run_command(self, ip: str) -> tuple[bool, str]:
        allowed, message = self._host_is_eligible(ip)
        if not allowed:
            return False, message
        host = str(ipaddress.ip_address(ip))
        if not self._host_sessions.get(host):
            if self.settings.preapproved:
                self._host_sessions[host] = True
            else:
                return False, f"active host session has not been approved for {host}."
        if self._commands_by_host.get(host, 0) >= self.settings.max_commands_per_host:
            return False, f"max active commands reached for {host}."
        return True, ""

    def _attempt_dir(self, host: str) -> tuple[Path, str]:
        attempt_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        attempt_dir = ensure_within(self.workspace_root / safe_name(host) / attempt_id, self.workspace_root)
        attempt_dir.mkdir(parents=True, exist_ok=True)
        return attempt_dir, attempt_id

    def _approve_command(
        self,
        host: str,
        purpose: str,
        risk_note: str,
        command: str,
        artifact_path: Path,
    ) -> bool:
        if self.settings.preapproved:
            self._log(
                "active_approval",
                f"Active command preapproved: {host}",
                detail=command,
                host=host,
            )
            return True
        prompt = (
            "\n[ACTIVE COMMAND APPROVAL REQUIRED]\n"
            f"Target: {host}\n"
            f"Purpose: {trim_for_prompt(purpose)}\n"
            f"Risk note: {trim_for_prompt(risk_note)}\n"
            f"Artifact: {artifact_path}\n"
            f"Command: {command}\n"
            f"Type ALLOW {host} to run this command: "
        )
        approved = self._ask(prompt, host)
        if approved:
            self._log("active_approval", f"Active command approved: {host}", detail=command, host=host)
        else:
            self._log("blocked", f"Active command denied: {host}", detail=command, host=host)
        return approved

    def _ask(self, prompt: str, host: str) -> bool:
        try:
            answer = self.prompt_func(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return False
        return answer == f"ALLOW {host}"

    def _record_rejected(
        self,
        host: str,
        kind: str,
        purpose: str,
        risk_note: str,
        command: str,
        error: str,
    ) -> ActiveCommandResult:
        attempt_dir, attempt_id = self._attempt_dir(host)
        result = ActiveCommandResult(
            host=host,
            attempt_id=attempt_id,
            kind=kind,
            approved=False,
            status="blocked",
            command=command,
            purpose=purpose,
            risk_note=risk_note,
            workspace=attempt_dir,
            error=error,
        )
        self._write_record(result)
        self._log("blocked", f"Active {kind} blocked: {host}", detail=error, host=host)
        return result

    def _write_record(self, result: ActiveCommandResult) -> None:
        audit_path = self.reports_dir / ACTIVE_AUDIT_FILENAME
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(result.to_json(), default=str) + "\n")

    def _log(self, category: str, message: str, *, detail: str = "", host: str = "") -> None:
        if not self.activity_log:
            return
        severity = "warning" if category == "blocked" else "info"
        self.activity_log.log(category, message, detail=detail, host=host, severity=severity)


def validate_common_text(name: str, value: str, max_chars: int) -> None:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{name} is required.")
    if len(text) > max_chars:
        raise ValueError(f"{name} is too long.")
    if re.search(r"[\n\r]", text):
        raise ValueError(f"{name} must be a single line.")


def validate_text_scope(text: str, *, target_ip: str | None) -> None:
    lowered = text.lower()
    for term in BLOCKED_ACTIVE_TERMS:
        if term in lowered:
            raise ValueError(f"blocked active-check term {term!r} is not allowed.")

    for raw_ip in IPV4_RE.findall(text):
        try:
            parsed = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if target_ip is not None and str(parsed) != target_ip:
            raise ValueError(f"active checks may only reference target IP {target_ip}; found {parsed}.")

    for host in URL_RE.findall(text):
        if target_ip is None:
            continue
        if host != target_ip:
            raise ValueError("active checks may not reference non-target URLs.")


def validate_python_filename(filename: str) -> str:
    cleaned = str(filename or "").strip().replace("\\", "/").split("/")[-1]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}\.py", cleaned):
        raise ValueError("python filename must be a simple .py file name.")
    return cleaned


def validate_python_source(code: str, *, target_ip: str, max_chars: int) -> None:
    if not code or not code.strip():
        raise ValueError("python code is required.")
    if len(code) > max_chars:
        raise ValueError("python code is too long.")
    validate_text_scope(code, target_ip=target_ip)
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise ValueError(f"python code has a syntax error: {exc.msg}") from exc

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root not in ALLOWED_PYTHON_IMPORTS:
                    raise ValueError(f"python import {alias.name!r} is not allowed.")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".", 1)[0]
            if root not in ALLOWED_PYTHON_IMPORTS:
                raise ValueError(f"python import {node.module!r} is not allowed.")
        elif isinstance(node, ast.Call):
            name = call_name(node.func)
            if name in BLOCKED_PYTHON_CALLS or name.endswith(".system") or name.endswith(".popen"):
                raise ValueError(f"python call {name!r} is not allowed.")


def validate_shell_command(command: str, *, target_ip: str, max_chars: int) -> None:
    text = str(command or "").strip()
    if not text:
        raise ValueError("command is required.")
    if len(text) > max_chars:
        raise ValueError("command is too long.")
    if target_ip not in text:
        raise ValueError(f"command must include the target IP {target_ip}.")
    if any(char in text for char in SHELL_METACHARS):
        raise ValueError("shell metacharacters are not allowed in active commands.")
    validate_text_scope(text, target_ip=target_ip)
    try:
        tokens = shlex.split(text, posix=False)
    except ValueError as exc:
        raise ValueError("command could not be parsed safely.") from exc
    if not tokens:
        raise ValueError("command is required.")
    executable = Path(tokens[0].strip("\"'")).name.lower()
    if executable in BLOCKED_SHELL_EXECUTABLES:
        raise ValueError(f"active command executable {executable!r} is not allowed.")


def call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return ""


def ensure_within(path: Path, root: Path) -> Path:
    root_resolved = root.resolve()
    path_resolved = path.resolve()
    if root_resolved != path_resolved and root_resolved not in path_resolved.parents:
        raise ValueError(f"path {path} is outside active-check workspace {root}.")
    return path


def command_to_display(command: str | list[str]) -> str:
    if isinstance(command, str):
        return command
    if platform.system() == "Windows":
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def build_powershell_wrapper(command: str | list[str], *, cwd: Path, log_path: Path, title: str) -> str:
    if isinstance(command, list):
        exe = ps_quote(command[0])
        args = ", ".join(ps_quote(arg) for arg in command[1:])
        command_block = f"$activeArgs = @({args})\n& {exe} @activeArgs 2>&1 | Tee-Object -FilePath {ps_quote(str(log_path))} -Append"
    else:
        command_block = f"& cmd.exe /d /s /c {ps_quote(command)} 2>&1 | Tee-Object -FilePath {ps_quote(str(log_path))} -Append"

    return "\n".join(
        [
            "$ErrorActionPreference = 'Continue'",
            f"$Host.UI.RawUI.WindowTitle = {ps_quote(title)}",
            f"Set-Location -LiteralPath {ps_quote(str(cwd))}",
            f"'COMMAND: {command_to_display(command)}' | Tee-Object -FilePath {ps_quote(str(log_path))}",
            "'' | Tee-Object -FilePath " + ps_quote(str(log_path)) + " -Append",
            command_block,
            "$exitCode = if ($LASTEXITCODE -ne $null) { $LASTEXITCODE } else { 0 }",
            f"'EXIT_CODE: ' + $exitCode | Tee-Object -FilePath {ps_quote(str(log_path))} -Append",
            "exit $exitCode",
            "",
        ]
    )


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def append_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write(text)


def ensure_log_exists(path: Path) -> None:
    if not path.exists():
        path.write_text("", encoding="utf-8")


def read_tail(path: Path, limit: int) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= limit:
        return text
    return text[-limit:]


def trim_for_prompt(value: str, limit: int = 500) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def read_active_check_records(reports_dir: Path) -> list[dict[str, Any]]:
    path = reports_dir / ACTIVE_AUDIT_FILENAME
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        with contextlib.suppress(json.JSONDecodeError):
            payload = json.loads(line)
            if isinstance(payload, dict):
                records.append(payload)
    return records
