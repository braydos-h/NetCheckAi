"""Real-time activity dashboard with rich live display and audit trail logging."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


ICONS = {
    "ping": "🟢",
    "triage": "🔍",
    "basic_scan": "🔧",
    "service_scan": "🔬",
    "vuln_scan": "🛡️",
    "search": "🌐",
    "agent_spawn": "🧠",
    "agent_done": "✅",
    "agent_fail": "❌",
    "report": "📝",
    "blocked": "🚫",
    "info": "ℹ️",
    "warning": "⚠️",
    "error": "🔴",
    "budget": "💰",
}

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold green",
    "info": "dim",
}


@dataclass
class ActivityEvent:
    timestamp: str
    icon: str
    category: str
    message: str
    detail: str = ""
    host: str = ""
    severity: str = "info"


class ActivityLog:
    """Live activity dashboard + JSONL audit trail."""

    def __init__(
        self,
        reports_dir: Path,
        *,
        console: Console | None = None,
        max_events: int = 80,
        live_refresh: float = 0.5,
    ):
        self.console = console or Console()
        self.max_events = max_events
        self.events: list[ActivityEvent] = []
        self.reports_dir = reports_dir
        self.audit_path = reports_dir / "activity.jsonl"
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._start = time.monotonic()
        self._live: Live | None = None
        self._refresh = live_refresh
        self._agent_status: dict[str, dict[str, Any]] = {}
        self._overall_progress: dict[str, Any] = {
            "subnets_total": 0,
            "subnets_done": 0,
            "agents_total": 0,
            "agents_done": 0,
        }

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%H:%M:%S")

    def _write_audit(self, event: ActivityEvent) -> None:
        entry = {
            "time": event.timestamp,
            "category": event.category,
            "message": event.message,
            "detail": event.detail,
            "host": event.host,
            "severity": event.severity,
        }
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def log(
        self,
        category: str,
        message: str,
        *,
        detail: str = "",
        host: str = "",
        severity: str = "info",
    ) -> None:
        icon = ICONS.get(category, "•")
        event = ActivityEvent(
            timestamp=self._now(),
            icon=icon,
            category=category,
            message=message,
            detail=detail,
            host=host,
            severity=severity,
        )
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)
        self._write_audit(event)
        if self._live:
            self._live.update(self._render())

    def set_progress(self, **kwargs: Any) -> None:
        self._overall_progress.update(kwargs)
        if self._live:
            self._live.update(self._render())

    def set_agent_status(self, host: str, status: str, **kwargs: Any) -> None:
        self._agent_status[host] = {
            "status": status,
            "updated": self._now(),
            **kwargs,
        }
        if self._live:
            self._live.update(self._render())

    def _render(self) -> Group:
        # Top status bar
        elapsed = time.monotonic() - self._start
        mins, secs = divmod(int(elapsed), 60)
        prog = self._overall_progress
        status_parts = [
            f"⏱️ {mins:02d}:{secs:02d}",
            f"Subnets {prog['subnets_done']}/{prog['subnets_total']}",
            f"Agents {prog['agents_done']}/{prog['agents_total']}",
        ]
        status_line = Text("  |  ".join(status_parts), style="bold cyan")

        # Activity table
        table = Table(show_header=False, box=None, padding=(0, 1))
        for ev in self.events[-20:]:
            style = SEVERITY_STYLE.get(ev.severity, "")
            msg = f"{ev.icon} [{ev.timestamp}] {ev.message}"
            if ev.detail:
                msg += f"\n   {ev.detail[:120]}"
            table.add_row(Text(msg, style=style))

        # Agent status mini-table
        agent_table = Table(show_header=True, box=None, padding=(0, 2))
        agent_table.add_column("Host", style="cyan")
        agent_table.add_column("Status", style="white")
        agent_table.add_column("Info", style="dim")
        for host, data in list(self._agent_status.items())[-8:]:
            agent_table.add_row(
                host,
                data.get("status", "unknown"),
                data.get("info", "")[:40],
            )

        panels = [
            Panel(status_line, title="Status", border_style="blue"),
            Panel(table, title="Live Activity", border_style="green", height=18),
        ]
        if self._agent_status:
            panels.append(Panel(agent_table, title="Sub-Agents", border_style="magenta", height=10))

        return Group(*panels)

    def start(self) -> None:
        if not self._live:
            self._live = Live(self._render(), refresh_per_second=2, console=self.console)
            self._live.start()

    def stop(self) -> None:
        if self._live:
            self._live.stop()
            self._live = None

    def __enter__(self) -> ActivityLog:
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    # Convenience wrappers for common events
    def ping(self, subnet: str, result: str) -> None:
        self.log("ping", f"Ping sweep {subnet}", detail=result[:200])
        self.set_progress(subnets_done=self._overall_progress["subnets_done"] + 1)

    def triage(self, subnet: str, result: str) -> None:
        self.log("triage", f"Triage scan {subnet}", detail=result[:200])

    def tool_call(self, name: str, arguments: dict[str, Any], result: str = "") -> None:
        detail = f"Args: {json.dumps(arguments)}"
        if result:
            detail += f" | Result: {result[:120]}"
        self.log(name.replace("run_nmap_", "").replace("_", "_"), name, detail=detail)

    def blocked(self, reason: str) -> None:
        self.log("blocked", "Action blocked", detail=reason, severity="warning")

    def agent_spawn(self, host: str, reason: str) -> None:
        self.log("agent_spawn", f"Spawning sub-agent for {host}", detail=reason, host=host)
        self.set_agent_status(host, "spawning", info=reason)
        self.set_progress(agents_total=self._overall_progress["agents_total"] + 1)

    def agent_scan(self, host: str, scan_type: str) -> None:
        self.log("basic_scan" if scan_type == "basic" else scan_type, f"Sub-agent {host}: {scan_type} scan", host=host)
        self.set_agent_status(host, scan_type)

    def agent_search(self, host: str, query: str) -> None:
        self.log("search", f"Sub-agent {host}: search", detail=query, host=host)
        self.set_agent_status(host, "searching", info=query[:50])

    def agent_done(self, host: str, finding: Any) -> None:
        level = getattr(finding, "risk_level", "low")
        title = getattr(finding, "title", "done")
        self.log(
            "agent_done",
            f"Sub-agent {host} finished ({level.upper()})",
            detail=title,
            host=host,
            severity=level,
        )
        self.set_agent_status(host, f"done ({level})", info=title)
        self.set_progress(agents_done=self._overall_progress["agents_done"] + 1)

    def agent_fail(self, host: str, error: str) -> None:
        self.log("agent_fail", f"Sub-agent {host} failed", detail=error, host=host, severity="error")
        self.set_agent_status(host, "failed", info=error)
        self.set_progress(agents_done=self._overall_progress["agents_done"] + 1)

    def report_written(self, path: Path) -> None:
        self.log("report", f"Report written", detail=str(path))

    def budget_warning(self, remaining: int, kind: str) -> None:
        self.log("budget", f"Budget alert: {remaining} {kind} remaining", severity="warning")
