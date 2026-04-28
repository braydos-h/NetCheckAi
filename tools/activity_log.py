"""Activity log and audit trail logging (plain CLI)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ICONS = {
    "ping": "●",
    "triage": "▶",
    "basic_scan": "◎",
    "service_scan": "◇",
    "vuln_scan": "◈",
    "search": "◇",
    "agent_spawn": "▶",
    "agent_done": "✔",
    "agent_fail": "✘",
    "report": "◆",
    "blocked": "✘",
    "info": "◉",
    "warning": "⚠",
    "error": "✘",
    "budget": "$",
}

ASCII_ICONS = {
    "ping": "*",
    "triage": ">",
    "basic_scan": "o",
    "service_scan": "+",
    "vuln_scan": "!",
    "search": "?",
    "agent_spawn": ">",
    "agent_done": "OK",
    "agent_fail": "X",
    "report": "#",
    "blocked": "X",
    "info": "i",
    "warning": "!",
    "error": "X",
    "budget": "$",
}

SEVERITY_PREFIX = {
    "critical": "[CRIT] ",
    "high": "[HIGH] ",
    "medium": "[MED]  ",
    "low": "[LOW]  ",
    "info": "",
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
    """Plain activity logger writes JSONL audit trail and prints clean CLI lines."""

    def __init__(
        self,
        reports_dir: Path,
        *,
        max_events: int = 80,
    ):
        self.max_events = max_events
        self.events: list[ActivityEvent] = []
        self.reports_dir = reports_dir
        self.audit_path = reports_dir / "activity.jsonl"
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._start = time.monotonic()
        self._overall_progress: dict[str, Any] = {
            "subnets_total": 0,
            "subnets_done": 0,
            "agents_total": 0,
            "agents_done": 0,
        }
        self._agent_status: dict[str, dict[str, Any]] = {}

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
        icon = ASCII_ICONS.get(category, icon if icon.isascii() else "*")
        prefix = SEVERITY_PREFIX.get(severity, "")
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

        line = f"[{event.timestamp}] {icon} [{category.upper():12}] {prefix}{message}"
        if host:
            line += f"  (host: {host})"
        print(line)
        if detail:
            for dline in detail.splitlines()[:3]:
                dline = dline.strip()
                if dline:
                    print(f"                 {dline[:120]}")

    def set_progress(self, **kwargs: Any) -> None:
        self._overall_progress.update(kwargs)

    def set_agent_status(self, host: str, status: str, **kwargs: Any) -> None:
        self._agent_status[host] = {
            "status": status,
            "updated": self._now(),
            **kwargs,
        }

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def __enter__(self) -> ActivityLog:
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    def ping(self, subnet: str, result: str) -> None:
        self.log("ping", f"Ping sweep {subnet}", detail=result[:200])
        self.set_progress(subnets_done=self._overall_progress["subnets_done"] + 1)

    def triage(self, subnet: str, result: str) -> None:
        self.log("triage", f"Triage scan {subnet}", detail=result[:200])

    def tool_call(self, name: str, arguments: dict[str, Any], result: str = "") -> None:
        detail = f"Args: {json.dumps(arguments)}"
        if result:
            detail += f" | Result: {result[:120]}"
        cat = name.replace("run_nmap_", "").replace("_", " ")
        self.log(cat, name, detail=detail)

    def blocked(self, reason: str) -> None:
        self.log("blocked", "Action blocked", detail=reason, severity="warning")

    def agent_spawn(self, host: str, reason: str) -> None:
        self.log("agent_spawn", f"Spawning sub-agent for {host}", detail=reason, host=host)
        self.set_agent_status(host, "spawning", info=reason)
        self.set_progress(agents_total=self._overall_progress["agents_total"] + 1)

    def agent_scan(self, host: str, scan_type: str) -> None:
        self.log(
            "basic_scan" if scan_type == "basic" else scan_type,
            f"Sub-agent {host}: {scan_type} scan",
            host=host,
        )
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
        self.log("report", "Report written", detail=str(path))

    def budget_warning(self, remaining: int, kind: str) -> None:
        self.log("budget", f"Budget alert: {remaining} {kind} remaining", severity="warning")
