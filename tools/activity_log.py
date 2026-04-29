"""Activity log and audit trail logging (plain CLI)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ICONS = {
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

SEVERITY_COLOR = {
    "critical": "\x1b[1;31m",
    "high": "\x1b[31m",
    "medium": "\x1b[33m",
    "low": "\x1b[32m",
    "info": "\x1b[36m",
    "warning": "\x1b[33m",
    "error": "\x1b[1;31m",
}
RESET = "\x1b[0m"


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
    """Plain activity logger that writes JSONL audit trail and prints clean CLI lines."""

    def __init__(
        self,
        reports_dir: Path,
        *,
        plain: bool = False,
        max_events: int = 80,
    ):
        self.plain = plain
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

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%H:%M:%S")

    def _elapsed(self) -> str:
        elapsed = int(time.monotonic() - self._start)
        m, s = divmod(elapsed, 60)
        return f"{m:02d}:{s:02d}"

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

    def _fmt_line(self, event: ActivityEvent) -> str:
        icon = ICONS.get(event.category, "*")
        sev = event.severity
        if sev in ("critical", "high", "medium", "low", "info", "warning", "error"):
            label = sev.upper()[:4]
        else:
            label = "INFO"
        parts = ["", event.timestamp, icon, f"[{label:4}]", event.message]
        if event.host:
            parts.append(f"[{event.host}]")
        return " ".join(parts)

    def _print(self, text: str, severity: str = "info") -> None:
        if self.plain:
            print(text)
            return
        color = SEVERITY_COLOR.get(severity, "")
        print(f"{color}{text}{RESET}")

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def log(
        self,
        category: str,
        message: str,
        *,
        detail: str = "",
        host: str = "",
        severity: str = "info",
    ) -> None:
        event = ActivityEvent(
            timestamp=self._now(),
            icon=ICONS.get(category, "*"),
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

        self._print(self._fmt_line(event), severity=event.severity)
        if detail:
            for dline in detail.splitlines()[:3]:
                dline = dline.strip()
                if dline:
                    self._print(f"                 {dline[:120]}", severity="info")

    def progress(self) -> str:
        """Return a one-line progress string."""
        s = self._overall_progress
        parts: list[str] = []
        if s["subnets_total"]:
            parts.append(f"subnets {s['subnets_done']}/{s['subnets_total']}")
        if s["agents_total"]:
            parts.append(f"agents {s['agents_done']}/{s['agents_total']}")
        return f"elapsed {self._elapsed()}  {' | '.join(parts)}"

    def print_progress(self) -> None:
        text = self.progress()
        if self.plain:
            print(text)
        else:
            print(f"\x1b[90m{text}\x1b[0m")

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

    # Convenience wrappers used by main.py / sub_agents -----------------
    def ping(self, subnet: str, result: str) -> None:
        self.log("ping", f"Ping sweep {subnet}", detail=result[:200])
        self.set_progress(subnets_done=self._overall_progress["subnets_done"] + 1)

    def triage(self, subnet: str, result: str) -> None:
        self.log("triage", f"Triage scan {subnet}", detail=result[:200])

    def tool_call(self, name: str, arguments: dict[str, Any], result: str = "") -> None:
        detail = f"Args: {json.dumps(arguments)}"
        if result:
            detail += f" | Result: {result[:120]}"
        cat = name.replace("run_nmap_", "").replace("_", "_")
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
