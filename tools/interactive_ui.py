"""Interactive launcher with questionary menus, settings persistence, and help text."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
from pathlib import Path
from typing import Any

import yaml
from questionary import Choice, Style, checkbox, confirm, select, text

from tools.nmap_tools import RFC1918_NETWORKS, SCAN_PROFILES, validate_subnet

CUSTOM_STYLE = Style([
    ("qmark", "fg:cyan bold"),
    ("question", "fg:white bold"),
    ("answer", "fg:green bold"),
    ("pointer", "fg:cyan bold"),
    ("highlighted", "fg:cyan bold"),
    ("selected", "fg:green bold"),
    ("separator", "fg:gray"),
    ("instruction", "fg:gray italic"),
    ("text", ""),
    ("disabled", "fg:gray italic"),
])

HISTORY_PATH = Path.home() / ".config" / "netcheckai" / "history.yaml"


def _ensure_history_dir() -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)


def load_history() -> dict[str, Any]:
    _ensure_history_dir()
    if not HISTORY_PATH.exists():
        return {}
    try:
        with HISTORY_PATH.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def save_history(data: dict[str, Any]) -> None:
    _ensure_history_dir()
    with HISTORY_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def ask_subnets(history: dict[str, Any]) -> list[str]:
    previous = history.get("subnets", [])
    prev_str = ",".join(previous) if previous else ""
    ans = text(
        "Enter approved local subnets (comma-separated):",
        default=prev_str,
        instruction="Example: 192.168.1.0/24, 10.0.0.0/24",
        style=CUSTOM_STYLE,
    ).ask()
    subnets = [s.strip() for s in ans.split(",") if s.strip()]
    validated: list[str] = []
    for s in subnets:
        try:
            validate_subnet(s, RFC1918_NETWORKS, 1024)
            validated.append(s)
        except ValueError as exc:
            print(f"  (!) Skipping invalid subnet {s!r}: {exc}")
    return validated


def ask_profile(history: dict[str, Any]) -> str:
    profiles = list(SCAN_PROFILES.keys())
    default = history.get("profile", "standard")
    if default not in profiles:
        default = "standard"
    choices = [
        Choice(
            title=f"{p:10} - {SCAN_PROFILES[p].description}",
            value=p,
        )
        for p in profiles
    ]
    ans = select(
        "Select scan profile:",
        choices=choices,
        style=CUSTOM_STYLE,
    ).ask()
    return ans


def ask_sub_agents(history: dict[str, Any]) -> bool:
    default = history.get("sub_agents", True)
    return confirm(
        "Enable parallel sub-agents for suspicious hosts?",
        default=default,
        style=CUSTOM_STYLE,
    ).ask()


def ask_approval_mode(history: dict[str, Any]) -> str:
    choices = [
        Choice("auto   - AI proposes, no interruptions", value="auto"),
        Choice("review - Pick next action from a menu", value="review"),
        Choice("manual - Must approve every scan", value="manual"),
    ]
    default = history.get("approval_mode", "auto")
    ans = select(
        "Select approval mode:",
        choices=choices,
        default=next((c for c in choices if c.value == default), choices[0]),
        style=CUSTOM_STYLE,
    ).ask()
    return ans


def ask_search(history: dict[str, Any]) -> bool:
    default = history.get("search", True)
    return confirm(
        "Enable vulnerability-intelligence web search?",
        default=default,
        style=CUSTOM_STYLE,
    ).ask()


def ask_output_formats(history: dict[str, Any]) -> set[str]:
    prev = set(history.get("output_formats", ["markdown"]))
    choices = [
        Choice("Markdown", value="markdown", checked=("markdown" in prev)),
        Choice("HTML", value="html", checked=("html" in prev)),
        Choice("CSV", value="csv", checked=("csv" in prev)),
    ]
    ans = checkbox(
        "Select output report format(s):",
        choices=choices,
        style=CUSTOM_STYLE,
    ).ask()
    return set(ans) if ans else {"markdown"}


def ask_mcp_transport(history: dict[str, Any]) -> str:
    default = history.get("mcp_transport", "stdio")
    ans = select(
        "Select MCP transport:",
        choices=[
            Choice("stdio (default, single process)", value="stdio"),
            Choice("http  (better for parallel sub-agents)", value="http"),
        ],
        style=CUSTOM_STYLE,
    ).ask()
    return ans


def ask_concurrency(history: dict[str, Any]) -> int:
    default = str(history.get("sub_agent_concurrency", 4))
    ans = text(
        "Max concurrent sub-agent scans:",
        default=default,
        validate=lambda v: v.isdigit() and 1 <= int(v) <= 20 or "Enter 1-20",
        style=CUSTOM_STYLE,
    ).ask()
    return int(ans)


def interactive_menu(config: dict[str, Any]) -> dict[str, Any]:
    """Launch the full interactive menu and return a dict of chosen args."""
    history = load_history()

    print()
    print("=" * 40)
    print("  AI-Powered Nmap Assessment")
    print("  Defensive Local Network Scanner")
    print("=" * 40)
    print()

    # Quick mode or full menu
    quick = confirm(
        "Use Quick Start with last saved settings?",
        default=True if history else False,
        style=CUSTOM_STYLE,
    ).ask()

    if quick and history:
        subnets = history.get("subnets", [])
        if not subnets:
            subnets = ask_subnets(history)
    else:
        subnets = ask_subnets(history)

    if not subnets:
        print("(!) No valid subnets provided. Exiting.")
        raise SystemExit(1)

    if quick and history:
        profile = history.get("profile", "standard")
        use_sub_agents = history.get("sub_agents", True)
        approval_mode = history.get("approval_mode", "auto")
        search_enabled = history.get("search", True)
        output_formats = set(history.get("output_formats", ["markdown"]))
        mcp_transport = history.get("mcp_transport", "stdio")
        concurrency = history.get("sub_agent_concurrency", 4)
    else:
        profile = ask_profile(history)
        use_sub_agents = ask_sub_agents(history)
        approval_mode = ask_approval_mode(history)
        search_enabled = ask_search(history)
        output_formats = ask_output_formats(history)
        mcp_transport = ask_mcp_transport(history)
        concurrency = ask_concurrency(history) if use_sub_agents else 4
        if not use_sub_agents:
            mcp_transport = "stdio"

    # Save for next time
    save_history({
        "subnets": subnets,
        "profile": profile,
        "sub_agents": use_sub_agents,
        "approval_mode": approval_mode,
        "search": search_enabled,
        "output_formats": list(output_formats),
        "mcp_transport": mcp_transport,
        "sub_agent_concurrency": concurrency,
    })

    # Build synthetic argparse Namespace
    return {
        "subnet": subnets,
        "mcp_transport": mcp_transport,
        "model": config.get("ollama", {}).get("model", "kimi-k2.6:cloud"),
        "reports_dir": Path(config.get("reports", {}).get("base_dir", "reports")),
        "max_hosts": None,
        "config": Path("config.yaml"),
        "http_port": None,
        "plain": False,
        "no_search": not search_enabled,
        "profile": profile,
        "approval_mode": approval_mode,
        "output": "all" if len(output_formats) == 3 else list(output_formats)[0] if output_formats else "markdown",
        "no_sub_agents": not use_sub_agents,
        "sub_agent_concurrency": concurrency,
        "max_sub_agent_rounds": None,
    }


def approval_prompt(action_desc: str, ai_reason: str | None = None) -> bool:
    """Plain approval prompt for manual/review mode."""
    lines = [f"Action: {action_desc}"]
    if ai_reason:
        lines.append(f"AI Reason: {ai_reason}")
    print("-" * 40)
    print("  Approval Required")
    print("-" * 40)
    for line in lines:
        print(f"  {line}")
    ans = confirm("Approve this action?", default=False, style=CUSTOM_STYLE).ask()
    return ans
