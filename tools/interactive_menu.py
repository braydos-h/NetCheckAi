"""Interactive menu system for BreachPilot.

Provides a polished arrow-key-driven menu when `python main.py` is run
with no arguments. Uses questionary for rich terminal interaction.

Architecture:
    MainMenu ──> Start New Session ──> Interactive wizard (attack_ui.py)
             ├──> Manage Missions ──> CLI backend
             ├──> View Reports ──> reports/ browser
             ├──> Settings ──> config.yaml editor
             ├──> Help ──> quick reference
             └──> Exit
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

try:
    import questionary
    from questionary import Choice, Style

    _HAS_QUESTIONARY = True
except ImportError:
    _HAS_QUESTIONARY = False
    Choice = None  # type: ignore
    Style = None  # type: ignore


# ── Styling ────────────────────────────────────────────────────────────────


def _get_style() -> Style | None:
    if not _HAS_QUESTIONARY or Style is None:
        return None
    return Style(
        [
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
        ]
    )


# ── Main Menu ──────────────────────────────────────────────────────────────


def _fallback_main_menu() -> str | None:
    """Simple numbered menu fallback when questionary is unavailable."""
    options = {
        "1": "recon_first",
        "2": "new_session",
        "3": "missions",
        "4": "reports",
        "5": "settings",
        "6": "help",
        "7": "exit",
    }
    print("\nMain Menu:")
    print("  1. Recon & Suggest Goals")
    print("  2. Start New Session")
    print("  3. Manage Missions")
    print("  4. View Reports")
    print("  5. Settings")
    print("  6. Help")
    print("  7. Exit")
    try:
        choice = input("\n  > ").strip()
        return options.get(choice, "exit")
    except (EOFError, KeyboardInterrupt):
        return "exit"


# ── Sub-menus ──────────────────────────────────────────────────────────────


def _manage_missions() -> None:
    """Mission management submenu — list, create, delete missions."""
    try:
        from pathlib import Path

        from db import DatabaseManager
        from mission import MissionController

        ws = Path(os.environ.get("RESEARCH_WORKSPACE", "research_workspace"))
        ws.mkdir(parents=True, exist_ok=True)
        db = DatabaseManager(ws / "research.db")
        ctrl = MissionController(db, ws)

        while True:
            missions = _list_missions(db)
            choices = []
            for m in missions:
                status_icon = "✓" if m.get("status") == "active" else " "
                choices.append(
                    Choice(
                        title=f"  [{status_icon}] {m.get('program_name', '?')} ({m.get('risk_profile', '?')})",
                        value=m.get("id", ""),
                    )
                )
            choices.append(Choice(title="  ── Actions ──", value="__sep__"))
            choices.append(Choice(title="  + Create New Mission", value="__create__"))
            choices.append(Choice(title="  ← Back to Main Menu", value="__back__"))

            if not _HAS_QUESTIONARY:
                _fallback_mission_menu(missions)
                return

            selected = questionary.select(
                "Select a mission or action:",
                choices=choices,
                style=_get_style(),
            ).unsafe_ask()

            if selected == "__back__":
                return
            elif selected == "__create__":
                _create_mission_interactive(ctrl)
            elif selected == "__sep__":
                continue
            elif selected:
                _mission_detail(db, ctrl, selected)
    except ImportError as exc:
        print(f"ERROR: Backend modules not available: {exc}")
    except Exception as exc:
        print(f"ERROR: {exc}")


def _list_missions(db: Any) -> list[dict[str, Any]]:
    """List all missions from the database."""
    with db.connection() as conn:
        db.ensure_schema(conn)
        cur = conn.execute(
            "SELECT id, program_name, risk_profile, status, created_at FROM missions ORDER BY created_at DESC"
        )
        return [dict(r) for r in cur.fetchall()]


def _fallback_mission_menu(missions: list[dict[str, Any]]) -> None:
    """Fallback mission menu without questionary."""
    print("\nMissions:")
    for i, m in enumerate(missions, 1):
        status = "✓" if m.get("status") == "active" else " "
        print(f"  {i}. [{status}] {m.get('program_name', '?')} ({m.get('risk_profile', '?')})")
    print("  n. Create New Mission")
    print("  b. Back to Main Menu")
    try:
        choice = input("\n  > ").strip().lower()
        if choice == "b":
            return
        elif choice == "n":
            # Would need ctrl reference; skip for fallback
            print("Use questionary for full mission management.")
    except (EOFError, KeyboardInterrupt):
        pass


def _create_mission_interactive(ctrl: Any) -> None:
    """Interactive mission creation."""
    if not _HAS_QUESTIONARY:
        print("\nMission creation requires questionary. Install: pip install questionary")
        return

    print("\n[Create New Mission]\n")

    name = questionary.text(
        "Program name:",
        validate=lambda v: len(v.strip()) > 0 or "Name cannot be empty",
        style=_get_style(),
    ).unsafe_ask()

    if not name:
        return

    objective = questionary.text(
        "Objective:",
        default="Identify valid, in-scope, non-destructive security issues.",
        style=_get_style(),
    ).unsafe_ask()

    risk = questionary.select(
        "Risk profile:",
        choices=[
            Choice(title="Low-Noise (safe) — Recon + Analysis only", value="low_noise_non_destructive"),
            Choice(title="Standard — Authorized bug bounty", value="standard_authorized"),
            Choice(title="High — Full exploitation (OWNED INFRA ONLY)", value="high_authorized_testing"),
        ],
        style=_get_style(),
    ).unsafe_ask()

    assets = questionary.text(
        "Allowed assets (comma-separated):",
        default="example.com, *.example.com",
        style=_get_style(),
    ).unsafe_ask()

    allowed = [a.strip() for a in (assets or "").split(",") if a.strip()]

    config = {
        "program_name": name,
        "objective": objective or "",
        "risk_profile": risk or "standard_authorized",
        "allowed_assets": allowed,
        "disallowed_assets": [],
        "forbidden_actions": [
            "denial_of_service",
            "destructive_exploit",
            "credential_theft",
            "social_engineering",
            "physical_attack",
            "persistence",
            "malware",
            "uncontrolled_fuzzing",
        ],
        "testing_modes": ["recon", "analysis", "report"],
        "rate_limits": {"default_requests_per_second": 2, "max_concurrent_requests": 3},
        "accounts": [],
        "notes": "",
    }

    try:
        mission = ctrl.create_from_config(config)
        print(f"\n  ✓ Mission '{mission.program_name}' created! ID: {mission.mission_id}")
    except ValueError as exc:
        print(f"\n  ✗ Validation error: {exc}")


def _mission_detail(db: Any, ctrl: Any, mission_id: str) -> None:
    """Show mission detail and allow actions."""
    with db.connection() as conn:
        cur = conn.execute("SELECT * FROM missions WHERE id=?", (mission_id,))
        row = cur.fetchone()
        if not row:
            print("Mission not found.")
            return
        data = dict(row)

    print(f"\n{'=' * 60}")
    print(f"  Mission: {data.get('program_name', '?')}")
    print(f"{'=' * 60}")
    print(f"  ID:           {data.get('id', '?')}")
    print(f"  Status:       {data.get('status', '?')}")
    print(f"  Risk Profile: {data.get('risk_profile', '?')}")
    print(f"  Objective:    {data.get('objective', '?')}")
    print(f"  Created:      {data.get('created_at', '?')}")
    print()

    if _HAS_QUESTIONARY:
        action = questionary.select(
            "Action:",
            choices=[
                Choice(title="← Back", value="back"),
            ],
            style=_get_style(),
        ).unsafe_ask()


def _view_reports() -> None:
    """Browse generated reports in the reports/ directory."""
    reports_dir = Path("reports")
    if not reports_dir.exists():
        print("\nNo reports directory found. Run a session first.")
        return

    sessions = sorted(
        [d for d in reports_dir.iterdir() if d.is_dir()],
        reverse=True,
    )

    if not sessions:
        print("\nNo report sessions found.")
        return

    if not _HAS_QUESTIONARY:
        print("\nReports:")
        for i, s in enumerate(sessions[:20], 1):
            summary = s / "session_summary.md"
            has_summary = "📄" if summary.exists() else "  "
            print(f"  {i}. {has_summary} {s.name}")
        return

    choices = []
    for s in sessions[:30]:
        summary = s / "session_summary.md"
        has_summary = "📄" if summary.exists() else "  "
        choices.append(
            Choice(
                title=f"  {has_summary} {s.name}",
                value=str(s),
            )
        )
    choices.append(Choice(title="← Back to Main Menu", value="__back__"))

    while True:
        selected = questionary.select(
            "Select a report session to view:",
            choices=choices,
            style=_get_style(),
        ).unsafe_ask()

        if selected == "__back__":
            return
        elif selected:
            _preview_report(Path(selected))


def _preview_report(session_dir: Path) -> None:
    """Preview a session report."""
    summary_path = session_dir / "session_summary.md"
    activity_path = session_dir / "activity.jsonl"

    print(f"\n{'=' * 60}")
    print(f"  Report: {session_dir.name}")
    print(f"{'=' * 60}")

    if summary_path.exists():
        content = summary_path.read_text(encoding="utf-8")
        print(content[:2000])
        if len(content) > 2000:
            print(f"\n... ({len(content) - 2000} more characters)")
    else:
        print("  No summary available.")

    if activity_path.exists():
        lines = activity_path.read_text(encoding="utf-8").strip().splitlines()
        print(f"\n  Activity entries: {len(lines)}")

    print()


def _edit_settings() -> None:
    """Edit config.yaml values interactively."""
    config_path = Path("config.yaml")
    if not config_path.exists():
        print("\nconfig.yaml not found. Creating default...")
        _create_default_config(config_path)

    import yaml

    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    if not _HAS_QUESTIONARY:
        print("\nSettings editing requires questionary. Install: pip install questionary")
        return

    print("\n[Settings Editor]\n")

    # Ollama host
    current_host = config.get("ollama", {}).get("host", "http://localhost:11434")
    new_host = questionary.text(
        "Ollama host URL:",
        default=current_host,
        style=_get_style(),
    ).unsafe_ask()

    # AI provider selection (ollama | chatgpt | opencode_go). Defaults to ollama so an
    # absent key (the common case) is unchanged.
    from tools.config_manager import get_ai_provider, get_chatgpt_config, get_opencode_go_config

    current_provider = get_ai_provider(config)
    provider = questionary.select(
        "AI provider (chat/generate):",
        choices=[
            Choice(title="Ollama (local or Ollama Cloud)", value="ollama"),
            Choice(title="ChatGPT (local openai-oauth proxy)", value="chatgpt"),
            Choice(title="OpenCode Go (Responses API)", value="opencode_go"),
        ],
        default=current_provider if current_provider in ("ollama", "chatgpt", "opencode_go") else "ollama",
        style=_get_style(),
    ).unsafe_ask()

    chatgpt_cfg = get_chatgpt_config(config)
    if provider == "chatgpt":
        # Auth status (bool only — never read token contents) + sign-in flow.
        from tools.providers.chatgpt_provider import ChatGptProxyManager

        manager = ChatGptProxyManager.get()
        if not manager.is_authenticated(chatgpt_cfg):
            print("\n  ChatGPT: not signed in yet.")
            do_login = questionary.confirm(
                "Sign in with ChatGPT now? (opens a browser OAuth flow)",
                default=True,
                style=_get_style(),
            ).unsafe_ask()
            if do_login:
                result = manager.run_login_open(chatgpt_cfg)
                if not result.get("ok") and result.get("reason") != "already_authenticated":
                    print(f"\n  Login could not start: {result.get('reason')}")
        # Ensure the proxy is running so discovery works.
        running = manager.ensure_running(chatgpt_cfg)
        proxy_models = []
        if running.get("ok"):
            proxy_models = manager.discover_models(running["base_url"], chatgpt_cfg)
        if not proxy_models:
            configured = list(chatgpt_cfg.get("models") or [])
            proxy_models = configured or [str(chatgpt_cfg.get("default_model") or "gpt-5.2")]
        default_model = str(chatgpt_cfg.get("default_model") or proxy_models[0])
        new_model = questionary.select(
            "ChatGPT model (discovered from /v1/models):",
            choices=[Choice(title=m, value=m) for m in proxy_models],
            default=default_model if default_model in proxy_models else proxy_models[0],
            style=_get_style(),
        ).unsafe_ask()
        # Skip the Ollama alias picker below.
        _skip_ollama_picker = True
    elif provider == "opencode_go":
        from tools.providers.opencode_go_provider import OpenCodeGoResponsesClient

        og_cfg = get_opencode_go_config(config)
        env_name = str(og_cfg.get("api_key_env") or "OPENCODE_GO_API_KEY")
        api_key = (os.environ.get(env_name, "") or "").strip()
        if not api_key:
            print(
                f"\n  OpenCode Go: API key not set ({env_name}). Set it via 'python main.py --setup-api-keys' or env."
            )
        else:
            # Probe discovery (best-effort)
            try:
                client = OpenCodeGoResponsesClient(
                    base_url=str(og_cfg.get("base_url") or "https://opencode.ai/zen/go/v1"),
                    api_key=api_key,
                    timeout=float(og_cfg.get("request_timeout_seconds") or 300),
                    config=og_cfg,
                )
                proxy_models = client.discover_models(
                    str(og_cfg.get("base_url") or "https://opencode.ai/zen/go/v1"), og_cfg
                )
            except Exception as exc:
                print(f"\n  OpenCode Go discovery failed: {exc}")
                proxy_models = []
        if not proxy_models:
            configured = list(og_cfg.get("models") or [])
            proxy_models = configured or [str(og_cfg.get("default_model") or "muse-spark-1.2-contributor")]
        default_model = str(og_cfg.get("default_model") or proxy_models[0])
        new_model = questionary.select(
            "OpenCode Go model (Responses API — discovered from /models):",
            choices=[Choice(title=m, value=m) for m in proxy_models],
            default=default_model if default_model in proxy_models else proxy_models[0],
            style=_get_style(),
        ).unsafe_ask()
        _skip_ollama_picker = True
    else:
        _skip_ollama_picker = False

    # Default model — surface context window + description for each alias
    # so the operator can see what they're picking instead of staring at
    # bare keys. Falls back to MODEL_INFO in tools.model_router if the
    # config doesn't have an ``info`` block yet.
    if not _skip_ollama_picker:
        current_model = config.get("models", {}).get("default_alias", "glm")
        aliases = list(config.get("models", {}).get("registry", {}).keys())
        if not aliases:
            aliases = ["glm", "kimi", "deepseek", "deepseek_flash", "minimax"]

        try:
            from tools.model_router import format_model_choice

            _info_lookup = config.get("models", {}).get("info", {}) or {}
        except Exception:
            format_model_choice = None
            _info_lookup = {}

        def _format_choice(alias: str) -> str:
            if format_model_choice:
                return format_model_choice(
                    alias,
                    registry=config.get("models", {}).get("registry", {}) or {},
                    registry_info=_info_lookup,
                )
            return alias

        new_model = questionary.select(
            "Default model alias (format: alias  label  (context window)  — description):",
            choices=[Choice(title=_format_choice(a), value=a) for a in aliases],
            default=current_model if current_model in aliases else aliases[0],
            style=_get_style(),
        ).unsafe_ask()

    # Stealth defaults
    stealth_cfg = config.get("stealth", {})
    rotate_ua = questionary.confirm(
        "Rotate User-Agent by default?",
        default=stealth_cfg.get("rotate_ua", False),
        style=_get_style(),
    ).unsafe_ask()

    doh = questionary.confirm(
        "Use DNS-over-HTTPS by default?",
        default=stealth_cfg.get("dns_over_https", False),
        style=_get_style(),
    ).unsafe_ask()

    multi_model_cfg = config.get("multi_model", {}) or {}
    multi_model_enabled = questionary.confirm(
        "Enable peer-model consultation by default? This can use extra tokens.",
        default=bool(multi_model_cfg.get("enabled", False)),
        style=_get_style(),
    ).unsafe_ask()

    # Default risk profile
    risk_profiles = ["low_noise_non_destructive", "standard_authorized", "high_authorized_testing"]
    default_risk = questionary.select(
        "Default risk profile:",
        choices=[Choice(title=r.replace("_", " ").title(), value=r) for r in risk_profiles],
        default="standard_authorized",
        style=_get_style(),
    ).unsafe_ask()

    # Workspace directory
    current_ws = config.get("exploit", {}).get("workspace_dir", "exploit_workspace")
    new_ws = questionary.text(
        "Exploit workspace directory:",
        default=current_ws,
        style=_get_style(),
    ).unsafe_ask()

    # Save
    save = questionary.confirm(
        "Save settings to config.yaml?",
        default=True,
        style=_get_style(),
    ).unsafe_ask()

    if save:
        config.setdefault("ollama", {})["host"] = new_host
        config.setdefault("models", {})["provider"] = provider
        config.setdefault("models", {})["default_alias"] = new_model
        if provider == "chatgpt":
            # Enable the chatgpt block and remember the chosen model. Tokens
            # are never written here — they stay in ~/.codex/auth.json.
            cg = config.setdefault("chatgpt", {})
            cg["enabled"] = True
            cg["default_model"] = new_model
        elif provider == "opencode_go":
            og = config.setdefault("opencode_go", {})
            og["enabled"] = True
            og["default_model"] = new_model
        config.setdefault("stealth", {})["rotate_ua"] = rotate_ua
        config.setdefault("stealth", {})["dns_over_https"] = doh
        config.setdefault("exploit", {})["workspace_dir"] = new_ws
        config.setdefault("multi_model", {})["enabled"] = multi_model_enabled

        config_path.write_text(
            yaml.safe_dump(config, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        print("\n  ✓ Settings saved to config.yaml")
    else:
        print("\n  Settings not saved.")


def _create_default_config(path: Path) -> None:
    """Create a default config.yaml."""
    import yaml

    default = {
        "ollama": {"host": "http://localhost:11434", "model": "glm-5.2:cloud"},
        "models": {
            "registry": {
                "kimi": "kimi-k2.6:cloud",
                "deepseek": "deepseek-v4-pro:cloud",
                "deepseek_flash": "deepseek-v4-flash:cloud",
                "glm": "glm-5.2:cloud",
                "minimax": "minimax-m3:cloud",
                "glm3": "glm-5.3-flash",
            },
            "default_alias": "glm",
            "info": {
                "kimi": {
                    "label": "Kimi K2.6",
                    "context_window": 256000,
                    "description": "Moonshot Kimi K2.6 — strong long-form reasoning, 256K context.",
                },
                "deepseek": {
                    "label": "DeepSeek V4 Pro",
                    "context_window": 1000000,
                    "description": "DeepSeek V4 Pro — 1M token context, deep code reasoning.",
                },
                "deepseek_flash": {
                    "label": "DeepSeek V4 Flash",
                    "context_window": 1000000,
                    "description": "DeepSeek V4 Flash - 1M token context, fast DeepSeek option for lower-latency work.",
                },
                "glm": {
                    "label": "GLM-5.2",
                    "context_window": 976000,
                    "description": "Zhipu GLM-5.2 — 976K context, the smartest/newest GLM for deep reasoning + coding.",
                },
                "minimax": {
                    "label": "Minimax M3",
                    "context_window": 512000,
                    "description": "Minimax M3 (cloud) — 512K context, balanced coding + reasoning.",
                },
                "glm3": {
                    "label": "GLM-5.3 Flash",
                    "context_window": 128000,
                    "description": "Zhipu GLM-5.3 Flash — fast low-latency GLM option (128K context).",
                },
            },
        },
        "mcp": {"default_transport": "stdio", "http_host": "127.0.0.1", "http_port": 8001},
        "exploit": {
            "enabled": True,
            "mode": "standalone",
            "workspace_dir": "exploit_workspace",
            "command_timeout_seconds": 300,
            "max_rounds": 200,
        },
        "stealth": {"rotate_ua": False, "dns_over_https": False, "doh_provider": "cloudflare"},
        "multi_model": {
            "enabled": False,
            "consult_aliases": ["kimi", "deepseek", "deepseek_flash", "glm", "minimax"],
            "max_consultations": 10,
            "max_question_chars": 4000,
            "max_answer_chars": 8000,
        },
    }
    path.write_text(
        yaml.safe_dump(default, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )


# ── Main entry point ───────────────────────────────────────────────────────

BANNER = (
    "\n"
    "  BreachPilot — AI Bug Bounty Research Agent\n"
    "  Authorized reconnaissance, research, evidence, reporting\n"
    "  ----------------------------------------------\n"
)


def _show_banner() -> None:
    """Display a plain ASCII banner that renders reliably on Windows."""
    print(
        "\n"
        "  BreachPilot — AI Bug Bounty Research Agent\n"
        "  Authorized reconnaissance, research, evidence, reporting\n"
        "  ----------------------------------------------\n"
    )


def _main_menu() -> str | None:
    """Display the main menu and return the selected action."""
    if not _HAS_QUESTIONARY:
        return _fallback_main_menu()

    return questionary.select(
        "What would you like to do?",
        choices=[
            Choice(title="Recon & Suggest Goals", value="recon_first"),
            Choice(title="Start New Session", value="new_session"),
            Choice(title="Manage Missions", value="missions"),
            Choice(title="View Reports", value="reports"),
            Choice(title="Settings", value="settings"),
            Choice(title="Help", value="help"),
            Choice(title="Exit", value="exit"),
        ],
        style=_get_style(),
        use_indicator=True,
    ).unsafe_ask()


def _build_session_args(*, recon_first: bool | None = None) -> Any:
    """Return a Namespace that stays in sync with main.parse_args defaults."""
    from main import parse_args

    args = parse_args([])
    args.recon_first = recon_first
    return args


def _start_new_session() -> int:
    """Launch the interactive attack wizard and run a session."""
    from main import async_main

    try:
        return asyncio.run(async_main(_build_session_args(recon_first=None)))
    except KeyboardInterrupt:
        print("\nSession aborted.")
        return 130


def _recon_first_session() -> int:
    """Launch recon-first mode: scan target, suggest rated goals, then attack."""
    from main import async_main

    try:
        return asyncio.run(async_main(_build_session_args(recon_first=True)))
    except KeyboardInterrupt:
        print("\nSession aborted.")
        return 130


def _show_help() -> None:
    """Display quick reference help using portable ASCII output."""
    print(
        """
============================================================
  BreachPilot — QUICK REFERENCE
============================================================

  INTERACTIVE MODE (no arguments)
    python main.py

  DIRECT ATTACK
    python main.py --target 10.0.0.50 --mode recon
    python main.py --target 10.0.0.50 --mode attack
    python main.py --target 10.0.0.50 --mode attack --goal backdoor
    python main.py --target 10.0.0.50 --mode attack --swarm --critic --reflection

  RECON-FIRST (scan, then suggest rated goals)
    python main.py --target 10.0.0.50 --recon-first

  COMMON FLAGS
    --mode {recon,attack}        recon = intel only, attack = full path
    --goal NAME                  preset goal (backdoor, initial_access, ...)
    --custom-goal TEXT           custom goal description
    --model ALIAS                glm / kimi / deepseek / deepseek_flash / minimax
    --long-session               raise budgets for multi-hour runs
    --ultrathink                 deep reasoning + frequent reflection
    --adaptive-exploits          mutate exploits on failure
    --resume RUN_ID              resume a prior run
    --skills {on,off,hints,lookup}
    --yes                        skip the ready-to-begin gate
    --json / --quiet / --plain   output control

  SUPPORT
    python main.py --doctor      environment + config self-check
    python main.py --self-test   safe localhost smoke test

  SAFETY
    - Only scan targets you own or are authorized to test.
    - Recon mode gathers intelligence only.
    - Attack mode uses the exploit policy and a confirmation gate.
    - Reports and run artifacts are written under reports/.
"""
    )


def run_interactive_menu() -> int:
    """Run the interactive menu loop. Returns exit code."""
    _show_banner()

    while True:
        try:
            action = _main_menu()
        except (EOFError, KeyboardInterrupt):
            print("\n\nGoodbye!")
            return 0

        if action is None or action == "exit":
            print("\nGoodbye!")
            return 0
        elif action == "recon_first":
            code = _recon_first_session()
            if code != 0:
                return code
        elif action == "new_session":
            code = _start_new_session()
            if code != 0:
                return code
        elif action == "missions":
            _manage_missions()
        elif action == "reports":
            _view_reports()
        elif action == "settings":
            _edit_settings()
        elif action == "help":
            _show_help()
        else:
            print(f"Unknown action: {action}")

    return 0
