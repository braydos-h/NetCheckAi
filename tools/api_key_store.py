"""Local provider API-key bootstrap for research integrations.

The store is intentionally small and explicit. It exists to let the operator
enter research-provider API keys once at startup, then have MCP subprocesses
inherit them through the process environment. Values are never logged or
printed.
"""

from __future__ import annotations

import getpass
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DEFAULT_API_KEY_FILE = Path("secr.json")
RESEARCH_MCP_TOOLS = frozenset({"search_web_exploit", "fetch_webpage", "deep_research"})


@dataclass(frozen=True)
class ApiKeyBootstrapResult:
    loaded: list[str]
    saved: list[str]
    missing: list[str]
    store_path: Path


def configured_api_key_env_names(config: dict[str, Any]) -> list[str]:
    """Return provider API-key environment variable names from config."""

    names: list[str] = []
    # ponytail: top-level ollama.api_key_env drives the cloud fallback on the
    # MAIN model path (model_router._build_model_client swaps the client to
    # https://api.ollama.com when local is unreachable). Without this the key
    # is loaded only for the research subsystem (research.ollama.api_key_env).
    # Provider blocks resolve via the single normalization layer so a custom
    # api_key_env under providers.<id> is honored, not just the legacy
    # top-level block.
    try:
        from tools.config.loader import get_provider_config

        top_ollama_env = str(get_provider_config(config, "ollama").get("api_key_env") or "OLLAMA_API_KEY")
        opencode_go_env = str(get_provider_config(config, "opencode_go").get("api_key_env") or "OPENCODE_GO_API_KEY")
    except Exception:
        top_ollama = config.get("ollama", {}) or {}
        top_ollama_env = str(top_ollama.get("api_key_env", "OLLAMA_API_KEY"))
        legacy_go = config.get("opencode_go", {}) or {}
        opencode_go_env = str(legacy_go.get("api_key_env", "OPENCODE_GO_API_KEY"))
    research = config.get("research", {}) or {}
    ollama = research.get("ollama", {}) or {}
    serpapi = research.get("serpapi", {}) or {}
    cve_lookup = config.get("cve_lookup", {}) or {}
    github = cve_lookup.get("github", {}) or {}

    for value in (
        top_ollama_env,
        ollama.get("api_key_env", "OLLAMA_API_KEY"),
        serpapi.get("api_key_env", "SERPAPI_API_KEY"),
        cve_lookup.get("api_key_env", "NVD_API_KEY"),
        github.get("token_env", "GITHUB_TOKEN"),
        opencode_go_env,
    ):
        name = str(value or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def research_api_key_env_names(config: dict[str, Any]) -> list[str]:
    """Return API-key env names that can unlock MCP research tools."""

    research = config.get("research", {}) or {}
    names: list[str] = []
    ollama = research.get("ollama", {}) or {}
    serpapi = research.get("serpapi", {}) or {}
    provider_names = {
        str(research.get("provider", "ollama") or "").lower(),
        str(research.get("fallback_provider", "serpapi") or "").lower(),
    }

    if "ollama" in provider_names and (
        bool(ollama.get("use_web_search", True)) or bool(ollama.get("use_web_fetch", True))
    ):
        names.append(str(ollama.get("api_key_env", "OLLAMA_API_KEY") or "OLLAMA_API_KEY"))
    if "serpapi" in provider_names:
        names.append(str(serpapi.get("api_key_env", "SERPAPI_API_KEY") or "SERPAPI_API_KEY"))
    return _dedupe(names)


def load_api_key_file(path: Path = DEFAULT_API_KEY_FILE) -> dict[str, str]:
    """Load API keys from ``path`` without mutating the environment."""

    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    raw_keys = data.get("api_keys", data)
    if not isinstance(raw_keys, dict):
        return {}
    keys: dict[str, str] = {}
    for name, value in raw_keys.items():
        env_name = str(name or "").strip()
        secret = str(value or "").strip()
        if env_name and secret:
            keys[env_name] = secret
    return keys


def load_api_keys_into_env(
    path: Path = DEFAULT_API_KEY_FILE,
    *,
    allowed_names: Iterable[str] | None = None,
) -> list[str]:
    """Load saved keys into ``os.environ`` when not already set."""

    allowed = set(allowed_names or [])
    loaded: list[str] = []
    for name, value in load_api_key_file(path).items():
        if allowed and name not in allowed:
            continue
        if not os.environ.get(name):
            os.environ[name] = value
            loaded.append(name)
    return loaded


def save_api_keys(path: Path, keys: dict[str, str]) -> list[str]:
    """Merge and save non-empty keys to ``path``. Returns saved env names."""

    cleaned = {str(k).strip(): str(v).strip() for k, v in keys.items() if str(k).strip() and str(v).strip()}
    if not cleaned:
        return []
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"Refusing to overwrite unreadable API key store: {path}") from exc
        if not isinstance(raw, dict) or ("api_keys" in raw and not isinstance(raw["api_keys"], dict)):
            raise ValueError(f"Refusing to overwrite invalid API key store: {path}")
    existing = load_api_key_file(path)
    existing.update(cleaned)
    payload = {
        "version": 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "api_keys": existing,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp:
            json.dump(payload, temp, indent=2, sort_keys=True)
            temp.write("\n")
            temp.flush()
            os.fsync(temp.fileno())
            temp_path = Path(temp.name)
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        os.replace(temp_path, path)
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
    return sorted(cleaned)


def missing_api_key_env_names(config: dict[str, Any]) -> list[str]:
    return [name for name in configured_api_key_env_names(config) if not os.environ.get(name)]


def research_api_keys_available(config: dict[str, Any]) -> bool:
    research = config.get("research", {}) or {}
    if not bool(research.get("enabled", True)):
        return True
    if not bool(research.get("require_api_key_for_mcp_tools", True)):
        return True
    return any(os.environ.get(name) for name in research_api_key_env_names(config))


def disabled_mcp_tools_without_api_key(config: dict[str, Any]) -> set[str]:
    if research_api_keys_available(config):
        return set()
    return set(RESEARCH_MCP_TOOLS)


def disabled_research_tools_message(config: dict[str, Any]) -> str:
    names = ", ".join(research_api_key_env_names(config) or ["OLLAMA_API_KEY", "SERPAPI_API_KEY"])
    return (
        "RESEARCH_API_KEY_MISSING: MCP web research tools are disabled because no configured "
        f"research API key is available. Set one of: {names}; run "
        "`python main.py --setup-api-keys`; or save keys to secr.json. "
        "Model research assistant (local CVE intel + chat provider) stays available."
    )


def bootstrap_api_keys(
    config: dict[str, Any],
    *,
    store_path: Path = DEFAULT_API_KEY_FILE,
    prompt: bool = False,
    force_prompt: bool = False,
) -> ApiKeyBootstrapResult:
    """Load saved keys and optionally prompt for missing configured keys."""

    env_names = configured_api_key_env_names(config)
    loaded = load_api_keys_into_env(store_path, allowed_names=env_names)
    missing = [name for name in env_names if not os.environ.get(name)]
    saved: list[str] = []
    if (prompt or force_prompt) and missing and _can_prompt(force_prompt=force_prompt):
        entered = _prompt_for_api_keys(missing, force_prompt=force_prompt)
        saved = save_api_keys(store_path, entered)
        for name, value in entered.items():
            if value and not os.environ.get(name):
                os.environ[name] = value
        missing = [name for name in env_names if not os.environ.get(name)]
    return ApiKeyBootstrapResult(loaded=loaded, saved=saved, missing=missing, store_path=store_path)


def _prompt_for_api_keys(names: list[str], *, force_prompt: bool) -> dict[str, str]:
    if not names:
        return {}
    if not force_prompt:
        answer = _confirm(
            "Configure provider API keys now? Research MCP tools are disabled until a key is set.",
            default=False,
        )
        if not answer:
            return {}

    entered: dict[str, str] = {}
    for name in names:
        value = _secret_prompt(f"{name} (leave blank to skip): ")
        if value:
            entered[name] = value
    return entered


def _confirm(message: str, *, default: bool) -> bool:
    try:
        import questionary

        answer = questionary.confirm(message, default=default).unsafe_ask()
        return bool(answer)
    except Exception:
        suffix = "Y/n" if default else "y/N"
        try:
            raw = input(f"{message} [{suffix}] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if not raw:
            return default
        return raw in {"y", "yes"}


def _secret_prompt(message: str) -> str:
    try:
        import questionary

        value = questionary.password(message).unsafe_ask()
        return str(value or "").strip()
    except Exception:
        try:
            return getpass.getpass(message).strip()
        except (EOFError, KeyboardInterrupt):
            return ""


def _can_prompt(*, force_prompt: bool) -> bool:
    return force_prompt or bool(getattr(sys.stdin, "isatty", lambda: False)())


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out
