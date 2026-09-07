"""Workspace path helpers — pure, no I/O beyond Path checks.

Extracted from ``tools.mcp_shared`` (Phase 2 kernel). Both flows and
``tools.persistent_session_manager`` import from here; ``tools.mcp_shared``
re-exports for backwards compat.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from pathlib import Path


def _is_inside_workspace(workspace: Path, target: Path) -> bool:
    """True if ``target`` (resolved) is equal to or nested under ``workspace``.

    Ponytail: single source for the predicate previously duplicated in
    ``tools.mcp_shared`` and ``tools.persistent_session_manager``.
    Handles ``OSError`` (broken symlink / permission) and treats the
    workspace root itself as inside (equality check).
    """
    try:
        root = workspace.resolve()
        resolved = target.resolve()
    except OSError:
        return False
    try:
        resolved.relative_to(root)
        return True
    except ValueError:
        return resolved == root


def _resolve_workspace_file(workspace: Path, filename: str, suffix: str | None = None) -> Path:
    """Resolve a workspace file by absolute path, relative path, or basename.

    Mirrors ``tools.mcp_shared._resolve_workspace_file`` verbatim (Phase 2
    move, no behavior change). See that function for the full docstring.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    root = workspace.resolve()
    raw = str(filename or "").strip().strip("\"'")
    if not raw:
        return root / "__missing__"

    normalized = raw.replace("\\", "/")
    raw_path = Path(raw)
    candidates: list[Path] = []
    if raw_path.is_absolute():
        candidates.append(raw_path)
    elif "/" in normalized:
        candidates.append(root / normalized)

    safe_name = Path(normalized).name.lstrip("/").lstrip("\\")
    if safe_name:
        candidates.append(root / safe_name)

    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not _is_inside_workspace(root, resolved):
            continue
        if resolved.is_file() and (suffix is None or resolved.name.endswith(suffix)):
            return resolved

    if not safe_name:
        return root / "__missing__"

    matches: list[Path] = []
    for candidate in root.rglob(safe_name):
        if not candidate.is_file() or (suffix is not None and not candidate.name.endswith(suffix)):
            continue
        try:
            resolved_cand = candidate.resolve()
        except OSError:
            continue
        if _is_inside_workspace(root, resolved_cand):
            matches.append(resolved_cand)
    if matches:
        return max(matches, key=lambda p: p.stat().st_mtime if p.exists() else 0)

    return root / safe_name


def _find_file(workspace: Path, filename: str) -> Path | None:
    resolved = _resolve_workspace_file(workspace, filename)
    if not resolved.exists() or not resolved.is_file():
        return None
    root = workspace.resolve()
    try:
        if not _is_inside_workspace(root, resolved.resolve()):
            return None
    except OSError:
        return None
    return resolved


def _attempt_dir(workspace: Path) -> tuple[Path, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    attempt_id = f"{stamp}_{secrets.token_hex(4)}"
    attempt_dir = workspace / attempt_id
    attempt_dir.mkdir(parents=True, exist_ok=True)
    return attempt_dir, attempt_id


# Vault keyfiles must never be served to the model: the live key lives
# outside the workspace tree, but a hand-placed or legacy in-workspace
# ``.vault_key`` would otherwise hand the Fernet key over on request
# (encrypted-at-rest secrets = plaintext). Basename match, so no path
# spelling reaches it.
_VAULT_KEY_BASENAMES = frozenset({".vault_key"})


def is_vault_key_path(filename: str) -> bool:
    """True when ``filename`` names a vault keyfile (deny-listed from reads)."""
    name = str(filename or "").strip().replace("\\", "/").split("/")[-1].strip("\"'")
    return name in _VAULT_KEY_BASENAMES


def read_workspace(workspace: Path, filename: str) -> str:
    """Read a file inside the run workspace by path (Phase 3 kernel move).

    Workspace-contained only: absolute paths escaping the workspace (and
    unreadable/missing files) are refused. Previously this read any
    operator-box path, letting a prompt-injected filename exfiltrate
    /etc/shadow, cloud credentials, or OAuth tokens into the model context.
    Vault keyfiles (``.vault_key``) are deny-listed by basename: serving one
    would hand the credential-store Fernet key to the model.
    """
    raw = str(filename or "").strip()
    if not raw:
        return "BLOCKED: empty filename."
    if is_vault_key_path(raw):
        return f"BLOCKED: {Path(raw).name!r} is a credential-store keyfile and is never served."
    workspace.mkdir(parents=True, exist_ok=True)
    root = workspace.resolve()
    target = Path(raw)
    if not target.is_absolute():
        target = root / raw
    try:
        resolved = target.resolve()
    except OSError as exc:
        return f"BLOCKED: could not read {Path(filename).name!r}: {exc}"
    if not _is_inside_workspace(root, resolved):
        return f"BLOCKED: {Path(filename).name!r} is outside the workspace."
    if not resolved.exists() or not resolved.is_file():
        return f"FILE_NOT_FOUND: {Path(filename).name}"
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"BLOCKED: could not read {filename!r}: {exc}"
    if len(text) > 120_000:
        text = text[:120_000] + "\n[truncated]"
    return text
