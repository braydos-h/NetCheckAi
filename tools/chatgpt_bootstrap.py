"""Safe bootstrap for the ChatGPT (openai-oauth) provider runtime.

This module is the ONE obvious home for the third-party pins used by the
ChatGPT provider setup:

- ``BUN_VERSION`` — exact bun release installed via the npm ``bun`` package
  (the npm registry verifies tarball integrity on install).
- ``OPENAI_OAUTH_REPO`` / ``OPENAI_OAUTH_TAG`` / ``OPENAI_OAUTH_COMMIT`` —
  the exact upstream revision of EvanZhouDev/openai-oauth we clone and run.

Security posture (deliberate):

- We NEVER pipe a mutable remote script into a shell (no
  ``curl ... | bash``, no ``irm ... | iex``). If bun is absent and cannot be
  installed via the pinned npm package, setup fails with an actionable
  manual-install message.
- The oauth checkout is cloned at the pinned tag and ``HEAD`` is verified
  against ``OPENAI_OAUTH_COMMIT`` before ``bun install``/``bun run build``
  ever execute. A mismatch fails closed.
- ``bun install`` uses ``--frozen-lockfile`` so the vendored ``bun.lock``
  pins every transitive dependency.
- No ``shell=True`` anywhere — every subprocess call is an argv list.

To refresh the pins: update the constants below, verify the new oauth tag
contains ``packages/openai-oauth/src/cli.ts`` and a ``bun.lock``, run
``python -m pytest tests/test_chatgpt_bootstrap.py -q``, and document the
new versions in ``docs/providers.md``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

# ── Pins ─────────────────────────────────────────────────────────────────

#: Exact bun release. Matches the ``packageManager: bun@1.3.11`` declared by
#: the pinned openai-oauth checkout itself.
BUN_VERSION = "1.3.11"

#: Upstream openai-oauth repository (clone source only — never executed
#: directly; HEAD is verified against the pin below before anything runs).
OPENAI_OAUTH_REPO = "https://github.com/EvanZhouDev/openai-oauth.git"

#: Pinned tag — a stable release, not the mutable default branch.
OPENAI_OAUTH_TAG = "v2.0.0"

#: Full commit SHA the tag must resolve to. Verified via ``git rev-parse
#: HEAD`` after clone (and on pre-existing checkouts) — any other revision
#: fails closed.
OPENAI_OAUTH_COMMIT = "4be9c04ccfcaa8fc0982044d17a29a82cb131374"

#: Where to send the operator when automatic install is unavailable.
BUN_MANUAL_INSTALL_URL = "https://bun.sh"

#: CLI entry inside the vendored checkout (run from source via bun).
_CLI_ENTRY = Path("packages") / "openai-oauth" / "src" / "cli.ts"

#: Marker that the workspace packages have been built (the package
#: ``exports`` maps point at ``./dist/*.js``, which ``bun install`` alone
#: does NOT produce).
_LOCAL_DIST_MARKER = Path("packages") / "local" / "dist" / "auth-file-entry.js"

_INSTALL_TIMEOUT = 180
_BUN_INSTALL_TIMEOUT = 300
_BUN_BUILD_TIMEOUT = 600


# ── bun ──────────────────────────────────────────────────────────────────


def find_bun() -> str | None:
    """Return a bun binary path, or None if bun is not runnable."""
    found = shutil.which("bun")
    if found:
        return found
    # The official installer drops bun here without updating this process's PATH.
    user_bun = Path.home() / ".bun" / "bin" / ("bun.exe" if os.name == "nt" else "bun")
    if user_bun.exists():
        return str(user_bun)
    return None


def manual_bun_message() -> str:
    """Actionable message used whenever automatic bun install is unavailable."""
    return (
        f"bun {BUN_VERSION} (or newer) is required for the ChatGPT provider. "
        f"Install it manually from {BUN_MANUAL_INSTALL_URL} (or "
        f"`npm install -g bun@{BUN_VERSION}`), ensure `bun` is on PATH, "
        "then re-run. See docs/providers.md."
    )


def install_bun(ui: Any) -> bool:
    """Best-effort install of the pinned bun release. Returns True on success.

    Only the pinned npm package (``bun@<version>``) is attempted — the npm
    registry verifies tarball integrity, and no remote script is ever piped
    into a shell. Never raises.
    """
    if find_bun():
        return True
    ui.status(f"bun not found — attempting pinned install (bun@{BUN_VERSION}, ChatGPT provider)...")
    npm_cmd = shutil.which("npm.cmd") or shutil.which("npm")
    if npm_cmd:
        try:
            result = subprocess.run(
                [npm_cmd, "install", "-g", f"bun@{BUN_VERSION}"],
                capture_output=True,
                text=True,
                timeout=_INSTALL_TIMEOUT,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            ui.error(f"npm install -g bun@{BUN_VERSION} failed: {exc}")
        else:
            if result.returncode == 0 and find_bun():
                ui.status(f"bun@{BUN_VERSION} installed via npm.")
                return True
            ui.error(f"npm install -g bun@{BUN_VERSION} exited {result.returncode}.")
    else:
        ui.error("npm not found on PATH — cannot install bun automatically.")
    ui.error(manual_bun_message())
    return False


# ── openai-oauth checkout ────────────────────────────────────────────────


def verify_oauth_revision(repo: Path, ui: Any) -> bool:
    """Verify a checkout's HEAD matches the pinned commit. Fail closed."""
    git_cmd = shutil.which("git")
    if not git_cmd:
        ui.error("git not found on PATH — cannot verify the oauth checkout.")
        return False
    try:
        result = subprocess.run(
            [git_cmd, "rev-parse", "HEAD"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        ui.error(f"git rev-parse HEAD failed: {exc}")
        return False
    if result.returncode != 0:
        ui.error(f"git rev-parse HEAD exited {result.returncode}.")
        return False
    head = (result.stdout or "").strip()
    if head != OPENAI_OAUTH_COMMIT:
        ui.error(
            f"oauth checkout at {repo} is at unexpected revision {head[:12] or '(unknown)'}; "
            f"expected pinned {OPENAI_OAUTH_TAG} ({OPENAI_OAUTH_COMMIT[:12]}). "
            "Refusing to run code from an unverified revision. Delete the "
            f"directory and re-run to clone {OPENAI_OAUTH_TAG} fresh."
        )
        return False
    return True


def clone_oauth(repo: Path, ui: Any) -> bool:
    """Clone the pinned tag, then verify HEAD before returning success."""
    ui.status(f"oauth checkout missing at {repo} — cloning openai-oauth {OPENAI_OAUTH_TAG}...")
    git_cmd = shutil.which("git")
    if not git_cmd:
        ui.error(
            "git not found on PATH. Manually clone the pinned tag "
            f"(`git clone --branch {OPENAI_OAUTH_TAG} {OPENAI_OAUTH_REPO}`) "
            f"into {repo}, then re-run. See docs/providers.md."
        )
        return False
    try:
        result = subprocess.run(
            [git_cmd, "clone", "--depth", "1", "--branch", OPENAI_OAUTH_TAG, OPENAI_OAUTH_REPO, str(repo)],
            capture_output=True,
            text=True,
            timeout=_INSTALL_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        ui.error(f"git clone openai-oauth failed: {exc}")
        return False
    if result.returncode != 0:
        ui.error(f"git clone openai-oauth exited {result.returncode}: {(result.stderr or '')[:300]}")
        return False
    ui.status(f"openai-oauth {OPENAI_OAUTH_TAG} cloned.")
    return verify_oauth_revision(repo, ui)


def _run_bun(repo: Path, args: list[str], ui: Any, label: str, timeout: int) -> bool:
    """Run ``bun <args>`` in *repo*. Returns True on exit 0. Never raises."""
    bun_cmd = find_bun()
    if not bun_cmd:
        ui.error(
            "bun is not on PATH after install. Open a new terminal so PATH "
            "updates apply, or add bun to PATH manually, then re-run. See "
            "docs/providers.md."
        )
        return False
    ui.status(f"Running `bun {' '.join(args)}` in oauth/ (one-time setup)...")
    try:
        result = subprocess.run(
            [bun_cmd, *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        ui.error(f"bun {label} failed: {exc}")
        return False
    if result.returncode != 0:
        ui.error(f"bun {label} exited {result.returncode}: {(result.stderr or '')[:300]}")
        return False
    ui.status(f"bun {label} complete.")
    return True


# ── Orchestration ────────────────────────────────────────────────────────


def ensure_chatgpt_runtime(*, provider: str, local_repo: str, ui: Any) -> int:
    """Ensure the ChatGPT (openai-oauth) provider is runnable.

    Only acts when *provider* is ``"chatgpt"``. Checks, in order:

      1. bun on PATH (pinned npm install if missing, else manual message)
      2. the vendored ``oauth/`` checkout (pinned-tag clone if absent, plus
         HEAD verification on pre-existing checkouts)
      3. ``bun install --frozen-lockfile`` (if ``node_modules/`` is absent)
      4. ``bun run build --force`` (if the workspace ``dist/`` marker is absent)

    Returns 0 on success or when the ChatGPT provider is not active; non-zero
    only when a required step fails AND the operator is about to use the
    ChatGPT provider.
    """
    if provider != "chatgpt":
        return 0

    repo = Path(local_repo or "./oauth")
    if not repo.is_absolute():
        repo = Path.cwd() / repo
    entry = repo / _CLI_ENTRY

    if not find_bun():
        if not install_bun(ui):
            return 1
        # npm installs may put bun on PATH for future shells but not this
        # one; find_bun() already covers the ~/.bun fallback location.
        if not find_bun():
            ui.error(manual_bun_message())
            return 1

    if not entry.exists():
        if not clone_oauth(repo, ui):
            return 1
    elif not verify_oauth_revision(repo, ui):
        # Pre-existing checkout at an unknown revision — never run it.
        return 1

    if not (repo / "node_modules").exists():
        if not _run_bun(repo, ["install", "--frozen-lockfile"], ui, "install", _BUN_INSTALL_TIMEOUT):
            return 1

    # Workspace packages export from ./dist/*.js. bun install only installs
    # deps; without dist/, `bun ./src/cli.ts` fails at import time with
    # "Cannot find module '@openai-oauth/local/auth-file'".
    if not (repo / _LOCAL_DIST_MARKER).exists():
        if not _run_bun(repo, ["run", "build", "--force"], ui, "run build", _BUN_BUILD_TIMEOUT):
            return 1
    return 0
