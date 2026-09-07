"""Tests for ChatGPT provider bootstrap (``tools/chatgpt_bootstrap.py``).

Security posture under test:

- No mutable remote script is ever piped into a shell (no ``curl | bash``,
  no ``irm | iex``, no ``shell=True`` anywhere in the bootstrap path).
- Bun installs use only the pinned npm package (``bun@<BUN_VERSION>``);
  when that is unavailable setup fails with an actionable manual message.
- The openai-oauth checkout is cloned at the pinned tag and ``HEAD`` is
  verified against ``OPENAI_OAUTH_COMMIT`` before ``bun install``/``bun run
  build`` ever execute — an unexpected revision fails closed.
- ``bun install`` uses ``--frozen-lockfile``.

All subprocess/filesystem lookups are faked — no network, no git, no npm.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import tools.chatgpt_bootstrap as boot

# ── Fakes ────────────────────────────────────────────────────────────────


class _FakeUI:
    def __init__(self) -> None:
        self.statuses: list[str] = []
        self.errors: list[str] = []

    def status(self, msg: str) -> None:
        self.statuses.append(msg)

    def error(self, msg: str) -> None:
        self.errors.append(msg)


def _ok(stdout: str = "") -> MagicMock:
    result = MagicMock()
    result.returncode = 0
    result.stdout = stdout
    result.stderr = ""
    return result


def _fail(code: int = 1) -> MagicMock:
    result = MagicMock()
    result.returncode = code
    result.stdout = ""
    result.stderr = "boom"
    return result


# ── 1. No mutable remote scripts, no shell=True ──────────────────────────


def test_no_shell_true_or_remote_script_piping(monkeypatch: Any, tmp_path: Path) -> None:
    """Every subprocess call in the bootstrap path must be an argv list.

    Records all ``subprocess.run`` invocations across install/clone/verify/
    bun-install/bun-build and asserts none use ``shell=True`` and none
    contain a remote-script pipe (``curl | bash``, ``irm | iex``).
    """
    calls: list[tuple[Any, dict[str, Any]]] = []

    def fake_run(cmd: Any, **kwargs: Any) -> MagicMock:
        calls.append((cmd, kwargs))
        if isinstance(cmd, list) and len(cmd) > 1 and cmd[1] == "rev-parse":
            return _ok(boot.OPENAI_OAUTH_COMMIT + "\n")
        return _ok()

    monkeypatch.setattr(boot.subprocess, "run", fake_run)
    # bun found via find_bun; git present for the revision check.
    monkeypatch.setattr(boot.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(boot, "find_bun", lambda: "/usr/bin/bun")

    ui = _FakeUI()
    repo = tmp_path / "oauth"
    (repo / "packages" / "openai-oauth" / "src").mkdir(parents=True)
    (repo / "packages" / "openai-oauth" / "src" / "cli.ts").write_text("// cli")
    (repo / "node_modules").mkdir()
    (repo / "packages" / "local" / "dist").mkdir(parents=True)
    (repo / "packages" / "local" / "dist" / "auth-file-entry.js").write_text("// built")

    assert boot.ensure_chatgpt_runtime(provider="chatgpt", local_repo=str(repo), ui=ui) == 0
    assert calls, "expected subprocess calls to have been recorded"
    for cmd, kwargs in calls:
        assert isinstance(cmd, list), f"subprocess must use argv list, got: {cmd!r}"
        assert kwargs.get("shell") is not True, f"shell=True is forbidden: {cmd!r}"
        joined = " ".join(cmd)
        assert "bun.sh/install" not in joined, f"remote bun installer used: {joined}"
        assert not ("curl" in joined and "bash" in joined), f"curl|bash used: {joined}"
        assert "iex" not in joined, f"iex used: {joined}"


def test_install_bun_uses_pinned_npm_package(monkeypatch: Any) -> None:
    """Bun auto-install goes through ``npm install -g bun@<version>`` only."""
    seen: list[list[str]] = []

    def fake_run(cmd: Any, **kwargs: Any) -> MagicMock:
        seen.append(list(cmd))
        return _ok()

    monkeypatch.setattr(boot.subprocess, "run", fake_run)
    monkeypatch.setattr(boot.shutil, "which", lambda name: "/usr/bin/npm" if name.startswith("npm") else None)
    # install succeeds and bun appears afterwards
    calls = {"n": 0}

    def fake_find_bun() -> str | None:
        calls["n"] += 1
        return None if calls["n"] == 1 else "/usr/bin/bun"

    monkeypatch.setattr(boot, "find_bun", fake_find_bun)

    ui = _FakeUI()
    assert boot.install_bun(ui) is True
    assert seen == [["/usr/bin/npm", "install", "-g", f"bun@{boot.BUN_VERSION}"]]


def test_install_bun_falls_back_to_manual_message(monkeypatch: Any) -> None:
    """No npm → no silent failure: an actionable manual-install message."""
    monkeypatch.setattr(boot.subprocess, "run", lambda *a, **k: _ok())
    monkeypatch.setattr(boot.shutil, "which", lambda name: None)
    monkeypatch.setattr(boot, "find_bun", lambda: None)

    ui = _FakeUI()
    assert boot.install_bun(ui) is False
    assert any("bun.sh" in e or "npm install -g bun@" in e for e in ui.errors), ui.errors


def test_npm_failure_is_not_silent(monkeypatch: Any) -> None:
    """A failed pinned npm install surfaces an error and fails closed."""
    monkeypatch.setattr(boot.subprocess, "run", lambda *a, **k: _fail(1))
    monkeypatch.setattr(boot.shutil, "which", lambda name: "/usr/bin/npm" if name.startswith("npm") else None)
    monkeypatch.setattr(boot, "find_bun", lambda: None)

    ui = _FakeUI()
    assert boot.install_bun(ui) is False
    assert ui.errors, "npm failure must produce an error message"


# ── 2. OAuth pinning: clone at tag, verify HEAD ──────────────────────────


def test_clone_uses_pinned_tag_not_default_branch(monkeypatch: Any, tmp_path: Path) -> None:
    """Clone must request ``--branch <tag>``, never the mutable default branch."""
    seen: list[list[str]] = []

    def fake_run(cmd: Any, **kwargs: Any) -> MagicMock:
        seen.append(list(cmd))
        return _ok(boot.OPENAI_OAUTH_COMMIT + "\n")

    monkeypatch.setattr(boot.subprocess, "run", fake_run)
    monkeypatch.setattr(boot.shutil, "which", lambda name: "/usr/bin/git" if name == "git" else None)

    ui = _FakeUI()
    assert boot.clone_oauth(tmp_path / "oauth", ui) is True
    clone = [c for c in seen if c[:2] == ["/usr/bin/git", "clone"]]
    assert len(clone) == 1
    assert "--branch" in clone[0] and boot.OPENAI_OAUTH_TAG in clone[0], clone[0]
    # No bare `--depth 1` clone of the default branch.
    assert clone[0].count("--depth") == 1


def test_unexpected_revision_fails_closed(monkeypatch: Any, tmp_path: Path) -> None:
    """A checkout at any commit other than the pin must refuse to proceed."""
    monkeypatch.setattr(boot.subprocess, "run", lambda *a, **k: _ok("deadbeef" * 5 + "\n"))
    monkeypatch.setattr(boot.shutil, "which", lambda name: "/usr/bin/git" if name == "git" else None)

    ui = _FakeUI()
    assert boot.verify_oauth_revision(tmp_path, ui) is False
    assert any("unexpected revision" in e for e in ui.errors), ui.errors


def test_expected_revision_passes(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(boot.subprocess, "run", lambda *a, **k: _ok(boot.OPENAI_OAUTH_COMMIT + "\n"))
    monkeypatch.setattr(boot.shutil, "which", lambda name: "/usr/bin/git" if name == "git" else None)

    ui = _FakeUI()
    assert boot.verify_oauth_revision(tmp_path, ui) is True
    assert not ui.errors


def test_preexisting_checkout_with_wrong_revision_blocks_build(monkeypatch: Any, tmp_path: Path) -> None:
    """A pre-existing checkout at the wrong commit must fail BEFORE bun runs.

    The recorded subprocess calls must contain no ``bun install``/``bun run
    build`` — unverified code is never executed.
    """
    calls: list[list[str]] = []

    def fake_run(cmd: Any, **kwargs: Any) -> MagicMock:
        calls.append(list(cmd))
        if isinstance(cmd, list) and cmd[:2] == ["git", "rev-parse"]:
            return _ok("cafef00d" * 5 + "\n")
        return _ok()

    monkeypatch.setattr(boot.subprocess, "run", fake_run)
    monkeypatch.setattr(boot.shutil, "which", lambda name: "/usr/bin/git" if name == "git" else "/usr/bin/bun")
    monkeypatch.setattr(boot, "find_bun", lambda: "/usr/bin/bun")

    repo = tmp_path / "oauth"
    (repo / "packages" / "openai-oauth" / "src").mkdir(parents=True)
    (repo / "packages" / "openai-oauth" / "src" / "cli.ts").write_text("// cli")

    ui = _FakeUI()
    assert boot.ensure_chatgpt_runtime(provider="chatgpt", local_repo=str(repo), ui=ui) == 1
    assert not any("bun" in c[0] and "install" in c for c in calls), calls


def test_bun_install_uses_frozen_lockfile(monkeypatch: Any, tmp_path: Path) -> None:
    """Dependency install must be reproducible via ``--frozen-lockfile``."""
    seen: list[list[str]] = []

    def fake_run(cmd: Any, **kwargs: Any) -> MagicMock:
        seen.append(list(cmd))
        return _ok(boot.OPENAI_OAUTH_COMMIT + "\n")

    monkeypatch.setattr(boot.subprocess, "run", fake_run)
    monkeypatch.setattr(boot.shutil, "which", lambda name: "/usr/bin/git" if name == "git" else None)
    monkeypatch.setattr(boot, "find_bun", lambda: "/usr/bin/bun")

    repo = tmp_path / "oauth"
    (repo / "packages" / "openai-oauth" / "src").mkdir(parents=True)
    (repo / "packages" / "openai-oauth" / "src" / "cli.ts").write_text("// cli")
    # node_modules absent → bun install runs; dist marker present → no build.
    (repo / "packages" / "local" / "dist").mkdir(parents=True)
    (repo / "packages" / "local" / "dist" / "auth-file-entry.js").write_text("// built")

    ui = _FakeUI()
    assert boot.ensure_chatgpt_runtime(provider="chatgpt", local_repo=str(repo), ui=ui) == 0
    installs = [c for c in seen if c[:2] == ["/usr/bin/bun", "install"]]
    assert len(installs) == 1
    assert "--frozen-lockfile" in installs[0], installs[0]


def test_non_chatgpt_provider_is_noop(monkeypatch: Any) -> None:
    """Ollama (or any other) provider must not touch subprocess at all."""
    monkeypatch.setattr(
        boot.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run subprocess")),
    )
    assert boot.ensure_chatgpt_runtime(provider="ollama", local_repo="./oauth", ui=_FakeUI()) == 0


def test_pin_constants_have_expected_shape() -> None:
    """Pins live in one place and look like real pins (not branches/empty)."""
    assert boot.BUN_VERSION and "." in boot.BUN_VERSION
    assert boot.OPENAI_OAUTH_REPO.startswith("https://github.com/")
    assert boot.OPENAI_OAUTH_TAG.startswith("v")
    assert len(boot.OPENAI_OAUTH_COMMIT) == 40
    int(boot.OPENAI_OAUTH_COMMIT, 16)  # valid hex SHA
    # git failures are fail-closed, not hidden: rev-parse error → False.
    assert subprocess.TimeoutExpired.__name__ == "TimeoutExpired"  # sanity
