"""Tests for the root install.sh installer (hermetic — never touches the real host).

Every test runs install.sh with an isolated HOME/TMPDIR and stubbed PATH so
nothing outside tmp_path is read or written. Network-touching paths are
covered via --dry-run or file:// fixtures, never live GitHub calls.

Conventions: plain pytest + tmp_path + subprocess, matching the repo suite.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"


def run_install(
    args: list[str],
    script: Path = INSTALL_SH,
    *,
    home: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run install.sh with isolated HOME/TMPDIR and a minimal safe PATH."""
    env = {
        "HOME": str(home),
        "TMPDIR": str(home / "tmp"),
        "PATH": "/usr/bin:/bin",
        "SHELL": "/bin/bash",
        "TERM": "dumb",  # deterministic, no ANSI
    }
    if extra_env:
        env.update(extra_env)
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        ["/usr/bin/bash", str(script), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


@pytest.fixture
def fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


# ── argument parsing ───────────────────────────────────────────────────────


def test_help_exits_zero(fake_home: Path):
    proc = run_install(["--help"], home=fake_home)
    assert proc.returncode == 0
    assert "--update" in proc.stdout
    assert "--uninstall" in proc.stdout
    assert "--dry-run" in proc.stdout


def test_unknown_option_fails_with_code_2(fake_home: Path):
    proc = run_install(["--bogus"], home=fake_home)
    assert proc.returncode == 2


def test_conflicting_modes_fail_with_code_2(fake_home: Path):
    proc = run_install(["--update", "--repair"], home=fake_home)
    assert proc.returncode == 2


def test_missing_option_value_fails_with_code_2(fake_home: Path):
    assert run_install(["--version"], home=fake_home).returncode == 2
    assert run_install(["--install-dir"], home=fake_home).returncode == 2


def test_unexpected_positional_fails_with_code_2(fake_home: Path):
    assert run_install(["extra"], home=fake_home).returncode == 2


# ── --check: read-only diagnostics ─────────────────────────────────────────


def test_check_makes_no_modifications(fake_home: Path, tmp_path: Path):
    before = {p for p in fake_home.rglob("*")}
    proc = run_install(["--check"], home=fake_home)
    assert proc.returncode == 0
    after = {p for p in fake_home.rglob("*")}
    # Only harness scaffolding (tmp/) and the install log may appear — no
    # launchers, installs, rc files, or other state.
    new = {str(p) for p in after - before}
    allowed = ("/tmp", ".local/state/breachpilot", ".local/state", ".local")
    assert all(any(a in p for a in allowed) for p in new), new
    assert not (fake_home / ".local" / "bin").exists()
    assert not (fake_home / ".local" / "share" / "breachpilot").exists()
    assert "BreachPilot Installation Check" in proc.stdout
    assert "Platform" in proc.stdout
    assert "Tools" in proc.stdout


def test_check_reports_tool_matrix(fake_home: Path):
    proc = run_install(["--check"], home=fake_home)
    assert proc.returncode == 0
    for tool in ("nmap", "Python", "Ollama", "WebUI"):
        assert tool in proc.stdout


# ── --dry-run: nothing changes ─────────────────────────────────────────────


def test_dry_run_changes_nothing(fake_home: Path):
    proc = run_install(["--dry-run"], home=fake_home)
    assert proc.returncode == 0
    # No managed install, no launchers, no rc edits.
    assert not (fake_home / ".local" / "share" / "breachpilot").exists()
    assert not (fake_home / ".local" / "bin" / "breachpilot").exists()
    assert "[dry-run]" in proc.stdout


def test_full_profile_without_sudo_fails_preflight(fake_home: Path):
    """--full needs OS package installs, so sudo-less preflight must fail 4."""
    proc = run_install(["--dry-run", "--full"], home=fake_home)
    assert proc.returncode == 4
    assert "sudo" in proc.stdout + proc.stderr


def test_dry_run_uninstall_changes_nothing(fake_home: Path):
    rc = fake_home / ".bashrc"
    rc.write_text("# pristine\n")
    proc = run_install(["--uninstall", "--dry-run"], home=fake_home)
    assert proc.returncode == 0
    assert rc.read_text() == "# pristine\n"


# ── version / platform guards ──────────────────────────────────────────────


def test_old_python_fails_preflight(tmp_path: Path, fake_home: Path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake_py = bindir / "python3"
    fake_py.write_text('#!/bin/sh\necho "Python 3.10.12"\n')
    fake_py.chmod(fake_py.stat().st_mode | stat.S_IEXEC)
    proc = run_install(
        ["--dry-run"],
        home=fake_home,
        extra_env={"PATH": f"{bindir}:/usr/bin:/bin", "PYTHON": "python3"},
    )
    assert proc.returncode == 4
    assert "3.11" in proc.stdout + proc.stderr


def test_missing_python_fails_preflight(fake_home: Path):
    proc = run_install(
        ["--dry-run"],
        home=fake_home,
        extra_env={"PYTHON": "no-such-python-xyz"},
    )
    assert proc.returncode == 4


# ── update safety ──────────────────────────────────────────────────────────


def test_update_refuses_dev_checkout(fake_home: Path, tmp_path: Path):
    # A dir with .git but no .install-info must never be auto-updated.
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    (checkout / "main.py").write_text("# app\n")
    (checkout / "pyproject.toml").write_text("[project]\n")
    (checkout / "requirements.txt").write_text("pyyaml\n")
    (checkout / "tools").mkdir()
    # Point the installer at it by copying install.sh alongside (script-dir
    # resolution treats the script's dir as the source tree).
    import shutil

    shutil.copy(INSTALL_SH, checkout / "install.sh")
    proc = run_install(["--update", "--dry-run"], script=checkout / "install.sh", home=fake_home)
    assert proc.returncode == 2
    assert "development checkout" in proc.stdout + proc.stderr


# ── PATH block idempotency ─────────────────────────────────────────────────


def test_path_block_functions_are_idempotent(fake_home: Path):
    """ensure/remove helpers via --uninstall --dry-run on a seeded rc file."""
    rc = fake_home / ".bashrc"
    rc.write_text(
        "# hello\n\n# >>> Added by BreachPilot install.sh >>>\ncase x in x) :;; esac\n# <<< Added by BreachPilot install.sh <<<\n"
    )
    proc = run_install(["--uninstall", "--dry-run", "--yes"], home=fake_home)
    assert proc.returncode == 0
    # Dry-run must not edit.
    assert "Added by BreachPilot" in rc.read_text()


# ── launcher template ──────────────────────────────────────────────────────


def test_launcher_resolves_install_and_passes_args(tmp_path: Path, fake_home: Path):
    """write_launcher output: venv resolution + exact argv passthrough."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    install_dir = tmp_path / "install"
    venv_bin = install_dir / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    fake_interp = venv_bin / "python"
    fake_interp.write_text('#!/bin/sh\necho "INTERP=$0"; printf "<%s>" "$@"\n')
    fake_interp.chmod(fake_interp.stat().st_mode | stat.S_IEXEC)
    (install_dir / "main.py").write_text("# app\n")
    (install_dir / ".install-info").write_text("version=test\n")

    # Extract + run write_launcher in isolation.
    script = INSTALL_SH.read_text()
    stub = script[: script.index('\nmain "$@"')]
    helper = tmp_path / "gen.sh"
    helper.write_text(stub + '\nBP_LOG_FILE=/dev/null\nBP_DRY_RUN=0\nwrite_launcher "$1" "$2"\n')
    proc = subprocess.run(
        ["bash", str(helper), str(bindir), "breachpilot"],
        capture_output=True,
        text=True,
        env={"HOME": str(fake_home), "PATH": "/usr/bin:/bin"},
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    launcher = bindir / "breachpilot"
    assert launcher.exists() and os.access(launcher, os.X_OK)

    # Symlink like the real `bp` alias, then execute from another cwd.
    (bindir / "bp").symlink_to(bindir / "breachpilot")
    fake_root = tmp_path / "fakebin"
    fake_root.mkdir()
    (fake_root / ".install-info").write_text("version=x\n")
    (fake_root / "main.py").write_text("# app\n")
    (fake_root / ".venv" / "bin").mkdir(parents=True)
    import shutil

    shutil.copy(fake_interp, fake_root / ".venv" / "bin" / "python")
    # Point the launcher subtree at fake_root via BREACHPILOT_HOME fallback.
    out = subprocess.run(
        [str(bindir / "bp"), "--doctor", "--target", "x"],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env={"HOME": str(fake_home), "PATH": "/usr/bin:/bin", "BREACHPILOT_HOME": str(fake_root)},
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert "--doctor" in out.stdout and "--target" in out.stdout


# ── spaces in paths ────────────────────────────────────────────────────────


def test_spaces_in_install_dir_are_safe(tmp_path: Path, fake_home: Path):
    spaced = tmp_path / "dir with spaces" / "breachpilot"
    proc = run_install(
        ["--dry-run", "--install-dir", str(spaced)],
        home=fake_home,
    )
    assert proc.returncode == 0
    assert "[dry-run]" in proc.stdout
