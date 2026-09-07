"""Pre-flight environment probe for the exploit agent (Issue 4).

The agent used to discover missing tools *reactively* -- it would invoke a
tool, watch it fail, try ``apt install`` (which fails again on a sudo-less
operator box), and only then pivot to a workspace Python implementation. This
module runs ONCE at agent startup (local-only, no target interaction, no
audit) and records per-tool availability AND installability so the system
prompt can tell the model up front which tools are present, which are missing,
and -- critically -- which missing tools it should pivot to a Python fallback
for instead of attempting a doomed ``apt_install``.

Kept dependency-light (stdlib only) so it can run at boot before the MCP
server's heavy imports resolve.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from functools import lru_cache
from typing import Any

# Curated tool list the exploit agent commonly relies on. Probed via PATH.
# This is the single source of truth for "which pentest tools does this box
# have?" -- ``check_environment``'s default list (tools/mcp_tools/terminal.py)
# derives from it. ``ReconConfig``'s per-tool ``*_path`` fields are a SEPARATE
# concern (binary-path overrides for the recon pipeline), not a presence
# registry, and are intentionally not unified here.
ENV_TOOLS: list[str] = [
    "nmap",
    "searchsploit",
    "hydra",
    "sqlmap",
    "msfconsole",
    "gobuster",
    "nikto",
    "enum4linux",
    "smbclient",
    "impacket-secretsdump",
    "crackmapexec",
    "hashcat",
    "john",
    "gcc",
    "pip",
    "python3",
    "python",
    "py",
    "curl",
    "git",
    "nc",
    "netcat",
]
# Backward-compat alias so existing patch sites that reference ``_ENV_TOOLS``
# keep working (it is the same list object).
_ENV_TOOLS = ENV_TOOLS

# Tools that have a straightforward workspace-Python replacement. When one of
# these is missing AND sudo is unavailable, the probe flags it as
# "write_python_fallback" so the agent pivots immediately instead of trying to
# install it.
_PYTHON_FALLBACK: set[str] = {
    "searchsploit",
    "hydra",
    "sqlmap",
    "gobuster",
    "nikto",
    "enum4linux",
    "smbclient",
    "crackmapexec",
    "hashcat",
    "john",
}

# Tools installable via pip (best-effort; used only when pip is available).
_PIP_INSTALLABLE: set[str] = {"impacket-secretsdump", "crackmapexec", "hydra"}


@lru_cache(maxsize=1)
def _can_passwordless_sudo() -> bool:
    """True if `sudo -n true` succeeds (passwordless sudo available)."""
    if platform.system() == "Windows":
        return False
    try:
        r = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def preflight_env_probe() -> dict[str, Any]:
    """Probe installed tools, sudo/pip installability, and a per-missing-tool
    recommendation. Local-only; touches no target, writes no audit.

    Returns::
        {
          "installed": [...], "missing": [...],
          "passwordless_sudo": bool, "pip_available": bool,
          "recommendations": {tool: "install_via_apt"|"install_via_pip"|"write_python_fallback"}
        }
    """
    installed: list[str] = []
    missing: list[str] = []
    for t in _ENV_TOOLS:
        (installed if shutil.which(t) else missing).append(t)
    sudo = _can_passwordless_sudo()
    pip = bool(shutil.which("pip") or shutil.which("pip3"))

    recs: dict[str, str] = {}
    for t in missing:
        if t in _PYTHON_FALLBACK and not sudo:
            # No sudo -> apt_install will fail. Pivot to a Python impl.
            recs[t] = "write_python_fallback"
        elif t in _PIP_INSTALLABLE and pip:
            recs[t] = "install_via_pip"
        elif sudo:
            recs[t] = "install_via_apt"
        else:
            # Not a known Python-fallback tool and no sudo -> still pivot to
            # Python (the only remaining option on this box).
            recs[t] = "write_python_fallback"
    return {
        "installed": installed,
        "missing": missing,
        "passwordless_sudo": sudo,
        "pip_available": pip,
        "recommendations": recs,
    }


def render_env_context(probe: dict[str, Any]) -> str:
    """Render the probe result as the ``PRE-FLIGHT ENVIRONMENT`` prompt block.

    Returns an empty string when nothing is missing (all standard tools
    present) so the prompt stays unchanged for a fully-equipped Kali box.
    """
    if not probe.get("missing"):
        return ""
    missing = probe["missing"]
    recs = probe.get("recommendations", {}) or {}
    py_fb = [t for t, r in recs.items() if r == "write_python_fallback"]
    pip_fb = [t for t, r in recs.items() if r == "install_via_pip"]
    apt_fb = [t for t, r in recs.items() if r == "install_via_apt"]

    lines = [
        "PRE-FLIGHT ENVIRONMENT (probed at startup — do NOT re-discover by failing):",
        f"  Installed: {', '.join(probe.get('installed') or []) or '(none)'}",
        f"  Missing:   {', '.join(missing)}",
        f"  passwordless_sudo: {probe.get('passwordless_sudo')}  pip_available: {probe.get('pip_available')}",
    ]
    if apt_fb:
        lines.append(f"  Installable via apt (sudo ok): {', '.join(apt_fb)}")
    if pip_fb:
        lines.append(f"  Installable via pip: {', '.join(pip_fb)}")
    if py_fb:
        lines.append(f"  PIVOT NOW (no sudo, apt_install will fail): {', '.join(py_fb)}")
        lines.append(
            "  For these tools DO NOT call apt_install/install_package — they will"
            " fail. Instead write a workspace-contained Python implementation via"
            " write_python_file + run_python_file (e.g. hydra->ssh_brute.py,"
            " searchsploit->exploit-db HTTP scrape via cve_to_poc/search_exploit_db,"
            " gobuster->asyncio dir brute)."
        )
    elif not apt_fb and not pip_fb:
        lines.append(
            "  No sudo and no pip: for any missing tool, pivot directly to a"
            " workspace-contained Python implementation; do NOT attempt"
            " apt_install/install_package."
        )
    return "\n".join(lines) + "\n"
