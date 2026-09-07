"""Shared nmap privilege-handling helpers.

Extracted from ``mcp_server.py`` so the *defensive* MCP server and the
exploit recon pipeline (``tools/recon_pipeline.py``) apply the SAME
unprivileged-downgrade behaviour. Previously only the defensive server
downgraded root-requiring flags (``-O``/``-sS``/...); the recon pipeline
hardcoded ``-sS``/``-O`` and failed on a non-root host, retrying the
identical failing command three times.

These helpers are also reused (re-exported) by ``mcp_server.py`` so
existing imports ``from mcp_server import _downgrade_unprivileged_args``
keep working.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from functools import lru_cache

# nmap flags that require root / CAP_NET_RAW on Linux. Connect-scan + service
# detection do not; SYN/Xmas/Null/FIN/ACK/Maimon + UDP (-sU) + OS detection
# (``-O``) do.
_NMAP_ROOT_FLAGS: set[str] = {"-O", "-sS", "-sU", "-sX", "-sN", "-sF", "-sA", "-sM"}

# Linux capability bit for raw-packet sockets (see capabilities(7)).
_CAP_NET_RAW_BIT = 13
# VFS capability revision mask/values + effective flag (see linux/capability.h).
_CAP_REVISION_MASK = 0xFF000000
_CAP_KNOWN_REVISIONS = (1, 2, 3)
_CAP_FLAG_EFFECTIVE = 0x01


def _cap_blob_has_effective_net_raw(blob: bytes) -> bool:
    """Parse a ``security.capability`` xattr blob for effective CAP_NET_RAW.

    Layout (little-endian u32s): ``magic_etc`` at offset 0 (top byte is the
    revision, low bit is the effective flag), permitted word0 at offset 4
    (bit 13 is CAP_NET_RAW).
    """
    if len(blob) < 8:
        return False
    magic_etc = int.from_bytes(blob[0:4], "little")
    if ((magic_etc & _CAP_REVISION_MASK) >> 24) not in _CAP_KNOWN_REVISIONS:
        return False
    permitted = int.from_bytes(blob[4:8], "little")
    if not permitted & (1 << _CAP_NET_RAW_BIT):
        return False
    return bool(magic_etc & _CAP_FLAG_EFFECTIVE)


@lru_cache(maxsize=128)
def _nmap_has_cap_net_raw(nmap_binary: str = "nmap") -> bool:
    """True if the nmap binary carries an effective file CAP_NET_RAW.

    Resolves ``nmap_binary`` via ``shutil.which``, then reads the file
    capability with stdlib-only ``os.getxattr(path, "security.capability")``
    parsing (see ``_cap_blob_has_effective_net_raw``). When the xattr is
    missing/unreadable, falls back to the ``getcap`` binary if present. Any
    error (binary not found, no xattr support, no getcap, timeout) → False.
    """
    path = shutil.which(nmap_binary)
    if not path:
        return False
    getxattr = getattr(os, "getxattr", None)
    if getxattr is not None:
        try:
            return _cap_blob_has_effective_net_raw(getxattr(path, "security.capability"))
        except Exception:
            pass  # xattr missing/unreadable -> try the getcap fallback below
    getcap = shutil.which("getcap")
    if not getcap:
        return False
    try:
        proc = subprocess.run([getcap, path], capture_output=True, text=True, timeout=5)
    except Exception:
        return False
    return "cap_net_raw" in (proc.stdout or "").lower()


@lru_cache(maxsize=1)
def _can_passwordless_sudo() -> bool:
    """True if `sudo -n true` succeeds (passwordless sudo available)."""
    try:
        proc = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
    except Exception:
        return False
    return proc.returncode == 0


def _is_privileged() -> bool:
    """True if the process may use raw-packet nmap scans.

    On POSIX this means euid 0 (root) or an effective CAP_NET_RAW file
    capability on the nmap binary (common in containers, where euid != 0 but
    the capability is granted). Windows has no root concept, so nmap on
    Windows does its own socket handling and is treated as privileged.
    """
    if os.name == "nt":
        return True
    try:
        if os.geteuid() == 0:
            return True
    except AttributeError:
        return True
    return bool(_nmap_has_cap_net_raw())


def _downgrade_unprivileged_args(args: list[str]) -> tuple[list[str], str]:
    """Return (args, note). Strip root-requiring nmap flags when unprivileged.

    If ``args`` contains a SYN scan flag, replace it with ``-sT`` (TCP connect
    scan, no root needed) so port coverage is preserved. ``-O`` and the other
    raw-packet scan types are simply removed. The returned note explains what
    was downgraded so the caller can surface it to the operator.
    """
    out: list[str] = []
    removed: list[str] = []
    has_syn = False
    for tok in args:
        if tok in _NMAP_ROOT_FLAGS:
            removed.append(tok)
            if tok == "-sS":
                has_syn = True
        else:
            out.append(tok)
    if not removed:
        return args, ""
    if has_syn:
        out.append("-sT")
    note = (
        "nmap: removed root-requiring flags "
        + ",".join(removed)
        + " (needs root). Rerun as root or set nmap.sudo: true in config.yaml "
        "to enable OS/SYN scans. SYN scan was replaced with -sT (connect scan)."
    )
    return out, note


def apply_nmap_privilege(argv: list[str], *, sudo: bool, priv_fallback: bool) -> tuple[list[str], str]:
    """Apply sudo-prefix + unprivileged downgrade to a full nmap argv.

    ``argv[0]`` is the nmap binary (e.g. ``nmap`` or a configured path); the
    remaining tokens are the flags/target. Returns ``(effective_argv, note)``.

    - Privileged (root / file CAP_NET_RAW / Windows): no change.
    - Unprivileged + ``sudo``: probe passwordless sudo via ``sudo -n true``.
      Present → prepend ``sudo -n`` (non-interactive; fails fast instead of
      hanging on a password prompt). No downgrade — sudo gives root. Absent
      + ``priv_fallback`` → take the downgrade path. Absent + no fallback →
      keep the sudo prefix (explicit config; fails loudly at runtime).
    - Unprivileged + ``priv_fallback``: strip root-requiring flags, replacing
      ``-sS`` with ``-sT``. The note describes the downgrade.
    - Unprivileged, neither: return argv unchanged (the scan will fail with a
      privilege error; the caller may then retry once with ``priv_fallback=True``).
    """
    if _is_privileged():
        return list(argv), ""
    binary = argv[0]
    rest = list(argv[1:])
    use_sudo = sudo and os.name != "nt"
    if use_sudo and not _can_passwordless_sudo():
        # No passwordless sudo on this box: a ``sudo -n`` prefix would fail
        # loudly in the scan anyway. Downgrade when allowed; otherwise keep
        # the requested prefix so the explicit misconfiguration surfaces.
        if priv_fallback:
            downgraded, note = _downgrade_unprivileged_args(rest)
            if note:
                note += "; sudo -n unavailable (no passwordless sudo)"
            else:
                note = "nmap: no root-requiring flags to downgrade; sudo -n unavailable (no passwordless sudo)"
            return [binary, *downgraded], note
        return ["sudo", "-n", binary, *rest], ""
    if use_sudo:
        return ["sudo", "-n", binary, *rest], ""
    if priv_fallback and os.name != "nt":
        downgraded, note = _downgrade_unprivileged_args(rest)
        return [binary, *downgraded], note
    return list(argv), ""


_PRIV_ERROR_RE = re.compile(
    r"requires root|raw socket|permission denied|cap_net_raw|must be run as root|"
    r"you requested a scan type which requires root",
    re.IGNORECASE,
)


def is_privilege_error(stderr: str) -> bool:
    """True if a scan's stderr indicates a root/privilege failure.

    Such failures are identical across retries, so ``run_command`` uses this
    to break out of its retry loop early and let the caller downgrade the argv
    (``-sS`` -> ``-sT``) and retry once with the corrected command.
    """
    return bool(_PRIV_ERROR_RE.search(stderr or ""))
