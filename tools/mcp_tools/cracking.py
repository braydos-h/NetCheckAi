"""Hash-cracking MCP tool registration.

First-class execution wrapper for hashcat / john. ``hash_crack_identify`` only
identifies hashes and suggests commands; this tool actually runs the cracker
locally on the operator box and returns the recovered plaintext. Local-only --
no target touch -- so it is ``@audit_tool`` only (no allowlist gate).
"""

from __future__ import annotations

import re
import shutil
from typing import Any

from tools.mcp_shared import _attempt_dir
from tools.mcp_tools.modules.hash import _identify_hash_modes
from tools.mcp_tools.registry import ToolContext, run_argv_captured


def register_cracking_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool

    _TOOLS = {"hashcat", "john"}
    _DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

    def _resolve_wordlist(wordlist: str) -> str:
        wl = (wordlist or "").strip()
        if wl:
            return wl
        cfg_wl = (config or {}).get("exploit", {}).get("wordlist")
        return str(cfg_wl) if cfg_wl else _DEFAULT_WORDLIST

    @mcp.tool()
    @audit_tool
    def run_hash_crack(
        hash_value: str,
        tool: str = "hashcat",
        hash_mode: str = "",
        wordlist: str = "",
        rules: str = "",
        timeout: int = 600,
    ) -> str:
        """Crack a hash locally with hashcat or john. Auto-identifies the hash type (hashcat -m mode) if hash_mode is omitted. Returns recovered plaintext via the cracker's --show output. Local-only; no target. Optional rules is a hashcat rule file (e.g. best64.rule)."""
        if not hash_value or not hash_value.strip():
            return "BLOCKED: hash_value is required."
        t = (tool or "").strip().lower()
        if t not in _TOOLS:
            return f"BLOCKED: unsupported tool '{t}'. Allowed: {', '.join(sorted(_TOOLS))}."

        h = hash_value.strip()
        # Resolve the hashcat -m mode: explicit override, else auto-identify.
        mode = (hash_mode or "").strip()
        hash_name = ""
        if not mode:
            ids = _identify_hash_modes(h)
            # Drop non-hashcat modes (e.g. Argon2 "N/A" -- john-only) before exec.
            ids = [(name, m, cmd) for name, m, cmd in ids if m != "N/A" and m.isdigit()]
            if not ids:
                if any(m == "N/A" for _, m, _ in _identify_hash_modes(h)):
                    return (
                        "BLOCKED: identified hash type is not supported by hashcat "
                        "(e.g. Argon2); retry with tool='john'."
                    )
                return (
                    "BLOCKED: could not identify hash type; pass hash_mode=<hashcat mode> "
                    "explicitly (e.g. 1000 for NTLM, 3200 for bcrypt)."
                )
            hash_name, mode, _ = ids[0]
        else:
            # Try to label the mode for the result block (best-effort, non-authoritative).
            ids = _identify_hash_modes(h)
            for name, m, _ in ids:
                if m == mode:
                    hash_name = name
                    break
            if not hash_name:
                hash_name = f"mode {mode}"

        if not shutil.which(t):
            return (
                f"CRACKER_NOT_INSTALLED: {t} is not on PATH. "
                f"Install it (e.g. apt install {t}) on the operator box and retry."
            )

        attempt_dir, attempt_id = _attempt_dir(workspace)
        hashfile = attempt_dir / "hash.txt"
        hashfile.write_text(h + "\n", encoding="utf-8")
        wl = _resolve_wordlist(wordlist)

        cracked: list[tuple[str, str]] = []
        crack_argv: list[str]
        show_argv: list[str]
        if t == "hashcat":
            crack_argv = ["hashcat", "-m", mode, "-a", "0", str(hashfile), wl]
            if rules.strip():
                crack_argv.extend(["-r", rules.strip()])
            show_argv = ["hashcat", "-m", mode, str(hashfile), "--show"]
        else:  # john
            crack_argv = ["john", f"--wordlist={wl}", str(hashfile)]
            show_argv = ["john", "--show", str(hashfile)]

        cmd = " ".join(crack_argv)
        crack_status, returncode, crack_out, elapsed = run_argv_captured(crack_argv, timeout, max_chars=3000)

        # Retrieve recovered plaintext via the cracker's --show view.
        show_out = ""
        if crack_status != "error" and shutil.which(t):
            _, _, show_out, _ = run_argv_captured(show_argv, 60, max_chars=2000)

        # Parse --show output. hashcat: "hash:plain" (or "hash:salt:plain");
        # john: "username:password" lines plus a "Ng 0:00:..." summary line.
        for line in show_out.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            # Skip john's summary line ("2g 0:00:00:00 DONE ...").
            if t == "john" and re.match(r"^\d+g\s+\d+:\d", line):
                continue
            if t == "hashcat":
                left, plain = line.rsplit(":", 1)
            else:
                left, plain = line.split(":", 1)
            if plain:
                cracked.append((left, plain))

        cracked_lines = "\n".join(f"  {left} : {plain}" for left, plain in cracked[:50])

        return (
            f"CRACK_RESULT: {crack_status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"TOOL: {t}\n"
            f"HASH_TYPE: {hash_name} (mode {mode})\n"
            f"COMMAND: {cmd}\n"
            f"EXIT_CODE: {returncode}\n"
            f"DURATION: {elapsed:.1f}s\n"
            f"CRACKED: {len(cracked)}\n"
            f"{cracked_lines}\n"
            f"SHOW_OUTPUT:\n{show_out[-1500:]}\n"
            f"OUTPUT:\n{crack_out}"
        )
