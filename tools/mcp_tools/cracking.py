"""Hash-cracking MCP tool registration.

First-class execution wrapper for hashcat / john. ``hash_crack_identify`` only
identifies hashes and suggests commands; this tool actually runs the cracker
locally on the operator box and returns the recovered plaintext. Local-only --
no target touch -- so it is ``@audit_tool`` only (no allowlist gate).
"""

from __future__ import annotations

import os
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
    # MB-scale anti-fill only (RULE-NO-CAP-SECRETS): hashes are secrets, never
    # capped small; this rejects only absurd multi-MB fills.
    _MAX_HASH_CHARS = 1_000_000
    _MIN_TIMEOUT = 1
    _MAX_TIMEOUT = 3600
    _DEFAULT_TIMEOUT = 600
    # Hashcat -m mode -> john --format map (best-effort). Unmapped modes warn
    # and fall back to john auto-detect instead of failing.
    _JOHN_FORMAT_BY_MODE = {
        "0": "Raw-MD5",
        "100": "Raw-SHA1",
        "1000": "NT",
        "1400": "Raw-SHA256",
        "1700": "Raw-SHA512",
        "1800": "sha512crypt",
        "500": "md5crypt",
        "3200": "bcrypt",
        "5600": "netntlmv2",
        "13100": "krb5tgs",
        "18200": "krb5asrep",
    }

    def _resolve_wordlist(wordlist: str) -> str:
        wl = (wordlist or "").strip()
        if wl:
            return wl
        cfg_wl = ((config or {}).get("exploit") or {}).get("wordlist")
        return str(cfg_wl) if cfg_wl else _DEFAULT_WORDLIST

    def _clamp_timeout(value: Any) -> int:
        try:
            ivalue = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return _DEFAULT_TIMEOUT
        return max(_MIN_TIMEOUT, min(_MAX_TIMEOUT, ivalue))

    def _tail(text: str, limit: int) -> str:
        body = str(text or "")
        if len(body) <= limit:
            return body
        return "[truncated]\n" + body[-limit:]

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
        """Crack a hash locally with hashcat or john.

        Args:
            hash_value: Single hash string to crack (full input is gated;
                MB-scale anti-fill only, never capped small).
            tool: ``hashcat`` or ``john`` (case-insensitive).
            hash_mode: Optional explicit hashcat ``-m`` mode (digits only).
                Omitted means auto-identify from the hash string.
            wordlist: Optional wordlist path (explicit, config, or default).
                Must exist on the operator box.
            rules: Optional hashcat rule file path. Must exist when given.
            timeout: Crack-command timeout in seconds, clamped to 1..3600.

        Returns:
            ``CRACK_RESULT`` envelope with ``--show`` plaintext recovery, or a
            ``BLOCKED`` / ``WORDLIST_NOT_FOUND`` / ``RULES_NOT_FOUND`` /
            ``CRACKER_NOT_INSTALLED`` fail-closed string.

        Gates:
            ``@audit_tool`` only. Local-only tool: no target is touched, so no
            allowlist gate is added (never add one here).

        Side-effects:
            Writes the hash to ``<workspace>/hash.txt`` for the attempt and
            executes the local cracker via argv (no shell).
        """
        # RULE-LOCK-FIRST: gate sees the FULL input; truncation applies only to
        # display OUTPUT tails below (with [truncated] markers).
        if not hash_value or not hash_value.strip():
            return "BLOCKED: hash_value is required."
        h = hash_value.strip()
        if len(h) > _MAX_HASH_CHARS:
            return f"BLOCKED: hash_value exceeds {_MAX_HASH_CHARS} chars."
        t = (tool or "").strip().lower()
        if t not in _TOOLS:
            return f"BLOCKED: unsupported tool '{t}'. Allowed: {', '.join(sorted(_TOOLS))}."
        clamped_timeout = _clamp_timeout(timeout)

        # Resolve the hashcat -m mode: explicit override, else auto-identify.
        mode = (hash_mode or "").strip()
        hash_name = ""
        if not mode:
            all_ids = _identify_hash_modes(h)
            # Drop non-hashcat modes (e.g. Argon2 "N/A" -- john-only) before exec.
            ids = [(name, m, cmd) for name, m, cmd in all_ids if m != "N/A" and m.isdigit()]
            if not ids:
                if any(m == "N/A" for _, m, _ in all_ids):
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
            if not mode.isdigit():
                return f"BLOCKED: hash_mode must be a numeric hashcat mode (got '{mode}')."
            # Try to label the mode for the result block (best-effort, non-authoritative).
            ids = _identify_hash_modes(h)
            for name, m, _ in ids:
                if m == mode:
                    hash_name = name
                    break
            if not hash_name:
                hash_name = f"mode {mode}"

        # Map-or-warn john modes: numeric hash_mode is hashcat-specific. Map the
        # common modes to a john --format; otherwise warn and let john
        # auto-detect instead of failing.
        john_format = ""
        john_warn = ""
        if t == "john" and mode:
            john_format = _JOHN_FORMAT_BY_MODE.get(mode, "")
            if not john_format:
                john_warn = (
                    f"WARN: hash_mode {mode} is hashcat-specific and has no john mapping; "
                    "proceeding with john auto-detect."
                )

        if not shutil.which(t):
            return (
                f"CRACKER_NOT_INSTALLED: {t} is not on PATH. "
                f"Install it (e.g. apt install {t}) on the operator box and retry."
            )

        wl = _resolve_wordlist(wordlist)
        if not os.path.exists(wl):
            return f"WORDLIST_NOT_FOUND: wordlist '{wl}' does not exist on the operator box."
        rules_path = (rules or "").strip()
        if rules_path and not os.path.exists(rules_path):
            return f"RULES_NOT_FOUND: rule file '{rules_path}' does not exist on the operator box."

        attempt_dir, attempt_id = _attempt_dir(workspace)
        hashfile = attempt_dir / "hash.txt"
        hashfile.write_text(h + "\n", encoding="utf-8")

        cracked: list[tuple[str, str]] = []
        crack_argv: list[str]
        show_argv: list[str]
        if t == "hashcat":
            crack_argv = ["hashcat", "-m", mode, "-a", "0", str(hashfile), wl]
            if rules_path:
                crack_argv.extend(["-r", rules_path])
            show_argv = ["hashcat", "-m", mode, str(hashfile), "--show"]
        else:  # john
            crack_argv = ["john", f"--wordlist={wl}", str(hashfile)]
            if john_format:
                crack_argv.extend([f"--format={john_format}"])
            show_argv = ["john", "--show", str(hashfile)]
            if john_format:
                show_argv.extend([f"--format={john_format}"])

        cmd = " ".join(crack_argv)
        crack_status, returncode, crack_out, elapsed = run_argv_captured(crack_argv, clamped_timeout, max_chars=3000)

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
        warn_block = f"{john_warn}\n" if john_warn else ""

        return (
            f"CRACK_RESULT: {crack_status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"TOOL: {t}\n"
            f"HASH_TYPE: {hash_name} (mode {mode})\n"
            f"COMMAND: {cmd}\n"
            f"EXIT_CODE: {returncode}\n"
            f"DURATION: {elapsed:.1f}s\n"
            f"CRACKED: {len(cracked)}\n"
            f"{warn_block}"
            f"{cracked_lines}\n"
            f"SHOW_OUTPUT:\n{_tail(show_out, 1500)}\n"
            f"OUTPUT:\n{_tail(crack_out, 3000)}"
        )
