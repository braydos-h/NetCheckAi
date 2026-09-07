"""Audit-log helpers — credential redaction + audit decorators.

Extracted from ``tools.mcp_shared`` (Phase 2 kernel). ``tools.mcp_shared``
re-exports for backwards compat; ``tools.mcp_tools.registry`` re-imports
from there.

Ponytail: pure redaction + thin decorator factories. No behavior change —
verbatim move of ``_redact_*``, ``_mask_secret_content``, ``_audit_log``,
``_result_is_blocked``, ``_extract_audit_target``, ``make_audit_tool``,
``make_require_allowlist``.
"""

from __future__ import annotations

import functools
import inspect
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from tools.kernel.allowlist import (
    _check_allowlist,
    _extract_msf_rhosts,
    allowlist_env_audit_extra,
)

_SECRET_ARG_NAMES = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "passphrase",
        "secret",
        "shared_secret",
        "pre_shared_key",
        "secret_key",
        "signing_key",
        "ntlm_hash",
        "ntlm",
        "hash",
        "kerberos_ticket",
        "asrep_key",
        "rc4_key",
        "aes_key",
        "token",
        "auth_token",
        "access_token",
        "refresh_token",
        "session_key",
        "cookies",
        "authorization",
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "creds",
        "private_key",
        "priv_key",
    }
)

_REDACTED = "***REDACTED***"

_MASK_URL_AUTH_RE = re.compile(r"(?<=://)[^@\s:/]+:[^@\s:/]+(?=@)", re.IGNORECASE)
_MASK_U_FLAG_RE = re.compile(
    r"((?<![\w-])(?:-u|--user)\s+)[^\s:]+:[^\s]+",
    re.IGNORECASE,
)
_MASK_LONG_PW_RE = re.compile(
    r"((?<![\w-])(?:--password|--passwd|--passphrase|--pass|--pwd|-pass|-password|-passwd)\s+)[^\s]+",
    re.IGNORECASE,
)
_MASK_HYDRA_P_RE = re.compile(
    r"(\b(?:hydra|medusa|crackmapexec|netexec|cme|evil-winrm)\b[^\n]*?(?<![\w-])-[pP]\s+)[^\s]+",
    re.IGNORECASE,
)
_MASK_MSF_SET_RE = re.compile(
    r"(\bset\s+(?:SMBPass|PASSWORD|PASSWD|DbUserPass|DbPassword|DbPass|SECRET|SECRETKEY|"
    r"SECRET_KEY|TOKEN|API_KEY|APIKEY|NTLM_HASH|PRIVATE_KEY|PRIV_KEY|ACCESS_KEY|"
    r"AUTH_TOKEN|CREDENTIAL|DB_PASSWORD|DBPASS)\s+)[^\s]+",
    re.IGNORECASE,
)
_MASK_HASHES_RE = re.compile(
    r"((?<![\w-])-hashes\s+)(?:[\da-fA-F]{16,}:[\da-fA-F]{16,}|:[\da-fA-F]{16,}|[\da-fA-F]{16,})",
    re.IGNORECASE,
)
_MASK_NTLM_FLAG_RE = re.compile(
    r"((?<![\w-])-ntlm\s+)[\da-fA-F]{16,}",
    re.IGNORECASE,
)
_MASK_KV_SECRET_RE = re.compile(
    r"\b((?:SMBPass|PASSWORD|PASSWD|DbUserPass|DbPassword|DbPass|SECRETKEY|SECRET_KEY|"
    r"SECRET|TOKEN|API_KEY|APIKEY|NTLM_HASH|PRIVATE_KEY|PRIV_KEY|ACCESS_KEY|"
    r"AUTH_TOKEN|CREDENTIAL|CREDENTIALS|DB_PASSWORD|DBPASS)\s*=\s*)"
    r"[^\s,;=.\[\(\$\{]+",
    re.IGNORECASE,
)
_MASK_AUTH_HDR_RE = re.compile(
    r"(Authorization\s*:\s*(?:Basic|Bearer|Digest|Negotiate|NTLM)\s+)[^\s,;'\"]+",
    re.IGNORECASE,
)
_MASK_PY_AUTH_TUPLE_RE = re.compile(
    r"(\bauth\s*=\s*\(\s*)[\"'][^\"']+[\"']\s*,\s*[\"'][^\"']+[\"'](\s*\))",
    re.IGNORECASE,
)
# `password: hunter2` / `"password": "hunter2"` colon forms (YAML/JSON/tool
# output) -- the `=`-only KV mask above misses them. NTLM covers secretsdump
# `NTLM: <lm>:<nt>` lines; bare `32hex:32hex` pairs (no label) are caught by
# _MASK_NTLM_PAIR_RE below.
_MASK_KV_COLON_RE = re.compile(
    r"\b((?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|NTLM(?:_HASH)?)\s*:\s*[\"']?)[^\s,\"']+",
    re.IGNORECASE,
)
# Bare NTLM hash pairs with no label (secretsdump `user:rid:lm:nt:::` lines,
# hashcat Potfile `hash:plain` leftovers): 32 hex, colon, 32 hex. Specific
# enough to avoid false positives on UUIDs/SHAs (neither is 32:32).
_MASK_NTLM_PAIR_RE = re.compile(r"\b[\da-fA-F]{32}:[\da-fA-F]{32}\b")
# PEM blocks pasted into commands/logs (heredoc'd keys) -- the whole block is
# key material.
_MASK_PEM_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----",
    re.IGNORECASE,
)

_MASK_RES = (
    _MASK_URL_AUTH_RE,
    _MASK_U_FLAG_RE,
    _MASK_LONG_PW_RE,
    _MASK_HYDRA_P_RE,
    _MASK_MSF_SET_RE,
    _MASK_HASHES_RE,
    _MASK_NTLM_FLAG_RE,
    _MASK_KV_SECRET_RE,
    _MASK_KV_COLON_RE,
    _MASK_NTLM_PAIR_RE,
    _MASK_PEM_RE,
    _MASK_AUTH_HDR_RE,
    _MASK_PY_AUTH_TUPLE_RE,
)

_WHOLESALE_REDACT_FIELDS = frozenset({"input_text", "notes"})


def _mask_secret_content(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    out = value
    for rx in _MASK_RES:
        if rx is _MASK_URL_AUTH_RE or rx is _MASK_PEM_RE or rx is _MASK_NTLM_PAIR_RE:
            # Group-less whole-match masks: replace the match itself.
            out = rx.sub(_REDACTED, out)
        elif rx is _MASK_PY_AUTH_TUPLE_RE:
            out = rx.sub(rf"\1{_REDACTED}\2", out)
        else:
            out = rx.sub(rf"\1{_REDACTED}", out)
    return out


def _redact_nested(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (_REDACTED if isinstance(k, str) and k.lower() in _SECRET_ARG_NAMES else _redact_nested(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        # Credential dicts nested in lists (e.g. extra={creds: [{password: ...}]})
        # must be sanitized element-wise, not passed through.
        return [_redact_nested(v) for v in value]
    if isinstance(value, str):
        return _mask_secret_content(value)
    return value


def _redact_args(args: dict[str, Any] | None) -> dict[str, Any]:
    if not args:
        return {}
    redacted: dict[str, Any] = {}
    for name, value in args.items():
        lname = name.lower() if isinstance(name, str) else ""
        if lname in _SECRET_ARG_NAMES:
            redacted[name] = _REDACTED
        elif lname in _WHOLESALE_REDACT_FIELDS and value:
            redacted[name] = _REDACTED
        elif isinstance(value, str):
            redacted[name] = _mask_secret_content(value)
        else:
            redacted[name] = _redact_nested(value)
    return redacted


def _audit_log(
    audit_path: Path,
    *,
    target_ip: str,
    tool_name: str,
    approved: bool,
    status: str,
    command: str = "",
    args: dict[str, Any] | None = None,
    attempt_id: str = "",
    code_sha256: str = "",
    duration_seconds: float = 0.0,
    extra: dict[str, Any] | None = None,
) -> None:
    import json as _json

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_ip": target_ip,
        "tool_name": tool_name,
        "approved": approved,
        "status": status,
        "command": _mask_secret_content(command) if command else "",
        "args": args or {},
        "attempt_id": attempt_id,
        "code_sha256": code_sha256,
        "duration_seconds": duration_seconds,
    }
    if extra:
        # Optional structured context (e.g. the sandbox subsystem's container
        # id / network-policy fingerprint). Merged after the base keys so a
        # caller-supplied override is explicit. Sanitized with the SAME
        # pipeline as ordinary argument logging (secret-named keys at every
        # depth, secret-shaped strings, lists descended element-wise) —
        # callers must still keep secrets out, but anything that slips into
        # ``extra`` never reaches disk in cleartext.
        redacted_extra = _redact_args(extra)
        for key, value in redacted_extra.items():
            if value is not None:
                record[key] = value
    # ponytail: mkdir per audit row (2x per tool call) stats the fs every time.
    parent = audit_path.parent
    if str(parent) not in _MKDIR_CACHE:
        parent.mkdir(parents=True, exist_ok=True)
        _MKDIR_CACHE.add(str(parent))
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(_json.dumps(record, default=str) + "\n")


_BLOCKED_RESULT_MARKERS = ("BLOCKED:", "TERMINAL_RESULT: BLOCKED", "ROOT_CMD_RESULT: BLOCKED", "ERROR:")

# Structured terminal statuses for audit records. ``failed`` covers any
# exception escaping the wrapped tool (including BaseExceptionGroup and
# cancellation) — every ``started`` record is guaranteed a terminal sibling.
# The legacy ``"BLOCKED:"`` text prefixes in MCP responses are preserved;
# this model describes the audit record, not the wire format.
AuditStatus = Literal["started", "completed", "blocked", "failed"]

# Max characters of sanitized exception text kept in a failure record.
_FAILURE_SUMMARY_LEN = 500

# ponytail: cache mkdir'd parents — audit fires 2x per tool call.
_MKDIR_CACHE: set[str] = set()


def _failure_extra(exc: BaseException) -> dict[str, Any]:
    """Build the audit ``extra`` payload for a tool failure.

    Records the exception class name plus a sanitized one-line summary run
    through the same credential-redaction pipeline as ordinary argument
    logging — passwords, tokens, hashes, private keys, and Authorization
    headers in exception text never reach disk in cleartext.
    """
    summary = _mask_secret_content(str(exc)) if str(exc) else ""
    summary = " ".join(summary.split())[:_FAILURE_SUMMARY_LEN]
    return {"error_class": type(exc).__name__, "error_summary": summary}


def _extract_attempt_id(bound: "inspect.BoundArguments") -> str:
    """Return the tool's attempt ID when it takes one, else ``""``."""
    attempt_id = bound.arguments.get("attempt_id", "")
    return attempt_id if isinstance(attempt_id, str) else ""


def _safe_audit_log(audit_path: Path, **record: Any) -> None:
    """Best-effort :func:`_audit_log` for the failure path only.

    A full disk (or vanished workspace) must never mask the tool's original
    exception — or erase its failure record by raising inside the handler.
    Swallowing here is deliberate and narrow: normal-path audit writes keep
    surfacing errors loudly.
    """
    import logging

    try:
        _audit_log(audit_path, **record)
    except Exception as exc:  # noqa: BLE001 -- best-effort failure-path logging only
        logging.getLogger(__name__).warning("audit failure record lost: %s", exc)


def _log_terminal(
    audit_path: Path,
    *,
    target_ip: str,
    tool_name: str,
    result: Any,
    args: dict[str, Any],
    attempt_id: str = "",
    duration_seconds: float = 0.0,
) -> None:
    """Write the ``completed``/``blocked`` record for a returned result."""
    blocked = _result_is_blocked(result)
    _audit_log(
        audit_path,
        target_ip=target_ip,
        tool_name=tool_name,
        approved=not blocked,
        status="blocked" if blocked else "completed",
        args=args,
        attempt_id=attempt_id,
        duration_seconds=duration_seconds,
    )


def _log_failure(
    audit_path: Path,
    *,
    target_ip: str,
    tool_name: str,
    exc: BaseException,
    args: dict[str, Any],
    attempt_id: str = "",
    duration_seconds: float = 0.0,
) -> None:
    """Write the terminal ``failed`` record for an escaping exception."""
    _safe_audit_log(
        audit_path,
        target_ip=target_ip,
        tool_name=tool_name,
        approved=False,
        status="failed",
        args=args,
        attempt_id=attempt_id,
        duration_seconds=duration_seconds,
        extra=_failure_extra(exc),
    )


def _result_is_blocked(result: Any) -> bool:
    try:
        text = str(result).lstrip().upper()
    except Exception:  # noqa: BLE001 -- str() on hostile result objects must never break audit classification
        return False
    return text.startswith(_BLOCKED_RESULT_MARKERS)


def _extract_audit_target(bound: "inspect.BoundArguments") -> str:
    args = bound.arguments
    hosts: list[str] = []
    for key in ("command", "script_content"):
        text = args.get(key)
        if isinstance(text, str) and text:
            hosts.extend(_extract_msf_rhosts(text))
    lhost = args.get("lhost")
    if isinstance(lhost, str) and lhost:
        hosts.append(lhost)
    seen: set[str] = set()
    cleaned: list[str] = []
    for h in hosts:
        v = h.strip().strip('"').strip("'")
        if v and v not in seen:
            seen.add(v)
            cleaned.append(v)
    return ",".join(cleaned)


def make_require_allowlist(workspace: Path, config: dict[str, Any] | None):
    def require_allowlist(target_param: str = "target_ip", *, audit: bool = True, host_param: str | None = None):
        """Gate a tool on the target-IP allowlist.

        ``host_param`` names an optional second bound argument holding a
        hostname that gives the target its context (e.g. ``vhost_enum``'s
        ``domain`` for the ``Host:`` header / TLS SNI). When the primary
        target alone is not allowlisted, the pair is accepted iff the
        hostname is allowlisted AND the provenance store ties the target IP
        to that hostname (see :mod:`tools.kernel.discovered`). A resolved
        IP is therefore usable only in a context tied to its hostname,
        unless the IP itself is explicitly allowlisted. ``None`` (the
        default) preserves the legacy single-target gate.
        """
        from tools.kernel.discovered import get_discovered_host, is_pair_authorized
        from tools.validation_utils import is_target_in_allowlist

        def _pair_fallback(target_ip: Any, bound: "inspect.BoundArguments") -> tuple[bool, str] | None:
            """Pair-aware second chance after the flat gate denies. None = no pair context."""
            if not host_param:
                return None
            hostname = bound.arguments.get(host_param, "")
            if not isinstance(hostname, str) or not hostname.strip():
                return None
            if not isinstance(target_ip, str) or not target_ip.strip():
                return None
            from tools.kernel.allowlist import _allowed_target_list

            allowed_targets = _allowed_target_list(config)
            if not is_target_in_allowlist(hostname.strip(), allowed_targets):
                return None
            if is_pair_authorized(target_ip, hostname, allowed=allowed_targets):
                entry = get_discovered_host(hostname)
                via = (
                    f" via {hostname.strip()} ({entry.source})"
                    if entry and entry.source
                    else f" via {hostname.strip()}"
                )
                return True, f"target in allowlist{via}"
            return None

        def decorator(fn):
            sig = inspect.signature(fn)
            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args, **kwargs):
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    target_ip = bound.arguments.get(target_param, "")
                    allowed, reason = _check_allowlist(target_ip, config)
                    if not allowed:
                        pair = _pair_fallback(target_ip, bound)
                        if pair is not None:
                            allowed, reason = pair
                    redacted = _redact_args(dict(bound.arguments)) if audit else {}
                    attempt_id = _extract_attempt_id(bound)
                    if audit:
                        _audit_log(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            approved=allowed,
                            status="blocked" if not allowed else "started",
                            args=redacted,
                            attempt_id=attempt_id,
                            # Explicit env-widening event: when EXPLOIT_* env
                            # vars widen the lock beyond config.yaml, the
                            # widening is named on the row ({} otherwise).
                            extra=allowlist_env_audit_extra(config) or None,
                        )
                    if not allowed:
                        return f"BLOCKED: {reason}\nATTEMPT_ID: preflight\nTOOL: {fn.__name__}\nTARGET: {target_ip}"
                    # BaseException (not Exception): BaseExceptionGroup from
                    # anyio task groups and asyncio cancellation must still
                    # produce a terminal audit record — then re-raise
                    # unchanged so cancellation semantics are preserved.
                    start = time.monotonic()
                    try:
                        result = await fn(*args, **kwargs)
                    except BaseException as exc:
                        if audit:
                            _log_failure(
                                workspace / "exploit_audit.jsonl",
                                target_ip=target_ip,
                                tool_name=fn.__name__,
                                exc=exc,
                                args=redacted,
                                attempt_id=attempt_id,
                                duration_seconds=time.monotonic() - start,
                            )
                        raise
                    if audit:
                        _log_terminal(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            result=result,
                            args=redacted,
                            attempt_id=attempt_id,
                            duration_seconds=time.monotonic() - start,
                        )
                    return result

                async_wrapper.__signature__ = sig  # type: ignore[attr-defined]
                async_wrapper.__wrapped_require_allowlist__ = True  # type: ignore[attr-defined]
                async_wrapper.__wrapped_audit_tool__ = bool(audit)  # type: ignore[attr-defined]
                return async_wrapper
            else:

                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    target_ip = bound.arguments.get(target_param, "")
                    allowed, reason = _check_allowlist(target_ip, config)
                    if not allowed:
                        pair = _pair_fallback(target_ip, bound)
                        if pair is not None:
                            allowed, reason = pair
                    redacted = _redact_args(dict(bound.arguments)) if audit else {}
                    attempt_id = _extract_attempt_id(bound)
                    if audit:
                        _audit_log(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            approved=allowed,
                            status="blocked" if not allowed else "started",
                            args=redacted,
                            attempt_id=attempt_id,
                            # Explicit env-widening event (see async_wrapper).
                            extra=allowlist_env_audit_extra(config) or None,
                        )
                    if not allowed:
                        return f"BLOCKED: {reason}\nATTEMPT_ID: preflight\nTOOL: {fn.__name__}\nTARGET: {target_ip}"
                    start = time.monotonic()
                    try:
                        result = fn(*args, **kwargs)
                    except BaseException as exc:
                        if audit:
                            _log_failure(
                                workspace / "exploit_audit.jsonl",
                                target_ip=target_ip,
                                tool_name=fn.__name__,
                                exc=exc,
                                args=redacted,
                                attempt_id=attempt_id,
                                duration_seconds=time.monotonic() - start,
                            )
                        raise
                    if audit:
                        _log_terminal(
                            workspace / "exploit_audit.jsonl",
                            target_ip=target_ip,
                            tool_name=fn.__name__,
                            result=result,
                            args=redacted,
                            attempt_id=attempt_id,
                            duration_seconds=time.monotonic() - start,
                        )
                    return result

                wrapper.__signature__ = sig  # type: ignore[attr-defined]
                wrapper.__wrapped_require_allowlist__ = True  # type: ignore[attr-defined]
                wrapper.__wrapped_audit_tool__ = bool(audit)  # type: ignore[attr-defined]
                return wrapper

        return decorator

    return require_allowlist


def make_audit_tool(workspace: Path):
    def audit_tool(fn):
        sig = inspect.signature(fn)
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                target_ip = _extract_audit_target(bound)
                redacted = _redact_args(dict(bound.arguments))
                attempt_id = _extract_attempt_id(bound)
                _audit_log(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    approved=True,
                    status="started",
                    args=redacted,
                    attempt_id=attempt_id,
                )
                start = time.monotonic()
                try:
                    result = await fn(*args, **kwargs)
                except BaseException as exc:
                    _log_failure(
                        workspace / "exploit_audit.jsonl",
                        target_ip=target_ip,
                        tool_name=fn.__name__,
                        exc=exc,
                        args=redacted,
                        attempt_id=attempt_id,
                        duration_seconds=time.monotonic() - start,
                    )
                    raise
                _log_terminal(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    result=result,
                    args=redacted,
                    attempt_id=attempt_id,
                    duration_seconds=time.monotonic() - start,
                )
                return result

            async_wrapper.__signature__ = sig  # type: ignore[attr-defined]
            async_wrapper.__wrapped_audit_tool__ = True  # type: ignore[attr-defined]
            return async_wrapper
        else:

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                target_ip = _extract_audit_target(bound)
                redacted = _redact_args(dict(bound.arguments))
                attempt_id = _extract_attempt_id(bound)
                _audit_log(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    approved=True,
                    status="started",
                    args=redacted,
                    attempt_id=attempt_id,
                )
                start = time.monotonic()
                try:
                    result = fn(*args, **kwargs)
                except BaseException as exc:
                    _log_failure(
                        workspace / "exploit_audit.jsonl",
                        target_ip=target_ip,
                        tool_name=fn.__name__,
                        exc=exc,
                        args=redacted,
                        attempt_id=attempt_id,
                        duration_seconds=time.monotonic() - start,
                    )
                    raise
                _log_terminal(
                    workspace / "exploit_audit.jsonl",
                    target_ip=target_ip,
                    tool_name=fn.__name__,
                    result=result,
                    args=redacted,
                    attempt_id=attempt_id,
                    duration_seconds=time.monotonic() - start,
                )
                return result

            wrapper.__signature__ = sig  # type: ignore[attr-defined]
            wrapper.__wrapped_audit_tool__ = True  # type: ignore[attr-defined]
            return wrapper

    return audit_tool
