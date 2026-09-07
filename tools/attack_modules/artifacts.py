"""Closed artifact vocabulary for attack-module capability composition.

``requires``/``produces`` strings on :class:`AttackModule` must come from
``ARTIFACT_VOCAB``. The old ``_artifact_present`` treated any unknown kind
as present ("so a typo never hides the module"), which silently passed
gating on typos and made producer/consumer mismatches invisible. Unknown
kinds are now absent (fail closed) and flagged by the contract test.
"""

from __future__ import annotations

import re
from typing import Any

# Canonical artifact kinds. Aliases map onto these (e.g. a module declaring
# ``creds`` means ``credentials``).
ARTIFACT_VOCAB: frozenset[str] = frozenset(
    {
        "credentials",
        "hash_artifact",
        "user_list",
        "foothold",
        "shell",
        "webshell",
        "session",
        "admin_priv",
        "high_priv",
        "persistence",
        "signing_posture",
        "git_config_leak",
        "vuln_confirmed",
        "lpe_candidates",
        "k8s_sa_token",
        "web_tech",
        "auth_scheme",
    }
)

_ALIASES: dict[str, str] = {
    "creds": "credentials",
    "password": "credentials",
    "hash": "hash_artifact",
    "root_priv": "admin_priv",
    "system_priv": "admin_priv",
}

# Typed ctx-field keys (lowercased) that count as a user identity / hash
# artifact. Substring-matching whole findings (e.g. "user" in str(f)) matched
# near-everything; only structured keys count now.
_FOOTHOLD_KINDS = {"foothold", "shell", "session"}
_PRIV_KINDS = {"admin_priv", "high_priv"}
_USER_KEYS = frozenset({"user", "username", "login", "account", "samaccountname", "upn"})
_HASH_KEYS = frozenset({"hash", "ntlm", "nthash", "lmhash", "lthash", "asrep", "tgs", "tgt", "kerberos", "hashcat"})

# Artifacts that are terminal findings (no consumer expected).
# high_priv: escalation outcome, end of chain (admin_priv is the plannable
# currency; high_priv marks cloud/container vectors already realized).
# webshell: terminal access — WebShellUpload co-produces foothold, which is
# what chains consume.
TERMINAL_ARTIFACTS: frozenset[str] = frozenset({"persistence", "vuln_confirmed", "high_priv", "webshell"})


def normalize(kind: str) -> str:
    """Lowercase + alias-resolve an artifact kind. Unknown kinds pass through
    unchanged (so the contract test can flag them as non-vocab)."""
    k = (kind or "").strip().lower()
    return _ALIASES.get(k, k)


def is_known(kind: str) -> bool:
    """True when ``kind`` is in the closed vocabulary (after aliasing)."""
    return normalize(kind) in ARTIFACT_VOCAB


def unknown_kinds(kinds: list[str]) -> list[str]:
    """Return entries of ``kinds`` outside the closed vocabulary."""
    return [k for k in kinds if not is_known(k)]


def is_satisfied(kind: str, ctx: Any) -> bool:
    """Best-effort prerequisite check: is artifact ``kind`` available in ctx?

    Closed-world: unknown kinds are NOT satisfiable (fail closed). Known
    kinds resolve against credentials / sessions / privilege level.
    """
    k = normalize(kind)
    if k not in ARTIFACT_VOCAB:
        return False
    if k == "credentials":
        return bool(getattr(ctx, "credentials", None))
    if k == "hash_artifact":
        if getattr(ctx, "credentials", None):
            return True
        for f in getattr(ctx, "findings", None) or []:
            if isinstance(f, dict) and _HASH_KEYS & {str(key).lower() for key in f}:
                return True
        return False
    if k in _FOOTHOLD_KINDS or k == "webshell":
        return bool(getattr(ctx, "access_achieved", False) or getattr(ctx, "sessions", None))
    if k in _PRIV_KINDS:
        return str(getattr(ctx, "privilege_level", "") or "").lower() in {
            "admin",
            "administrator",
            "system",
            "root",
            "high",
        }
    if k == "user_list":
        for source in (getattr(ctx, "credentials", None) or [], getattr(ctx, "findings", None) or []):
            for entry in source:
                if isinstance(entry, dict) and any(
                    str(key).lower() in _USER_KEYS and str(val).strip() for key, val in entry.items()
                ):
                    return True
        return False
    # State-backed artifacts with no dedicated ctx field (signing_posture,
    # git_config_leak, vuln_confirmed, lpe_candidates, k8s_sa_token,
    # web_tech, auth_scheme): satisfied only by a structured finding — a dict
    # key / kind / type naming the kind, or an exact-kind string ref.
    for f in getattr(ctx, "findings", None) or []:
        if isinstance(f, dict):
            if k in {str(key).lower() for key in f} or f.get("kind") == k or f.get("type") == k:
                return True
        elif isinstance(f, str):
            text = f.strip().lower()
            if text == k or re.search(rf"(?:^|\s){re.escape(k)}\s*:", text):
                return True
    return any(isinstance(ref, str) and ref.strip().lower() == k for ref in (getattr(ctx, "evidence_refs", None) or []))
