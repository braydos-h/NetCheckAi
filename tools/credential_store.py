"""Credential store for persistent loot and credential management across exploitation sessions.

Provides:
- CredentialRecord: structured credential entry
- CredentialStore: JSONL-backed persistent credential store with **at-rest Fernet
  encryption** of the secret (``password``) field
- LootItem / LootStore: arbitrary loot storage

At-rest encryption (Tier 0 item 0.3, Phase B)
----------------------------------------------
Harvested credentials used to live in ``credentials.jsonl`` as plaintext on the
operator's host. ``CredentialStore`` now encrypts the ``password`` field of
every record before it touches disk and decrypts it on load, so the in-memory
records stay plaintext (callers see ``record.password`` as before) while the
file on disk holds ciphertext. The key is resolved, in priority order, from:

  1. the ``AI_NMAP_VAULT_KEY`` environment variable (a urlsafe-base64 32-byte
     Fernet key the operator carries out-of-band), else
  2. a 0600 keyfile OUTSIDE the workspace tree at
     ``$BREACHPILOT_VAULT_DIR/<sha256-of-store-dir>.key`` (default
     ``~/.breachpilot/vault_keys/``), auto-generated on first use
     (per-store key -- protects against other non-root users on a shared
     host; does not protect against the operator/root who own the box).
     Keeping the key outside the workspace tree (which the AI reads freely
     via ``read_workspace_file``/``list_workspace``) is what keeps
     encrypted-at-rest secrets from degrading to plaintext. A legacy
     in-workspace ``.vault_key`` is adopted once (moved, not copied) so
     existing stores keep decrypting.

If the ``cryptography`` package is not importable, encryption is disabled and
the store falls back to **plaintext**, emitting a one-time loud WARNING (never
silent). Legacy plaintext files still load: a value that does not decrypt under
the current key is treated as plaintext, so existing stores are never bricked.

``confirmed`` gating
---------------------
A harvested credential is stored with ``confirmed=False`` and stays that way.
The *only* path to ``confirmed=True`` is :meth:`CredentialStore.confirm_credential`,
which a caller invokes only after validating that the credential was actually
reused (e.g. authenticated against the target). The caller MUST pass
``validated=True`` to assert that reuse succeeded -- a bare confirm is refused
(no flag flipped, nothing persisted), so a careless call cannot promote an
unvalidated credential. The harvester never grants confirmation.

The ``confirmed`` flag is **tamper-evident at rest**: every record carries an
HMAC-SHA256 over its canonical fields, keyed by the vault key. On load, a
record whose ``confirmed=True`` does not verify under the current key (a
hand-edited file, a file copied from another workspace, or anything written
while encryption was disabled) is downgraded to ``confirmed=False`` and logged.
So ``confirmed=True`` in memory always means *this workspace's key signed it
after a deliberate confirm* -- never a value merely asserted on disk.

Threat-model boundary (important): ``add`` forces ``confirmed=False`` and the
HMAC backstop defeats anyone who does NOT hold the vault key -- a hand-edited
file, a foreign workspace, or a plaintext-fallback write cannot produce a
signature the load-time verifier accepts, so a forged ``confirmed=True`` is
downgraded. They do **not** defend against code that runs *with* the vault key:
``full_access`` mode grants the agent arbitrary code execution on the operator's
host, so it can read the 0600 keyfile (which, per the key-resolution note above,
"does not protect against the operator/root who own the workspace") and append a
validly-signed ``confirmed=True`` record itself. That is the documented
``full_access`` trade-off, not a defeatable bug -- the vault is built for the
``read_only`` / ``approve_only`` trust boundary and for non-operator adversaries.
Operators who do not want the agent able to self-promote a credential must keep
``exploit.permission`` at ``read_only`` / ``approve_only``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Use the application's configured logger tree (``ai_bug_bounty``, set up by
# tools/logging_setup.setup_logging) so the plaintext-fallback WARNING is
# captured by the app's file/console handlers instead of being silently
# dropped by a stray ``breachpilot.creds`` logger that nothing configures.
_LOG = logging.getLogger("ai_bug_bounty.creds")


@dataclass
class CredentialRecord:
    timestamp: float
    source_host: str
    target_host: str
    username: str
    password: str
    credential_type: str  # password, hash, token, key
    source_action: str
    confirmed: bool = False
    notes: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_host": self.source_host,
            "target_host": self.target_host,
            "username": self.username,
            "password": self.password,
            "credential_type": self.credential_type,
            "source_action": self.source_action,
            "confirmed": self.confirmed,
            "notes": self.notes,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> CredentialRecord:
        return cls(
            timestamp=data.get("timestamp", time.time()),
            source_host=str(data.get("source_host", "")),
            target_host=str(data.get("target_host", "")),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            credential_type=str(data.get("credential_type", "password")),
            source_action=str(data.get("source_action", "")),
            confirmed=bool(data.get("confirmed", False)),
            notes=str(data.get("notes", "")),
        )


# ── At-rest Fernet vault ─────────────────────────────────────────────────────


def _vault_keys_dir() -> Path:
    """Directory holding vault keyfiles (outside every workspace tree).

    ``$BREACHPILOT_VAULT_DIR`` overrides (tests); default
    ``~/.breachpilot/vault_keys``. Falls back to ``None`` when the home
    directory cannot be resolved — callers then use the legacy
    in-workspace path (loud warning via the plaintext-fallback gate is
    NOT triggered; the legacy path is still 0600, just AI-readable, so a
    warning is logged at use).
    """
    override = os.environ.get("BREACHPILOT_VAULT_DIR", "").strip()
    if override:
        return Path(override)
    try:
        return Path.home() / ".breachpilot" / "vault_keys"
    except (RuntimeError, OSError, KeyError):
        return None  # type: ignore[return-value]


def _vault_key_path(store_dir: Path) -> Path:
    """Keyfile for ``store_dir`` — outside the workspace tree.

    Per-store key (sha256 of the resolved store path) so the HMAC
    tamper-evidence keeps its per-workspace property: a file copied from
    another store does not verify. Returns the legacy in-workspace path
    when no out-of-tree dir is available (caller logs a warning).
    """
    keys_dir = _vault_keys_dir()
    if keys_dir is None:
        return Path(store_dir) / ".vault_key"
    try:
        digest = hashlib.sha256(str(Path(store_dir).resolve()).encode("utf-8")).hexdigest()[:32]
    except OSError:
        digest = hashlib.sha256(str(store_dir).encode("utf-8")).hexdigest()[:32]
    return keys_dir / f"{digest}.key"


class _Vault:
    """Fernet-based at-rest encryption for the credential store's secret field.

    See the module docstring for the key resolution order and threat model.
    ``enabled`` is False (plaintext fallback) when ``cryptography`` is missing or
    a usable key cannot be established; the fallback is loud (one-time WARNING),
    never silent.
    """

    _plaintext_warned = False

    #: Basename deny-listed in ``read_workspace_file``/``list_workspace``
    #: (defense in depth: the live key no longer lives under the workspace,
    #: but a hand-placed or legacy keyfile must never be served to the model).
    DENY_BASENAME = ".vault_key"

    def __init__(self, workspace: Path) -> None:
        self.enabled = False
        self._fernet = None
        self._key_material: bytes | None = None
        self._store_dir = Path(workspace)
        self._legacy_keyfile = self._store_dir / ".vault_key"
        self._keyfile = _vault_key_path(self._store_dir)
        try:
            from cryptography.fernet import Fernet  # type: ignore

            self._Fernet = Fernet
        except ImportError:
            self._warn_plaintext_fallback(
                "cryptography package not installed -- credential store will be "
                "written in PLAINTEXT. Install 'cryptography' to enable at-rest "
                "Fernet encryption."
            )
            return
        key = os.environ.get("AI_NMAP_VAULT_KEY") or self._load_or_create_key()
        if not key:
            self._warn_plaintext_fallback("no vault key could be established")
            return
        try:
            key_bytes = key if isinstance(key, bytes) else key.encode()
            self._fernet = Fernet(key_bytes)
            self._key_material = key_bytes
            self.enabled = True
        except Exception as exc:  # invalid key material -> fail safe to plaintext
            self._warn_plaintext_fallback(f"invalid vault key ({exc!r})")

    @property
    def signing_key(self) -> bytes | None:
        """Key material for the record HMAC, or None when encryption is disabled.

        The HMAC is keyed by the same vault key as the Fernet encryption, so the
        ``confirmed`` flag is tamper-evident: a record whose ``confirmed=True``
        was not signed by this workspace's key (a crafted / hand-edited file, or
        a file from another workspace) is treated as untrusted on load.
        """
        return self._key_material

    @classmethod
    def _warn_plaintext_fallback(cls, detail: str) -> None:
        if not cls._plaintext_warned:
            _LOG.warning("Credential-store encryption DISABLED: %s", detail)
            cls._plaintext_warned = True

    def _load_or_create_key(self) -> str | None:
        """Return the 0600 keyfile's key, generating one on first use.

        The live keyfile lives OUTSIDE the workspace tree (see
        :func:`_vault_key_path`). A legacy in-workspace ``.vault_key`` is
        adopted once (moved, not copied) so existing stores keep decrypting
        and no key material is left behind in AI-readable space.
        """
        try:
            if self._keyfile.exists():
                return self._keyfile.read_text(encoding="utf-8").strip() or None
            if self._legacy_keyfile.exists():
                try:
                    key = self._legacy_keyfile.read_text(encoding="utf-8").strip() or None
                except OSError:
                    key = None
                if key:
                    self._keyfile.parent.mkdir(parents=True, exist_ok=True)
                    self._keyfile.write_text(key, encoding="utf-8")
                    try:
                        os.chmod(self._keyfile, 0o600)
                    except OSError:
                        pass
                    try:
                        self._legacy_keyfile.unlink()
                    except OSError:
                        pass
                    return key
            key = self._Fernet.generate_key().decode()
            self._keyfile.parent.mkdir(parents=True, exist_ok=True)
            self._keyfile.write_text(key, encoding="utf-8")
            # 0600 where the platform supports it (POSIX). On Windows os.chmod
            # only strips group/world bits -- a best-effort, not a guarantee.
            try:
                os.chmod(self._keyfile, 0o600)
            except OSError:
                pass
            return key
        except OSError as exc:
            self._warn_plaintext_fallback(f"could not read/create keyfile {self._keyfile}: {exc!r}")
            return None

    def encrypt(self, plaintext: str) -> str:
        """Return the at-rest form of ``plaintext`` (ciphertext, or plaintext if disabled)."""
        if not self.enabled or self._fernet is None:
            return plaintext
        try:
            return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        except Exception:
            return plaintext  # never lose a record to a crypto error

    def decrypt(self, token: str) -> str:
        """Return the plaintext form of ``token``; fall back to ``token`` if it is not ciphertext.

        Falling back (rather than raising) means legacy plaintext files and
        wrong-key/rotated-key reads still surface *something* instead of bricking
        the store. A wrong key yields garbage rather than the original secret,
        but the record is never lost.
        """
        if not self.enabled or self._fernet is None:
            return token
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except Exception:
            return token


class CredentialStore:
    """Persistent store for credentials and loot across sessions.

    The ``password`` field of each record is encrypted at rest (see ``_Vault``)
    and decrypted on load; in memory, records hold plaintext, so existing
    callers that read ``record.password`` are unchanged.
    """

    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._store_path = self.workspace / "credentials.jsonl"
        self._vault = _Vault(self.workspace)
        self._records: list[CredentialRecord] = []
        self._load()

    # ── record integrity (HMAC over the confirmed flag) ─────────────────────
    #
    # ``confirmed=True`` is the gate the exploit loop trusts before it reuses a
    # credential at full access. To stop a crafted/hand-edited file -- or a file
    # copied in from another workspace -- from carrying a forged
    # ``confirmed=True`` into memory, every record is HMAC-signed on write and
    # verified on load. The HMAC is keyed by the vault key, so it is only
    # produced when at-rest encryption is enabled; in plaintext-fallback mode no
    # signature is possible, so ``confirmed=True`` read from disk is *never*
    # trusted and is downgraded to False on load.

    def _sign_payload(self, payload: dict[str, Any]) -> str:
        """HMAC-SHA256 hex over canonical JSON of ``payload`` (which must NOT yet
        contain ``sig``). Returns ``""`` when no signing key is available (plaintext
        fallback); callers then omit the ``sig`` field entirely.
        """
        key = self._vault.signing_key
        if key is None:
            return ""
        body = json.dumps(payload, default=str, sort_keys=True, separators=(",", ":"))
        return hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()

    def _verify_sig(self, data: dict[str, Any], sig: str | None) -> bool:
        """True iff ``sig`` matches the record's HMAC under the current vault key.

        Constant-time via ``hmac.compare_digest``. With no signing key (plaintext
        fallback) or no signature present, no signature is valid, so every on-disk
        ``confirmed=True`` is treated as untrusted and downgraded on load.
        """
        key = self._vault.signing_key
        if key is None or not sig:
            return False
        expected = self._sign_payload(data)
        return hmac.compare_digest(expected, sig)

    def _attach_sig(self, payload: dict[str, Any]) -> None:
        """Sign ``payload`` in place, attaching ``sig`` when a key is available."""
        sig = self._sign_payload(payload)
        if sig:
            payload["sig"] = sig

    def _load(self) -> None:
        if not self._store_path.exists():
            return
        for line in self._store_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            # Verify the record's HMAC before trusting the ``confirmed`` flag.
            # The signature was computed over the on-disk fields (with the
            # CIPHERTEXT password) *before* ``sig`` was attached, so pop sig and
            # verify BEFORE decrypting the password into plaintext -- otherwise the
            # recomputed digest would cover the plaintext secret and never match.
            sig = data.pop("sig", None)
            sig_ok = self._verify_sig(data, sig)
            # Decrypt the secret field if it was written under encryption;
            # legacy plaintext falls through (decrypt returns it unchanged).
            if "password" in data:
                data["password"] = self._vault.decrypt(str(data["password"]))
            rec = CredentialRecord.from_json(data)
            if not sig_ok and rec.confirmed:
                # A confirmed=True we cannot authenticate was hand-edited, copied
                # from another workspace, or written under plaintext fallback. It
                # is downgraded so a stale/forged credential cannot masquerade as
                # validated. Legacy unconfirmed records load unchanged (the guard
                # only fires when confirmed was True).
                _LOG.warning(
                    "Downgrading untrusted confirmed=True credential for "
                    "%s@%s (no valid HMAC -- hand-edited, foreign workspace, or "
                    "plaintext-fallback write); re-confirm after a validated reuse.",
                    rec.username,
                    rec.target_host,
                )
                rec.confirmed = False
            self._records.append(rec)

    def save(self) -> None:
        # Atomic write: serialize to a sibling temp file in the same directory
        # (same filesystem, so os.replace is atomic) then rename over the store.
        # A plain ``open("w")`` truncates first -- a crash mid-write would leave
        # the whole credential store truncated and every credential lost.
        tmp_path = self._store_path.with_name(self._store_path.name + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            for rec in self._records:
                payload = rec.to_json()
                payload["password"] = self._vault.encrypt(rec.password)
                self._attach_sig(payload)
                handle.write(json.dumps(payload, default=str) + "\n")
        os.replace(tmp_path, self._store_path)

    def add(self, record: CredentialRecord) -> None:
        # The harvester path must NEVER produce a confirmed credential:
        # confirmation is a deliberate post-reuse signal gated behind
        # ``confirm_credential(validated=True)``. A caller-supplied
        # ``record.confirmed=True`` would otherwise be persisted AND HMAC-signed
        # under this workspace's own vault key, so it would survive reload as a
        # trusted, signature-verified credential -- silently bypassing the
        # validated gate the exploit loop trusts before reusing a credential at
        # full access. Force it to False here so the *only* path to
        # ``confirmed=True`` remains ``confirm_credential`` (matching the module
        # docstring). ``save()`` deliberately does NOT force False, so records that
        # ``confirm_credential`` legitimately flips to True are persisted as True.
        if record.confirmed:
            _LOG.warning(
                "add() received confirmed=True for %s@%s -- forcing False "
                "(harvested credentials are never confirmed; use "
                "confirm_credential(validated=True) after a validated reuse).",
                record.username,
                record.target_host,
            )
            record.confirmed = False
        for existing in self._records:
            if (
                existing.username == record.username
                and existing.target_host == record.target_host
                and existing.credential_type == record.credential_type
            ):
                return
        self._records.append(record)
        with self._store_path.open("a", encoding="utf-8") as handle:
            payload = record.to_json()
            payload["password"] = self._vault.encrypt(record.password)
            self._attach_sig(payload)
            handle.write(json.dumps(payload, default=str) + "\n")

    def confirm_credential(
        self,
        *,
        username: str,
        target_host: str,
        credential_type: str | None = None,
        validated: bool = False,
    ) -> bool:
        """Mark a harvested credential ``confirmed=True`` after a validated reuse.

        This is the *only* path to ``confirmed=True``: ``add`` stores unconfirmed
        records. Confirmation is a deliberate post-reuse signal, not something the
        harvester grants, so the caller MUST pass ``validated=True`` to assert it
        actually authenticated with the credential (e.g. via lateral_exec /
        dump_credentials). A bare confirm without ``validated=True`` is refused --
        it flips no flags and persists nothing -- so a careless call cannot
        promote an unvalidated credential. Returns True iff at least one record
        was newly confirmed.
        """
        if not validated:
            _LOG.warning(
                "confirm_credential refused for %s@%s: validated=False (caller did "
                "not assert the credential was reused successfully).",
                username,
                target_host,
            )
            return False
        changed = False
        for rec in self._records:
            if rec.confirmed:
                continue
            if rec.username != username or rec.target_host != target_host:
                continue
            if credential_type is not None and rec.credential_type != credential_type:
                continue
            rec.confirmed = True
            changed = True
        if changed:
            self.save()
        return changed

    def credentials_for_host(self, host: str) -> list[CredentialRecord]:
        return [r for r in self._records if r.target_host == host or r.source_host == host]

    def all_credentials(self) -> list[CredentialRecord]:
        return list(self._records)

    def hosts_with_credentials(self) -> list[str]:
        hosts = {r.target_host for r in self._records}
        hosts.update(r.source_host for r in self._records)
        return sorted(hosts)

    def summary(self) -> str:
        lines = ["CREDENTIAL STORE SUMMARY:", f"  Total records: {len(self._records)}"]
        for r in self._records:
            lines.append(f"  {r.target_host}: {r.username}/{r.credential_type} (confirmed={r.confirmed})")
        return "\n".join(lines)

    # ── introspection used by the MCP cred_store tools ──────────────────────

    @property
    def encryption_enabled(self) -> bool:
        return self._vault.enabled

    @property
    def store_path(self) -> Path:
        return self._store_path


@dataclass
class LootItem:
    timestamp: float
    source_host: str
    loot_type: str
    description: str
    content: str = ""
    path: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_host": self.source_host,
            "loot_type": self.loot_type,
            "description": self.description,
            "content": self.content[:5000],  # Bound inline content
            "path": self.path,
        }


class LootStore:
    """Persistent store for arbitrary loot (files, configs, data)."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._store_path = workspace / "loot.jsonl"
        self._items: list[LootItem] = []
        self._load()

    def _load(self) -> None:
        if not self._store_path.exists():
            return
        for line in self._store_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                self._items.append(
                    LootItem(
                        timestamp=data.get("timestamp", time.time()),
                        source_host=str(data.get("source_host", "")),
                        loot_type=str(data.get("loot_type", "")),
                        description=str(data.get("description", "")),
                        content=str(data.get("content", "")),
                        path=str(data.get("path", "")),
                    )
                )
            except (json.JSONDecodeError, TypeError):
                continue

    def add(self, item: LootItem) -> None:
        self._items.append(item)
        with self._store_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item.to_json(), default=str) + "\n")

    def loot_for_host(self, host: str) -> list[LootItem]:
        return [i for i in self._items if i.source_host == host]

    def summary(self) -> str:
        lines = ["LOOT STORE SUMMARY:", f"  Total items: {len(self._items)}"]
        for i in self._items:
            lines.append(f"  [{i.loot_type}] {i.source_host}: {i.description[:60]}")
        return "\n".join(lines)
