# Credential Vault

At-rest encryption for harvested credentials in `tools/credential_store.py`. The `password` field of every `CredentialRecord` is Fernet-encrypted before it touches disk and decrypted on load, so in-memory callers keep reading `record.password` as plaintext while `credentials.jsonl` on disk holds ciphertext.

## Key resolution

Resolution order is fixed in `_Vault.__init__` (`tools/credential_store.py`):

| Priority | Source | Notes |
|---|---|---|
| 1 | `AI_NMAP_VAULT_KEY` environment variable | Operator-carried urlsafe-base64 32-byte Fernet key. When set, no keyfile is read or created. |
| 2 | Per-store keyfile from `_vault_key_path(store_dir)` | Auto-generated on first use via `Fernet.generate_key()`. One key per store directory. |

```python
key = os.environ.get("AI_NMAP_VAULT_KEY") or self._load_or_create_key()
```

The per-store keyfile name is derived from the store path so each workspace gets its own key:

```python
digest = hashlib.sha256(str(Path(store_dir).resolve()).encode("utf-8")).hexdigest()[:32]
return keys_dir / f"{digest}.key"
```

`_vault_keys_dir()` returns `$BREACHPILOT_VAULT_DIR` when that variable is set (used by tests), otherwise `~/.breachpilot/vault_keys`. When the home directory cannot be resolved it returns `None` and `_vault_key_path` falls back to the legacy in-workspace path (the caller logs a warning at use).

Keeping the live key outside the workspace tree is the point: the agent reads workspace files freely via `read_workspace_file` / `list_workspace`, so a key stored inside the workspace would degrade encrypted-at-rest secrets to plaintext.

## Keyfile permissions and location

- Live location: `$BREACHPILOT_VAULT_DIR/<sha256-of-store-dir>.key`, default `~/.breachpilot/vault_keys/<sha256-of-store-dir>.key`.
- Created with `parent.mkdir(parents=True, exist_ok=True)` then `os.chmod(keyfile, 0o600)` (best-effort on Windows, where `os.chmod` only strips group/world bits).
- Per-store (not global): the `sha256` digest covers the resolved store path, so the HMAC tamper-evidence keeps its per-workspace property — a file copied from another store does not verify under this store's key.
- The 0600 mode protects against other non-root users on a shared host. It does not protect against the operator or root, who own the box (see Threat boundary below).

## Legacy `.vault_key` adoption

A legacy in-workspace `.vault_key` (`<store_dir>/.vault_key`) is adopted once, in `_load_or_create_key`:

1. Read the legacy keyfile.
2. Write the same key bytes to the out-of-tree keyfile (`0600`).
3. `unlink` the legacy file (moved, not copied), so no key material is left behind in AI-readable space.
4. Return the adopted key, so existing stores keep decrypting.

```text
<store_dir>/.vault_key  --move-->  ~/.breachpilot/vault_keys/<digest>.key
```

If the out-of-tree keyfile already exists, it wins and the legacy file is left alone by this path (no adoption needed).

## Plaintext fallback

If the `cryptography` package is not importable, or no usable key can be established (empty keyfile, invalid key material, keyfile I/O error), `_Vault.enabled` stays `False` and the store falls back to plaintext. The fallback is loud, never silent:

```python
_LOG = logging.getLogger("ai_bug_bounty.creds")
_Vault._warn_plaintext_fallback("cryptography package not installed -- ...")
```

- One-time `WARNING` via `_warn_plaintext_fallback` (guarded by `_plaintext_warned`), emitted on the `ai_bug_bounty.creds` logger so the app's configured handlers capture it.
- `encrypt` returns the input unchanged when disabled; `decrypt` returns its input unchanged when disabled or when the token is not valid ciphertext under the current key.
- Legacy plaintext files still load: a value that does not decrypt is treated as plaintext, so existing stores are never bricked. A wrong-key read surfaces *something* (possibly garbage) instead of losing the record — crypto errors never drop a record.

In plaintext-fallback mode no HMAC signature is possible, so on-disk `confirmed=True` is never trusted (see next section).

## Record integrity: `confirm_credential` plus HMAC downgrade

A harvested credential is stored with `confirmed=False` and stays that way. The only path to `confirmed=True` is `CredentialStore.confirm_credential`, which the caller invokes only after validating reuse (for example, authenticating against the target):

```python
store.confirm_credential(username="admin", target_host="10.0.0.50", validated=True)
```

| Method | Behavior |
|---|---|
| `CredentialStore.add(record)` | Forces `record.confirmed` to `False` (with a `WARNING` when the caller passed `True`). Dedupes on `(username, target_host, credential_type)`, then appends one signed JSONL line. `save()` does not force `False`, so legitimately confirmed records persist as `True`. |
| `CredentialStore.confirm_credential(*, username, target_host, credential_type=None, validated=False)` | Refuses when `validated` is falsy (flips no flags, persists nothing, returns `False` with a `WARNING`). Otherwise flips every matching unconfirmed record to `True`, calls `save()`, and returns `True` only when at least one record was newly confirmed. |
| `CredentialStore.credentials_for_host(host)` / `all_credentials()` / `hosts_with_credentials()` / `summary()` | Read-only views; `summary()` renders `target: user/type (confirmed=...)` lines. |
| `CredentialStore.encryption_enabled` / `store_path` | Introspection used by the MCP `cred_store` tools: vault `enabled` flag and the `credentials.jsonl` path. |

Every record carries an HMAC-SHA256 over its canonical fields, keyed by the vault key (`_Vault.signing_key`, the same Fernet key material):

- `_attach_sig` signs the on-disk payload (with the *ciphertext* password) before `sig` is attached, using canonical JSON (`sort_keys=True`, compact separators).
- `_verify_sig` uses `hmac.compare_digest`. With no signing key (plaintext fallback) or no `sig` present, no signature is valid.
- `_load` pops `sig` and verifies *before* decrypting the password — verifying after decryption would digest the plaintext secret and never match.
- Any record whose `confirmed=True` does not verify (hand-edited file, file copied from another workspace, or anything written while encryption was disabled) is downgraded to `confirmed=False` with a `WARNING` naming `username@target_host`. Legacy unconfirmed records load unchanged.

So `confirmed=True` in memory always means this workspace's key signed it after a deliberate `confirm_credential(validated=True)` — never a value merely asserted on disk.

## `DENY_BASENAME` and workspace reads

`_Vault.DENY_BASENAME = ".vault_key"`. The live key no longer lives under the workspace, but a hand-placed or legacy keyfile must never be served to the model. Enforcement lives in `tools/kernel/workspace.py`:

- `is_vault_key_path(filename)` matches the basename (after normalizing separators and quotes), so no path spelling reaches the key.
- `read_workspace` refuses with `BLOCKED: '.vault_key' is a credential-store keyfile and is never served.` before any filesystem access.

The same basename set (`_VAULT_KEY_BASENAMES = frozenset({".vault_key"})`) backs listing-time hiding covered by `tests/test_credential_store.py` (`test_read_workspace_file_denies_vault_keyfile` and the `".vault_key" not in listed` assertions).

Implementation note: the exact `list_workspace` hide path was verified via tests and `tools/kernel/workspace.py` comments, not by reading the list implementation in this pass.

## Threat boundary

`add` forces `confirmed=False` and the HMAC backstop defeats anyone who does not hold the vault key: a hand-edited file, a foreign workspace, or a plaintext-fallback write cannot produce a signature the load-time verifier accepts, so a forged `confirmed=True` is downgraded.

This does not defend against code running *with* the vault key. `full_access` mode grants the agent arbitrary code execution on the operator's host, so it can read the 0600 keyfile and append a validly-signed `confirmed=True` record itself. That is the documented `full_access` trade-off, not a defeatable bug: the vault is built for the `read_only` / `approve_only` trust boundary and for non-operator adversaries. Operators who do not want the agent able to self-promote a credential must keep `exploit.permission` at `read_only` / `approve_only`.

Related controls:

- `LootStore` (`loot.jsonl`, `LootItem` with inline `content` capped at 5000 chars) is arbitrary loot storage and is not encrypted — only the credential `password` field goes through the vault.
- `CredentialStore.save()` writes atomically (sibling `.tmp` file plus `os.replace`) so a crash mid-write cannot truncate the store.

## Related documentation

- [Safety model](safety-model.md) — permission modes, target-IP lock, and the audit/evidence safety layer.
- [Database and mission persistence](database-mission.md) — the SQLite schemas the credential JSONL stores sit alongside.
- [Outcome judgment and evidence handling](outcome-evidence.md) — evidential versus execution status and the Flow A audit trail.

## Source map

- `tools/credential_store.py`
- `tools/kernel/workspace.py`
- `tools/run_service/execute.py`
- `tools/exploit_agent/runner/_impl.py`
