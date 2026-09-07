---
title: Config — Overview
package: tools/config
files: [loader.py, schema.py, validator.py]
---

# Config — Overview (`tools/config/`)

Canonical config schema, validator, and loader. `schema.py` declares every default, `validator.py` enforces shape, `loader.py` loads with validation plus provider-config accessors. Legacy import sites keep working through the shim path below.

## Package map

| File | LOC | Role | Re-export via |
|---|---|---|---|
| `schema.py` | 921 | `CONFIG_SCHEMA` defaults + `KNOWN_TOP_KEYS` + `DEFAULT_CONFIG` alias | `tools.config_manager` |
| `validator.py` | 773 | `ConfigValidator` + `ConfigValidationResult` | `tools.config_manager` |
| `loader.py` | 199 | `load_validated_config`, `validate_config_file`, provider/embeddings accessors | `tools.config_manager` |
| `tools/config_manager.py` | shim | Re-exports the package + `resolve_known_provider_ids` | — |
| `tools/kernel/config.py` | pure loader | `load_config(path)` YAML mapping loader, hierarchy-aware | `tools.config_cli`, `tools.mcp_shared` |
| `tools/config_cli.py` | CLI helpers | `load_config` re-export + `add_target_to_allowlist` atomic allowlist writer | — |

## `schema.py` — defaults (`schema.py:20`)

```python
CONFIG_SCHEMA: dict[str, Any] = {...}
KNOWN_TOP_KEYS: set[str] = set(CONFIG_SCHEMA.keys())
DEFAULT_CONFIG = CONFIG_SCHEMA
```

One dict holds every top-level block and its defaults: `ollama`, `models`, `chatgpt`, `opencode_go`, `mcp`, `providers`, `embeddings`, `engine_mcp`, `nmap`, `exploit`, `stealth`, `cve_lookup`, `threat_intel`, `research`, `swarm`, `witness`, `autonomous`, `fsm`, `orchestrator`, `recon`, `opsec`, `eval`, `benchmark`, `killchain`, `browser`, `long_session`, `reasoning`, `memory`, `outcome_judgment`, `poc_verification`, `replay_simulator`, `hitl`, `snapshots`, `adaptive_exploits`, `multi_model`, `skills`, `plugins`, `webhook_notify`, `mitre`, `ticketing`, `api`, `agent`, `caldera`, `ics`, `operator_connection`, `sandbox`. Keys never hold secrets — they hold env var names (`api_key_env`, `token_env`).

Notable lab defaults: `exploit.permission: full_access` (target-IP lock is the lock), `sandbox.enabled: true` with `fallback_native: false`, `browser.enabled: false` + `backend: none`, `killchain.enabled: false`, `snapshots.enabled: false`, `operator_connection.enabled: true` with `auto_start_listener: true`.

## `validator.py` — validation

```python
class ConfigValidationResult: ...
class ConfigValidator:
    def __init__(self, config_path: Path | str = "config.yaml") -> None: ...
    def load(self) -> dict[str, Any]: ...
    def validate(self) -> ConfigValidationResult: ...
    def load_and_validate(self) -> tuple[dict[str, Any], ConfigValidationResult]: ...
    def apply_defaults(self) -> dict[str, Any]: ...
    def save(self, path: Path | str | None = None) -> None: ...
```

| Symbol | Kind | Description |
|---|---|---|
| `ConfigValidationResult` | class | `errors` / `warnings` / `unknown_keys`; `is_valid` (no errors), `has_warnings` |
| `ConfigValidator.load()` | def | Missing file → schema defaults with warning; non-mapping root → `ValueError` |
| `ConfigValidator.validate()` | def | Unknown top-level keys → errors (plugin sections exempt); strict nested-key errors for `ollama/models/mcp/exploit` (typos like `exploit.permision` are errors, not warnings) |
| `ConfigValidator.apply_defaults()` | def | Deep-merge loaded config over `copy.deepcopy(CONFIG_SCHEMA)` — file wins over schema |
| `ConfigValidator.save()` | def | `yaml.safe_dump` back to disk (used by `PATCH /api/v1/system/config`) |

Validation model is warn-not-reject except hard errors: `api.*` (loopback-only host, port range, token file), `eval.*`/`benchmark.*` types and ranges, `exploit.permission` enum, `models.provider` against registry ids. The `browser` block warns (never errors) on bad value types and errors only when `browser` is not a mapping (`validator.py:436-475`).

## `loader.py` — loading + provider accessors

```python
def validate_config_file(path: Path | str = "config.yaml") -> ConfigValidationResult: ...
def load_validated_config(path: Path | str = "config.yaml") -> dict[str, Any]: ...
def get_ai_provider(config: dict[str, Any] | None = None) -> str: ...
def get_provider_config(config: dict[str, Any] | None = None, provider_id: str = "") -> dict[str, Any]: ...
def get_embeddings_config(config: dict[str, Any] | None = None) -> dict[str, Any]: ...
def get_model_host(config: dict[str, Any] | None = None, provider_id: str | None = None) -> str: ...
def get_chatgpt_config(config: dict[str, Any] | None = None) -> dict[str, Any]: ...
def get_opencode_go_config(config: dict[str, Any] | None = None) -> dict[str, Any]: ...
def get_ollama_host(config: dict[str, Any] | None = None) -> str: ...
```

- `load_validated_config` raises `ValueError` on `is_valid == False`, logs warnings + unknown keys, returns `apply_defaults()` output.
- `get_provider_config` is the single normalization layer: modern `providers.<id>` block wins → legacy top-level block (`ollama`/`chatgpt`/`opencode_go`) with schema defaults → unknown providers get an empty block (third-party adapters supply their own defaults). Unknown non-empty `provider_id` raises `ValueError`.
- `get_ai_provider` reads `models.provider`, defaults to `"ollama"`, tolerates `None`.
- `get_embeddings_config` applies schema defaults plus legacy back-compat (inherits `ollama.embed_host`/`host` and `memory.embedding_model` when the modern block is untouched).
- `get_model_host` returns a host only for `ollama` (other providers own their endpoint); `""` otherwise.

## Shim path

1. `tools/config_manager.py` — pure re-export shim (`CONFIG_SCHEMA`, `DEFAULT_CONFIG`, `KNOWN_TOP_KEYS`, validator, loader symbols) plus `resolve_known_provider_ids()`, which reads the provider registry so adding provider #4 needs no validator edit (import-safe fallback to the built-in three).
2. `tools/kernel/config.py::load_config(path)` — the pure YAML loader shared by `tools.config_cli`, `tools.mcp_shared`, `tools.exploit_session`: `{}` if missing (hierarchy-aware for the default sentinel — missing `Path("config.yaml")` resolves via `tools.paths.load_effective_config` so packaged defaults survive; an explicit custom missing path still returns `{}`), `yaml.safe_load` + mapping check else `ValueError`. No global state.
3. `tools/config_cli.py` — re-exports kernel `load_config` for back-compat and adds `add_target_to_allowlist(path, target_ip)`, which normalizes IPs via `ipaddress` (domains/wildcards verbatim, lowercased) and does an atomic comment-preserving YAML edit.

## Lifecycle

```
--config <path> (default Path("config.yaml"))
      │
      ▼
kernel load_config ──► ConfigValidator.load()
      │                        │
      │                        ▼
      │                 .validate() → errors (raise) / warnings (log) / unknown_keys (log)
      │                        │
      ▼                        ▼
light path               load_validated_config → .apply_defaults() → merged config
(no defaults)                   │
                                ▼
                         consumers (main.py, app.py, mcp_*_server.py, doctor)
```

Two loaders coexist: the validated path (raises on errors, deep-merges defaults) and the light kernel path (pure, no defaults) where consumers apply defensive per-key defaults. File hierarchy for the effective config: explicit `--config` → `./config.yaml` → user locations (`$XDG_CONFIG_HOME`, `~/.config`, `~/.breachpilot`) → packaged `CONFIG_SCHEMA` (see `docs/configuration/overview.md`).

## Config keys consumed by this package

The package *defines* the schema rather than consuming keys, but two blocks shape its own behavior:

| Key | Default | Effect |
|---|---|---|
| `models.provider` | `"ollama"` | Whitelisted against registry ids; unknown → validation error |
| `providers.<id>` | `{}` | Modern per-provider layout, normalized by `get_provider_config` |
| `chatgpt.*` / `opencode_go.*` / `ollama.*` | legacy blocks | Back-compat overlays under the modern block |
| `embeddings.*` | `provider: ollama` | `none` disables embeddings; legacy `ollama.embed_host` inherited |

## Example

```python
from tools.config.loader import load_validated_config, get_provider_config

config = load_validated_config("config.yaml")
ollama_cfg = get_provider_config(config, "ollama")
```

## Tests (selected)

| File | Covers |
|---|---|
| `tests/test_config_manager.py` | Schema/validator/loader behavior |
| `tests/test_config_cli.py`, `test_config_cli_domain.py` | Allowlist writer, domain handling |
| `tests/test_agent_config_wiring.py`, `test_autonomous_config.py` | Consumer wiring |
| `tests/test_browser_config_defaults.py`, `test_eval_config.py` | Per-block defaults |

## Related documentation

- [Configuration overview](../../../configuration/overview.md)
- [Kernel overview](../kernel/overview.md)
- [Providers](../../../providers.md)
- [Provider development](../../../provider-development.md)

## Source map

- `tools/config/loader.py`
- `tools/config/schema.py`
- `tools/config/validator.py`
- `tools/config_manager.py`
- `tools/kernel/config.py`
- `tools/config_cli.py`
- `docs/configuration/overview.md`
