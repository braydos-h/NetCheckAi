# Config Reference (`config.yaml`)

Runtime source of truth for all engine behavior. This file documents every
top-level section and key, where each is consumed, and which CLI flags / env
vars can override it.

> **`opencode.jsonc` is NOT app config.** It is editor-local config (gitignored)
> for the opencode.ai editor's own model provider. Application config lives
> only in `config.yaml` (AGENTS.md rule 5). `mission.yaml` is Flow B's mission
> scope file — the exploit engine reads its scope rules from
> `config.yaml`'s `exploit` block instead (config.yaml:112-125).

## Purpose

- `config.yaml` is the checked-in operator defaults; `tools/config/schema.py::CONFIG_SCHEMA` mirrors the same defaults for when the file is missing or a key is absent (re-exported for back-compat by the `tools/config_manager.py` shim). **The two are proven in sync** by `tests/test_config_manager.py::test_config_yaml_keys_subset_of_schema` (`assert set(yaml.safe_load(open('config.yaml')))==set(CONFIG_SCHEMA)` — CI fails on drift; the same check runs as a CI lint step on top-level keys).
- Every top-level key is consumed somewhere; a missing key almost always falls back to a schema default rather than failing. **Strict sections** `exploit`, `mcp`, `ollama`, `models` promote unknown nested keys (e.g. `exploit.permision` typo) from warning to **error**, so CI fails on typos (`python -m pytest tests/test_config_manager.py -k unknown`).
- Secrets never live here — they are env vars (or `secr.json` via `--setup-api-keys`), named by `api_key_env` / `token_env` keys.
- **Machine-readable health:** `python main.py --doctor --json` emits `{checks:[{name, ok, error}], is_valid, unknown_keys}` (see `tools/doctor.py::build_doctor_report`) for `make doctor --json | jq -e '.is_valid'`.

## Load & validation flow

| Step | Where | Behavior |
|------|-------|----------|
| Load YAML | `ConfigValidator.load` (`tools/config/validator.py`) | Missing file → defaults; non-mapping → `ValueError` |
| Validate | `ConfigValidator.validate` (`tools/config/validator.py`) | Unknown top-level keys → warnings (plugin-registered sections exempt); type/range checks per section; **errors** for hard violations (e.g. `api.host` non-loopback) |
| Merge defaults | `apply_defaults` (`tools/config/validator.py`) | Deep-merge loaded config over `CONFIG_SCHEMA` defaults |
| Entry points | `load_validated_config` (`tools/config/loader.py`) raises on errors, logs warnings; `main.py` and `mcp_*_server.py` use the lighter `tools/config_cli.load_config` (raw YAML, no defaults merged) |
| Live PATCH | `PATCH /config` (tools/api/routes/system.py) | Atomic deep-merge, re-validated through `ConfigValidator`; loopback-only `allowed_origins` enforced |

Required sections (warned if absent, defaults apply): `ollama`, `models`,
`mcp`, `exploit` (`tools/config/validator.py`).

**Two load paths matter for defaults:** `tools/kernel/config.py::load_config` (raw YAML; `{}` when
the file is missing; no defaults merged) is what `main.py`/`mcp_shared`/`exploit_session` use, so
run-time consumers read missing keys defensively with their own fallbacks (e.g. `exploit.permission`
→ `read_only`). `tools/config/loader.py::load_validated_config` (validation + `apply_defaults()`
over `CONFIG_SCHEMA`) is what policy-adjacent helpers use.

## Config CLI

There is no dedicated `config` subcommand; config interaction is via flags on
`main.py` and helpers in `tools/config_cli.py`:

| Command / flag | What it does | Source |
|----------------|--------------|--------|
| `--config <path>` | Path to the YAML file (default `config.yaml`) | main.py `--config` |
| `--setup-api-keys` / `--api-key-file` / `--no-api-key-prompt` | Prompt for provider keys, persist to `secr.json`, load into env at boot | main.py api-keys group; `bootstrap_startup_api_keys` (`tools/config_cli.py`); `tools/api_key_store.py` |
| Start New Session (target entry) | Persists target into `exploit.allowed_targets` via atomic, comment-preserving YAML edit | `add_target_to_allowlist` / `_add_allowed_target_to_yaml` (`tools/config_cli.py`) |
| `--skills*` flags | Mutate the in-memory `config["skills"]` dict only (advisory) | `apply_skills_cli_overrides` (`tools/skills_cli.py`) |
| `--doctor` | Loads config, checks ollama host/models/nmap/ports/workspace | `tools/doctor.py` |
| `--self-test` | Same config reads as doctor, localhost smoke test | `tools/self_test.py` |

**Change config → verify with `python main.py --doctor`** (env, nmap, Ollama
reachability, model registry, port conflicts) and `python main.py --self-test`
(a safe localhost smoke test) before running sessions.

## Env var reference

| Env var | Default | Purpose | Set by config key | Read at |
|---------|---------|---------|-------------------|---------|
| `OLLAMA_API_KEY` | — | Bearer token for Ollama Cloud; missing → 401 on first chat | `ollama.api_key_env` (also `research.ollama.api_key_env`) | model_router.py:301-304, doctor.py:154, api_key_store.py:49-50 |
| `NVD_API_KEY` | — | NVD API key (raises rate limit) | `cve_lookup.api_key_env` | mcp_shared.py:109, cve_lookup.py:62 |
| `GITHUB_TOKEN` | — | GitHub Search token for `cve_to_poc` (60/hr unauth limit) | `cve_lookup.github.token_env` | api_key_store.py:53, exploit_search.py:190-237 |
| `SERPAPI_API_KEY` | — | SerpAPI key for web research | `research.serpapi.api_key_env` | mcp_shared.py:160, web_researcher.py:182 |
| `SHODAN_API_KEY` | — | Shodan key for passive OSINT (config key wins) | `recon.shodan_api_key` | recon_pipeline.py:287 |
| `EXPLOIT_TARGET` | — | Operator's literal `--target` (IP or domain); the allowlist lock's primary identity, unioned at check time | set by `tools/mcp_session.py:255` from `--target` | mcp_shared.py:523 |
| `EXPLOIT_TARGET_IP` | — | Resolved IP for a domain `--target` | mcp_session.py:265 | mcp_shared.py:523 |
| `EXPLOIT_TARGET_DOMAIN` | — | Domain string for a domain `--target` | mcp_session.py:266 | mcp_shared.py:523 |
| `EXPLOIT_DISCOVERED_TARGETS` | — | Comma-separated subdomains/IPs auto-authorized mid-run | `add_discovered_target` mcp_shared.py:537-555 | mcp_shared.py:528-533 |
| `EXPLOIT_WORKSPACE` | `exploit_workspace` | Exploit workspace root override | set by mcp_session.py:256 | cve_lookup.py:171 (KEV cache), tools/kernel/workspace.py:139 |
| `BREACHPILOT_API_TOKEN` | token file | WebUI daemon bearer token override (never logged) | `api.token_file` | app.py:71, tools/api/auth.py:46 |
| `OPENCODE_GO_API_KEY` | — | OpenCode Go provider key (Responses API at opencode.ai) | `providers.opencode_go.api_key_env` | tools/providers/opencode_go_provider.py, api_key_store.py |
| `CALDERA_API_KEY` | — | Caldera server API key (env-only, never config) | `caldera.api_key_env` | plugins/caldera/plugin.py:42 |
| `TICKETING_TOKEN` | — | Jira/GitHub ticketing token (env-only) | `ticketing.token_env` | tools/ticketing.py:33 |
| `PROXMOX_API_TOKEN` | — | Proxmox snapshot provider token (env-only, never logged) | — (provider `proxmox`) | tools/snapshots.py ProxmoxProvider |
| `MCP_HTTP_TOKEN` | — | Optional bearer auth for MCP HTTP transport | — | mcp_shared.run_mcp_http_server, mcp_engine_server.py:27 |
| `MCP_ALLOW_PUBLIC_BIND` | — | Second half of the two-person rule for non-loopback MCP binds | — | mcp_shared.run_mcp_http_server |
| `AI_NMAP_ACTIVE_MODEL_ALIAS` | — | Active model alias threaded into the MCP server subprocess | set by mcp_session.py:270 | tools/mcp_tools/registry.py:201, peer_models.py:80 |
| `AI_NMAP_DEBUG` | — | Debug logging switch | set by main.py:590 from `--debug` | exploit_agent |
| `RESEARCH_WORKSPACE` | `research_workspace` | Flow B research workspace | — | db.py:806, model_telemetry.py:111 |

## Top-level sections

### `ollama:` (config.yaml:2-6) — model backend

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `host` | str | `https://api.ollama.com` | Ollama endpoint for chat/generate (cloud default; point at a local daemon to go local). The ollama Python client auto-attaches `Authorization: Bearer $OLLAMA_API_KEY`. | `tools/config/loader.py` `get_ollama_host`, `tools/model_router.py`, `tools/doctor.py` |
| `model` | str | `glm-5.2:cloud` | Default concrete model id | `tools/config/schema.py`, `tools/interactive_menu.py` (menu default write) |
| `api_key_env` | str | `OLLAMA_API_KEY` | Env var holding the bearer token | `tools/api_key_store.py` |
| `embed_host` | str | `http://localhost:11434` | Embedding host (falls back to `host`) — embeddings stay local by default even on the cloud chat path | `tools/exploit_agent/runner/_impl.py` (SemanticMemoryManager wiring), `tools/skill_embeddings.py` |

### `models:` (config.yaml:15-44) — model registry

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `provider` | enum | `opencode_go` (lab config.yaml) / `ollama` (schema fallback; absent = `ollama`) | Active chat/generate provider; validated against the provider **registry** (built-ins: `ollama`\|`opencode_go`\|`chatgpt`, via `tools.config_manager.resolve_known_provider_ids`) — adding provider #4 extends the whitelist automatically. | `tools/config/loader.py` `get_ai_provider`, `tools/providers/registry.py`, `tools/model_router.py` `build_router`/`build_model_client_for_provider`, run_service/service.py, doctor.py, api/routes/system.py |
| `registry` | map[alias→model id] | kimi/deepseek/deepseek_flash/glm/minimax | Alias → concrete cloud model mapping (Ollama path) | `tools/config/schema.py`, `tools/doctor.py`, `tools/run_service/service.py`, `tools/mcp_tools/registry.py` |
| `default_alias` | str | `glm` | Active model alias (Ollama path; ChatGPT path uses `chatgpt.default_model`) | `tools/config/schema.py`, `tools/run_service/service.py`, `tools/eval_harness.py`, `legacy/agent_loop.py` |
| `auto_update` | bool | `true` | Auto-update `registry` against the live Ollama API (`GET /api/tags`): at daemon boot each alias is bumped to the newest same-family version (e.g. `glm-5.2:cloud` → `glm-5.3:cloud`). No pulls (cloud pull = pointer only); `models.info` stays operator-managed. On demand: `POST /api/v1/models/refresh` | `tools/ollama_models.py` (`auto_refresh_on_startup`, `refresh_model_registry`), `main.py` `_auto_update_models`, `api/routes/system.py` `refresh_models` |
| `info.<alias>.context_window` | int | per-model | Source of truth for the adaptive context compactor | model_router.py:202-221, exploit_agent/context.py:63-104 |
| `info.<alias>.label/description` | str | per-model | Display metadata | model_router.py:130, api routes/system.py:193-194 |

### `providers:` (config.yaml) — per-provider chat config (canonical shape)

The modern home for chat-provider config. Each registered provider id gets its
own block — exactly one normalization layer reads them
(`tools/config/loader.py` `get_provider_config`): the `providers.<id>` block
wins, the legacy top-level block (`chatgpt:`, `opencode_go:`) is the
fallback, and `tools/config/schema.py` `DEFAULT_CONFIG["<id>"]` supplies
schema defaults. Adding provider #4 adds a block here — no new top-level
config plumbing. The checked-in `config.yaml` carries `providers.opencode_go`
(the active provider) + `providers.chatgpt`.

| Key (per provider) | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` | Master switch (advisory; `models.provider` is the real selector) | `BaseProvider.is_configured`, adapters |
| `base_url` | str | per adapter | Provider endpoint | adapter `build_client`/`list_models` |
| `api_key_env` | str | per adapter | Env var holding the API key (value is env-only, never in config) | adapters, `tools/api_key_store.py` |
| `request_timeout_seconds` | int | `300` | HTTP timeout for provider calls | `model_router.py`, adapters |
| `default_model` | str | per adapter | Default concrete model id; also the session-titler model | `resolve_default_model` (`tools/providers/registry.py`), `session_titler.py` |
| `models` | list[str] | `[]` | Override model list; `[]` = live discovery | `BaseProvider.list_models`, `build_router` |
| `context_window` | int | `128000` | Conservative context window for the compactor | `model_router.py`, `exploit_agent/context.py` |
| `discover_cache_seconds` | int | `300` | Live-model-discovery cache TTL | adapters |

Built-in id → legacy-fallback block mapping: `chatgpt` → `chatgpt:`,
`opencode_go` → `opencode_go:`, `ollama` → `ollama:` (host/model only —
Ollama's alias registry stays in `models:`). See
[provider-development.md](provider-development.md) for the provider #4 recipe.

### `chatgpt:` (top-level, legacy fallback) — ChatGPT provider (opt-in)

Alternative chat/generate provider backed by the vendored
`openai-oauth/` loopback proxy. Active only when `models.provider: chatgpt`.
Legacy top-level keys still resolve (see `providers:` above) — prefer the
`providers.chatgpt` block in new configs. See
[docs/providers.md § ChatGPT provider](providers.md#the-chatgpt-provider-openai-oauth).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` | Master switch (advisory; `models.provider` is the real selector) | `tools/config/loader.py` `get_chatgpt_config` |
| `host` | str | `127.0.0.1` | Proxy bind — **loopback-only; do not point at a non-loopback interface** | chatgpt_provider.py `ensure_running` |
| `port` | int | `10531` | Proxy port | chatgpt_provider.py `ensure_running` |
| `base_url` | str | `http://127.0.0.1:10531/v1` | OpenAI-compatible endpoint the adapter POSTs to | chatgpt_provider.py `ChatGptProxyClient`, `discover_models` |
| `auto_start` | bool | `true` | Start the vendored proxy if `/health` is down | chatgpt_provider.py `ensure_running` |
| `local_repo` | str | `./oauth` | Path to the vendored checkout (cwd for CLI subprocess) | chatgpt_provider.py `_resolve_runtime`/`ensure_running`/`run_login`/`shutdown` |
| `runtime` | str | `auto` | `auto`\|`bun`\|`node` — how to run the openai-oauth CLI | chatgpt_provider.py `_resolve_runtime` |
| `request_timeout_seconds` | int | `300` | httpx timeout for `/v1/chat/completions` | chatgpt_provider.py `ChatGptProxyClient`, model_router.py |
| `default_model` | str | `gpt-5.2` | Fallback model id when `/v1/models` discovery fails; also the session-titler model | model_router.py `_build_chatgpt_router`, session_titler.py |
| `models` | list[str] | `[]` | Override model list; `[]` = discover from `/v1/models` | model_router.py `_build_chatgpt_router` |
| `context_window` | int | `128000` | Conservative context window (`/v1/models` returns no metadata) | model_router.py, exploit_agent/context.py |
| `login_timeout_seconds` | int | `300` | `login` CLI subprocess timeout | chatgpt_provider.py `run_login` |
| `start_timeout_seconds` | int | `30` | `/health` poll budget when auto-starting | chatgpt_provider.py `ensure_running` |
| `discover_cache_seconds` | int | `300` | `/v1/models` discovery cache TTL | chatgpt_provider.py `discover_models` |
| `oauth_file` | str | `""` | `""` = auto-resolve `~/.codex/auth.json` \| `$CODEX_HOME/auth.json` (existence only — never read) | chatgpt_provider.py `is_authenticated` |

### `embeddings:` (config.yaml) — embedding provider selection

Semantic memory + skill embeddings go through a separate, chat-provider-
independent abstraction (`tools/providers/embeddings.py`):

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `provider` | enum | `ollama` | `ollama` (legacy: local Ollama embeddings) \| `none` (**zero requests — semantic memory falls back to keyword storage, skills to deterministic matching**) | `tools/providers/embeddings.py` `build_embedding_provider` |
| `host` | str | `""` | Embedding endpoint; `""` = `ollama.embed_host` → `ollama.host` fallback | `OllamaEmbeddingProvider` |
| `model` | str | `""` | Embedding model; `""` = `nomic-embed-text` | `OllamaEmbeddingProvider` |
| `api_key_env` | str | `OLLAMA_API_KEY` | Env var holding the bearer token (sent unconditionally; local daemons ignore it) | `OllamaEmbeddingProvider` |
| `timeout_seconds` | int | `30` | urlopen timeout | `OllamaEmbeddingProvider` |

With `provider: none` (as checked in) the engine makes ZERO Ollama requests
from the embeddings path — `embeddings_disabled()` short-circuits consumers.

### `mcp:` (config.yaml:45-46) — exploit MCP transport

### `mcp:` (config.yaml:45-46) — exploit MCP transport

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `default_transport` | str | `stdio` | Default exploit-server transport (`stdio`\|`http`) | `tools/config/schema.py`; CLI `--mcp-transport` is **ignored on the run path** — always forced to `http` so the target-IP lock reaches the server |
| `http_host` / `http_port` | str / int | `127.0.0.1` / `8001` | HTTP transport bind (schema default; absent from config.yaml) | `tools/doctor.py`, `tools/self_test.py`, `tools/eval_harness.py`, `tools/run_service/service.py` |

### `engine_mcp:` (config.yaml:54-57) — advisory MCP server for foreign AI assistants

Read-only surface (skill search, NVD CVE lookup, run history); no target
touching. CLI-runnable regardless; block supplies entrypoint defaults.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Advertise/enable the engine server | mcp_engine_server.py:201-211 (config loaded for CLI defaults) |
| `host` | str | `127.0.0.1` | Loopback-only bind | mcp_engine_server.py:22-27 |
| `port` | int | `8002` | HTTP port | mcp_engine_server.py:22 |

### `nmap:` (config.yaml:62-65) — Linux-friendly nmap invocation

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `path` | str | `nmap` | Binary override when not on PATH | recon_pipeline.py:289, mcp_server.py:178, doctor.py:331 |
| `sudo` | bool | `false` | Run nmap via `sudo -n` for root-only `-O`/`-sS` | recon_pipeline.py:290, tools/nmap_priv |
| `priv_fallback` | bool | `true` | Auto-downgrade `-sS`/`-O` → `-sT` instead of failing | recon_pipeline.py:291, tools/nmap_priv |

### `exploit:` (config.yaml:66-155) — attack path

**The target-IP allowlist lock is THE safety gate** — `require_explicit_allowlist`
+ `allowed_targets` unioned with the `EXPLOIT_TARGET*` env vars
(`_allowed_target_list` mcp_shared.py:494-534, `_check_allowlist` :558-571).
`permission: full_access` auto-approves every action; recon is **always**
`READ_ONLY` regardless of config (cli_exploit_settings.py:157-159).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch for exploit path | mcp_shared.py:77 |
| `mode` | str | `standalone` | Run mode | cli_exploit_settings.py:128 |
| `permission` | enum | `full_access` | `full_access`/`approve_only`/`read_only`; unknown or **missing** → `read_only` (safe baseline) | cli_exploit_settings.py:12-30, mcp-tools.md:171 |
| `attack_mode` | bool | `true` | Live attack posture | cli_exploit_settings.py:131 |
| `terminal` | str | `visible` | Terminal echo mode | cli_exploit_settings.py:131 |
| `command_timeout_seconds` | int | `300` | Per-command timeout | cli_exploit_settings.py:132 |
| `max_commands_per_session` | int | `9999` | Command budget | cli_exploit_settings.py:133 |
| `max_rounds` | int | `200` | Round cap (recon/analysis) | cli_exploit_settings.py:134 |
| `attack_max_commands` | int | `150` | Attack-mode command budget | cli_exploit_settings.py:123 (long-session overrides, :119) |
| `attack_max_rounds` | int | `50` | Attack-mode round cap | cli_exploit_settings.py:124 |
| `attack_max_duration_minutes` | int | `360` | Attack-mode wall clock | cli_exploit_settings.py:125 |
| `context_summarize_every` | int | `50` | Min gap between context compactions | cli_exploit_settings.py:140, exploit_agent/context.py:596 |
| `auto_post_exploit` | bool | `true` | Auto-run post-exploit phase | cli_exploit_settings.py:141 |
| `max_pivot_depth` | int | `2` | Pivot recursion cap | cli_exploit_settings.py:142, autonomous_orchestrator.py:1091,1638 |
| `workspace_dir` | str | `exploit_workspace` | Workspace root | cli_exploit_settings.py:148, interactive_menu.py:417 |
| `loot_workspace` | str | `exploit_workspace/loot` | Loot dir | cli_exploit_settings.py:144 |
| `attacker_os` | str | `auto` | OS-aware instructions/tools | tools/exploit_agent/runner/_impl.py (`_resolve_attacker_os`) |
| `searchsploit_path` | str | `searchsploit` | Searchsploit binary | mcp_shared.py:78, doctor.py:123 |
| `shell` | str | `bash` | Shell for `run_exploit_terminal` (cmd.exe on Windows) | cli_exploit_settings.py:146 |
| `msfconsole_path` | str | `msfconsole` | Metasploit console binary | cli_exploit_settings.py:147, tools/mcp_tools/metasploit.py:83 |
| `web_search` | bool | `true` | Web search for exploit intel | mcp_shared.py:73-87 (via `search` block) |
| `max_query_chars` / `cache_ttl_seconds` / `cache_max_entries` | int | `200` / `3600` / `50` | ExploitSearch cache limits | mcp_shared.py:85-87 |
| `require_explicit_allowlist` | bool | `true` | **The target-IP lock** — when true every target-touching tool checks the allowlist | mcp_shared.py:561,635; mcp_exploit_server.py:141 |
| `allowed_targets` | list[str] | `[127.0.0.1]` | Operator-authorized hosts (IP, domain, `*.wildcard`, CIDR); Start New Session persists here | `tools/mcp_shared.py`, `tools/config_cli.py`, `tools/exploit_agent/runner/_impl.py` (`_resolve_allowed_targets`) |
| `disallowed_assets` / `forbidden_actions` | list[str] | `[]` | **Enforced on the full_access attack path.** Parsed into the `ScopeGate` handed to `ExploitPolicy` (`tools/exploit_session.py::_build_exploit_scope_gate`) and consulted by `ExploitPolicy._enforce_mission_scope` in `approve_action`: a tool whose `_TOOL_ACTION_CATEGORY` category is listed in `forbidden_actions`, or a command whose destinations fall outside `allowed_assets` / inside `disallowed_assets`, is denied with a `SCOPE_DENIED` row in `exploit_audit.jsonl`. Hostname destinations are only vetted when the gate's allow rules include a domain/wildcard pattern (otherwise hostname authorization is delegated to the MCP-layer allowlist); loopback and `exploit.allowed_targets` hosts are pre-authorized at the policy layer. `scope_gate=None` (swarm without a mission gate) stays permissive. Additional enforcement: the swarm **critic agent** blocks actions in the swarm mission's `forbidden_actions` (`tools/swarm/agents/critic_agent.py`), and Flow B's `ScopeGate` enforces them (`scope_gate.py`). | `tools/exploit_session.py`, `tools/exploit_agent/policy.py`, `tools/swarm/agents/critic_agent.py`, `scope_gate.py` |
| `ad_kerberos.enabled` + per-tool flags | bool | `false` (all; `smb_signing_check: true`) | AD/Kerberos post-exploit suite — master + per-tool must both be true | tools/mcp_tools/ad.py:36, tests/test_ad_mcp_tools.py |
| `msf.recipes_enabled` / `auto_local_exploit_suggester` | bool | `false` | MSF recipe dispatch + advisory LES task | tools/mcp_tools/metasploit.py, autonomous_orchestrator.py:1114-1115 |
| `listeners.tls/dns/https_beacon/socks_pivot` | bool | `false` | Extended C2 listener types (legacy nc/socat/http ungated) | persistent_session_manager.py:399-524, tests/test_listeners_extended.py |

### `stealth:` (config.yaml:156-159) — legacy stealth flags (INERT, use `opsec`)

> **Stealth is legacy/inert.** `stealth` is kept for compat and is UI-only; it is NOT consumed by the active OPSEC engine. The canonical block is `opsec` (`tools/opsec.py`) which gates pacing, UA rotation, DoH, quiet-command hints, and target-aware `local_targets_off` logic. New config should set `opsec.*`, not `stealth.*`. The `stealth` keys are still validated but have no effect on the agent's runtime behavior (only `interactive_menu.py` reads them to seed legacy UI).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `rotate_ua` | bool | `false` | **LEGACY** Rotate User-Agent across HTTP egress | interactive_menu.py:387 (superseded by `opsec.ua_rotation`) |
| `dns_over_https` | bool | `false` | **LEGACY** Resolve via DoH | interactive_menu.py:387 (superseded by `opsec.doh`) |
| `doh_provider` | str | `cloudflare` | **LEGACY** `cloudflare`\|`google` | opsec.py:63,95 |


### `opsec:` (config.yaml:268-285) — active OPSEC (canonical, replaces `stealth`)

The `opsec` block is the **active** detection-evasion / pacing / UA-rotation / DoH / quiet-command block consumed by `tools/opsec.py`. See `opsec` section below for full key table — do not confuse with `stealth`.

### `cve_lookup:` (config.yaml:160-179) — NVD / vuln-intel

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | NVD lookup master switch | mcp_shared.py:103 |
| `max_results` | int | `5` | Results per lookup | mcp_shared.py:105 |
| `rate_limit_seconds` | float | `6.0` | Per-instance NVD gap (fallback when no shared limiter) | mcp_shared.py:108, cve_lookup.py:61 |
| `timeout_seconds` | int | `30` | HTTP timeout | mcp_shared.py:104 |
| `cache_ttl_seconds` / `cache_max_entries` | int | `3600` / `100` | Cache bounds | mcp_shared.py:106-107 |
| `api_key_env` | str | `NVD_API_KEY` | Key env name | mcp_shared.py:109, api_key_store.py:52 |
| `circuit_failure_threshold` | int | `5` | Breaker opens after N consecutive failures | mcp_shared.py:110, cve_lookup.py:69 |
| `circuit_recovery_timeout` | float | `60.0` | Half-open probe wait | mcp_shared.py:111, cve_lookup.py:70 |
| `search_rate_limit_per_minute` | number | `10` | Process-wide shared NVD budget (0 disables) | mcp_shared.py:113-114 |
| `epss_enabled` / `kev_enabled` | bool | `true` | EPSS/KEV enrichment (lab default ON, live out of the box) | cve_lookup.py:73-74,246-247 |
| `kev_cache_ttl_seconds` | int | `86400` | KEV catalog refresh TTL | cve_lookup.py:75,182 |
| `kev_cache_path` | str | `""` | `""` = `exploit_workspace/.kev_catalog.json` | cve_lookup.py:76,170-171 |
| `github.token_env` | str | `GITHUB_TOKEN` | GitHub token for `cve_to_poc` (optional; unauth 60/hr fallback) | api_key_store.py:53, exploit_search.py:190-237 |

### `research:` (config.yaml:180-213) — web research

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Research subsystem | mcp_shared.py:129, api_key_store.py:177 |
| `provider` / `fallback_provider` | str | `ollama` / `serpapi` | Provider and fallback (`ollama`\|`serpapi`\|`stdlib`) | mcp_shared.py:130-131 |
| `timeout_seconds` | int | `15` | HTTP timeout | mcp_shared.py:132 |
| `max_results` | int | `8` | Result cap | mcp_shared.py:133 |
| `max_fetch_depth` | int | `5` | Page-fetch depth | mcp_shared.py:134, web_researcher.py:677-681 |
| `max_content_chars` | int | `12000` | Fetched-content cap | mcp_shared.py:135 |
| `cache_ttl_seconds` / `cache_max_entries` | int | `1800` / `250` | Cache bounds | mcp_shared.py:136-137 |
| `min_source_quality` | str | `medium` | `low`\|`medium`\|`high` source ranking | mcp_shared.py:138, web_researcher.py:889 |
| `require_api_key_for_mcp_tools` | bool | `true` | Gate MCP research tools on provider keys | api_key_store.py:179 |
| `allow_local_fetch` | bool | `false` | Permit localhost/private fetches | mcp_shared.py:139 |
| `ollama.api_key_env` / `max_results` / `use_web_search` / `use_web_fetch` | — | `OLLAMA_API_KEY` / `8` / `true` / `true` | Ollama research provider | mcp_shared.py:153-158, web_researcher.py:319-369 |
| `serpapi.api_key_env` / `endpoint` / `engine` / `region` | — | `SERPAPI_API_KEY` / serpapi.com / `duckduckgo` / `us-en` | SerpAPI provider | mcp_shared.py:159-164 |
| `assistant.*` | see research_assistant.py:97-140 | enabled, `automatic: true`, `failure_trigger: 2`, budgets | Read-only in-loop research assistant (advisory) | `tools/exploit_agent/research_assistant.py`, `tools/exploit_agent/runner/_impl.py` |

### `swarm:` (config.yaml:214-233) — multi-agent swarm

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Swarm mode | cli_exploit_settings.py:105, run_service/service.py:437 |
| `agents` | list[str] | recon/vuln/exploit/post_exploit/critic/reflection | Agent roster | swarm/orchestrator.py:564 |
| `max_parallel_agents` | int | `3` | Flow B parallel cap | `legacy/agent_loop.py` |
| `parallel_enabled` | bool | `false` | Gates `route_parallel` + `spawn_subagent` MCP tool; CLI `--parallel-swarm` flips it (main.py:365-370) | mcp_tools/parallel_agents.py:268, prompt.py:386-390 |
| `per_phase_concurrency` | int | `3` | Semaphore for same-phase parallel dispatch | prompt.py |
| `exploit_parallel` | bool | `false` | Parallelize exploit/post_exploit phases | swarm/orchestrator.py:60-73, prompt.py:387 |
| `subagent_timeout_seconds` | int | `600` | Ceiling for `await_subagent` | prompt.py:386 |
| `session_timeout_seconds` | float | — (300s default) | Plain-run swarm wall clock (schema-only override; long-session raises it via `long_session.swarm_session_timeout_minutes`) | cli_exploit_settings.py:33-49 |
| `critic_enabled` / `reflection_enabled` | bool | `true` | Agent enablement | cli_exploit_settings.py:106-107 |

### `autonomous:` (config.yaml:239-244) — orchestrator Phase 2 (opt-in)

Read by the orchestrator from mission_config (merged from `config["autonomous"]`).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `persistence_phase` | bool | `false` | Run PERSISTENCE phase after access | autonomous_orchestrator.py:1104 |
| `checkpoint_every` | int | `0` | Save `attack_states.json` every N targets (0=off) | autonomous_orchestrator.py:1105 |
| `adaptive_replan` | bool | `false` | Per-target replan + vuln-chaining | autonomous_orchestrator.py:1106 |
| `max_cycles` | int | `100` | Round cap when adaptive_replan is on | autonomous_orchestrator.py:1077 |
| `max_pivot_depth` | int | `0` | Single-IP lock default | autonomous_orchestrator.py:1091 |

### `orchestrator:` (config.yaml) — cross-mission learning consumer

Semantic-memory consumer for the autonomous orchestrator. When true, the orchestrator builds a `SemanticMemoryManager` (from the `memory` config block's `embed_host`/`embedding_model`) and calls `store_lesson` on every confirmed module win so the campaign learns across missions, not just within the exploit loop. Advisory-only — read-only memory store consumer, no execution authority change. Distinct `action_type='orchestrator:module_success'` isolates these rows from the exploit-loop and swarm-reflection lessons. Lab default ON (matches `memory.semantic_enabled: true` — the orchestrator is the missing consumer of an already-on capability, not a new attack-path opt-in).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `semantic_memory` | bool | `true` | Build a SemanticMemoryManager + store cross-mission lessons on confirmed wins | autonomous_orchestrator.py:1095-1116 |

### `fsm:` (config.yaml) — FSM / planner-executor split (opt-in, default off)

When `enabled`, campaign code may route plan execution through the FSM phase guard + memoryless step executor (`tools/attack_planner.py`: `planner_context` / `step_context_for` / `record_step_result` / `fsm_advance`, `AttackModuleExecutor.execute_plan_step`) instead of the LLM-does-everything loop. No command-content gates — only the target-IP allowlist at the MCP layer; recon stays `read_only`.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` | Route plan execution through the FSM guard + memoryless executors | attack_planner.py:482 (`fsm_settings`) |
| `max_retries_per_step` | int | `3` | Same-`failure_class` failures before the stuck-loop breaker blocks the step and forces a replan | attack_planner.py:438 (`record_step_result`) |

### `recon:` (config.yaml:251-274) — recon coverage & depth

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `extended_enumerators` | bool | `true` | TLS/SMTP/DB/spider/OSINT additive enumerators | recon_pipeline.py:294,1102 |
| `udp_top_ports` | int | `100` | `nmap -sU --top-ports N` | recon_pipeline.py:251,2246 |
| `shodan_api_key` | str | `""` | Passive OSINT key; `""` = disabled (falls back to `$SHODAN_API_KEY`) | recon_pipeline.py:287,1853 |
| `max_retries` | int | `2` | Nmap retry count on timeout/crash; set `0` to skip straight to native socket fallback (faster on Windows Npcap hangs) | recon_pipeline.py:234,589 |
| `retry_delay` | float | `5.0` | Initial retry delay (s); multiplied by 1.5 each retry | recon_pipeline.py:235,590 |
| `timeout_seconds` | int | `300` | Per-attempt nmap command timeout (s) | recon_pipeline.py:233,588 |
| `domain_resolution.enabled` | bool | `true` | Accept domain `--target`, resolve at boot | tools/validation_utils.resolve_target_to_ip, main.py target threading |
| `domain_resolution.max_subdomains` | int | `500` | Cap on `enumerate_subdomains` results | tools/mcp_tools/domain.py:361 (tool default) |
| `domain_resolution.subdomain_sources` | list | crt_sh/dns_bruteforce/subfinder/amass | Discovery sources | tools/mcp_tools/domain.py:360,393-448 |
| `domain_resolution.dns_zone_transfer` | bool | `false` | AXFR attempt opt-in | tools/mcp_tools/domain.py:587-588 |
| `domain_resolution.whois_enabled` | bool | `true` | `domain_whois` tool | tools/mcp_tools/domain.py |
| `subdomain_enum` / `vhost_discovery` / `waf_fingerprint` / `asn_whois` / `cloud_metadata_probe` / `snmp_enum` / `dns_zone_transfer` | bool | `false` | Extended depth enumerators (individually gated) | recon_pipeline.py:298-302,1158 |

### `opsec:` (config.yaml:283-300) — agent's own detection-evasion (opt-in, advisory)

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` | Master switch (opt-in) | opsec.py:92 |
| `ua_rotation` / `doh` | bool | `false` | UA rotation / DNS-over-HTTPS | opsec.py:93-94 |
| `doh_provider` | str | `cloudflare` | `cloudflare`\|`google` | opsec.py:95 |
| `min_gap_seconds` / `jitter_seconds` | float | `0.0` | Pacing base + jitter | opsec.py:96-97 |
| `rate_per_minute` | int | `0` | Token-bucket cap (0=unlimited) | opsec.py:98 |
| `quiet_command_patterns` | list[str] | `[]` | Substrings refused when enabled (advisory) | opsec.py:99 |
| `noise_budget` | int | `0` | Max noisy commands (0=unlimited; dormant, not a gate) | opsec.py:100, safety-model.md:181 |
| `local_targets_off` | bool | `true` | Local/private target → OPSEC forced OFF; public → ON | opsec.py:101,124-159 |
| `local_cidrs` | list[str] | `[]` | Extra CIDRs treated as local | opsec.py:102,150 |
| `public_autonomy` | bool | `true` | Public target → AI chooses its own attacks (documentary) | opsec.py:103 |

### `eval:` (config.yaml:305-310) — eval/benchmark harness

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Gates harness defaults (the `--eval` flag still works when false) | eval_harness.py:376 |
| `output_dir` | str | `reports/eval` | Where `reports/eval/<run_id>/` trees go | eval_harness.py:377 |
| `max_rounds` | int | `30` | `attack_max_rounds` for an eval run | eval_harness.py:378,421 |
| `write_markdown` / `write_html` | bool | `true` | Emit markdown/HTML reports | eval_harness.py:379-380 |
| `regression_tolerance` | float | `0.05` | Graded eval: a target regresses when `score < baseline_score - tolerance` | eval_harness.py `check_regression` |
| `baseline_path` | str | `reports/eval/baseline.json` | Graded eval: baseline file written by `--save-baseline` / read by `--check-regression` | eval_harness.py `save_baseline` / `check_regression` |

### `benchmark:` (top-level) — reproducible benchmark suite

See [docs/benchmarks.md](benchmarks.md). Defaults in `tools/config/schema.py`; validated in `tools/config/validator.py`.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Gates the benchmark CLI (`--benchmark*`) | tools/benchmark_cli.py |
| `output_dir` | str | `reports/benchmarks` | Where `reports/benchmarks/<suite>/<run_id>/` trees go | tools/benchmark/runner.py, storage.py |
| `trials` | int | `3` | Default repeated trials per scenario (1-20; CLI `--trials` overrides) | tools/benchmark_cli.py, service.py |
| `timeout_seconds` | int | `1800` | Per-trial mission timeout | tools/benchmark/runner.py |
| `sandbox_required` | bool | `true` | When true, runs without `sandbox.enabled` are `INFRASTRUCTURE_ERROR` (no host-execution fallback) | tools/benchmark/runner.py |
| `baseline_path` | str | `reports/benchmarks/baseline.json` | Baseline file written by `--save-baseline` / read by `--check-regression` | tools/benchmark/regression.py |
| `regression.success_rate_tolerance` | float | `0.02` | Verified-success-rate drop beyond this is a HARD regression (CI exit 1) | tools/benchmark/regression.py |
| `regression.false_positive_tolerance` | float | `0.01` | False-positive-rate rise beyond this is a HARD regression | tools/benchmark/regression.py |
| `regression.median_time_tolerance` | float | `0.20` | Relative median-solve-time rise beyond this is a warning | tools/benchmark/regression.py |
| `regression.tool_actions_tolerance` | float | `0.30` | Relative median-action rise beyond this is a warning | tools/benchmark/regression.py |
| `regression.cost_tolerance` | float | `0.30` | Relative estimated-cost rise beyond this is a warning | tools/benchmark/regression.py |
| `telemetry.events` / `token_usage` / `cost` | bool | `true` | Telemetry toggles (events JSONL, token accounting, cost) | tools/benchmark/agent_runner.py |

### `long_session:` (config.yaml:319-326) — multi-hour mode

Enabled by `--long-session` (main.py:374-376) or `enabled: true`.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` (config.yaml) / `false` (schema) | Master switch | cli_exploit_settings.py:43,75 |
| `request_timeout_seconds` | int | `600` | Per-LLM-call httpx timeout | run_service/service.py:337-341, model_router.py:313-316 |
| `swarm_session_timeout_minutes` | int | `30` | Raises the 300s swarm cap | cli_exploit_settings.py:42-49 |
| `attack_max_rounds` | int | `200` | Budget override | cli_exploit_settings.py:120 |
| `attack_max_commands` | int | `1000` | Budget override | cli_exploit_settings.py:119 |
| `attack_max_duration_minutes` | int | `720` | 12h wall clock | cli_exploit_settings.py:121 |
| `persist_messages` | bool | `true` | Checkpoint compacted messages to `session_state.json` for crash-safe resume | cli_exploit_settings.py:139, session_manager.py:71-99, exploit_agent/context.py:616-623 |

### `reasoning:` (config.yaml:327-345) — agent reasoning

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `chain_of_thought` | bool | `true` | CoT mode | cli_exploit_settings.py:89 |
| `reflection_every_n_actions` | int | `10` | Reflection cadence | cli_exploit_settings.py:93, `tools/exploit_agent/runner/_impl.py` (reflection cadence) |
| `critic_enabled` | bool | `true` | Critic agent (swarm) | cli_exploit_settings.py:106 |
| `observer_mode` | str | `hybrid` | `heuristic`\|`llm`\|`hybrid` fact extraction | cli_exploit_settings.py:98, main.py:641 |
| `ultrathink` | bool | `true` (config.yaml) / `false` (schema) | Deep-reasoning mode; CLI `--ultrathink` overrides | cli_exploit_settings.py:90 |
| `ultrathink_reflection_interval` | int | `3` | Ultrathink reflection cadence | cli_exploit_settings.py:92 |
| `llm_reflection` | bool | `true` (config.yaml) / `false` (schema) | LLM-driven reflection in the hot loop (extra LLM calls) | cli_exploit_settings.py:94, exploit_agent/reflection.py:135 |
| `peer_consult_on_failure_threshold` | int | `3` | Auto-consult peers after N consecutive exploit failures (0 disables) | cli_exploit_settings.py:97, `tools/exploit_agent/runner/_impl.py` |

### `memory:` (config.yaml:346-352) — learning stores

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `semantic_enabled` | bool | `true` | Semantic memory / embeddings | agent_loop.py (legacy), `tools/skill_embeddings.py`, `tools/exploit_agent/runner/_impl.py` (semantic memory wiring) |
| `embedding_model` | str | `nomic-embed-text` | Embedding model | skill_embeddings.py:174, semantic_memory.py:29 |
| `cross_mission_learning` | bool | `true` | Learn across missions | eval_benchmark.py:176 |
| `attack_memory_enabled` | bool | `true` | AttackMemoryStore in the exploit loop | `tools/exploit_agent/runner/_impl.py` (`_load_attack_memory_settings` + store wiring) |
| `attack_memory_max_context_chars` | int | `6000` | Attack-memory advisory size | `tools/exploit_agent/runner/_impl.py`, `tools/exploit_agent/context.py` |
| `experience_min_samples` | int | `3` | ExperienceStore soundness gate | agent_loop.py (legacy), `tools/exploit_agent/runner/_impl.py`, `tools/skill_feedback.py` |
| `experience_time_decay_days` | float | `90` | Experience decay (≤0 disables) | agent_loop.py:193, skill_feedback.py:128 |

### `outcome_judgment:` (config.yaml:354-365) — evidence-grounded verdicts

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `max_inconclusive_attempts` | int | `3` | ≥2 prevents one failed command exhausting a hypothesis | `tools/config/validator.py` (validation) |
| `confirmation_threshold` / `refutation_threshold` | float | `0.75` | Evidence thresholds (0.5-1.0) | `tools/config/validator.py` |
| `min_evidence_references` | int | `1` | Min evidence refs for a verdict | `tools/config/validator.py` |
| `flow_a` | bool | `true` (config.yaml) / `false` (schema) | Wire OutcomeJudge into Flow A exploit loop (overrides shallow exit-code success) | cli_exploit_settings.py:154, eval_benchmark.py:231 |
| `peer_review` | bool | `true` (config.yaml lab) / `false` (schema) | D3: cross-model outcome grading (`peer_review_outcome` MCP tool — one alias plans, a different alias grades evidence; advisory-only, deterministic judge stays authority) | mcp_tools/peer_models.py:162 |

### `poc_verification:` (config.yaml:264-271) — self-healing PoC verification (Killer Feature #3)

When `enabled`, `cve_to_exploit_synth` syntax-checks its synthesized PoC inline
(`py_compile`, no exec) and the `verify_poc` MCP tool compile-tests the PoC
inside a fully-isolated Docker container. The PoC is NEVER executed on the
operator box — this is a compile/import gate, not a sandbox guarantee.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` (config.yaml lab) / `false` (schema) | Master toggle (inline synth check + Docker compile path) | mcp_tools/attack_modules.py (cve_to_exploit_synth), mcp_tools/poc_verifier.py |
| `docker_image` | str | `python:3.11-slim` | Image for the compile/import container | tools/poc_verifier.py:docker_check |
| `compile_timeout_seconds` | int | `30` | Container run timeout | tools/poc_verifier.py:docker_check |
| `max_retries` | int | `3` | Self-heal loop cap (synth → verify → LLM fix → re-verify) | mcp_tools/attack_modules.py (agent-driven) |
| `docker_network` | str | `none` | Container network mode (always `none` — PoC must never reach target/network) | tools/poc_verifier.py:docker_check |
| `docker_read_only` | bool | `true` | Mount container filesystem read-only | tools/poc_verifier.py:docker_check |
| `docker_memory` | str | `256m` | Container memory cap | tools/poc_verifier.py:docker_check |

### `replay_simulator:` (config.yaml:273) — pre-commit attack-plan critique (D2)

When `enabled`, registers the `replay_simulate` MCP tool — a local-only
`@audit_tool` (no target touch) that dry-runs an attack plan against a saved
`ReconAssessment` JSON. The LLM critiques its own plan (confidence, branches);
if the LLM is unavailable, degrades to rule-based scoring. Zero target touch.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` (lab config.yaml) / `false` (schema) | Registers the `replay_simulate` MCP tool | mcp_tools/replay_simulator.py |
| `counterfactual` | bool | `false` | Exploit-loop counterfactual replay: after a failed exploit action that had a snapshot taken, the loop reverts the snapshot and retries the mutated payload against the clean state, recording both outcomes in `final_result["counterfactual"]`. Requires `snapshots.enabled` for effect | exploit_agent/runner/_impl.py (`_counterfactual_enabled`) |

### `killchain:` (top-level) — kill-chain state machine (opt-in, default OFF)

When `enabled`, registers the kill-chain MCP tool family
(`tools/mcp_tools/killchain.py`) and builds a per-target
`tools/killchain/machine.py::KillChainMachine` inside the exploit loop. The
machine tracks stage progression (recon → initial_access → escalation →
objective), refuses out-of-order transitions when `require_verification` is
true (a stage advance needs an evidence-verified exploit outcome, never an
agent claim), and renders a `KILLCHAIN BRIEFING` block into the agent system
prompt. The campaign orchestrator prefers kill-chain state for phase selection
when enabled. Every transition is recorded on the audit trail.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|---------|-------------|
| `enabled` | bool | `false` | Registers the `killchain_*` MCP tools + loop wiring | mcp_tools/killchain.py, exploit_agent/runner/_impl.py (`_build_killchain_machine`) |
| `goal_state` | str | `shell_as_root` | Objective stage the machine drives toward | killchain/machine.py |
| `require_verification` | bool | `true` | Reporting verbosity only — stage-advance verification is always enforced | killchain/machine.py |
| `graph_db` | str | `""` | Kill-chain graph store path; `""` = `<workspace>/killchain_graph.db` | killchain/ |

### `snapshots:` (top-level) — snapshot + rollback (opt-in, default OFF)

Snapshot-before-destructive infrastructure for the lab build. A pluggable
provider layer (`tools/snapshots.py`: Docker commit/rollback is the mandatory,
fully-implemented path; Proxmox / libvirt / Hyper-V / VMware are best-effort
wrappers). Wired into all three dispatch funnels — the exploit loop
(`tools/exploit_agent/runner/_impl.py`), the swarm bridge
(`tools/swarm_bridge.py`), and the campaign executor
(`tools/campaign/executor.py`) — plus three MCP tools. Every consumer is
**fail-open**: a snapshot failure logs a warning and never blocks the attack
path. The `vm_id`/container must be operator-authorized (the MCP tools are
`@require_allowlist("vm_id")`-gated; the allowlist IS the lock).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` | Master gate; when false no snapshot is taken and no `snapshot_*` tool registers | snapshots.py `should_snapshot`, mcp_tools/snapshots.py |
| `provider` | str | `docker` | Active provider (`docker` \| `proxmox` \| `libvirt` \| `hyperv` \| `vmware`) | snapshots.py `get_provider` |
| `auto_before_destructive` | bool | `true` | Snapshot automatically before destructive payloads / exploit-execution-category tools | snapshots.py `should_snapshot` |
| `max_snapshots_per_target` | int | `3` | Rolling cap; oldest snapshot deleted when exceeded | snapshots.py `_enforce_cap` |
| `vm_map` | map | `{}` | target IP → vm_id/container name (env override `SNAPSHOT_VM_MAP`); unmapped targets are used raw | snapshots.py `_vm_id_for_target` |
| `providers.docker.compose_file` | str | `eval_targets/docker-compose.yml` | Documented compose file backing container targets | snapshots.py DockerProvider |
| `providers.hyperv.powershell_command` | str | `powershell` | PowerShell executable for Checkpoint-VM / Restore-VMCheckpoint | snapshots.py HyperVProvider |
| `providers.vmware.vmrun_path` | str | `vmrun` | vmrun binary path | snapshots.py VMwareProvider |
| `providers.proxmox.host` / `.node` | str | `""` | Proxmox API endpoint + node (auth via `PROXMOX_API_TOKEN` env only — never config, never logged) | snapshots.py ProxmoxProvider |
| `providers.libvirt.virsh_path` | str | `virsh` | virsh binary path | snapshots.py LibvirtProvider |

### `adaptive_exploits:` (config.yaml:366-373) — exploit mutation

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Mutation engine | cli_exploit_settings.py:99, mcp_tools/attack_modules.py:1325,1420 |
| `max_mutations` | int | `5` | Mutation cap | cli_exploit_settings.py:100 |
| `mutation_strategies` | list[str] | parameter_tweak/encoding_change/delivery_swap/context_aware | Strategy roster | cli_exploit_settings.py:101-104 |

### `multi_model:` (config.yaml:374-384) — peer-model consultation (advisory)

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` (config.yaml) / `false` (schema) | Exposes `consult_peer_models`; CLI `--multi-model-consult`/`--no-multi-model-consult` override | main.py:607-609, tools/mcp_tools/registry.py:223 |
| `consult_aliases` | list[str] | all five aliases | Peer roster (intersected with registered models) | cli_exploit_settings.py:109, tools/mcp_tools/registry.py:190-201 |
| `max_consultations` | int | `10` | Shared per-run budget (single counter) | exploit_agent/reflection.py:325, peer_models.py:55 |
| `max_question_chars` / `max_answer_chars` | int | `4000` / `8000` | Truncation bounds | reflection.py:326-327, peer_models.py:56-57 |

### `skills:` (config.yaml:385-422) — runtime skill pipeline

Advisory prompt context only — never permission/scope/audit (docs/skills.md:162-168).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master toggle | skill_pipeline.py:63,196, exploit_agent/skills.py:65 |
| `roots` | list[str] | `["skills"]` | Skill directories | mcp_engine_server.py:70, skill_registry_cache.py:27 |
| `default_enabled` | list[str] | 6 skills (nmap, pentest, red-team, mcp-audit, agentic-ai, domains) | Always-active skills | skill_selector.py:164,321 |
| `include_tags` / `exclude_names` | list[str] | `[]` | Tag include / name exclude filters | skill_selector.py |
| `maybe_enabled` | bool | `false` | Include `skills/maybe/` skills | skill_selector.py:130 |
| `allow_model_lookup` | bool | `true` | Enable read-only skill MCP tools | tools/mcp_tools/registry.py:266 |
| `inject_startup_context` | bool | `false` | Eager body injection into initial prompt | skill_pipeline.py (CLI `--skills on` sets it: skills_cli.py:37-39) |
| `max_active_skills` / `min_contextual_skills` | int | `6` / `3` | Selection bounds | skill_selector.py:124 |
| `max_chars_per_skill` / `max_total_chars` | int | `2500` / `9000` | Prompt budget caps | skill_pipeline.py |
| `default_skill_weight` / `context_skill_weight` | int | `12` / `24` | Score weights | skill_selector.py |
| `reselect_mid_run` / `reselect_max_per_run` / `reselect_min_interval_actions` / `reselect_sticky_defaults` | — | `true` / `3` / `5` / `true` | Mid-run re-selection; `--no-skills-reselect` disables | skill_selector.py, exploit_agent/skills.py:44 |
| `swarm_inject` / `swarm_phase_hints_only` | bool | `true` | Swarm skill sharing (hints only for non-exploit agents) | skill_pipeline.py:198 |
| `feedback_enabled` / `feedback_skill_weight` / `feedback_min_observations` | — | `true` / `8` / `3` | Cross-mission feedback boost | skill_selector.py:300, skill_feedback.py |
| `semantic_matching` / `semantic_skill_weight` / `semantic_min_similarity` / `semantic_model` | — | `true` / `16` / `0.35` / `nomic-embed-text` | Embedding-based ranking | skill_selector.py:265 |
| `diversity_penalty` | int | `12` | Penalize tag-overlapping skills | skill_selector.py:316 |
| `include_metadata` | bool | `false` | Append references in rendered context | skills.md:127 |
| `allow_reference_listing` | bool | `true` | `list_skill_references` MCP tool | skills.md:153 |

### `plugins:` (schema default `[]`; the lab `config.yaml` enables 13 shipped plugins)

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | list[str] | `[]` | Explicitly loaded plugins (schema default OFF — trusted Python, full operator-box privileges; the lab `config.yaml` lists 13, each no-op until its own API key/URL is configured) | tools/plugins.py |
| `disabled` | list[str] | `[]` | Hard-blocked regardless of manifest | tools/plugins.py |
| `search_paths` | list[str] | `["plugins"]` | Filesystem dirs scanned for `plugin.yaml` | tools/plugins.py |
| `entry_points` | bool | `true` | `breachpilot.plugins` entry-point discovery | tools/plugins.py |

### `threat_intel:` (config.yaml:126-137) — threat-feed ingestion (OSV.dev + GHSA + KEV)

Advisory-only, never touches the target. Lab build ON so the feed is live out-of-the-box. Reuses `cve_lookup` KEV catalog (shared disk cache). GHSA needs `GITHUB_TOKEN` (shared with `cve_lookup.github.token_env`); when absent, GHSA is silently dropped and `osv`+`kev` still answer.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Threat-feed master switch | tools/threat_intel.py:45, mcp_tools/research.py:210 |
| `cache_dir` | str | `exploit_workspace/.threat_intel` | Feed cache directory | tools/threat_intel.py:50 |
| `cache_ttl_seconds` | int | `86400` | Cache TTL | tools/threat_intel.py:52 |
| `sources.osv` / `ghsa` / `kev` / `exploitdb_rss` | bool | `true`/`true`/`true`/`false` | Source toggles | tools/threat_intel.py:55-60 |
| `max_results` | int | `20` | Results per query | tools/threat_intel.py:62 |
| `github_token_env` | str | `GITHUB_TOKEN` | GHSA token env | tools/threat_intel.py:65, api_key_store.py:53 |
| `timeout_seconds` | int | `30` | HTTP timeout | tools/threat_intel.py:66 |

### `witness:` (config.yaml:187-194) — advisory audit-stream watcher (agent-on-agent safety)

Library default OFF (conservative for downstream re-use); the checked-in `config.yaml` flips it ON
for the lab runtime. **Wiring:** when `enabled` is true, the transport-neutral run lifecycle
(`tools/run_service/execute.py`, serving BOTH the CLI and API transports) spawns a per-run
`WitnessAgent` side task that polls the run's audit trails (`reports/<run_id>/activity.jsonl`,
plus the per-attempt `exploit_audit.jsonl` registered from the session result at teardown) and
flags anomalies (allowlist breach, PoC escape, permission escalation, prompt-injection pattern,
DoS drift) to `log_path` (process-global) and, when `escalate_to_event_broker` is true, as
`witness_flag` events through the transport's event sink (WS/SSE). **Detection/auditing only —
it never blocks, modifies, or kills a run, and its failure never propagates into the run's
result path.** The WebUI reads the log via `GET /api/v1/runs/{run_id}/witness`
(`tools/api/routes/runs.py`), which 404s when the log file does not exist.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `false` (schema) / `true` (config.yaml lab) | Master switch — gates the per-run witness side task | `tools/run_service/execute.py` (`_start_witness`), `tools/swarm/agents/witness_agent.py` |
| `log_path` | str | `reports/witness.jsonl` | Witness log (process-global, not per-run) | witness_agent.py; `tools/api/routes/runs.py` (`GET /runs/{id}/witness`) |
| `poll_interval_seconds` | int | `5` | Poll interval | witness_agent.py; execute.py poll task |
| `escalate_to_event_broker` | bool | `true` | Emit `witness_flag` events through the event sink | witness_agent.py; execute.py |
| `max_flags_per_signal_per_minute` | int | `10` | Per-signal rate cap | witness_agent.py |
| `dos_failure_window_seconds` | float | `60.0` | DoS drift window | witness_agent.py |
| `dos_failure_threshold` | int | `8` | DoS drift threshold | witness_agent.py |

### `ics:` (config.yaml:416-418) — D8 ICS write-side modules

`ModbusWriteCoil`/`ModbusWriteRegister`/`S7PlcStop`/`S7PlcStart` are DESTRUCTIVE — they change physical process state. Dual-gated: `@require_allowlist` on `run_attack_module` AND `ics.allow_write: true` AND `ics.destructive_ics: true` (both must be true). Default `false` so checked-in config is safe; set true only for authorized PLC testing. PHYSICAL-DAMAGE RISK.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `allow_write` | bool | `false` | ICS write gate (read-only enum when false) | tools/attack_modules/modules/ics_iot.py |
| `destructive_ics` | bool | `false` | Second physical-damage gate (both must be true) | tools/attack_modules/modules/ics_iot.py:42 |

### `webhook_notify:` (config.yaml:438-449) — outbound Slack/Discord run-status notifications

Lab build `enabled: true`. No-op without a `url` — logs once then drops events. Set `url` to a Slack/Discord incoming webhook to actually receive pings.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch | tools/plugins/webhook_notify.py, `tools/config/schema.py` |
| `url` | str | `""` | Webhook URL (secret, never logged) | webhook_notify.py:35 |
| `events` | list[str] | `["finding","state"]` | Event-type filter | webhook_notify.py:36 |
| `timeout_seconds` | int | `5` | HTTP timeout | webhook_notify.py:37 |
| `max_retries` | int | `3` | Retry count | webhook_notify.py:38 |
| `backoff_seconds` | float | `2.0` | Backoff | webhook_notify.py:39 |
| `max_payload_chars` | int | `8192` | Payload cap | webhook_notify.py:40 |

### `mitre:` (config.yaml:450-456) — MITRE ATT&CK Navigator export

Lab build `enabled: true`. `export_attack_navigator` MCP tool writes Navigator layer JSON to `navigator_output_dir` for SOC handoff.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch | `tools/mitre_export.py`, `tools/config/schema.py` |
| `technique_map` | str | `tools/mitre_technique_map.json` | ATT&CK technique map | mitre_export.py:31 |
| `navigator_output_dir` | str | `reports/mitre` | Output dir | mitre_export.py:32 |
| `include_skill_tags` | bool | `true` | Include skill tags | mitre_export.py:33 |

### `ticketing:` (config.yaml:457-467) — remediation ticket generation (Jira/GitHub)

Lab build `enabled: true`. No-op without `provider`/`base_url`/`token` — logs once then drops. Set `provider` (`jira`|`github`), `base_url`, and the named `token_env` env var to actually create tickets.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch | `tools/ticketing.py`, `tools/config/schema.py` |
| `provider` | str | `""` | `jira` \| `github` | ticketing.py:31 |
| `base_url` | str | `""` | Ticketing base URL | ticketing.py:32 |
| `token_env` | str | `TICKETING_TOKEN` | Token env var | ticketing.py:33, api_key_store.py |
| `project_key` | str | `""` | Project key | ticketing.py:34 |
| `max_retries` | int | `3` | Retry count | ticketing.py:35 |
| `backoff_seconds` | float | `2.0` | Backoff | ticketing.py:36 |

### `caldera:` (config.yaml:476-480) — D6 Caldera adversary emulation plugin

Lab build `enabled: true`. The Caldera server is target-side — operator adds its IP to `exploit.allowed_targets`. Plugin MCP tools (`caldera_list_abilities`, `caldera_run_ability`) are `@require_allowlist`-gated on the target IP.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch | `plugins/caldera/plugin.py`, `tools/config/schema.py` |
| `url` | str | `""` | Caldera server base URL | caldera/plugin.py:41 |
| `api_key_env` | str | `CALDERA_API_KEY` | Caldera API key env | caldera/plugin.py:42 |

### `agent:` (config.yaml:486-494) — capability-upgrade agent block (design §23)

Toggles + budgets for the task graph, capability discovery, AI-facing state tools, planner hints, decision logging, reflection, and retry/repair budgets. Defaults preserve today's behavior. `config_cli.load_config` merges NO defaults, so every consumer reads defensively via `cfg.get("agent", {}).get(key, default)`.

**Wiring status:** every key below has a live runtime consumer (regression-tested in
`tests/test_agent_config_wiring.py`). All consumers read defensively — an absent `agent`
block or key preserves the historical default behavior. `reflection` in the loop is also
gated by `reasoning.llm_reflection` / `reasoning.reflection_every_n_actions`; swarm
reflection by `swarm.reflection_enabled`.

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `task_graph_enabled` | bool | `true` | When false, the plan-mutating `update_task` MCP tool is not registered (read-only state tools remain) | `tools/mcp_tools/assessment_state.py` |
| `capability_discovery_enabled` | bool | `true` | Gate the capability-discovery prompt block + the `query_capabilities`/`get_capability_details` MCP tools | `tools/exploit_agent/runner/_impl.py`, `tools/exploit_agent/prompt.py`, `tools/mcp_tools/assessment_state.py` |
| `state_tools_enabled` | bool | `true` | When false, the whole assessment-state MCP tool family is unregistered and its prompt section dropped | `tools/mcp_tools/assessment_state.py`, `tools/exploit_agent/prompt.py` |
| `planner_hints_enabled` | bool | `true` | When false, the hypothesis-workflow advisory bullets are dropped from the capability-guidance prompt block | `tools/exploit_agent/prompt.py:build_capability_guidance` |
| `decision_log_enabled` | bool | `true` | When false, the §17 decision-log hook writes nothing to `decision_log.jsonl` | `tools/exploit_agent/runner/_impl.py` |
| `reflection_enabled` | bool | `true` | When false, inline reflection rounds in the exploit loop are skipped | `tools/exploit_agent/runner/_impl.py` |
| `max_retries_per_task` | int | `2` | Per-module failure cap for autonomous campaigns (drop a module from the retry set after N failures); absent key falls back to the campaign class default of 3 | `tools/campaign/orchestrator.py` |
| `max_actions` | int | `0` | Hard cap on agent actions per run; `0` = sentinel (legacy `attack_max_commands` / `max_commands_per_session` budgets apply) | `tools/cli_exploit_settings.py` → `ExploitSettings.effective_max_commands` |
| `generated_code_repair_attempts` | int | `3` | Default for `poc_verification.max_retries` (explicit `poc_verification.max_retries` still wins) | `tools/poc_verifier.py:poc_verification_config` |

### `api:` (config.yaml:386-407) — WebUI daemon (`--demon` / `--daemon` / `--web`)

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Daemon enablement | `app.create_app` |
| `host` | str | `127.0.0.1` | **Loopback-only in v1; any other value is a validation ERROR**; CLI `--api-host` overrides | `main._run_daemon`, `tools/config/validator.py` |
| `port` | int | `8765` | Daemon port; CLI `--api-port` overrides | `main._run_daemon` |
| `token_file` | str | `.webui_secret_key` | Auto-generated bearer token file (gitignored); `BREACHPILOT_API_TOKEN` env overrides | app.py:70, tools/api/auth.py:42-46 |
| `allowed_origins` | list[str] | `[]` | Extra loopback origins for CORS/WS; `null` and non-loopback always rejected | app.py:108 |
| `event_buffer_size` | int | `256` | In-memory ring buffer per run for WS subscribers | app.py:81 |
| `shutdown_timeout_seconds` | int | `15` | Graceful shutdown wait | tools/api/run_manager.py:320 |
| `serve_webui` | bool | `false` | Mount `webui/dist/` at `/`; `--web` sets this **in memory only** | app.py:145, main.py:542 |
| `max_concurrent_runs` | int | `3` | D3: N concurrent runs (1 = legacy 409) | `tools/api/run_manager.py`, `tools/config/schema.py` |
| `multi_operator` | bool | `true` | D4: user accounts + annotations (loopback-only) | tools/api/auth.py:60 |
| `graph_route` | bool | `true` | Attack-path DAG API route | tools/api/routes/graph_explorer.py:30 |

### `operator_connection:` (config.yaml:514-521) — persistent RCE beacons / operator callbacks

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch for beacon/listener management | `tools/operator_connection/manager.py`, `tools/mcp_tools/operator_connection.py` |
| `auto_start_listener` | bool | `true` | Auto-start callback listener | operator_connection/manager.py |
| `default_callback_port` | int | `4444` | Default callback port | operator_connection/manager.py |
| `default_listener_type` | str | `netcat` | Default listener type | operator_connection/manager.py |
| `beacon_interval_seconds` | int | `300` | Beacon callback interval | operator_connection/manager.py |
| `health_check_interval_seconds` | int | `60` | Beacon health-check interval | operator_connection/manager.py |
| `workspace_dir` | str | `exploit_workspace` | Callback workspace root | operator_connection/manager.py |

### `sandbox:` (config.yaml:541-566) — disposable execution sandbox (isolation boundary)

Every attack command (terminal commands, generated Python, nmap, Metasploit,
etc.) runs inside a hardened per-run Docker worker. Any sandbox failure blocks
offensive execution with a structured `SANDBOX_*` error — host execution is
never an automatic fallback. Full architecture + threat model:
[docs/sandbox.md](sandbox.md).

| Key | Type | Default | Controls | Consumed at |
|-----|------|---------|----------|-------------|
| `enabled` | bool | `true` | Master switch; `false` = explicit legacy host-execution opt-out (uncontained) | `tools/sandbox/manager.py:resolve_manager` |
| `backend` | str | `docker` | Execution backend | `tools/sandbox/models.py` |
| `image` | str | `breachpilot-sandbox:latest` | Worker image (build: `docker build -t <image> docker/sandbox`) | `tools/sandbox/docker_backend.py` |
| `fallback_native` | bool | `true` | Boot-time degrade: unusable Docker (CLI missing, daemon down, image not built) degrades the whole session to legacy uncontained native mode with warning + WebUI banner + `SANDBOX_FALLBACK:` lines; `false` = strict fail-closed (executions denied until Docker works) | `tools/sandbox/manager.py:resolve_manager_with_fallback`, docs/sandbox.md |
| `user` | str | `sandbox` | Container user (non-root default) | `tools/sandbox/docker_backend.py:_build_create_args` |
| `read_only_rootfs` | bool | `true` | Read-only container rootfs; `/workspace` + tmpfs stay writable | `_build_create_args` |
| `env_passthrough` | list[str] | `[]` | Extra host env var names the worker may receive (allowlist; never the whole env) | `tools/sandbox/manager.py:_build_env` |
| `resources.memory_mb` | int | `4096` | Container memory cap (min 256) | `_build_create_args` |
| `resources.cpus` | float | `2` | CPU cap (min 0.1) | `_build_create_args` |
| `resources.pids` | int | `512` | Process-count cap (min 32) | `_build_create_args` |
| `resources.timeout_seconds` | int | `300` | Per-command default timeout | `tools/sandbox/manager.py:execute` |
| `resources.output_max_bytes` | int | `2000000` | Per-stream output clamp (min 1024) | `tools/sandbox/manager.py:_clamp_output` |
| `network.enforce` | bool | `true` | Install the netns firewall; `false` = Docker bridge isolation only (NOT containment) | `tools/sandbox/manager.py:_apply_policy` |
| `network.fail_closed` | bool | `true` | Policy failures block execution | `tools/sandbox/*` |
| `network.allow_dns` | str | `controlled` | `controlled` (host-side validated resolution) or `none` (port 53 blocked everywhere) | `tools/sandbox/policy.py`, `network.py` |
| `network.map_host_loopback` | bool | `false` | Dev-only mapping of sandbox loopback targets to the host gateway; never enable for production runs | `tools/sandbox/policy.py` |
| `network.extra_allow_cidrs` | list[str] | `[]` | Operator-authorized extra CIDRs | `tools/sandbox/policy.py` |
| `network.allow_gateway` | bool | `false` | Authorize the Docker bridge gateway (path to host services + Docker daemon) — keep false | `tools/sandbox/network.py` |
| `network.allow_research_hosts` | bool | `true` | Pinned exploit-research egress (github.com et al., host-resolved + audited) | `tools/sandbox/policy.py` |
| `cleanup.remove_on_exit` | bool | `true` | Destroy worker + network after the run | `tools/sandbox/manager.py:destroy` |
| `cleanup.remove_stale_on_startup` | bool | `true` | Sweep exited labeled containers / empty networks at startup (running concurrent-session workers kept) | `tools/sandbox/manager.py:cleanup_stale` |
| `multi_net_raw` | bool | `true` | Grant NET_RAW for raw-packet scanning (nmap -sS); NET_ADMIN is never granted to the worker | `tools/sandbox/manager.py:resolve_manager` |

### `browser:` (top-level) — browser-native web agent (Playwright, default OFF)

Sandboxed Chromium agent behind the prepared seam. `tools/browser/` holds the
`BrowserBackend` ABC, the Playwright adapter (`playwright_backend.py`), the
sandbox launcher (one Chromium op per docker exec, no host fallback), and the
fail-closed `BrowserManager`. Capabilities report available only when enabled +
registered + runnable (host SDK or sandbox worker). Full design:
[docs/browser-agent-design.md](browser-agent-design.md).

| Key | Type | Default | Controls |
|-----|------|---------|----------|
| `enabled` | bool | `false` | Master switch; stock installs never enable |
| `backend` | str | `none` | `none` or `playwright` (requires a `BACKEND_REGISTRY` entry — declared ≠ available) |
| `headless` | bool | `true` | Sessions run headless (headed refused in the sandbox worker) |
| `max_sessions` | int | `2` | Concurrent session cap (manager-enforced) |
| `session_timeout_seconds` | int | `300` | Session idle budget (reaper closes idle sessions) |
| `navigation_timeout_seconds` | int | `30` | Per-navigation budget |
| `capture_screenshots` | bool | `true` | Persist screenshots as hashed artifacts |
| `capture_network` | bool | `true` | Capture request/response records (redacted at serialization) |
| `capture_console` | bool | `false` | Console capture (opt-in) |
| `persist_storage` | bool | `false` | Storage harvest goes to the credential store, never plaintext logs |
| `allow_mutating_actions` | bool | `false` | Lab opt-in for `browser_execute_js` (read-only otherwise) |
| `console_max_events` | int | `200` | Console ring-buffer cap per session |
| `network_max_events` | int | `500` | Converted network-event history cap per session |
| `body_sample_max_bytes` | int | `4096` | Truncated body sample cap per event |
| `dom_summary_max_chars` | int | `8000` | DOM text summary cap (huge pages truncate) |
| `artifact_dir` | str | `""` | Screenshot dir override (`""` = `<workspace>/browser/<session>/`) |
| `executable_path` | str | `""` | Explicit Chromium binary (`""` = Playwright default) |
| `worker_image` | str | `""` | Browser worker image override (`""` = `breachpilot-sandbox:browser`) |


## Other consumed keys

- `reports_dir` (not in schema): `Path(config.get("reports_dir", "reports"))` — app.py:76; also `mcp_engine_server.py:74` defaults to `reports`.

## `models.roles` — model-role routing (design §23)

Nested under the existing `models` key in `CONFIG_SCHEMA` (`tools/config/schema.py`, `"models"["roles"]`). Mirrored into `config.yaml` under `models.roles`. Validation: `ConfigValidator.validate` warns when a value is not a string or when a non-empty alias is not in `models.registry` (warn-not-reject).

Each role maps to a model alias; **an empty string means "use `models.default_alias`"** so first-run behavior is unchanged. Consumed by `tools/model_router.py::ModelRouter.get_client_for_role`, which falls back to `models.default_alias` when the role's alias is empty.

Live call sites (regression-tested in `tests/test_agent_config_wiring.py`):

- **`critic`** — swarm critic pre-check: `tools/swarm/orchestrator.py::_ensure_role_clients` stashes `critic_model_client` into the shared context (resolved once, lazily, best-effort) and `tools/swarm/agents/critic_agent.py` prefers it over the shared client for its LLM calls.
- **`critic`** — exploit-loop inline reflection: `tools/exploit_agent/runner/_impl.py` routes `_llm_reflect_inline` through `get_client_for_role("critic", ...)` when a role router is resolvable (falls back to the run's default model).

| Role | Default | Purpose |
|------|---------|---------|
| `planner` | `""` | Task-graph / attack-plan generation. |
| `executor` | `""` | Tool-call driving / terminal + MSF execution. |
| `interpreter` | `""` | Recon / output parsing / evidence interpretation. |
| `code_generator` | `""` | PoC synthesis + repair. |
| `critic` | `""` | Pre-action risk critique. |
| `summarizer` | `""` | Run reporting / outcome summarization. |

Precedents for per-role model overrides: `research.assistant.model_alias`, `multi_model.consult_aliases`. Keep `models.registry` / `models.info` synchronized (context-window metadata feeds `tools/exploit_agent` adaptive context handling).

## CLI vs config precedence

Explicit CLI flags win over config values; config wins over schema defaults:

| Config key | CLI override |
|------------|--------------|
| `models.default_alias` | `--model <alias>` |
| `long_session.enabled` | `--long-session` (cli_exploit_settings.py:43,75) |
| `swarm.parallel_enabled` | `--parallel-swarm` |
| `multi_model.enabled` | `--multi-model-consult` / `--no-multi-model-consult` |
| `exploit.attack_max_commands/rounds` | `agent.max_actions` (`0` = sentinel → legacy budgets apply) + `--long-session` raises budgets (cli_exploit_settings.py, `ExploitSettings.effective_max_commands`) |
| `skills.*` | `--skills on\|off\|hints\|lookup`, `--skills-include`, `--skills-exclude`, `--no-skills-reselect` (tools/skills_cli.py) |
| `api.host` / `api.port` | `--api-host` / `--api-port` |
| `mcp.default_transport` | `--mcp-transport` (ignored on the run path — always `http`) |
| `api.serve_webui` | `--web` (in-memory only, never persisted) |
| `reasoning.ultrathink` | `--ultrathink` |
