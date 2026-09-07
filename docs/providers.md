# Model Providers

How the engine talks to LLM backends. Since the pluggable-provider refactor,
**Ollama is one optional provider, not the internal protocol**: chat/generate
goes through a provider registry (`tools/providers/`), and every
backend-specific behavior (SDK import, auth, host handling, model discovery,
response normalization) lives inside its adapter. Generic engine code sees
only the canonical `ModelClient` contract.

Read alongside [provider-development.md](provider-development.md) for the
add-a-provider recipe (canonical, most current), [config-reference.md](config-reference.md)
for the config keys, and [deployment.md](deployment.md) for cloud-vs-local setup.

## Architecture overview

```
config.yaml (models.provider, providers.<id>, legacy blocks)
    │
    ▼
tools/providers/registry.py      ← get_provider(id) / get_provider_from_config(config)
    │   lazy-registered adapters: ollama | opencode_go | chatgpt
    │   one normalization layer: providers.<id> block > legacy top-level block
    │
    ▼
adapter (BaseProvider subclass)  ← ALL backend behavior lives here
    │   build_router / build_client / list_models / title_model / health
    │
    ▼
tools/model_router.py            ← ModelClient factory (telemetry + canonical args)
    │   provider-neutral: consumers receive ModelClient, call .chat()/.stream()
    │
    ▼
consumers (exploit loop, swarm, payload crafter, titler, eval, WebUI routes)
```

Three distinct provider surfaces:

| Surface | Abstraction | Providers today |
|---|---|---|
| Chat/generate | `tools/providers/` registry → `ModelClient` | `ollama` (default), `opencode_go`, `chatgpt` |
| Embeddings | `tools/providers/embeddings.py` → `EmbeddingProvider` | `ollama` (default), `none` |
| Research (web search/fetch) | `tools/web_researcher.py` → `ResearchProvider` | `ollama`, `serpapi` |

**Ollama is optional.** A zero-Ollama install (no `ollama` Python package, no
Ollama endpoints/traffic) runs the engine on another provider:

```yaml
models:
  provider: opencode_go
providers:
  opencode_go:
    base_url: https://opencode.ai/zen/go/v1
    api_key_env: OPENCODE_GO_API_KEY
    default_model: muse-spark-1.2-contributor
    request_timeout_seconds: 300
embeddings:
  provider: none
```

The `ollama` pip dependency is an extra (`pip install -e ".[ollama]"`; the
dev extra includes it). Selecting Ollama without the package raises an
actionable `ProviderMissingDependencyError`; `tests/test_no_ollama_regression.py`
enforces the guarantee, and `docs/provider-development.md` shows how provider
#4 plugs in with ZERO engine edits.

## Chat/generate path

### The interface

`tools.providers.types.ModelClient` (canonical definition; re-exported by
`tools/model_router.py`) is the provider interface — a thin dataclass holding
the chat/stream callables, the model id, and the provider id used for
telemetry attribution. Every non-stream `.chat()` returns the **BreachPilot
model response format** (the formalized "Ollama-shaped dict"): `model`,
`message.{role, content, thinking, tool_calls}`, optional normalized `usage`.
Providers translate between this format and their external API — no provider
is required to emulate Ollama; Ollama is just one adapter.

`ModelRouter` (`tools/model_router.py`) is a `dict[alias → ModelClient]` with
`get_client(alias)`, `register()`, `clients()`, and `random_client()`;
`get_client` reverse-lookup a concrete model id to its alias so a stray
`--model glm-5.2:cloud` resolves instead of failing boot.

### The registry — `tools/providers/registry.py`

The single dispatch point. Replaces every historical
`if provider == "chatgpt" ... elif provider == "opencode_go" ... else ollama`
branch:

- `get_provider(provider_id)` / `get_provider_from_config(config)` — resolve
  an adapter (unknown id → `UnknownProviderError` listing registered ids).
- `resolve_default_model(config, provider_id)` — the provider's
  `default_model` (Ollama falls back to `models.registry[models.default_alias]`).
- Registration is lazy (importing the registry touches no provider SDK) and
  thread-safe; same-class re-registration overwrites, a different class
  claiming an id raises `ValueError`.
- `active_provider_metadata(config)` drives the WebUI provider picker and
  `GET /api/v1/providers` — no hard-coded provider switch statements.

### The factory — `tools/model_router.py:_build_model_client`

The single place a chat client is constructed for the chat path. Providers
call it through `make_model_client` (`tools/providers/base.py`) with an
injectable `raw_client` (anything with `.chat(**kwargs)` returning the
BreachPilot response shape), so the closure — telemetry
(`record_model_usage`, provider-attributed), `_normalize_chat_args`,
`_stream_with_telemetry` — is shared by every backend.

Two provider rules live in the closure:

- **Canonical kwarg**: generic code passes `context_window_tokens=N`. ONLY
  the Ollama adapter translates it (`apply_context_window` →
  `options.num_ctx`, when long-session mode asks); other providers drop it.
  Generic code must never send `options={"num_ctx": ...}`.
- **Ollama-only kwargs stripped** (`options`, `keep_alive`, `format`,
  `suffix`, `think`, `raw`, `num_ctx`) before dispatch to non-ollama
  providers.

When `raw_client is None` (and provider is `ollama`) the Ollama client is
constructed byte-identically to the pre-registry code, so tests that
`monkeypatch.setattr(model_router, "OllamaClient", FakeClient)` keep working.
Constructing it without the optional ollama package raises the actionable
`ProviderMissingDependencyError` ("Install BreachPilot with the Ollama extra
… or select another provider").

`build_router(provider=…, config=…)` (`tools/model_router.py`) dispatches
through the registry — there is no if/elif chain: provider #4 is an adapter +
registration, no edits to this function. For `ollama` the semantics are
byte-identical to before (one `ModelClient` per `models.registry` alias).

`build_model_client_for_provider(config, alias, ...)` is the shared helper
for the call sites that build one client outside a router (`run_service`,
`research_assistant`, `session_titler`, eval/benchmark): it resolves the
active provider through the registry and asks its adapter.

### Consumer call sites

All of these receive a `ModelClient` and call `.chat()` — provider-agnostic:

| Consumer | File | Notes |
|---|---|---|
| Model-call retry/stream/tools | `tools/exploit_agent/model_client.py` | `_call_model_with_retry` / `_stream_model` / `_call_model_with_tools`; retry logs attribute by provider — `[MODEL RETRY opencode_go]` |
| Exploit agent entry | `tools/exploit_agent/runner/_impl.py` | the main per-round LLM call |
| Payload crafter | `tools/payload_crafter.py` | script generation + LLM mutation |
| Semantic memory summarization | `tools/semantic_memory.py` | routed model client |
| Safety reviewer | `tools/safety_reviewer.py` | |
| Swarm: vuln / critic / reflection agents | `tools/swarm/agents/*.py` | `context.get("model_client")` |
| Peer-model consultation | `tools/mcp_tools/peer_models.py`, `tools/exploit_agent/reflection.py` | advisory only, no tool schemas |
| Attack planning | `tools/mcp_tools/attack_modules.py` | create/replan attack plan |

> The old Ollama-named symbols (`ollama_client.py`,
> `_call_ollama_with_retry/_with_tools`, `_stream_ollama`) remain importable
> as documented deprecation shims re-exporting `model_client` — existing call
> sites and tests keep working; new code imports from `model_client`.

### Tool-schema conversion — already OpenAI-shaped

`mcp_tools_to_ollama()` (`tools/mcp_session.py`) converts MCP tool schemas
into `{"type":"function","function":{name,description,parameters}}` — the
OpenAI tool schema. Most OpenAI-compatible providers accept this verbatim;
Responses-API providers translate inside the adapter
(`opencode_go_provider`). Tool-call *responses* come back with
`function.arguments` as a JSON **string**; `_normalize_tool_call`
(`tools/exploit_agent/tool_calls.py`) JSON-parses it (malformed → `{}`).

## The Ollama provider

`tools/providers/ollama_provider.py` owns ALL Ollama behavior:

- the `from ollama import Client` SDK import (isolated here, try/except so
  the package is optional; `load_client_cls()` returns `None` when absent);
- cloud/local host handling (`ollama.host`, default `https://api.ollama.com`;
  the client auto-attaches `Authorization: Bearer $OLLAMA_API_KEY`);
- the canonical `context_window_tokens` → `options.num_ctx` translation
  (`apply_context_window`, non-mutating; Ollama is the only backend with
  that knob);
- the `/api/tags` model-catalog fetch and the `models.registry` auto-bump
  sync (moved out of `tools/ollama_models.py`, now a compat shim — tests
  must patch `tools.providers.ollama_provider.<fn>`);
- Ollama health checks (delegating to doctor's probe helpers).

Unreachable backends raise `ProviderDiscoveryError` with the registry-mode
fallback so the API degrades to `source: "registry"` instead of failing.

## The OpenCode Go provider

`tools/providers/opencode_go_provider.py` — an OpenAI **Responses API**
cloud backend, the reference zero-Ollama provider:

```yaml
models:
  provider: opencode_go
providers:
  opencode_go:
    enabled: true
    base_url: https://opencode.ai/zen/go/v1
    api_key_env: OPENCODE_GO_API_KEY
    request_timeout_seconds: 300
    default_model: muse-spark-1.2-contributor
    models: []                 # [] = discover from GET {base_url}/models
    context_window: 128000
    discover_cache_seconds: 300
```

- `OpenCodeGoResponsesClient` speaks the Responses API over `httpx` with a
  bearer key read from `$OPENCODE_GO_API_KEY`; normalizes Responses
  events/stream chunks back into the BreachPilot response shape,
  normalizes tool schemas, and drops Ollama-only kwargs (handled by the
  router closure).
- `list_models` probes `{base_url}/models` (5s) and filters to
  Responses-compatible models (raw-list / default-model backstops); a
  missing key or unreachable endpoint raises `ProviderDiscoveryError` with
  secrets redacted from the message.
- The key is env-only (loaded by `tools/api_key_store` at boot); it never
  appears in config, logs, or error text.

## The ChatGPT provider (openai-oauth)

The opt-in `chatgpt` provider routes chat/generate through the operator's
ChatGPT account via a vendored copy of [`openai-oauth`](https://github.com/EvanZhouDev/openai-oauth)
(cloned at `oauth/` in the repo root). openai-oauth runs a **loopback
OpenAI-compatible HTTP proxy** (`127.0.0.1:10531/v1`) backed by browser OAuth
that reuses the Codex CLI credential file at `~/.codex/auth.json` (or
`$CODEX_HOME/auth.json`). Full config key table in
[config-reference.md](config-reference.md):

```yaml
models:
  provider: chatgpt
chatgpt:
  enabled: false
  base_url: http://127.0.0.1:10531/v1
  host: 127.0.0.1            # loopback-only unless you explicitly change it
  port: 10531
  auto_start: true
  local_repo: ./oauth
  runtime: auto              # auto = prefer bun (run from source), fall back to node+dist/cli.js
  request_timeout_seconds: 300
  default_model: gpt-5.2
  models: []                 # [] = discover from /v1/models
  context_window: 128000     # conservative; /v1/models returns no context metadata
  login_timeout_seconds: 300
  start_timeout_seconds: 30
  discover_cache_seconds: 300
  oauth_file: ""             # "" = auto-resolve ~/.codex/auth.json | $CODEX_HOME/auth.json
```

### Authentication — browser OAuth, tokens never enter Python/config

`ChatGptProxyManager.is_authenticated()` checks **only the existence** of
`~/.codex/auth.json` / `$CODEX_HOME/auth.json` — it never opens, reads, or
prints the file. Login is "Sign in with ChatGPT": the manager shells out to
openai-oauth's own `login` CLI, which prints an `OpenAI OAuth login URL:`
and runs an OAuth callback server on `localhost:1455`. The browser handles
the consent; the resulting tokens are written by openai-oauth directly to
`~/.codex/auth.json`. **No OAuth access token, refresh token, cookie, or
`Authorization` header is ever copied into `config.yaml`, stored in Python
memory as a configured secret, or written to logs.** The CLI menu launches
the browser (`--open`); the WebUI backend uses `--no-open` to capture the
URL and surface a clickable link (backend-driven — the browser SPA never
handles raw tokens).

### Proxy lifecycle — check, reuse, else start; never kill what we didn't start

`ChatGptProxyManager.ensure_running()` (a singleton via `get()`, thread-locked):

1. If `not is_authenticated()` → return `{ok:False, reason:"not_authenticated"}`.
   **It never spawns when unauthenticated** (the CLI throws without a TTY).
2. `GET {base_url}/health` (2s). If ok → `_we_started=False`, reuse the
   pre-existing proxy. We will **not** stop a proxy we did not start.
3. If down and `auto_start`: run openai-oauth's own `serve --host --port
   --detach`, then poll `/health` until `start_timeout_seconds`. On success
   `_we_started=True`. Idempotent (lock + cached `_base_url`).

`shutdown()` runs openai-oauth's `stop` CLI **only when `_we_started`** — it
POSTs to the worker's auth-token-gated control server and cleanly tears down
(no `taskkill`, no `psutil`, no Popen-tree kill). If we reused a pre-existing
proxy, `shutdown()` is a no-op. `atexit` registers a best-effort shutdown.
All subprocess calls use list args (no `shell=True`), `cwd=local_repo`
(handles paths with spaces), and `CREATE_NO_WINDOW` on Windows.

> **Why not Popen+kill `serve` directly?** `serve` forks a detached grandchild
> worker that a controller-`Popen` kill can't reach on Windows. Using
> openai-oauth's own `--detach`/`stop` CLI machinery is the only reliable
> cross-platform lifecycle.

### Bootstrap pins (reproducibility + safety)

First-run setup lives in `tools/chatgpt_bootstrap.py`, the single home for
the third-party pins:

- **Bun `1.3.11`** — installed only via the pinned npm package
  (`npm install -g bun@1.3.11`). BreachPilot never pipes a remote script
  into a shell (no `curl | bash`, no `irm | iex`); if bun is absent and npm
  cannot install it, setup fails with a manual-install message.
- **openai-oauth `v2.0.0`** (commit `4be9c04…`) — cloned with
  `git clone --depth 1 --branch v2.0.0`, and `HEAD` is verified against the
  pinned commit via `git rev-parse` before `bun install` / `bun run build`
  ever execute. A checkout at any other revision fails closed (delete
  `oauth/` and re-run for a fresh pinned clone).
- **`bun install --frozen-lockfile`** — the vendored `bun.lock` pins every
  transitive dependency, so installs are reproducible.

To refresh the pins, update the constants in `tools/chatgpt_bootstrap.py`,
verify the new tag contains `packages/openai-oauth/src/cli.ts` and a
`bun.lock`, and run `pytest tests/test_chatgpt_bootstrap.py`.

### Model discovery

`discover_models(base_url)` does `GET /v1/models`, cached for
`discover_cache_seconds`. Discovery failure raises
`ProviderDiscoveryError` carrying the fallback (`chatgpt.models`, then
`default_model`), so the API/UI degrade to registry mode. Each discovered
model id becomes a `ModelClient` (alias = model id). `/v1/models` returns no
context metadata, so `chatgpt.context_window` (default 128000) is the
conservative source of truth for the context compactor. The Ollama
`models.registry` is untouched and still used when `provider: ollama`.

## Embeddings path

Embeddings are decoupled from the chat provider via
`tools/providers/embeddings.py`:

| Provider | Behavior |
|---|---|
| `ollama` (default) | legacy behavior — local Ollama embeddings at `embed_host` (host fallback → `ollama.host`); owns the raw `urllib` POST and the bearer header |
| `none` | embeddings disabled — **zero network, zero env reads**; semantic memory falls back to keyword storage, skills to deterministic matching |

```yaml
embeddings:
  provider: ollama           # ollama | none
  host: ""                   # "" = ollama.embed_host → ollama.host fallback
  model: ""                  # "" = nomic-embed-text
  api_key_env: OLLAMA_API_KEY
  timeout_seconds: 30
```

`build_embedding_provider(config)` is the factory; `embeddings_disabled(provider)`
short-circuits consumers. `OllamaEmbeddingProvider.embed` returns `None` on
any failure (network error, missing embedding, non-finite values) — never
raises — and never logs the API key. Consumers (semantic memory, skill
embeddings) are unchanged: they call `.embed(text)` through
`SemanticMemoryManager` (which accepts an injected `embedding_provider`).

## Research path

The research subsystem (web search/fetch) has its own provider abstraction —
`ResearchProvider` (`tools/web_researcher.py`) with `OllamaResearchProvider`
(dynamic `import_module("ollama")`, degrade-graceful when absent) and
`SerpAPIResearchProvider`. It is independent of the chat provider selection.
See [research.md](research.md) for the full walkthrough.

## Provider-aware surfaces

- **Doctor** (`python main.py --doctor`) probes ONLY the active provider:
  `ollama` keeps the detailed `_check_ollama` / `_check_models`; built-in
  alternatives run `_check_chatgpt` / `_check_opencode_go`; any other
  registered provider consults its adapter's `health()`. A non-ollama
  selection performs **zero Ollama probes**.
- **API** — `GET /api/v1/providers` returns registry metadata rows
  (capabilities, `configured`, `default_model` — no secrets) plus `active`;
  `GET /api/v1/models/live` dispatches the active adapter's `list_models`
  (503 + registry fallback on `ProviderDiscoveryError`);
  `POST /api/v1/models/provider` validates provider ids against the
  registry. See [api/models.md](api/models.md).
- **WebUI** — the System → Models picker renders from registry metadata
  (`webui/src/components/Settings/ProviderSetup.tsx`; types in
  `webui/src/api/types.ts` — no hard-coded provider switch).
- **Session titler** — single generic path: the active adapter resolves the
  cheap title model (`title_model`) and `build_model_client_for_provider`
  routes it; the Ollama path keeps its raw client (module-level
  `OllamaClient` symbol preserved as the monkeypatch seam) with Ollama-API
  options isolated there.
- **Telemetry** — `record_model_usage` is provider-attributed;
  `read_usage_records` still filters by alias.

## Gotchas

- **The ollama SDK import is isolated by a source-scan guard.**
  `tests/test_no_ollama_regression.py` fails CI on any new generic
  `import ollama` under `tools/` — the only allowed sites are
  `tools/providers/ollama_provider.py` and `tools/web_researcher.py`
  (dynamic import, degrade-graceful).
- **Registry monkeypatch seams moved with the code.** Tests that patch
  model-catalog helpers must patch `tools.providers.ollama_provider.<fn>`
  (`tools/ollama_models.py` is a re-export shim and no longer the seam);
  session-titler tests keep patching `tools.api.session_titler.OllamaClient`.
- **Legacy config blocks still resolve.** `providers.<id>` wins over the
  legacy top-level block (`opencode_go:` / `chatgpt:`); the merge happens in
  ONE layer (`tools/config/loader.get_provider_config`) — adapters never
  hand-merge defaults.
- **Credentials are env-only.** `OLLAMA_API_KEY`, `OPENCODE_GO_API_KEY`,
  provider tokens — never in `config.yaml`, never in logs;
  `tools/api_key_store.load_api_keys_into_env()` loads `.api_keys.json`
  into the env at boot. ChatGPT OAuth tokens live in `~/.codex/auth.json`
  (existence-checked only, never read).
- **Adding a provider touches only the four points in
  [provider-development.md](provider-development.md)** — if you find yourself
  editing `model_router.py`, the exploit agent, run service, session titler,
  doctor, or WebUI for a new backend, you are re-introducing an if/elif
  chain.