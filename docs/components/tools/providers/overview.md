---
title: Providers — Overview
package: tools/providers
files: [base.py, registry.py, types.py, embeddings.py]
---

# Providers — Overview (`tools/providers/`)

Pluggable LLM backends. Chat/generate goes through a provider registry to a canonical `ModelClient`; every backend-specific behavior (SDK import, auth, host handling, model discovery, response normalization) lives inside its adapter. Generic engine code sees only the `ModelClient` contract — Ollama is one optional adapter, not the internal protocol.

## Architecture

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

Three distinct provider surfaces (from `docs/providers.md`):

| Surface | Abstraction | Providers today |
|---|---|---|
| Chat/generate | `tools/providers/` registry → `ModelClient` | `ollama` (default), `opencode_go`, `chatgpt` |
| Embeddings | `tools/providers/embeddings.py` → `EmbeddingProvider` | `ollama` (default), `none` |
| Research (web search/fetch) | `tools/web_researcher.py` → `ResearchProvider` | `ollama`, `serpapi` |

## `types.py` — the canonical contract

`ModelClient` (dataclass) is the provider interface — a thin wrapper holding the chat/stream callables, the model id, and the provider id used for telemetry attribution (`types.py:143-166`):

```python
@dataclass
class ModelClient:
    name: str
    chat: Callable[..., Any]
    stream: Callable[..., Any]
    model_id: str = ""   # defaults to name
    provider: str = ""   # defaults to "ollama"
```

Every non-stream `.chat()` returns the BreachPilot model response format (`types.py:8-24`): `model`, `message.{role, content, thinking, tool_calls}`, optional normalized `usage`. Streaming yields chunk dicts of the same shape, one per text delta, with a final chunk carrying `tool_calls` / `usage`. Providers translate between this format and their external API. Build responses with the helpers — the single source of the shape (`types.py:44-135`):

```python
def tool_call(name: str, arguments: Any, call_id: str = "") -> dict[str, Any]
def usage_report(input_tokens: Any = None, output_tokens: Any = None, total_tokens: Any = None, **extra: Any) -> dict[str, Any]
def chat_response(model: str, content: str, *, tool_calls: list[dict[str, Any]] | None = None, thinking: str = "", usage: Mapping[str, Any] | None = None) -> dict[str, Any]
def stream_chunk(content: str, *, thinking: str = "") -> dict[str, Any]
def stream_tool_chunk(tool_calls: list[dict[str, Any]], *, usage: Mapping[str, Any] | None = None) -> dict[str, Any]
```

`arguments` is normalized to a JSON string (the shape `tools/exploit_agent/tool_calls._normalize_tool_call` parses; malformed → `{}`).

Supporting metadata types (`types.py:168-268`):

| Type | Kind | Description |
|---|---|---|
| `ProviderCapabilities` | frozen dataclass | Explicit `chat / streaming / tool_calls / embeddings / model_discovery / reasoning` flags plus `as_dict()`; UI and consumers consult these instead of per-provider `if`s |
| `ModelInfo` | dataclass | `id, label, context_window, description, default` plus `as_dict()`; what `list_models` returns |
| `ProviderError` | exception | Base error for provider health/config problems |
| `ProviderMissingDependencyError` | exception | Third-party SDK not installed; message must be actionable (name the extra or alternative) |
| `ProviderDiscoveryError` | exception | Cannot enumerate live models; carries operator-safe `message` plus `fallback_models` so the API degrades to registry mode with secrets redacted |
| `ProviderHealth` | dataclass | `checks` list of doctor-shaped `{name, ok, error?, hint?, subchecks?}` dicts; `ok` property; `as_check(name)` compacts to one doctor entry |

## `base.py` — `BaseProvider`

Abstract adapter every chat/generate provider implements (`base.py:45-150`). API-specific translation lives entirely inside the adapter.

```python
class BaseProvider(ABC):
    id: str = ""
    display_name: str = ""
    capabilities: ProviderCapabilities = ProviderCapabilities()

    def metadata(self, config: Mapping[str, Any] | None = None) -> dict[str, Any]
    def is_configured(self, cfg: Mapping[str, Any]) -> bool
    def provider_config(self, config: Mapping[str, Any] | None = None) -> dict[str, Any]
    @abstractmethod
    def build_router(self, config: Mapping[str, Any] | None = None, *, request_timeout_seconds: float | None = None,
                     provider_config: Mapping[str, Any] | None = None) -> "ModelRouter"
    def build_client(self, config: Mapping[str, Any] | None = None, alias: str = "", *,
                     request_timeout_seconds: float | None = None) -> "ModelClient"
    def use_raw_client_factory(self, factory: Any) -> None
    def list_models(self, config: Mapping[str, Any] | None = None) -> list[ModelInfo]
    def title_model(self, config: Mapping[str, Any] | None = None) -> str
    def health(self, config: Mapping[str, Any] | None = None) -> ProviderHealth
```

Contract methods: `build_router` returns a `ModelRouter` of registered clients for this provider; `build_client` returns one client for a concrete alias/model id; `list_models` enumerates available models; `title_model` is the cheap session-titling model (default: `default_model`); `health` returns doctor-compatible checks (default: empty `ProviderHealth`).

Defaults cover `metadata` (id, name, capability dict, `configured` bool, `default_model` — no secrets), `is_configured` (`enabled` flag or non-empty `base_url`; secret-holding providers override to require the key), and the baseline `list_models` (configured `models` list plus `default_model`, with `context_window` attached when numeric). `provider_config` delegates to the single normalization layer `tools.config.loader.get_provider_config` — modern `providers.<id>` block first, legacy top-level block fallback; never returns `None`.

`make_model_client` (`base.py:153-176) is the shared factory — a thin wrapper over `tools.model_router._build_model_client` (lazy import keeps the package cycle-free) so the telemetry plus canonical-arg closure is shared by every backend:

```python
def make_model_client(model_name: str, *, alias: str = "", request_timeout_seconds: float | None = None,
                      raw_client: Any = None, provider: str | None = None, host: str | None = None) -> "ModelClient"
```

`use_raw_client_factory` injects a `build_raw_client(provider_config, timeout)` factory for tests. `CANONICAL_CHAT_KWARGS = ("context_window_tokens",)` (`base.py:42`): generic code may pass it on any provider; adapters translate it to their backend's mechanism or drop it.

## `registry.py` — `ProviderRegistry`

The single dispatch point replacing every historical `if provider == ... elif ... else ollama` chain (`registry.py:39-89`):

```python
class ProviderRegistry:
    def register(self, provider: BaseProvider) -> None
    def get(self, provider_id: str) -> BaseProvider
    get_provider = get
    def ids(self) -> list[str]
    def all(self) -> list[BaseProvider]
    def metadata(self, config: Mapping[str, Any] | None = None) -> list[dict[str, Any]]
```

Thread-safe (`threading.Lock`); same-class re-registration overwrites, a different class claiming an id raises `ValueError`. Unknown ids raise `UnknownProviderError` (a `ProviderError`) with an actionable message listing registered ids. Module-level entry points:

```python
PROVIDERS = ProviderRegistry()
def get_provider(provider_id: str) -> BaseProvider
def get_provider_from_config(config: Mapping[str, Any] | None) -> BaseProvider
def active_provider_metadata(config: Mapping[str, Any] | None = None) -> dict[str, Any]
def resolve_default_model(config: Mapping[str, Any], provider_id: str) -> str
```

`_LazyDefaultRegistry._ensure` registers the three built-ins on first access (`ollama`, `opencode_go`, `chatgpt`), so importing the registry never touches provider SDKs. `get_provider_from_config` reads `models.provider` (default `ollama`) via `get_ai_provider`. `resolve_default_model` reads the provider's `default_model`, with the Ollama fallback to `models.registry[models.default_alias]`. `active_provider_metadata` drives the WebUI provider picker and `GET /api/v1/providers`.

## Lifecycle

1. Config selects: `models.provider` names the adapter; `providers.<id>` (or the legacy top-level block) configures it.
2. Call site resolves: `get_provider(id)` or `get_provider_from_config(config)` → adapter.
3. Adapter builds: `build_router(config)` for the alias-keyed chat path, or `build_client(config, alias)` for one-off clients (run service, titler, eval).
4. Consumer calls: `client.chat(model, **kwargs)` / `client.stream(...)` — provider-agnostic; retry/stream/tool-call handling lives in `tools/exploit_agent/model_client.py`.
5. Discovery/health: `list_models` feeds `GET /api/v1/models/live` (failures raise `ProviderDiscoveryError` → 503 plus registry fallback); `health` feeds `python main.py --doctor`, which probes only the active provider.

The factory closure (`tools/model_router.py:_build_model_client`, reached via `make_model_client`) enforces two provider rules: the canonical `context_window_tokens` kwarg (only the Ollama adapter translates it to `options.num_ctx`; others drop it) and stripping of Ollama-only kwargs (`options`, `keep_alive`, `format`, `suffix`, `think`, `raw`, `num_ctx`) before dispatch to non-Ollama providers.

## Embeddings providers (`embeddings.py`)

Decoupled from chat selection. `EmbeddingProvider` is a `Protocol` with `name` plus `embed(text) -> vector or None` (`embeddings.py:27-31`):

| Provider | Class | Behavior |
|---|---|---|
| `ollama` (default) | `OllamaEmbeddingProvider(host, model, api_key_env, timeout_seconds)` | Legacy behavior — raw `urllib` POST to `{host}/api/embeddings`; bearer header when the key env is set; returns `None` on any failure (network, missing embedding, non-finite values) — never raises, never logs the key |
| `none` | `NullEmbeddingProvider` | Embeddings disabled — zero network, zero env reads; semantic memory falls back to keyword storage, skills to deterministic matching |

```python
def build_embedding_provider(config: dict[str, Any] | None = None) -> EmbeddingProvider
def embeddings_disabled(provider: Any) -> bool
```

`build_embedding_provider` reads `embeddings.provider` via `get_embeddings_config`; unknown ids warn and degrade to `none` (embeddings are an optimization, never on the critical path). `none` / `null` / `disabled` / `""` all select the null provider.

## Config keys

| Key | Default | Effect |
|---|---|---|
| `models.provider` | `ollama` | Selects the chat/generate adapter (`ollama` \| `opencode_go` \| `chatgpt`) |
| `models.registry` / `models.default_alias` | per install | Ollama alias→model map; `resolve_default_model` fallback when the Ollama block sets no `default_model` |
| `providers.<id>.enabled` | per provider | Adapter on/off; read by `is_configured` |
| `providers.<id>.base_url` | per provider | Endpoint (e.g. Ollama cloud host, `https://opencode.ai/zen/go/v1`) |
| `providers.<id>.api_key_env` | per provider | Env var holding the key — keys are env-only, never in config or logs |
| `providers.<id>.default_model` | per provider | Default concrete model; also the `title_model` default |
| `providers.<id>.models` | `[]` | Configured ids (`[]` = discover live via the adapter) |
| `providers.<id>.context_window` | per provider | Conservative context size (used by the compactor where the API exposes none) |
| `providers.<id>.request_timeout_seconds` | `300` | Per-call timeout |
| `providers.<id>.discover_cache_seconds` | `300` | Live-discovery cache TTL |
| `embeddings.provider` | `ollama` | `ollama` \| `none` |
| `embeddings.host` / `model` / `api_key_env` / `timeout_seconds` | `""` → Ollama fallback / `""` → `nomic-embed-text` / `OLLAMA_API_KEY` / `30` | Ollama embeddings endpoint tuning |

Legacy top-level blocks (`ollama:`, `opencode_go:`, `chatgpt:`) still resolve — `providers.<id>` wins, merged in the one layer `tools.config.loader.get_provider_config`. Credentials (`OLLAMA_API_KEY`, `OPENCODE_GO_API_KEY`) load from `.api_keys.json` into the env at boot via `tools/api_key_store`; ChatGPT OAuth tokens live in `~/.codex/auth.json` (existence-checked only, never read).

## Examples

```python
from tools.providers.registry import get_provider, get_provider_from_config

provider = get_provider("opencode_go")          # or get_provider_from_config(config)
router = provider.build_router(config)
client = provider.build_client(config, alias)
response = client.chat(model, messages=[{"role": "user", "content": "hello"}])
```

```python
from tools.providers.embeddings import build_embedding_provider

embeddings = build_embedding_provider(config)   # ollama | none
vector = embeddings.embed("privilege escalation technique")  # None when disabled/failing
```

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

## Adding a provider

Exactly four steps, all in new code — if a new backend needs edits to the agent, swarm, run service, titler, doctor, or WebUI, that re-introduces an if/elif chain. Full recipe plus reference adapters (`OpenCodeGoProvider` for pure-HTTP Responses-API, `ChatGptProvider` for owned process lifecycle) in [provider development](../../../provider-development.md):

1. Write one adapter: a `BaseProvider` subclass in `tools/providers/<id>_provider.py`.
2. Register its instance in `tools/providers/registry.py:_LazyDefaultRegistry._ensure()` (or via `PROVIDERS.register`).
3. Add a `providers.<id>` schema block plus defaults in `tools/config/schema.py`.
4. Add tests — the contract suite (`tests/test_provider_contract.py`) parameterizes over `PROVIDERS.all()` automatically, plus focused tests for the adapter's chat/translation/auth behavior with HTTP/SDK mocked.

## Tests

| File | Verified | Covers |
|---|---|---|
| `tests/test_provider_registry.py` | yes | Lazy built-in registration, duplicate-id rejection |
| `tests/test_provider_contract.py` | yes | Shared interface contract over `PROVIDERS.all()` |
| `tests/test_embeddings_provider.py` | yes | `none` vs `ollama` selection, config application |
| `tests/test_no_ollama_regression.py` | yes | Engine runs Ollama-free; ollama SDK import isolated to its adapter |
| `tests/test_opencode_go_provider.py` | yes | Present; Responses-API adapter behavior |
| `tests/test_chatgpt_provider.py` | yes | Present; proxy adapter behavior |
| `tests/test_provider_switching.py` | yes | Present; active-provider switching |
| `tests/test_provider_alias_resolve.py` | yes | Present; alias→model resolution |
| `tests/test_provider_tool_contract.py` | yes | Present; tool-call contract per provider |
| `tests/test_llm_tool_contract.py` | yes | Present; LLM tool-call shape |

Implementation note: Covers entries beyond the first four rows are grounded on file presence plus names, not a full read of each file.

## Related documentation

- [Providers](../../../providers.md)
- [Provider development](../../../provider-development.md)
- [Config reference](../../../config-reference.md)
- [Deployment](../../../deployment.md)
- [Research](../../../research.md)
- [Sandbox overview](../sandbox/overview.md)

## Source map

- `tools/providers/base.py`
- `tools/providers/registry.py`
- `tools/providers/types.py`
- `tools/providers/embeddings.py`
- `tools/providers/ollama_provider.py`
- `tools/providers/opencode_go_provider.py`
- `tools/providers/chatgpt_provider.py`
- `tools/model_router.py`
- `tools/web_researcher.py`
