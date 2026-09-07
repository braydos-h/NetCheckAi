# Contributing to BreachPilot

Thanks for helping improve BreachPilot. This guide covers setup, workflow, and the non-obvious rules you will break otherwise.

> [!WARNING]
> **Authorized use only.** BreachPilot is a lab-only offensive security tool. Contribute and test only against networks/systems you own or have explicit written authorization to assess, on a throwaway operator box. Attack mode ships as `full_access` (`config.yaml:61`) — the single remaining attack-path safety is the target-IP allowlist lock at the MCP tool layer (`tools/mcp_shared.py:494` + `tools/mcp_tools/terminal.py:_target_lock_block`). See `docs/safety-model.md` and `README.md#safety-model`.

## 1. What to read first

| Doc | Why |
|-----|-----|
| `AGENTS.md` | Compact agent guide — 8 non-obvious rules. Read before any edit. |
| `CLAUDE.md` | Authoritative architecture, permission model, boot sequence, Flow A/B split |
| `README.md` | Canonical user-facing doc — update it when you add a CLI flag, MCP tool, or config key |
| `config.yaml` | Runtime source of truth — `tools/config/schema.py:CONFIG_SCHEMA` is validated in sync (`tests/test_config_manager.py`) |
| `docs/architecture.md`, `docs/runtime-flows.md`, `docs/module-guide.md` | System shape and module responsibilities |
| `docs/extension-guide.md` | Exact edit points for in-tree changes |
| `docs/testing-guide.md` | Test layout and focused commands |
| `docs/safety-model.md` | Layered safety model |
| `legacy/README.md` | Flow B frozen status |

## 2. Prerequisites

- **Python 3.11+** (`pyproject.toml:11` `requires-python = ">=3.11"`; CI matrix 3.11–3.13). `--doctor` rejects 3.10.
- `nmap` on `PATH` (or set `nmap.path` in `config.yaml`).
- An Ollama endpoint — **cloud is the default** (`config.yaml:3` `https://api.ollama.com` + `OLLAMA_API_KEY`) or a local daemon (`http://localhost:11434`). Embeddings stay local via `ollama.embed_host` → `nomic-embed-text`.
- Optional: Metasploit, searchsploit, impacket, tmux (Linux full arsenal); Node.js + npm (first `--web` build); `bun` ≥ 1.3.11 only if using `models.provider: chatgpt`.

## 3. Setup

### Windows (primary dev platform)

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt          # synced from pyproject.toml
# or dev toolchain (ruff + mypy + build + twine + pytest + coverage):
python -m pip install -e ".[dev]"

python main.py --doctor          # env check: Python/nmap/Ollama/models/config
python main.py --self-test       # safe localhost smoke test
python main.py                   # WebUI daemon (default, opens http://127.0.0.1:8765)
```

One-click alternative: `.\install.bat` (checks tools, creates venv, builds WebUI, pulls models, runs `--doctor`); `.\START.bat` launches afterwards.

### Linux / macOS

```bash
python3 -m venv .venv; source .venv/bin/activate
python -m pip install -r requirements.txt   # or: python -m pip install -e ".[dev]"
./scripts/setup-linux.sh                    # one-shot: venv + deps + doctor
# or: ./install.sh                          # full bootstrap (OS prereqs + Ollama + venv)
```

Linux `nmap -O`/`-sS` need root: set `nmap.sudo: true` (uses `sudo -n`) or run as root; otherwise `nmap.priv_fallback` (default `true`) auto-downgrades.

### API keys (before `--doctor`)

Keys come from **process env** or `secr.json` (gitignored). There is no `.env` auto-load.

```bash
python main.py --setup-api-keys   # prompts and writes secr.json
```

| Var | Purpose |
|-----|---------|
| `OLLAMA_API_KEY` | **Required** for default Ollama Cloud path |
| `NVD_API_KEY` | Raises NVD CVE lookup rate limit |
| `GITHUB_TOKEN` | Raises `cve_to_poc` GitHub Search limit 60→5000/hr |
| `SERPAPI_API_KEY` | Optional fallback research provider |
| `BREACHPILOT_API_TOKEN` | Override auto-generated WebUI bearer token |

ChatGPT provider (`models.provider: chatgpt`) uses browser OAuth tokens at `~/.codex/auth.json` — **never copy them into `config.yaml` or logs**.

## 4. Development workflow

### Branch and commit

1. Fork and clone, or branch from `main`.
2. Keep changes focused — one feature/fix per PR.
3. Write a concise commit message (imperative, what + why, not how). Check `git log --oneline -10` for style.
4. Push and open a PR against `main`. CI runs on every push/PR (concurrency-cancelled).

### What CI enforces (`.github/workflows/ci.yml`)

| Job | Command | Notes |
|-----|---------|-------|
| **Tests** (3.11/3.12/3.13) | `python -m pytest tests/ -v` | ~250 files, all mock subprocess/network — no live Nmap |
| **Coverage** (3.12) | `python -m coverage run -m pytest tests/` + `coverage report`/`coverage xml` | `pyproject.toml:95` `source = ["tools","main","cli"]` |
| **Lint** | `ruff check .` (0 errors) + `ruff format --check .` (0 diffs) | `pyproject.toml:102` line-length 120, `select = ["E","F","W","I"]`, `ignore = ["E501"]` |
| **Lint guards** | bare-`except Exception` guard + god-file budget + `config.yaml`↔`CONFIG_SCHEMA` sync + `doctor --json` shape | See `ci.yml:99-146` |
| **Types** | `mypy --follow-imports=skip tools` (256 files, 0 errors with masks) + strict `tools/validation_utils.py` `tools/exceptions.py` `tools/mcp_shared.py` | Masks at `pyproject.toml:156`; strict hot files at `pyproject.toml:201` |
| **Package** | `python -m build` + `python -m twine check dist/*` | |
| **WebUI** | `npm ci` + `npm run build` (tsc + vite) + `npm run test` (vitest) | `webui/` |
| + CodeQL (Python + JS/TS), dependency-review, Dependabot (pip / Actions / npm weekly) | | |

### Run the same checks locally before opening a PR

```powershell
python -m pip install -e ".[dev]"
python -m pytest tests/ -v
ruff check .
ruff format --check .
mypy --follow-imports=skip tools
# if you touched the WebUI:
Set-Location webui; npm ci; npm run build; npm run test; Set-Location ..
```

And verify `README.md` flags/config still match reality if you added any.

### Focused test commands

```powershell
python -m pytest tests/test_scope_gate.py -v
python -m pytest tests/test_recon_pipeline.py::TestClass::test_method -v
python -m pytest tests/ -v -k "scope"
python -m coverage run -m pytest tests/; python -m coverage report   # coverage (CI command; pytest-cov is not installed)
```

On Linux/macOS `make test`, `make test-one F=tests/test_scope_gate.py`, `make doctor` also work.

## 5. Non-obvious rules (you will otherwise break)

### 5.1 `except Exception` hides MCP subprocess death

Anyio task groups (`mcp.client.stdio.stdio_client`, `streamable_http_client`, `ClientSession.initialize()`) raise `BaseExceptionGroup` (not an `Exception` subclass). Bare `except Exception` silently swallows it.

Use `tools/exceptions.py:38` `_EXC_GROUP_CATCH` + `_is_exception_group` / `_log_nested_exceptions`:

```python
from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions

try:
    ...
except _EXC_GROUP_CATCH as exc:
    _log_nested_exceptions(exc)
```

CI fails bare `except Exception` in `tools/mcp_tools/`, `tools/exploit_agent/`, `tools/mcp_session.py` unless annotated `# ponytail: bare except intentional` (`.github/workflows/ci.yml:99`).

### 5.2 Do not edit Flow B safety files

`scope_gate.py`, `safety_reviewer.py`, and `legacy/` (`legacy/agent_loop.py`, `legacy/tool_router.py`, `legacy/risk_controller.py`, `legacy/mission.py`, `db.py`) are **frozen** — they carry recon safety. Root shims (`cli.py`, `agent_loop.py`, etc.) are `DeprecationWarning` proxies for one release.

- **Flow A** (modern, canonical): `main.py` / `app.py` → `tools/exploit_agent/`, `tools/mcp_tools/`, `tools/swarm/`, `tools/autonomous_orchestrator.py`, `tools/run_service/`, `tools/api/`
- **Flow B** (legacy, frozen): `legacy/cli.py` + `legacy/agent_loop.py` / `legacy/mission.py` / `db.py` / `scope_gate.py` — shares `db.py`/`mission.py` schemas only

New code must use Flow A or `legacy.*` for frozen reference.

### 5.3 The one attack-mode safety is the target-IP allowlist lock

Enforced at the **MCP tool layer**, not in `tools/exploit_agent/policy.py`:

- Allowlist: `tools/mcp_shared.py:494` `_allowed_target_list` unions `EXPLOIT_TARGET` (runtime `--target`) + `exploit.allowed_targets` + `EXPLOIT_TARGET_IP`/`EXPLOIT_TARGET_DOMAIN`/`EXPLOIT_DISCOVERED_TARGETS` (domain targeting).
- Gate: `tools/mcp_tools/terminal/allowlist.py:_target_lock_block` (re-exported from the `terminal` package) gated by `ctx.require_allowlist` (`tools/mcp_tools/registry.py:make_require_allowlist`), extracting every destination (URL authorities, `/dev/tcp`, LHOST/RHOST, bare IPs, hostnames) via `tools/command_analyzer.py`.
- Matcher: `tools/validation_utils.py:380` `is_target_in_allowlist` supports domains, `*.wildcard`, and CIDR.

`full_access` auto-approves everything with no command/scope/pivot inspection. **Do not re-add removed gates** without ensuring the allowlist covers the path — the allowlist IS the lock. Recon stays `read_only` via `tools/cli_exploit_settings.py:12` missing-key fallback.

### 5.4 New exploit MCP tools: single-source registration

Add `@audit_tool` (or `@require_allowlist()` for target-touching) in `tools/mcp_tools/<family>.py` **only**. `mcp_exploit_server.py` auto-discovers every `register_*_tools` via `tools/mcp_tools/registry.py:collect_tools` (pkgutil + AST validation, fails CI if decorator missing). No manual list edit in `mcp_exploit_server.py`. Target-touching = `@require_allowlist()` + `validate_target_or_ip`.

### 5.5 Config is `config.yaml`, not `opencode.jsonc`

`opencode.jsonc` is gitignored editor-local config for the opencode.ai editor — not app state. App config lives in `config.yaml`. **Never copy `~/.codex/auth.json` OAuth tokens into `config.yaml` or logs** (`models.provider: chatgpt` only) — check `is_authenticated()` by file existence only.

### 5.6 `--target` accepts IP or domain (Phase 4)

Domains resolve via `tools/validation_utils.py:resolve_target_to_ip` and thread `EXPLOIT_TARGET`/`EXPLOIT_TARGET_IP`/`EXPLOIT_TARGET_DOMAIN`/`EXPLOIT_DISCOVERED_TARGETS` (`tools/mcp_shared.py:494`, `tools/mcp_session.py:255`). Discovered subdomains auto-authorize via `tools/mcp_shared.py:add_discovered_target`.

### 5.7 Ollama Cloud is the default model path

`ollama.host` defaults to `https://api.ollama.com` (`config.yaml:3`); the `ollama` Python client auto-attaches `Authorization: Bearer $OLLAMA_API_KEY`. Override `ollama.host` for a local daemon — same code path. Embeddings stay local via `ollama.embed_host` (`nomic-embed-text`). `OLLAMA_API_KEY` missing surfaces as 401 on first chat. ChatGPT provider seam is `tools/model_router.py:290` `_build_model_client`.

## 6. Where to add things

See `docs/extension-guide.md` for the full edit-point table. Summary:

| What you are adding | Primary edit points |
|---|---|
| **Defensive MCP tool** (scan-only, scoped) | `mcp_server.py` + `tools/validation_utils.py` |
| **Exploit MCP tool** | `tools/mcp_tools/<family>.py` `@audit_tool`/`@require_allowlist()` → `tools/mcp_tools/registry.py` helpers → `tools/command_analyzer.py` if shell/Python/MSF/file-write |
| **Attack module** | `tools/attack_modules/modules/<category>/` subclass `AttackModule` → `tools/attack_modules/registry.py:_MODULE_CLASSES` (or `register_attack_module` for plugins) |
| **Runtime skill** | `skills/<name>/SKILL.md` (YAML front matter + Markdown) + `config.yaml:skills.*` |
| **Recon behavior** | `tools/recon/` pkg (`pipeline.py` / `scanner.py` / `enumerator.py` / `config.py`; `tools/recon_pipeline.py` is a deprecated shim) + `tools/goal_suggester.py` |
| **Goal / suggestion** | `tools/goal_engine.py` presets + `tools/goal_suggester.py` heuristics |
| **Model routing** | `tools/model_router.py` + `config.yaml:models.*` + `tools/config/schema.py:CONFIG_SCHEMA` |
| **Config key** | `config.yaml` + `tools/config/schema.py:CONFIG_SCHEMA` + `ConfigValidator.validate` + `tools/config_cli.py` + `tests/test_config_manager.py` |
| **Persistent data** | `db.py` (`DDL`, `_SCHEMA_VERSION`, `_run_migration`) |
| **Swarm behavior** | `tools/swarm/orchestrator.py` + `tools/swarm/agents/*.py` |
| **Evidence/finding/report** | `evidence.py` / `finding_verifier.py` / `report_generator.py` / `tools/enhanced_reporting.py` |
| **OPSEC / detection** | `tools/opsec.py` + `tools/detection_coverage.py` (advisory-only, never a gate) |
| **Out-of-tree plugin** | `plugins/<name>/plugin.yaml` + `plugin.py` (see `docs/plugin-development.md`, `plugins/example_recon_report/`) |

Keep `pyproject.toml` and `requirements.txt` synced — header says "Synced from pyproject.toml" (`pip install -e ".[dev]" == pip install -r requirements.txt`).

**Reproducible installs:** compatibility ranges live in `pyproject.toml`; the exact CI/dev environment is pinned in `constraints-dev.txt` (install with `pip install -c constraints-dev.txt -e ".[dev]"` — CI does this on 3.11/3.12/3.13). Refresh it from a clean venv on Python 3.11 after changing ranges (full procedure in the file header), then run tests + lint + typecheck before committing. WebUI uses `npm ci` (lockfile-enforced; `npm ci` fails when `package-lock.json` is out of sync, so keep the lock committed and consistent).

## 7. Code style and constraints

- **Ruff**: line-length 120, `select = ["E","F","W","I"]`, `ignore = ["E501"]` (`pyproject.toml:102`). Per-file ignores document intentional patterns (e.g. `tools/mcp_tools/*.py` star-import helpers, `tools/exploit_agent/__init__.py` facade re-exports). Keep security-sensitive diffs readable.
- **Mypy**: `mypy --follow-imports=skip tools` must pass. 256 files, masks at `pyproject.toml:156`; 3 hot files strict (`tools/validation_utils.py`, `tools/exceptions.py`, `tools/mcp_shared.py` — zero disables, `pyproject.toml:201`).
- **God-file budget**: CI fails any new file >1000 LOC and ≥72 kB (600×120) under `tools/` unless split (`.github/workflows/ci.yml:115`).
- **No new files unless necessary** — prefer editing existing files. Workspace dirs (`reports/`, `exploit_workspace/`, `research_workspace/`, `swarm_workspace/`, `webui/dist/`) are gitignored.
- **Secrets**: never commit `.webui_secret_key`, `secr.json`, `.env`, `opencode.jsonc`, or OAuth tokens. Use `python main.py --setup-api-keys`.
- **ics write-side** (`tools/attack_modules/` ICS modules): dual-gated — `ics.allow_write: true` **and** `ics.destructive_ics: true` **and** `@require_allowlist` (`config.yaml:416`). Default both `false`.

## 8. Safety-sensitive changes

1. Run `python main.py --doctor` and `python main.py --self-test` after any safety-adjacent change.
2. Cover new safety surfaces with regression tests near `tests/test_scope_gate.py`, `tests/test_safety_reviewer.py`, `tests/test_validate_target.py` (or a new file if the surface is new).
3. Threat-model the allowlist lock: if your change introduces a new destination extraction point (new scanner verb, new LHOST/RHOST form, new shell indirection), add it to `tools/command_analyzer.py` and `_target_lock_block`.
4. Do not weaken recon's `read_only` path or the `require_explicit_allowlist` default.

## 9. Reporting issues

- **Bugs**: include `python main.py --doctor` output, `config.yaml` (redacted), relevant `reports/<run_id>/` or `exploit_workspace/<ip>/exploit_audit.jsonl` excerpt, and the failing test/command.
- **Security vulnerabilities**: do **not** open a public issue. Email the maintainers or use a private advisory — the tool is offensive by design, so responsible disclosure matters.
- **Feature requests**: describe the use case, the proposed MCP tool / attack module / skill / config key, and whether it is target-touching (needs `@require_allowlist`).

## 10. Pull request checklist

Before requesting review, confirm:

- [ ] Read `AGENTS.md` and the relevant `docs/` guide
- [ ] `python -m pytest tests/ -v` passes (or focused suite with justification)
- [ ] `ruff check .` — 0 errors; `ruff format --check .` — 0 diffs
- [ ] `mypy --follow-imports=skip tools` — 0 errors (with documented masks)
- [ ] `config.yaml` ↔ `CONFIG_SCHEMA` in sync (add key to both + validator + test if needed)
- [ ] If new CLI flag / MCP tool / config key: `README.md` updated
- [ ] If new exploit MCP tool: `@audit_tool` or `@require_allowlist()` + `validate_target_or_ip`, auto-discovered via `registry.collect_tools`
- [ ] No Flow B safety file edits, no `opencode.jsonc` app-state misuse, no OAuth token copying
- [ ] No secrets committed; no god-file budget violation

## 11. Documentation and housekeeping

- `README.md` is the canonical user-facing doc — flags, MCP tools, and config keys must be documented there.
- `pyproject.toml` and `requirements.txt` stay synced.
- `reports/`, `exploit_workspace/`, `research_workspace/`, `swarm_workspace/`, `webui/dist/`, `oauth/` are runtime/generated — never commit.
- GitHub workflows: `.github/workflows/ci.yml`, `codeql.yml`, `dependency-review` — PRs must keep them green.

## 12. License

By contributing, you agree that your contributions will be licensed under the **Apache License 2.0** (`LICENSE`). You retain copyright; you grant the project a perpetual license to use your contribution under the same terms.

## 13. Getting help

- Docs: `docs/getting-started.md`, `docs/providers.md`, `docs/api.md`, `docs/webui.md`
- Diagnostics: `python main.py --doctor --json` (machine-readable)
- Issues: https://github.com/braydos-h/BreachPilot/issues
- Feedback on this guide: open an issue or PR editing `CONTRIBUTING.md`

