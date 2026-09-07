# Getting Started

## Prerequisites

| Need | Minimum | Notes |
|------|---------|-------|
| Python | 3.11+ (`pyproject.toml` `requires-python = ">=3.11"`; `tools/doctor.py:31` rejects older; CI 3.11–3.13) | `python --version` |
| Docker | Docker Desktop (Win/macOS) or Engine (Linux) + image `breachpilot-sandbox:latest` | Sandbox is default-on; without it attacks degrade to native (`sandbox.fallback_native: true`) or block (`false`). Build: `docker build -t breachpilot-sandbox:latest docker/sandbox` |
| Node.js + npm | Node 18+ | Only for first WebUI build (`webui/dist/` auto-built, ~600s timeout) |
| nmap | On `PATH` or `nmap.path` in `config.yaml` | Linux `-O`/`-sS` need root (`nmap.sudo: true` with `sudo -n`) or `nmap.priv_fallback` auto-downgrade |
| Ollama endpoint | Cloud default (`https://api.ollama.com` + `OLLAMA_API_KEY`) or local (`http://localhost:11434`) | Embeddings stay local via `ollama.embed_host`. Alt providers: `opencode_go` (`OPENCODE_GO_API_KEY`), `chatgpt` (browser OAuth, tokens in `~/.codex/auth.json` — never config) |
| Disk / rights | ~4GB free, admin for `install.bat`/winget (Win) or apt (Linux) | Git required for clone |
| Optional | Metasploit, `searchsploit`, `tmux`, impacket/hydra (Linux Kali arsenal; Windows = Python-only exploits) | Probed at boot (`tools/env_probe.py`); agent pivots to Python fallbacks |

> **Auth trifecta (don't conflate):** (a) model keys → `secr.json`/env (`OLLAMA_API_KEY`, `OPENCODE_GO_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`, `SERPAPI_API_KEY` — app never auto-loads `.env`); (b) WebUI bearer → `.webui_secret_key`/`BREACHPILOT_API_TOKEN` + WS `{"auth":…}` (HTTP 401 vs WS 4401); (c) scope → `allowed_targets`/`EXPLOIT_TARGET` (`BLOCKED` = off-allowlist destination vs `SCOPE_DENIED` = `forbidden_actions`/`disallowed_assets` vs `SANDBOX_*` = execution containment).

## Setup

From the repository root.

**Windows — one-click (recommended for new users):**

```powershell
# Double-click install.bat in Explorer, or from PowerShell:
.\install.bat          # checks/installs Python/Node/Nmap/Ollama, venv, WebUI, --doctor
.\START.bat            # after install: double-click to launch (WebUI at http://127.0.0.1:8765)
```

`install.bat` does everything: it checks for Python 3.11+, Node.js, Nmap and Ollama
(offering to install anything missing via `winget` when you approve), creates
`.venv`, installs `requirements.txt`, builds `webui/dist/` if Node is present,
starts Ollama, pulls the default model + embedding model, walks you through
`OLLAMA_API_KEY`, runs `python main.py --doctor`, and wires the `breachpilot`
launcher. Safe to re-run; try `install.bat --check` for an audit-only pass
or `install.bat --help` for options.

**Windows — manual (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
# one-shot bootstrap (installs the `breachpilot` and `bp` launchers):
./install.sh               # full bootstrap (OS prereqs + Ollama + venv + launchers)
./scripts/setup-linux.sh   # lightweight: venv + deps + doctor
```

For editable package metadata and dev extras (either shell):

```bash
python -m pip install -e ".[dev]"
```

`requirements.txt` includes runtime dependencies plus Pytest for local development. `pyproject.toml` separates runtime and development dependencies for packaging. Prefer `requirements.txt` for a local checkout unless packaging is the specific task.

## First Commands

Run environment checks (expected: all `[OK]`, exit 0; failures name the subsystem + hint):

```bash
python main.py --doctor
```

Run the safe localhost smoke test (localhost-only, `read_only`, writes
`reports/self_test_<run_id>/self_test_report.{json,md}`):

```bash
python main.py --self-test
```

Launch the WebUI daemon (the default with no arguments — builds the SPA if
needed, serves it at http://127.0.0.1:8765, and opens a browser):

```bash
bp
```

`bp` can be run from any directory; it switches to the project root and uses
the project virtual environment automatically. It accepts the same arguments
as `python main.py` (for example, `bp --doctor`).

Prefer the terminal? The legacy interactive questionary menu is still available:

```bash
python main.py --menu
```

Run recon against an explicitly allowed target:

```bash
python main.py --target 127.0.0.1 --mode recon --goal initial_access --yes
```

### Lab target for your first exploit (copy-paste victim)

Never scan a host you don't own. For a local victim:

```bash
docker run --rm -p 8080:80 vulnerables/web-dvwa   # DVWA on http://127.0.0.1:8080
# or: python main.py --demo   # Docker DVWA on 127.0.0.1:8081, synthetic HTTP fallback, writes reports/demo/
```

Then allowlist it (`config.yaml` `exploit.allowed_targets: [127.0.0.1]` covers
loopback; add LAN IPs explicitly) and run:
`python main.py --target 127.0.0.1 --mode attack --goal initial_access`.
Expect `quick_scan` output → goal suggestion → `ALLOW <target>` gate (in
`approve_only`) → milestones under `reports/<run_id>/` + `exploit_audit.jsonl`.

Run the workflow CLI:

```bash
python cli.py init-mission --config mission.yaml
python cli.py status
python cli.py list-scope
python cli.py next-task
```

## Configuration Files

- `config.yaml`: runtime configuration for Ollama, model aliases, MCP transport, exploit behavior, stealth options, CVE lookup, research, swarm, reasoning, memory, outcome judgment, adaptive exploit settings, and optional peer-model consultation.
- `mission.yaml`: sample mission definition. This is where allowed assets, disallowed assets, forbidden actions, testing modes, rate limits, accounts, and notes are defined.
- `plugins` block in `config.yaml`: controls plugin enablement (`enabled`/`disabled` name lists), `search_paths` (default `["plugins"]`), and `entry_points` (default `true`).

Important defaults in `config.yaml`:

- `exploit.permission: full_access` (lab build; set `read_only` for propose-only recon)
- `exploit.attack_mode: true`
- `exploit.require_explicit_allowlist: true`
- `exploit.allowed_targets: [127.0.0.1]` in the shipped lab config (a target entered in Start New Session is added here; the runtime `--target` is also unioned in via `EXPLOIT_TARGET`)
- `swarm.enabled: true`
- `memory.semantic_enabled: true`
- `outcome_judgment.max_inconclusive_attempts: 3`
- `outcome_judgment.confirmation_threshold: 0.75`
- `outcome_judgment.refutation_threshold: 0.75`
- `outcome_judgment.min_evidence_references: 1`

Only materially different inconclusive checks count toward the attempt cap, and
the configured minimum is two so one failed command cannot exhaust a
hypothesis. Thresholds must be between `0.5` and `1.0`; evidence references must
be at least one for a confirmed/refuted terminal judgment. These settings only
control interpretation and replanning—they do not grant execution authority.

## Main Entry Points

- `python main.py`: start the WebUI daemon — the default with no arguments (build + serve the SPA at http://127.0.0.1:8765 and open a browser).
- `python main.py --menu`: force the legacy interactive terminal menu.
- `python main.py --target <ip> --mode recon`: reconnaissance mode.
- `python main.py --target <ip> --mode attack`: exploitation mode, still subject to config and policy gates.
- `python main.py --demon` / `--web`: API-only daemon / daemon + SPA + browser.
- `python main.py --mcp-transport stdio|http`: select exploit MCP transport (ignored on the run path — always http).
- `python main.py --swarm --critic --reflection`: enable swarm orchestration helpers.
- `python main.py --list-plugins`: list discovered plugins.
- `python main.py --skills {on,off,hints,lookup}`: set runtime skill mode.
- `python main.py --skills-list`: list available skills.
- `python main.py --long-session`: opt-in multi-hour attack mode.
- `python mcp_server.py`: start the defensive MCP server.
- `python mcp_exploit_server.py`: start the exploit MCP server.
- `python mcp_engine_server.py`: start the engine advisory MCP server (skills/CVE/run history, read-only, for foreign AI assistants).

For plugin authoring see `docs/plugin-development.md`; for the runtime skills system see `docs/skills.md`.

## Developer Loop

1. Read the relevant module guide entry before editing.
2. Add or update focused tests in `tests/`.
3. Run the smallest matching test file.
4. Run `python -m pytest` before handing off larger changes.
5. For safety-sensitive changes, also run `python main.py --doctor` and `python main.py --self-test`.
