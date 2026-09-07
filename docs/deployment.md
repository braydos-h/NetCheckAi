# Deployment

How to stand up BreachPilot on a fresh operator box: supported platforms,
dependency installation, Ollama wiring, nmap privileges, the WebUI build, and
running the API daemon as a service. Ends with runtime state layout, backup
guidance, and a production hardening checklist.

> [!WARNING]
> Attack mode ships as `full_access` (auto-approve, no content/scope
> inspection) with an unrestricted operator-box filesystem. Deploy only on a
> **throwaway lab VM** against targets you own or are explicitly authorized to
> test. See [`README.md`](../README.md#-safety-model) and
> [`docs/safety-model.md`](safety-model.md).

## Supported platforms

| Platform | Status | Notes |
|---|---|---|
| **Linux** | **Primary** | `./install.sh` one-shot bootstrap; full Kali arsenal (searchsploit, Metasploit, hydra, impacket) |
| Windows | Legacy / secondary | `install.bat` one-shot bootstrap; Python-only exploit tooling (no Kali arsenal) |
| macOS | Best-effort | `scripts/setup-linux.sh` covers it; untested as a primary platform |

The exploit agent's system prompt is OS-aware: Windows attackers get
Python-only exploits, Linux attackers get the full Kali toolkit
(README.md:262-263, config.yaml:90-95).

## Prerequisites

- **Python 3.11+** — `pyproject.toml:11` (`requires-python = ">=3.11"`).
  Note `main.py --doctor` rejects 3.10 and below (README.md:113).
- **`nmap`** on `PATH` (or set `nmap.path` in `config.yaml:63`).
- **Ollama** — cloud default, or a local daemon (see [Ollama model
  availability](#ollama-model-availability)).
- **Node.js + npm** — only needed for the first `--web` run (builds
  `webui/dist/`).
- Optional Linux arsenal: Metasploit, searchsploit/exploitdb, impacket, tmux.

## Install (step by step)

### Windows (one-click)

This repo's primary dev platform. **New users: double-click `install.bat` in
Explorer** — no PowerShell knowledge needed. From a terminal:

```powershell
# Easiest path (recommended for new users):
.\install.bat          # one-click: checks/installs Python/Node/Nmap/Ollama via winget,
                       # creates .venv, installs deps, builds WebUI, pulls models,
                       # guides OLLAMA_API_KEY setup, runs --doctor, installs `breachpilot`
.\START.bat            # after install: double-click to launch (WebUI at http://127.0.0.1:8765)
# Options: install.bat --check  (audit only), --yes (non-interactive), --help, --uninstall

# Manual alternative (if you prefer to do it step by step):
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -e ".[dev]"   # optional: dev extras (ruff + pytest + coverage)
python main.py --setup-api-keys
python main.py --doctor
python main.py --self-test
```

`install.bat` is idempotent and non-fatal on missing optional tools; it also
installs a `breachpilot` command to `%USERPROFILE%\.local\bin` that always runs from
the repo root. Uninstall with `install.bat --uninstall`. `START.bat` is a
double-click launcher that passes args through (e.g. `START.bat --menu`).

### Linux (./install.sh one-shot)

```bash
# Option 0: one-shot bootstrap (recommended — OS prereqs + Ollama + venv +
#           WebUI + models + --doctor + `bp` launchers).
#           See README "Quick start in 60 seconds" for the short version.
./install.sh
bp                        # launch from any directory; opens http://127.0.0.1:8765

# Full Kali arsenal (metasploit/searchsploit/hydra/impacket):
INSTALL_KALI_TOOLS=1 ./install.sh

# Option A: make (thin wrappers, Makefile)
make install         # venv + pip install -r requirements.txt (Makefile:14-16)
make install-dev     # venv + pip install -e ".[dev]" (Makefile:18-20)
make doctor          # python main.py --doctor (Makefile:22-23)
make self-test       # python main.py --self-test (Makefile:25-26)
make run             # python main.py (Makefile:38-39)
make test-one F=tests/test_scope_gate.py   # focused test (Makefile:35-36)
make clean           # rm -rf .venv + caches (Makefile:50-53)

# Option B: lightweight alternative (venv + deps + external-tool checks +
#           best-effort `ollama pull` + --doctor)
./scripts/setup-linux.sh

# Manual equivalent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

`./install.sh` is the primary path (OS prereqs + Ollama + venv + WebUI +
models + `--doctor` + `bp` launchers; `INSTALL_KALI_TOOLS=1 ./install.sh`
for the full Kali arsenal). `scripts/setup-linux.sh` is the lightweight
alternative: it checks for `nmap`, `ollama`, `tmux`, `searchsploit`,
`msfconsole`, `hydra`, and `impacket` and prints install hints for anything
missing (setup-linux.sh:42-48). It never installs or runs anything against a
target — host prep only.

## Dependency installation: requirements.txt vs pyproject extras

- **`requirements.txt`** — runtime deps **plus** pytest and pytest-asyncio for
  local development (requirements.txt:9-10). Use this for a local checkout.
- **`pyproject.toml`** — separates runtime (`dependencies`, pyproject.toml:27-38)
  from dev extras (`[project.optional-dependencies].dev`: pytest,
  pytest-asyncio, coverage, ruff — pyproject.toml:40-46). Use `.[dev]` when
  packaging or when you want the lint tooling.

**Keep the two in sync.** Runtime deps appear in both files today — if you add
a runtime dependency, add it to `requirements.txt` **and**
`pyproject.toml:dependencies` (AGENTS.md "Toolchain notes"; getting-started.md:36).

```bash
python -m pip install -r requirements.txt    # local checkout (recommended)
python -m pip install -e ".[dev]"            # packaging / lint / coverage
```

## Ollama model availability

Default path is **Ollama Cloud**; the same code path runs against a local
daemon after a one-line config swap.

| Setting | Default | Purpose |
|---|---|---|
| `ollama.host` (config.yaml:7) | `https://api.ollama.com` | Chat/generate endpoint |
| `ollama.model` (config.yaml:8) | `glm-5.2:cloud` | Default model spec |
| `ollama.api_key_env` (config.yaml:9) | `OLLAMA_API_KEY` | Env var for the cloud bearer token |
| `ollama.embed_host` (config.yaml:14) | `http://localhost:11434` | Local embeddings endpoint; falls back to `host` when absent |

- **Cloud (default):** export `OLLAMA_API_KEY` (or store via
  `python main.py --setup-api-keys` → `secr.json`, gitignored). Missing key
  surfaces as a 401 on the first chat. The ollama Python client auto-attaches
  `Authorization: Bearer $OLLAMA_API_KEY` to every request, so the host swap
  is the entire wiring — no probe, no local→cloud fallback (config.yaml:2-6).
- **Local daemon:** set `ollama.host: http://localhost:11434` (and `ollama pull
  glm-5.2:cloud`). The `--doctor` model check runs a 1-token generation to
  verify; local models report an `ollama pull <spec>` hint if missing
  (README.md:170-172).
- **Embeddings stay local by default:** `nomic-embed-text` via `embed_host`
  (config.yaml:10-14, config.yaml:348). Required for semantic memory/skills;
  `install.bat` pulls it when Ollama is available.

There is no `.env` auto-load — keys come from process environment variables or
`secr.json` (README.md:143-160).

## nmap requirements

`nmap` must be installed and on `PATH` (or set `nmap.path`, config.yaml:63).

- **Windows:** plain nmap works; `nmap.sudo`/`priv_fallback` are no-ops.
  Install from https://nmap.org/download.html or `winget install Insecure.Nmap`
  (`install.bat` offers this via winget when you approve).
- **Linux:** `-O`/`-sS` scans need root. Either set `nmap.sudo: true` (runs
  `sudo -n`), run as root, or leave `nmap.priv_fallback: true` (default) to
  auto-downgrade those flags instead of failing when unprivileged
  (config.yaml:58-65, README.md:138-139).
  `nmap.sudo` uses `sudo -n` (non-interactive), so it needs a NOPASSWD rule
  for nmap — enabling `nmap.sudo: true` without one fails every `-O`/`-sS`
  scan. Add a sudoers.d exception, e.g.:

  ```bash
  echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/breachpilot-nmap
  ```

  Verify the path first with `command -v nmap` and keep `nmap.priv_fallback:
  true` unless privileged scans must hard-fail instead of downgrading.

## WebUI build

The SPA is a Vite + React + TypeScript app under `webui/`. It is **not**
pre-built in the repo — `webui/dist/` is gitignored and created on demand.

- First `python main.py --web` run runs `npm install && npm run build` in
  `webui/` (`_ensure_webui_build`, main.py:436-462; build = `tsc -b && vite
  build`, webui/package.json:8), then serves `webui/dist/` at `/` and opens
  `http://127.0.0.1:8765` (main.py:537-558).
- Node/npm must be on `PATH` (main.py:442-446). Build manually with
  `cd webui && npm install && npm run build`.
- Manual rebuild: `npm install`, `npm run dev` (port 5173, strictPort), `npm
  run build`, `npm run preview` (webui/package.json:6-10; webui.md:81-95).
- The built UI talks to `/api/v1` REST + WebSocket with bearer-token auth; see
  [`docs/api.md`](api.md) and [`docs/webui.md`](webui.md).

## Running as a service / daemon

`--demon` (alias `--daemon`) starts the local WebUI API daemon without the
SPA; `--web` additionally builds/serves the SPA and opens a browser.

```bash
python main.py --demon              # API on http://127.0.0.1:8765 (no SPA)
python main.py --daemon --api-port 9000   # alias, custom port
python main.py --web                # build + serve SPA + open browser
```

- Flags: `--demon`/`--daemon` (main.py:423-426), `--api-host`/`--api-port`
  (main.py:427-428).
- Config: `api.host` (default `127.0.0.1`), `api.port` (8765),
  `api.token_file` (`.webui_secret_key`), `api.allowed_origins`
  (config.yaml:430-438).
- Docs at `http://127.0.0.1:8765/docs`; OpenAPI at `/openapi.json`
  (main.py:546-547).
- Re-entrancy: a second daemon start detects the running instance and exits 0
  (main.py:497-525).

**Daemon-ize with the OS, not a flag:**

```powershell
# Windows: NSSM or a scheduled task
nssm install BreachPilot "C:\Users\BH\Documents\GitHub\BreachPilot\.venv\Scripts\python.exe" "C:\Users\BH\Documents\GitHub\BreachPilot\main.py" --daemon
```

```bash
# Linux: systemd unit
[Unit]
Description=BreachPilot WebUI API daemon
After=network.target

[Service]
WorkingDirectory=/opt/BreachPilot
ExecStart=/opt/BreachPilot/.venv/bin/python main.py --daemon
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Loopback-only binding security note

The API daemon is **loopback-only by design in v1 — there is no public-bind
override** (config.yaml:424-429). `--api-host` accepts only
`127.0.0.1`/`localhost`/`::1` and exits with code 2 otherwise (main.py:515-518),
and `create_app` re-validates via `assert_api_loopback` (tools/api/auth.py:30-36,
docs/api.md:73). Never tunnel it to a public interface; use a VPN if remote
access is required. The MCP HTTP servers have a separate two-person rule
(`--allow-public-bind` + `MCP_ALLOW_PUBLIC_BIND=1`, docs/mcp-tools.md:19).

## Directory layout for runtime state

All runtime state is gitignored (`.gitignore:22-26,37`):

| Path | Content | Created by |
|---|---|---|
| `reports/<run_id>/` | Per-run reports, logs, eval trees (`reports/eval/<run_id>/`) | CLI/daemon runs, `--eval` |
| `reports/api_runtime.db` | WebUI daemon run/decision state (SQLite) | `--demon`/`--daemon` |
| `exploit_workspace/<ip>/<attempt_id>/` | Exploit attempts + `exploit_audit.jsonl` (SHA256-chained audit) | Attack runs |
| `exploit_workspace/loot/` | Loot workspace (`exploit.loot_workspace`, config.yaml:89) | Attack runs |
| `research_workspace/<mission_id>/` | Flow B mission data (SQLite) | `cli.py` missions |
| `swarm_workspace/` | Swarm artifacts | Swarm runs |
| `webui/dist/` | Built SPA | First `--web` run |
| `.webui_secret_key` | Auto-generated API bearer token | First daemon boot |
| `secr.json` | Provider API keys | `--setup-api-keys` |

These directories are excluded from version control on purpose — treat them as
data, never as source.

## Backup / migration

To move or preserve an operator box, copy the runtime data **without** the
venv and build artifacts:

```bash
# What to keep (copy whole, preserving structure):
reports/              # run reports + api_runtime.db (daemon state)
exploit_workspace/    # audit chains + loot (tamper-evident records)
research_workspace/   # Flow B mission data
swarm_workspace/      # swarm artifacts
secr.json             # provider keys (encrypt this copy separately)

# What to regenerate, don't back up:
.venv/                # python -m venv + pip install -r requirements.txt
webui/dist/           # first --web run rebuilds it
.webui_secret_key     # regenerated; or re-set BREACHPILOT_API_TOKEN
```

Migration notes:

- `reports/api_runtime.db` is daemon state; if it is copied mid-run, the
  daemon's startup `recover_interrupted()` marks live runs `interrupted` and
  expires pending decisions (docs/api.md:170) — expected after a move.
- The API daemon is **single active run**; running two daemons against one
  copied `api_runtime.db` is unsupported.
- `secr.json` and `.webui_secret_key` hold credentials — back them up encrypted
  or regenerate them (`.webui_secret_key` is `0o600` where supported,
  docs/api.md:75).

## Production hardening checklist

Deployment-time verification for a box you intend to run for a while:

**Target allowlist (the one attack-mode lock)**

- [ ] `exploit.require_explicit_allowlist: true` (config.yaml:100)
- [ ] `exploit.allowed_targets` contains only authorized hosts/domains/CIDRs
      (config.yaml:110-111); runtime `--target` is unioned via
      `EXPLOIT_TARGET`, so confirm each run's target, don't rely on it
- [ ] Callback/C2 listener hosts added explicitly to `allowed_targets`
      (README.md:252)
- [ ] Understand the lock is a destination guard, not a sandbox
      (README.md:254-258); run on a throwaway VM
- [ ] `exploit.permission` set deliberately — `full_access` is the shipped
      default; `read_only` for propose-only recon, `approve_only` for a
      per-action banner (README.md:235-240, config.yaml:76)
- [ ] `exploit.forbidden_actions` / `disallowed_assets` reviewed (opt-out
      categories, config.yaml:124-125)

**Token auth (WebUI daemon)**

- [ ] Bearer token set explicitly via `BREACHPILOT_API_TOKEN` (precedes the
      auto-generated `.webui_secret_key`; docs/api.md:75, docs/api.md:935)
- [ ] `.webui_secret_key` perms `0o600` where supported
- [ ] `api.allowed_origins` left `[]` or loopback-only entries
      (config.yaml:435; non-loopback entries rejected by the config validator,
      docs/config-reference.md:24)
- [ ] `GET /health` is the only unauthenticated route (docs/api.md:12)

**Loopback bind**

- [ ] `api.host: 127.0.0.1` (config.yaml:432) — v1 refuses public binds
      (main.py:515-518, tools/api/auth.py:30-36); never port-forward it
- [ ] MCP HTTP servers run loopback-only unless the two-person rule
      (`MCP_ALLOW_PUBLIC_BIND`) is consciously invoked (docs/mcp-tools.md:19)
- [ ] `engine_mcp.host: 127.0.0.1` (config.yaml:56)

**Secrets & environment**

- [ ] `OLLAMA_API_KEY` (and optionally `NVD_API_KEY`, `GITHUB_TOKEN`,
      `SERPAPI_API_KEY`) set in the environment or `secr.json`, never in
      tracked files (README.md:151-157; `.gitignore:37-42`)
- [ ] No `.env`/`secr.json`/`.webui_secret_key` in git (`git status` clean of
      those paths)

**Operational**

- [ ] `python main.py --doctor` exits 0 and `python main.py --self-test`
      passes on the deploy target (README.md:164-172)
- [ ] Command timeouts in place (300s terminal / 300s python / 600s msf) —
      these are unconditional operational guards (README.md:260-263)
- [ ] `reports/` + `exploit_workspace/` backed up off-box (audit chain is the
      evidence record)
- [ ] Linux: `nmap.sudo`/`priv_fallback` decided for the deploy account
      (config.yaml:62-65)

## Deployment decision table

| Scenario | Recommendation |
|---|---|
| Windows operator, no Kali tools | `install.bat` (or venv + `requirements.txt`); Python-only exploits; embed host `http://localhost:11434` |
| Linux operator, full Kali arsenal | `./install.sh` (primary; `INSTALL_KALI_TOOLS=1 ./install.sh` for searchsploit/Metasploit/hydra/impacket; `scripts/setup-linux.sh` is the lightweight alternative); decide `nmap.sudo` |
| Cloud-first LLM (default) | `ollama.host: https://api.ollama.com` + `OLLAMA_API_KEY`; embeddings stay local via `embed_host` |
| Air-gapped / local LLM | `ollama.host: http://localhost:11434`, `ollama pull glm-5.2:cloud` + `nomic-embed-text`; no API key needed |
| Headless service (API only) | `--daemon` (optionally `--api-port`), daemonized via systemd/NSSM; skip the SPA |
| SPA served locally | `--web` (builds `webui/dist/` once; requires Node/npm at build time only) |
| Long multi-hour campaigns | `--long-session` (config.yaml:319-326: real context window, 600s LLM timeout, checkpoints) |
| Benchmarking | `--eval` → `reports/eval/<run_id>/` (config.yaml:305-310) |
| Flow B research missions | `cli.py` + `mission.yaml`; state in `research_workspace/` (SQLite) |

## Further reading

- [`docs/getting-started.md`](getting-started.md) — setup, first commands, dev loop
- [`docs/api.md`](api.md) — WebUI API daemon, auth, WS handshake
- [`docs/webui.md`](webui.md) — the SPA and its build/dev loop
- [`docs/safety-model.md`](safety-model.md) — permission model, allowlist, audit
- [`README.md`](../README.md) — config reference and CLI surface
