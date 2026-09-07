# Troubleshooting

Practical fixes for the failures you will actually hit, organized by symptom.
Every entry lists the symptom, the likely cause, an exact check command, and
an exact fix. When in doubt, start with the diagnostics table below — the
`--doctor` check names the failing subsystem and prints its own hint.

## Diagnostics at a glance

| Command | What it checks | Exit code |
|---|---|---|
| `python main.py --doctor` | Python >= 3.11, imports, nmap binary, workspace writable, config validity, Ollama reachability + model registry, MCP/WebUI port free, (Linux) root/sudo + Kali tooling | 0 = all pass, 1 = any fail (`tools/doctor.py:305`) |
| `python main.py --self-test` | Safe localhost-only smoke test; writes `reports/self_test_<run_id>/self_test_report.{json,md}` | 0 = pass, 1 = fail (`tools/self_test.py:65`) |
| `python -m pytest tests/ -v` | Full suite (~250 files, all mocked — no live nmap/network) | 0 = pass |
| `ruff check .` | Lint (line-length 120, E/F/W/I, E501 ignored) | 0 = clean |
| `python main.py --setup-api-keys` | Prompt for provider keys, save to `secr.json` (gitignored) | — |

`--doctor` and `--self-test` are mutually exclusive with each other and with
`--web`/`--demon`/`--menu`/`--demo`/`--eval` — combining them exits 2
(`main.py:838`).

## 1. Setup problems

### Python version too old

- **Symptom:** `--doctor` reports `[FAIL] python_version`.
- **Cause:** the doctor requires Python >= 3.11 (`tools/doctor.py:31`,
  `pyproject.toml` `requires-python = ">=3.11"`, CI matrix 3.11–3.13).
- **Check:** `python --version`
- **Fix:** install Python >= 3.11 from https://www.python.org/downloads/ and
  recreate the venv:
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  python -m pip install -r requirements.txt
  ```

### Missing dependencies / import errors

- **Symptom:** `--doctor` reports `[FAIL] python_imports` listing `yaml`,
  `ollama`, `mcp`, `uvicorn`, `websockets`, `questionary`, `pytest`; or a
  startup `ModuleNotFoundError`.
- **Cause:** deps not installed in the active venv (`tools/doctor.py:45`).
- **Check:** `python -m pip list | findstr /i "ollama mcp uvicorn"` (Windows)
  or `python -m pip list | grep -iE "ollama|mcp|uvicorn"` (Linux/macOS)
- **Fix:**
  ```powershell
  python -m pip install -r requirements.txt
  python -m pip install -e ".[dev]"   # adds ruff + pytest + coverage
  ```
  If the MCP SDK import fails at session start you get
  `RuntimeError: The MCP Python SDK is not installed. Run: python -m pip install -r requirements.txt`
  (`tools/mcp_session.py:245`).

### nmap not found

- **Symptom:** `--doctor` reports `[FAIL] nmap_binary` with
  `nmap 'nmap' not on PATH`.
- **Cause:** nmap missing, or installed somewhere not on PATH.
- **Check:** `nmap --version` (or `where nmap` on Windows)
- **Fix:** install it, or point the doctor at it via config:
  ```bash
  # Debian/Ubuntu
  sudo apt install nmap
  # macOS
  brew install nmap
  ```
  ```yaml
  # config.yaml
  nmap:
    path: /usr/local/bin/nmap
  ```
  The doctor honors `nmap.path` (`tools/doctor.py:66`).

### nmap needs root on Linux (`-O` / `-sS` fail)

- **Symptom:** scans fail with `requires root` / `raw socket` /
  `cap_net_raw` / `must be run as root`; `--doctor` prints a
  `linux_privilege` note.
- **Cause:** OS detection (`-O`) and SYN scans (`-sS`) need root or
  CAP_NET_RAW. The defensive server's service scan uses `-O`
  (`tools/doctor.py:82`).
- **Check:** `id -u` (0 = root); `sudo -n true; echo $?` (0 = passwordless
  sudo works)
- **Fix:** one of:
  ```yaml
  # config.yaml — run root-only scans via sudo -n (needs passwordless sudo)
  nmap:
    sudo: true
  ```
  or run as root. Otherwise `nmap.priv_fallback` (default true) auto-downgrades
  `-sS` to `-sT` and strips `-O` with a note (`tools/nmap_priv.py:70`). With
  `sudo: true` and no passwordless sudo, `sudo -n` fails fast instead of
  hanging on a password prompt (`tools/nmap_priv.py:79`).

### OLLAMA_API_KEY missing → auth failure on first chat

- **Symptom:** `--doctor` reports `[FAIL] ollama_reachable` (401) against
  `https://api.ollama.com`; or the first LLM call fails with an auth error.
- **Cause:** the default model path is Ollama Cloud; the ollama client
  auto-attaches `Authorization: Bearer $OLLAMA_API_KEY` to every request, so
  a missing key 401s on the first chat (`tools/model_router.py:287`,
  `tools/doctor.py:145`). Keys are read from **process environment variables
  or `secr.json`** — there is no `.env` auto-load.
- **Check:** `echo $env:OLLAMA_API_KEY` (PowerShell) /
  `echo $OLLAMA_API_KEY` (bash); or `python main.py --doctor` and read the
  `ollama_reachable` line.
- **Fix:**
  ```bash
  python main.py --setup-api-keys      # prompts + writes secr.json (gitignored)
  ```
  or export it in your shell before running. Startup also loads saved keys
  from `secr.json` into the environment (`tools/api_key_store.py:199`,
  `tools/config_cli.py:175`).

### Cloud vs local Ollama host

- **Symptom:** you want a local daemon but the app keeps hitting the cloud;
  or the doctor pings the wrong host.
- **Cause:** `ollama.host` defaults to `https://api.ollama.com`; a host swap
  is the whole wiring — no probe, no local→cloud fallback
  (`tools/config_manager.py:30`, `tools/model_router.py:290`).
- **Check:** `python main.py --doctor` shows the host it pings.
- **Fix:**
  ```yaml
  # config.yaml
  ollama:
    host: http://localhost:11434
  ```
  Embeddings stay local by default via `ollama.embed_host` (falls back to
  `ollama.host` when absent). Local daemons ignore the Authorization header,
  so sending it unconditionally is safe (`tools/doctor.py:148`).

### Missing local model

- **Symptom:** `--doctor` reports `[FAIL] model_registry` with a
  `ollama pull <spec>` hint.
- **Cause:** a configured local model isn't pulled. Cloud models
  (`*:cloud`) are verified by a 1-token generation instead — `ollama pull`
  only registers a pointer and isn't a real test (`tools/doctor.py:206`,
  `tools/doctor.py:361`).
- **Check:** `ollama list`
- **Fix:** `ollama pull <spec>` for local models; for cloud models run
  `ollama run <spec>` once to register + verify. The doctor self-heals
  missing cloud models by pinging them via `/api/generate`
  (`tools/doctor.py:361`).

## 2. Startup failures

### config.yaml invalid

- **Symptom:** `--doctor` reports `[FAIL] config_valid` with a list of
  errors; or startup aborts with
  `ValueError: Config validation failed: ...`.
- **Cause:** YAML parse error, non-mapping root, or a type/range violation
  (e.g. `api.port` not in 1-65535, `eval.enabled` not a boolean). The
  validator reports per-key errors (`tools/config_manager.py:544`); the
  strict loader raises on any error (`tools/config_manager.py:1043`).
- **Check:**
  ```bash
  python main.py --doctor          # prints errors + warnings + unknown keys
  ```
  or directly:
  ```bash
  python -c "from tools.config_manager import validate_config_file; r = validate_config_file('config.yaml'); print(r.errors)"
  ```
- **Fix:** correct the reported keys in `config.yaml`. The doctor's
  `_check_config` uses the real validator — a parseable-but-broken YAML
  reports `ok: False`, not a false green (`tools/doctor.py:262`).

### Import error at startup

- **Symptom:** `ModuleNotFoundError` / `ImportError` before the menu shows.
- **Cause:** missing dep (see §1) or a broken editable install.
- **Check:** `python -c "import yaml, ollama, mcp, uvicorn, questionary"`
- **Fix:** `python -m pip install -r requirements.txt`; if that fails,
  reinstall editable metadata: `python -m pip install -e ".[dev]"`.

### Port already in use (MCP 8001 / WebUI 8765)

- **Symptom:** `--doctor` reports `[FAIL] port_8001_free` /
  `port_8080_free`; or session start fails with
  `Exploit MCP HTTP port 8001 is already in use. Stop the process using it.`
  (`tools/mcp_session.py:617`); or the daemon says it's "already running".
- **Cause:** an orphaned server or another app holds the port.
- **Check:** `netstat -ano | findstr :8001` (Windows) /
  `lsof -i :8001` (Linux/macOS) — the doctor prints this hint itself
  (`tools/doctor.py:294`).
- **Fix:** stop the holder, or move the port:
  ```yaml
  # config.yaml
  mcp:
    http_port: 8002
  api:
    port: 8766
  ```
  The WebUI daemon also refuses non-loopback binds:
  `--api-host must be loopback (127.0.0.1/localhost/::1)` (`main.py:516`,
  `tools/api/auth.py:30`).

## 3. Runtime failures

### MCP subprocess death hidden by `except Exception`

- **Symptom:** a session dies with no visible error, or an error that a bare
  `except Exception` should have caught never fires; the CLI prints
  `Exploitation session failed unexpectedly` and points at
  `reports/<run_id>/session_error.log` (`main.py:779`).
- **Cause:** anyio task groups raise `BaseExceptionGroup` (PEP 654) on
  subprocess death, which is **not** a subclass of `Exception`. Bare
  `except Exception` silently misses it.
- **Check:** the session error log; look for `ExceptionGroup` /
  `BaseExceptionGroup` in the traceback.
- **Fix:** any code wrapping `stdio_client` / `streamable_http_client` /
  `ClientSession.initialize()` must catch `_EXC_GROUP_CATCH` and unpack with
  `_is_exception_group` + `_log_nested_exceptions` from
  `tools/exceptions.py:15` (the tuple is `(Exception, BaseExceptionGroup)`
  on 3.11+, `tools/exceptions.py:38`). Reference pattern:
  ```python
  from tools.exceptions import _EXC_GROUP_CATCH, _is_exception_group, _log_nested_exceptions
  try:
      ...
  except _EXC_GROUP_CATCH as exc:
      if _is_exception_group(exc):
          _log_nested_exceptions(exc)
  ```
  Existing correct call sites: `main.py:779`, `tools/mcp_session.py:188`,
  `tools/api/run_manager.py:243`, `tools/exploit_agent/model_client.py:35`.

### LLM server disconnected / timeouts

- **Symptom:** `ERROR: LLM server disconnected after retries. Last error: ...`
  or repeated `[MODEL RETRY <provider> n/3]` lines.
- **Cause:** transient network errors (httpx `ReadTimeout`, `ConnectError`,
  `RemoteProtocolError`) against the active model provider.
- **Check:** `python main.py --doctor` (probes the active provider only);
  watch the retry lines — 3 retries with exponential backoff
  (`tools/exploit_agent/model_client.py:35`).
- **Fix:** confirm the backend is up and the key is set (§1); for long
  generations use `--long-session`, which raises the LLM call timeout
  (`config.yaml` `long_session.request_timeout_seconds`, default 600).
  Retryable errors are matched in `tools/exploit_agent/model_client.py`.

### Command timeouts

- **Symptom:** tools return `timed out after 300s` (terminal/python/msfvenom)
  or `secretsdump timed out after 300s` etc.
- **Cause:** the operational command timeout (default 300s terminal/python,
  600s msf) killed a long-running command.
- **Check:** `config.yaml` → `exploit.command_timeout_seconds` (default 300,
  `tools/config_manager.py:114`).
- **Fix:** raise the budget for the run:
  ```yaml
  exploit:
    command_timeout_seconds: 600
  ```
  or use `--long-session` which raises round/command/duration budgets
  (`tools/cli_exploit_settings.py:116`).

### No targets in allowlist → target lock blocks every tool

- **Symptom:** every target-touching tool returns
  `Target <ip> is not in the explicit allowlist. Add it to config.yaml exploit.allowed_targets to authorize.`
  or `require_explicit_allowlist is True but allowed_targets is empty`.
- **Cause:** the target-IP allowlist lock is the one attack-mode safety,
  enforced at the MCP tool layer, not in policy. The effective list is
  `exploit.allowed_targets` UNION the runtime env vars `EXPLOIT_TARGET`,
  `EXPLOIT_TARGET_IP`, `EXPLOIT_TARGET_DOMAIN`, `EXPLOIT_DISCOVERED_TARGETS`
  (`tools/mcp_shared.py:494`). With `require_explicit_allowlist: true` and an
  empty list, everything is blocked (`tools/mcp_shared.py:558`).
- **Check:** `python main.py --doctor` (config section); or
  ```bash
  python -c "from tools.mcp_shared import _allowed_target_list; print(_allowed_target_list(__import__('yaml').safe_load(open('config.yaml'))))"
  ```
- **Fix:** pass `--target <ip>` (it is unioned in via `EXPLOIT_TARGET`,
  `tools/mcp_session.py:255`), or add the host to config:
  ```yaml
  exploit:
    require_explicit_allowlist: true
    allowed_targets:
      - 10.0.0.50
      - 10.0.0.0/24        # CIDR and *.wildcard supported
  ```
  Callback/C2 hosts must be added explicitly; domain enumeration
  auto-authorizes discovered hosts via `add_discovered_target`
  (`tools/mcp_shared.py:537`). The lock itself lives in
  `tools/mcp_tools/terminal.py:57` (`_target_lock_block`).

### MCP server fails to boot (stdio/http)

- **Symptom:** `MCP HTTP server failed to start on port 8001: ...` or the
  boot spinner times out after 30s (`MCP_BOOT_TIMEOUT_SECONDS`,
  `tools/mcp_session.py:33`).
- **Cause:** the exploit server subprocess crashed at import, or the port is
  taken, or a heavy import exceeded the boot window.
- **Check:** the server log tail is printed in the error; also
  `exploit_workspace/<ip>/mcp_exploit_server.log`.
- **Fix:** fix the underlying import/port issue (§1, §2). The recon-first
  path tolerates MCP being unavailable (soft-fail → `[WARN]`, session
  degrades to a minimal assessment) but a hard import failure still aborts
  (`tools/mcp_session.py:228`).

## 4. Test failures

### Tests need live nmap / network

- **Symptom:** a test fails with `nmap not found` or tries to reach the
  network.
- **Cause:** you ran a test that isn't mocked — but the whole suite is
  designed to be offline. All ~250 tests mock subprocess/network; no live
  Nmap, no live network (README §Testing).
- **Check:** `python -m pytest tests/ -v`
- **Fix:** nothing to install. If a specific test still hits the network,
  it's a bug — report it. Run a single file:
  ```bash
  python -m pytest tests/test_doctor.py -v
  python -m pytest tests/ -v -k "scope"
  ```

### Async tests fail with "no running event loop" / coroutine warnings

- **Symptom:** `RuntimeError: no running event loop` or
  `coroutine ... was never awaited`.
- **Cause:** pytest isn't picking up the asyncio plugin config.
- **Check:** `pyproject.toml` has `asyncio_mode = "auto"` and
  `testpaths = ["tests"]` (`pyproject.toml:81`).
- **Fix:** ensure pytest + pytest-asyncio are installed:
  `python -m pip install -e ".[dev]"`. With `asyncio_mode = "auto"` you do
  not need `@pytest.mark.asyncio` on every test.

### Lint failures

- **Symptom:** `ruff check .` reports E/F/W/I violations.
- **Cause:** style drift; config is line-length 120, `select = ["E","F","W","I"]`,
  `ignore = ["E501"]`.
- **Check:** `ruff check .`
- **Fix:** `ruff check . --fix` for auto-fixable issues; manually fix the
  rest. CI enforces this on every push/PR (`.github/workflows/ci.yml`:
  `ruff check .` + `ruff format --check .` + `mypy --follow-imports=skip tools`
  + mocked pytest on 3.11–3.13) — run it before a PR.

## 5. WebUI issues

### `webui/dist/` missing or stale

- **Symptom:** `--web` fails with `Node/npm not found on PATH` or
  `npm install exited 1`, or the SPA shows old content.
- **Cause:** first `--web` run builds `webui/dist/`; it needs Node.js + npm
  (`main.py:436`). The build is skipped when `dist/index.html` exists.
- **Check:** `Test-Path webui\dist\index.html` (Windows) /
  `test -f webui/dist/index.html` (Linux)
- **Fix:**
  ```bash
  cd webui
  npm install
  npm run build
  cd ..
  python main.py --web
  ```
  The auto-build runs `npm install --no-audit --no-fund` then
  `npm run build` with a 600s timeout (`main.py:449`).

### Port conflict / daemon already running

- **Symptom:** `WebUI API daemon is already running on http://127.0.0.1:8765`
  or bind errors.
- **Cause:** another daemon instance holds the port (default 8765,
  `tools/config_manager.py:468`).
- **Check:** `netstat -ano | findstr :8765` (Windows) /
  `lsof -i :8765` (Linux/macOS)
- **Fix:** when the "already running" message appears in an interactive
  terminal, press `K` to kill the old daemon and start a fresh one (Enter
  keeps it). Otherwise stop the other instance manually, or change the port:
  ```yaml
  api:
    port: 8766
  ```
  `--api-port` overrides it per-run (`main.py:514`). Only one run can be
  active at a time — a second run returns HTTP 409
  (`tools/api/run_manager.py:120`).

### Token auth failures (401)

- **Symptom:** API/WebSocket calls return 401; the SPA can't connect.
- **Cause:** every route except `/health` requires a bearer token. The token
  is auto-generated into `.webui_secret_key` (gitignored) on first boot, or
  overridden by `BREACHPILOT_API_TOKEN` (`tools/api/auth.py:39`). WebSocket
  clients must send `{"auth": "<token>"}` as the first message or get closed
  with 4401 (`tools/api/auth.py:8`).
- **Check:** `Get-Content .webui_secret_key` (Windows) /
  `cat .webui_secret_key` (Linux)
- **Fix:** set a stable token:
  ```powershell
  $env:BREACHPILOT_API_TOKEN = "your-token"
  python main.py --web
  ```
  or delete `.webui_secret_key` to regenerate. The token is never logged or
  returned through the API.

### Sandbox / execution failures (`SANDBOX_*`, fallback banner)

- **Symptom:** tool results contain `SANDBOX_*` errors; WebUI home shows amber
  "Sandbox unavailable"; results contain a `SANDBOX_FALLBACK:` line.
- **Cause:** sandbox is default-on (`sandbox.enabled: true`). Mid-session
  sandbox failures fail closed (offensive execution blocked, no host
  fallback). At boot, an unusable Docker stack (CLI missing, daemon down,
  image not built) degrades the whole session to legacy native mode when
  `sandbox.fallback_native: true` (default) — warning + banner + per-result
  `SANDBOX_FALLBACK:` line. See `docs/sandbox.md`, README §Safety model.
- **Check:** `docker info`, `docker images | findstr breachpilot-sandbox`
  (Windows) / `docker images | grep breachpilot-sandbox` (Linux);
  `python main.py --doctor` verifies Docker + worker image when enabled.
- **Fix:** `docker build -t breachpilot-sandbox:latest docker/sandbox` and
  start the Docker daemon/Desktop. For strict fail-closed posture set
  `sandbox.fallback_native: false` (executions denied until Docker works);
  `sandbox.enabled: false` is the explicit uncontained opt-out.

### Single-run conflict (409) / audit tamper warning / MCP boot timeout

- **Symptom:** second run returns HTTP 409; audit verification warns of a
  broken hash chain; MCP session fails after ~30s with a redacted
  `mcp_exploit_server.log` tail.
- **Cause:** only one run active at a time by default
  (`api.max_concurrent_runs: 3`, legacy single-run = 409 in
  `tools/api/run_manager.py`); tamper-evident audit chain detects edits;
  MCP boot budget is 30s (`MCP_BOOT_TIMEOUT_SECONDS`, `tools/mcp_session.py`).
- **Check:** WebUI runs page / `reports/<run_id>/activity.jsonl`;
  `exploit_workspace/<target>/<attempt>/exploit_audit.jsonl`.
- **Fix:** wait/cancel the active run or raise `api.max_concurrent_runs`;
  never hand-edit audit JSONL; re-run `--doctor` for MCP boot causes.

## 6. Platform-specific

### Windows

- **Symptom:** `make install` / `make test` fail; exploit tools like
  `searchsploit`/`msfconsole` are missing.
- **Cause:** Makefile targets don't run on Windows (AGENTS.md §Commands);
  the Windows attacker profile is Python-only — the exploit agent's system
  prompt is OS-aware and pivots to workspace Python implementations
  (`tools/env_probe.py:43`).
- **Check:** `python main.py --doctor` — `linux_privilege` reports
  `n/a (Windows)` and `optional_tools` lists what's missing
  (informational, never a failure, `tools/doctor.py:114`).
- **Fix:** use the PowerShell commands from §1. For missing tools the agent
  writes Python fallbacks instead of attempting `apt_install` — the
  pre-flight probe tells it up front which tools to pivot on
  (`tools/env_probe.py:67`). `sudo` is never used on Windows
  (`tools/nmap_priv.py:91`, `tools/env_probe.py:54`).

### Linux / macOS

- **Symptom:** `-O`/`-sS` scans fail as non-root; `apt_install` hangs on a
  password prompt.
- **Cause:** root-only nmap flags (§1) and interactive sudo.
- **Check:** `id -u`; `sudo -n true; echo $?`
- **Fix:** set `nmap.sudo: true` (uses `sudo -n`, fails fast without
  passwordless sudo) or run as root. The tool layer pre-checks
  `_can_passwordless_sudo` and returns a `BLOCKED:` pivot message instead of
  spawning a hanging `sudo` (`tools/mcp_tools/terminal.py:97`). Full Kali
  arsenal (searchsploit/metasploit/hydra/crackmapexec/impacket) is expected
  on Linux; `scripts/setup-linux.sh` bootstraps venv + deps + doctor.

## 7. Daemon, auth, sandbox, benchmark, vault, and live events

| Symptom | Entry |
|---|---|
| `--daemon/--web cannot be combined with ...`, exit 2 | [Daemon flag conflicts](#daemon-flag-conflicts-exit-2) |
| `--api-host must be loopback`, exit 2 | [Non-loopback bind refusal](#non-loopback-bind-refusal) |
| `Unauthorized: MCP_HTTP_TOKEN required` on HTTP MCP | [MCP_HTTP_TOKEN mismatch](#mcp_http_token-mismatch) |
| Skill hints rebuild every few actions (prompt churn) | [Skill reselect storms](#skill-reselect-storms) |
| `Docker sandbox unavailable ... falling back to NATIVE` | [Sandbox Docker unavailable](#sandbox-docker-unavailable-fallback_native) |
| Benchmark trials `INFRASTRUCTURE_ERROR (SANDBOX_FAILED)` | [Benchmark sandbox_required refusal](#benchmark-sandbox_required-refusal) |
| Credential store plaintext WARNING on startup | [.vault_key plaintext fallback](#vault_key-plaintext-fallback-warning) |
| WebUI event stream reconnects after ~90s silence | [SSE 90s watchdog](#sse-90s-watchdog-reconnects) |

### Daemon flag conflicts (exit 2)

- **Symptoms:** `--demon/--daemon/--web cannot be combined with: --target, ...`
  and the process exits 2 (`main.py:1391`).
- **Cause:** the daemon gate fires before `--doctor`/`--self-test`/target-run
  handling and rejects any run-describing or mode flag alongside daemon mode
  (`--target`, `--mode`, `--goal`, `--custom-goal`, `--menu`, `--doctor`,
  `--demo`, `--self-test`, `--skills-list`, `--list-plugins`,
  `--setup-api-keys`, `--eval`, `--benchmark`; `main.py:1372`).
- **Check:** re-read the error — it names the exact conflicting flags.
- **Fix:** run the daemon alone, then run assessments separately:
  ```bash
  python main.py --daemon
  python main.py --target 10.0.0.50 --mode recon
  ```

### Non-loopback bind refusal

- **Symptoms:** `--api-host must be loopback (127.0.0.1/localhost/::1); got
  ...` and exit 2 (`main.py:962`); the API layer raises the same refusal as a
  `ValueError` (`tools/api/auth.py:41`).
- **Cause:** v1 is loopback-only by design — there is no public-bind override
  (`main.py:962` comment, `tools/api/auth.py:41` docstring).
- **Check:** inspect the effective host:
  ```bash
  python -c "from tools.config_manager import load_config; print(load_config('config.yaml').get('api', {}).get('host'))"
  ```
- **Fix:** bind loopback only:
  ```yaml
  # config.yaml
  api:
    host: 127.0.0.1
    port: 8765
  ```

### MCP_HTTP_TOKEN mismatch

- **Symptoms:** HTTP-transport MCP calls fail with
  `Unauthorized: MCP_HTTP_TOKEN required` (`tools/mcp_shared.py:471`).
- **Cause:** the server wraps its HTTP app in bearer auth whenever
  `MCP_HTTP_TOKEN` is set (`tools/mcp_shared.py:493`), and the live client
  attaches `Authorization: Bearer <token>` only when its own env has the same
  value (`tools/mcp_session.py:518`, `:760`). Set on one side but missing or
  different on the other = every call 401s.
- **Check:** confirm the variable is present (not its value) in both
  environments:
  ```bash
  python -c "import os; print('server-side sees token:', bool(os.environ.get('MCP_HTTP_TOKEN', '').strip()))"
  ```
- **Fix:** export the identical value for the daemon and the MCP server
  subprocess (it inherits the daemon env), then restart:
  ```bash
  export MCP_HTTP_TOKEN="a-long-random-value"
  python main.py --daemon
  ```

### Skill reselect storms

- **Symptoms:** skill guidance blocks churn every few actions mid-run instead
  of settling.
- **Cause:** mid-run reselection fires on every newly observed service/CVE
  unless the rate guards stop it: capped at `reselect_max_per_run` (default 3)
  with at least `reselect_min_interval_actions` (default 5) between rebuilds,
  and skipped entirely when the rebuilt set is identical
  (`tools/exploit_agent/skills.py:44`, guards at `:67`; defaults in
  `tools/config/schema.py:719`).
- **Check:** read your `skills:` block in `config.yaml`.
- **Fix:** tighten the guards or disable mid-run reselection:
  ```yaml
  # config.yaml
  skills:
    reselect_mid_run: true
    reselect_max_per_run: 3
    reselect_min_interval_actions: 5
  ```
  Set `reselect_mid_run: false` if recon output keeps tripping rebuilds with
  no benefit.

### Sandbox Docker unavailable (`fallback_native`)

- **Symptoms:** boot log says
  `Docker sandbox unavailable (<reason>) -- falling back to NATIVE
  (uncontained) legacy host execution for this session` and tool results carry
  `SANDBOX_FALLBACK:` lines (`tools/sandbox/manager.py:108`,
  `tools/mcp_tools/sandbox_exec.py:187`).
- **Cause:** Docker CLI missing, daemon down, or the worker image not built,
  with `sandbox.fallback_native: true` degrading the whole session to native
  mode (decision in `tools/sandbox/__init__.py:18`; notice text in
  `tools/sandbox/manager.py:104`).
- **Check:**
  ```bash
  docker info
  docker images | grep breachpilot-sandbox
  ```
- **Fix:** start the Docker daemon and build the worker image
  (`docker build -t breachpilot-sandbox:latest docker/sandbox`), or fail
  closed instead:
  ```yaml
  # config.yaml
  sandbox:
    enabled: true
    fallback_native: false
  ```

### Benchmark `sandbox_required` refusal

- **Symptoms:** every trial is marked
  `INFRASTRUCTURE_ERROR (SANDBOX_FAILED)` with a `sandbox_unavailable` error
  event whose detail reads
  `sandbox_required=true but sandbox.enabled=false; ... There is no
  host-execution fallback` (`tools/benchmark/runner.py:180`).
- **Cause:** `sandbox_required` defaults to true on both the environment and
  run configs (`tools/benchmark/models.py:293`, `:313`) while
  `sandbox.enabled` is false — benchmarks refuse to run uncontained.
- **Check:** `sandbox.enabled` in `config.yaml` versus the benchmark request's
  `sandbox_required` (`tools/benchmark/service.py:113`).
- **Fix:** enable the sandbox (see previous entry), or explicitly opt the
  benchmark run out of containment:
  ```bash
  python main.py --benchmark xben --no-sandbox-required
  ```
  Implementation note: verify the exact CLI flag spelling with
  `python main.py --help` — the config/request key is `sandbox_required`, but
  the flag wrapper lives in `tools/benchmark_cli.py` and was not re-read here.

### `.vault_key` plaintext fallback warning

- **Symptoms:** a loud one-time WARNING that the credential store will be
  written in PLAINTEXT (`tools/credential_store.py:167`, warnings at
  `:195`).
- **Cause:** the `_Vault` falls back to plaintext when `cryptography` is not
  installed, no usable key is found (`AI_NMAP_VAULT_KEY` env, then
  `~/.breachpilot/vault_keys/`, then the legacy in-workspace `.vault_key`
  adopted once), or the key material is invalid (`tools/credential_store.py:17`,
  `:195`). Legacy plaintext values still load so existing stores never brick
  (`:32`).
- **Check:**
  ```bash
  python -c "import cryptography; print(cryptography.__version__)"
  python -c "import os; print('vault key set:', bool(os.environ.get('AI_NMAP_VAULT_KEY')))"
  ```
- **Fix:** install the dependency and set a persistent key:
  ```bash
  python -m pip install cryptography
  export AI_NMAP_VAULT_KEY="$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")"
  ```
  Never commit keyfiles — the `.vault_key` basename is deny-listed from
  workspace reads (`tools/credential_store.py:181`).

### SSE 90s watchdog reconnects

- **Symptoms:** the WebUI live-event stream drops to `reconnecting` after
  ~90s of silence, then resumes; the run itself keeps going.
- **Cause:** client-side watchdogs force-reconnect a silently dead socket —
  90s for SSE (`webui/src/api/sse.ts:77`) and 45s-stale/90s-timeout for WS
  (`webui/src/api/ws.ts:25`). The server side is `text/event-stream` with
  no-cache/keep-alive headers (`tools/api/routes/events.py:119`) backed by a
  ring buffer explicitly kept for reconnects
  (`tools/api/event_broker.py:6`), and a browser disconnect does NOT cancel
  the run (`tools/api/routes/events.py:132`).
- **Check:** browser devtools → Network → the `text/event-stream` request;
  confirm the run is still progressing via `GET /api/v1/runs/{id}`.
- **Fix:** usually none needed — the client resubscribes with `after=<seq>`
  and replays missed events. If reconnects are chronic, suspect a proxy or
  idle-timeout killing long-lived streams (the server already sends
  `X-Accel-Buffering: no`); prefer the WS transport or bypass the proxy for
  `127.0.0.1:8765`.
  ```bash
  curl -N -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
    "http://127.0.0.1:8765/api/v1/runs/<run_id>/events" | head -n 20
  ```

### Related documentation

- [config-reference.md](config-reference.md), [run-service.md](run-service.md), [api.md](api.md), [sandbox.md](sandbox.md), [benchmarks.md](benchmarks.md), [skills.md](skills.md), [webui.md](webui.md)

### Source map

- `main.py`, `app.py`
- `tools/api/auth.py`, `tools/api/event_broker.py`, `tools/api/routes/events.py`
- `tools/mcp_shared.py`, `tools/mcp_session.py`
- `tools/exploit_agent/skills.py`, `tools/skill_embeddings.py`, `tools/config/schema.py`
- `tools/sandbox/__init__.py`, `tools/sandbox/manager.py`, `tools/sandbox/models.py`, `tools/mcp_tools/sandbox_exec.py`
- `tools/benchmark/service.py`, `tools/benchmark/models.py`, `tools/benchmark/runner.py`, `tools/benchmark_cli.py`
- `tools/credential_store.py`
- `webui/src/api/sse.ts`, `webui/src/api/ws.ts`

Implementation note: the `--no-sandbox-required` flag spelling above was not
re-verified against `tools/benchmark_cli.py` — confirm with
`python main.py --help` before relying on it; the underlying
`sandbox_required` request key (`tools/benchmark/service.py:113`) is verified.
