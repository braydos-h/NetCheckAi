# CLI Reference

Complete reference for every command-line entry point, flag, interactive option, and environment
variable in BreachPilot. See `docs/getting-started.md` for setup and first commands.

## Entry Points

There are three top-level Python entry points, one per flow (see AGENTS.md Flow A / Flow B):

| Command | Flow | Purpose |
|---------|------|---------|
| `python main.py` | Flow A (modern, what users run) | **WebUI daemon + browser by default** (no args), direct recon/attack runs, doctor/self-test/eval/demo, API-only daemon, `--menu` terminal menu |
| `python app.py` | Flow A | ASGI app factory — **not a CLI**; imported by `main._run_daemon`, never run directly |
| `python cli.py` | Flow B (legacy, SQLite-backed) | Database-backed mission/scope/task/finding/report workflow commands |

`app.py` contains no argument parser; it is invoked as `python main.py --demon` which imports
`create_app` and serves it with uvicorn (`main._run_daemon`).

The MCP servers are separate entry points: `python mcp_server.py` (defensive),
`python mcp_exploit_server.py` (exploit, target-lock enforced), `python mcp_engine_server.py`
(engine advisory). All accept `--transport stdio|http`, `--config`, `--host`, `--port`
(`mcp_exploit_server.py:203-209`).

## `python main.py` — Flow A

Argument parser: `main.parse_args`. Dispatch order in `main()`: API-key bootstrap →
`--setup-api-keys` exit → daemon (`--demon`/`--daemon`/`--web`) → `--doctor` → `--self-test` →
`--eval-list` → `--eval` → `--ctf` → `--demo` → `--skills-list` → `--list-plugins` → `--menu` (terminal menu) →
**no-args default (WebUI daemon, `--web`)** → `async_main`.

### Run flags

Parser group: **targeting** (plus `--version`). The "Group" column names the argparse
argument group in `main.parse_args`, so references survive line drift.

| Flag | Default | Description | Group |
|------|---------|-------------|------|
| `--version` | — | Print `BreachPilot <version>` and exit | — |
| `--target <ip-or-domain>` | `""` | Target to attack or recon. Accepts an IP **or a domain** (Phase 4); domains resolve via `tools/validation_utils.resolve_target_to_ip` and thread `EXPLOIT_TARGET`/`EXPLOIT_TARGET_IP`/`EXPLOIT_TARGET_DOMAIN` into the MCP server (AGENTS.md rule 6) | targeting |
| `--mode {recon,attack,fast}` | `""` | `recon` = gather intel only, `attack` = full exploitation, `fast` = parallel recon preset then attack. Recon is always `read_only` (`tools/cli_exploit_settings.py:157-163`) | targeting |
| `--goal <name>` | `""` | Preset goal: `backdoor`, `initial_access`, `privilege_escalation`, … | targeting |
| `--custom-goal <text>` | `""` | Free-text goal description | targeting |
| `--config <path>` | `config.yaml` | Config file path | targeting |
| `--model <alias>` | config default | Override model alias (`glm`/`kimi`/`deepseek`/`deepseek_flash`/`minimax`) | targeting |
| `--model-strategy {default,round-robin,random,specific}` | `default` | How to pick model across targets | targeting |
| `--mcp-transport {stdio,http}` | `None` | MCP transport. Ignored on the run path: always forced to `http` so the target-IP lock reaches the server | targeting |
| `--http-port <n>` | `None` | HTTP port for the MCP server (http transport) | targeting |
| `--reports-dir <path>` | `reports` | Root dir for run artifacts (`reports/<run_id>/`) | targeting |
| `--resume <run_id\|session_id>` | `""` | Resume a prior run by run_id or session_id | operational |

### Swarm / reasoning flags

| Flag | Description | Group |
|------|-------------|------|
| `--swarm` | Multi-agent swarm mode: six specialists decompose a single target (parallel recon + vuln research, critic pre-check, reflection). Without it, attack mode runs the persistent autonomous campaign queue (recon → exploit → privesc → lateral → validation, resume + checkpoints). Combine both on high-value targets. See `docs/swarm.md` ("Swarm vs Campaign") | swarm & reasoning |
| `--parallel-swarm` | Parallel sub-agents (recon + vuln-research parallelize; exploit/post_exploit stay sequential unless `swarm.exploit_parallel`) | swarm & reasoning |
| `--critic` | Critic agent pre-approval (requires `--swarm`) | swarm & reasoning |
| `--reflection` | Reflection agent (requires `--swarm`) | swarm & reasoning |
| `--adaptive-exploits` | Adaptive exploit generation with mutation on failure | swarm & reasoning |
| `--long-session` | Raise context window, LLM call timeout, round/command/duration budgets, and the swarm cap for multi-hour runs; checkpointed messages for crash-safe resume | swarm & reasoning |
| `--multi-model-consult` / `--no-multi-model-consult` | Allow / forbid the agent asking configured peer models for advisory help | swarm & reasoning |
| `--observer-mode {heuristic,llm,hybrid}` | Observer fact-extraction mode (default `hybrid`) | swarm & reasoning |
| `--recon-first` / `--no-recon-first` | Force recon-first (scan, suggest rated goals, then ask) / skip straight to goal selection | swarm & reasoning |
| `--ultrathink` | Deep reasoning: verbose chain-of-thought and frequent reflection | swarm & reasoning |

### Operational flags

| Flag | Description | Group |
|------|-------------|------|
| `--doctor` | Run the self-check (Python, nmap, Ollama, config) and exit — `tools.doctor.run_doctor` | operational |
| `--self-test` | Run the safe localhost smoke test against `127.0.0.1` and exit — `tools.self_test.run_self_test` | operational |
| `--demo` | Run against a local sandbox target (DVWA via Docker on `127.0.0.1:8081`, synthetic in-process HTTP server as fallback); writes `reports/demo/demo_report.md` (`tools/demo_mode.py`) | operational |
| `--yes` | Skip the ready-to-begin confirmation gate — use with caution | operational |
| `--json` | Machine-readable JSON to stdout where supported; also forces plain output | output |
| `--quiet` | Warnings/errors only; forces plain output | output |
| `--debug` | Verbose debug output; sets `AI_NMAP_DEBUG=1` | output |
| `--plain` | Disable color output (ANSI) | output |
| `--menu` | Force the legacy interactive terminal menu even with other args | output |

### Eval & regression flags

| Flag | Description | Group |
|------|-------------|------|
| `--eval [TARGET ...]` | With target ids: run the graded eval suite (oracle v2) against those `eval_targets/*.oracle.json` targets. Bare `--eval`: all oracle targets — the graded path needs no `--target` and does not exit 2. With `--target <ip>`: the legacy single-target benchmark instead, writing `reports/eval/<run_id>/` (`tools/eval_harness.py:run_eval`, whose exit-2 no-target check only applies to that legacy path) | eval & regression |
| `--eval-list` | Print the graded-eval oracle targets (id + flag count) and exit | eval & regression |
| `--save-baseline` | With `--eval` or `--benchmark`: persist the report as the regression baseline (`eval.baseline_path` / `benchmark.baseline_path`) | eval & regression |
| `--check-regression` | With `--eval` or `--benchmark`: exit 1 when score drops beyond tolerance (`eval.regression_tolerance` / `benchmark` tolerances); fails closed on a missing baseline | eval & regression |

### Benchmark suite flags (`--benchmark`, `tools/benchmark/`)

| Flag | Description | Group |
|------|-------------|------|
| `--benchmark [SUITE ...]` | Run a benchmark suite (bare `--benchmark` = `xben`). Repeatable filters via `--scenario`/`--tag`, repeated trials via `--trials`. Results under `reports/benchmarks/<suite>/<run_id>/`. See `docs/benchmarks.md` | benchmark suite |
| `--benchmark-list` | List registered benchmark suites (id, scenario count, tags) and exit | benchmark suite |
| `--scenario <ID>` | With `--benchmark`: restrict to specific scenario ids (repeatable) | benchmark suite |
| `--tag <TAG>` | With `--benchmark`: restrict to scenarios carrying a tag (repeatable) | benchmark suite |
| `--trials <N>` | With `--benchmark`: repeated trials per scenario (default `benchmark.trials`, 1-20) | benchmark suite |

### API keys / config

| Flag | Description | Group |
|------|-------------|------|
| `--setup-api-keys` | Prompt for provider API keys and save them to the key file; exits after saving (when no other action is requested) | api keys |
| `--api-key-file <path>` | Local JSON file for saved provider API keys (default `secr.json` / `DEFAULT_API_KEY_FILE`) | api keys |
| `--no-api-key-prompt` | Skip the interactive startup API-key prompt | api keys |

Startup key loading lives in `tools/config_cli.py` (`bootstrap_startup_api_keys`) and
`tools/api_key_store.py`. The interactive prompt only fires in `--menu` mode; the WebUI
daemon default and direct runs load keys without prompting.

### Skills / plugins / CTF flags

| Flag | Description | Group |
|------|-------------|------|
| `--skills {on,off,hints,lookup}` | Override runtime-skills behavior: `on`=startup context, `hints`=hints only (default), `lookup`=MCP tools only, `off`=disabled | runtime skills |
| `--skills-list` | Print the read-only runtime-skill catalog and exit | runtime skills |
| `--skills-include <name>` | Force-include a skill for this run. Repeatable (`action="append"`) | runtime skills |
| `--skills-exclude <name>` | Exclude a skill for this run. Repeatable | runtime skills |
| `--no-skills-reselect` | Disable mid-run skill re-selection | runtime skills |
| `--list-plugins` | Print discovered plugins (name/version/capabilities/loaded) and exit | plugins |
| `--ctf` | CTF autopilot: run against `--target` and stop when the goal is heuristically met (flag marker / uid=0 / port-marker) | ctf autopilot |
| `--ctf-flag-path <path>` | CTF goal: flag file path on the target (e.g. `/root/flag.txt`; default empty) | ctf autopilot |
| `--ctf-marker <str>` | CTF known-string marker expected from `--ctf-port` | ctf autopilot |
| `--ctf-port <n>` | CTF port to probe for marker | ctf autopilot |
| `--ctf-root-shell` | CTF: treat `uid=0` in any output as goal-met (default False) | ctf autopilot |

### WebUI / API daemon flags

| Flag | Description | Group |
|------|-------------|------|
| `--demon`, `--daemon` | Start the local WebUI API server instead of the terminal menu (`main._run_daemon`) | webui |
| `--web` | Daemon mode plus: build `webui/dist/` if needed, serve it at `/`, open a browser (`main._ensure_webui_build`) | webui |
| `--api-host <host>` | Daemon bind host — **loopback only** (`127.0.0.1`/`localhost`/`::1`); any other host exits with code 2 | webui |
| `--api-port <n>` | Daemon port (default 8765) | webui |

Daemon mode refuses to combine with target/goal/menu/doctor/demo/eval/self-test/skills-list/
list-plugins/setup-api-keys flags and exits 2 on conflict. The API is served
by the FastAPI factory in `app.py` (`create_app`), mounted under `/api/v1`, bearer-token protected
(`BREACHPILOT_API_TOKEN` env override; `tools/api/auth.py`).

### Interactive menu (`--menu`)

`--menu` (or `ui.ask_advanced_settings` in an interactive session without `--target`) launches the
questionary terminal menu (`tools/interactive_menu.py`):

1. **Recon & Suggest Goals** — recon-first session
2. **Start New Session** — interactive wizard → `async_main`
3. **Manage Missions** — list/create/delete Flow B missions in `research_workspace/research.db`
4. **View Reports** — browse `reports/<run_id>/` sessions
5. **Settings** — write a default `config.yaml` if missing
6. **Help** — quick reference
7. **Exit**

The wizard itself lives in `tools/attack_ui.py`:
`ask_advanced_settings` covers all CLI flags with current values as
defaults; `ask_power_ups` is a multi-select for
swarm/critic/reflection/adaptive-exploits/long-session/ultrathink/debug/yes. When no `--target`
is given, the flow prompts for one and, in interactive sessions, persists it
to `exploit.allowed_targets` in the config (`tools/config_cli.add_target_to_allowlist`).

> **No-args default:** `python main.py` with no arguments starts the **WebUI daemon** (`--web`:
> build `webui/dist/` if needed, serve at `http://127.0.0.1:8765/`, open a browser). It does NOT
> open the terminal menu; use `--menu` for that.

## `python cli.py` — Flow B (SQLite mission workflow)

Subcommands built at `legacy/cli.py:530-598`. All commands except `init-mission` accept
`--mission-id <id>` (placed after the subcommand) to operate on a specific mission instead of
the latest `active` one — the resume/reattach path (`legacy/cli.py:533-544`).

| Command | Flags | Description | Line |
|---------|-------|-------------|------|
| `init-mission` | `--config <path>` (required) | Create a new mission from a YAML config | `cli.py:521` |
| `add-scope` | `--allow <pattern>`, `--deny <pattern>`, `--notes <text>` | Add an allow or deny scope rule (domain, IP, CIDR, `*.wildcard`) | `cli.py:526` |
| `list-scope` | `--mission-id` | Show all scope rules for the active mission | `cli.py:533` |
| `next-task` | `--mission-id` | Show the next pending task | `cli.py:537` |
| `list-tasks` | `--mission-id` | List open (and blocked) tasks | `cli.py:541` |
| `run-task` | `[task_id]` positional (empty = next pending), `--mission-id` | Execute a task through scope gate → risk controller → executor | `cli.py:545` |
| `summarize-target` | `--target <name>`, `--mission-id` | Target memory summary + target graph | `cli.py:550` |
| `list-findings` | `--mission-id` | List all findings with status icons | `cli.py:555` |
| `validate-finding` | `finding_id` positional (e.g. `F-00001`), `--mission-id` | Run validation, print JSON result | `cli.py:559` |
| `generate-report` | `finding_id` positional, `--mission-id` | Generate a markdown report for a finding | `cli.py:564` |
| `status` | `--mission-id` | Agent loop status: mission, risk, task counts, findings | `cli.py:569` |

Examples:

```powershell
python cli.py init-mission --config mission.yaml
python cli.py add-scope --allow "*.example.com" --notes "main scope"
python cli.py add-scope --deny "payments.example.com"
python cli.py next-task
python cli.py run-task T-00001
python cli.py next-task --mission-id M-001     # resume/reattach a paused mission
python cli.py status
```

Data lives in `research_workspace/research.db` (override with `RESEARCH_WORKSPACE`, `cli.py:39-48`).
Exit codes: 0 success, 1 error (including scope/risk blocks that set the task to
`needs_approval`, `cli.py:338-341`), 130 on Ctrl-C (`cli.py:588-590`). No command → help, exit 1
(`cli.py:582-584`).

## Exit Codes

| Code | Meaning | Source |
|------|---------|--------|
| 0 | Success / clean exit | throughout |
| 1 | Run failure, invalid config/target, aborted session, setup-only path | `main.main` / `async_main` error paths; `cli.py` errors |
| 2 | Daemon flag conflicts; non-loopback `--api-host`; `--save-baseline`/`--check-regression` without `--eval` | `main._run_daemon`; `tools/eval_harness.py` |
| 130 | `KeyboardInterrupt` | `main.main`; `cli.py` |

## Example Workflows

```powershell
# Recon-only (read_only permission enforced — tools/cli_exploit_settings.py:157)
python main.py --target 10.0.0.50 --mode recon --goal initial_access

# Recon-first: scan, suggested rated goals, then operator picks
python main.py --target 10.0.0.50 --recon-first

# Full exploit (interactive ready-to-begin gate; --yes skips it)
python main.py --target 10.0.0.50 --mode attack --goal backdoor --yes

# Swarm mission with critic + reflection
python main.py --target 10.0.0.50 --mode attack --swarm --critic --reflection

# Long multi-hour run with checkpointed resume
python main.py --target 10.0.0.50 --mode attack --long-session

# WebUI: build, serve, and open the SPA
python main.py --web

# API daemon only (no SPA build)
python main.py --daemon --api-port 9000

# Diagnostics
python main.py --doctor
python main.py --self-test
python main.py --eval --target 10.0.0.50

# Graded eval suite (oracle v2)
python main.py --eval                # all eval_targets/ oracles, graded report
python main.py --eval dvwa juice_shop --save-baseline
python main.py --eval --check-regression   # exit 1 on score regression

# Demo against a local sandbox (Docker DVWA or synthetic server)
python main.py --demo

# Flow B mission workflow
python cli.py init-mission --config mission.yaml
python cli.py run-task; python cli.py status; python cli.py list-findings
```

## Environment Variables

### Target / allowlist (threaded into the MCP server)

| Variable | Effect | Source |
|----------|--------|--------|
| `EXPLOIT_TARGET` | Target IP lock for the exploit MCP server's terminal tool (`tools/mcp_tools/terminal.py:31`) | `tools/mcp_shared.py` |
| `EXPLOIT_TARGET_IP`, `EXPLOIT_TARGET_DOMAIN` | Resolved IP / original domain of the target | AGENTS.md rule 6 |
| `EXPLOIT_DISCOVERED_TARGETS` | Comma-separated discovered targets unioned into the allowlist matcher | `tools/mcp_shared.py:528-555` |
| `EXPLOIT_ALLOWED_TARGETS` | Comma-separated operator/CI override unioned into the allowlist (set authorized targets without editing `config.yaml`; used by the nightly eval workflow) | `tools/kernel/allowlist.py` |
| `EXPLOIT_WORKSPACE` | Workspace root (e.g. `.kev_catalog.json` path) | `tools/cve_lookup.py:171` |

### API keys

| Variable | Effect | Source |
|----------|--------|--------|
| `OLLAMA_API_KEY` | Required for the Ollama Cloud default path; auto-attached to chat/generate requests | `tools/doctor.py:154`; AGENTS.md rule 7 |
| `SERPAPI_API_KEY` | Research web-search provider | `tools/api_key_store.py:51` |
| `NVD_API_KEY` | CVE lookup | `tools/api_key_store.py:52` |
| `GITHUB_TOKEN` | Exploit search / CVE GitHub lookups | `tools/exploit_search.py:224`; `tools/api_key_store.py:53` |
| `SHODAN_API_KEY` | Shodan recon (optional) | `tools/recon_pipeline.py:287` |

Keys are loaded from the `--api-key-file` JSON into `os.environ` when not already set
(`tools/api_key_store.py:110-118`). Missing-key names come from `configured_api_key_env_names`
(`tools/api_key_store.py:33`).

### WebUI API

| Variable | Effect | Source |
|----------|--------|--------|
| `BREACHPILOT_API_TOKEN` | Bearer token override for the API daemon (else `.webui_secret_key` file) | `app.py:69-73`; `tools/api/auth.py:46` |
| `BREACHPILOT_API_KEY_FILE` | API key file path used by the API routes | `tools/api/routes/system.py:144, 181` |

### Behavior / debug

| Variable | Effect | Source |
|----------|--------|--------|
| `AI_NMAP_DEBUG` | Verbose nmap/exploit loop logging (`--debug` sets it) | `tools/exploit_agent/runner/_impl.py:_debug_enabled`; `main.py` debug handling |
| `AI_NMAP_ACTIVE_MODEL_ALIAS` | Active model alias override for MCP registry/peer tools | `tools/mcp_tools/registry.py:201` |
| `AI_NMAP_MULTI_MODEL_ENABLED` | Force multi-model enablement for the MCP server | `tools/mcp_tools/registry.py:220` |
| `AI_NMAP_AUDIT_VERIFY_VERBOSE` | Verbose audit verification output | `tools/exploit_agent/policy.py:340` |
| `AI_NMAP_VAULT_KEY` | Credential-store vault key (else auto-generated) | `tools/credential_store.py:149` |
| `MCP_ALLOW_PUBLIC_BIND` | Allow MCP HTTP servers to bind non-loopback | `tools/mcp_shared.py:1022` |
| `MCP_HTTP_TOKEN` | Bearer token for MCP HTTP transport | `tools/mcp_shared.py:1081` |
| `RESEARCH_WORKSPACE` | Flow B workspace root (default `research_workspace`) | `cli.py:39-43`; `tools/logging_setup.py:18` |

## Windows vs Linux

- **Windows is the primary dev platform.** The Makefile is Unix-only — `make doctor` etc. do not
  run on Windows; use the equivalent `python main.py --doctor` commands (Makefile:1-3).
- `scripts/setup-linux.sh` is a one-shot Linux/macOS bootstrap: venv + requirements + external
  tool check (nmap, ollama, tmux, searchsploit, msfconsole, hydra, impacket) + `ollama pull` +
  `python main.py --doctor` (`scripts/setup-linux.sh:21-54`). There is no Windows equivalent.
- Makefile targets map to: `doctor` → `main.py --doctor`, `self-test` → `main.py --self-test`,
  `eval` → `main.py --eval`, `test` → `pytest tests/ -v`, `test-one F=...` → focused pytest,
  `run` → `main.py`, `mcp-defensive|exploit|engine` → the three MCP servers (Makefile:22-48).
- Linux nmap `-O`/`-sS` need root: set `nmap.sudo: true` (uses `sudo -n`) or run as root; else
  `nmap.priv_fallback` (default true) auto-downgrades. Windows attacker = Python-only exploits;
  Linux attacker = full Kali arsenal (searchsploit/metasploit/hydra/crackmapexec/impacket).
- ANSI colors are auto-enabled on Windows terminals via `_enable_windows_ansi`
  (`tools/attack_ui.py:122-141`); `--plain`/`--quiet`/`--json` disable them.
- The interactive menu renders a plain ASCII banner that works on Windows cmd
  (`tools/interactive_menu.py:524-533`); questionary fallbacks are numbered-input menus.
