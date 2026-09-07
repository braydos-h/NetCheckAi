# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**AI Target Exploitation Engine** (also branded "BreachPilot") — an AI-driven, locally-run penetration testing / bug bounty research agent. It is a local-first Python application that uses pluggable LLM providers (Ollama Cloud default model path; lab config uses `opencode_go`; ChatGPT opt-in — see Configuration) to plan and execute authorized security assessments against targets the operator owns or has explicit written authorization to test.

The repo is NOT a generic nmap wrapper. It couples:
- An assessment controller (`main.py` / `app.py`) that opens an MCP exploit session (`tools/mcp_session.py:open_exploit_mcp_session`, an async context manager emitting `[BOOT]`/`[OK]` markers via `AttackUi.boot_step`) and dispatches tool calls.
- A defensive MCP tool server (`mcp_server.py`) that exposes scope-gated Nmap scanning, sanitized vulnerability search, and NVD CVE lookup.
- A second permissive MCP tool server (`mcp_exploit_server.py`, port 8001 by default) that exposes terminal execution, Python file write/run, searchsploit, Metasploit, msfvenom, impacket lateral movement, and credential dumping — gated at the policy layer in `tools/exploit_agent/policy.py`, not in the MCP server itself.
- A multi-agent swarm (`tools/swarm/`) that decomposes work across 6 specialist agents with a shared blackboard.
- A questionary-driven interactive terminal menu (`--menu`), direct CLI entry points, and the WebUI daemon (the default no-args launch).
- An autonomous attack orchestrator (`tools/autonomous_orchestrator.py`) that drives persistent multi-phase campaigns with adaptive aggression levels.

The operator must only ever run this against networks they own or are explicitly authorized to assess. Scope, command, and search safety are enforced in Python code, not just in prompts.

## Common Commands

### Install & verify
```bash
# Linux (primary platform)
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
nmap --version                               # must be on PATH or set nmap.path in config.yaml
ollama show glm-5.2:cloud                    # default model — verify reachable
```
<details>
<summary>Windows PowerShell (legacy, secondary)</summary>

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
nmap --version
ollama show glm-5.2:cloud
```
</details>

On Linux, nmap `-O`/`-sS` need root; set `nmap.sudo: true` in `config.yaml` (uses `sudo -n`) or run as root — otherwise the defensive server auto-downgrades those flags (`nmap.priv_fallback`, default true). The full Kali arsenal (metasploit, searchsploit, hydra, impacket, crackmapexec, tmux, nmap) is expected on Linux — install it with `INSTALL_KALI_TOOLS=1 ./install.sh`; Windows is a Python-only fallback.

### Makefile targets (Linux convenience)
```bash
make install          # venv + pip install -r requirements.txt
make install-dev      # venv + pip install -e ".[dev]"
make doctor           # python3 main.py --doctor
make self-test        # python3 main.py --self-test
make test             # full pytest suite
make test-one F=tests/test_scope_gate.py  # single file
make run              # python3 main.py (WebUI daemon)
make mcp-defensive    # defensive MCP server
make mcp-exploit      # exploit MCP server
make clean            # remove venv + __pycache__ dirs
```

### One-shot bootstrap
```bash
./install.sh               # full bootstrap: OS prereqs + Ollama + venv + WebUI + models + --doctor + launchers
./scripts/setup-linux.sh   # lightweight alternative: venv + deps + doctor
```

### Run
```bash
bp                                                   # WebUI daemon + browser (the DEFAULT no-args behavior)
bp --menu                                            # legacy interactive terminal menu, explicit
bp --target 10.0.0.50 --mode attack --goal backdoor
bp --target 10.0.0.50 --mode recon --recon-first
bp --target 10.0.0.50 --mode attack --swarm --critic --reflection --adaptive-exploits
# (equivalent without the launcher: python3 main.py ...)
```

### WebUI API daemon (--daemon / --demon / --web)
```bash
bp --daemon                       # start the local WebUI API on http://127.0.0.1:8765
bp --daemon --api-port 9000       # custom port (`--daemon` and `--demon` are equivalent aliases)
bp --web                          # build webui/ if needed, serve it at /, open a browser
# Interactive docs: http://127.0.0.1:8765/docs
# OpenAPI schema:  http://127.0.0.1:8765/openapi.json
# Bearer token: generated into .webui_secret_key (gitignored) or set BREACHPILOT_API_TOKEN
# v1 is loopback-only; concurrent runs capped by api.max_concurrent_runs (default 3);
# bundled WebUI served when api.serve_webui is true.
```
`--web` is shorthand for: build `webui/dist/` if missing (runs `npm install && npm run build` in `webui/`), set `api.serve_webui: true` in memory (not written to `config.yaml`), start the daemon, and open `http://127.0.0.1:8765/` in a browser. The built UI is a Vite + React + TypeScript SPA under `webui/` that talks to the `/api/v1` REST + WebSocket surface. `--web` has the same mutual-exclusion constraints as `--daemon` / `--demon`.

### Legacy research CLI (writes to research_workspace/research.db)
```bash
python3 cli.py init-mission --config mission.yaml
python3 cli.py next-task
python3 cli.py run-task T-00001
python3 cli.py list-findings
python3 cli.py generate-report F-00001
python3 cli.py status
```

### Tests
```bash
python3 -m pytest tests/ -v
python3 -m pytest tests/test_scope_gate.py -v          # single file
python3 -m pytest tests/test_recon_pipeline.py::TestClass::test_method -v   # single test
python3 -m pytest tests/ -v -k "scope"                  # by keyword
```
The test suite covers scope gates, safety review, semantic memory, recon, MCP workspaces, reporting, CVE lookup, the agent loop, reliability, swarm behavior, retry logic, skills, reasoning, long sessions, peer consultation, audit chains, credential storage, Metasploit integration, and more.

### MCP servers (standalone)
```bash
python3 mcp_server.py --transport stdio --approved-subnets 192.168.1.0/24
python3 mcp_server.py --transport http --host 127.0.0.1 --port 8000 --approved-subnets 192.168.1.0/24
python3 mcp_exploit_server.py   # defaults: stdio, port 8001
```
The HTTP transport refuses to bind to non-loopback interfaces unless `--allow-public-bind` AND `MCP_ALLOW_PUBLIC_BIND=1` are both set.

### Lint / type-check (CI-enforced, repo-wide)
```bash
python3 -m pip install -e ".[dev]"   # includes ruff
ruff check .                         # must pass (0 errors)
ruff format --check .                # must pass (0 diffs)
mypy --follow-imports=skip tools     # must pass (~335 files)
python3 -m coverage run -m pytest tests/ && python3 -m coverage report --fail-under=80   # coverage (CI command; pytest-cov is not installed)
```

## Configuration

Everything behavior-defining lives in **`config.yaml`**. Top-level keys (current state):
- `models` (`provider` + `registry`/`default_alias`/`auto_update`/`roles`) — `models.provider` selects the chat/generate provider (`ollama` | `opencode_go` | `chatgpt`; lab config.yaml uses `opencode_go`). Provider config lives in `providers.<id>` blocks (legacy top-level `ollama`/`chatgpt`/`opencode_go` blocks still resolve via one normalization layer: `tools/config/loader.get_provider_config`). Built-ins in `tools/providers/`: `ollama` (cloud `https://api.ollama.com` + `OLLAMA_API_KEY`, or local daemon; the ollama Python package is an install extra guarded by `tests/test_no_ollama_regression.py`), `opencode_go` (Responses API at opencode.ai, key env-only), `chatgpt` (vendored `oauth/` loopback proxy at `127.0.0.1:10531`, browser OAuth). Chat dispatches through the provider registry to a canonical `ModelClient` (`tools/providers/types.py`); adding provider #4 = adapter + registration + config metadata + tests, no agent/swarm/doctor/WebUI edits (see `docs/providers.md` / `docs/provider-development.md`). Embeddings are a separate abstraction (`embeddings.provider: ollama` | `none`; local by default). `models.auto_update` (default true) syncs `models.registry` at daemon boot to the newest same-family versions the Ollama API lists via `tools/ollama_models.py` (no pulls; on demand via `POST /api/v1/models/refresh`). OAuth tokens live in `~/.codex/auth.json` and are **never** copied into config or logged.
- `mcp` (default_transport, http_host/port)
- `nmap` (path, sudo, priv_fallback)
- `exploit` (mode, permission, attack_mode, timeouts, workspace_dir, allowed_targets, require_explicit_allowlist, shell, msfconsole_path, disallowed_assets, forbidden_actions) — **lab build: default permission is `full_access`** with `attack_mode: true`; the remaining safeties are the target-IP lock (`require_explicit_allowlist` unions the runtime `--target` via `EXPLOIT_TARGET`) and the mission ScopeGate consult (`forbidden_actions` / `disallowed_assets` deny on the full_access path — Phase 1). Set `permission: read_only` for propose-only recon; a missing key also falls back to `read_only`.
- `stealth` (rotate_ua, dns_over_https) — inert/UI-only legacy block; the live Phase 6.2 block is `opsec`
- `opsec` (enabled, ua_rotation, doh, doh_provider, min_gap_seconds, jitter_seconds, rate_per_minute, quiet_command_patterns, noise_budget, **local_targets_off**, **local_cidrs**, **public_autonomy**) — agent self-hardening + detection-coverage. **Target-aware (Phase 6.2+):** `OpsecProfile.resolve_for_target(ip)` / `OpsecManager.resolve_for_target(ip)` force the profile OFF for private/local target IPs (RFC1918/loopback/link-local/reserved/ULA, plus `local_cidrs`) so the AI moves freely on the operator's own box; a public-routable target keeps the configured posture ON. Classification via `tools/validation_utils.is_private_or_local_target` (distinct from `is_local_target`, which means "operator's own host"). Wired at `AutonomousOrchestrator.__init__` (process-global UA resolved against the primary target) and per-action at `AttackModuleExecutor.execute` (`resolve_for_target(task.target)` before `acquire_pacing`). Defaults: `local_targets_off: true`, `public_autonomy: true`. **AI-facing surfaces (advisory, never a gate):** `tools/exploit_agent/prompt.build_opsec_briefing` renders a target-aware OPSEC posture section into the system prompt (empty for local/off targets) via the `opsec_context` kwarg, wired at `run_exploit_agent`'s `build_exploit_system_prompt` call site (`tools/exploit_agent/runner/_impl.py`); `tools/mcp_tools/terminal._opsec_advisory_block` appends a live `OPSEC_ADVISORY:` block (noise score + suggested quieter rewrite + pacing posture) to every `run_exploit_terminal` result. Both reuse `OpsecManager.score_command_noise` / `suggest_low_noise_alternative` / `pacing_delay` and share the `OpsecManager._LOW_NOISE_REWRITES` table (single source of truth). `is_quiet_blocked` / `noise_budget` stay **dormant** — they are NOT consulted and must not become attack-path gates; the command always executes.
- `cve_lookup`, `research`, `swarm`, `reasoning`, `memory`, `adaptive_exploits`, `multi_model` (optional peer consultation; off by default)
- `eval` (graded eval harness: `output_dir`, `max_rounds`, `write_markdown`/`write_html`, `regression_tolerance`, `baseline_path`) — drives `main.py --eval` / `--save-baseline` / `--check-regression` against the `eval_targets/*.oracle.json` oracle targets (see `tools/eval_harness.py`)
- `killchain` (opt-in kill-chain state machine, **default OFF**: `enabled`, `goal_state` `shell_as_root`, `require_verification`, `graph_db`) — when enabled, `tools/mcp_tools/killchain.py` registers `killchain_status` (graph read, `@audit_tool`), `killchain_attempt` (`@require_allowlist("target")`; runs the edge playbook through the normal MCP tool layer, then **independently verifies success via check probes — state only advances when verification passes**), and `killchain_plan` (BFS over verified edges, stubs excluded). The loop builds a per-target `tools/killchain/` machine and renders a briefing into the system prompt (empty when disabled). Best-effort: any killchain failure degrades to no-op, never breaks the attack path.
- `snapshots` (opt-in snapshot + rollback, **default OFF**: `enabled`, `provider` `docker`, `auto_before_destructive`, `max_snapshots_per_target`, `vm_map` [target→vm_id, `SNAPSHOT_VM_MAP` env override], `providers.{docker,hyperv,vmware,proxmox,libvirt}`) — `tools/snapshots.py` provides pluggable providers (Docker commit/rollback is the implemented path; Proxmox/libvirt/Hyper-V/VMware best-effort wrappers) behind named wrapper seams (`docker_commit`, `docker_run_from_snapshot`, `_docker`, ... — tests monkeypatch the wrappers, never subprocess) plus a fail-open `SnapshotManager` with a JSON index (`snapshots_index.json`). Wired into all three dispatch funnels — exploit loop (`tools/exploit_agent/runner/_impl.py`, emits a `snapshot_taken` event), swarm bridge (`tools/swarm_bridge.py`), campaign executor (`tools/campaign/executor.py` `_snapshot_before_destructive`) — and three MCP tools (`tools/mcp_tools/snapshots.py`: `snapshot_create` / `snapshot_revert` [empty ref = latest] / `snapshot_list`, all `@require_allowlist("vm_id")`). **Fail-open by contract: a snapshot failure logs and the action proceeds — snapshot infrastructure must never become an attack-path gate.** Provider tokens (`PROXMOX_API_TOKEN`) are env-only, never in config or logs.
- `replay_simulator.counterfactual` (bool, default false) — exploit-loop counterfactual replay: on a failed exploit action that had a snapshot, the loop reverts the snapshot and retries the mutated payload against the clean state; both outcomes are recorded in `final_result["counterfactual"]` rows (requires `snapshots.enabled` for effect).
- `sandbox` (default-ON disposable execution worker: `enabled`, `backend` docker, `image` `breachpilot-sandbox:latest`, `fallback_native`, `auto_manage_docker`, resource limits, DNS mode, cleanup) — see Permission Model §Sandbox below; full reference `docs/sandbox.md`
- `embeddings` (`provider: ollama` | `none`) — separate from chat providers; a zero-Ollama install sets `models.provider: opencode_go` + `embeddings.provider: none`
- `browser` (Playwright browser agent, OFF by default: `enabled`, `backend: playwright`, `allow_mutating_actions`) — sandboxed Chromium in the browser worker image, target-locked, fail-closed when unconfigured; see `docs/browser-agent-design.md`
- `plugins` (`enabled` list) — out-of-tree extensions (attack modules, MCP tools, skills, config) managed by `tools/plugins.py`; reference example `plugins/example_recon_report/`; see `docs/plugin-development.md`
- `benchmark` (`output_dir`, trials, per-trial timeout, `sandbox_required`, baseline path, regression tolerances) — reproducible oracle-verified suites via `bp --benchmark xben`; see `docs/benchmarks.md`
- `ics` (destructive PLC writes dual-gated behind `allow_write` + `destructive_ics`), `fsm`, `api` (concurrent runs default 3, loopback auth), `orchestrator`
- `long_session` (opt-in multi-hour attack mode, also enabled by `--long-session`)
- `skills` (runtime skills system: selection, re-selection, feedback, semantic matching, sanitization)

Mission scope (allowed/disallowed assets, forbidden_actions, risk_profile, testing_modes, rate_limits) is configured in **`mission.yaml`** and loaded by `cli.py` / `mission.py`. The three risk profiles (`low_noise_non_destructive`, `standard_authorized`, `high_authorized_testing`) live in `mission.py:_RISK_PROFILES`. Hard-blocked actions regardless of config: `denial_of_service`, `destructive_exploit`, `social_engineering`, `physical_attack`, `malware`, `credential_theft` (see `scope_gate.py:_HARD_FORBIDDEN_ACTIONS`).

## High-Level Architecture

Two control flows exist: **Flow A is the active engine**; **Flow B is frozen in `legacy/`** (see `legacy/README.md`). Knowing which one is in play matters when reading any file. Root shims (`cli.py`, `agent_loop.py`, etc.) are `DeprecationWarning` proxies to `legacy.*` for one release.

### Flow A — Exploitation engine (modern, `main.py` / `app.py`)
The "what the user actually runs" path. Async, MCP-based, multi-agent-capable.

Both the CLI (`main.async_main`) and the WebUI API daemon (`--daemon` / `--demon`,
`app.py` → `tools/api/`) drive assessments through `AssessmentService`
(`tools/run_service/service.py`), a transport-neutral preparation + execution
service. The CLI supplies `TerminalDecisionProvider` / `TerminalEventSink` /
`TerminalApprovalProvider` adapters (backed by `AttackUi`); the API supplies
`ApiDecisionProvider` / `ApiEventSink` / `ApiApprovalProvider` adapters (backed
by persisted decisions + WebSocket events). The service never calls `AttackUi`
directly — it emits events and requests decisions through the provider/sink
interfaces. `Callables` injection lets the CLI pass its monkeypatchable
module-level symbols (`open_exploit_mcp_session`, `run_exploit_session`,
`build_router`, `GoalEngine`) so existing tests that patch `main_mod.*` work.

```
operator ──► main.py (or app.py)
                │
                ├─ open_exploit_mcp_session()  ← async ctx manager (tools/mcp_session.py,
                │     wrapped at main.py); wraps stdio_client / streamable_http_client,
                │     calls session.initialize() capped at MCP_BOOT_TIMEOUT_SECONDS (30s);
                │     sets EXPLOIT_TARGET env on the server subprocess (the target-IP lock);
                │     soft_fail lets the recon-first path degrade to None
                │
                ├─ interactive menu (AttackUi) / CLI args
                │
                ├─ GoalEngine (tools/goal_engine.py) → resolves preset or custom goal,
                │     gates by risk profile (SAFE/GATED/HIGH tags)
                │
                ├─ "Ready-to-begin gate" — prints run summary, asks confirm()
                │
                ├─ build_router() → Ollama model client  +  build ExploitSettings
                │
                ├─ run_exploit_session()  ─►  mcp_exploit_server.py (port 8001)
                │     policy gated by ExploitPolicy in tools/exploit_agent/policy.py
                │     (read_only | approve_only | full_access)
                │
                ├─ if --swarm: AgentLoop.run_autonomous_campaign()
                │     └─ SwarmOrchestrator (tools/swarm/orchestrator.py)
                │           • shared blackboard, critic pre-check, parallel dispatch
                │           • routes to: recon | vuln | exploit | post_exploit
                │                        | critic | reflection agents
                │
                └─ AutonomousOrchestrator (tools/autonomous_orchestrator.py)
                      • persistent multi-phase campaigns with adaptive aggression
                      • auto-triggers attack modules from recon findings
                      • retries with modified parameters on failure
                      • vulnerability chaining + privilege escalation tracking
```

`mcp_exploit_server.py` exposes the actual offensive tools: `run_exploit_terminal`, `write_python_file`, `run_python_file`, `search_exploit_db`, `search_web_exploit`, `search_cve_intel`, `run_msf_module`, `read_workspace_file`, `list_workspace`, `check_os`, `generate_payload` (msfvenom), `lateral_exec` (impacket), `dump_credentials`, `kerberoast`, `run_web_scan` (nikto/nuclei/sqlmap/gobuster/... — target-IP allowlist-locked), `run_hash_crack` (hashcat/john — local-only, audit-only). When `multi_model.enabled` is true or `--multi-model-consult` is passed, it also exposes `consult_peer_models`, an advisory-only tool that asks other configured model aliases for ideas without tool schemas. All target-touching tools require a target IP, are workspace-contained under `exploit_workspace/<ip>/`, and write to `exploit_audit.jsonl`.

### Flow B — Legacy research loop (`legacy/cli.py` + `legacy/agent_loop.py` / `db.py`) — Frozen

Frozen in `legacy/` — root `cli.py`/`agent_loop.py`/… are `DeprecationWarning` shims for one release (see `legacy/README.md`). Database-driven, scope-gated, suitable for headless/CI. Uses SQLite (`research_workspace/research.db`).

```
legacy/cli.py command
    └─► mission.yaml ─► MissionController.create_from_config()
    └─► ScopeGate.check_scope()  ← every executor action passes through here
    └─► AgentLoop (legacy/agent_loop.py)  ←─ Mission / DB / Memory / Evidence / TargetGraph
         PlannerAgent → TaskQueue → ExecutorAgent → ObserverAgent
              ↓
         ToolRouter → SafetyReviewer.preflight_check()
              ↓
         FindingVerifier → ReportGenerator
              ↓
         Audit log + evidence store + target graph
```

`ScopeGate` is the one chokepoint for *every* executor action in Flow B — it checks allowed/disallowed assets, hard-forbidden actions, third-party detection, rate limit bucket, and risk level. Mirror the same pattern if you add new actions.

### MCP Tool Subpackage (`tools/mcp_tools/`)

The exploit MCP server's tool implementations live in a structured subpackage, registered through `tools/mcp_tools/registry.py`:

| Module | Purpose |
|--------|---------|
| `registry.py` | Central wiring — `@audit_tool` decorator, workspace helpers, model-router resolution, multi-model/consult-alias config, process timeouts, `collect_tools()` discovery. Registers no tools itself. |
| `terminal/` (pkg) | `run_exploit_terminal` + package/clone primitives (`apt_install`, `git_clone`, `pip_install`, `run_as_root`, `check_environment`, `install_package`, `download_and_install`, `update_system`). `allowlist.py` holds the target-IP lock (`_target_lock_block`) and the OPSEC advisory block; `execute.py`/`package.py`/`privilege.py` register the tools |
| `recon.py` | `check_os`, `quick_scan`, `run_full_recon`, `get_service_fingerprint` |
| `attack_modules.py` | Web-app probes (`jwt_tamper`, `ssti_probe`, `graphql_introspect`, `race_request`, `timing_oracle`, `request_smuggling_probe`, `password_spray`, `cve_to_exploit_synth`, `hash_crack_identify`) + autonomous campaign planner (`create_attack_plan`/`get_current_plan`/`replan`, `start_autonomous_campaign`/`get_campaign_status`/`run_campaign_step`) + `list_attack_modules`, `run_attack_module`, `craft_exploit`, `mutate_exploit` |
| `metasploit.py` | `run_msf_module`, `msfconsole_start`/`stop`/`command`, `msf_run_exploit`, `msf_run_auxiliary`, `msf_list_sessions`, `msf_interact_session`, `msf_run_post_module`, `msf_kill_session`, `msf_generate_payload`, `msf_run_resource_script` |
| `payloads.py` | `generate_payload` — msfvenom payload generation |
| `web_scan.py` | `run_web_scan` (nikto/nuclei/sqlmap/gobuster/feroxbuster/whatweb/wpscan/dirb/dirbuster) — structured web scanning, target-IP allowlist-locked via `@require_allowlist()`; argv-list (no shell), `shutil.which` friendly-not-installed, parsed `WEB_SCAN_RESULT` block |
| `cracking.py` | `run_hash_crack` (hashcat/john) — local hash cracking with auto hash-type identification (reuses `attack_modules._identify_hash_modes`) and `--show` plaintext recovery; `@audit_tool` only (local, no target) |
| `credentials.py` | Encrypted credential store (`cred_store_add`/`get`/`list`/`confirm`) + `lateral_exec` (impacket), `dump_credentials`, `kerberoast` |
| `workspace.py` | `write_python_file`, `run_python_file`, `read_workspace_file`, `list_workspace` — workspace file I/O (lab build: arbitrary absolute paths allowed) |
| `sessions.py` | tmux/background-job + listener management (`start_tmux_session`, `send_to_session`, `read_session_output`, `kill_session`, `start_background_job`, `read_job_output`, `stop_background_job`, `start_listener`, `read_listener_output`, `stop_listener`, `list_sessions`, `list_processes`, `kill_process`) |
| `research.py` | `search_exploit_db`, `search_web_exploit`, `fetch_webpage`, `deep_research`, `search_cve_intel` |
| `domain.py` | `resolve_domain` (forward DNS), `enumerate_subdomains` (crt.sh + DNS bruteforce + optional subfinder/amass; auto-authorizes discovered hosts + flags dangling-CNAME takeover), `dns_recon` (AXFR/DNSSEC/SPF/DMARC/NS-version), `vhost_enum` (Host-header rotation), `domain_whois` — Phase 4 domain targeting |
| `runtime_skills.py` | `list_runtime_skills`, `search_runtime_skills`, `load_runtime_skill`, `list_skill_references` (conditionally registered) |
| `peer_models.py` | `consult_peer_models` (conditionally registered) — multi-model advisory consultation |
| `killchain.py` | `killchain_status` / `killchain_attempt` / `killchain_plan` (conditionally registered on `killchain.enabled`; backed by `tools/killchain/`) |
| `snapshots.py` | `snapshot_create` / `snapshot_revert` / `snapshot_list` (conditionally registered on `snapshots.enabled`; backed by `tools/snapshots.py`, `@require_allowlist("vm_id")` on all three) |
| `sandbox_exec.py` | Sandbox execution funnel — `run_exploit_terminal`, `run_as_root`, `git_clone`, `run_python_file`, Metasploit, scanners route through `run_command_in_sandbox` / `run_argv_in_sandbox` (see Permission Model §Sandbox) |
| `browser.py` | Sandboxed Chromium agent (`navigate`/`observe`/`discover`/`screenshot` + gated JS/form-submit/request-replay behind `browser.allow_mutating_actions`; conditionally registered on `browser.enabled`) |
| `mitre.py` | MITRE ATT&CK technique mapping / Navigator layer export |
| `operator_connection.py` | RCE beacons, listeners, callback management |
| `ad.py` | Active Directory modules (BloodHound CE, AS-REP roast, pass-the-hash, ADCS/Certipy, SMB signing checks) |
| `hitl.py` | `propose_finding` / `hitl_decide` / `list_proposed` — agents propose candidates (`PROPOSED`); humans Approve/Reject in the WebUI Evidence tab; only `APPROVED` becomes a finding |
| `retest.py` | `retest_finding` — re-runs a confirmed finding's stored PoC probe (`STILL_OPEN` / `FIXED` / `INCONCLUSIVE`) |
| `verify.py` | `verify_finding` — re-proves a candidate's stored probe N/N times (`VERIFIED` / `HOLDING` / `INCONCLUSIVE` + proof capsule) |
| `assessment_state.py` | Per-target `AssessmentState` (`record_hypothesis` / `update_task`, allowlist re-validated before writes) |
| `parallel_agents.py` | Parallel sub-agent dispatch |
| `poc_verifier.py` | PoC probe verification |
| `replay_simulator.py` | Counterfactual replay (requires `snapshots.enabled`) |
| `egress_guard.py` | Egress analysis helpers (see `tools/command_analyzer.py`) |

**Flow A CLI orchestration layer** (extracted from `main.py` into top-level `tools/*.py` during the cleanup):
- `mcp_session.py` — `open_exploit_mcp_session`, the MCP boot async context manager (see Boot Sequence).
- `exploit_session.py` — `run_exploit_session`: single-target orchestration, wires ScopeGate + MCP session + `run_exploit_agent`.
- `cli_exploit_settings.py` — `build_cli_exploit_settings`, `_resolve_exploit_permission` (missing-key fallback is `read_only`; `--mode attack` only upgrades to full_access when config explicitly grants it).
- `config_cli.py` — `load_config`, `bootstrap_startup_api_keys`.
- `recon_assessment_cli.py` — `run_recon_assessment` (OS/scan/CVE-intel → `ReconAssessment`).
- `resume_state.py` — `--resume` state loader (reloads `recon_assessment.json` + chosen goal).
- `safety_review_cli.py` — `run_safety_review` for recon mode.
- `skills_cli.py` — runtime skill overrides + startup selection (`--skills*` flags).
- `swarm_bridge.py` — `SwarmMcpBridge`: bridges the sync swarm `tool_executor`/`ExploitAgent.run` onto the live MCP `ClientSession` (preserves run_exploit_session's single-session invariant).
- `run_service/` (pkg) — Transport-neutral `AssessmentService` (prep + execute), typed `RunRequest`/`RunPreview`/`RunResult`/`Decision`/`Event`, `DecisionProvider`/`EventSink`/`ApprovalProvider` protocols with terminal + API adapters, `CancellationToken`, `Callables` injection for CLI monkeypatching.
- `api/` (pkg) — WebUI API daemon: `auth.py` (bearer token + loopback + WS auth), `errors.py` (stable error shape + redaction + request-id middleware), `persistence.py` (`api_runtime.db` SQLite), `event_broker.py` (per-run JSONL + ring buffer + WS pub/sub), `decision_broker.py` (decision futures), `run_manager.py` (single-active-run owner + tool-call serialization), `routes/` (system, runs, decisions, events).

### Shared infrastructure
- **`db.py`** — SQLite schema (missions, scope_rules, tasks, observations, graph_nodes, graph_edges, evidence, findings, audit_logs, memories) with `_new_id()` and `_now_iso()` helpers. Versioned migrations table.
### `tools/` Directory — Key Modules

| Module | Purpose |
|--------|---------|
| `exploit_agent/` (pkg) | `tools/exploit_agent/runner/_impl.py` (~2.1K lines) is the **canonical loop implementation** (`run_exploit_agent`) — a normal package submodule (moved out of `scripts/runner_impl.py` so the built wheel is independently importable); `tools/exploit_agent/runner/loop.py` re-exports it with a plain relative import and `runner.py`/`runner/` coexist as re-export shims. `tools/exploit_agent/loop.py` is a **deprecated shim** (DeprecationWarning) re-exporting from `runner`. Supporting modules in the package: `policy.py` (ExploitPolicy / ExploitPermission), `context.py` (context sizing/compaction/attack memory), `phase_tracker.py` (`_PhaseTracker`), `prompt.py`, `reflection.py`, `skills.py` (mid-run re-selection), `tool_calls.py`, `tool_catalog.py`, `ollama_client.py`, `research_assistant.py`, `outcome_{classify,truth,adapter}.py`, `_common.py` (shared import surface). The package root `__init__.py` re-exports `run_exploit_agent` (with `_sync_patchable_symbols` syncing package-root monkeypatches into `_impl`, whose globals the running loop reads). |
| `campaign/` (pkg) | The autonomous campaign engine behind the `tools/autonomous_orchestrator.py` facade: `state.py` (AttackState/phases/aggression), `executor.py` (AttackModuleExecutor, Path-B target lock), `orchestrator.py` (AutonomousOrchestrator: runner + lifecycle; batch/recovery/persistence/preflight/tasks bound from submodules), `phases.py` (phase handlers + per-target lifecycle), `batch.py` (task batches + prerequisite recovery), `preflight.py`, `service_tasks.py`, `state_store.py`. Shared swarm+campaign vocabulary lives in `tools/kernel/orchestration.py`. |
| `recon/` (pkg) | The recon pipeline behind the deprecated `tools/recon_pipeline.py` shim: `pipeline.py`, `scanner.py` (PrimaryReconScanner), `enumerator.py` (SecondaryEnumerator), `config.py`. |
| `killchain/` (pkg) | Kill-chain state machine (opt-in, `killchain.enabled`): stage machine with evidence-verified transitions (`machine.py` `KillChainMachine` — status/attempt/plan/BFS path-to-goal), stage + edge registry (`edges.py`, stub edges excluded from BFS), and graph persistence (`graph_db` → `<workspace>/killchain_graph.db`). Fail-open: build/advance errors degrade to no-op in the loop. |
| `snapshots.py` | Snapshot + rollback infrastructure (opt-in, `snapshots.enabled`): `SnapshotRef`, `should_snapshot` (destructive-payload + exploit-category gate), `_vm_id_for_target` (`vm_map` → `SNAPSHOT_VM_MAP` env → raw target), fail-open `SnapshotManager` (before_destructive / revert / list / delete, rolling cap, `snapshots_index.json`), pluggable providers via `get_provider` (Docker commit/rollback mandatory; Proxmox/libvirt/Hyper-V/VMware best-effort). All subprocess calls go through named wrapper functions (`_docker`, `docker_commit`, `docker_run_from_snapshot`, ...) — tests monkeypatch the wrappers, never `subprocess`. |
| `eval_harness.py` | Graded eval loop: `run_graded_eval` / `verify_flag_check` (oracle v2 declarative flags — agent claims never decide a flag), `save_baseline` / `check_regression`, plus the docker target-suite wrappers (`docker_suite_up` / `docker_suite_down` named seams). Drives `main.py --eval` / `--save-baseline` / `--check-regression` (see `.github/workflows/eval.yml`). |
| `attack_ui.py` (64K) | Interactive questionary-based menu system (AttackUi) |
| `interactive_menu.py` (27K) | Arrow-key-driven main menu (`--menu`) |
| `run_service/` (pkg) | Transport-neutral `AssessmentService` (prepare/execute), typed models, decision/event/approval adapters for CLI + API |
| `api/` (pkg) | WebUI API daemon: auth, event broker, decision broker, persistence, routes |
| `attack_modules/` (pkg, ~15 module families) | `base.py` (AttackModule ABC + ModuleContext), `registry.py` (ranking), `modules/` per-category (`web`, `auth_creds`, `crypto_jwt`, `deserialize`, `network_smb`, `privesc`, `services`, `ssh`, `synthesis`, `ad`, `ics_iot`, `detection`, `persistence`, `supply_chain`, `orchestrator_phases`, ...) |
| `command_analyzer.py` (31K) | Destructive command and egress analysis (load-bearing for the MCP target-lock destination extraction) |
| `config/` (pkg) | Canonical config schema/validator/loader (`schema.py::CONFIG_SCHEMA`, `validator.py`, `loader.py`); `tools/config_manager.py` is a re-export shim |
| `payload_crafter.py` (35K) | Payload generation and mutation |
| `metasploit_bridge.py` (38K) | Metasploit RPC integration |
| `persistent_session_manager.py` (45K) | Session persistence, checkpoint, resume |
| `web_researcher.py` (59K) | Provider-backed web research (Ollama/SerpAPI), source ranking, caching |
| `model_router.py` (22K) | Ollama model client routing, retry, context window normalization, provider seam |
| `model_telemetry.py` (11K) | LLM usage telemetry (tokens, context, duration, tokens/sec) |
| `validation_utils.py` (24K) | IP validation, command sanitization, banner parsing, allowlist matcher |
| `mcp_shared.py` (20K) | Workspace path checks, allowlist checks, audit helpers, redaction, HTTP server hardening |
| `skill_registry.py` (15K) | Skill catalog loading, sanitization, metadata |
| `skill_selector.py` (20K) | Deterministic + semantic skill selection |
| `skill_embeddings.py` (7K) | nomic-embed-text cosine similarity ranking |
| `skill_pipeline.py` (8K) | Skill context injection into agent prompts |
| `skill_feedback.py` (5K) | Cross-mission skill outcome feedback (ExperienceStore) |
| `semantic_memory.py` (18K) | Ollama nomic-embed-text cross-mission learning |
| `experience_store.py` (10K) | Bayesian confidence scoring for attack outcomes |
| `attack_memory.py` (17K) | Per-attempt memory with context window management |
| `credential_store.py` (23K) | Encrypted credential storage |
| `cve_lookup.py` (23K) | NVD CVE lookup with circuit breaker, rate limiting, EPSS/KEV enrichment |
| `goal_engine.py` (16K) | Goal preset resolution and risk gating |
| `goal_suggester.py` (31K) | Recon-driven goal suggestion |
| `enhanced_reporting.py` (66K) | Exploit-session reporting, timelines, CVSS, chains |
| `exploit_search.py` (20K) | Exploit database search (searchsploit wrapper) |
| `exploit_mutator.py` (8K) | Exploit parameter mutation strategies |
| `session_manager.py` (11K) | Session lifecycle management |
| `attack_planner.py` (19K) | Attack plan generation and step sequencing |
| `safety_reviewer.py` (5K) | Pre-flight safety checks for tool calls |
| `doctor.py` (28K) | Environment and configuration diagnostics |
| `self_test.py` (10K) | Safe localhost smoke test |
| `api_key_store.py` (10K) | API key collection, storage, env loading |
| `activity_log.py` (6K) | Per-run activity JSONL logging |
| `reliability.py` (38K) | Retry logic, circuit breakers, error classification |
| `post_exploit.py` (7K) | Post-exploitation helpers |
| `demo_mode.py` (7K) | Demo/presentation mode |
| `logging_setup.py` (5K) | Logging configuration |
| `exceptions.py` (1.5K) | `_EXC_GROUP_CATCH`, `_is_exception_group`, `_log_nested_exceptions` |

## Boot Sequence (Flow A)

The MCP exploit session is opened by `tools/mcp_session.py:open_exploit_mcp_session` (an async context manager, re-wrapped at `main.py:open_exploit_mcp_session` and re-bound into `tools/exploit_session.py`). It emits `[BOOT]`/`[OK]` progress markers via `AttackUi.boot_step` / `boot_section` (grep `boot_step` to find them), then per transport:

- **stdio** (default): spawns the exploit MCP server subprocess, wraps `mcp.client.stdio.stdio_client`, and calls `session.initialize()` capped at `MCP_BOOT_TIMEOUT_SECONDS` (30s). The subprocess env gets `EXPLOIT_TARGET` (the runtime `--target`), `EXPLOIT_WORKSPACE`, and the active-model/multi-model flags — this is how the target-IP lock reaches the server (see Permission Model).
- **http**: starts the loopback HTTP child in its own process group, waits for its listener within the same 30s cold-start budget, then opens and initializes the live `streamable_http_client` session. Startup/readiness/initialization failures safely fall back to stdio; failures after a live session has been yielded never fall back (to avoid repeating a partially completed tool call). `MCP_HTTP_TOKEN`, when configured, is sent by the live client. HTTP shutdown signals the process group and escalates to descendant-tree termination on Windows. Startup errors include a bounded, credential-redacted tail of `mcp_exploit_server.log`.

`soft_fail=True` yields `None` so the recon-first path can degrade when MCP is unavailable; hard-fail re-raises. The old runtime recon-module checklist is gone — heavy modules (`exploit_search`, `cve_lookup`, `web_researcher`, `recon_pipeline`, `attack_planner`, `attack_modules`, `payload_crafter`, `metasploit_runner`) are now imported by the server at subprocess boot (enumerated in the `MCP_BOOT_TIMEOUT_SECONDS` comment, not a runtime-checked list).

Critical detail: anyio task groups (used by the MCP SDK's `stdio_client`) raise `BaseExceptionGroup` on subprocess death, which is **not** a subclass of `Exception`. The module-level `_EXC_GROUP_CATCH` tuple and `_is_exception_group` / `_log_nested_exceptions` helpers (in `tools/exceptions.py`, imported by `mcp_session.py`) exist precisely because `except Exception` silently misses it. New code wrapping MCP tool calls or session lifecycle must use `_EXC_GROUP_CATCH`, not bare `except Exception`.

## Permission Model (exploit layer)

This is a **lab-only build**. The operator runs it against systems they own or are
explicitly authorized to test, on a throwaway operator box. The attack path is
**unrestricted but target-locked**: the AI may do whatever it takes to the one
target IP. Recon keeps its full safety (post-session SafetyReviewer, READ_ONLY
propose-only, goal-menu SAFE/GATED narrowing, defensive scope-gated MCP server).

Three levels, defined in `tools/exploit_agent/policy.py`:
- **`full_access`** (config + schema default) — the lab attack posture. `ExploitPolicy.approve_action` auto-approves every action with **no command-content inspection** — destructive commands, egress, reverse shells, credential dumping, Metasploit, and Python file write/run are all allowed. The former `_check_command_safety` / `_gate_pivot_and_count` gates stay removed. **Exception (Phase 1 hardening): the threaded mission `ScopeGate` IS consulted** — when `self._scope_gate` is set (built by `tools/exploit_session.py:_build_exploit_scope_gate` from `exploit.forbidden_actions` / `disallowed_assets`), `_enforce_mission_scope` maps the tool via `_TOOL_ACTION_CATEGORY`, derives assets via the `command_analyzer` extractors (loopback + `policy._allowed_targets` members pre-authorized so callback/C2 hosts keep working, locked-target fallback), and denies disallowed assets/actions with a `SCOPE_DENIED` chained audit row. `scope_gate=None` (swarm path) stays permissive; a `requires_human_approval` verdict still auto-approves (documented lab posture — not a blanket deny).
- **`approve_only`** — every tool call prints an "EXPLOIT ACTION REQUIRES APPROVAL" banner; user must type `ALLOW <target_ip>` to proceed. **Every denial (provider, interactive prompt, EOF/interrupt, budget exhaustion) is recorded to the tamper-evident chain** via `_record_denial()` → `record()` (status `"denied"`, `approved_by="operator"` for human decisions) — Phase 1 made operator denials auditable. Active when config explicitly sets `exploit.permission: approve_only` (it is also the `ExploitSettings` dataclass's programmatic default, but every CLI entry path resolves the permission from config first).
- **`read_only`** — agent gathers intel and proposes attacks without executing them. Recon uses this (`tools/cli_exploit_settings.py:_resolve_exploit_permission` hard-codes `read_only` as the missing-key fallback so a partial config never silently becomes live).

**The ONE attack-mode safety kept: target-IP lock (no pivoting to other hosts).**
It is enforced at the MCP tool layer, not the policy:
- `tools/mcp_shared._allowed_target_list` unions `os.environ["EXPLOIT_TARGET"]` (set to the runtime `--target` in `tools/mcp_session.py`) with `exploit.allowed_targets`. **Domain targeting** (Phase 4) also unions `EXPLOIT_TARGET_IP` (the resolved IP for a domain `--target`), `EXPLOIT_TARGET_DOMAIN` (the domain string), and `EXPLOIT_DISCOVERED_TARGETS` (comma-separated hosts/IPs discovered mid-run by subdomain expansion via `tools/mcp_shared.add_discovered_target`). The lock now locks to a *set* of operator-authorized hosts (primary target + resolved IP + discovered subdomains) instead of a single IP; every member is still operator-authorized and gated through `is_target_in_allowlist` (which supports domains + `*.wildcard` + CIDR by design).
- The target-IP lock is enforced by `tools/mcp_tools/terminal._target_lock_block`, gated by `ctx.require_allowlist` (driven by `exploit.require_explicit_allowlist` + a non-empty allowlist via `registry.make_require_allowlist`) and run on every target-touching tool. It extracts every destination (URL authorities, `/dev/tcp` hosts, LHOST/RHOST, scanner-verb targets, bare IPs, **and hostnames**) via `command_analyzer._extract_destinations` / `extract_ips_from_command` / `_SCANNER_TARGET_RE` and refuses any not in `is_target_in_allowlist`. Operator-authorized callback/C2 hosts are added via `exploit.allowed_targets`.
- The autonomous orchestrator's no-MCP "Path B" (`tools/autonomous_orchestrator.py` `AttackModuleExecutor`) is target-locked by its `scope_gate.check_scope(asset=task.target)` — that is why its scope/risk/critic gates were **kept** (removing the scope_gate would lose the Path-B target lock). Its `autonomous.max_pivot_depth` defaults to 0 (no host-pivoting recursion; note `exploit.max_pivot_depth` is 2 in the lab config). **Domain targeting**: when the operator gives a domain, the orchestrator runs subdomain expansion after recon (`_phase_reconnaissance`), auto-authorizing each discovered `(subdomain, ip)` pair via `add_discovered_target`. `AttackState` carries `original_target` / `resolved_ip` / `discovered_subdomains`.

**Domain targeting (Phase 4).** The operator may pass `--target example.com` (a domain) instead of a bare IP. `main.py` resolves the domain via `tools/validation_utils.resolve_target_to_ip` (system resolver, never raises) and threads both `original_target` (the domain) and `resolved_ip` through `run_exploit_session` → `open_exploit_mcp_session` → the MCP server env vars. The `validate_ipv4` pre-gates on every exploit MCP tool were relaxed to `validate_target_or_ip` (accepts IP or FQDN); the allowlist matcher (`is_target_in_allowlist`) and scope gate (`scope_gate._classify_target_type`/`_rule_matches`) already supported domains + wildcards + CIDR by design. Five new domain MCP tools live in `tools/mcp_tools/domain.py`: `resolve_domain`, `enumerate_subdomains` (auto-authorizes discovered hosts + flags dangling-CNAME takeover), `dns_recon` (AXFR/DNSSEC/SPF/DMARC/NS-version), `vhost_enum` (Host-header rotation), `domain_whois`. A `DOMAIN TARGET BRIEFING` is injected into the agent system prompt (`tools/exploit_agent/prompt.build_domain_briefing`) telling the agent to use the domain for Host/SNI and the IP for nmap/metasploit. The `attacking-domains-end-to-end` skill (`skills/`) orchestrates the full domain attack flow.

**Operator-box filesystem is unrestricted.** The workspace path-traversal
protection, sensitive-credential denylist, and `list_workspace` credentials/
hiding were removed (`tools/mcp_tools/registry.py:read_workspace`,
`tools/mcp_tools/workspace.py`). `write_python_file` accepts arbitrary
paths/sizes/code (absolute paths write anywhere on the operator box);
`read_workspace_file` reads any path (including `/etc/hosts`, the vault keyfile).

### Sandbox — disposable execution worker (default ON, fail-closed)

Attack commands do not run on the operator host when the sandbox is enabled
(`config.yaml sandbox.enabled: true`). `run_exploit_terminal`, `run_as_root`,
`git_clone`, `run_python_file`, Metasploit, and the scanners funnel through
`tools/mcp_tools/sandbox_exec.py` (`run_command_in_sandbox` /
`run_argv_in_sandbox`) into a disposable Docker worker (`tools/sandbox/`:
manager, docker backend/lifecycle, network) created per run and destroyed
afterward: non-root, `--cap-drop ALL`, `no-new-privileges`, read-only rootfs,
CPU/memory/PID limits, output clamping, no Docker socket, no host mounts
beyond the run workspace. A default-DROP netns firewall authorizes ONLY the
effective target allowlist (the same list the application layer enforces,
resolved host-side for domains); cloud metadata, the Docker gateway, host LAN,
and the open internet are unreachable. Sandbox failures fail closed as
structured `SANDBOX_*` blocks — **NEVER run agent-generated commands via host
`subprocess` on new paths, and NEVER add a host-execution fallback for sandbox
failures.** The worker image must be built: `docker build -t
breachpilot-sandbox:latest docker/sandbox` (CI `sandbox` job does this and
runs the 7 sandbox test files against real Docker). The one boot-time
exception is `sandbox.fallback_native` (whole-session degrade to legacy
uncontained native mode when Docker is unusable — the checked-in lab config
sets it `false`; README describes `true` as default, which is currently
inconsistent). `sandbox.enabled: false` is the explicit operator opt-out.
Full architecture/threat model: `docs/sandbox.md`.

Operational guards that remain regardless of mode: command timeouts (default
300s terminal / 300s python / 600s msf), full JSONL audit trail
(`exploit_audit.jsonl`) with SHA256 of generated code, OS-aware tooling
instructions (Linux attacker = full Kali arsenal including
searchsploit/metasploit/hydra/crackmapexec/impacket; Windows attacker = Python-only fallback).
`tools/command_analyzer.py` is **kept and load-bearing** — the tool-layer target-lock destination extraction (`terminal._target_lock_block`, `registry.py`) plus `exploit_agent/_common.py` and `swarm_bridge.py` import `analyze_command` / `_extract_destinations` / `analysis_payload` from it. It is no longer a *policy* gate on the attack path, but it is not dormant.

## Workspace Layout

- `reports/<run_id>/` — per-run artifacts (activity.jsonl, raw_nmap/, xml_nmap/, host_<ip>.md, network_summary.{md,html}, findings.csv, mcp_server.log, exploit_workspace/)
- `research_workspace/<mission_id>/` — Flow B mission data (research.db, evidence/, reports/)
- `exploit_workspace/<target_ip>/<attempt_id>/` — per-attempt exploit artifacts (exploit_script.py, terminal.log, python_run.log, msf_output.log, run_active_check.ps1) + `exploit_audit.jsonl`
- `swarm_workspace/` — created on demand by main.py

## Testing Notes

- **~340** test files in `tests/` (verify via `python3 -c "import pathlib; print(len(list(pathlib.Path('tests').glob('test_*.py'))))"`, all mock subprocess/network except `-m integration` files). No fixtures for live Nmap; everything mocks subprocess / network.
- New safety-relevant code needs regression tests in `test_scope_gate.py`, `test_safety_reviewer.py`, `test_validate_target.py` (or a new file if the surface is new).
- `pyproject.toml` configures pytest with `asyncio_mode = "auto"` and `testpaths = ["tests"]`. Coverage is configured in `[tool.coverage.run]` with `source = ["tools", "main", "cli", "legacy"]`; run it the way CI does — `python3 -m coverage run -m pytest tests/` then `python3 -m coverage report` (pytest-cov is NOT a dependency, so `pytest --cov` fails).
- Lint / type-check are CI-enforced repo-wide: `ruff check .` (0 errors) + `ruff format --check .` (0 diffs) and `mypy --follow-imports=skip tools` (~335 files, 0 errors with current `disable_error_code` masks; see `.github/workflows/ci.yml`). `pyproject.toml` has `ruff` line-length 120 `select = ["E","F","W","I"]` (`pyproject.toml:127-174`, with `ignore` + per-file-ignores documenting intentional patterns) and `mypy` configs with strict zero-disable tiers (`validation_utils`, `exceptions`, `mcp_shared`, `kernel.*`, `sandbox.*`). Keep security-sensitive diffs readable.

## Things To Watch Out For

- **`config.yaml` exploit.permission is `full_access` in the lab checked-in file (`config.yaml:61`) — schema default is also `full_access` (`tools/config/schema.py:150`); the *missing-key* fallback (`tools/cli_exploit_settings.py:13-30`) is `read_only` so a partial config never silently becomes live.** Do not change the lab default without updating `docs/safety-model.md` and README.
- **The `BaseExceptionGroup` thing** (`tools/exceptions.py:38-41` `_EXC_GROUP_CATCH = (Exception, BaseExceptionGroup)` on 3.11+) — any new code that wraps MCP `stdio_client` / `streamable_http_client` / `ClientSession.initialize()` calls must use `_EXC_GROUP_CATCH` and the `_is_exception_group` / `_log_nested_exceptions` helpers (`tools/exceptions.py:15-35`), not `except Exception`. Boot timeout `MCP_BOOT_TIMEOUT_SECONDS=30` (`tools/mcp_session.py:32`).
- **`config.yaml` exploit.permission defaults to `full_access` (lab build).** The attack path is unrestricted apart from two safeties: the target-IP lock (above) and the mission ScopeGate consult (`forbidden_actions`/`disallowed_assets` → `SCOPE_DENIED`). Recon still uses `read_only` via `_resolve_exploit_permission`'s missing-key fallback. Do not re-add the removed attack-path gates (command-content/pivot) without first ensuring the MCP allowlist target-lock covers the path you are de-restricting — the allowlist IS the lock.
- **Two mission/agent paths coexist** (`main.py` exploit engine vs `legacy/cli.py` legacy). When touching `scope_gate.py`, `risk_controller.py`, `legacy/mission.py`, `db.py` — those affect Flow B. When touching `tools/exploit_agent/`, `mcp_exploit_server.py`, `tools/swarm/`, `tools/mcp_tools/` — those affect Flow A. The two share `db.py` and `legacy/mission.py` schemas (root `mission.py` is a shim). **Do not edit `scope_gate.py`, `safety_reviewer.py`, or Flow B's `legacy/agent_loop.py`/`legacy/tool_router.py`/`legacy/risk_controller.py`/`legacy/mission.py`/`db.py` — recon safety depends on them.**
- **The exploit workspace is shared host filesystem state.** `mcp_exploit_server.py` and `tools/exploit_agent/` both write into `exploit_workspace/`. **Lab build: path-traversal protection was removed** — the operator box is unrestricted. The MCP tool layer enforces only the target-IP allowlist lock.
- **The model backend is Ollama Cloud by default** (`ollama.host: https://api.ollama.com` + `OLLAMA_API_KEY`; the ollama client attaches the bearer token automatically). A local daemon works by pointing `ollama.host` at it (`http://localhost:11434`) — no code change; embeddings always use `ollama.embed_host` (local by default). An unreachable/unauthenticated model backend surfaces as a `[WARN]` on the recon path or a hard fail on the attack path.
- **ChatGPT provider is opt-in and provider-agnostic by design.** `models.provider: chatgpt` swaps the chat/generate client at the single seam `tools/model_router.py::_build_model_client` (injects a `ChatGptProxyClient` from `tools/providers/chatgpt_provider.py` instead of `ollama.Client`); every consumer already receives a `ModelClient` and is untouched. **OAuth tokens live in `~/.codex/auth.json` — never copy them into `config.yaml` or logs; `is_authenticated()` checks file existence only, never reads it.** The proxy is loopback-only (`127.0.0.1:10531`); lifecycle uses openai-oauth's own `--detach`/`stop` CLI — never Popen+kill `serve`, and never stop a proxy we didn't start (`_we_started`). **This is a provider integration, not an auth-scope change: do not weaken the target-IP allowlist, permission model, MCP target locks, or recon restrictions.** Embeddings stay on Ollama under either provider. Default `provider: ollama` behavior is byte-identical to pre-provider code (the `raw_client is None` branch), so `monkeypatch.setattr(model_router, "OllamaClient", ...)` tests stay green.
- **Kill-chain and snapshot MCP families are conditional** (the `replay_simulate`/`peer_models` precedent): `tools/mcp_tools/killchain.py` registers nothing unless `killchain.enabled`, `tools/mcp_tools/snapshots.py` unless `snapshots.enabled` (both default OFF in schema + `config.yaml`). The loop's snapshot/counterfactual helpers (`_should_snapshot_for_action`, `_build_snapshot_manager`, `_counterfactual_enabled` in `runner/_impl.py`) are package-root patchables — extend `_sync_patchable_symbols` if you add more (see the exploit-agent patch seam rule) — and every snapshot consumer is **fail-open by contract**: a snapshot/revert failure logs a warning and the attack path proceeds. `PROXMOX_API_TOKEN` and other provider credentials are env-only, never in `config.yaml`, never logged.
- **CI runs on every push/PR** (`.github/workflows/ci.yml` + codeql + dependency-review, `.github/dependabot.yml`): 9 jobs — mocked test suite on Python 3.11-3.13, sandbox integration (real Docker, builds `breachpilot-sandbox:latest`), browser integration (Playwright + Chromium), coverage (`python3 -m coverage run -m pytest tests/` + `coverage report --fail-under=80` on 3.12), lint (repo-wide `ruff check .` + `ruff format --check .` plus guards: MCP bare-except grep, god-file budget, config-schema/YAML sync, requirements/pyproject sync, `doctor --json` shape, docs-truth guard on no-args startup), types (`mypy --follow-imports=skip tools` + strict hot files/subsystems + debt gate via `scripts/mypy_debt.py`), package build (`python3 -m build` + `twine check` + installed-wheel smoke), WebUI build+tests (`npm ci` + `tsc -b && vite build` + `vitest`), and dependency audit (pip-audit). The mocked eval suite runs separately (`.github/workflows/eval.yml`). Before a PR run `python3 -m pytest tests/ -v`, `ruff check .`, `ruff format --check .`, and `mypy --follow-imports=skip tools`, and verify README flags/config still match reality.
- **The README is the canonical user-facing doc**. When adding a CLI flag, MCP tool, or config key, update the relevant section there. There is no `CHANGELOG.md`; release history is the git history plus the version in `pyproject.toml` / `main.__version__`.
- **`pyproject.toml` and `requirements.txt` are synced** — both list runtime + dev (`pip install -e ".[dev]" == pip install -r requirements.txt`). `requirements.txt` header says “Synced from pyproject.toml”. The `opencode.jsonc` file configures an Ollama Cloud provider for the opencode.ai editor, not for the app itself.
- **`tools/mcp_tools/registry.py` is the central wiring point** for all exploit MCP tools — add tools there with the `@audit_tool` / `@require_allowlist()` decorators; `mcp_exploit_server.py` auto-discovers every `register_*_tools` via `collect_tools()` (pkgutil + AST validation, fails CI if a decorator is missing), so no manual list edit is needed.
- **`tools/autonomous_orchestrator.py` is a separate campaign engine** from the swarm — it drives persistent multi-phase attacks with adaptive aggression levels, while the swarm is a parallel specialist-agent decomposition. They can be used independently. Decision rule (`docs/swarm.md` §Swarm vs Campaign): `--swarm` for single-target specialist decomposition, campaign (no `--swarm`) for persistent multi-phase queues across one or many targets, combined on high-value targets. Shared retry/persistence/progress vocabulary lives in `tools/kernel/orchestration.py`.
- **Agents must NEVER push to GitHub or create new branches.** Do not run `git push`, `git branch`, `git checkout -b`, `git switch -c`, `gh repo create`, or any branch/push-creating `gh` command. All work stays on the current local branch; remote updates are the user's job. Enforced via `permission.bash` deny rules in `~/.config/opencode/opencode.json` and the repo `pre-push` hook — do not bypass.
