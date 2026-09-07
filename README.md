# BreachPilot

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![WebUI](https://img.shields.io/badge/WebUI-React%20%2B%20Vite%20%2B%20TypeScript-06b6d4?style=flat-square&logo=react&logoColor=white)
![LLM](https://img.shields.io/badge/LLM-Ollama%20Cloud%20%7C%20ChatGPT-22c55e?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-1.27%2B-f97316?style=flat-square)
![Skills](https://img.shields.io/badge/Skills-140%2B-8b5cf6?style=flat-square)
![MCP Tools](https://img.shields.io/badge/MCP%20Tools-120%2B-ec4899?style=flat-square)
![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)
### Autonomous tool for authorized hacking

**Plan · Recon · Exploit · Verify · Report.**

BreachPilot is an open-source agentic operator that plans, discovers, reasons, chains, and verifies, then delivers a complete report. It is built on Ollama Cloud (976K context), the Model Context Protocol, and 140+ advisory skills. It runs lab-only and target-locked, audits every action, and is designed for rigorous, operator-supervised use.

[Quick start](#quick-start-in-60-seconds) · [WebUI](#webui-mission-control) · [Capabilities](#platform-capabilities) · [Safety model](#safety-model) · [Docs](docs/)

</div>

---

> [!WARNING]
> **Authorized use only.** Only test systems you own or have explicit written permission to assess. Run on a throwaway operator box.
> **Attack mode = `full_access`**: every in-scope action is auto-approved. The safeties are the **target-IP allowlist lock** (a destination guard, not a sandbox) and the **mission scope gate** (`exploit.forbidden_actions` / `disallowed_assets` deny with a `SCOPE_DENIED` audit row). Recon stays fully scope-gated. See [Safety model](#safety-model)

---

## Why BreachPilot

BreachPilot covers the full assessment lifecycle, from reconnaissance through exploitation, verification, and reporting, under continuous operator supervision.

<table>
<tr>
<td width="33%" valign="top">

### Adversarial planning
A structured AttackPlan DAG with prerequisites, hypotheses, and automated failure recovery. It retries with refined parameters, switches capabilities, and composes prerequisites dynamically. Every decision is recorded in `decision_log.jsonl`.

</td>
<td width="33%" valign="top">

### Multi-agent orchestration
Six specialist agents on a shared blackboard: `recon`, `vuln`, `exploit`, `post_exploit`, `critic`, `reflection`. Dispatch is parallel, with battle logs and cross-phase negotiation, plus a persistent Autonomous Orchestrator for extended campaigns.

</td>
<td width="33%" valign="top">

### Evidence-based verification
Hypothesis-driven verdicts via `OutcomeJudge`: every finding is `confirmed`, `refuted`, or `exhausted`. Execution success is not conflated with evidential success; findings require supporting evidence.

</td>
</tr>
<tr>
<td width="33%" valign="top">

### Domain-aware reconnaissance
Give it `example.com` and the platform resolves and expands the attack surface (crt.sh, DNS bruteforce, subfinder/amass), auto-authorizes discovered hosts, flags dangling-CNAME takeovers, and assesses the full surface. Wildcard and CIDR allowlist support.

</td>
<td width="33%" valign="top">

### Target-locked safety model
`full_access` on the operator host is constrained to the allowlist at the MCP tool layer. Every destination is extracted from every command: URL authorities, `/dev/tcp`, LHOST/RHOST, bare IPs, hostnames. Anything not in the allowlist is `BLOCKED`. The policy also enforces the mission scope gate (`exploit.forbidden_actions` / `disallowed_assets` → `SCOPE_DENIED`), and approve_only denials are audited. All target-touching actions are recorded in a tamper-evident SHA-256 audit chain.

</td>
<td width="33%" valign="top">

### Knowledge base
140+ skills, 120+ tools, and 15 attack families covering network penetration testing, AD CS ESC1, JWT confusion, SSTI, GraphQL, XXE, BloodHound, EternalBlue, Zerologon, and noPac. Skill selection is deterministic and semantic, re-evaluated as new services and CVEs emerge.

</td>
</tr>
</table>

---

## Platform capabilities

Core capabilities:

### Reconnaissance
- Fast recon pipeline: parallel TCP discovery, service fingerprinting, OS detection, and vulnerability enrichment, all concurrent and cached.
- Nmap done right: ping sweep → triage → service → vuln scans, with `priv_fallback` auto-downgrade and pre-flight reachability probes so firewalled hosts don't waste your time.
- Extended enumerators: UDP top-ports, SNMP, DNS zone transfer / DNSSEC / SPF / DMARC, ASN/WHOIS, cloud metadata probe, WAF fingerprinting, vhost discovery.
- Domain recon: `resolve_domain`, `enumerate_subdomains`, `dns_recon` (AXFR/DNSSEC), `vhost_enum` (Host-header rotation), `domain_whois`, all allowlist-gated.
- Threat intel: NVD + EPSS + CISA KEV + OSV + GHSA, with circuit breaker, rate limiting, and GitHub token support for PoC search.

### Exploitation and chaining
- 15 attack module families (`tools/attack_modules/modules/`): `web`, `auth_creds`, `crypto_jwt`, `deserialize`, `network_smb`, `privesc`, `services`, `ssh`, `synthesis`, `supply_chain`, `persistence`, `ad`, `ics_iot`, `detection`, `orchestrator_phases`. Each scores its own applicability (0-100) against your target's services, ports, and CVEs.
- Capability-aware planning: every module declares `requires` / `produces` / `read_only` / `cost` / `phase_hint`, so the planner can dynamically compose prerequisites (`find_producers(artifact)`) and gate execution.
- Payload crafting and mutation: `PayloadCrafter` + `ExploitMutator` with 5 strategies (parameter tweak, encoding change, delivery swap, context-aware). Auto-generates and mutates Python exploit scripts.
- Metasploit bridge: `run_msf_module`, `msfconsole` lifecycle, `msfvenom` payload generation, session/payload/post-module orchestration, resource scripts. Full Kali arsenal on Linux, Python-only on Windows.
- Web scanning: nikto / nuclei / sqlmap / gobuster / feroxbuster / whatweb / wpscan. Argv-list execution, `which`-checked, parsed `WEB_SCAN_RESULT` blocks.

### Adaptive intelligence
- 140+ advisory skills: a YAML + markdown prompt-context layer, scored by deterministic tags + lexical search + cross-mission Bayesian feedback + semantic cosine similarity over `nomic-embed-text` embeddings. Mid-run re-selection as new CVEs surface.
- Semantic memory: `nomic-embed-text` cross-mission learning via `SemanticMemoryManager` + `ExperienceStore`. The orchestrator stores lessons on every confirmed win.
- Attack memory: per-attempt context window management (6K chars), compaction every 50 rounds, persistent campaign state.
- Model telemetry: token counts, context utilization, duration, and tokens/sec for every LLM call.
- Peer model consult: brings Kimi K2.6, DeepSeek V4 Pro (1M context), GLM-5.2, and Minimax M3 in mid-run for advisory ideas without tool access. Configurable `consult_aliases`.

### Post-exploitation and lateral movement
- Credential ops: encrypted vault (`credential_store`), `lateral_exec` via Impacket, `dump_credentials`, `kerberoast`, and `hash_crack` (hashcat/john with auto hash-type ID + `--show` recovery).
- Active Directory: BloodHound CE, AD ACL abuse, AS-REP roast, pass-the-hash, ADCS/Certipy, Golden Ticket, Responder relay, SMB signing checks.
- Operator connection: persistent RCE beacons (netcat/TLS/DNS/HTTPS/SOCKS pivot) with `exploit_workspace` callback management.
- ICS/IoT: Modbus & S7 PLC modules, read-only by default. Destructive writes are dual-gated behind `ics.allow_write` + `ics.destructive_ics`.

### Operational security
- Target-aware OPSEC: auto-disabled on private/local targets (RFC1918/loopback/link-local) so the agent moves freely in your lab; full posture on public targets. UA rotation, DoH, pacing with jitter, rate limiting, quiet-command rewrites, noise budget. All advisory, never a gate: the command always executes, and you get `OPSEC_ADVISORY` blocks suggesting quieter alternatives.

### Reporting and export
- MITRE ATT&CK Navigator export: technique-mapped layer JSON for SOC handoff (`reports/mitre/`).
- Ticketing: auto-create Jira/GitHub issues from confirmed findings.
- Report contents: timelines, CVSS, exploit chains, Markdown + HTML, `decision_log.jsonl`, tamper-evident audit, loot and credential tables, and graph evidence.

---

## WebUI: mission control

The WebUI serves at `http://127.0.0.1:8765`. It is loopback-only, bearer-token authenticated, and streams events in real time.

| Page | Description |
|------|-------------|
| New Run Wizard | Configure target, model, goal, and execution options, then review and launch. Supports IP and domain targets. |
| Live Run | Real-time event stream including tool calls, decisions, and telemetry via WebSocket and SSE. Token-gated and ring-buffered. |
| Attack Graph | Interactive DAG (ReactFlow) with pan, zoom, filtering, path finding, and evidence inspection. Backed by `AttackPlan` (`ready_steps()` / `blocked_steps()` / `graph_summary()`). |
| Artifacts & Audit | Reports, raw Nmap output, findings, and the SHA-256 audit chain, all tamper-evident. |
| Loot & Credentials | Captured credentials and loot per run, encrypted at rest. |
| Skills | Browse the advisory skill catalog and per-run skill selection. |
| Modules | Attack module families, applicability scores, and run history. |
| Goals | Goal presets, risk gating (SAFE/GATED/HIGH), and custom goals. |
| Benchmarks | Oracle-verified benchmark suites, live progress, and run comparison. |
| Memory | Cross-mission semantic memory and experience-store lessons. |
| Connections | Operator connections, listeners, and beacon health. |
| System | Configuration, secrets, models and providers, skills, plugins, and diagnostics. No manual YAML editing required. |

The UI is a Vite + React + TypeScript SPA (`webui/`) with TanStack Query, Radix UI, and Tailwind CSS. The production bundle is built automatically on first launch when Node.js is available.

For dev hot-reload:

```bash
cd webui && npm install && npm run dev   # http://127.0.0.1:5173 proxies to :8765
```

Full reference: [docs/webui.md](docs/webui.md) · API: [docs/api.md](docs/api.md) · Live docs: http://127.0.0.1:8765/docs

---

## Skills, agents, and memory

### 140+ advisory skills
Each skill is a curated `SKILL.md` under `skills/`, such as `conducting-network-penetration-test`, `executing-red-team-engagement-planning`, `exploiting-jwt-algorithm-confusion-attack`, `exploiting-ssti`, `exploiting-nopac-cve-2021-42278-42287`, and `attacking-domains-end-to-end`. The engine deterministically selects the top six for the current context, re-evaluates mid-run, and supports semantic matching via embeddings.

Categories include network penetration testing, web/API, auth/JWT/OAuth, deserialization, AD/BloodHound, SMB/network, privilege escalation, cryptography, supply chain, detection, persistence, and ICS/IoT. See [docs/skills.md](docs/skills.md) and [docs/skill-authoring.md](docs/skill-authoring.md).

### Swarm: six specialists, one blackboard

| Agent | Job |
|-------|-----|
| `recon` | Scanning, fingerprinting, attack surface scoring |
| `vuln` | CVE / exploit correlation, module matching |
| `exploit` | Module selection, payload crafting, mutation |
| `post_exploit` | Credential/loot handling, lateral target generation |
| `critic` | Pre-execution scope, risk & policy review |
| `reflection` | Strategy review, lessons learned |

Orchestrated via `tools/swarm/orchestrator.py` with a shared blackboard, battle log, parallel dispatch, and phase-aware skill hints. See [docs/swarm.md](docs/swarm.md).

**Swarm vs campaign:** `--swarm` decomposes a *single target* across the six specialists (parallel recon + vuln research, critic pre-check, reflection shifts). Without `--swarm`, the autonomous campaign drives a persistent multi-phase queue (recon → exploit → privesc → lateral → validation) with adaptive aggression, resume, and checkpoints across one or many targets. Combine both on high-value targets. Same target-IP lock and permission model either way.

### MCP tool suite: 120+ tools across 29 families

| Family | Capability |
|--------|-----------|
| `terminal` | Shell execution with target-IP allowlist enforcement and OPSEC advisory |
| `workspace` | `write_python_file` / `run_python_file` / `read_workspace_file`, all workspace-contained |
| `recon` | `check_os`, `quick_scan`, `run_full_recon`, `get_service_fingerprint` |
| `attack_modules` | `run_attack_module`, `craft_exploit`, `mutate_exploit` and hypothesis/state tools |
| `metasploit` | Full `msfconsole` lifecycle, sessions, payloads, and post modules |
| `payloads` | `generate_payload` via msfvenom |
| `web_scan` | nikto, nuclei, sqlmap, gobuster, feroxbuster, whatweb, wpscan |
| `cracking` | hashcat/john with automatic hash-type identification |
| `credentials` | Encrypted vault and Impacket-based lateral execution / Kerberoast |
| `sessions` | tmux, background jobs, and listeners (beacons) |
| `research` | `search_exploit_db`, `search_web_exploit`, `deep_research`, `search_cve_intel` |
| `domain` | DNS, subdomain enumeration, AXFR, vhost, WHOIS, with automatic authorization |
| `peer_models` | `consult_peer_models`, advisory multi-model consultation |
| `runtime_skills` | `list`, `search`, and `load` skills at runtime |
| `killchain` | `killchain_status`, `killchain_attempt`, `killchain_plan` — evidence-verified stage machine (opt-in, `killchain.enabled`) |
| `snapshots` | `snapshot_create`, `snapshot_revert`, `snapshot_list` — provider-backed VM/container rollback (opt-in, `snapshots.enabled`) |
| `retest` | `retest_finding` — re-runs a confirmed finding's stored PoC probe (`STILL_OPEN` / `FIXED` / `INCONCLUSIVE`), persists the verdict into the run report |
| `hitl` | `propose_finding`, `hitl_decide`, `list_proposed` — agents propose candidates (`PROPOSED`), a human Approves/Rejects them in the WebUI Evidence tab; only `APPROVED` becomes a finding |
| `verify` | `verify_finding` — re-proves a candidate finding's stored probe N/N times (`VERIFIED` / `HOLDING` / `INCONCLUSIVE` + proof capsule), persists the verdict into the run report |
| + 13 more | `assessment_state`, `parallel_agents`, `poc_verifier`, `replay_simulator`, `mitre`, `ad`, `operator_connection`, and others |

All tools are registered via `tools/mcp_tools/registry.py` using the `@audit_tool` / `@require_allowlist()` decorators and auto-discovered through `collect_tools()`, which also fails CI if a tool lacks its audit or allowlist gate. No manual registration required. See [docs/mcp-tools.md](docs/mcp-tools.md).

---

## Safety model

| Mode | What happens |
|------|--------------|
| Recon | Always `read_only`: gathers and proposes, never executes offensively |
| Attack | `full_access`: auto-approves after the mission scope gate (`forbidden_actions` / `disallowed_assets` → `SCOPE_DENIED`); no command-content inspection |
| The lock | Target-IP allowlist at the MCP tool layer. Every destination is extracted and refused if not in the allowlist (supports `IP`, `domain`, `*.wildcard`, `CIDR`). Domain runs auto-authorize discovered subdomains. |

Operational guards that always apply: 300s/600s timeouts, full JSONL audit trail, OS-aware tooling.

### Disposable execution sandbox (on by default)

Attack commands do not run on the operator host. Every terminal command,
generated Python script, exploit tool, and Metasploit run executes inside a
**disposable Docker worker** (`tools/sandbox/`) that is created per run and
destroyed afterward:

- **Hardened container**: non-root, `--cap-drop ALL` (NET_RAW at most — never
  NET_ADMIN), `no-new-privileges`, read-only rootfs, CPU/memory/PID limits,
  per-command timeout, output clamping. No Docker socket, no host mounts
  beyond the run workspace, no host networking.
- **Network containment (fail closed)**: an ephemeral `NET_ADMIN` sidecar
  installs a default-DROP firewall inside the worker's network namespace that
  authorizes ONLY the effective target allowlist — the same list the
  application layer enforces, resolved host-side for domains and recorded in
  the audit trail. Cloud metadata, the Docker gateway, host LAN devices, and
  the open internet are unreachable regardless of what the command says — a
  script with no destination on its command line cannot egress either.
- **Fail closed (or degrade loudly)**: mid-session sandbox failures always
  block offensive execution with a structured `SANDBOX_*` error — there is no
  per-command host fallback. At **boot**, though, one fallback decision is
  made: with `sandbox.fallback_native: true` (the default), an unusable Docker
  stack (CLI missing, daemon down, worker image not built) degrades the whole
  session to the legacy **uncontained native host-execution mode** — the
  server logs a warning, the WebUI home screen shows an amber "Sandbox
  unavailable" banner, and every execution result carries a `SANDBOX_FALLBACK:`
  line. Set `sandbox.fallback_native: false` to restore the strict fail-closed
  posture (executions denied until Docker works). `sandbox.enabled: false` is
  the explicit operator opt-out for the legacy uncontained mode, without the
  Docker probing.

Build the worker image once (Linux is the primary hardened target; Windows/macOS
work via Docker Desktop):

```bash
docker build -t breachpilot-sandbox:latest docker/sandbox
```

To save laptop battery, set `sandbox.auto_manage_docker: true` (enabled in the
shipped local config). BreachPilot starts Docker only when a sandboxed exploit
session needs it and stops it afterward only if BP started it and no containers
remain. Linux uses non-interactive `sudo -n`; run `sudo -v` before `bp` when
needed. The WebUI, doctor, and recon paths do not start Docker.

`python main.py --doctor` verifies Docker and the worker image when the sandbox
is enabled. Full architecture, threat model, and residual risks:
[docs/sandbox.md](docs/sandbox.md).

The target-IP allowlist remains the scope authority — the sandbox is
containment, not an authorization proof. Only run against what you own.

Full model: [docs/safety-model.md](docs/safety-model.md)

---

## Quick start in 60 seconds

### Linux (primary platform)

```bash
curl -fsSL https://raw.githubusercontent.com/braydos-h/BreachPilot/main/install.sh | bash
#   ^ fresh machine: downloads the newest version into ~/.local/share/breachpilot
bp                        # launch from any directory; opens http://127.0.0.1:8765
```

From an existing checkout:

```bash
./install.sh              # full bootstrap: OS prereqs + Ollama + venv + WebUI + models + --doctor + launchers
bp                        # launch from any directory; opens http://127.0.0.1:8765
```

Installer essentials (`./install.sh --help` for all options):

```bash
./install.sh --check      # read-only health check, changes nothing
./install.sh --update     # atomic update with rollback (managed installs)
./install.sh --repair     # fix venv/deps/launchers/WebUI in place
./install.sh --full       # core + WebUI + Kali arsenal + scanners + models
./install.sh --uninstall  # remove app files, keep your data (see below)
```

Default paths: install `~/.local/share/breachpilot`, launchers
`~/.local/bin/{breachpilot,bp}`, log `~/.local/state/breachpilot/install.log`.
Updates and uninstalls preserve `config.yaml`, `.env`, `secr.json`,
`mission.yaml`, `reports/`, `research_workspace/`, `exploit_workspace/`,
`swarm_workspace/`, `api_runtime.db`, and `logs/`.
Full reference: [docs/deployment.md](docs/deployment.md).

Or step by step with make targets:

```bash
make install            # venv + deps
make doctor             # env check (Python/nmap/Ollama/config)
make run                # WebUI daemon + browser (http://127.0.0.1:8765)
```

That is the whole app. No CLI flags to memorize: everything happens in the WebUI.

<details>
<summary><strong>Windows (legacy, secondary)</strong></summary>

Windows still works where cheap, but it is no longer the primary dev
platform — the Kali arsenal is unavailable there (Python-only exploits).

```powershell
.\install.bat    # checks Python/Node/Nmap/Ollama, creates .venv, builds WebUI, pulls models, runs --doctor
.\START.bat      # launches the WebUI at http://127.0.0.1:8765
```

Or after install, from any terminal:

```powershell
python main.py   # opens the WebUI in your browser
```

</details>

### Set your API key

The default model is Ollama Cloud (`glm-5.2:cloud`). You need one key:

```bash
bp --setup-api-keys   # prompts and saves to secr.json (gitignored)
# or set env:  OLLAMA_API_KEY=your_key_here
```

Get a free key at https://ollama.com/settings/keys. Then `bp --doctor` should be all green.

> Prefer a different AI provider? The engine is provider-pluggable: Ollama is
> one optional provider (OpenCode Go and ChatGPT ship built-in; the WebUI
> System → Models page switches between them). `models.provider: opencode_go`
> + `embeddings.provider: none` in `config.yaml` runs the engine with the
> ollama package and endpoints not needed at all. The ollama Python package
> is an install extra (`pip install -e ".[ollama]"`). See
> [docs/providers.md](docs/providers.md) and
> [docs/provider-development.md](docs/provider-development.md) for adding provider #4.

---

## Requirements

| Need | Notes |
|------|-------|
| Python 3.11+ | `python3 --version`; `--doctor` rejects 3.10 |
| Docker Engine | Expected on Linux (default-on sandbox). Build the worker image: `docker build -t breachpilot-sandbox:latest docker/sandbox` |
| nmap | On `PATH` or set `nmap.path` in `config.yaml`. Linux `-O`/`-sS` need root: `nmap.sudo: true` (uses `sudo -n`) or `nmap.priv_fallback` (default `true`) auto-downgrades |
| Ollama | Cloud default (`https://api.ollama.com` + `OLLAMA_API_KEY`) or local daemon |
| Node.js + npm | Only for the first WebUI build; auto-built on first launch if present |
| Kali arsenal | Expected on Linux: Metasploit, searchsploit/exploitdb, hydra, impacket, crackmapexec, tmux (`INSTALL_KALI_TOOLS=1 ./install.sh`). Windows = Python-only fallback, no Kali tooling. |

`bp --doctor` checks all of this. `bp --self-test` runs a safe localhost smoke test.

---

## API keys

One command handles everything:

```bash
bp --setup-api-keys
```

| Variable | Purpose |
|----------|---------|
| `OLLAMA_API_KEY` | **Required** for Ollama Cloud (default) |
| `NVD_API_KEY` | Higher NVD CVE rate limit (optional) |
| `GITHUB_TOKEN` | Higher GitHub search limit for PoC search (optional) |
| `SERPAPI_API_KEY` | Fallback web research (optional) |

Keys live in env or `secr.json` (gitignored). The app does **not** auto-load `.env`.

---

## Configuration

Everything lives in `config.yaml`, validated against `tools/config/schema.py::CONFIG_SCHEMA` (re-exported by the `tools/config_manager.py` compat shim).

For day-to-day use you do not need to touch it: the WebUI System → Config editor and System → Secrets / Models pages cover it. Full key reference: [docs/config-reference.md](docs/config-reference.md)

Switching providers (Ollama ↔ OpenCode Go ↔ ChatGPT), models, skills, swarm, OPSEC, persistence, and API settings are all in there. Highlights:

- AI providers: a pluggable registry (`tools/providers/`; `models.provider` + `providers.<id>` blocks). Built-ins: `ollama` (default, cloud/local), `opencode_go` (OpenAI Responses API at opencode.ai), and `chatgpt` (vendored OAuth proxy). Ollama is optional end-to-end — a zero-Ollama install selects another provider and disables embeddings (`embeddings.provider: none`). Doctor probes only the active provider; `GET /api/v1/providers` returns registry metadata. See [docs/providers.md](docs/providers.md) / [docs/provider-development.md](docs/provider-development.md).
- Models: cloud-first (`glm-5.2:cloud` 976K, `deepseek-v4-pro:cloud` 1M, `kimi-k2.6:cloud` 256K, `minimax-m3:cloud` 512K) with per-role routing (planner/executor/critic/etc.). The registry auto-updates from the Ollama API (`models.auto_update`, default on): at daemon boot each alias is bumped to the newest same-family version the host lists — no manual edits when Ollama Cloud ships a new model. Boot refresh is throttled to once per hour per config file so restarts stay fast. Also on demand via `POST /api/v1/models/refresh` (the WebUI model picker's refresh button).
- Swarm & autonomous: toggle agents, concurrency, persistence phases, adaptive replan
- OPSEC: target-aware pacing, UA rotation, DoH, noise budget
- ICS: destructive PLC writes dual-gated (`allow_write` + `destructive_ics`)
- Sandbox: per-run disposable execution worker (`sandbox.*` keys — image, resource limits, network enforcement, DNS mode, `fallback_native` boot-time degrade-to-native, cleanup); see [docs/sandbox.md](docs/sandbox.md)
- API: concurrent runs (default 3), multi-operator, graph route, loopback auth
- Benchmark suite: `benchmark.*` keys — output dir, default trials, per-trial timeout, `sandbox_required`, baseline path, regression tolerances, telemetry toggles; see [docs/benchmarks.md](docs/benchmarks.md)
- Browser agent (Playwright, OFF by default): `browser.enabled: true` + `backend: playwright` enables the sandboxed Chromium agent (navigate/observe/discover/screenshot + gated JS execution, form submission and request replay behind `browser.allow_mutating_actions`) — contained in the browser worker image, target-locked, fail-closed when unconfigured; see [docs/browser-agent-design.md](docs/browser-agent-design.md)

---

## Plugins: extend without forking

Managed in `tools/plugins.py`. A plugin can add attack modules, MCP tools, skills, and config. Enable via `config.yaml` `plugins.enabled`. Reference example: `plugins/example_recon_report/`.

Shipped (each requires its API key to actually run; the lab build enables all except `snmp`):

| Plugin | What it adds |
|--------|-------------|
| `shodan_recon` | Shodan-powered recon enrichment |
| `github_dorks` | GitHub dork search for leaked creds |
| `webhook_notify` | Slack/Discord findings + state webhooks |
| `sliver_c2` | Sliver C2 integration |
| `bloodhound_ce` | BloodHound CE attack path mapping |
| `zap_scan` | OWASP ZAP active scanning |
| `browser_attack` | Browser-based attack surface |
| `mobile_attack` | Mobile app assessment |
| `wireless` | Wireless recon |
| `spiderfoot` | SpiderFoot OSINT |
| `atomic_red_team` | Atomic Red Team emulation |
| `caldera` | MITRE Caldera adversary emulation |
| `firmware_analysis` | Firmware extraction & analysis |
| `snmp` | SNMP enumeration via snmpwalk (opt-in — not enabled in the lab build) |

See [docs/plugin-development.md](docs/plugin-development.md).

---

## Documentation

| Guide | For |
|-------|-----|
| [Getting Started](docs/getting-started.md) | Setup, first run, dev loop |
| [WebUI](docs/webui.md) | SPA pages, wizard, live view, graph |
| [WebUI API](docs/api.md) | `GET /api/v1` REST + WebSocket |
| [Safety Model](docs/safety-model.md) | Scope, permission, audit, allowlist |
| [Providers](docs/providers.md) | Pluggable AI provider registry (Ollama / OpenCode Go / ChatGPT) |
| [Provider Development](docs/provider-development.md) | Adding a new AI provider |
| [Architecture](docs/architecture.md) | System shape, Flow A/B, persistence |
| [Skills](docs/skills.md) | 140-skill advisory pipeline |
| [Attack Modules](docs/attack-modules.md) | Pre-packaged exploit logic |
| [MCP Tools](docs/mcp-tools.md) | 120+ MCP tool reference |
| [Swarm](docs/swarm.md) | 6-agent blackboard architecture |
| [Plugin Development](docs/plugin-development.md) | Out-of-tree extensions |
| [Config Reference](docs/config-reference.md) | Every `config.yaml` key |
| [Evaluation](docs/evaluation.md) | Metrics & eval harness |
| [Benchmarks](docs/benchmarks.md) | Reproducible benchmark suite, oracles, regression gates |

Full index (36 guides): [docs/README.md](docs/README.md).

---

## Quality assurance

- Mocked pytest suite (~250 files in `tests/`): all subprocess and network calls are mocked, so no live Nmap. Covers scope gates, safety review, recon, swarm, audit chains, credential storage, Metasploit, and more.
- CI on every push and PR: Python 3.11-3.13 matrix, coverage (`coverage run -m pytest`), CodeQL, dependency-review.
- Lint is law: `ruff check .` (0 errors), `ruff format --check .` (0 diffs), and `mypy --follow-imports=skip tools` (216 files), all CI-enforced.
- WebUI tested: `tsc -b && vite build` plus `vitest` on every PR.
- Graded eval loop: `bp --eval` scores the agent against the `eval_targets/` oracle targets (declarative flags verified independently — agent claims never decide a flag). `--save-baseline` persists a baseline and `--eval --check-regression` exits non-zero when a target's score drops beyond `eval.regression_tolerance`. A nightly workflow (`.github/workflows/eval.yml`) runs the mocked eval tests on push/PR and the live graded suite on schedule, skipping gracefully without `OLLAMA_API_KEY`.
- Reproducible benchmark suite: `bp --benchmark xben [--scenario id | --tag web | --trials N]` runs sandboxed, oracle-verified benchmark trials with recorded model/git/sandbox metadata; `--save-baseline` / `--benchmark xben --check-regression` gate regressions in CI (exit 1 on hard findings). Results persist under `reports/benchmarks/<suite>/<run_id>/` with a public Markdown/HTML report, and the WebUI **Benchmarks** page shows live progress, verified-vs-claimed results, false positives, timelines, run comparison and history. See [docs/benchmarks.md](docs/benchmarks.md).
- Kill-chain state machine (opt-in, `killchain.enabled`): a per-target stage machine tracks recon → initial access → escalation → objective; `killchain_attempt` only advances state after independent verification probes pass (agent claims can't move the chain), and a BFS plan + system-prompt briefing steer the agent toward the configured `goal_state`.
- Snapshot + rollback (opt-in, `snapshots.enabled`): automatic snapshots before destructive actions across all three dispatch funnels (exploit loop, swarm bridge, campaign executor), backed by pluggable providers (Docker commit/rollback is the implemented path; Proxmox/libvirt/Hyper-V/VMware best-effort) and exposed as `snapshot_*` MCP tools. With `replay_simulator.counterfactual`, a failed exploit auto-reverts its snapshot and retries the mutated payload against the clean state, recording both outcomes in the final result. Fail-open by contract: a snapshot failure never blocks the attack path; provider tokens (`PROXMOX_API_TOKEN`) live in env vars only.

```bash
python3 -m pytest tests/ -v
ruff check . && ruff format --check .
mypy --follow-imports=skip tools
cd webui && npm ci && npm run build && npm run test
```

Coverage (matches CI; uses `coverage`, not `pytest-cov`):

```bash
python3 -m coverage run -m pytest tests/ && python3 -m coverage report
```

See [docs/testing-guide.md](docs/testing-guide.md).

---

## Architecture

```
operator ──► main.py / app.py (WebUI @ :8765)
               │
               ├─ open_exploit_mcp_session()  ──► mcp_exploit_server.py (:8001)
               │     stdio or HTTP, 30s boot budget, EXPLOIT_TARGET allowlist lock
               │
               ├─ GoalEngine ──► resolves preset/custom goals, risk-gated (SAFE/GATED/HIGH)
               │
                ├─ run_exploit_session() ──► tools/exploit_agent/ (runner loop + policy + prompt)
                │     120+ MCP tools, 140+ skills, 15 attack module families
               │
                ├─ SwarmOrchestrator (6 agents, shared blackboard, parallel dispatch)
                │     `--swarm`: single-target specialist decomposition
                │
                └─ AutonomousOrchestrator (persistent campaigns, adaptive aggression, vuln chaining)
                      default (no `--swarm`): multi-phase queue, resume + checkpoints
```

Two flows: Flow A (modern: `main.py` → `tools/exploit_agent`, `tools/mcp_tools`, `tools/swarm`) is what you run. Flow B (legacy, frozen in `legacy/`) is the SQLite research loop, still tested but frozen. See [docs/architecture.md](docs/architecture.md) and [docs/runtime-flows.md](docs/runtime-flows.md).

---

## Contributing

1. Read [AGENTS.md](AGENTS.md): non-obvious rules you will otherwise break.
2. Run `bp --doctor && bp --self-test` after safety changes.
3. Before a PR:
   ```bash
   python3 -m pip install -e ".[dev]"
   python3 -m pytest tests/ -v
   ruff check . && ruff format --check .
   mypy --follow-imports=skip tools
   cd webui && npm ci && npm run build && npm run test
   ```
   CI runs the same on Python 3.11-3.13 plus CodeQL and dependency-review.
4. Do not edit frozen Flow B safety files (`scope_gate.py`, `safety_reviewer.py`, `legacy/`).
5. New exploit MCP tools: add `@audit_tool` / `@require_allowlist()` in `tools/mcp_tools/<family>.py`; they are auto-discovered via `tools/mcp_tools/registry.py`.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

<details>
<summary><strong>Advanced: CLI & headless use</strong> (most users do not need this)</summary>

The CLI still works for scripting and headless runs. The WebUI is the default (`bp` opens it); add flags only if you need them.

```bash
# Wheel installs work from any directory (no repo checkout needed):
#   pip install dist/*.whl
#   mkdir /tmp/clean && cd /tmp/clean && breachpilot --doctor --json  # uses packaged skills + defaults

bp --help                              # full flag list
bp --target 10.0.0.50 --mode recon      # recon only
bp --target 10.0.0.50 --mode attack --goal backdoor
bp --target example.com --mode attack   # domain targeting
bp --demon                              # API only, no browser
bp --menu                               # legacy terminal menu
```

Legacy SQLite research loop (Flow B, frozen in `legacy/`):

```bash
python3 -m legacy.cli init-mission --config mission.yaml
python3 -m legacy.cli next-task
```

See `docs/runtime-flows.md` and `legacy/README.md`.

</details>
