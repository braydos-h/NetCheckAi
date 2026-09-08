# BreachPilot — Autonomous Security Testing

<div align="center">

Open-source agentic operator for authorized testing — plans, verifies, and reports with evidence, target-locked and audited.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![WebUI](https://img.shields.io/badge/WebUI-React%20%2B%20Vite%20%2B%20TypeScript-06b6d4?style=flat-square&logo=react&logoColor=white)
![LLM](https://img.shields.io/badge/LLM-Ollama%20%7C%20OpenCode%20Go%20%7C%20ChatGPT-22c55e?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-1.27%2B-f97316?style=flat-square)
![Skills](https://img.shields.io/badge/skills-139-8b5cf6?style=flat-square)
![MCP Tools](https://img.shields.io/badge/MCP%20tools-153-ec4899?style=flat-square)
![Tool Families](https://img.shields.io/badge/tool%20families-33-f97316?style=flat-square)
![Attack Families](https://img.shields.io/badge/attack%20families-15-red?style=flat-square)
![Swarm](https://img.shields.io/badge/swarm-6%20agents-06b6d4?style=flat-square)
![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)
[![Website](https://img.shields.io/badge/site-breachpilot--site.vercel.app-22c55e?style=flat-square)](https://breachpilot-site.vercel.app/)

Open source · Apache 2.0 · Local-first

**Plan · Recon · Exploit · Verify · Report** — 139 skills, 153 MCP tools across 33 tool families, 15 attack families, 6 swarm agents.

🌐 **[Try the live site](https://breachpilot-site.vercel.app/)** · [Quick start](#quick-start-in-60-seconds) · [WebUI](#webui-mission-control) · [Safety model](#safety-model) · [Docs](#documentation)

</div>

---

> [!WARNING]
> **Authorized testing only.** Only test systems you own or have explicit written permission to assess. Run on a throwaway operator box.
> **Attack mode = `full_access`**: every in-scope action is auto-approved. The safeties are the **target-IP allowlist lock** (off-allowlist destinations are `BLOCKED`) and the **mission scope gate** (`forbidden_actions` / `disallowed_assets` → `SCOPE_DENIED` audit row). Every action lands in a tamper-evident SHA-256 audit chain. Recon stays fully scope-gated. See [Safety model](#safety-model).

---

## Why BreachPilot

**A full assessment lifecycle, under supervision** — from reconnaissance through exploitation, verification, and reporting, with a human in the loop.

<table>
<tr>
<td width="33%" valign="top">

### Adversarial planning

A structured AttackPlan DAG with prerequisites, hypotheses, and automated failure recovery. Retries with refined parameters and records every decision in `decision_log.jsonl`.

</td>
<td width="33%" valign="top">

### Target-locked execution

Allowlist + mission scope gate on every action. Every destination is extracted from every command — off-allowlist is `BLOCKED`, scope violations log `SCOPE_DENIED`.

</td>
<td width="33%" valign="top">

### Evidence-based verification

Execution success and evidential success are separate. Every finding is `CONFIRMED` / `REFUTED` / `EXHAUSTED`, backed by oracle probes — agent claims never decide a verdict.

</td>
</tr>
<tr>
<td width="33%" valign="top">

### Domain-aware recon

Domain in, scope-aware attack surface out. Give it `example.com`: crt.sh + DNS bruteforce + subfinder/amass expansion, auto-authorized hosts, dangling-CNAME takeover flags. Wildcard and CIDR allowlist support.

</td>
<td width="33%" valign="top">

### Persistent knowledge

Lessons survive the run. 139 advisory skills with deterministic + semantic selection, mid-run re-selection, cross-mission Bayesian feedback, and semantic memory over embeddings.

</td>
<td width="33%" valign="top">

### Operator-supervised

Approval gates, disposable sandbox workers, and a SHA-256 audit chain. [Read the safety model →](#safety-model)

</td>
</tr>
</table>

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

First authorized runs (CLI, when you want them):

```bash
bp --target 10.0.0.50 --mode recon --recon-first       # recon only, read-only
bp --target 10.0.0.50 --mode attack --goal backdoor    # full attack
bp --target example.com --mode attack                  # domain targeting
bp --target 10.0.0.50 --mode attack --swarm --critic --reflection --adaptive-exploits
```

Artifacts land in `reports/<run_id>/` and `exploit_workspace/<target_ip>/`.

<details>
<summary><strong>Windows 10/11 (installer-supported, secondary platform)</strong></summary>

Windows is fully installer-supported via `install.ps1` (the single source of
truth for Windows installation; `install.bat` is a thin wrapper that finds
PowerShell and invokes it). The Kali arsenal is unavailable there, so Windows
runs Python-only exploits — Linux stays the primary hardened platform.

From a checkout (recommended — inspect before running):

```powershell
git clone https://github.com/braydos-h/BreachPilot.git
cd BreachPilot
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Remote bootstrap (downloads the installer, inspect it, then run):

```powershell
Invoke-WebRequest `
  https://raw.githubusercontent.com/braydos-h/BreachPilot/main/install.ps1 `
  -OutFile "$env:TEMP\breachpilot-install.ps1"
& "$env:TEMP\breachpilot-install.ps1"
```

> Never pipe a downloaded script to `Invoke-Expression` (`irm ... | iex`).
> Save `install.ps1` to disk, inspect it if desired, then execute it.
> `-ExecutionPolicy Bypass` above applies to that one process only — no
> permanent policy change.

Installer essentials (`.\install.ps1 -Help` for exit codes and all options):

```powershell
.\install.ps1 -Check       # read-only diagnostics, changes nothing
.\install.ps1 -Yes         # non-interactive (auto-approves winget installs)
.\install.ps1 -Update      # safe upgrade preserving config/secrets/data, with rollback
.\install.ps1 -Repair      # repair launcher/venv/deps/WebUI/PATH, keeps user data
.\install.ps1 -Uninstall   # remove BreachPilot-owned components (keeps shared deps)
.\install.ps1 -InstallDir "D:\Apps\BreachPilot"   # custom per-user location
.\install.ps1 -Version "v0.68.4" -Channel Stable  # pin release / Stable|Prerelease|Main
.\install.ps1 -SkipWebUI -SkipDocker -SkipOllama  # opt out of WebUI build / sandbox / Ollama
```

Default install dir: `%LOCALAPPDATA%\BreachPilot`. Launchers `bp`/`breachpilot`
go to `%USERPROFILE%\.local\bin` (+ user PATH). Logs:
`%LOCALAPPDATA%\BreachPilot\logs\installer-*.log`.

Docker Desktop (WSL2) is recommended: the sandbox is default-ON and
fail-closed. With `-SkipDocker` the installer states the resulting
native-execution mode loudly instead of hiding it. Ollama is optional
(provider-pluggable: Ollama / OpenCode Go / ChatGPT) — the installer only
requires it when your `config.yaml` selects it.

After install, from any terminal:

```powershell
bp              # opens the WebUI at http://127.0.0.1:8765
.\START.bat     # double-click launcher (same, from the install folder)
python main.py  # direct, from the install folder
```

Troubleshooting: re-run with `-Repair`; read the printed log path; exit codes
`0` success / `7` doctor failed / `8` rolled back / `9` reboot needed /
`10` action required (e.g. provider key). Docker Desktop first-installs often
need a logout/reboot before the daemon responds.

</details>

---

## Requirements

| Need | Notes |
|------|-------|
| Python 3.11+ | `python3 --version`; `--doctor` rejects 3.10 |
| Docker Engine | Expected on Linux (default-on sandbox). Build the worker image: `docker build -t breachpilot-sandbox:latest docker/sandbox` |
| nmap | On `PATH` or set `nmap.path` in `config.yaml`. Linux `-O`/`-sS` need root: `nmap.sudo: true` (uses `sudo -n`) or `nmap.priv_fallback` (default `true`) auto-downgrades |
| AI provider | Lab checkout defaults to OpenCode Go (`OPENCODE_GO_API_KEY`); Ollama Cloud (`https://api.ollama.com` + `OLLAMA_API_KEY`) or local daemon via `models.provider: ollama`; ChatGPT via `models.provider: chatgpt` |
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
| `OPENCODE_GO_API_KEY` | **Required** when `models.provider: opencode_go` (lab checkout default) |
| `OLLAMA_API_KEY` | **Required** when `models.provider: ollama` (schema default, `glm-5.2:cloud`) |
| `NVD_API_KEY` | Higher NVD CVE rate limit (optional) |
| `GITHUB_TOKEN` | Higher GitHub search limit for PoC search (optional) |
| `SERPAPI_API_KEY` | Fallback web research (optional) |

Keys live in env or `secr.json` (gitignored). The app does **not** auto-load `.env`.
Get a free Ollama key at https://ollama.com/settings/keys. Then `bp --doctor` should be all green.

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
  the open internet are unreachable regardless of what the command says.
- **Fail closed**: `sandbox.fallback_native` defaults to `false` (schema +
  lab config) — sandbox failures deny execution with a structured
  `SANDBOX_*` error until Docker works. Set it `true` to opt into the loud
  whole-session degrade-to-native mode (warning + amber WebUI banner +
  `SANDBOX_FALLBACK:` lines). `sandbox.enabled: false` is the explicit
  operator opt-out for legacy uncontained mode.

Build the worker image once (Linux is the primary hardened target; Windows/macOS
work via Docker Desktop):

```bash
docker build -t breachpilot-sandbox:latest docker/sandbox
```

To save laptop battery, set `sandbox.auto_manage_docker: true`.
BreachPilot starts Docker only when a sandboxed exploit session needs it and
stops it afterward only if BP started it and no containers remain. Linux uses
non-interactive `sudo -n`; run `sudo -v` before `bp` when needed. The WebUI,
doctor, and recon paths do not start Docker.

`python main.py --doctor` verifies Docker and the worker image when the sandbox
is enabled. Full architecture, threat model, and residual risks:
[docs/sandbox.md](docs/sandbox.md).

The target-IP allowlist remains the scope authority — the sandbox is
containment, not an authorization proof. Only run against what you own.

Full model: [docs/safety-model.md](docs/safety-model.md)

---

## Platform capabilities

### A structured plan, not a prompt chain

The attack plan is a DAG: prerequisites, hypotheses, blocked steps, and
evidence-linked outcomes. The planner composes prerequisites dynamically
(`find_producers(artifact)`), retries with modified parameters on failure,
and tracks privilege-escalation chains. Every decision is recorded in
`decision_log.jsonl`.

### Reconnaissance

- Fast recon pipeline: parallel TCP discovery, service fingerprinting, OS detection, and vulnerability enrichment, all concurrent and cached.
- Nmap done right: ping sweep → triage → service → vuln scans, with `priv_fallback` auto-downgrade and pre-flight reachability probes so firewalled hosts don't waste your time.
- Extended enumerators: UDP top-ports, SNMP, DNS zone transfer / DNSSEC / SPF / DMARC, ASN/WHOIS, cloud metadata probe, WAF fingerprinting, vhost discovery.
- Domain recon: `resolve_domain`, `enumerate_subdomains`, `dns_recon` (AXFR/DNSSEC), `vhost_enum` (Host-header rotation), `domain_whois`, all allowlist-gated.
- Threat intel: NVD + EPSS + CISA KEV + OSV + GHSA, with circuit breaker, rate limiting, and GitHub token support for PoC search.

### Exploitation and chaining

- 15 attack module families (`tools/attack_modules/modules/`): `web` (+ `sqli`/`xss`/`upload`), `auth_creds`, `crypto_jwt`, `deserialize`, `network_smb`, `privesc`, `services`, `ssh`, `synthesis`, `supply_chain`, `persistence`, `ad`, `ics`/`ics_iot`, `detection`, `orchestrator_phases`. Each scores its own applicability (0-100) against your target's services, ports, and CVEs.
- Capability-aware planning: every module declares `requires` / `produces` / `read_only` / `cost` / `phase_hint`, so the planner can dynamically compose prerequisites and gate execution.
- Payload crafting and mutation: `PayloadCrafter` + `ExploitMutator` with 4 strategies (parameter tweak, encoding change, delivery swap, context-aware). Auto-generates and mutates Python exploit scripts.
- Metasploit bridge: `run_msf_module`, `msfconsole` lifecycle, `msfvenom` payload generation, session/payload/post-module orchestration, resource scripts. Full Kali arsenal on Linux, Python-only on Windows.
- Web scanning: nikto / nuclei / sqlmap / gobuster / feroxbuster / whatweb / wpscan. Argv-list execution, `which`-checked, parsed `WEB_SCAN_RESULT` blocks.

### Adaptive intelligence

- 139 advisory skills: a YAML + markdown prompt-context layer, scored by deterministic tags + lexical search + cross-mission Bayesian feedback + semantic cosine similarity over `nomic-embed-text` embeddings. Mid-run re-selection as new CVEs surface.
- Semantic memory: cross-mission learning via `SemanticMemoryManager` + `ExperienceStore`. The orchestrator stores lessons on every confirmed win.
- Attack memory: per-attempt context window management (6K chars), compaction every 50 rounds, persistent campaign state.
- Model telemetry: token counts, context utilization, duration, and tokens/sec for every LLM call.
- Peer model consult: brings Kimi K2.6, DeepSeek V4 Pro (1M context), GLM-5.2, and Minimax M3 in mid-run for advisory ideas without tool access. Configurable `consult_aliases`.

### Post-exploitation and lateral movement

- Credential ops: encrypted vault (`credential_store`), `lateral_exec` via Impacket, `dump_credentials`, `kerberoast`, and `hash_crack` (hashcat/john with auto hash-type ID + `--show` recovery).
- Active Directory: BloodHound CE, AD ACL abuse, AS-REP roast, pass-the-hash, ADCS/Certipy, Golden Ticket, Responder relay, SMB signing checks.
- Operator connection: persistent RCE beacons (netcat/TLS/DNS/HTTPS/SOCKS pivot) with `exploit_workspace` callback management.
- ICS/IoT: Modbus, S7 & BACnet PLC modules, read-only by default. Destructive writes are dual-gated behind `ics.allow_write` + `ics.destructive_ics`.

### Operational security

- Target-aware OPSEC: auto-disabled on private/local targets (RFC1918/loopback/link-local) so the agent moves freely in your lab; full posture on public targets. UA rotation, DoH, pacing with jitter, rate limiting, quiet-command rewrites, noise budget. All advisory, never a gate: the command always executes, and you get `OPSEC_ADVISORY` blocks suggesting quieter alternatives.

### Reporting and export

- MITRE ATT&CK Navigator export: technique-mapped layer JSON for SOC handoff (`reports/mitre/`).
- Ticketing: auto-create Jira/GitHub issues from confirmed findings.
- Report contents: timelines, CVSS, exploit chains, Markdown + HTML, `decision_log.jsonl`, tamper-evident audit, loot and credential tables, and graph evidence.

---

## Skills, agents, and memory

### 139 advisory skills

Each skill is a curated `SKILL.md` under `skills/`, such as `conducting-network-penetration-test`, `executing-red-team-engagement-planning`, `exploiting-jwt-algorithm-confusion-attack`, `exploiting-ssti`, `exploiting-nopac-cve-2021-42278-42287`, and `attacking-domains-end-to-end`. The engine deterministically selects the top six for the current context, re-evaluates mid-run, and supports semantic matching via embeddings.

Categories include network penetration testing, web/API, auth/JWT/OAuth, deserialization, AD/BloodHound, SMB/network, privilege escalation, cryptography, supply chain, detection, persistence, and ICS/IoT. See [docs/skills.md](docs/skills.md) and [docs/skill-authoring.md](docs/skill-authoring.md).

### Multi-agent orchestration: six specialists, one shared blackboard

Shared blackboard + battle log. The Swarm Orchestrator runs parallel dispatch with cross-phase negotiation.

| Agent | Job |
|-------|-----|
| `recon` | Expand surface, stay in scope |
| `vuln` | Match CVEs to capabilities |
| `exploit` | Craft, mutate, execute |
| `post_exploit` | Loot and lateral targets |
| `critic` | Kill out-of-scope actions |
| `reflection` | Learn for the next run |

Orchestrated via `tools/swarm/orchestrator.py` with a shared blackboard, battle log, parallel dispatch, and phase-aware skill hints. See [docs/swarm.md](docs/swarm.md).

**Swarm vs campaign:** `--swarm` decomposes a *single target* across the six specialists (parallel recon + vuln research, critic pre-check, reflection shifts). Without `--swarm`, the autonomous campaign drives a persistent multi-phase queue (recon → exploit → privesc → lateral → validation) with adaptive aggression, resume, and checkpoints across one or many targets. Combine both on high-value targets. Same target-IP lock and permission model either way.

### MCP tool suite: 153 tools across 33 families

| Family | Capability |
|--------|-----------|
| `terminal` | Shell execution with target-IP allowlist enforcement and OPSEC advisory |
| `workspace` | `write_python_file` / `run_python_file` / `read_workspace_file` (lab build: operator-box filesystem is unrestricted) |
| `recon` | `check_os`, `quick_scan`, `run_full_recon`, `get_service_fingerprint` |
| `attack_modules` + `planning` + `synthesis` + `adaptive` + `campaign` | `run_attack_module`, `craft_exploit`, `mutate_exploit`, plan DAG, prerequisite synthesis, campaign control |
| `web` + `web_scan` | Web-app probes (SQLi/XSS/upload/JWT/SSTI/GraphQL/…) + nikto, nuclei, sqlmap, gobuster, feroxbuster, whatweb, wpscan |
| `metasploit` | Full `msfconsole` lifecycle, sessions, payloads, and post modules |
| `payloads` | `generate_payload` via msfvenom |
| `cracking` + `hash` | hashcat/john with automatic hash-type identification |
| `credentials` | Encrypted vault and Impacket-based lateral execution / Kerberoast |
| `sessions` | tmux, background jobs, and listeners (beacons) |
| `research` | `search_exploit_db`, `search_web_exploit`, `deep_research`, `search_cve_intel` |
| `domain` | DNS, subdomain enumeration, AXFR, vhost, WHOIS, with automatic authorization |
| `browser` | Sandboxed Playwright agent (navigate/observe/discover/screenshot; JS execution, form submit, and request replay gated behind `browser.allow_mutating_actions`) |
| `peer_models` | `consult_peer_models`, advisory multi-model consultation |
| `runtime_skills` | `list`, `search`, and `load` skills at runtime |
| `killchain` | `killchain_status`, `killchain_attempt`, `killchain_plan` — evidence-verified stage machine (opt-in, `killchain.enabled`) |
| `snapshots` | `snapshot_create`, `snapshot_revert`, `snapshot_list` — provider-backed VM/container rollback (opt-in, `snapshots.enabled`) |
| `retest` | `retest_finding` — re-runs a confirmed finding's stored PoC probe (`STILL_OPEN` / `FIXED` / `INCONCLUSIVE`) |
| `hitl` | `propose_finding`, `hitl_decide`, `list_proposed` — agents propose candidates (`PROPOSED`), a human Approves/Rejects them in the WebUI Evidence tab; only `APPROVED` becomes a finding |
| `verify` | `verify_finding` — re-proves a candidate finding's stored probe N/N times (`VERIFIED` / `HOLDING` / `INCONCLUSIVE` + proof capsule) |
| + 6 more | `assessment_state`, `parallel_agents`, `poc_verifier`, `replay_simulator`, `mitre`, `ad`, `operator_connection` |

All tools are registered via `tools/mcp_tools/registry.py` using the `@audit_tool` / `@require_allowlist()` decorators and auto-discovered through `collect_tools()`, which also fails CI if a tool lacks its audit or allowlist gate. No manual registration required. See [docs/mcp-tools.md](docs/mcp-tools.md).

---

## WebUI: mission control

**Mission control for the whole run.** The WebUI serves at `http://127.0.0.1:8765`. It is loopback-only, bearer-token authenticated, and streams events in real time.

| Route | Page | Description |
|-------|------|-------------|
| `/` | Home | Status overview and entry point |
| `/runs/new` | New Run | Configure target, model, goal, and execution options, then review and launch. Supports IP and domain targets |
| `/sessions` | Sessions | Run list and history |
| `/runs/:runId` | Live Run | Real-time event stream: tool calls, decisions, telemetry via WebSocket and SSE, plus Evidence / Graph / Recon / Swarm / Campaign / Sandbox / Browser / Audit / Tools tabs |
| `/runs/:runId/graph` | Attack Graph | Interactive DAG (ReactFlow) with pan, zoom, filtering, path finding, and evidence inspection |
| `/graph` | Global Graph | Cross-run attack graph (v2) |
| `/runs/:runId/artifacts` | Artifacts & Audit | Reports, raw Nmap output, findings, and the SHA-256 audit chain |
| `/runs/:runId/loot` | Loot & Credentials | Captured credentials and loot per run, encrypted at rest |
| `/skills` | Skills | Advisory skill catalog and per-run skill selection |
| `/modules` | Modules | Attack module families, applicability scores, and run history |
| `/goals` | Goals | Goal presets, risk gating (SAFE/GATED/HIGH), and custom goals |
| `/benchmarks` | Benchmarks | Oracle-verified suites, live progress, run comparison (`/new`, `/history`, `/:runId`) |
| `/memory` | Memory | Cross-mission semantic memory and experience-store lessons |
| `/connections` | Connections | Operator connections, listeners, and beacon health |
| `/ops` | Ops | Operational controls and runtime state |
| `/stats` | Stats | Run statistics and telemetry |
| `/system` | System | Configuration, secrets, models and providers, skills, plugins, and diagnostics. No manual YAML editing required |
| `/help` | Help | In-app help and reference |

The UI is a Vite + React + TypeScript SPA (`webui/`) with TanStack Query, Radix UI, and Tailwind CSS. The production bundle is built automatically on first launch when Node.js is available.

For dev hot-reload:

```bash
cd webui && npm install && npm run dev   # http://127.0.0.1:5173 proxies to :8765
```

Full reference: [docs/webui.md](docs/webui.md) · API: [docs/api.md](docs/api.md) · Live docs: http://127.0.0.1:8765/docs

---

## Configuration

Everything lives in `config.yaml`, validated against `tools/config/schema.py::CONFIG_SCHEMA` (re-exported by the `tools/config_manager.py` compat shim).

For day-to-day use you do not need to touch it: the WebUI System → Config editor and System → Secrets / Models pages cover it. Full key reference: [docs/config-reference.md](docs/config-reference.md)

Provider reality check (schema default vs lab checkout):

- Schema default is `models.provider: ollama` (Ollama Cloud `glm-5.2:cloud`).
  The lab `config.yaml` ships `models.provider: opencode_go` with
  `embeddings.provider: none` — a zero-Ollama setup. Switch providers from
  the WebUI System → Models page; no code change either way.
- AI providers are a pluggable registry (`tools/providers/`; `models.provider`
  + `providers.<id>` blocks). Built-ins: `ollama` (cloud/local),
  `opencode_go` (OpenAI Responses API at opencode.ai), and `chatgpt`
  (vendored OAuth proxy). Doctor probes only the active provider.
- Models: cloud-first (`glm-5.2:cloud` 976K, `deepseek-v4-pro:cloud` 1M,
  `kimi-k2.6:cloud` 256K, `minimax-m3:cloud` 512K, `glm-5.3-flash` 128K fast
  option) with per-role routing (planner/executor/critic/etc.). The registry
  auto-updates from the Ollama API (`models.auto_update`, default on), also
  on demand via `POST /api/v1/models/refresh`.
- Browser agent: OFF by schema default; **ON in the shipped lab
  `config.yaml`** (`browser.enabled: true`, `backend: playwright`) —
  sandboxed Chromium, target-locked, fail-closed when unconfigured; JS
  execution, form submission, and request replay stay behind
  `browser.allow_mutating_actions`. See [docs/browser-agent-design.md](docs/browser-agent-design.md).
- Sandbox: per-run disposable execution worker (`sandbox.*` keys — image,
  resource limits, network enforcement, DNS mode, `fallback_native`
  fail-closed default, cleanup); see [docs/sandbox.md](docs/sandbox.md).
- API: concurrent runs (default 3), multi-operator, graph route, loopback auth.
- Benchmark suite: `benchmark.*` keys — output dir, default trials,
  per-trial timeout, `sandbox_required`, baseline path, regression
  tolerances, telemetry toggles; see [docs/benchmarks.md](docs/benchmarks.md).

---

## Plugins: extend without forking

Managed in `tools/plugins.py`. A plugin can add attack modules, MCP tools, skills, and config. Enable via `config.yaml` `plugins.enabled`. Reference example: `plugins/example_recon_report/`.

Shipped (the lab build enables 13 of these; each requires its API key to actually run):

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
| [Getting Started](docs/getting-started.md) · [Tutorial](docs/tutorial.md) · [Glossary](docs/glossary.md) · [CLI Reference](docs/cli-reference.md) | Setup, first run, terms, flags, entry points |
| [Architecture](docs/architecture.md) · [Runtime Flows](docs/runtime-flows.md) · [Run Service](docs/run-service.md) | System shape, Flow A/B, run lifecycle, persistence |
| [Exploit Agent](docs/exploit-agent.md) · [Exploit Policy](docs/exploit-policy.md) · [Attack Modules](docs/attack-modules.md) · [Swarm](docs/swarm.md) · [Campaign](docs/campaign.md) · [Browser Agent](docs/browser-agent-design.md) | Loop lifecycle, permission model, 15 exploit families, 6-agent swarm, multi-phase campaigns, Playwright agent |
| [WebUI](docs/webui.md) · [WebUI API](docs/api.md) · [MCP Tools](docs/mcp-tools.md) · [MCP Wiring](docs/mcp-wiring.md) | SPA pages, REST + WebSocket, 153-tool catalog, transports and boot |
| [Safety Model](docs/safety-model.md) · [Sandbox](docs/sandbox.md) · [Config Reference](docs/config-reference.md) · [Deployment](docs/deployment.md) | Scope and audit, Docker worker, every `config.yaml` key, install and hardening |
| [Providers](docs/providers.md) · [Provider Development](docs/provider-development.md) · [Skills](docs/skills.md) · [Skill Authoring](docs/skill-authoring.md) · [Research](docs/research.md) | Ollama / OpenCode Go / ChatGPT registry, adding provider #4, 139-skill pipeline, authoring, web research |
| [Evaluation](docs/evaluation.md) · [Benchmarks](docs/benchmarks.md) · [Testing Guide](docs/testing-guide.md) | Metrics and eval harness, oracle suites and regression gates, pytest layout |

Full index (40+ guides): [docs/README.md](docs/README.md). Product tour: [breachpilot-site.vercel.app](https://breachpilot-site.vercel.app/).

---

## Quality assurance

- Mocked pytest suite (~340 files in `tests/`): all subprocess and network calls are mocked, so no live Nmap. Covers scope gates, safety review, recon, swarm, audit chains, credential storage, Metasploit, and more.
- CI on every push and PR: Python 3.11-3.13 matrix, coverage (`coverage run -m pytest`), CodeQL, dependency-review.
- Lint is law: `ruff check .` (0 errors), `ruff format --check .` (0 diffs), and `mypy --follow-imports=skip tools` (~335 files), all CI-enforced.
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
                │     153 MCP tools, 139 skills, 15 attack module families
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

Product tour: [breachpilot-site.vercel.app](https://breachpilot-site.vercel.app/) · Repository: [github.com/braydos-h/BreachPilot](https://github.com/braydos-h/BreachPilot)

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
bp --target 10.0.0.50 --mode fast       # parallel recon preset, then attack
bp --demon                              # API only, no browser (--daemon alias)
bp --web                                # build WebUI if needed, serve it, open a browser
bp --menu                               # legacy terminal menu
bp --swarm --parallel-swarm --critic --reflection   # swarm decomposition
bp --long-session                       # multi-hour attack mode
bp --eval --save-baseline --check-regression        # graded eval harness
bp --benchmark xben --check-regression  # oracle benchmark suite
```

`--mode fast` runs the parallel recon preset then attacks. `--ctf*` flags
(`--ctf`, `--ctf-flag-path`, `--ctf-root-shell`, `--ctf-port`,
`--ctf-marker`) adapt runs for CTF targets. `--skills*` flags
(`--skills on|off|hints|lookup`, `--skills-list`, `--skills-include`,
`--skills-exclude`, `--no-skills-reselect`) override skill selection.
`--multi-model-consult` / `--no-multi-model-consult` toggle peer-model
advisories; `--observer-mode` picks heuristic/llm/hybrid observation.

Legacy SQLite research loop (Flow B, frozen in `legacy/`):

```bash
python3 -m legacy.cli init-mission --config mission.yaml
python3 -m legacy.cli next-task
```

See `docs/runtime-flows.md`, `docs/cli-reference.md`, and `legacy/README.md`.

</details>
