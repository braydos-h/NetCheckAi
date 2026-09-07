---
title: "Tool Family: agent-modules"
sources:
  - tools/mcp_tools/modules/planning.py
  - tools/mcp_tools/modules/campaign.py
  - tools/mcp_tools/modules/adaptive.py
  - tools/mcp_tools/modules/synthesis.py
  - tools/mcp_tools/modules/hash.py
  - tools/mcp_tools/modules/web.py
  - tools/mcp_tools/attack_modules.py
  - tools/attack_planner.py
  - tools/autonomous_orchestrator.py
  - tools/exploit_mutator.py
  - tools/payload_crafter.py
  - tools/attack_modules/
  - tools/cve_lookup.py
  - tools/recon_pipeline.py
tests:
  - tests/test_mcp_tool_registration.py
  - tests/test_mcp_injection_hardening.py
  - tests/test_web_probe_tools.py
  - tests/test_cve_templates_phase4.py
  - tests/test_mcp_cracking.py
  - tests/test_campaign_checkpoint.py
  - tests/test_cve_to_poc.py
  - tests/test_poc_verifier.py
subsystem: mcp
---

# Tool Family: agent-modules

Agent-planning MCP adapters split out of the attack-modules god file into `tools/mcp_tools/modules/`. Each file defines one `register_*_tools(mcp, *, ctx)` registrar; `tools/mcp_tools/registry.py` auto-discovers every `register_*_tools` in the package **including subpackages** (`modules/`, `terminal/`) via `_discover_tool_registrars`, and `collect_tools()` AST-validates that every `@mcp.tool` also carries `@audit_tool` or `@require_allowlist` (CI fails otherwise). No edit to `mcp_exploit_server.py` is needed for a new module file.

- **Registration sources:** `register_planning_tools` (`modules/planning.py:18`), `register_campaign_tools` (`modules/campaign.py:32`), `register_adaptive_tools` (`modules/adaptive.py:17`), `register_synthesis_tools` (`modules/synthesis.py:16`), `register_hash_tools` (`modules/hash.py:128`), `register_web_tools` (`modules/web.py:170`).
- **Context:** `ToolContext` (`tools/mcp_tools/registry.py:45-61`) — `workspace`, `config`, `search` (`ExploitSearch`), `nvd` (`NVDClient`), `researcher` (`WebResearcher`), `audit_tool`, `require_allowlist`, plus `sandbox` / `sandbox_notice` for the execution plane.
- **Gate pattern:** target-touching tools use `@require_allowlist()`; advisory/local-only tools use `@audit_tool`. `run_campaign_step` is `@audit_tool` + a **manual** `check_targets_allowlist` on the target read back from `state.json` (LLM-writable path).
- **Shared helper:** `_identify_hash_modes(h)` (`modules/hash.py:11`) — single source for the hash-type → hashcat-mode mapping, re-exported via `tools/mcp_tools/attack_modules.py` for `cracking.py` and `modules/synthesis.py`.

## Architecture

```
mcp_exploit_server.create_mcp_server
  └─ collect_tools() ─► _discover_tool_registrars()  (package walk incl. modules/)
       ├─ register_planning_tools  → create_attack_plan / get_current_plan / replan
       ├─ register_campaign_tools  → start_autonomous_campaign / get_campaign_status /
       │                              run_campaign_step / stop_campaign
       ├─ register_adaptive_tools  → craft_exploit / mutate_exploit
       ├─ register_synthesis_tools → cve_to_exploit_synth (+ 18 _render_* templates)
       ├─ register_hash_tools      → hash_crack_identify (+ _identify_hash_modes)
       └─ register_web_tools       → jwt_tamper / ssti_probe / graphql_introspect /
                                      race_request / timing_oracle /
                                      request_smuggling_probe / password_spray
```

Backing engines live outside `mcp_tools`: `tools/attack_planner.py` (plan model + prompts), `tools/autonomous_orchestrator.py` (campaign runner), `tools/exploit_mutator.py` + `tools/payload_crafter.py` (adaptive generation), `tools/attack_modules/` (pre-packaged module registry), `tools/cve_lookup.py` + `ExploitSearch.cve_to_poc` (synth evidence), `tools/recon_pipeline.py` (campaign step recon).

## Planning (`modules/planning.py`)

```python
def register_planning_tools(mcp: Any, *, ctx: ToolContext) -> None
def create_attack_plan(target_ip: str, target_os: str = "", known_cves: str = "") -> str
def get_current_plan(target_ip: str) -> str
def replan(target_ip: str, failure_reason: str) -> str
```

| Tool | Gate | Result shape | Notes |
|------|------|--------------|-------|
| `create_attack_plan` | `@require_allowlist()` | `ATTACK_PLAN_CREATED: <ip>\nPLAN_ID: ...\nPHASES: RECON → …\nCURRENT_PHASE: ...\nTOTAL_STEPS: N\nSAVED_TO: plans/<ip>_plan.json` | `AttackPlanner(workspace).create_plan(target_ip, target_os, known_cves.split(","), attack_mode=True)`; when `_get_model_client(config)` returns a client, builds `build_planning_prompt(...)` and appends `parse_plan_json(content)` steps; always `planner.save_plan(plan)`. Invalid target → `ERROR: Invalid target (IP or domain).` |
| `get_current_plan` | `@require_allowlist()` | `ATTACK_PLAN: ...\nCURRENT_PHASE / PHASES / TOTAL_STEPS / COMPLETED / SUCCESSFUL / FAILED / IS_COMPLETE` + `plan.generate_battle_log()` | `planner.load_plan(target_ip)`; missing → `NO_PLAN_FOUND: ... Use create_attack_plan first.` |
| `replan` | `@require_allowlist()` | `REPLAN_RESULT: ...\nFAILURE_REASON: <first 200 chars>\nNEW_PHASE: ...\nTOTAL_STEPS: ...` + battle log | Loads plan, builds `build_replanning_prompt(plan, failure_reason, attacker_os)`; `parse_replan_json` yields `(action, step, explanation)` — `next_phase` / `done` / `add_step`; model failure falls back to `plan.next_phase()`. Always re-saves. |

Lifecycle: `create_attack_plan` → `workspace/plans/<ip_underscored>_plan.json` → `get_current_plan` reads → `replan` mutates + re-saves. Kill chain phases follow `RECON → ENUMERATE → EXPLOIT → ESCALATE → LOOT → PIVOT → DONE` (per the tool docstring; phase enum lives in `tools/attack_planner.py`).

## Campaign (`modules/campaign.py`)

```python
_running_campaign_tasks: set = set()
_campaign_orchestrators: dict[str, Any] = {}
def register_campaign_tools(mcp: Any, *, ctx: ToolContext) -> None
async def start_autonomous_campaign(target_ip: str, goal: str = "initial_access", aggression_level: str = "normal") -> str
def get_campaign_status(campaign_id: str) -> str
async def run_campaign_step(campaign_id: str) -> str
def stop_campaign(campaign_id: str) -> str
```

| Tool | Gate | Result shape | Notes |
|------|------|--------------|-------|
| `start_autonomous_campaign` | `@require_allowlist()` | `CAMPAIGN_STARTED: <id>\nTARGET / GOAL / AGGRESSION\nSTATUS: started\nCAMPAIGN_DIR / STATE_FILE` | Maps `stealth/normal/aggressive/maximum` → `AggressionLevel` (unknown → NORMAL). `campaign_id = campaign-<UTC ts>-<sha256(target)[:8]>`; `workspace/campaigns/<id>/` + initial `state.json` (`status: started`). Merges the `autonomous` config block plus `opsec`, `exploit.msf.auto_local_exploit_suggester`, `orchestrator.semantic_memory` + `ollama`/`memory.embedding_model`, `agent`, `killchain`, `snapshots`, `replay_simulator`, then overrides `target/goal/aggression/max_cycles (= exploit.max_rounds)/workspace`. Domain targets thread `original_target` + `resolved_ip` (`is_fqdn` / `resolve_target_to_ip`). Launches `asyncio.create_task(orchestrator.run_autonomous_campaign(...))`, held in `_running_campaign_tasks` (strong ref — the event loop only weak-refs tasks) with a done-callback that drops the ref and pops `_campaign_orchestrators[campaign_id]`. Completion writes `status: completed` (+ task counts from `orchestrator._tasks` by `TaskStatus`); exception writes `status: error` + `last_error`. `swarm.enabled: false` in config → `BLOCKED: swarm is disabled in config.yaml.` |
| `get_campaign_status` | `@audit_tool` | `CAMPAIGN_STATUS / TARGET / GOAL / STATUS / AGGRESSION / CURRENT_PHASE / STARTED_AT / COMPLETED_AT\nTASKS: Completed/Failed/Pending\nCOMPROMISED: ...\nLAST_ERROR?` | Pure read of `workspace/campaigns/<id>/state.json`; missing → `ERROR: Campaign '<id>' not found.` |
| `run_campaign_step` | `@audit_tool` + manual `check_targets_allowlist([target_ip], config)` | `CAMPAIGN_STEP_RESULT: recon_completed / executed / no_applicable_modules / blocked` | Rebuilds a single-step `AutonomousOrchestrator` (`max_cycles=1`, same config merge as start). If `state.recon_result is None`, runs `ReconPipeline(ReconConfig()).recon_host(target_ip)` → sets `ENUMERATION`, writes state, returns open ports/services. Else builds `ModuleContext(target_ip, target_os, services)` and runs the top `find_modules(ctx)` hit, bumping `tasks.completed/failed` and `compromised_hosts` in `state.json`. Off-allowlist target from state → `CAMPAIGN_STEP_RESULT: blocked`. |
| `stop_campaign` | `@audit_tool` | `STOPPED: Campaign '<id>' stop signal sent.` / `... is not running (already finished).` / `ERROR: Campaign '<id>' not found.` | `orchestrator.stop()` on the live entry in `_campaign_orchestrators`; `state.json` left intact for `get_campaign_status`. |

## Adaptive (`modules/adaptive.py`)

```python
def register_adaptive_tools(mcp: Any, *, ctx: ToolContext) -> None
def craft_exploit(target_ip: str, service_name: str, version: str = "", os_hint: str = "", module_name: str = "") -> str
def mutate_exploit(script_id: str, failure_output: str) -> str
```

| Tool | Gate | Result shape | Notes |
|------|------|--------------|-------|
| `craft_exploit` | `@require_allowlist()` | `CRAFT_EXPLOIT_RESULT: generated\nGENERATION_ID / SCRIPT_PATH / SIDECAR_PATH / CONFIDENCE / MUTATION_STRATEGY / TARGET / SERVICE / OS_HINT / MODULE` + `SCRIPT_PREVIEW (first 500 chars)` | `ExploitMutator(workspace=exploits_dir, experience_store, client, model, max_mutations).craft_initial(...)`. `ExperienceStore(get_default_db())` falls back to `None` when the DB is unavailable. Saves `workspace/exploits/<generation_id>.py` + sidecar `<generation_id>.json` (`generation_id, parent_id, mutation_strategy, confidence, metadata, created_at`). Empty service → `ERROR`; `adaptive_exploits.enabled: false` → `BLOCKED`. |
| `mutate_exploit` | `@audit_tool` (no target touch — operates on workspace files by id) | `MUTATE_EXPLOIT_RESULT: mutated\nGENERATION_ID / PARENT_ID / SCRIPT_PATH / SIDECAR_PATH / CONFIDENCE / MUTATION_STRATEGY / ATTEMPT_NUMBER` + preview; or `max_mutations_reached` with `ATTEMPT / MAX_MUTATIONS` | Loads `<script_id>.py` + `<script_id>.json`, reconstructs `CraftedPayload`, walks parent sidecars to derive `attempt_number`, calls `mutator.mutate_on_failure(payload, failure_output, attempt_number)` (`None` → max-reached block). Missing script/sidecar → `ERROR`. Same `adaptive_exploits.enabled` gate. |

Lifecycle: `craft_exploit` (generation 1, `parent_id=None`) → run → `mutate_exploit` with failure output → child generation with `parent_id` linkage, up to `adaptive_exploits.max_mutations`.

## Synthesis (`modules/synthesis.py`)

```python
def register_synthesis_tools(mcp: Any, *, ctx: ToolContext) -> None
def cve_to_exploit_synth(target_ip: str, cve_id: str, service_name: str = "", version: str = "") -> str
def _render_log4j_exploit(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str
# + 17 more _render_*_template with the same signature (see table)
def _render_generic_probe(target_ip: str, port: int, svc: str, ver: str, cve: str) -> str
```

Dispatch table (18 branches; `TEMPLATE_DISPATCHED: <name>` is echoed so the agent can see which branch fired):

| Branch | Trigger (CVE id or `service_name` hint) | Renderer |
|--------|------------------------------------------|----------|
| `log4j` | name contains log4j/log4shell, `CVE-2021-44228`, `CVE-2021-45046` | `_render_log4j_exploit` |
| `eternalblue` | name contains eternalblue, `CVE-2017-0143…0146` | `_render_eternalblue_template` |
| `smbghost` | name contains smbghost, `CVE-2020-0796` | `_render_smbghost_template` |
| `bluekeep` | name contains bluekeep, `CVE-2019-0708` | `_render_bluekeep_template` |
| `regresshion` | `CVE-2024-6387`, svc `openssh` | `_render_regresshion_template` |
| `xz_backdoor` | `CVE-2024-3094`, name contains xz | `_render_xz_backdoor_template` |
| `activemq` | `CVE-2023-46604`, svc `activemq` | `_render_activemq_rce_template` |
| `confluence` | `CVE-2023-22515`, svc `confluence` | `_render_confluence_template` |
| `ivanti` | `CVE-2024-21887`, `CVE-2023-46805`, svc `ivanti` | `_render_ivanti_template` |
| `panos` | `CVE-2024-3400`, svc `panos` | `_render_panos_template` |
| `citrix` | `CVE-2023-3519`, svc `citrix` | `_render_citrix_template` |
| `connectwise` | `CVE-2024-0204`, svc `connectwise` | `_render_connectwise_template` |
| `jenkins` | `CVE-2024-23897`, svc `jenkins` | `_render_jenkins_template` |
| `joomla` | `CVE-2023-23752`, svc `joomla` | `_render_joomla_template` |
| `text4shell` | `CVE-2022-42889`, svc `commons_text` | `_render_text4shell_template` |
| `php_cgi` | `CVE-2024-4577`, svc `php_cgi` | `_render_php_cgi_template` |
| `http2_rapid_reset` | `CVE-2023-44487` | `_render_http2_rapid_reset_template` |
| `generic` | fallback | `_render_generic_probe` |

`cve_to_exploit_synth` pipeline: validate target (`validate_target_or_ip`) + CVE format (`CVE-\d{4}-\d{4,}`) + reject newline/quote/backslash in `service_name`/`version` (they are interpolated into generated-source comments) → `nvd.search_sync(cve)` + `format_cve_results` (capped at 2000 chars) → verified PoC lookup via `search.cve_to_poc(cve, nvd_refs)` with `search_web_exploit` fallback (capped at 1500 chars) → port hint from `service_name` (http 80, https 443, smb 445, rdp 3389, ssh 22, activemq 61616, confluence 8090, jenkins 8080, …) → renderer → optional inline syntax gate (`poc_verification.enabled` → `syntax_check(exploit_body)` → `SYNTAX_OK: true/false` + fix-and-`verify_poc` instructions) → `INSTRUCTIONS: Use write_python_file ... then run_python_file`.

All templates are **detection-only probes** (banner/version checks, safe payloads, non-routable default callbacks) meant for the LLM to refine — not weaponized exploits.

Implementation note: `CVEToExploit` (`tools.attack_modules.modules.synthesis`) and `_identify_hash_modes` are imported at the top of `synthesis.py` as the single-source reuse seam, but the tool body builds its output from the local `_render_*` templates plus `nvd`/`search` evidence rather than calling the module class directly.

## Hash (`modules/hash.py`)

```python
def _identify_hash_modes(h: str) -> list[tuple[str, str, str]]
def register_hash_tools(mcp: Any, *, ctx: ToolContext) -> None
def hash_crack_identify(hash_value: str) -> str
```

`_identify_hash_modes` returns `[(name, hashcat_mode, sample_cmd), ...]`. Order matters: a 32-hex string reports **both** NTLM (mode 1000) and MD5 (mode 0) since they are format-indistinguishable (context decides — NTLM from SMB, MD5 from a web app). LM (16 hex, mode 3000) only fires when nothing else matched, so fragments of longer hashes do not false-positive.

| Pattern | Name | Mode |
|---------|------|------|
| 32 hex | NTLM + MD5 (also possible) | 1000 / 0 |
| `user::domain:challenge:…` (≥5 `:` parts) | NetNTLMv2 | 5600 |
| `$krb5tgs$18$…` / `$krb5tgs$…` | Kerberos 5 TGS-REP etype 18 / TGS-REP | 19900 / 13100 |
| `$krb5asrep$18$…` / `$krb5asrep$…` | Kerberos 5 AS-REP etype 18 / AS-REP | 19900 / 18200 |
| 40 / 64 / 128 hex | SHA1 / SHA2-256 / SHA2-512 | 100 / 1400 / 1700 |
| `$2a$/$2b$/$2y$/$2$/$2x$` | bcrypt | 3200 |
| `$6$…$…` / `$1$…$…` | sha512crypt / md5crypt + Cisco type 5 | 1800 / 500 |
| `$9$` / `$4$` | Cisco type 9 (scrypt) / type 4 (PBKDF2-SHA256) | 22321 / 2400 |
| `0x0100…` (≥54 chars) / `0x0200…` (≥70) | MSSQL 2005 / 2012-2014 | 132 / 1731 |
| `$argon2…` | Argon2 (john only) | N/A (`john --format=argon2`) |
| `$scrypt$…` / `SCRYPT:…` | scrypt | 8900 |
| `pbkdf2_sha256$/sha1$` | Django PBKDF2 | 12100 |
| `$pdf$…` / `$office$…` | PDF / MS Office | 10400 / 9400 |
| 64-hex:`SSID` | WPA-PBKDF2 (possible) | 22000 |
| 16 hex (nothing else matched) | LM | 3000 |

`hash_crack_identify` (`@audit_tool`, local-only) prints each `(Type, mode, Command)` plus a rule-based-attack hint (`-r best64.rule` / OneRuleToRuleThemAll); unknown formats suggest `hashid`/`hash-identifier` with an 80-char preview.

## Web probes (`modules/web.py`)

```python
_MIN_PORT = 1; _MAX_PORT = 65535
_MIN_CONCURRENT = 2; _MAX_CONCURRENT = 100
_MIN_TOOL_TIMEOUT = 5; _MAX_TOOL_TIMEOUT = 300; _DEFAULT_TOOL_TIMEOUT = 90
_MAX_OUTPUT_CHARS = 20000; _MAX_ENDPOINT_CHARS = 2048
def register_web_tools(mcp: Any, *, ctx: ToolContext) -> None
def jwt_tamper(target_ip: str, jwt_token: str = "", timeout: int = 90) -> str
def ssti_probe(target_ip: str, port: int = 80, timeout: int = 90) -> str
def graphql_introspect(target_ip: str, port: int = 80, timeout: int = 90) -> str
def race_request(target_ip: str, port: int = 80, endpoint: str = "/api/redeem", concurrent: int = 20, timeout: int = 90) -> str
def timing_oracle(target_ip: str, port: int = 80, timeout: int = 90) -> str
def request_smuggling_probe(target_ip: str, port: int = 80, timeout: int = 90) -> str
def password_spray(target_ip: str, port: int = 80, password: str = "Password1", timeout: int = 90) -> str
```

Shared pre-gates (`web.py:43-167`): `_check_target` (non-empty, no CR/LF, `validate_target_or_ip`), `_check_port` (1-65535, numeric strings accepted), `_check_concurrent` (2-100), `_check_endpoint` (absolute path, no CR/LF or whitespace, ≤2048 chars), `_clamp_timeout` (5-300 s, default 90), `_http_host` (brackets IPv6), `_open_connection` (`socket.create_connection`, always used as a context manager), `_sock_budget` (per-connection budget honoring the tool deadline), `_finish` (caps display at 20000 chars with a `[truncated]` marker).

| Tool | Gate | What it does |
|------|------|--------------|
| `jwt_tamper` | `@require_allowlist()` + syntax/CR-LF pre-gates | Empty `jwt_token` → probes 15 discovery paths (`/api/auth/login`, `/oauth/token`, Keycloak, `wp-json/jwt-auth`, `openid-configuration`, …) on port 80 for a `header.payload.signature` regex hit. Then: `alg:none` token material + curl tester; weak-HMAC brute-force over a 34-secret list when `alg` starts with `HS`; key-confusion note when `alg` starts with `RS`. Returns `JWT_TAMPER_RESULTS`. Discovery socket reads only. |
| `ssti_probe` | `@require_allowlist()` + target/port pre-gates | 10 math payloads (`{{7*7}}`→49 Jinja2/Twig … `{{this.constructor…}}`→7 Handlebars) × 18 endpoints × 21 params via raw-socket GETs; stops at the tool deadline or first `expected in resp` hit. Returns `SSTI_PROBE_RESULTS` + engine or `No SSTI detected`. Read-only GETs. |
| `graphql_introspect` | `@require_allowlist()` + target/port pre-gates | POSTs the `__schema` introspection query to 14 endpoints (`/graphql`, `/gql`, `/api/v1/graphql`, `/__graphql`, …); on a hit prints up to 20 type names, then a 5-query batching test (`__typename` × 5 → batching verdict). Returns `GRAPHQL_INTROSPECT_RESULTS`. |
| `race_request` | `@require_allowlist()` + target/port/endpoint/concurrent pre-gates | Fires `concurrent` POSTs (`{"code":"TEST100","user":"attacker"}`) via `ThreadPoolExecutor(max 50)`; counts 200/201 vs other; mixed status codes or >1 success → possible TOCTOU. **State-changing POSTs by design.** Returns `RACE_REQUEST_RESULTS`. |
| `timing_oracle` | `@require_allowlist()` + target/port pre-gates | 8 samples each (0.15 s pacing): valid vs invalid user on `/api/login`, existing vs non-existing email on `/api/reset-password`; >50 ms mean diff → oracle verdict. Early deadline expiry → `Insufficient samples.` Returns `TIMING_ORACLE_RESULTS`. |
| `request_smuggling_probe` | `@require_allowlist()` + target/port pre-gates | Baseline `Content-Length: 0` POST, then CL.TE / TE.CL / TE.TE (obfuscated TE) malformed probes; flags baseline deltas >200 B or a leaked `GPOST`/`Unrecognized method`. **Sends intentionally malformed requests (detection only).** Returns `REQUEST_SMUGGLING_RESULTS`. |
| `password_spray` | `@require_allowlist()` + target/port pre-gates | Sprays one `password` (never echoed — output shows `[redacted]`) across 47 usernames (`POST /api/login`, ~1.5 s pacing to avoid lockout); 200/302 → per-user SUCCESS. Stops at the deadline with a `Stopped at tool deadline after N/47` note. Returns `PASSWORD_SPRAY_RESULTS` (usernames only, no password material). |

Implementation note: `web.py` imports `PasswordSpray`, `JWTTamper`, `GraphQLIntrospect`, `RaceRequest`, `RequestSmuggling`, `SSTIProbe`, `TimingOracle` from `tools.attack_modules.modules.*` as the single-source seam, but the registered probe bodies are inline raw-socket implementations in `web.py` itself.

## Config keys

| Key | Default | Effect |
|-----|---------|--------|
| `adaptive_exploits.enabled` | `true` (`config.yaml:381`) | `false` blocks `craft_exploit`/`mutate_exploit` with `BLOCKED: adaptive_exploits is disabled` |
| `adaptive_exploits.max_mutations` | `5` (`config.yaml:383`) | Lineage cap; `mutate_on_failure` returns `None` past it → `max_mutations_reached` block |
| `swarm.enabled` | `true` (`config.yaml:175`) | `false` blocks `start_autonomous_campaign` with `BLOCKED: swarm is disabled` |
| `autonomous.*` | merged first into campaign `mission_config` | Opt-in Phase 2 flags (`persistence_phase`, `checkpoint_every`, `adaptive_replan`, `max_pivot_depth`) reach the orchestrator |
| `opsec.*` | merged into campaign `mission_config` | Builds the `OpsecManager`; absent → disabled profile → pacing no-op |
| `exploit.msf.auto_local_exploit_suggester` | merged as `msf_auto_les` | Lets the campaign privesc phase dispatch the advisory follow-up |
| `orchestrator.semantic_memory` + `ollama` + `memory.embedding_model` | `false` / `nomic-embed-text` | Builds the orchestrator's `SemanticMemoryManager` when opted in |
| `agent.*` / `killchain.*` / `snapshots.*` / `replay_simulator.*` | merged into campaign `mission_config` | Retry caps, kill-chain branch, snapshot-before-destructive, counterfactual toggle reach the campaign |
| `exploit.max_rounds` | read as campaign `max_cycles` | Bounds the background campaign loop (`run_campaign_step` forces `max_cycles=1`) |
| `poc_verification.enabled` | `true` (`config.yaml:350`) | Runs the inline `syntax_check` gate inside `cve_to_exploit_synth`; opt-in — failures never break the synth path |
| `exploit.require_explicit_allowlist` / `exploit.allowed_targets` | `true` / `[127.0.0.1]` | Target-IP lock for every `@require_allowlist()` tool in this family |
| model routing (`models.*`, provider blocks) | via `_get_model_client(config)` | Planning/adaptive LLM enrichment; `None` client degrades gracefully (plan saved without AI steps) |

## Examples

```python
# 1. Plan, inspect, adapt.
create_attack_plan("192.168.1.100", "linux", "CVE-2024-6387,CVE-2021-44228")
get_current_plan("192.168.1.100")
replan("192.168.1.100", "Log4j probe returned no response — service may be patched")

# 2. Autonomous campaign with monitoring.
start_autonomous_campaign("192.168.1.100", "full_compromise", "aggressive")
get_campaign_status("campaign-20260504_120000-abc12345")
run_campaign_step("campaign-20260504_120000-abc12345")  # single-step/debug pacing
stop_campaign("campaign-20260504_120000-abc12345")

# 3. Adaptive exploit generation loop.
craft_exploit("192.168.1.100", "ssh", "OpenSSH 8.9p1", "linux", "RegreSSHion")
mutate_exploit("gen-1712345678-abc12345", "ConnectionResetError: target closed connection")

# 4. CVE synthesis → save → run.
cve_to_exploit_synth("192.168.1.100", "CVE-2021-44228", "http", "")
# write_python_file the TEMPLATE_DISPATCHED script, then run_python_file.

# 5. Identify a hash, then probe the web surface.
hash_crack_identify("5d41402abc4b2a76b9719d911017c592")
jwt_tamper("192.168.1.100")
ssti_probe("192.168.1.100", 80)
graphql_introspect("192.168.1.100", 80)
race_request("192.168.1.100", 80, "/api/redeem", 20)
timing_oracle("192.168.1.100", 80)
request_smuggling_probe("192.168.1.100", 80)
password_spray("192.168.1.100", 80, "Password1")
```

## Related documentation

- [Attack-modules tool family](./attack-modules.md) — `list_attack_modules` / `run_attack_module` aggregate that campaigns step into
- [Terminal tool family](./terminal.md) — target-IP lock primitives reused by campaign steps
- [Sessions tool family](./sessions.md) — background execution plane campaigns run alongside
- [Cracking tool family](./cracking.md) — `run_hash_crack` execution side of `hash_crack_identify`
- [Research tool family](./research.md) — `cve_to_poc` verified-PoC resolver used by synthesis
- [MCP security](../security.md) — allowlist + audit decorator contract
- [MCP registration](../registration.md) — `collect_tools()` auto-discovery

## Source map

- `tools/mcp_tools/modules/planning.py` — `register_planning_tools`, `create_attack_plan`, `get_current_plan`, `replan`
- `tools/mcp_tools/modules/campaign.py` — `register_campaign_tools`, `start_autonomous_campaign`, `get_campaign_status`, `run_campaign_step`, `stop_campaign`, `_running_campaign_tasks`, `_campaign_orchestrators`
- `tools/mcp_tools/modules/adaptive.py` — `register_adaptive_tools`, `craft_exploit`, `mutate_exploit`
- `tools/mcp_tools/modules/synthesis.py` — `register_synthesis_tools`, `cve_to_exploit_synth`, 18 `_render_*` CVE-family templates
- `tools/mcp_tools/modules/hash.py` — `register_hash_tools`, `hash_crack_identify`, `_identify_hash_modes`
- `tools/mcp_tools/modules/web.py` — `register_web_tools`, `jwt_tamper`, `ssti_probe`, `graphql_introspect`, `race_request`, `timing_oracle`, `request_smuggling_probe`, `password_spray`, shared `_check_*/_clamp_timeout/_finish` helpers
- `tools/mcp_tools/attack_modules.py` — `register_attack_module_tools` aggregate, `_identify_hash_modes` re-export
- `tools/mcp_tools/registry.py` — `ToolContext`, `_discover_tool_registrars`, `collect_tools`, decorator validation
- `tools/attack_planner.py` — plan model, planning/replanning prompts and parsers
- `tools/autonomous_orchestrator.py` — campaign runner, `AggressionLevel`, `TaskStatus`
- `tools/exploit_mutator.py` + `tools/payload_crafter.py` — adaptive generation and mutation
- `tools/attack_modules/` — pre-packaged module registry stepped by campaigns
- `config.yaml` — `adaptive_exploits`, `swarm`, `autonomous`, `opsec`, `poc_verification`, `exploit`
