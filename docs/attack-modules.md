# Attack Modules

`tools/attack_modules/` is the plugin framework that gives the AI "known
recipes" for common vulnerabilities, so it doesn't have to write every exploit
from scratch (`tools/attack_modules/__init__.py:1-6`). A module is a
pre-packaged, context-scored attack recipe: it declares which services, ports,
and CVEs it targets, scores its own applicability against a target, and either
generates an exploit script, emits a suggested command / MSF recipe, or returns
a workflow that routes the agent through existing MCP tools.

## What an attack module is

An `AttackModule` subclass (`tools/attack_modules/base.py:144`) is the unit of
attack knowledge. It has two contracts:

- **Metadata** (class attributes): `name`, `description`, `target_services`,
  `target_ports`, `required_cves`, `target_versions` — used for scoring and
  display (`base.py:163-168`).
- **Behavior**: `run(ctx) -> dict` (abstract, `base.py:208-211`) plus optional
  `generate_python_script(ctx) -> str` (`base.py:213-215`) and
  `generate_dynamic_script(ctx, mutator)` (`base.py:217-249`, which routes
  script generation through the PayloadCrafter when a mutator is supplied).

`ModuleContext` (`base.py:11-17`) carries `target_ip`, `target_os`, `services`
(list of `{service, port, version}` dicts), `cves`, and the workspace path. The
capability upgrade added defaulted fields the orchestrator threads from
`AttackState`: `sessions`, `findings`, `hypotheses`, `evidence_refs`,
`access_achieved`, `privilege_level`, and `phase` — constructors that don't
supply them keep the ABC defaults.
`ModuleResult` (`base.py:26-156`) is the typed outcome shape the autonomous
orchestrator and MCP renderer read; `ModuleResult.to_result()` adapts a legacy
dict return so old modules keep working unchanged. It gained defaulted
`failure_class`, `retryable`, `confidence`, `produced_artifacts`, `follow_ups`,
and `unlocked_capabilities` fields (emitted by `to_dict` only when set, so the
legacy contract is byte-identical).

### Capability metadata (capability upgrade §1/§19)

Every `AttackModule` subclass declares five additional class attributes so the
planner can do dynamic composition (find what *produces* a missing artifact)
and prerequisite gating (find what a module *requires*):

| Attr | Default | Meaning |
|---|---|---|
| `requires` | `[]` | Artifacts the module needs before it can run (`credentials`, `foothold`, `admin_priv`, `user_list`, `hash_artifact`, `shell`, …) |
| `produces` | `[]` | Artifacts the module yields on success (`foothold`, `shell`, `credentials`, `hash_artifact`, `user_list`, `persistence`, `webshell`, `high_priv`, `admin_priv`, …) |
| `read_only` | `False` | `True` = enumeration/check only, never writes to the target |
| `cost` | `"medium"` | `low` / `medium` / `high` — operator-attention heuristic |
| `phase_hint` | `""` | Planning bucket: `recon` / `enumerate` / `exploit` / `escalate` / `loot` / `persist` / `validate` / `pivot` |

`find_producers(artifact_kind)` (`registry.py`) returns the modules whose
`produces` claims the kind — the dynamic-composition primitive for
prerequisite-recovery scheduling. `missing_prerequisites(mod, ctx)` reports
declared `requires` not satisfiable from a `ModuleContext`.
`capability_record()` (`base.py`) is the superset metadata dict for discovery
tools; `to_json()` stays byte-identical and does **not** leak the new attrs.
`applicability_explain(ctx)` returns an `ApplicabilityReport(score, reasons,
penalties)` while delegating the score to `applicability()`, so subclass
overrides (ICS destructive zero-gate, `ics_iot` write flags) stay authoritative.

### Applicability scoring

`AttackModule.applicability(ctx) -> int` (`base.py:170-206`) returns 0-100:

| Signal | Points |
| --- | --- |
| Declared `target_services` present in `ctx.services` | +30 each |
| Declared `target_ports` present in `ctx.services` | +20 each |
| Declared `required_cves` present in `ctx.cves` | +40 each |
| Any service version matches a `target_versions` pattern | +25 flat (once) |
| Cap | `min(score, 100)` |

A score of 0 means the module is not applicable and is excluded from ranking
(`registry.py:236-239`).

## Registry mechanism

The registry lives in `tools/attack_modules/registry.py`. Registration is
**filesystem auto-discovery**: the single source is the filesystem under
`tools/attack_modules/modules/`, scanned with `pkgutil.iter_modules`
(`registry.py:21-67`). There is no manual `_MODULE_CLASSES` literal to edit.

### How modules register

1. Define an `AttackModule` subclass in the relevant category file under
   `tools/attack_modules/modules/` (e.g. `modules/web/sqli.py`,
   `modules/network_smb.py`).
2. `_discover_attack_modules()` imports every module file and walks
   subpackages too: category families split into packages such as
   `modules/web/` and `modules/ics/` still register their classes, because a
   plain `iter_modules` loop skips packages and the walker explicitly queues
   each subpackage `__path__` (`registry.py:27-42`). Discovery runs on import
   and is idempotent (`registry.py:71`).
3. Dedupe is by class identity and by `module.name`: a family mid-split that
   defines the same modules twice (e.g. `modules/ics_iot.py` alongside
   `modules/ics/`) registers only once, since `module.name` is the registry
   key for `get_module` / `run_attack_module` (`registry.py:60-67`).
4. `tools/attack_modules/__init__.py` re-exports the registry helpers and all
   module classes for tests that import them by name.

The `@register_attack_module` decorator remains as an explicit opt-in for
out-of-tree or test modules: it appends the decorated class when absent and
returns it unchanged (`registry.py:96-106`).

Out-of-tree modules register through the plugin system instead:
`registry._plugin_extra_module_classes()` lazily consults
`tools.plugins.PLUGIN_REGISTRY.extra_module_classes` (`registry.py:74-85`),
and `list_modules()` / `get_module()` append those instances
(`registry.py:109-117`, `registry.py:292-302`). See
[plugin-development.md](plugin-development.md) §4a.

### Registry metadata fields

The metadata schema is the class attributes on `AttackModule`
(`base.py:335-340`), surfaced by `to_json()` (`base.py:646-653`):

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | `str` | `""` | Stable module identifier; referenced by orchestrators and tests. Must stay stable (`docs/extension-guide.md:99`). |
| `description` | `str` | `""` | Human/AI-facing one-liner of what the module does. |
| `target_services` | `list[str]` | `[]` | Lowercased service names matched against `ctx.services` (+30 each). |
| `target_ports` | `list[int]` | `[]` | Ports matched against `ctx.services` (+20 each). |
| `required_cves` | `list[str]` | `[]` | CVE IDs that must be present in `ctx.cves` (+40 each). |
| `target_versions` | `dict[str, list[str]]` | `{}` | Service name → known-vulnerable version substrings; any match adds a flat +25 once (`base.py:325-332`). |

There is **no explicit risk field** in the metadata. Risk is implicit in
module behavior: read-only / detection / planning modules (detection, ICS/IoT,
supply-chain families) never set `shell_type`/`privilege_level` and are
low-risk; exploit and persistence modules are high-risk. The inventory table
below marks this derived risk.

### Registry API

| Function | Purpose |
| --- | --- |
| `list_modules()` | Instantiated copies of all registered modules (built-in + plugin) (`registry.py:109-117`). |
| `find_modules(ctx, experience_store=None)` | Modules with `applicability > 0`, sorted by composite score (`registry.py:120-159`). |
| `explain_modules(ctx, experience_store=None)` | Per-module score breakdowns parallel to `find_modules` (`registry.py:214-246`). |
| `find_producers(artifact_kind)` | Modules whose `produces` claims the kind (`registry.py:273-282`). |
| `missing_prerequisites(mod, ctx)` | Declared `requires` not satisfiable from `ctx` (`registry.py:285-289`). |
| `get_module(name)` | Case-insensitive lookup by `name`, returns an instance or `None` (`registry.py:292-302`). |
| `_module_primary_service(mod, ctx)` | Single source of truth for which `service:version` a module's outcome is recorded against (`registry.py:162-195`). |
| `_module_target_signature(mod, ctx)` | Builds the `service:version:os` ExperienceStore key (`registry.py:198-211`). |
| `_module_experience_confidence(mod, ctx, store)` | Mean Bayesian confidence for the module's target signature, neutral 0.5 when absent (`registry.py:249-270`). |

### Experience-aware ranking

`find_modules` blends static applicability with historical Bayesian confidence
when an `experience_store` is provided (`registry.py:120-159`): the composite
score is `static + (confidence - 0.5) * 20`, so experience swings the ordering
by at most ±10 and can never include a module with 0 applicability. The
write side (`generate_dynamic_script`, `base.py:612-644`) and the read side
(`_module_target_signature`) share `_module_primary_service` so they can never
disagree on which `service:version:os` signature an outcome was recorded
against (`registry.py:162-211`).

## Module inventory

All modules live in `tools/attack_modules/modules/`. Two families are split
into subpackages: web probes live in `modules/web/` (`sqli.py`, `upload.py`,
`xss.py`, re-exported by `modules/web/__init__.py`) and ICS modules live in
`modules/ics/` (`bacnet.py`, `modbus.py`, `s7.py`, re-exported by
`modules/ics/__init__.py`). The legacy `modules/ics_iot.py` still defines the
same ICS classes; the registry dedupes by `module.name`, so each registers
once (see Registry mechanism above).

Risk is derived from behavior, not a metadata field: **low** = read-only /
detection / planning (never sets `shell_type`/`privilege_level`), **high** =
active exploitation / credential attack / persistence.

| Module | Family | Purpose | Risk |
| --- | --- | --- | --- |
| `Log4jRCE` | web/upload | Log4j JNDI injection RCE (CVE-2021-44228), generates a payload sender script (`modules/web/upload.py`) | high |
| `BasicAuthBuster` | web/upload | Brute-force HTTP Basic Auth with a small default wordlist (`modules/web/upload.py`) | high |
| `APIFuzzer` | web/upload | Fuzz common REST endpoints for disclosure/injection (`modules/web/upload.py`) | high |
| `WebShellUpload` | web/upload | Upload PHP/JSP/ASPX web shells via file-upload flaws (`modules/web/upload.py`) | high |
| `RaceRequest` | web/upload | Concurrent requests for TOCTOU race conditions (`modules/web/upload.py`) | high |
| `SQLInjection` | web/sqli | sqlmap integration recipe for SQLi testing (`modules/web/sqli.py`) | high |
| `SSTIProbe` | web/sqli | Server-side template injection detection across engines (`modules/web/sqli.py`) | high |
| `XXEProbe` | web/sqli | In-band + OOB XML external entity injection (`modules/web/sqli.py`) | high |
| `LFITraversal` | web/sqli | LFI / path traversal detection incl. `php://filter` (`modules/web/sqli.py`) | high |
| `SSRFProbe` | web/sqli | SSRF detection via internal-URL payloads (target-fetched only) (`modules/web/sqli.py`) | high |
| `XSSScanner` | web/xss | Reflected/stored XSS payload injection (`modules/web/xss.py`) | high |
| `GraphQLIntrospect` | web/xss | GraphQL schema extraction, depth/batching/alias attacks (`modules/web/xss.py`) | high |
| `TimingOracle` | web/xss | Timing side-channel detection for user enumeration / blind extraction (`modules/web/xss.py`) | high |
| `RequestSmuggling` | web/xss | CL.TE / TE.CL / TE.TE HTTP request smuggling (`modules/web/xss.py`) | high |
| `JWTTamper` | crypto_jwt | JWT alg confusion, none-alg, HMAC-to-RSA, weak-secret brute force (`crypto_jwt.py:12-148`) | high |
| `DeserializeAttack` | deserialize | Java/PHP/.NET deserialization payload generation/injection (`deserialize.py:10-152`) | high |
| `SMBGhost` | network_smb | SMBv3 compression RCE (CVE-2020-0796), MSF/check recipe (`network_smb.py:9-22`) | high |
| `EternalBlue` | network_smb | SMBv1 MS17-010 RCE (CVE-2017-0144), MSF recipe (`network_smb.py:24-37`) | high |
| `SMBRelay` | network_smb | SMB relay via impacket ntlmrelayx (`network_smb.py:39-53`) | high |
| `SMBNullSession` | network_smb | Enumerate SMB shares/users via null session (`network_smb.py:55-86`) | high |
| `PassTheHash` | network_smb | Execute via NTLM hash with impacket wmiexec/psexec/smbexec (`network_smb.py:93-112`) | high |
| `DumpHashes` | network_smb | SAM/LSASS/NTDS.dit hash extraction recipes (`network_smb.py:114-134`) | high |
| `SSHBruteForce` | ssh | Hydra/paramiko SSH brute force with default creds (`ssh.py:8-50`) | high |
| `RegreSSHion` | ssh | OpenSSH regreSSHion RCE (CVE-2024-6387) (`ssh.py:52-69`) | high |
| `OpenSSHCVECheck` | ssh | Map OpenSSH version to known CVEs (`ssh.py:71-128`) | low |
| `RDPBlueKeep` | services | RDP use-after-free RCE (CVE-2019-0708), MSF recipe (`services.py:8-21`) | high |
| `FTPAnonymous` | services | Anonymous FTP login + file enumeration (`services.py:28-41`) | high |
| `RedisExploit` | services | Unauthenticated Redis RCE / data extraction (`services.py:43-61`) | high |
| `ElasticsearchExploit` | services | Data extraction from exposed Elasticsearch (`services.py:63-76`) | high |
| `LDAPAnonymous` | services | LDAP anonymous-bind enumeration (`services.py:78-91`) | high |
| `RDPExploit` | services | RDP credential testing / known vulns (`services.py:93-106`) | high |
| `CredentialSpray` | auth_creds | Password spraying across multiple services (`auth_creds.py:9-22`) | high |
| `PasswordSpray` | auth_creds | One-password-many-users low-and-slow spray (`auth_creds.py:29-118`) | high |
| `HashCrack` | auth_creds | hashcat/john wrapper with hash-mode table (`auth_creds.py:120-145`) | high |
| `ASREPRoast` | auth_creds | AS-REP roasting recipe (impacket-GetNPUsers) (`auth_creds.py:156-183`) | high |
| `Kerberoasting` | auth_creds | Kerberoasting recipe (impacket-GetUserSPNs) (`auth_creds.py:186-213`) | high |
| `DCSyncAttack` | auth_creds | DCSync via DRSUAPI (impacket-secretsdump) (`auth_creds.py:216-243`) | high |
| `ADLDAPEnum` | auth_creds | Pure-stdlib LDAP enumeration of AD users/groups/SPNs (`auth_creds.py:246-435`) | low |
| `LinuxPrivescCheck` | privesc | Enumerate Linux privesc vectors (SUID/sudo/kernel/cron) (`privesc.py:9-44`) | high |
| `WindowsPrivescCheck` | privesc | Enumerate Windows privesc vectors (`privesc.py:46-59`) | high |
| `SUIDEnumeration` | privesc | SUID/SGID binary enumeration vs GTFOBins (`privesc.py:61-74`) | high |
| `KernelExploitCheck` | privesc | Kernel version → known LPE exploits (`privesc.py:76-92`) | low |
| `ContainerBreakout` | privesc | Docker/container escape detection (`privesc.py:94-135`) | high |
| `CloudPrivesc` | privesc | Cloud/k8s privesc from inside the target (IMDS, SA token, Docker API) (`privesc.py:138-227`) | high |
| `K8sPrivesc` | privesc | Kubelet/API-server probe for k8s privesc (`privesc.py:230-327`) | high |
| `LinuxPersistence` | persistence | Cron/systemd/authorized_keys persistence (`persistence.py:10-114`) | high |
| `WindowsPersistence` | persistence | Scheduled task / registry Run key / service persistence (`persistence.py:117-186`) | high |
| `WebShellPersistence` | persistence | Web-shell drop into common web roots (`persistence.py:189-273`) | high |
| `CVEToExploit` | synthesis | LLM synthesis of an exploit from CVE intel (`synthesis.py:8-35`) | high |
| `DiffPatchAnalysis` | synthesis | Reverse-engineer a patch diff into an exploit (`synthesis.py:37-61`) | high |
| `FuzzToExploit` | synthesis | Turn crash/fuzz output into an exploit (`synthesis.py:63-87`) | high |
| `WeaponizedExploit` | synthesis | CVE-to-exploit that also gains a reverse shell to an operator callback host; prints a canonical `COMPROMISE:` marker (`synthesis.py:90-133`) | high |
| `ModbusEnum` | ics/modbus | Read-only Modbus/TCP unit enumeration (FC 43/04, no writes) (`modules/ics/modbus.py`; also defined in legacy `modules/ics_iot.py`) | low |
| `ModbusWriteCoil` | ics/modbus | Destructive single-coil write (FC 05); dual-gated by allowlist + `ics.allow_write`/`ics.destructive_ics` (`modules/ics/modbus.py`; also in `modules/ics_iot.py`) | high |
| `ModbusWriteRegister` | ics/modbus | Destructive holding-register write (FC 06); same dual gate (`modules/ics/modbus.py`; also in `modules/ics_iot.py`) | high |
| `S7Enum` | ics/s7 | Read-only Siemens S7 identity via COTP/SZL reads (`modules/ics/s7.py`; also in `modules/ics_iot.py`) | low |
| `S7PlcStop` | ics/s7 | Destructive S7 PLC stop (halts the controlled process); same dual gate (`modules/ics/s7.py`; also in `modules/ics_iot.py`) | high |
| `S7PlcStart` | ics/s7 | Write-side S7 PLC start/cold start control command; same dual gate (`modules/ics/s7.py`; also in `modules/ics_iot.py`) | high |
| `BACnetEnum` | ics/bacnet | Read-only BACnet Who-Is/ReadProperty enumeration (`modules/ics/bacnet.py`; also in `modules/ics_iot.py`) | low |
| `DNP3Enum` | ics/bacnet | Read-only DNP3 outstation enumeration (FC 1, class 0) (`modules/ics/bacnet.py`; also in `modules/ics_iot.py`) | low |
| `HMIDefaultCred` | ics/bacnet | HMI web fingerprint + small default-cred check (`modules/ics/bacnet.py`; also in `modules/ics_iot.py`) | low |
| `IoTDefaultCred` | ics/bacnet | IoT web fingerprint + default-cred check (Mirai-class) (`modules/ics/bacnet.py`; also in `modules/ics_iot.py`) | low |
| `ExposedVCS` | supply_chain | Detect exposed `.git/.svn/.hg/.bzr`, leak `.git/config` (read-only) (`supply_chain.py:10-75`) | low |
| `CICDMisconfig` | supply_chain | Detect exposed CI/CD config + fingerprint CI servers (read-only) (`supply_chain.py:78-175`) | low |
| `DependencyConfusion` | supply_chain | Detection-only dependency-confusion risk report; never registers packages (`supply_chain.py:178-220`) | low |
| `ArtifactExposure` | supply_chain | Detect exposed `.env`/credentials/artifacts (read-only) (`supply_chain.py:223-291`) | low |
| `SupplyChainRecon` | supply_chain | Orchestrates VCS/manifest findings into a per-dependency CVE report (`supply_chain.py:294-338`) | low |
| `DetectionCoverageProbe` | detection | Plans canary actions to validate SIEM/IDS/FIM coverage; always selectable at score 15 (`detection.py:51-80`) | low |
| `LogSourceEnum` | detection | Lists candidate log/audit sources per OS (read-only) (`detection.py:83-137`) | low |
| `OPSECPostureReport` | detection | Reports OPSEC posture + audit-footprint summary (read-only) (`detection.py:140-200`) | low |
| `TokenImpersonation` | orchestrator_phases | Windows privesc via mimikatz token ops (`orchestrator_phases.py:33-74`) | high |
| `ServiceMisconfiguration` | orchestrator_phases | Detection-only Windows service misconfig enumeration (`orchestrator_phases.py:77-123`) | low |
| `LateralMovement` | orchestrator_phases | Phase-level lateral-movement driver via `lateral_exec`; `phase_only` (`orchestrator_phases.py:126-152`) | high |
| `ValidateFinding` | orchestrator_phases | Phase-level validation driver; re-confirms foothold (`orchestrator_phases.py:155-181`) | low |
| `LocalExploitSuggester` | orchestrator_phases | Advisory MSF `local_exploit_suggester` recipe; never fabricates a session id (`orchestrator_phases.py:184-221`) | low |
| `ADCSEnum` | ad | AD CS template enumeration for ESC1-8 paths (certipy) (`ad.py:19-45`) | high |
| `BloodHoundCollect` | ad | BloodHound graph data collection (bloodhound-python) (`ad.py:48-74`) | high |
| `ResponderRelay` | ad | SMB/NTLM relay via ntlmrelayx, targets restricted to the allowlist (`ad.py:77-103`) | high |
| `GoldenTicket` | ad | Mint a Kerberos golden ticket from krbtgt hash (impacket-ticketer) (`ad.py:106-133`) | high |
| `SMBSigningCheck` | ad | Detection-only SMB signing posture check (relay feasibility) (`ad.py:136-159`) | low |

## Producer graph and artifact vocabulary

### Producer graph (`graph.py`)

`tools/attack_modules/graph.py` is the producer/consumer graph over the closed
artifact vocabulary. Its module docstring states it is shared by the campaign
prerequisite scheduler and planner integration tests, and that all ranking is
deterministic: cost order (`low` < `medium` < `high`), read-only preferred on
ties, then name (`graph.py:1-13`). The campaign batch scheduler consults
`graph.rank_producers` to order prerequisite-recovery candidates
cheapest/read-only-first with ctx-satisfied prerequisites ahead
(`tools/campaign/batch.py:154-160`). `tests/test_artifact_graph.py` is the
contract test: closed vocabulary, every `requires` has a producer, no
producer/consumer cycle, and dead ends are terminal or documented.

| Function | Signature | Purpose |
| --- | --- | --- |
| `rank_producers` | `rank_producers(artifact_kind, ctx=None, *, exclude="", modules=None)` | Producers of `artifact_kind`, cheapest/read-only first. When `ctx` is given, producers whose own `requires` are unsatisfied sort after satisfiable ones but are still returned. `exclude` skips a module name (no self-recovery) (`graph.py:25-61`). |
| `chain_to` | `chain_to(target_kind, ctx, *, depth=2, modules=None)` | BFS chains `[producer..., consumer]` yielding `target_kind`. Each chain ends in a module producing the target whose prerequisites are satisfied by `ctx` or produced by an earlier link (recursively, up to `depth`). Cycle-guarded via visited names, sorted cheapest-first by summed cost rank, `[]` when unsatisfiable (`graph.py:87-143`). |
| `orphan_requires` | `orphan_requires(modules=None)` | Map module name to required kinds with no producer (`graph.py:146-157`). |
| `dead_end_produces` | `dead_end_produces(modules=None)` | Map module name to produced kinds with no consumer, excluding `TERMINAL_ARTIFACTS` (`graph.py:160-171`). |
| `find_cycle` | `find_cycle(modules=None)` | Return one requires-to-produces cycle through non-currency kinds, else `[]`. Currency artifacts (`credentials`, `hash_artifact`, `user_list`, `foothold`, `shell`, `session`) cycle by design and are skipped (`graph.py:180-214`). |

Two unsorted helpers sit alongside: `producers_for(kind, modules=None)` lists
all modules producing `kind` and `consumers_of(kind, modules=None)` lists all
modules requiring it (`graph.py:69-84`). `graph.missing_prerequisites(mod,
ctx)` mirrors the registry helper against the closed vocabulary
(`graph.py:64-66`).

```python
from tools.attack_modules.graph import chain_to, rank_producers

# Cheapest producer of admin_priv whose own prerequisites are satisfiable first.
producers = rank_producers("admin_priv", ctx, exclude="DCSyncAttack")
# Full prerequisite chains yielding the artifact, up to 2 links deep.
chains = chain_to("admin_priv", ctx, depth=2)
```

Implementation note: `orphan_requires` docstring says "(excluding terminals)"
but the code read filters only on the produced set with no terminal-kind
exclusion; `dead_end_produces` is the one that excludes `TERMINAL_ARTIFACTS`.

### Closed artifact vocabulary (`artifacts.py`)

`tools/attack_modules/artifacts.py` is the closed vocabulary for capability
composition: `requires`/`produces` strings must come from `ARTIFACT_VOCAB`.
Unknown kinds are absent (fail closed) and flagged by the contract test
(`artifacts.py:1-8`). `base._artifact_present` delegates to this module
(`base.py:75-80`).

| Kind | Meaning |
| --- | --- |
| `credentials` | Recovered passwords, tickets, or keys usable for authentication |
| `hash_artifact` | Captured hashes / tickets for offline cracking or relay |
| `user_list` | Enumerated usernames / accounts (spray/roast input) |
| `foothold` | Initial access to the target |
| `shell` | Command execution on the target |
| `webshell` | Web-shell access (terminal; chains consume the co-produced `foothold`) |
| `session` | Established session (Metasploit or equivalent) |
| `admin_priv` | Administrative / SYSTEM / root equivalence (plannable currency) |
| `high_priv` | Realized escalation outcome, end of chain |
| `persistence` | Surviving access mechanism (terminal finding) |
| `signing_posture` | SMB signing posture finding (relay feasibility input) |
| `git_config_leak` | Exposed VCS config leak finding |
| `vuln_confirmed` | Confirmed-vulnerability finding (terminal) |
| `lpe_candidates` | Local privilege-escalation candidate finding |
| `k8s_sa_token` | Kubernetes service-account token finding |
| `web_tech` | Web technology fingerprint finding |
| `auth_scheme` | Authentication-scheme fingerprint finding |

Aliases resolve onto the canonical kinds: `creds` and `password` mean
`credentials`, `hash` means `hash_artifact`, `root_priv` and `system_priv`
mean `admin_priv` (`artifacts.py:39-45`). Terminal artifacts with no consumer
expected are `persistence`, `vuln_confirmed`, `high_priv`, and `webshell`
(`artifacts.py:55-60`).

| Helper | Purpose |
| --- | --- |
| `normalize(kind)` | Lowercase plus alias-resolve; unknown kinds pass through unchanged so the contract test can flag them (`artifacts.py:63-67`). |
| `is_known(kind)` | True when the kind is in the closed vocabulary after aliasing (`artifacts.py:70-72`). |
| `unknown_kinds(kinds)` | Entries outside the closed vocabulary (`artifacts.py:75-77`). |
| `is_satisfied(kind, ctx)` | Best-effort prerequisite check against `ctx` credentials, sessions, privilege level, and structured findings. Unknown kinds return `False` (`artifacts.py:80-128`). |

## Orchestrator phases

The autonomous orchestrator (`tools/autonomous_orchestrator.py`) drives modules
through a fixed campaign. Phase order and module selection:

| Phase | How modules are picked | Reference |
| --- | --- | --- |
| Reconnaissance | Recon pipeline maps services/CVEs into a `ModuleContext` and calls `find_modules(ctx)`; the top 10 become `recommended_attack_modules` in the attack surface | `tools/recon_pipeline.py:2312-2324` |
| Exploitation | `find_modules(ctx, experience_store=...)` ranks applicable modules; top 15 become `AttackTask`s (deduped against service-specific tasks); `skip_failed` drops previously-failed modules on adaptive replan; aggression escalates and retries on no access | `autonomous_orchestrator.py:1463-1543` |
| Privilege escalation | OS-family hardcoded lists: Linux → `LinuxPrivescCheck`/`SUIDEnumeration`/`KernelExploitCheck`; Windows → `WindowsPrivescCheck`/`TokenImpersonation`/`ServiceMisconfiguration`; else generic trio; optional advisory `LocalExploitSuggester` task when access achieved | `autonomous_orchestrator.py:1545-1582` |
| Lateral movement | `LateralMovement` phase driver instantiated by name for a vetted pivot target; capped at `max_pivot_depth`, no recursion | `autonomous_orchestrator.py:1595-1626` |
| Validation | `ValidateFinding` phase driver re-confirms the foothold | `autonomous_orchestrator.py:1649-1661` |
| Persistence | `get_module(mod_name)` for `LinuxPersistence`/`WindowsPersistence`/`WebShellPersistence` | `autonomous_orchestrator.py:1728-1770` |

The phase modules in `orchestrator_phases.py` exist because the orchestrator
previously referenced names that were not registered — `get_module(name)`
returned `None` and every privesc/lateral/validation task FAILED
(`orchestrator_phases.py:1-25`). `LateralMovement` and `ValidateFinding` declare
`target_services=[]` so they are never service-matched; the orchestrator
instantiates them by name (`orchestrator_phases.py:126-131`, `155-160`).

## How the planner picks modules

`tools/attack_planner.py` is the LLM-driven planning layer, distinct from the
deterministic orchestrator. It defines the `AttackPhase` enum
(RECON → ENUMERATE → EXPLOIT → ESCALATE → LOOT → PIVOT → DONE,
`attack_planner.py:20-27`), `AttackPlan`/`AttackStep` dataclasses
(`attack_planner.py:30-155`), and prompt builders that ask the AI to emit JSON
steps (`build_planning_prompt`, `attack_planner.py:158-203`; adaptive
`build_replanning_prompt`, `attack_planner.py:206-238`). Steps reference MCP
tool names (including the `attack_module` family tools), not module classes
directly; `AttackPlanner` manages plan lifecycle and persists plans as JSON
under `<workspace>/plans/` (`attack_planner.py:304-363`). The MCP tool layer
(`tools/mcp_tools/attack_modules.py`) exposes `list_attack_modules`,
`run_attack_module`, `craft_exploit`, `mutate_exploit`, and the campaign
planner tools (`CLAUDE.md:214`).

## How the eval harness drives them

`tools/eval_harness.py` (`--eval`) runs a single attack-mode exploit session
against `--target` and derives `EvalMetrics` from the `run_exploit_agent`
final-result dict (`eval_harness.py:1-19`, `130-204`). It does not call
`find_modules` directly — modules are selected inside the exploit session by
the agent loop. The harness:

1. Loads validated config, builds the model router, and probes the MCP exploit
   server with `open_exploit_mcp_session(soft_fail=True)`
   (`eval_harness.py:369-467`).
2. Runs `run_exploit_session` in attack mode with
   `ExploitPermission.FULL_ACCESS` and the `initial_access` goal
   (`eval_harness.py:416-484`).
3. Computes metrics (compromises / cred dumps / partials / failures, success
   rate, verdict) from the outcome summary and audit records
   (`eval_harness.py:64-204`), then writes `eval_report.json` / `.md` / `.html`
   under `reports/eval/<run_id>/` (`eval_harness.py:328-355`).

The attack path is target-locked at the MCP tool layer (allowlist unions the
runtime `--target`); the harness adds no further gate (`eval_harness.py:15-18`).

## OPSEC / detection-coverage integration

`tools/detection_coverage.py` is the read-only helper backing the detection
family modules (`detection_coverage.py:1-18`):

- `detection_probe_plan(target_ip)` builds a 4-item canary plan (auth / file /
  exec / network) the operator deploys against their own target to validate
  SIEM/IDS/FIM coverage; nothing executes (`detection_coverage.py:86-124`).
  Consumed by `DetectionCoverageProbe.run` (`detection.py:66-80`).
- `footprint_summary(audit_records)` reduces `exploit_audit.jsonl` records into
  counts (total/noisy/commands/targets/tools/egress) without mutating the
  append-only audit trail (`detection_coverage.py:127-179`). Consumed by
  `OPSECPostureReport.run` (`detection.py:154-200`).
- `LogSourceEnum` lists candidate log sources per OS family
  (`detection.py:83-137`).

The detection modules are deliberately read-only: they never set
`shell_type`/`privilege_level` (so `access_achieved` is never flipped), never
clear logs or defeat EDR/SIEM, and are target-locked to `ctx.target_ip`
(`detection.py:1-21`). `DetectionCoverageProbe` and `OPSECPostureReport`
override `applicability` to fixed low scores (15 / 10) so they are always
selectable but never outrank real exploit modules (`detection.py:62-64`,
`150-152`). The OPSEC posture itself (pacing, UA rotation, DoH, quiet-command
rewriting) is enforced elsewhere — `tools/opsec.py` and the
`AttackModuleExecutor` — not by these modules (`CLAUDE.md:123`).

## Add a module

Minimal module (matching `docs/extension-guide.md:78-102`):

```python
# tools/attack_modules/modules/web/sqli.py
from tools.attack_modules.base import AttackModule, ModuleContext
from typing import Any

class MyProbe(AttackModule):
    name = "MyProbe"
    description = "Probe for a specific misconfiguration"
    target_services = ["http", "https"]
    target_ports = [80, 443]
    required_cves = []
    # Capability metadata (required for find_producers composition + gating):
    requires = ["credentials"]   # artifacts needed before this can run
    produces = ["high_priv"]     # artifacts yielded on success
    read_only = True             # False if it writes to the target
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": "What this probe does.",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f"""import sys
host = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
print(f"probing {{host}}")
"""
```

### Checklist

1. **Subclass `AttackModule`** in the relevant category file under
   `tools/attack_modules/modules/` (`docs/extension-guide.md:84`).
2. **Set metadata**: `name` (stable — tests and orchestrators reference it),
   `description`, `target_services`, `target_ports`, `required_cves`, and
   `target_versions` if version-aware scoring is needed.
3. **Declare capability metadata**: `requires` (artifacts the module needs),
   `produces` (artifacts it yields — use the shared vocabulary:
   `credentials` / `foothold` / `shell` / `user_list` / `hash_artifact` /
   `admin_priv` / `high_priv` / `persistence` / `webshell`), `read_only`
   (False only when it actually writes to the target), `cost`, and an explicit
   `phase_hint` (recon/enumerate/exploit/escalate/loot/persist/validate/pivot).
   `tests/test_module_capability_metadata_{a,b}.py` assert these are set.
4. **Implement `run(ctx) -> dict`**; override `applicability(ctx)` only if the
   base scoring is not enough (`docs/extension-guide.md:85-86`).
5. **Return structured data**: status, script text, suggested commands, or
   workflow instructions as dict keys; never embed credentials in plain output
   (`docs/extension-guide.md:98-100`).
6. **Re-export** the class from `tools/attack_modules/modules/__init__.py`
   (`modules/__init__.py:3-105`) and add it to `__all__`
   (`modules/__init__.py:106-183`).
7. **No registry edit needed** — filesystem auto-discovery picks up the new
   file on import (see Registry mechanism above). Out-of-tree:
   use `registry.register_attack_module(cls)` via the plugin system instead
   (`docs/extension-guide.md:102`, `docs/plugin-development.md:153-188`).
8. **Add tests** to `tests/test_attack_modules.py` covering registry
   registration, applicability, run output, and edge cases
   (`docs/extension-guide.md:88`).
9. **Run the suite**: `python -m pytest tests/ -v` and `ruff check .`
   (`AGENTS.md §Commands`).

Read-only / detection modules should follow the detection-family conventions:
no `shell_type`/`privilege_level` in results, target-locked to `ctx.target_ip`,
and a fixed low `applicability` override if they should always be selectable
(`detection.py:1-21`).

## Related documentation

- [extension-guide.md](extension-guide.md) — authoring a new module
- [plugin-development.md](plugin-development.md) — out-of-tree registration via `register_attack_module`
- [campaign.md](campaign.md) — campaign prerequisite-recovery scheduling
- [safety-model.md](safety-model.md) — ICS write dual gate and allowlist lock

## Source map

- `tools/attack_modules/registry.py`
- `tools/attack_modules/graph.py`
- `tools/attack_modules/artifacts.py`
- `tools/attack_modules/base.py`
- `tools/attack_modules/__init__.py`
- `tools/attack_modules/modules/__init__.py`
- `tools/attack_modules/modules/web/__init__.py`
- `tools/attack_modules/modules/web/sqli.py`
- `tools/attack_modules/modules/web/upload.py`
- `tools/attack_modules/modules/web/xss.py`
- `tools/attack_modules/modules/ics/__init__.py`
- `tools/attack_modules/modules/ics/bacnet.py`
- `tools/attack_modules/modules/ics/modbus.py`
- `tools/attack_modules/modules/ics/s7.py`
- `tools/attack_modules/modules/ics_iot.py`
- `tools/campaign/batch.py`
- `tests/test_artifact_graph.py`
