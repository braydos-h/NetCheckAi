# Disposable Execution Sandbox

The sandbox is BreachPilot's **isolation boundary** for offensive execution.
Every attack command — arbitrary terminal commands, generated Python, exploit
tools, Metasploit — runs inside a hardened, disposable Docker worker instead
of on the operator host.

```
LLM/MCP tool → BreachPilot policy/scope checks → disposable sandbox → target
```

This document distinguishes the two layers the rest of the safety docs refer
to, lists the exact security invariants, and documents residual risks.

## The two layers

| Layer | Controls | Role |
|---|---|---|
| **Application controls** (defense-in-depth) | ScopeGate, `@require_allowlist` decorators, destination parsing (`command_analyzer`, `_target_lock_block`), mission policy, `exploit.forbidden_actions` | Decide *what may be attempted*, inspect command strings and targets |
| **Isolation boundary** (containment) | Disposable worker container, cap-drop + no-new-privileges, read-only rootfs, resource limits, netns egress firewall, host filesystem isolation | Decide *what can physically be reached or damaged* |

**Docker alone does not make exploitation safe.** The application layer can be
confused by encoded destinations, by destinations that never appear on the
command line, or by dynamic resolution inside a script. The sandbox network
policy is independent of the command string: it authorizes concrete IPs/CIDRs
at the packet level and DROPs everything else.

## Lifecycle

One worker per attack run/session (`tools/sandbox/manager.py`):

1. **create** — `docker create` + `start` a hardened worker (never reuse
   existing containers; containers are labeled `breachpilot=true`,
   `run_id=<id>`)
2. **configure network policy** — an ephemeral `NET_ADMIN` sidecar sharing the
   worker's network namespace installs a default-DROP `iptables`/`ip6tables`
   ruleset authorizing ONLY the effective target allowlist (before the first
   agent command)
3. **mount run workspace** — `exploit_workspace/<run>/` binds at `/workspace`
   (the only host path the worker can see)
4. **execute** — all attack tools run inside the worker
5. **collect evidence** — artifacts persist via `/workspace` (reports, audit,
   WebUI artifact viewer, loot all read the same run workspace)
6. **terminate processes** — `docker stop` (inner `timeout` TERM→KILL per
   command is the first bound)
7. **destroy** — container + dedicated bridge network removed on normal
   completion, exception, timeout, cancellation, and interpreter shutdown
   (atexit)

Stale exited BreachPilot-labeled containers and empty labeled networks are
swept at MCP server startup (running workers of concurrent sessions are kept).

## Worker hardening

Enforced in `tools/sandbox/docker_backend.py::_build_create_args` (unit-tested):

- `--cap-drop ALL`; only `NET_RAW` is added back (`sandbox.multi_net_raw`,
  default true) for raw packet scanning. **`NET_ADMIN` is never granted to the
  worker** — the worker cannot loosen, remove, or even enumerate its own
  netns firewall rules.
- `--security-opt no-new-privileges`, non-root user (`--user sandbox`),
  `--privileged` never.
- `--read-only` rootfs (default) + `--tmpfs /tmp`; `/workspace` is the only
  writable bind.
- `--memory`/`--memory-swap`/`--cpus`/`--pids-limit` per config.
- Dedicated per-run bridge network (`network_mode` is never `host`; `pid_mode`
  and `ipc_mode` are never `host`; no devices).
- **No** `/var/run/docker.sock`, no SSH agent sockets, no home-directory
  mounts, no arbitrary host paths.

## Network containment (fail closed)

`tools/sandbox/policy.py` derives the concrete egress allow set from the same
allowlist sources the application layer uses (`exploit.allowed_targets` +
`EXPLOIT_TARGET*` env vars):

- **IPs / CIDRs** — authorized verbatim.
- **FQDNs** — resolved **host-side** by BreachPilot, validated against the
  allowlist, resolved IPs added to the firewall authorization, and the
  domain→IP mapping recorded in the audit trail. The worker never performs
  arbitrary DNS-driven egress.
- **`*.wildcard` domains** — authorize nothing statically; only their
  dynamically discovered, separately allowlist-validated resolved IPs apply.
- **`localhost`/`127.0.0.1`** — sandbox loopback only (container `lo`). Host
  loopback is reachable ONLY with the explicit dev opt-in
  `sandbox.network.map_host_loopback: true`; production attack mode must not
  enable it.
- **Everything else is DROPped**: arbitrary internet hosts, host LAN devices,
  cloud metadata (`169.254.169.254`, link-local, AWS IMDS IPv6, Alibaba),
  the Docker bridge gateway (path to host-published services and the Docker
  daemon), and unrelated containers. `sandbox.network.allow_dns: none` blocks
  port 53 entirely (including loopback) for zero-DNS missions.

The ruleset terminates in `-A NAI-OUTPUT -j DROP` (default-deny egress). IPv6
is default-deny with the same shape.

### Why a sidecar, not worker NET_ADMIN

`tools/sandbox/network.py` runs `iptables-restore`/`ip6tables-restore` from an
ephemeral `--rm` sidecar container that shares the **worker's** network
namespace and holds the only `NET_ADMIN` grant. Docker drops the grant when
the sidecar exits. The worker itself runs `--cap-drop ALL` (possibly + NET_RAW),
so agent commands — even as root inside the container — cannot modify the
firewall. Rules are (re-)applied at each command boundary when the
authorization fingerprint changes (dynamic target pickup), always host-driven.

## Fail-closed behavior (with one boot-time fallback)

Any failure DURING an active session **blocks offensive execution** and
returns a structured `SANDBOX_*` result block (never a per-command host
fallback):

| Code | Trigger |
|---|---|
| `SANDBOX_UNAVAILABLE` | Docker daemon died after boot, worker start failed |
| `SANDBOX_POLICY_FAILED` | netns firewall could not be installed |
| `SANDBOX_SCOPE_DENIED` | target outside allowlist, or empty allowlist with `require_explicit_allowlist: true` |
| `SANDBOX_WORKSPACE_FAILED` | workspace missing/symlink/path escape |
| `SANDBOX_UNSUPPORTED` | operation has no sandbox-safe implementation (documented; never auto-host) |

Invariant: `require_explicit_allowlist: true` + empty effective allowlist ⇒
**DENY all target-touching execution** (enforced in `tools/kernel/allowlist.py`,
the sandbox scope gate, and the empty netns policy simultaneously).

The ONE sanctioned host-execution fallback is the boot-time decision in
`tools/sandbox/manager.py::resolve_manager_with_fallback`: with
`sandbox.fallback_native: true` (the default), a server whose Docker stack is
unusable at boot (CLI missing, daemon down, **worker image not built**) wholly
degrades to the legacy uncontained host-execution mode BEFORE any tool
exists — loudly: a `SANDBOX FALLBACK:` boot-log warning, an amber
"Sandbox unavailable — running natively" card on the WebUI home screen, and a
`SANDBOX_FALLBACK:` line in every legacy-path tool result (and its audit
chain). No session ever switches between contained and native execution
mid-stream. Set `sandbox.fallback_native: false` to restore the strict
fail-closed posture (executions denied until Docker works). `sandbox.enabled:
false` remains the explicit operator opt-out for the legacy uncontained mode,
without any Docker probing.

## What runs where

| Tool | Runs |
|---|---|
| `run_exploit_terminal`, `run_as_root` (container root), `git_clone` | sandbox |
| Generated Python (`run_python_file`) | sandbox (never the operator's interpreter) |
| nmap / masscan / rustscan | sandbox |
| curl / wget | sandbox |
| sqlmap / nikto / gobuster-class scanners | sandbox |
| Metasploit (`msfconsole`) / msfvenom | sandbox |
| Impacket / SMB tooling | sandbox |
| hashcat / john | sandbox when the worker image provides them (GPU passthrough is out of scope; document CPU-only runs) |
| Exploit scripts / general terminal commands | sandbox |
| Browser ops (`browser_*`: navigate/observe/screenshot/JS) | sandbox browser worker (`breachpilot-sandbox:browser`: base worker + Playwright/Chromium; one Chromium op per docker exec, strict fail-closed — never host fallback, never the native fallback) |
| Recon pipeline (host-side, no agent-generated code execution) | host (unchanged, scope-gated) |
| PoC verifier (`poc_verifier`) compile gate | host docker (isolated, network `none` — pre-existing separate mechanism) |

Tools absent from the worker image surface as missing-tool warnings from
preflight; extend a derived image (`FROM breachpilot-sandbox:latest`) for
mission-specific tooling. Do not add host fallbacks.

### Planned families

`tools/sandbox/family_audit.py` also carries `PLANNED_FAMILIES` — tool
families whose architecture exists but whose execution is not implemented
(empty today: the **browser** family graduated to `SANDBOXED_FAMILIES` when
the Playwright backend landed — Chromium runs one op per docker exec inside
the worker netns via `SandboxPlaywrightLauncher`, obeying the effective
target allowlist with no host fallback). Planned families emit no audit rows
and never count as audit problems (see `tests/test_browser_sandbox_family.py`).
Design: [docs/browser-agent-design.md §8](browser-agent-design.md).

To run the browser agent contained, point the worker at the browser variant
(a strict superset of the base image, so terminal/Python execution is unchanged):

```bash
docker build -t breachpilot-sandbox:browser -f docker/sandbox/Dockerfile.browser docker/sandbox
```

## Worker image

`docker/sandbox/Dockerfile` — Debian slim + python3, nmap, curl/wget,
netcat, git, iproute2, iptables (needed by the firewall sidecar), openssh
client, and recon helpers. No secrets, API keys, repo credentials, or user
configuration are baked in. Rebuild/upgrade independently:

```bash
docker build -t breachpilot-sandbox:latest docker/sandbox
```

### Optional Docker daemon lifecycle

Set `sandbox.auto_manage_docker: true` to keep Docker stopped while BreachPilot
is idle and have the sandbox session start it on demand. The controller never
claims or stops a daemon that was already running. On exit it stops Docker only
when BreachPilot started it and `docker ps` reports no running containers, so
other local workloads are left alone. On Linux it uses `sudo -n`; run
`sudo -v` before starting BP if your sudo policy requires a password. If the
service cannot be started, the existing strict fail-closed or explicit native
fallback decision applies—there is no mid-session host-execution fallback.

The feature is enabled in the shipped local `config.yaml`, but it is disabled
by default in the schema for deployments that should never manage a host
daemon. `bp --doctor` and the WebUI daemon do not start Docker; only an exploit
MCP sandbox session acquires it.

## Secrets & environment

The worker never receives the host environment. It gets a fixed set of sandbox
markers, an allowlist of run-context keys (`EXPLOIT_TARGET*`, model host), and
operator-configured `sandbox.env_passthrough` names. Audit payloads are
secret-free by construction and existing redaction (`tools/kernel/audit.py`)
still applies to command text.

## Auditing

Every sandbox execution writes `exploit_audit.jsonl` rows with a `sandbox`
context: run id, container id, image, user, env keys, network-authorization
decision (authorized destinations, explicit blocks, resolved domains,
unresolved targets, fingerprint), exit code, timeout, duration, and a cleanup
audit row on destroy.

## WebUI / API

`GET /api/v1/system/sandbox` (bearer-auth) reports enabled/backend/image/user,
rootfs mode, the effective posture (`mode`: `disabled` / `contained` /
`native_fallback` / `blocked`, from the recorded BOOT-TIME decision — a
session's posture never flips mid-run even if Docker state changes
afterwards), `fallback_native`, the failure reason (`fallback_reason`),
live Docker reachability, worker-image presence (`image_present`, null when
unknowable), network policy posture, resource limits, and cleanup flags.
The WebUI home screen renders a posture banner from this endpoint (green
"contained" line, muted "disabled" line, amber native-fallback warning card,
red fail-closed card). The System UI (Settings → Advanced → Sandbox) renders
the same with a build hint when the worker image is missing; the status-bar
chip surfaces the short state ("Contained", "Image missing", "Docker
unreachable", "Disabled").

`GET /api/v1/runs/{run_id}/sandbox` (bearer-auth) summarizes a run's sandbox
activity for the run page's Sandbox tab, derived read-only from run artifacts:
container identity and config echo (exploit_audit.jsonl `sandbox` rows), the
last network-authorization policy (authorized/blocked destinations, resolved
domains, fingerprint), execution status counts (cleanup rows excluded), and
the last five SANDBOX_* blocked commands with reason codes (from tool_result
events). Both endpoints are read-only — the WebUI never exposes Docker
exec/remove controls; sandbox lifecycle belongs to the run engine.

## Doctor

`python main.py --doctor` adds a `sandbox` check when `sandbox.enabled: true`:
Docker CLI present, daemon reachable, worker image present. With
`sandbox.fallback_native: false` a failed check fails the doctor (because
attack execution would be blocked); with the default `fallback_native: true`
the doctor still flags the check but the session would degrade to native
execution instead of blocking.

## Configuration

```yaml
sandbox:
  enabled: true                # false = explicit legacy host-execution opt-out
  backend: docker
  image: breachpilot-sandbox:latest
  fallback_native: true        # boot-time Docker down/image missing => degrade to
                               # uncontained native execution (loud warning) instead
                               # of fail-closed blocks; false = strict fail-closed
  user: sandbox
  read_only_rootfs: true
  env_passthrough: []          # extra host env var names the worker may receive
  resources:
    memory_mb: 4096
    cpus: 2
    pids: 512
    timeout_seconds: 300       # per-command default
    output_max_bytes: 2000000
    tmpfs_size_mb: 256         # /tmp tmpfs size (MB, min 64)
  network:
    enforce: true              # false = no netns firewall (NOT containment)
    fail_closed: true
    allow_dns: controlled      # controlled | none
    map_host_loopback: false   # dev-only host-loopback mapping
    extra_allow_cidrs: []      # operator-authorized extra CIDRs
    allow_gateway: false       # keep false (gateway = path to Docker daemon)
    allow_research_hosts: true # pinned github/gitlab egress, host-resolved
  cleanup:
    remove_on_exit: true
    remove_stale_on_startup: true
  multi_net_raw: true          # NET_RAW for raw packet scanning
```

The worker's `/tmp` is a tmpfs sized by `sandbox.resources.tmpfs_size_mb` (default 256m, minimum 64m; invalid values fall back to the default, never to host execution). Raise it when staging msfvenom payloads or spilling large wordlists to `/tmp`; the `rw,noexec,nosuid` flags stay fixed regardless of size.

## Threat model coverage

| Threat | Mitigation |
|---|---|
| Reach unauthorized public IP | netns default-DROP egress; only allowlist ACCEPTs |
| Reach another LAN host | same (RFC1918 is not blanket-allowed; authorization is the boundary) |
| Reach cloud metadata | explicit DROPs for 169.254.169.254, link-local, IMDS IPv6, Alibaba |
| Access Docker daemon | no docker.sock mount; bridge gateway DROPped |
| Read host filesystem | only validated workspace bound; read-only rootfs; no privileged |
| Fork bomb / resource abuse | pids-limit, memory/swap, cpus, per-command timeout |
| Background processes outliving run | `docker stop` + container destruction on exit/atexit |
| Persistence on operator host | no host writes outside workspace; disposable container/network |
| Bypass destination parsing | policy independent of command string (destinationless script test) |
| Python socket hidden egress | same firewall (integration-tested) |
| Encoded IPs | enforcement at packet layer (integration-tested with hex-decoded IP) |
| DNS destination switch | host-side controlled resolution; resolved IPs validated + audited |
| Reach host services via gateway | gateway DROPped unless explicitly configured |
| Tamper with firewall from inside | NET_ADMIN lives only in the ephemeral sidecar |

## Residual risks (documented, not hidden)

- **Docker itself** is the trust base: a Docker daemon/container-escape
  vulnerability defeats the boundary. Keep Docker updated; the sandbox raises
  the bar but is not a VM.
- **`map_host_loopback: true`** intentionally maps sandbox loopback targets to
  the host gateway — dev/lab only.
- **`network.enforce: false`** removes the netns firewall and leaves only
  Docker bridge isolation — explicitly NOT containment; audits record it.
- **`allow_research_hosts: true`** (default) authorizes pinned research
  egress (github.com et al.) — a fixed, auditable list; set false for
  air-gapped missions.
- **`extra_allow_cidrs`** widens the boundary by configuration; operator
  responsibility.
- **RAW sockets (NET_RAW)** enable packet spoofing *toward authorized
  destinations only*; the OUTPUT filter still bounds destinations. Set
  `multi_net_raw: false` to drop even NET_RAW.
- **Windows/macOS** run via Docker Desktop; the netns firewall applies inside
  the Linux VM. If strong containment cannot be guaranteed on a platform, the
  sandbox fails closed (`SANDBOX_*`) rather than falling back to host
  execution.
- On-container root (`run_as_root`) is container-root only — confined by
  cap-drop, no-new-privileges, the netns firewall, and the workspace bind.
