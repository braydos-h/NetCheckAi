---
title: Sandbox — Overview
package: tools/sandbox
files: [manager.py, policy.py, models.py, docker_backend.py, network.py, exceptions.py]
---

# Sandbox — Overview (`tools/sandbox/`)

Disposable Docker worker that contains offensive execution. MCP tools funnel attack commands through `SandboxManager`; the worker is hardened, network-filtered to the effective target allowlist, and destroyed after the run. Failures block execution — host execution is never a per-command fallback.

## Architecture

```
MCP tool (sandbox_exec.py) → SandboxManager.execute / execute_argv
    │   scope gate (_enforce_scope) + workspace validation
    ▼
ensure_sandbox → DockerBackend (create network + hardened worker)
    ▼
_apply_policy → policy.build_network_policy → network.apply_network_policy
    │   (ephemeral NET_ADMIN sidecar installs default-DROP ruleset)
    ▼
backend.exec inside worker (/workspace bind) → SandboxResult + audit row
    ▼
destroy (stop + rm container + rm network, idempotent, atexit)
```

The application layer (`@require_allowlist`, destination parsing) is defense-in-depth, not the boundary. The boundary is the worker plus its netns firewall, which is independent of the command string (`policy.py:1-16`, `docs/sandbox.md`).

## Package map

| File | Role | Key surface |
|---|---|---|
| `manager.py` | Lifecycle + execution funnel, one worker per run | `SandboxManager`, `resolve_manager`, `resolve_manager_with_fallback`, `status_report` |
| `policy.py` | Egress authorization derived from the target allowlist | `build_network_policy`, `authorize_destinations`, `audit_policy_payload` |
| `models.py` | Pure data + defensive config parsing, no Docker imports | `SandboxConfig`, `SandboxResult`, `SandboxSpec`, `NetworkPolicy` |
| `docker_backend.py` | Only Docker-aware component; named wrapper seams for tests | `DockerBackend`, `_build_create_args`, `_docker`, `run_netns_sidecar` |
| `network.py` | iptables/ip6tables ruleset build + install | `build_ipv4_rules`, `build_ipv6_rules`, `apply_network_policy` |
| `exceptions.py` | Fail-closed error hierarchy + `SANDBOX_*` codes | `SandboxError`, `sandbox_block` consumer in `mcp_bridge.py` |
| `mcp_bridge.py` | Tool-layer bridge (`sandbox_block`, `manager_from_ctx`) | `sandbox_block(exc, *, tool_name)` |
| `docker_lifecycle.py` | Optional host Docker daemon start/stop | `DockerLifecycle.from_config`, `acquire` |

House convention (`docker_backend.py:3-8`): every Docker CLI call goes through a named module-level wrapper; tests monkeypatch the wrappers, never `subprocess`.

## Lifecycle — `ensure` / `execute` / `destroy` (`manager.py:218`)

```python
def ensure_sandbox(self) -> str
def execute(self, command: str, *, timeout: int | None = None, cwd: str | None = None,
            env: dict[str, str] | None = None, user: str = "",
            target_ip: str = "", tool_name: str = "run_exploit_terminal") -> SandboxResult
def execute_argv(self, argv: list[str], *, timeout: int | None = None, cwd: str | None = None,
                 env: dict[str, str] | None = None, user: str = "",
                 target_ip: str = "", tool_name: str = "") -> SandboxResult
def destroy(self) -> dict[str, bool]
```

`ensure_sandbox` (`manager.py:246`): checks Docker + image, validates the workspace, sweeps stale labeled resources, creates a dedicated bridge network plus a hardened worker, installs the firewall **before the first agent command**, and verifies the worker is `running`. A vanished mid-run worker is recreated fresh, never reused. Partial failures destroy what was created and raise `SandboxError`.

Hot path (`manager.py:58-64`): a verified worker is cached for `_HOT_PATH_TTL_S = 30.0`s so `execute` skips `docker-inspect` plus policy rebuilds per command. A worker that vanishes inside the window surfaces as a fail-closed `backend.exec` error; dynamically authorized targets apply at most one window late.

`execute` wraps the command in `timeout -k <grace> <inner> bash -lc <command>`; host-side timeout is `inner + grace + 10`. `execute_argv` is the argv-list path (nmap, impacket, msfvenom) with no shell. Both call `_enforce_scope`, `_validate_workspace`, `ensure_sandbox`, `_apply_policy`, then `backend.exec`, and write started/completed (or timed_out) audit rows carrying the sandbox plus network-authorization context (`manager.py:411-481`).

`destroy` (`manager.py:612`): `stop` plus container/network removal, idempotent, audited via `audit_cleanup`, and registered with `atexit` (`_atexit_destroy`). `cleanup_stale` removes only non-running BreachPilot-labeled containers and empty labeled networks, so concurrent sessions keep their running workers.

Boot and status helpers:

```python
def resolve_manager(workspace: Path, config: dict | None) -> SandboxManager | None
def resolve_manager_with_fallback(workspace: Path, config: dict | None, *, probe: Any = None) -> tuple[SandboxManager | None, str]
def status_report(config: dict | None) -> dict[str, Any]
def native_fallback_notice(reason: str) -> str
def boot_state_path(config: dict | None) -> Path
def read_boot_state(config: dict | None) -> dict[str, Any] | None
```

`resolve_manager` returns `None` when the sandbox is disabled (explicit legacy opt-out). A present-but-broken section returns a manager that fail-closes at execution time (`manager.py:91-102`).

## Worker hardening (`docker_backend.py:240`)

Enforced in the pure, unit-tested `_build_create_args(spec, *, cap_raw, read_only_rootfs)`:

- `--cap-drop ALL`, only `NET_RAW` added back (for raw packet scanning). `NET_ADMIN` is never granted to the worker — the firewall sidecar alone holds it ephemerally.
- `--security-opt no-new-privileges`, non-root `--user sandbox`, never `--privileged`.
- `--read-only` rootfs (when configured) plus `--tmpfs /tmp:rw,noexec,nosuid,size=<tmpfs_size_mb>m`.
- `--memory` / `--memory-swap` / `--cpus` / `--pids-limit` from config.
- Dedicated per-run bridge network; never `host` network/pid/ipc; no devices.
- No `docker.sock`, no home-directory or arbitrary host mounts — only the validated run workspace binds at `/workspace` (`-w /workspace`).
- Labels `breachpilot=true` / `run_id=<id>`; keepalive `sleep infinity` so `docker exec` plus netns firewall have a long-lived target.

`DockerBackend.exec` allowlists env keys, rejects non-absolute or `..`-containing workdirs, and converts a host-side `DockerCommandTimeout` into a bare `TimeoutError` so a long agent command reads as a normal command timeout, not sandbox breakage (`docker_backend.py:361-399`).

The worker never receives the host environment — only fixed markers (`EXPLOIT_SANDBOX`, `EXPLOIT_WORKSPACE`, `TERM`) plus run-context keys in `_RUN_ENV_ALLOWLIST` and operator-configured `env_passthrough` names (`manager.py:66-82`).

## Network policy (`policy.py:68`, `network.py:141`)

```python
def build_network_policy(config: dict | None, *, gateway: str = "") -> NetworkPolicy
def authorize_destinations(destinations: list[str], config: dict | None) -> tuple[bool, str]
def audit_policy_payload(policy: NetworkPolicy) -> dict[str, Any]
def apply_network_policy(policy: NetworkPolicy, *, container_id: str, image: str, gateway: str = "", run_sidecar: Any = None) -> bool
```

`build_network_policy` derives the concrete egress allow set from `_allowed_target_list(config)` — the same sources the application layer uses:

| Allowlist token | Firewall treatment |
|---|---|
| IP / CIDR | Authorized verbatim |
| FQDN | Resolved **host-side** (all A/AAAA via `resolve_all_addresses`), resolved IPs authorized, hostname-to-address mapping recorded for audit |
| `*.wildcard` | Authorizes nothing statically; discovered hosts arrive via `EXPLOIT_DISCOVERED_TARGETS` on refresh |
| `localhost` / `127.0.0.1` / `::1` | Sandbox loopback only, unless `map_host_loopback` plus a gateway explicitly maps the dev host loopback |
| `0.0.0.0/0`, `::/0`, `*`, `any`, `all` | `ValueError` — the policy refuses to express "everywhere", caller fail-closes |

Always denied: `METADATA_DESTINATIONS` (`169.254.169.254`, `169.254.0.0/16`, `fd00:ec2::254`, `100.100.100.200`, `fe80::/10`) plus the Docker bridge gateway unless `allow_gateway` is set. `RESEARCH_HOSTS` (`github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `raw.githubusercontent.com`, `gitlab.com`) are resolved host-side and authorized when `allow_research_hosts` is true. `allow_dns: controlled` keeps the container resolver (`127.0.0.11`); `none` adds explicit port-53 REJECTs.

`network.py` renders default-DROP `iptables-restore` / `ip6tables-restore` rulesets installed by the ephemeral `--rm` sidecar sharing the worker netns (`run_netns_sidecar`). Re-application happens at each command boundary only when `NetworkPolicy.fingerprint()` changes, so dynamic targets are picked up deliberately. With `network.enforce: false` no firewall is installed — Docker bridge isolation only, explicitly not containment, and logged as such.

`authorize_destinations` is the command-level scope re-check (`SANDBOX_SCOPE_DENIED`) using the shared `check_targets_allowlist` matcher; `_enforce_scope` (`manager.py:500`) additionally denies target-less execution whenever any authorization material exists.

## Fail-closed errors (`exceptions.py:32-74`)

| Class | Code | Trigger |
|---|---|---|
| `SandboxUnavailableError` | `SANDBOX_UNAVAILABLE` | Docker CLI/daemon/image missing, worker start failed |
| `SandboxPolicyError` | `SANDBOX_POLICY_FAILED` | Netns firewall could not be installed |
| `SandboxScopeError` | `SANDBOX_SCOPE_DENIED` | Target outside allowlist, or empty allowlist with `require_explicit_allowlist: true` |
| `SandboxUnsupportedError` | `SANDBOX_UNSUPPORTED` | Operation has no sandbox-safe implementation — never auto-host |
| `SandboxWorkspaceError` | `SANDBOX_WORKSPACE_FAILED` | Workspace missing, symlink, or path escape |

`mcp_bridge.sandbox_block(exc, *, tool_name)` converts these into structured result blocks. `DockerCommandTimeout` is dual-typed (`SandboxUnavailableError`, `TimeoutError`) on purpose: verb wrappers treat it as unavailable, `DockerBackend.exec` re-raises it as `TimeoutError`.

## `fallback_native` — the one sanctioned fallback

`SandboxConfig.fallback_native` defaults to `False`. `resolve_manager_with_fallback` (`manager.py:159`) makes the decision once per server process, at boot: Docker stack unusable (CLI, daemon, or worker image probe) plus `fallback_native: true` returns `(None, notice)` so the whole session runs the documented legacy uncontained mode loudly (boot-log warning, WebUI amber card, `SANDBOX_FALLBACK:` line in legacy-path results). With `fallback_native: false` the manager is returned either way and every execution fail-closes. No session ever switches modes mid-stream.

The decision is recorded to `sandbox_boot_state.json` under the exploit workspace dir; `read_boot_state` / `status_report` report that recorded mode (`disabled` / `contained` / `native_fallback` / `blocked`), not a live probe that could drift mid-run.

Implementation note: `docs/sandbox.md` describes `fallback_native: true` as "the default" in two places, but `tools/config/schema.py:871` sets `False` and the shipped lab `config.yaml` sets `fallback_native: false`. The schema plus lab config are the operative defaults.

## Config keys

| Key | Default | Effect |
|---|---|---|
| `sandbox.enabled` | `True` (schema); absent section means disabled (`models.py:99-101`) | `false` is the explicit legacy host-execution opt-out |
| `sandbox.backend` | `docker` | Only backend |
| `sandbox.image` | `breachpilot-sandbox:latest` | Worker image; missing image fails closed or triggers boot fallback |
| `sandbox.user` | `sandbox` | In-container user |
| `sandbox.read_only_rootfs` | `true` | `--read-only` rootfs |
| `sandbox.fallback_native` | `false` | Boot-time whole-session native degrade vs strict fail-closed |
| `sandbox.auto_manage_docker` | `false` (schema; lab config enables it) | Start Docker on demand; stop it on exit only if BP started it and no containers remain |
| `sandbox.env_passthrough` | `[]` | Extra host env names the worker may receive |
| `sandbox.resources.memory_mb` / `cpus` / `pids` / `timeout_seconds` / `output_max_bytes` / `tmpfs_size_mb` | `4096` / `2` / `512` / `300` / `2000000` / `256` | Limits; invalid values fall back to defaults, never to host execution |
| `sandbox.network.enforce` | `true` | `false` disables the netns firewall (not containment) |
| `sandbox.network.fail_closed` | `true` | Policy posture flag |
| `sandbox.network.allow_dns` | `controlled` | `controlled` or `none` (port 53 fully blocked) |
| `sandbox.network.map_host_loopback` | `false` | Dev-only host-loopback mapping |
| `sandbox.network.extra_allow_cidrs` | `[]` | Operator-authorized extra CIDRs; invalid entries warn and skip |
| `sandbox.network.allow_gateway` | `false` | Keep false; gateway reaches host-published services and the daemon |
| `sandbox.network.allow_research_hosts` | `true` | Pinned github/gitlab egress, host-resolved |
| `sandbox.cleanup.remove_on_exit` / `remove_stale_on_startup` | `true` / `true` | Destroy worker/network on exit; sweep stale labeled resources at boot |
| `sandbox.multi_net_raw` | `true` | `NET_RAW` for raw packet scanning; `false` drops even that |

`SandboxConfig.from_config` parses defensively (`_as_dict` / `_as_bool` / `_as_int` / `_as_float` floor invalid values to defaults), so partial config dicts stay on the legacy path instead of crashing.

## Examples

```python
from pathlib import Path
from tools.sandbox.manager import resolve_manager_with_fallback

manager, notice = resolve_manager_with_fallback(Path("exploit_workspace/10.0.0.50"), config)
if manager is None:
    print(notice)  # whole session runs legacy native mode; no per-command fallback
    ...
result = manager.execute("nmap -sV 10.0.0.50", target_ip="10.0.0.50")
print(result.exit_code, result.status)
manager.destroy()
```

```python
from tools.sandbox.policy import build_network_policy

policy = build_network_policy(config, gateway="172.18.0.1")
print(policy.authorized_destinations, policy.fingerprint())
```

```bash
docker build -t breachpilot-sandbox:latest docker/sandbox
```

## Tests

| File | Verified | Covers |
|---|---|---|
| `tests/test_sandbox_manager.py` | yes | `TestResolveManager`, `TestExecutionFunnel` |
| `tests/test_sandbox_policy.py` | yes | `TestBuildNetworkPolicy`, `TestAuditPolicyPayload` |
| `tests/test_sandbox_network.py` | yes | `TestIpv4Rules`, `TestIpv6Rules` |
| `tests/test_sandbox_models.py` | yes | `TestSandboxConfigFromConfig` |
| `tests/test_sandbox_backend.py` | yes | `TestBuildCreateArgs`, `TestValidation` |
| `tests/test_sandbox_hardening.py` | yes | Present; hardening invariants |
| `tests/test_sandbox_native_fallback.py` | yes | Present; boot-time fallback decision |
| `tests/test_sandbox_mcp_exec.py` | yes | Present; tool-layer exec funnel |
| `tests/test_sandbox_docker_lifecycle.py` | yes | Present; daemon lifecycle |
| `tests/test_sandbox_family_audit.py` | yes | Present; planned vs sandboxed families |
| `tests/test_sandbox_remediation.py` | yes | Present; remediation plans |
| `tests/test_sandbox_integration.py` | yes | Present; real-Docker integration |
| `tests/test_api_run_sandbox.py` | yes | Present; run API sandbox surface |
| `tests/test_browser_sandbox_family.py` | yes | Present; browser worker family |

Implementation note: Covers entries beyond the first five rows are grounded on file presence plus names, not a full read of each file.

## Related documentation

- [Sandbox](../../../sandbox.md)
- [Safety model](../../../safety-model.md)
- [MCP tools](../../../mcp-tools.md)
- [Architecture](../../../architecture.md)
- [Kernel overview](../kernel/overview.md)
- [Providers overview](../providers/overview.md)

## Source map

- `tools/sandbox/manager.py`
- `tools/sandbox/policy.py`
- `tools/sandbox/models.py`
- `tools/sandbox/docker_backend.py`
- `tools/sandbox/network.py`
- `tools/sandbox/exceptions.py`
- `tools/sandbox/mcp_bridge.py`
- `tools/sandbox/docker_lifecycle.py`
- `tools/mcp_tools/sandbox_exec.py`
