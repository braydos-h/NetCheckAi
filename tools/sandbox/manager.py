"""SandboxManager: disposable worker lifecycle, fail-closed execution funnel.

Lifecycle per attack session (one worker container per MCP server process,
i.e. one per attack run):

    ensure (docker checks -> dedicated network -> hardened worker -> netns
    firewall) -> execute every attack command inside -> destroy on normal
    exit / exception / timeout / cancellation / interpreter shutdown (atexit).

FAIL CLOSED contract: any creation, policy, scope, or workspace failure raises
a ``SandboxError`` subclass with a structured ``code``; the MCP tools convert
it into a ``SANDBOX_*`` result block and never fall back to host execution.
``resolve_manager`` returns None when the sandbox is disabled so the
documented legacy host-execution mode stays available as the explicit opt-out.

Audit: every execution writes sandbox-context rows (container id, image,
network-authorization decision, authorized set, exit code, duration, cleanup
result) into ``exploit_audit.jsonl`` through the shared kernel auditor
(secret redaction reused from ``tools/kernel/audit.py``; the sandbox payload
is secret-free by construction -- see ``policy.audit_policy_payload``).
"""

from __future__ import annotations

import atexit
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any

from tools.sandbox import docker_backend as _db
from tools.sandbox import policy as _policy
from tools.sandbox.exceptions import (
    SandboxError,
    SandboxScopeError,
    SandboxUnavailableError,
    SandboxWorkspaceError,
)
from tools.sandbox.models import NetworkPolicy, SandboxConfig, SandboxResult, SandboxSpec
from tools.sandbox.network import apply_network_policy

logger = logging.getLogger(__name__)

__all__ = [
    "SandboxManager",
    "resolve_manager",
    "status_report",
    "CONTAINER_WORKSPACE",
    "BOOT_STATE_FILE",
    "boot_state_path",
    "read_boot_state",
]

CONTAINER_WORKSPACE = "/workspace"

# Hot-path bound: per-command docker-inspect + policy rebuilds are skipped for
# this long after a verified ensure (execute() is the hot path; a cold
# docker-inspect + DNS-touching policy rebuild on EVERY command added seconds
# per call). A vanished worker inside the window surfaces as a fail-closed
# backend.exec SandboxError (safe direction); dynamically authorized targets
# apply at most one window late.
_HOT_PATH_TTL_S = 30.0

# Environment the worker may receive: fixed sandbox markers, run-context keys
# the MCP tool layer injects, and operator-configured ``env_passthrough`` names.
# NEVER a copy of the host environment.
_BASE_ENV: dict[str, str] = {
    "EXPLOIT_SANDBOX": "1",
    "EXPLOIT_WORKSPACE": CONTAINER_WORKSPACE,
    "TERM": "dumb",
}
_RUN_ENV_ALLOWLIST = {
    "ACTIVE_CHECK_TARGET",
    "EXPLOIT_TARGET",
    "EXPLOIT_TARGET_IP",
    "EXPLOIT_TARGET_DOMAIN",
    "MCP_EXPLOIT_MODEL",
    "MODEL",
    "OLLAMA_HOST",
}


def _build_manager(cfg: SandboxConfig, workspace: Path, config: dict[str, Any] | None) -> SandboxManager:
    # cap_raw honors sandbox.multi_net_raw: NET_RAW is the ONLY capability the
    # worker may receive (raw packet scanning); NET_ADMIN is never granted.
    return SandboxManager(cfg, workspace, config_dict=config, backend=_db.DockerBackend(cap_raw=cfg.multi_net_raw))


def resolve_manager(workspace: Path, config: dict[str, Any] | None) -> SandboxManager | None:
    """Build a SandboxManager from config; returns None when the sandbox is disabled.

    A MISSING ``sandbox`` section (tests, partial config dicts) means disabled =>
    documented legacy host-execution mode. A PRESENT-but-broken section returns
    a manager that fail-closes at execution time -- it never silently upgrades
    to host execution.
    """
    cfg = SandboxConfig.from_config(config)
    if not cfg.enabled:
        return None
    return _build_manager(cfg, workspace, config)


def native_fallback_notice(reason: str) -> str:
    """Canonical one-line native-fallback notice (boot log, ctx, tool result)."""
    return (
        f"Docker sandbox unavailable ({reason}) -- falling back to NATIVE "
        f"(uncontained) legacy host execution for this session "
        f"(sandbox.fallback_native=true). Start Docker and build the sandbox "
        f"image to contain execution; set sandbox.fallback_native: false to "
        f"fail closed instead."
    )


# Boot-state plumbing: the fallback decision happens once per MCP server
# process, at boot, inside that subprocess. The API daemon cannot re-derive
# it, so it is recorded to a config-derived shared file that both the server
# and the daemon resolve identically (both run from the same repo root CWD).
# The home banner reports THIS decision, not a live Docker probe (which can
# drift from the session after the fact -- e.g. the operator starts Docker
# mid-run; the running session stays native/blocked regardless).
BOOT_STATE_FILE = "sandbox_boot_state.json"
_VALID_BOOT_MODES = ("disabled", "contained", "native_fallback", "blocked")


def boot_state_path(config: dict[str, Any] | None) -> Path:
    """Shared boot-state file location, derived from the config the same way
    on both sides (MCP server subprocess + API daemon): the exploit
    ``workspace_dir`` root, resolved against the process CWD."""
    root = str((config or {}).get("exploit", {}).get("workspace_dir") or "exploit_workspace")
    p = Path(root)
    root_dir = p if p.is_absolute() else Path.cwd() / p
    return root_dir / BOOT_STATE_FILE


def _record_boot_state(config: dict[str, Any] | None, mode: str, reason: str = "") -> None:
    """Best-effort boot-posture record; never breaks server boot."""
    try:
        path = boot_state_path(config)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"mode": mode, "reason": reason, "recorded_at": time.time()}),
            encoding="utf-8",
        )
    except (OSError, ValueError, TypeError):  # noqa: BLE001 -- status bookkeeping must never affect the attack path
        logger.warning("sandbox boot-state record failed", exc_info=True)


def read_boot_state(config: dict[str, Any] | None) -> dict[str, Any] | None:
    """Latest recorded boot posture, or None (missing/unreadable/stale)."""
    try:
        state = json.loads(boot_state_path(config).read_text(encoding="utf-8"))
        return state if state.get("mode") in _VALID_BOOT_MODES else None
    except (OSError, ValueError, TypeError, KeyError, AttributeError):  # noqa: BLE001 -- absence is a normal first-run state
        return None


def resolve_manager_with_fallback(
    workspace: Path,
    config: dict[str, Any] | None,
    *,
    probe: Any = None,
) -> tuple[SandboxManager | None, str]:
    """Boot-time sandbox resolution WITH the documented native fallback.

    Same contract as :func:`resolve_manager` plus the one sanctioned fallback
    decision: when the sandbox is enabled but the Docker stack is unusable
    (CLI / daemon / worker image missing) and ``sandbox.fallback_native`` is
    true, return ``(None, notice)`` so the caller runs the documented legacy
    host-execution mode for the whole session and can warn loudly. With
    ``fallback_native: false`` the manager is returned either way -- it then
    fail-closes at execution time exactly as before.

    The resolved boot posture is ALSO recorded to a shared boot-state file
    (:func:`boot_state_path`) so the WebUI home banner reports the effective
    session decision (decided ONCE, here) instead of a live Docker probe that
    can drift from the session after the fact.

    Probes are injected (``probe``: ``(ok, reason)`` callable) so tests never
    need a real Docker daemon. The image probe only runs when Docker answers;
    its failure is treated as "sandboxing doesn't work" for the fallback
    decision (a missing first-run image is the common broken-lab case).
    """
    cfg = SandboxConfig.from_config(config)
    if not cfg.enabled:
        return None, ""
    from tools.sandbox.docker_lifecycle import DockerLifecycle

    lifecycle = DockerLifecycle.from_config(config, probe=probe)
    ok, reason = lifecycle.acquire()
    if ok:
        try:
            image_ok = bool(_db.docker_image_exists(cfg.image))
            if not image_ok and not reason:
                reason = f"sandbox image '{cfg.image}' not built"
        except SandboxError as exc:
            image_ok, reason = False, str(exc)
        except Exception as exc:  # noqa: BLE001 -- probe seams may raise anything; degrade, never crash boot
            image_ok, reason = False, f"sandbox image probe failed: {exc}"
        if image_ok:
            _record_boot_state(config, "contained")
            return _build_manager(cfg, workspace, config), ""
        if not cfg.fallback_native:
            _record_boot_state(config, "blocked", reason)
            return _build_manager(cfg, workspace, config), ""
        reason = native_fallback_notice(reason)
        _record_boot_state(config, "native_fallback", reason)
        return None, reason
    if not cfg.fallback_native:
        _record_boot_state(config, "blocked", reason)
        return _build_manager(cfg, workspace, config), ""
    reason = native_fallback_notice(reason)
    _record_boot_state(config, "native_fallback", reason)
    return None, reason


class SandboxManager:
    """Owns exactly one disposable worker container + its dedicated bridge network."""

    def __init__(
        self,
        config: SandboxConfig,
        workspace: Path,
        *,
        config_dict: dict[str, Any] | None = None,
        backend: Any = None,
        run_id: str = "",
    ) -> None:
        self.cfg = config
        self.workspace = Path(workspace)
        self.config_dict = config_dict
        self.backend = backend if backend is not None else _db.DockerBackend()
        self.run_id = run_id or secrets.token_hex(6)
        self.container_id: str = ""
        self.network_name: str = ""
        self.gateway: str = ""
        self._policy: NetworkPolicy | None = None
        self._ensure_valid_until: float = 0.0
        self._policy_valid_until: float = 0.0
        self._destroyed = False
        atexit.register(self._atexit_destroy)

    # ------------------------------------------------------------------ setup

    def ensure_sandbox(self) -> str:
        """Guarantee a running, policy-contained worker. Returns the container id.

        A mid-run vanished worker is recreated fresh (never reused). Any
        failure destroys partial resources and raises ``SandboxError`` -- the
        caller must block execution; there is no host fallback.

        Hot path: a recently verified worker is returned from a time-bound
        cache instead of re-probing docker-inspect on every command.
        """
        if self.container_id and time.monotonic() < self._ensure_valid_until:
            return self.container_id
        if self.container_id:
            state = self._container_state()
            if state == "running":
                self._apply_policy()
                self._ensure_valid_until = time.monotonic() + _HOT_PATH_TTL_S
                return self.container_id
            logger.warning("sandbox worker %s vanished (state=%r); recreating", self.container_id, state)
            self._destroy_resources()
        try:
            self.backend.ensure_docker()
            self.backend.ensure_image(self.cfg.image)
            self._validate_workspace()
            if self.cfg.remove_stale_on_startup:
                self.cleanup_stale()
            self.network_name = f"breachpilot-net-{self.run_id}-{secrets.token_hex(3)}"
            self.backend.create_network(self.network_name)
            self.gateway = _db.docker_network_gateway(self.network_name)
            spec = SandboxSpec(
                sandbox_id=f"breachpilot-{self.run_id}-{secrets.token_hex(3)}",
                image=self.cfg.image,
                user=self.cfg.user,
                network_name=self.network_name,
                workspace_src=str(self.workspace),
                memory_mb=self.cfg.memory_mb,
                cpus=self.cfg.cpus,
                pids_limit=self.cfg.pids_limit,
                read_only_rootfs=self.cfg.read_only_rootfs,
                tmpfs_size_mb=self.cfg.tmpfs_size_mb,
                labels={"run_id": self.run_id},
            )
            self.container_id = self.backend.create_worker(spec, read_only_rootfs=self.cfg.read_only_rootfs)
            self.container_id = _db._validate_container_id(self.container_id)
            # Firewall BEFORE the first agent command; NET_ADMIN lives only in
            # the ephemeral --rm sidecar, never in the worker itself.
            self._apply_policy(force=True)
            if self._container_state() != "running":
                raise SandboxUnavailableError("sandbox worker is not running after start")
            self._ensure_valid_until = time.monotonic() + _HOT_PATH_TTL_S
        except SandboxError:
            self._destroy_resources()
            raise
        except Exception as exc:
            self._destroy_resources()
            raise SandboxUnavailableError(f"sandbox creation failed: {exc}") from exc
        return self.container_id

    def _container_state(self) -> str:
        if not self.container_id:
            return ""
        try:
            return _db.docker_inspect_state(self.container_id)
        except SandboxError:
            return ""

    def _validate_workspace(self) -> None:
        ws = self.workspace
        if not ws.exists() or not ws.is_dir():
            raise SandboxWorkspaceError(f"sandbox workspace {ws} is not a directory")
        # Symlink-escape guard: the bound directory must be a real directory.
        if ws.is_symlink():
            raise SandboxWorkspaceError(f"sandbox workspace {ws} must not be a symlink")

    # ------------------------------------------------------- network policy

    def _apply_policy(self, *, force: bool = False) -> NetworkPolicy:
        """Derive the egress policy; install firewall rules when it changed.

        Re-derivation happens per command boundary so dynamically authorized
        targets (allowlist-validated resolved domains + discovered subdomains)
        are picked up deliberately -- never automatic DNS egress. Within one
        hot window (``_HOT_PATH_TTL_S``) the last installed policy is reused
        without rebuilding, so the hot execute() path stays cheap; a forced
        apply (fresh worker) always rebuilds.
        """
        now = time.monotonic()
        if not force and self._policy is not None and now < self._policy_valid_until:
            return self._policy
        pol = _policy.build_network_policy(self.config_dict, gateway=self.gateway)
        if not force and self._policy is not None and pol.fingerprint() == self._policy.fingerprint():
            self._policy_valid_until = now + _HOT_PATH_TTL_S
            return pol
        if self.cfg.network_enforce:
            apply_network_policy(pol, container_id=self.container_id, image=self.cfg.image, gateway=self.gateway)
        else:
            logger.warning(
                "sandbox network.enforce=false: worker runs WITHOUT netns firewall "
                "(Docker bridge isolation only -- this is NOT containment)"
            )
        self._policy = pol
        self._policy_valid_until = time.monotonic() + _HOT_PATH_TTL_S
        return pol

    def ensure_network_policy(self) -> NetworkPolicy:
        return self._apply_policy(force=False)

    # ------------------------------------------------------------- execution

    def execute(
        self,
        command: str,
        *,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        user: str = "",
        target_ip: str = "",
        tool_name: str = "run_exploit_terminal",
    ) -> SandboxResult:
        """Run one LLM-generated shell command inside the sandbox.

        Raises ``SandboxError`` subclasses (fail closed) -- NEVER falls back to
        the host. Audit rows carry the sandbox / network-authorization context.
        """
        inner = int(timeout or self.cfg.exec_timeout_seconds)
        grace = _db.EXEC_KILL_GRACE_SECONDS
        argv = ["timeout", "-k", str(grace), str(inner), "bash", "-lc", command]
        return self._execute_argv(
            argv,
            timeout=inner + grace + 10,
            cwd=cwd,
            env=env,
            user=user or self.cfg.user,
            target_ip=target_ip,
            tool_name=tool_name,
            audit_command=command,
        )

    def execute_argv(
        self,
        argv: list[str],
        *,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        user: str = "",
        target_ip: str = "",
        tool_name: str = "",
    ) -> SandboxResult:
        """Run an argv-list tool (nmap, impacket, msfvenom, ...) inside the sandbox."""
        inner = int(timeout or self.cfg.exec_timeout_seconds)
        grace = _db.EXEC_KILL_GRACE_SECONDS
        wrapped = ["timeout", "-k", str(grace), str(inner), *argv]
        return self._execute_argv(
            wrapped,
            timeout=inner + grace + 10,
            cwd=cwd,
            env=env,
            user=user or self.cfg.user,
            target_ip=target_ip,
            tool_name=tool_name,
            audit_command="",
        )

    def _execute_argv(
        self,
        argv: list[str],
        *,
        timeout: int,
        cwd: str | None,
        env: dict[str, str] | None,
        user: str,
        target_ip: str,
        tool_name: str,
        audit_command: str,
    ) -> SandboxResult:
        self._enforce_scope(target_ip)
        self._validate_workspace()
        container = self.ensure_sandbox()
        pol = self._apply_policy()
        extra_env = self._build_env(env)
        start = time.monotonic()
        self._audit(
            target_ip=target_ip,
            tool_name=tool_name,
            status="started",
            command=audit_command,
            extra_env=extra_env,
            policy_payload=_policy.audit_policy_payload(pol),
            exit_code=None,
            duration=None,
        )
        try:
            rc, out, err = self.backend.exec(
                container,
                argv,
                timeout=timeout,
                user=user,
                env=extra_env,
                workdir=cwd or "",
            )
        except TimeoutError:
            elapsed = time.monotonic() - start
            self._audit(
                target_ip=target_ip,
                tool_name=tool_name,
                status="timed_out",
                command=audit_command,
                extra_env=extra_env,
                policy_payload=_policy.audit_policy_payload(pol),
                exit_code=None,
                duration=elapsed,
            )
            return SandboxResult.timed_out_result(elapsed, container)
        duration = time.monotonic() - start
        result = SandboxResult(
            exit_code=int(rc),
            stdout=_clamp_output(out, self.cfg.output_max_bytes),
            stderr=_clamp_output(err, self.cfg.output_max_bytes),
            timed_out=False,
            duration_seconds=duration,
            sandbox_id=container,
            status="completed" if int(rc) == 0 else "failed",
        )
        self._audit(
            target_ip=target_ip,
            tool_name=tool_name,
            status=result.status,
            command=audit_command,
            extra_env=extra_env,
            policy_payload=_policy.audit_policy_payload(pol),
            exit_code=result.exit_code,
            duration=duration,
        )
        return result

    def container_path(self, host_path: Path) -> str:
        """Map a host path under the run workspace to its in-container path.

        Only paths inside the validated workspace are mapped; anything else
        raises (traversal / symlink-escape / arbitrary-host-path prevention).
        """
        resolved = Path(host_path).resolve()
        try:
            rel = resolved.relative_to(self.workspace.resolve())
        except ValueError:
            raise SandboxWorkspaceError(f"path {resolved} is outside the sandbox workspace {self.workspace}") from None
        if str(rel) == ".":
            return CONTAINER_WORKSPACE
        return f"{CONTAINER_WORKSPACE}/{rel.as_posix()}"

    # ------------------------------------------------------------ scope gate

    def _enforce_scope(self, target_ip: str) -> None:
        """Unauthorized-target fail-closed gate.

        The invariant, enforced independently at this layer (on top of the MCP
        allowlist decorators and the real netns firewall): an execution naming
        a target outside the effective allowlist is DENIED before any container
        work happens whenever ANY authorization material exists (config
        ``allowed_targets`` or any ``EXPLOIT_*`` env union). Only a fully
        empty union skips the check here (the netns policy then authorizes
        nothing, so even a target-less command has zero reachable
        destinations).

        An empty ``target_ip`` (no destinations could be associated with the
        execution) is denied when the union is non-empty: an execution that
        cannot name its target cannot prove it stays inside the allowlist
        (variable indirection), so it fail-closes here instead of relying on
        the firewall layer alone.
        """
        from tools.kernel.allowlist import _allowed_target_list, _check_allowlist

        if not _allowed_target_list(self.config_dict):
            return
        if not target_ip:
            raise SandboxScopeError(
                "sandbox scope gate: execution names no target (empty target_ip) "
                "while the allowlist is non-empty -- name the "
                "destination literally so it can be checked against the allowlist"
            )
        allowed, reason = _check_allowlist(target_ip, self.config_dict)
        if not allowed and self.cfg.allow_research_hosts and self._is_research_host(target_ip):
            # Pinned exploit-research egress (github/gitlab) is authorized by
            # the fixed RESEARCH_HOSTS set, not by the target allowlist.
            return
        if not allowed:
            raise SandboxScopeError(f"{reason} (sandbox scope gate)")

    @staticmethod
    def _is_research_host(token: str) -> bool:
        from tools.sandbox.policy import RESEARCH_HOSTS

        tok = str(token).strip().lower().rstrip(".")
        return any(tok == h or tok.endswith(f".{h}") for h in RESEARCH_HOSTS)

    def _build_env(self, extra: dict[str, str] | None) -> dict[str, str]:
        env = dict(_BASE_ENV)
        allowed = set(_RUN_ENV_ALLOWLIST) | set(self.cfg.env_passthrough)
        for key, value in (extra or {}).items():
            if key in allowed:
                env[str(key)] = str(value)
        return env

    # ------------------------------------------------------------ audit

    def _audit(
        self,
        *,
        target_ip: str,
        tool_name: str,
        status: str,
        command: str,
        extra_env: dict[str, str],
        policy_payload: dict[str, Any] | None,
        exit_code: int | None,
        duration: float | None,
    ) -> None:
        try:
            from tools.kernel.audit import _audit_log, _mask_secret_content

            extra: dict[str, Any] = {
                "sandbox": {
                    "enabled": self.cfg.enabled,
                    "backend": self.cfg.backend,
                    "run_id": self.run_id,
                    "container_id": self.container_id,
                    "image": self.cfg.image,
                    "user": self.cfg.user,
                    "env_keys": sorted(extra_env.keys()),
                    "network": policy_payload,
                    "exit_code": exit_code,
                    "timeout_seconds": self.cfg.exec_timeout_seconds,
                }
            }
            _audit_log(
                self.workspace / "exploit_audit.jsonl",
                target_ip=target_ip,
                tool_name=f"sandbox.{tool_name}" if tool_name else "sandbox.execute",
                approved=True,
                status=status,
                command=_mask_secret_content(command) if command else "",
                duration_seconds=duration or 0.0,
                extra=extra,
            )
        except Exception as exc:  # noqa: BLE001 -- audit is best-effort, never blocks the attack path
            logger.warning("sandbox audit row failed: %s", exc)

    def audit_cleanup(self, results: dict[str, bool]) -> None:
        self._audit(
            target_ip="",
            tool_name="cleanup",
            status="completed" if all(results.values()) else "failed",
            command="",
            extra_env={},
            policy_payload=None,
            exit_code=None,
            duration=None,
        )

    # -------------------------------------------------------- teardown

    def destroy(self) -> dict[str, bool]:
        """Terminate + remove the worker and its network. Idempotent; audited."""
        if self._destroyed:
            return {"container_removed": False, "network_removed": False}
        results = self._destroy_resources()
        self._destroyed = True
        self.audit_cleanup(results)
        return results

    def _destroy_resources(self) -> dict[str, bool]:
        results = {"container_removed": False, "network_removed": False}
        if self.container_id:
            try:
                self.backend.stop(self.container_id)
            except SandboxError:
                logger.warning("sandbox stop %s failed", self.container_id)
            results["container_removed"] = bool(
                self.backend.destroy(self.container_id, self.network_name)["container_removed"]
            )
        if self.network_name:
            results["network_removed"] = bool(_db.docker_network_rm(self.network_name))
        self.container_id = ""
        self.network_name = ""
        self._ensure_valid_until = 0.0
        self._policy_valid_until = 0.0
        return results

    def _atexit_destroy(self) -> None:
        try:
            self.destroy()
        except Exception:  # noqa: BLE001 -- interpreter shutdown best-effort
            pass

    def cleanup_stale(self) -> int:
        """Remove exited BreachPilot-labeled containers + empty labeled networks.

        Conservative by design: a RUNNING worker may belong to a concurrent
        session (``api.max_concurrent_runs`` > 1), so only containers that are
        NOT running -- and networks holding no running containers -- are removed.
        This manager's own container/network is always skipped.
        """
        removed = 0
        for name in _db.docker_container_list_stale():
            if name == self.container_id:
                continue
            if _db.docker_inspect_state(name) in ("exited", "created", "dead"):
                removed += 1 if _db.docker_rm(name) else 0
        for name in _db.docker_network_list_stale():
            if name == self.network_name:
                continue
            info = _db.docker_network_inspect(name)
            if not info:
                continue
            if not (info.get("Containers") or {}):
                removed += 1 if _db.docker_network_rm(name) else 0
        return removed

    def status(self) -> dict[str, Any]:
        state = self._container_state()
        return {
            "enabled": self.cfg.enabled,
            "backend": self.cfg.backend,
            "image": self.cfg.image,
            "user": self.cfg.user,
            "run_id": self.run_id,
            "container_id": self.container_id,
            "container_status": state,
            "network": self.network_name,
            "network_locked": bool(self._policy and self._policy.enforced),
            "network_policy_fingerprint": self._policy.fingerprint() if self._policy else "",
            "resources": {
                "memory_mb": self.cfg.memory_mb,
                "cpus": self.cfg.cpus,
                "pids": self.cfg.pids_limit,
                "timeout_seconds": self.cfg.exec_timeout_seconds,
            },
        }


def _clamp_output(text: str, max_bytes: int) -> str:
    """Keep the LAST ``max_bytes`` of one output stream (tails matter for
    debugging); never lets an agent command flood host-process memory."""
    if not text:
        return ""
    data = text.encode("utf-8", errors="replace")
    if len(data) <= max_bytes:
        return text
    return data[-max_bytes:].decode("utf-8", errors="replace") + "\n[output truncated to last N bytes]"


def status_report(config: dict[str, Any] | None) -> dict[str, Any]:
    """Static sandbox status for the WebUI API / doctor (no manager instance).

    Probing is seam-mediated and cheap; a status endpoint never throws --
    any probe failure surfaces as ``docker_error`` text, never an exception.
    ``image_present`` distinguishes "Docker up but worker image not built"
    (the common first-run gap) from "Docker unreachable"; it stays ``None``
    when the answer cannot be known (sandbox disabled / daemon down).

    ``mode`` is the effective execution posture the WebUI home screen
    banners. It comes from the recorded BOOT-TIME decision
    (``sandbox_boot_state.json``, written by ``resolve_manager_with_fallback``
    in the MCP server process) whenever one exists -- the session's posture
    was fixed at ITS boot and a live Docker probe that drifts afterwards
    (operator starts Docker mid-run, daemon dies mid-run) must not flip the
    banner. When no boot state exists yet (fresh install / no session since
    the feature landed) the live probe decides, same as before:
    - "disabled": sandbox.enabled false -- legacy host-execution mode.
    - "contained": Docker + worker image usable -- commands run contained.
    - "native_fallback": enabled but Docker/image unusable AND
      fallback_native=true -- the session degrades to uncontained host
      execution (one warning, never per-command).
    - "blocked": enabled, Docker/image unusable, fallback_native=false --
      every execution fail-closes.
    """
    cfg = SandboxConfig.from_config(config)
    report: dict[str, Any] = {
        "enabled": cfg.enabled,
        "backend": cfg.backend,
        "image": cfg.image,
        "user": cfg.user,
        "read_only_rootfs": cfg.read_only_rootfs,
        "fallback_native": cfg.fallback_native,
        "auto_manage_docker": cfg.auto_manage_docker,
        "mode": "disabled",
        "fallback_reason": "",
        "docker_available": False,
        "docker_error": "",
        "image_present": None,
        "network": {
            "enforce": cfg.network_enforce,
            "fail_closed": cfg.network_fail_closed,
            "allow_dns": cfg.allow_dns,
            "map_host_loopback": cfg.map_host_loopback,
            "extra_allow_cidrs": cfg.extra_allow_cidrs,
        },
        "resources": {
            "memory_mb": cfg.memory_mb,
            "cpus": cfg.cpus,
            "pids": cfg.pids_limit,
            "timeout_seconds": cfg.exec_timeout_seconds,
            "output_max_bytes": cfg.output_max_bytes,
        },
        "cleanup": {"remove_on_exit": cfg.remove_on_exit, "remove_stale_on_startup": cfg.remove_stale_on_startup},
    }
    if not cfg.enabled:
        report["note"] = "sandbox disabled -- documented legacy host-execution mode"
        return report
    boot = read_boot_state(config)
    if boot:
        report["mode"] = boot["mode"]
        report["fallback_reason"] = str(boot.get("reason") or "")
    # Live probes always fill the remediation fields (is Docker reachable
    # RIGHT NOW?) but only decide ``mode`` when no boot state exists.
    try:
        ok, reason = _db.docker_version()
        report["docker_available"] = ok
        if not ok:
            report["docker_error"] = reason
            if not boot:
                report["mode"] = "native_fallback" if cfg.fallback_native else "blocked"
                report["fallback_reason"] = reason
        else:
            image_ok = bool(_db.docker_image_exists(cfg.image))
            report["image_present"] = image_ok
            if not boot:
                if image_ok:
                    report["mode"] = "contained"
                else:
                    report["mode"] = "native_fallback" if cfg.fallback_native else "blocked"
                    report["fallback_reason"] = f"sandbox image '{cfg.image}' not built"
    except Exception as exc:  # noqa: BLE001 -- a status endpoint never throws
        report["docker_error"] = str(exc)
        if not boot:
            report["mode"] = "native_fallback" if cfg.fallback_native else "blocked"
            report["fallback_reason"] = str(exc)
    return report
