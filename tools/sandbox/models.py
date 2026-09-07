"""Typed models for the disposable execution sandbox.

Pure data + defensive config parsing. No Docker/network imports here so the
whole configuration surface is unit-testable on any platform (including hosts
without Docker). ``SandboxConfig.from_config`` is the ONLY sanctioned way to
build sandbox configuration from a user config dict -- it reads defensively
(``sandbox`` section absent => disabled) so the ~250 existing mocked tests that
pass partial config dicts keep the documented legacy host-mode behavior.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "SandboxConfig",
    "SandboxResult",
    "SandboxSpec",
    "NetworkPolicy",
    "_as_dict",
    "_as_bool",
    "_as_int",
    "_as_float",
]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def _as_int(value: Any, default: int, minimum: int = 1) -> int:
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return default
    return ivalue if ivalue >= minimum else default


def _as_float(value: Any, default: float, minimum: float = 0.1) -> float:
    try:
        fvalue = float(value)
    except (TypeError, ValueError):
        return default
    return fvalue if fvalue >= minimum else default


@dataclass(frozen=True)
class SandboxConfig:
    """Validated sandbox configuration (subset of the ``sandbox`` config section)."""

    enabled: bool
    backend: str
    image: str
    user: str
    read_only_rootfs: bool
    # When the boot-time Docker probe fails (CLI/daemon/image missing), a
    # server with fallback_native=true (explicit opt-in only) degrades to the
    # documented legacy host-execution mode for the whole session instead of
    # failing every execution closed. The default is false: fail closed.
    fallback_native: bool = False
    auto_manage_docker: bool = False
    env_passthrough: list[str] = field(default_factory=list)
    memory_mb: int = 4096
    cpus: float = 2.0
    pids_limit: int = 512
    exec_timeout_seconds: int = 300
    output_max_bytes: int = 2_000_000
    tmpfs_size_mb: int = 256
    network_enforce: bool = True
    network_fail_closed: bool = True
    allow_dns: str = "controlled"  # "controlled" | "none"
    map_host_loopback: bool = False  # explicit dev mapping; never silent
    extra_allow_cidrs: list[str] = field(default_factory=list)
    allow_gateway: bool = False
    allow_research_hosts: bool = True  # pinned exploit-research egress (github/gitlab)
    remove_on_exit: bool = True
    remove_stale_on_startup: bool = True
    multi_net_raw: bool = True  # NET_RAW for raw packet scanning (nmap -sS)

    @classmethod
    def from_config(cls, config: dict[str, Any] | None) -> "SandboxConfig":
        """Parse the ``sandbox`` config section defensively.

        A missing ``sandbox`` section (or missing ``enabled`` key) means the
        sandbox is DISABLED -- this keeps partial config dicts (tests, legacy
        callers, ``tools/config_cli.load_config`` which merges no defaults) on
        the documented host-execution path instead of failing every run.
        Real runs get ``enabled: true`` via CONFIG_SCHEMA defaults +
        ``apply_defaults()``.
        """
        sec = _as_dict((config or {}).get("sandbox"))
        if not sec:
            return cls(enabled=False, backend="docker", image="", user="", read_only_rootfs=False)
        resources = _as_dict(sec.get("resources"))
        network = _as_dict(sec.get("network"))
        cleanup = _as_dict(sec.get("cleanup"))
        allow_dns = str(network.get("allow_dns", "controlled") or "controlled").strip().lower()
        if allow_dns not in ("controlled", "none"):
            allow_dns = "controlled"
        extra_cidrs = [
            str(c).strip() for c in (network.get("extra_allow_cidrs") or []) if isinstance(c, str) and str(c).strip()
        ]
        passthrough = [
            str(k).strip() for k in (sec.get("env_passthrough") or []) if isinstance(k, str) and str(k).strip()
        ]
        return cls(
            enabled=_as_bool(sec.get("enabled"), False),
            backend=str(sec.get("backend", "docker") or "docker").strip().lower(),
            image=str(sec.get("image", "breachpilot-sandbox:latest") or "").strip(),
            user=str(sec.get("user", "sandbox") or "sandbox").strip(),
            read_only_rootfs=_as_bool(sec.get("read_only_rootfs"), True),
            fallback_native=_as_bool(sec.get("fallback_native"), False),
            auto_manage_docker=_as_bool(sec.get("auto_manage_docker"), False),
            env_passthrough=passthrough,
            memory_mb=_as_int(resources.get("memory_mb"), 4096, minimum=256),
            cpus=_as_float(resources.get("cpus"), 2.0, minimum=0.1),
            pids_limit=_as_int(resources.get("pids"), 512, minimum=32),
            exec_timeout_seconds=_as_int(resources.get("timeout_seconds"), 300, minimum=5),
            output_max_bytes=_as_int(resources.get("output_max_bytes"), 2_000_000, minimum=1024),
            tmpfs_size_mb=_as_int(resources.get("tmpfs_size_mb"), 256, minimum=64),
            network_enforce=_as_bool(network.get("enforce"), True),
            network_fail_closed=_as_bool(network.get("fail_closed"), True),
            allow_dns=allow_dns,
            map_host_loopback=_as_bool(network.get("map_host_loopback"), False),
            extra_allow_cidrs=extra_cidrs,
            allow_gateway=_as_bool(network.get("allow_gateway"), False),
            allow_research_hosts=_as_bool(network.get("allow_research_hosts"), True),
            remove_on_exit=_as_bool(cleanup.get("remove_on_exit"), True),
            remove_stale_on_startup=_as_bool(cleanup.get("remove_stale_on_startup"), True),
            multi_net_raw=_as_bool(sec.get("multi_net_raw"), True),
        )


@dataclass(frozen=True)
class SandboxResult:
    """One execution inside the sandbox (host-side view)."""

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    sandbox_id: str = ""
    status: str = "completed"  # completed | failed | timed_out

    @classmethod
    def timed_out_result(
        cls, duration: float, sandbox_id: str = "", stdout: str = "", stderr: str = ""
    ) -> "SandboxResult":
        return cls(
            exit_code=None,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            duration_seconds=duration,
            sandbox_id=sandbox_id,
            status="timed_out",
        )


@dataclass(frozen=True)
class SandboxSpec:
    """Immutable description of the worker container to create."""

    sandbox_id: str  # container name, e.g. breachpilot-<run_id>-<rand>
    image: str
    user: str
    network_name: str
    workspace_src: str  # host path bound to /workspace
    memory_mb: int
    cpus: float
    pids_limit: int
    read_only_rootfs: bool
    tmpfs_size_mb: int = 256
    labels: dict[str, str] = field(default_factory=lambda: {"breachpilot": "true"})


@dataclass(frozen=True)
class NetworkPolicy:
    """Egress authorization for the worker network namespace.

    ``authorized`` is the concrete allow set (IPs / CIDRs) the worker may talk
    to. Everything else -- unknown internet hosts, host LAN devices, cloud
    metadata, the Docker bridge gateway, unrelated containers -- is denied by
    the default-DROP ruleset regardless of the command string.
    """

    authorized_destinations: list[str] = field(default_factory=list)
    explicitly_blocked: list[str] = field(default_factory=list)
    allow_dns: str = "controlled"
    dns_servers: list[str] = field(default_factory=list)
    resolved_domains: dict[str, str] = field(default_factory=dict)  # domain -> primary IP (audit)
    # domain -> ALL resolved addresses (A+AAAA) authorizing the firewall IPs.
    # The primary-IP map above is kept for backwards compat; this map is the
    # hostname-tied provenance (see tools.kernel.discovered).
    resolved_domain_addresses: dict[str, list[str]] = field(default_factory=dict)
    unresolved_targets: list[str] = field(default_factory=list)  # wildcards/etc (audit)
    enforced: bool = True
    # Whether the Docker bridge gateway (path to host-published services and
    # the Docker daemon) is authorized. Default False: the gateway is DROPped.
    allow_gateway: bool = False

    def fingerprint(self) -> str:
        """Stable fingerprint for change detection (re-apply rules only when set changes)."""
        import hashlib as _hashlib
        import json as _json

        payload = _json.dumps(
            {
                "authorized": sorted(self.authorized_destinations),
                "allow_dns": self.allow_dns,
                "dns_servers": sorted(self.dns_servers),
                "enforced": self.enforced,
            },
            sort_keys=True,
        )
        return _hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def deep_copy_default_sandbox_cfg() -> dict[str, Any]:
    """Deep-copyable empty default (section absent) used by tests."""
    return copy.deepcopy({})
