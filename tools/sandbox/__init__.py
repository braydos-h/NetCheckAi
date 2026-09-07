"""Disposable execution sandbox: hardened worker containers for attack tools.

Architecture (see docs/safety-model.md + docs/sandbox.md):

    LLM/MCP tool ->application policy/allowlist checks -> disposable sandbox
    worker -> target

The sandbox is the security boundary; the legacy application-layer controls
(ScopeGate, ``@require_allowlist``, destination parsing) remain active as
defense-in-depth. The worker is a disposable Docker container per attack
session: cap-dropped (NET_RAW at most, never NET_ADMIN), non-root,
no-new-privileges, bounded resources, read-only rootfs, the run workspace bound
at ``/workspace`` only, and a default-DROP netns firewall installed by an
ephemeral NET_ADMIN sidecar that authorizes ONLY the target allowlist. Any
sandbox failure DURING a session FAILS CLOSED: ``SandboxError`` subclasses
surface as ``SANDBOX_*`` result blocks and host execution is never a
per-command fallback. The single sanctioned fallback is the boot-time
decision in ``resolve_manager_with_fallback``: with ``sandbox.fallback_native``
true (default) a server whose Docker stack is unusable degrades wholly to the
documented legacy host-execution mode with a warning (surfaced by the WebUI
home screen); ``fallback_native: false`` fails closed instead.

Docker access is seam-mediated (house convention from ``tools/snapshots.py``):
tests monkeypatch the named wrappers in ``tools.sandbox.docker_backend``,
never ``subprocess``.
"""

from tools.sandbox.docker_lifecycle import DockerLifecycle
from tools.sandbox.exceptions import (
    SANDBOX_POLICY_FAILED,
    SANDBOX_SCOPE_DENIED,
    SANDBOX_UNAVAILABLE,
    SANDBOX_UNSUPPORTED,
    SANDBOX_WORKSPACE_FAILED,
    SandboxError,
    SandboxPolicyError,
    SandboxScopeError,
    SandboxUnavailableError,
    SandboxUnsupportedError,
    SandboxWorkspaceError,
)
from tools.sandbox.manager import (
    BOOT_STATE_FILE,
    SandboxManager,
    boot_state_path,
    native_fallback_notice,
    read_boot_state,
    resolve_manager,
    resolve_manager_with_fallback,
    status_report,
)
from tools.sandbox.mcp_bridge import is_sandbox_active, manager_from_ctx, sandbox_block
from tools.sandbox.models import NetworkPolicy, SandboxConfig, SandboxResult, SandboxSpec

__all__ = [
    "SandboxManager",
    "DockerLifecycle",
    "resolve_manager",
    "resolve_manager_with_fallback",
    "native_fallback_notice",
    "status_report",
    "BOOT_STATE_FILE",
    "boot_state_path",
    "read_boot_state",
    "SandboxConfig",
    "SandboxResult",
    "SandboxSpec",
    "NetworkPolicy",
    "SandboxError",
    "SandboxPolicyError",
    "SandboxScopeError",
    "SandboxUnavailableError",
    "SandboxUnsupportedError",
    "SandboxWorkspaceError",
    "SANDBOX_UNAVAILABLE",
    "SANDBOX_POLICY_FAILED",
    "SANDBOX_SCOPE_DENIED",
    "SANDBOX_UNSUPPORTED",
    "SANDBOX_WORKSPACE_FAILED",
    "sandbox_block",
    "manager_from_ctx",
    "is_sandbox_active",
]
