"""Unit tests for the Docker backend (tools/sandbox/docker_backend.py).

Security invariants covered by ``_build_create_args`` (the hardened create argv):
- ``--cap-drop ALL`` always; NET_RAW only when explicitly configured; NET_ADMIN
  NEVER granted to the worker.
- ``no-new-privileges``, non-root user, resource limits, ``--read-only``,
  tmpfs /tmp, exactly ONE bind (the validated workspace at /workspace).
- No docker.sock, no devices, no host pid/ipc namespaces, no host networking.
- Hostile strings (image/container id/env-key injection) are rejected.
"""

from __future__ import annotations

import pytest

from tools.sandbox import docker_backend as db
from tools.sandbox.docker_backend import DockerBackend, DockerCommandTimeout, _build_create_args, _validate_container_id
from tools.sandbox.exceptions import SandboxUnavailableError
from tools.sandbox.models import SandboxSpec


def _spec(**overrides) -> SandboxSpec:
    defaults = dict(
        sandbox_id="breachpilot-run123-deadbe",
        image="breachpilot-sandbox:latest",
        user="sandbox",
        network_name="breachpilot-net-run123-beef01",
        workspace_src="C:/tmp/exploit_workspace/run123",
        memory_mb=1024,
        cpus=1.0,
        pids_limit=256,
        read_only_rootfs=True,
        labels={"run_id": "run123"},
    )
    defaults.update(overrides)
    return SandboxSpec(**defaults)


class TestBuildCreateArgs:
    def test_caps_dropped_all_and_no_net_admin(self):
        args = _build_create_args(_spec(), cap_raw=True, read_only_rootfs=True)
        assert "--cap-drop" in args and "ALL" in args
        assert "NET_ADMIN" not in args
        assert args[args.index("--cap-add") + 1] == "NET_RAW"

    def test_no_net_raw_when_disabled(self):
        args = _build_create_args(_spec(), cap_raw=False, read_only_rootfs=True)
        assert "--cap-add" not in args

    def test_no_privileged_mode(self):
        args = _build_create_args(_spec(), cap_raw=True, read_only_rootfs=True)
        assert "--privileged" not in args

    def test_no_new_privileges(self):
        args = _build_create_args(_spec(), cap_raw=True, read_only_rootfs=True)
        assert args[args.index("--security-opt") + 1] == "no-new-privileges"

    def test_no_docker_socket_mount(self):
        args = " ".join(_build_create_args(_spec(), cap_raw=True, read_only_rootfs=True))
        assert "docker.sock" not in args
        assert "/var/run" not in args

    def test_exactly_one_bind_the_workspace(self):
        args = _build_create_args(_spec(), cap_raw=True, read_only_rootfs=True)
        binds = [a for a in args if a.endswith(":/workspace:rw")]
        assert len(binds) == 1
        assert binds[0].startswith(str(_spec().workspace_src))

    def test_no_devices_or_host_namespaces(self):
        args = _build_create_args(_spec(), cap_raw=True, read_only_rootfs=True)
        assert "--device" not in args
        assert "--pid" not in args
        assert "--ipc" not in args
        assert "--network" in args and "host" not in args[args.index("--network") + 1]

    def test_resource_limits_applied(self):
        args = _build_create_args(_spec(memory_mb=1024, cpus=1.0, pids_limit=256), cap_raw=True, read_only_rootfs=True)
        assert args[args.index("--memory") + 1] == "1024m"
        assert args[args.index("--memory-swap") + 1] == "1024m"
        assert args[args.index("--cpus") + 1] == "1.0"
        assert args[args.index("--pids-limit") + 1] == "256"

    def test_read_only_rootfs_and_tmpfs(self):
        args = _build_create_args(_spec(), cap_raw=True, read_only_rootfs=True)
        assert "--read-only" in args
        assert args[args.index("--tmpfs") + 1].startswith("/tmp:")

    def test_custom_tmpfs_size_flows_through(self):
        args = _build_create_args(_spec(tmpfs_size_mb=512), cap_raw=True, read_only_rootfs=True)
        assert args[args.index("--tmpfs") + 1] == "/tmp:rw,noexec,nosuid,size=512m"
        args_small = _build_create_args(_spec(tmpfs_size_mb=1), cap_raw=True, read_only_rootfs=True)
        assert args_small[args_small.index("--tmpfs") + 1] == "/tmp:rw,noexec,nosuid,size=64m"

    def test_writable_rootfs_when_configured(self):
        args = _build_create_args(_spec(), cap_raw=True, read_only_rootfs=False)
        assert "--read-only" not in args

    def test_non_root_user(self):
        args = _build_create_args(_spec(user="sandbox"), cap_raw=True, read_only_rootfs=True)
        assert args[args.index("--user") + 1] == "sandbox"

    def test_labels_mark_our_containers(self):
        args = _build_create_args(_spec(), cap_raw=True, read_only_rootfs=True)
        assert args[args.index("--label") + 1] == "breachpilot=true"
        assert any(a.startswith("run_id=") for a in args)

    def test_invalid_image_rejected(self):
        for bad in ("", "; rm -rf /", "-e EVIL", "img\nx"):
            with pytest.raises(SandboxUnavailableError):
                _build_create_args(_spec(image=bad), cap_raw=True, read_only_rootfs=True)

    def test_missing_workspace_rejected(self):
        with pytest.raises(SandboxUnavailableError, match="workspace"):
            _build_create_args(_spec(workspace_src=""), cap_raw=True, read_only_rootfs=True)


class TestValidation:
    def test_container_id_injection_rejected(self):
        for bad in ("", "abc;rm", "a|b", "`id`", "a b", "x\ny", "a$b"):
            with pytest.raises(SandboxUnavailableError):
                _validate_container_id(bad)

    def test_env_key_rejected(self):
        for bad in ("", "A=B", "A B", "A\nB", "-X"):
            with pytest.raises(SandboxUnavailableError):
                db._validate_env_key(bad)

    def test_exec_rejects_relative_workdir(self):
        backend = DockerBackend(exec_seam=lambda *a, **k: (0, "", ""))
        with pytest.raises(SandboxUnavailableError, match="workdir"):
            backend.exec("abc123", ["ls"], timeout=5, workdir="relative/path")
        with pytest.raises(SandboxUnavailableError, match="workdir"):
            backend.exec("abc123", ["ls"], timeout=5, workdir="/workspace/../escape")


class TestExecSeam:
    def test_docker_command_timeout_becomes_bare_timeout(self):
        """The manager distinguishes 'agent command too long' from sandbox breakage."""

        def timeout_seam(argv, timeout, input_text=""):
            raise DockerCommandTimeout("docker exec timed out")

        backend = DockerBackend(exec_seam=timeout_seam)
        with pytest.raises(TimeoutError):
            backend.exec("abc123", ["sleep", "999"], timeout=5)


class TestDockerVersion:
    def test_version_probe_reports_daemon_down(self, monkeypatch):
        monkeypatch.setattr(db, "_docker", lambda *a, **k: (_ for _ in ()).throw(SandboxUnavailableError("no cli")))
        ok, reason = db.docker_version()
        assert ok is False
        assert "no cli" in reason

    def test_version_probe_ok(self, monkeypatch):
        monkeypatch.setattr(db, "_docker", lambda *a, **k: (0, "27.0.3\n", ""))
        ok, version = db.docker_version()
        assert ok is True
        assert version == "27.0.3"


class TestDockerStdin:
    def test_input_text_sent_as_lf_bytes(self, monkeypatch):
        """Regression: text-mode pipes mangle "\n" to "\r\n" on Windows, which
        makes iptables-restore reject the ruleset (line 1 table name invalid)."""
        import subprocess

        seen: dict = {}

        class _Proc:
            returncode = 0
            stdout = b"out"
            stderr = b""

        def _fake_run(argv, **kwargs):
            seen.update(kwargs)
            return _Proc()

        monkeypatch.setattr(subprocess, "run", _fake_run)
        rc, out, _ = db._docker("run", "img", input_text="*filter\nCOMMIT\n")
        assert rc == 0
        assert out == "out"
        assert isinstance(seen["input"], bytes)
        assert seen["input"] == b"*filter\nCOMMIT\n"
        assert b"\r" not in seen["input"]
