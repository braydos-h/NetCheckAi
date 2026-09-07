"""Tests for opt-in Docker daemon ownership around sandbox sessions."""

from __future__ import annotations

from typing import Any

from tools.sandbox import docker_backend as _db
from tools.sandbox.docker_lifecycle import DockerLifecycle


def _cfg(**values: Any) -> dict[str, Any]:
    return {"sandbox": {"enabled": True, **values}}


def test_existing_daemon_is_not_owned_or_stopped(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(_db, "docker_running_containers", lambda: [])
    lifecycle = DockerLifecycle.from_config(
        _cfg(auto_manage_docker=True),
        probe=lambda: (True, "27.0.0"),
        runner=lambda argv, timeout: calls.append(argv) or (0, "", ""),
    )

    assert lifecycle.acquire() == (True, "")
    assert lifecycle.release()["stopped"] is False
    assert calls == []


def test_started_daemon_is_stopped_when_idle(monkeypatch) -> None:
    calls: list[list[str]] = []
    probes = iter([(False, "daemon down"), (True, "27.0.0")])
    monkeypatch.setattr(_db, "docker_running_containers", lambda: [])
    lifecycle = DockerLifecycle.from_config(
        _cfg(auto_manage_docker=True),
        probe=lambda: next(probes),
        runner=lambda argv, timeout: calls.append(argv) or (0, "", ""),
        sleeper=lambda _seconds: None,
    )
    lifecycle.platform_name = "linux"
    lifecycle.service_method = "systemctl"

    assert lifecycle.acquire() == (True, "")
    result = lifecycle.release()
    assert result["stopped"] is True
    assert calls == [["sudo", "-n", "systemctl", "start", "docker"], ["sudo", "-n", "systemctl", "stop", "docker"]]


def test_started_daemon_is_left_running_when_other_container_exists(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(_db, "docker_running_containers", lambda: ["other-container"])
    lifecycle = DockerLifecycle(
        enabled=True,
        probe=lambda: (False, "daemon down"),
        runner=lambda argv, timeout: calls.append(argv) or (0, "", ""),
    )
    lifecycle.started_by_us = True
    lifecycle.platform_name = "linux"
    lifecycle.service_method = "systemctl"

    result = lifecycle.release()
    assert result["stopped"] is False
    assert result["reason"] == "running containers remain"
    assert calls == []


def test_disabled_lifecycle_does_not_start(monkeypatch) -> None:
    calls: list[list[str]] = []
    lifecycle = DockerLifecycle.from_config(
        _cfg(auto_manage_docker=False),
        probe=lambda: (False, "daemon down"),
        runner=lambda argv, timeout: calls.append(argv) or (0, "", ""),
    )

    assert lifecycle.acquire() == (False, "daemon down")
    assert lifecycle.release()["stopped"] is False
    assert calls == []
