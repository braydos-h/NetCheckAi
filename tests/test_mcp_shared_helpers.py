"""Regression tests for shared helpers in ``tools.mcp_shared``.

Covers:
- ``_run_with_pgrp_timeout`` (Shared #1): subprocess with process-group kill
  on timeout. Mocks ``subprocess.Popen`` so no real process runs.
- ``_check_allowlist`` CIDR / wildcard routing through
  ``validation_utils.is_target_in_allowlist`` (Shared #2 / M1).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from tools.mcp_shared import _check_allowlist, _run_with_pgrp_timeout

# ── _check_allowlist: CIDR / wildcard via is_target_in_allowlist (M1) ─────────


def test_check_allowlist_permissive_only_when_union_empty():
    # Empty union + flag off: nothing to enforce against (unchanged legacy).
    allowed, reason = _check_allowlist("10.0.0.50", {"exploit": {"require_explicit_allowlist": False}})
    assert allowed is True
    assert "no allowlist configured" in reason


def test_check_allowlist_flag_false_still_enforces_env_union(monkeypatch):
    """Flag-false + EXPLOIT_ALLOWED_TARGETS must NOT yield unrestricted targeting.

    Regression: the flag used to short-circuit every check while the env
    silently widened the lock — any host passed. Now the union enforces.
    """
    from tools.kernel.allowlist import allowlist_env_audit_extra

    for key in (
        "EXPLOIT_TARGET",
        "EXPLOIT_TARGET_IP",
        "EXPLOIT_TARGET_DOMAIN",
        "EXPLOIT_DISCOVERED_TARGETS",
        "EXPLOIT_ALLOWED_TARGETS",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("EXPLOIT_ALLOWED_TARGETS", "10.0.0.50")
    cfg = {"exploit": {"require_explicit_allowlist": False, "allowed_targets": []}}
    allowed, reason = _check_allowlist("10.0.0.99", cfg)
    assert allowed is False
    assert "10.0.0.99" in reason
    # the widening is named, never silent
    assert "10.0.0.50" in reason
    allowed, _ = _check_allowlist("10.0.0.50", cfg)
    assert allowed is True
    # ... and it is an explicit audit-tree event
    assert allowlist_env_audit_extra(cfg) == {"allowlist_env_union": ["10.0.0.50"]}


def test_check_allowlist_blocks_empty_allowlist():
    allowed, reason = _check_allowlist(
        "10.0.0.50",
        {"exploit": {"require_explicit_allowlist": True, "allowed_targets": []}},
    )
    assert allowed is False
    assert "empty" in reason


def test_check_allowlist_allows_cidr_member():
    # M1: a CIDR range in allowed_targets admits any member IP.
    allowed, _ = _check_allowlist(
        "10.0.0.5",
        {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.0/24"]}},
    )
    assert allowed is True


def test_check_allowlist_blocks_non_member_of_cidr():
    allowed, _ = _check_allowlist(
        "10.0.1.5",
        {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.0/24"]}},
    )
    assert allowed is False


def test_check_allowlist_allows_exact_ip():
    allowed, _ = _check_allowlist(
        "10.0.0.50",
        {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.50"]}},
    )
    assert allowed is True


# ── _run_with_pgrp_timeout (Shared #1) ───────────────────────────────────────


class _FakeProc:
    """Minimal Popen stand-in capturing communicate / kill / wait calls."""

    def __init__(self, returncode=0, out=b"", err=b"", raise_on_communicate=None):
        self.returncode = returncode
        self._out = out
        self._err = err
        self._raise = raise_on_communicate
        self.pid = 12345
        self.killed = False
        self.waited = False
        self.communicate_calls: list = []

    def communicate(self, input=None, timeout=None):
        self.communicate_calls.append((input, timeout))
        if self._raise is not None:
            raise self._raise
        return self._out, self._err

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waited = True
        return self.returncode


def _patch_popen(monkeypatch, proc: _FakeProc):
    captured: dict = {}

    def fake_popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return proc

    # _run_with_pgrp_timeout does a local ``import subprocess`` which resolves to
    # the same module object as the global ``subprocess`` module, so patching the
    # global module's Popen is sufficient.
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return captured


def test_run_with_pgrp_timeout_normal_completion_bytes(monkeypatch):
    proc = _FakeProc(returncode=0, out=b"hello", err=b"")
    cap = _patch_popen(monkeypatch, proc)
    rc, out, err = _run_with_pgrp_timeout(["echo", "hi"], 10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert rc == 0
    assert out == b"hello"
    assert err == b""
    # start_new_session is True on POSIX, False on Windows -- the helper passes
    # the conditional so no platform ever sets start_new_session incorrectly.
    assert cap["kwargs"]["start_new_session"] == (__import__("os").name != "nt")


def test_run_with_pgrp_timeout_text_mode_decodes(monkeypatch):
    proc = _FakeProc(returncode=0, out=b"hello", err=b"oops")
    _patch_popen(monkeypatch, proc)
    rc, out, err = _run_with_pgrp_timeout(
        ["echo", "hi"],
        10,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert rc == 0
    assert out == "hello"
    assert err == "oops"


def test_run_with_pgrp_timeout_input_text_encoded(monkeypatch):
    proc = _FakeProc(returncode=0, out=b"", err=b"")
    cap_proc = _patch_popen(monkeypatch, proc)
    _run_with_pgrp_timeout(
        ["grep", "x"],
        10,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        input_text="needle\n",
    )
    # communicate received bytes
    assert proc.communicate_calls[0][0] == b"needle\n"


def test_run_with_pgrp_timeout_reraises_timeout_expired(monkeypatch):
    proc = _FakeProc(raise_on_communicate=subprocess.TimeoutExpired(cmd=["x"], timeout=10))
    _patch_popen(monkeypatch, proc)
    with pytest.raises(subprocess.TimeoutExpired):
        _run_with_pgrp_timeout(["sleep", "100"], 10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # On timeout the proc must be reaped via wait().
    assert proc.waited is True


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only process-group kill path")
def test_run_with_pgrp_timeout_kills_pgrp_on_posix(monkeypatch):
    proc = _FakeProc(raise_on_communicate=subprocess.TimeoutExpired(cmd=["x"], timeout=10))
    _patch_popen(monkeypatch, proc)
    killed_pgrp: dict = {}

    import tools.mcp_shared as _ms

    def fake_killpg(pgid, sig):
        killed_pgrp["pgid"] = pgid
        killed_pgrp["sig"] = sig

    def fake_getpgid(pid):
        return 999

    monkeypatch.setattr(_ms.os, "killpg", fake_killpg)
    monkeypatch.setattr(_ms.os, "getpgid", fake_getpgid)
    with pytest.raises(subprocess.TimeoutExpired):
        _run_with_pgrp_timeout(["sleep", "100"], 10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert killed_pgrp["pgid"] == 999
    assert killed_pgrp["sig"] == _ms.signal.SIGKILL
    # proc.kill() fallback NOT used because killpg succeeded
    assert proc.killed is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only fallback path")
def test_run_with_pgrp_timeout_kills_proc_on_windows(monkeypatch):
    proc = _FakeProc(raise_on_communicate=subprocess.TimeoutExpired(cmd=["x"], timeout=10))
    _patch_popen(monkeypatch, proc)
    with pytest.raises(subprocess.TimeoutExpired):
        _run_with_pgrp_timeout(["sleep", "100"], 10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.killed is True
    assert proc.waited is True


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only process-group kill path")
def test_run_with_pgrp_timeout_falls_back_to_kill_on_permission_error(monkeypatch):
    """If killpg raises PermissionError, the helper falls back to proc.kill()."""
    proc = _FakeProc(raise_on_communicate=subprocess.TimeoutExpired(cmd=["x"], timeout=10))
    _patch_popen(monkeypatch, proc)

    import tools.mcp_shared as _ms

    def boom(pgid, sig):
        raise PermissionError("not allowed")

    monkeypatch.setattr(_ms.os, "killpg", boom)
    monkeypatch.setattr(_ms.os, "getpgid", lambda pid: 999)
    with pytest.raises(subprocess.TimeoutExpired):
        _run_with_pgrp_timeout(["sleep", "100"], 10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.killed is True
    assert proc.waited is True
