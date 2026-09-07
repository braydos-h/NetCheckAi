"""Tests for domain-target allowlist union and discovered-target expansion.

Covers ``_allowed_target_list`` (the union of config + env vars that IS the
target-IP lock) and ``add_discovered_target`` (the runtime helper that
auto-authorizes subdomains discovered mid-run). These are the Phase 3
allowlist changes that let the lock accept a domain + its resolved IP +
discovered subdomains as a set of operator-authorized hosts.
"""

from __future__ import annotations

import os

import pytest


# add_discovered_target writes os.environ["EXPLOIT_DISCOVERED_TARGETS"]
# directly (NOT via monkeypatch), and monkeypatch does not restore direct
# os.environ[k]=v writes -- they leak for the whole pytest session and break
# unrelated empty-allowlist tests later. This autouse fixture snapshots and
# restores the 4 target env vars around every test in this file.
@pytest.fixture(autouse=True)
def _restore_target_env():
    _snap = {
        k: os.environ.get(k)
        for k in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN", "EXPLOIT_DISCOVERED_TARGETS")
    }
    yield
    for _k, _v in _snap.items():
        if _v is None:
            os.environ.pop(_k, None)
        else:
            os.environ[_k] = _v


def _clear_env(monkeypatch):
    """Clear all domain env vars so tests start from a clean slate."""
    for k in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN", "EXPLOIT_DISCOVERED_TARGETS"):
        monkeypatch.delenv(k, raising=False)


def test_allowed_target_list_config_only(monkeypatch):
    _clear_env(monkeypatch)
    from tools.mcp_shared import _allowed_target_list

    config = {"exploit": {"allowed_targets": ["10.0.0.5", "127.0.0.1"]}}
    assert _allowed_target_list(config) == ["10.0.0.5", "127.0.0.1"]


def test_allowed_target_list_unions_exploit_target(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET", "10.0.0.50")
    from tools.mcp_shared import _allowed_target_list

    config = {"exploit": {"allowed_targets": ["127.0.0.1"]}}
    result = _allowed_target_list(config)
    assert "127.0.0.1" in result
    assert "10.0.0.50" in result


def test_allowed_target_list_unions_domain_env_vars(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET", "example.com")
    monkeypatch.setenv("EXPLOIT_TARGET_IP", "93.184.216.34")
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import _allowed_target_list

    config = {"exploit": {"allowed_targets": ["127.0.0.1"]}}
    result = _allowed_target_list(config)
    assert "example.com" in result
    assert "93.184.216.34" in result
    assert "127.0.0.1" in result


def test_allowed_target_list_unions_discovered_targets(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_DISCOVERED_TARGETS", "sub1.example.com,sub2.example.com,1.2.3.4")
    from tools.mcp_shared import _allowed_target_list

    config = {"exploit": {"allowed_targets": []}}
    result = _allowed_target_list(config)
    assert "sub1.example.com" in result
    assert "sub2.example.com" in result
    assert "1.2.3.4" in result


def test_allowed_target_list_deduplicates(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET", "example.com")
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import _allowed_target_list

    config = {"exploit": {"allowed_targets": ["example.com"]}}
    result = _allowed_target_list(config)
    # example.com should appear exactly once despite being in 3 sources
    assert result.count("example.com") == 1


def test_add_discovered_target_adds_host(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET", "example.com")
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import _allowed_target_list, add_discovered_target, get_discovered_host

    add_discovered_target("new.example.com", "5.6.7.8")
    result = _allowed_target_list({"exploit": {"allowed_targets": []}})
    assert "new.example.com" in result
    # Provenance, not global IP authorization: the resolved IP is tied to the
    # hostname in the provenance store, never a bare reusable allowlist entry.
    assert "5.6.7.8" not in result
    entry = get_discovered_host("new.example.com")
    assert entry is not None and "5.6.7.8" in entry.addresses


def test_add_discovered_target_deduplicates(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET", "example.com")
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    from tools.mcp_shared import _allowed_target_list, add_discovered_target

    add_discovered_target("sub.example.com", "1.2.3.4")
    add_discovered_target("sub.example.com", "1.2.3.4")  # duplicate
    result = _allowed_target_list({"exploit": {"allowed_targets": []}})
    assert result.count("sub.example.com") == 1
    assert "1.2.3.4" not in result


def test_add_discovered_target_appends_to_existing(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("EXPLOIT_TARGET", "example.com")
    monkeypatch.setenv("EXPLOIT_TARGET_DOMAIN", "example.com")
    monkeypatch.setenv("EXPLOIT_DISCOVERED_TARGETS", "existing.example.com")
    from tools.mcp_shared import _allowed_target_list, add_discovered_target, get_discovered_host

    add_discovered_target("new.example.com", "9.10.11.12")
    result = _allowed_target_list({"exploit": {"allowed_targets": []}})
    assert "existing.example.com" in result
    assert "new.example.com" in result
    assert "9.10.11.12" not in result
    entry = get_discovered_host("new.example.com")
    assert entry is not None and "9.10.11.12" in entry.addresses


def test_is_target_in_allowlist_matches_domain():
    from tools.validation_utils import is_target_in_allowlist

    assert is_target_in_allowlist("example.com", ["example.com"]) is True
    assert is_target_in_allowlist("sub.example.com", ["*.example.com"]) is True
    assert is_target_in_allowlist("other.com", ["*.example.com"]) is False
    assert is_target_in_allowlist("example.com", ["10.0.0.5"]) is False


def test_is_target_in_allowlist_matches_resolved_ip():
    from tools.validation_utils import is_target_in_allowlist

    assert is_target_in_allowlist("93.184.216.34", ["93.184.216.34"]) is True
    assert is_target_in_allowlist("93.184.216.34", ["example.com"]) is False


# --- EXPLOIT_ALLOWED_TARGETS operator/CI override (read-only env union) ---


def test_allowed_target_list_unions_allowed_targets_env(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.delenv("EXPLOIT_ALLOWED_TARGETS", raising=False)
    from tools.mcp_shared import _allowed_target_list

    config = {"exploit": {"allowed_targets": ["127.0.0.1"]}}
    assert _allowed_target_list(config) == ["127.0.0.1"]  # empty by default

    monkeypatch.setenv("EXPLOIT_ALLOWED_TARGETS", "10.0.0.99,10.0.0.100")
    result = _allowed_target_list(config)
    assert "10.0.0.99" in result
    assert "10.0.0.100" in result
    assert "127.0.0.1" in result


def test_allowed_target_list_env_override_deduplicates_and_strips(monkeypatch):
    _clear_env(monkeypatch)
    from tools.kernel.allowlist import _allowed_target_list as _kernel_list

    monkeypatch.setenv("EXPLOIT_ALLOWED_TARGETS", " 10.0.0.99 , 10.0.0.99,example.com,")
    result = _kernel_list({"exploit": {"allowed_targets": ["example.com"]}})
    assert result.count("10.0.0.99") == 1
    assert result.count("example.com") == 1
    assert "example.com" in result


def test_allowed_target_list_env_override_empty_tokens_ignored(monkeypatch):
    _clear_env(monkeypatch)
    from tools.kernel.allowlist import _allowed_target_list as _kernel_list

    monkeypatch.setenv("EXPLOIT_ALLOWED_TARGETS", ",,")
    assert _kernel_list({"exploit": {"allowed_targets": ["10.0.0.5"]}}) == ["10.0.0.5"]
