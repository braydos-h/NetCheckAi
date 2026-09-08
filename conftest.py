"""Pytest conftest: shared fixtures and test-isolation guards.

Two concerns live here:

1. pytest 9.0.3 ``PosixPath`` INTERNALERROR workaround on Windows (a monkeypatch
   of ``_pytest.nodes.Node._repr_failure_py`` that falls back to a plain
   traceback when the stock repr raises ``NotImplementedError``).

2. An autouse fixture that snapshots + restores the four ``EXPLOIT_*`` env vars
   that production code mutates via raw ``os.environ[...] = ...`` (not via
   monkeypatch). ``tools/mcp_shared.add_discovered_target`` writes
   ``EXPLOIT_DISCOVERED_TARGETS`` directly, and ``tools/mcp_session`` sets
   ``EXPLOIT_TARGET`` / ``EXPLOIT_TARGET_IP`` / ``EXPLOIT_TARGET_DOMAIN`` on the
   server subprocess env. Tests that exercise these paths leak the values into
   later tests because ``monkeypatch.delenv(k, raising=False)`` on an already-
   unset key records nothing, so a subsequent raw write is not reverted on
   teardown. The leaking values pollute the allowlist union
   (``_allowed_target_list``) and break the empty-allowlist / invalid-target /
   ollama-unreachable tests non-deterministically. Snapshot+restore around every
   test is the standard fix for process-global env written outside monkeypatch.
"""

import os
import traceback

import pytest

# Tests in this repository are intended to be hermetic.  In particular, a
# test process must not inherit the desktop's GPU/display stack just because
# pytest was started from a Wayland terminal.  A native graphics or BLAS
# library can otherwise create GPU contexts or a large number of worker
# threads before a test has had a chance to mock it.  Keep an escape hatch for
# the small number of explicitly hardware-backed tests.
_TEST_HARDWARE_OPT_IN = "BREACHPILOT_TEST_ALLOW_HARDWARE"
_SAFE_TEST_ENV = {
    "CUDA_VISIBLE_DEVICES": "",
    "ROCR_VISIBLE_DEVICES": "",
    "HIP_VISIBLE_DEVICES": "",
    "NVIDIA_VISIBLE_DEVICES": "void",
    "LIBGL_ALWAYS_SOFTWARE": "1",
    "QT_QPA_PLATFORM": "offscreen",
    "MPLBACKEND": "Agg",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "BLIS_NUM_THREADS": "1",
}


def pytest_configure(config: pytest.Config) -> None:
    """Make ordinary pytest runs independent of the logged-in desktop.

    This hook runs before test modules are collected, so optional numerical,
    plotting, or Qt dependencies see the safe environment during import.
    Hardware-backed tests can opt in explicitly with
    ``BREACHPILOT_TEST_ALLOW_HARDWARE=1``.
    """
    if os.environ.get(_TEST_HARDWARE_OPT_IN) == "1":
        return
    os.environ.update(_SAFE_TEST_ENV)


try:
    import _pytest.nodes as _n

    _orig = _n.Node._repr_failure_py

    def _safe(self, excinfo, *a, **k):
        try:
            return _orig(self, excinfo, *a, **k)
        except NotImplementedError:
            return "".join(traceback.format_exception(excinfo.type, excinfo.value, excinfo.tb))

    _n.Node._repr_failure_py = _safe
except Exception:
    pass


# Env vars that production code writes via raw os.environ (not monkeypatch) and
# that feed the allowlist union in tools.mcp_shared._allowed_target_list. Tests
# that trigger add_discovered_target / run_autonomous_campaign leak these into
# later tests; snapshot+restore keeps each test hermetic.
_EXPLOIT_ENV_VARS = (
    "EXPLOIT_TARGET",
    "EXPLOIT_TARGET_IP",
    "EXPLOIT_TARGET_DOMAIN",
    "EXPLOIT_DISCOVERED_TARGETS",
)


@pytest.fixture(autouse=True)
def _isolate_exploit_target_env():
    """Snapshot + restore the EXPLOIT_* env vars around every test.

    Restores both the value AND the presence/absence of each key, so a test that
    writes ``os.environ["EXPLOIT_DISCOVERED_TARGETS"] = "..."`` directly cannot
    leak it into a later test (which broke the empty-allowlist tests, the
    invalid-target rejection tests, and the ollama-unreachable fallback test).

    Also clears the ``resolve_target_to_ip`` DNS cache: tests patch
    ``socket.getaddrinfo`` with different fake records per test, and a cached
    entry from an earlier test would shadow the mock.
    """
    try:
        from tools.validation_utils import _RESOLVE_CACHE

        _RESOLVE_CACHE.clear()
    except Exception:
        pass
    try:
        from tools.mcp_tools.recon import _FINGERPRINT_CACHE

        _FINGERPRINT_CACHE.clear()
    except Exception:
        pass
    snapshot = {k: os.environ.get(k) for k in _EXPLOIT_ENV_VARS}
    yield
    for k in _EXPLOIT_ENV_VARS:
        original = snapshot[k]
        if original is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = original
    try:
        from tools.validation_utils import _RESOLVE_CACHE

        _RESOLVE_CACHE.clear()
    except Exception:
        pass
    try:
        from tools.mcp_tools.recon import _FINGERPRINT_CACHE

        _FINGERPRINT_CACHE.clear()
    except Exception:
        pass
