"""Regression tests for the ``run_python_file`` runtime egress guard (Fix 2).

The static ``_target_lock_block`` body scan only sees literal destinations —
a script that builds its second host at runtime (argv slicing, string
concat, base64 decode) used to sail through and pivot. The egress-guard
preamble (``tools/mcp_tools/egress_guard.py``) wraps ``socket.connect`` /
``create_connection`` in the child, so any construction method is denied at
connect time.

All mocked except the guard unit tests, which run a real ``sys.executable
-c`` child (no network leaves the box: the evil destination is
TEST-NET-1 and the guard denies before any packet; the allowlisted probe
fails with refused/timeout, proving it passed the guard).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.mcp_tools.egress_guard import (
    build_egress_preamble,
    egress_denied_in_output,
)


def _run_child(preamble: str, body: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", preamble + body],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ── guard unit: denied however the destination was built ─────────────────────


def test_guard_denies_concat_built_host() -> None:
    pre = build_egress_preamble(["10.0.0.5"])
    proc = _run_child(pre, "import socket; h = '10.0.0.' + '99'; socket.create_connection((h, 4444), timeout=2)")
    assert proc.returncode != 0
    assert egress_denied_in_output((proc.stdout or "") + (proc.stderr or "")) == "10.0.0.99"


def test_guard_denies_decode_built_host() -> None:
    import base64

    evil = base64.b64encode(b"10.0.0.99").decode()
    pre = build_egress_preamble(["10.0.0.5"])
    body = (
        "import base64, socket; h = base64.b64decode(%r).decode(); "
        "socket.create_connection((h, 4444), timeout=2)" % (evil,)
    )
    proc = _run_child(pre, body)
    assert proc.returncode != 0
    assert egress_denied_in_output((proc.stdout or "") + (proc.stderr or "")) == "10.0.0.99"


def test_guard_denies_argv_built_host() -> None:
    pre = build_egress_preamble(["10.0.0.5"])
    body = (
        "import socket, sys; sys.argv = ['x.py', '10.0.0.5', '--target', '10.0.0.5']; "
        "h = sys.argv[1].rsplit('.', 1)[0] + '.99'; socket.create_connection((h, 4444), timeout=2)"
    )
    proc = _run_child(pre, body)
    assert proc.returncode != 0
    assert egress_denied_in_output((proc.stdout or "") + (proc.stderr or "")) == "10.0.0.99"


def test_guard_allows_allowlisted_host() -> None:
    """An allowlisted destination passes the guard (connection itself may
    refuse/time out — that proves the guard let it through)."""
    pre = build_egress_preamble(["10.0.0.5"])
    body = (
        "import socket; s = socket.socket(); s.settimeout(2);\n"
        "try:\n s.connect(('10.0.0.5', 9))\n"
        "except OSError as e:\n print('PAST-GUARD:', e)"
    )
    proc = _run_child(pre, body)
    assert egress_denied_in_output((proc.stdout or "") + (proc.stderr or "")) is None
    assert "PAST-GUARD:" in (proc.stdout or "")


def test_guard_empty_allowlist_permits_all() -> None:
    """Empty union = nothing configured = nothing to enforce (gate parity)."""
    pre = build_egress_preamble([])
    body = (
        "import socket; s = socket.socket(); s.settimeout(2);\n"
        "try:\n s.connect(('10.0.0.99', 9))\n"
        "except OSError as e:\n print('PAST-GUARD:', e)"
    )
    proc = _run_child(pre, body)
    assert egress_denied_in_output((proc.stdout or "") + (proc.stderr or "")) is None
    assert "PAST-GUARD:" in (proc.stdout or "")


def test_guard_cidr_and_wildcard() -> None:
    pre = build_egress_preamble(["10.0.0.0/24", "*.example.com"])
    ok_body = (
        "import socket; s = socket.socket(); s.settimeout(2);\n"
        "try:\n s.connect(('10.0.0.9', 9))\n"
        "except OSError as e:\n print('PAST-GUARD:', e)"
    )
    proc = _run_child(pre, ok_body)
    assert "PAST-GUARD:" in (proc.stdout or "")
    evil = _run_child(pre, "import socket; socket.create_connection(('10.0.1.9', 4444), timeout=2)")
    assert egress_denied_in_output((evil.stdout or "") + (evil.stderr or "")) == "10.0.1.9"


# ── end-to-end: run_python_file denies the argv-built second host ─────────────


def _make_server(tmp_path: Path):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config: dict[str, Any] = {
        "exploit": {
            "require_explicit_allowlist": True,
            "allowed_targets": ["10.0.0.5"],
        }
    }
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        config,
    )


def _text(result) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts = []
    for c in content:
        t = getattr(c, "text", None)
        if t is None and isinstance(c, dict):
            t = c.get("text")
        if t is None:
            t = str(c)
        parts.append(t)
    return "".join(parts)


@pytest.mark.asyncio
async def test_run_python_file_denies_argv_built_second_host(tmp_path: Path) -> None:
    """Script with an allowlisted target_ip but an argv-built second host must
    be denied: no literal evil destination exists for the static scan, so the
    runtime guard is the layer that fires. Runs the real host-path child
    (TEST-NET-1 evil host; the guard denies before any packet)."""
    mcp = _make_server(tmp_path)
    code = (
        "import socket, sys\n"
        "target = sys.argv[1]\n"
        "print('primary:', target)\n"
        "second = target.rsplit('.', 1)[0] + '.99'\n"
        "socket.create_connection((second, 4444), timeout=5)\n"
        "print('SECOND CONNECTED (must not happen)')\n"
    )
    written = _text(await mcp.call_tool("write_python_file", {"filename": "dynpivot.py", "code": code}))
    assert "PYTHON_FILE_WRITTEN" in written
    text = _text(await mcp.call_tool("run_python_file", {"target_ip": "10.0.0.5", "filename": "dynpivot.py"}))
    assert text.startswith("BLOCKED:")
    assert "10.0.0.99" in text
    assert "run_python_file" in text
    assert "SECOND CONNECTED" not in text


@pytest.mark.asyncio
async def test_run_python_file_still_runs_clean_script(tmp_path: Path) -> None:
    """A script that only touches the allowlisted target still runs: the
    guard must not break the legitimate argv[1] contract."""
    mcp = _make_server(tmp_path)
    code = "import sys\nprint('target is', sys.argv[1])\n"
    written = _text(await mcp.call_tool("write_python_file", {"filename": "clean.py", "code": code}))
    assert "PYTHON_FILE_WRITTEN" in written
    text = _text(await mcp.call_tool("run_python_file", {"target_ip": "10.0.0.5", "filename": "clean.py"}))
    assert "PYTHON_RUN_RESULT" in text
    assert "target is 10.0.0.5" in text
