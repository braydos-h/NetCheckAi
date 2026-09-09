#!/usr/bin/env python3
"""PreToolUse hook: block pytest invocations that crash the operator's PC.

Reads hook JSON from stdin, inspects Bash commands, and blocks:
  - bare `pytest tests/` (full-suite runs log the operator out)
  - `-n auto` / `-n 4+` / PYTEST_XDIST_AUTO_NUM_WORKERS > 2
  - `-m` overrides on multi-file runs (integration/live_llm spawn Docker/Chromium)
  - runs spanning more than ~30 test files

Single-file runs with `-n 0`/`-n 2` always pass. A single integration file
run explicitly with `-m integration` is allowed.

Protocol: stdout JSON {"decision": "block", "reason": ...} + exit 0 blocks
the call; silent exit 0 allows it. Never fail open loudly — any internal
error exits 0 silently so normal tool use is unaffected.
"""

import json
import os
import re
import shlex
import sys

MAX_FILES = 30
MAX_WORKERS = 2

_BARE_SUITE_RE = re.compile(r"\bpytest\b[^|;&]*\btests/\s*(?=$|[|;&]|\s-[a-zA-Z])")
_NFLAG_RE = re.compile(r"(?:^|\s)-n(?:\s+|=)(\S+)")
_MFLAG_RE = re.compile(r"(?:^|\s)-m(?:\s+|=)(\S+)")


def _pytest_segments(command):
    """Split a shell command into segments that invoke pytest."""
    segments = []
    for chunk in re.split(r"[|;&]+", command):
        if re.match(r"^\s*(?:[\w./-]*bin/)?python\d?\s+-m\s+pytest\b", chunk) or re.match(
            r"^\s*pytest\b", chunk
        ):
            segments.append(chunk)
    return segments


def _test_file_count(segment, cwd):
    """Count test files a pytest segment would collect (best effort)."""
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return 0
    paths = [
        t
        for t in tokens
        if t.startswith("tests/") and not t.startswith("-") and "=" not in t.split("/")[-1][:1]
    ]
    paths = [t.split("::")[0] for t in paths]
    if not paths or any(p in ("tests", "tests/") for p in paths):
        return 10**9  # bare suite dir = everything
    count = 0
    for p in paths:
        full = os.path.join(cwd, p) if not os.path.isabs(p) else p
        if os.path.isdir(full):
            for _root, _dirs, files in os.walk(full):
                count += sum(1 for f in files if f.startswith("test_") and f.endswith(".py"))
        elif os.path.isfile(full):
            count += 1
        else:
            count += 1  # glob or unknown — count conservatively
    return count


def check(command, cwd):
    segments = _pytest_segments(command)
    if not segments:
        return None
    for seg in segments:
        if _BARE_SUITE_RE.search(seg + " "):
            return (
                "Blocked: bare `pytest tests/` runs the full suite and crashes this machine "
                "(desktop session logout). Run one file at a time, e.g. "
                "`pytest tests/test_scope_gate.py -q -p no:cacheprovider -n 0`. "
                "Full-suite verification is CI's job."
            )
        m = _NFLAG_RE.search(seg)
        if m:
            val = m.group(1)
            if val == "auto" or (val.isdigit() and int(val) > MAX_WORKERS):
                return (
                    f"Blocked: `-n {val}` oversubscribes this machine. "
                    "Use `-n 0` (serial) or `-n 2` max."
                )
        workers = os.environ.get("PYTEST_XDIST_AUTO_NUM_WORKERS", "")
        if workers.isdigit() and int(workers) > MAX_WORKERS:
            return (
                f"Blocked: PYTEST_XDIST_AUTO_NUM_WORKERS={workers} exceeds the max of 2. "
                "Unset it or set it to 2."
            )
        mflag = _MFLAG_RE.search(seg)
        try:
            file_args = [
                t.split("::")[0]
                for t in shlex.split(seg, posix=True)
                if re.match(r"tests/test_[A-Za-z0-9_]+\.py$", t.split("::")[0])
            ]
        except ValueError:
            file_args = []
        single_file = len(file_args) == 1
        if mflag and not single_file:
            return (
                f"Blocked: `-m {mflag.group(1)}` override on a multi-file run. "
                "The repo default deselects integration/live_llm on purpose "
                "(they spawn real Docker/Chromium). Only a single file may use "
                "`-m integration` explicitly."
            )
        if _test_file_count(seg, cwd) > MAX_FILES:
            return (
                f"Blocked: run spans more than ~{MAX_FILES} test files in one command. "
                "Split into slices of one file (or ≤30 files) at a time."
            )
    return None


def main():
    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    try:
        if payload.get("tool_name") != "Bash":
            return 0
        command = (payload.get("tool_input") or {}).get("command", "")
        cwd = payload.get("cwd") or os.getcwd()
        reason = check(command, cwd)
        if reason:
            json.dump({"decision": "block", "reason": reason}, sys.stdout)
    except Exception:  # ponytail: fail-open guard — a hook bug must never break tool use
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
