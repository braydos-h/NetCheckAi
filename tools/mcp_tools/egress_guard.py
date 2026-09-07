"""Runtime egress guard for ``run_python_file`` children.

The static ``_target_lock_block`` scan of the script body only sees literal
destinations — a host built at runtime (``sys.argv`` slicing, string concat,
``base64``/hex decode, ``os.environ``) sails through and pivots. This module
builds a small stdlib-only preamble that the tool prepends to the child
``python -c`` bootstrap: it wraps :meth:`socket.socket.connect` and
:func:`socket.create_connection` and denies any host outside the effective
target-IP allowlist *at connect time*, however the destination was built.

Design notes:
- Stdlib-only (``json``/``ipaddress``/``socket``/``os``): the child may run
  inside the sandbox worker where ``tools.*`` is not importable, so the
  matcher re-implements the ``is_target_in_allowlist`` cases that matter
  (exact case-insensitive, ``*.wildcard`` with dot boundary — the bare
  parent is NOT covered — CIDR). Anything fancier should be allowlisted
  literally.
- Fail-closed: a matcher error denies (with a clear marker), never allows.
- Empty allowlist = permit everything (matches the gate: nothing configured,
  nothing to enforce). The structured ``target_ip`` gate already denies an
  empty target before we get here.
- Ceiling (documented, not fixed here): subprocess-spawned network clients
  inside the script (``curl``/``nc`` via ``os.system``) are NOT intercepted
  — literals there are still caught by the static body scan, and the sandbox
  netns firewall remains the backstop for those when sandboxed.

The denial marker ``BP_EGRESS_DENIED`` is matched by
:func:`egress_denied_in_output` so the tool renders a clean ``BLOCKED:``
result instead of a raw traceback.
"""

from __future__ import annotations

import json
from typing import Any

#: Marker raised in the child and matched in the parent result.
DENIAL_MARKER = "BP_EGRESS_DENIED"

# Stdlib-only preamble, formatted with the JSON allowlist. Runs before the
# script (via runpy) inside the SAME child interpreter, so every socket the
# script opens is wrapped. ``{allowlist_json}`` is the only interpolation.
GUARD_PREAMBLE = """import ipaddress as _ip, json as _json, os as _os, socket as _socket
_BP_ALLOW = _json.loads({allowlist_json!r})
def _bp_allowed(_host):
    try:
        if not _BP_ALLOW:
            return True
        _h = str(_host or "").strip().lower().rstrip(".")
        if not _h:
            return False
        for _e in _BP_ALLOW:
            _e = str(_e or "").strip().lower().rstrip(".")
            if not _e:
                continue
            if _h == _e:
                return True
            if _e.startswith("*."):
                _parent = _e[2:]
                if _parent and _h.endswith("." + _parent):
                    return True
                continue
            if "/" in _e:
                try:
                    if _ip.ip_address(_h) in _ip.ip_network(_e, strict=False):
                        return True
                except ValueError:
                    pass
        return False
    except Exception:
        return False
_orig_connect = _socket.socket.connect
_orig_create_connection = _socket.create_connection
def _bp_connect(self, address, *a, **k):
    _host = address[0] if isinstance(address, (tuple, list)) else address
    if not _bp_allowed(_host):
        raise _socket.error("BP_EGRESS_DENIED: socket.connect to %r is not in the target allowlist" % (_host,))
    return _orig_connect(self, address, *a, **k)
def _bp_create_connection(address, *a, **k):
    _host = address[0] if isinstance(address, (tuple, list)) else address
    if not _bp_allowed(_host):
        raise _socket.error("BP_EGRESS_DENIED: socket.create_connection to %r is not in the target allowlist" % (_host,))
    return _orig_create_connection(address, *a, **k)
_socket.socket.connect = _bp_connect
_socket.create_connection = _bp_create_connection
"""


def build_egress_preamble(allowlist: list[str] | None) -> str:
    """Render the child preamble for ``allowlist`` (empty/None = permit all)."""
    entries = [str(t) for t in (allowlist or []) if str(t or "").strip()]
    return GUARD_PREAMBLE.format(allowlist_json=json.dumps(entries))


def egress_denied_in_output(text: Any) -> str | None:
    """Return the denied host from tool output, or None when no guard denial."""
    if not isinstance(text, str) or DENIAL_MARKER not in text:
        return None
    import re

    m = re.search(r"BP_EGRESS_DENIED: \S+ to ('([^']+)'|\"([^\"]+)\")", text)
    if m:
        return m.group(2) or m.group(3)
    return "<unknown>"
