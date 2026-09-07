"""Domain-attack MCP tool registration.

Five domain-specific tools that give the agent a first-class domain attack
surface alongside the existing IP-based tools:

  - ``resolve_domain``       forward DNS (A/AAAA/MX/NS/TXT/CNAME/SOA/CAA)
  - ``enumerate_subdomains`` subdomain discovery (crt.sh + DNS bruteforce +
                             optional subfinder/amass) with auto-authorization
  - ``dns_recon``            full DNS intel (all records, AXFR, DNSSEC, NS
                             version, SPF/DMARC)
  - ``vhost_enum``           virtual-host enumeration on a web server via
                             Host-header rotation
  - ``domain_whois``         WHOIS + DNS-provider profiling

All tools are ``@require_allowlist()``-gated (the allowlist already supports
domains + wildcard domains via ``is_target_in_allowlist``) and write audit
records via ``@audit_tool``. Discovered subdomains are auto-authorized by
``add_discovered_target`` so the agent can attack them without per-host config
edits -- the lock model is preserved (each discovered host is still gated
through ``is_target_in_allowlist``; this helper only extends the
operator-authorized set).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
from typing import Any

from tools.mcp_shared import _attempt_dir, _check_allowlist, add_discovered_target
from tools.mcp_tools.registry import ToolContext, _run_with_pgrp_timeout
from tools.validation_utils import (
    is_fqdn,
    is_subdomain_of,
    resolve_target_bounded,
    validate_target_or_ip,
)

# Built-in subdomain wordlist for DNS bruteforce (reused from
# recon_pipeline._enumerate_vhosts + common additions). ~200 prefixes.
_SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "smtp",
    "imap",
    "pop",
    "pop3",
    "webmail",
    "ns1",
    "ns2",
    "dns",
    "dns1",
    "dns2",
    "vpn",
    "remote",
    "secure",
    "portal",
    "admin",
    "administrator",
    "webadmin",
    "api",
    "api1",
    "api2",
    "app",
    "apps",
    "app1",
    "app2",
    "staging",
    "stage",
    "stg",
    "test",
    "testing",
    "qa",
    "dev",
    "dev1",
    "dev2",
    "development",
    "uat",
    "sandbox",
    "beta",
    "alpha",
    "demo",
    "preview",
    "git",
    "github",
    "gitlab",
    "gitea",
    "ci",
    "cd",
    "jenkins",
    "jira",
    "confluence",
    "wiki",
    "docs",
    "doc",
    "help",
    "support",
    "kb",
    "status",
    "monitor",
    "monitoring",
    "grafana",
    "kibana",
    "elastic",
    "elasticsearch",
    "log",
    "logs",
    "logging",
    "splunk",
    "backup",
    "backups",
    "bk",
    "bak",
    "old",
    "new",
    "v1",
    "v2",
    "v3",
    "internal",
    "intranet",
    "corp",
    "private",
    "secure",
    "ssl",
    "tls",
    "auth",
    "sso",
    "oauth",
    "id",
    "identity",
    "login",
    "signin",
    "register",
    "account",
    "accounts",
    "user",
    "users",
    "profile",
    "dashboard",
    "panel",
    "cpanel",
    "whm",
    "plesk",
    "ftp",
    "sftp",
    "tftp",
    "file",
    "files",
    "share",
    "shared",
    "storage",
    "data",
    "db",
    "database",
    "mysql",
    "postgres",
    "pg",
    "redis",
    "mongo",
    "mongodb",
    "couch",
    "couchdb",
    "cassandra",
    "elastic",
    "mq",
    "rabbit",
    "rabbitmq",
    "shop",
    "store",
    "cart",
    "checkout",
    "pay",
    "payment",
    "billing",
    "order",
    "orders",
    "client",
    "clients",
    "customer",
    "customers",
    "service",
    "services",
    "svc",
    "bus",
    "esb",
    "soap",
    "rest",
    "graphql",
    "ws",
    "websocket",
    "socket",
    "io",
    "stream",
    "streaming",
    "media",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "image",
    "pic",
    "pics",
    "video",
    "videos",
    "audio",
    "download",
    "downloads",
    "upload",
    "uploads",
    "cdn1",
    "cdn2",
    "edge",
    "origin",
    "cache",
    "proxy",
    "lb",
    "load",
    "loadbalancer",
    "haproxy",
    "nginx",
    "apache",
    "iis",
    "tomcat",
    "jboss",
    "wildfly",
    "glassfish",
    "jetty",
    "weblogic",
    "mssql",
    "sqlserver",
    "oracle",
    "db2",
    "sybase",
    "informix",
    "ldap",
    "ldaps",
    "ad",
    "dc",
    "dc1",
    "dc2",
    "domain",
    "forest",
    "exchange",
    "exch",
    "owa",
    "ecp",
    "autodiscover",
    "mapi",
    "ews",
    "office",
    "o365",
    "saml",
    "adfs",
    "fs",
    "federation",
    "trust",
    "print",
    "printer",
    "printers",
    "scan",
    "scanner",
    "fax",
    "camera",
    "cam",
    "cctv",
    "dvr",
    "nvr",
    "iot",
    "sensor",
    "sensors",
    "building",
    "facility",
    "facilities",
    "energy",
    "power",
    "ups",
    "hr",
    "finance",
    "legal",
    "marketing",
    "sales",
    "ops",
    "it",
    "eng",
    "engineering",
    "prod",
    "production",
    "lab",
    "labs",
    "train",
    "training",
    "edu",
    "education",
    "research",
    "rd",
    "r&d",
    "m",
    "mobile",
    "wap",
    "app",
    "mobile-api",
    "mobile-api-1",
    "go",
    "rust",
    "java",
    "python",
    "node",
    "nodejs",
    "php",
    "ruby",
    "rails",
    "django",
    "flask",
    "spring",
    "dotnet",
    "asp",
    "test1",
    "test2",
    "test3",
    "qa1",
    "qa2",
    "stg1",
    "stg2",
    "preprod",
    "pre-prod",
    "prod1",
    "prod2",
    "prod3",
    "aws",
    "gcp",
    "azure",
    "cloud",
    "cloud1",
    "cloud2",
    "k8s",
    "kubernetes",
    "kubernetes-master",
    "k8s-master",
    "swarm",
    "docker",
    "docker-registry",
    "registry",
    "harbor",
    "minio",
    "s3",
    "ceph",
    "gluster",
    "nfs",
    "iscsi",
    "prometheus",
    "alertmanager",
    "thanos",
    "vault",
    "consul",
    "nomad",
    "terraform",
    "ansible",
    "puppet",
    "chef",
    "salt",
    "nexus",
    "sonar",
    "sonarqube",
    "sonatype",
    "fortify",
    "squid",
    "foreman",
    "spacewalk",
    "katello",
    "pulp",
    "zabbix",
    "nagios",
    "checkmk",
    "pnp4nagios",
    "icinga",
    "librenms",
    "observium",
    "ntop",
    "cacti",
    "mrtg",
]

# DNS record types resolved by resolve_domain (the bridge primitive).
_RESOLVE_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")

# Known dangling-CNAME takeover fingerprints (service -> DNS suffix + HTTP body marker).
# Used by subdomain-takeover detection inside enumerate_subdomains. The HTTP
# body_markers are matched (case-insensitive, substring) against the response
# body of the unresolvable subdomain to CONFIRM a takeover (the CNAME suffix
# alone is only a "likely" signal -- a deprovisioned service may still resolve).
# Sources: takeovers exposed HackerOne/HackerOne reports, can-i-takeover-xyz.
_TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": {
        "suffix": ".github.io",
        "body_markers": ["There isn't a GitHub Pages site here", "404 Not Found"],
    },
    "Heroku": {
        "suffix": ".herokuapp.com",
        "body_markers": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    },
    "AWS S3": {
        "suffix": ".s3.amazonaws.com",
        "body_markers": ["The specified bucket does not exist", "NoSuchBucket"],
    },
    "Azure": {
        "suffix": ".azurewebsites.net",
        "body_markers": ["404 Web Site not found", "Azure"],
    },
    "Shopify": {
        "suffix": ".myshopify.com",
        "body_markers": ["Sorry, this shop is currently unavailable", "shopify"],
    },
    "Tumblr": {
        "suffix": ".tumblr.com",
        "body_markers": ["Whatever you were looking for doesn't currently exist at this address", "tumblr"],
    },
    "Pantheon": {
        "suffix": ".pantheonsite.io",
        "body_markers": ["The gods are wise", "pantheon"],
    },
    "Fastly": {
        "suffix": ".fastly.net",
        "body_markers": ["Fastly", "no domain configured"],
    },
    "Surge.sh": {
        "suffix": ".surge.sh",
        "body_markers": ["project not found", "surge"],
    },
    "Ghost": {
        "suffix": ".ghost.io",
        "body_markers": ["The thing you were looking for is no longer here", "ghost"],
    },
    "Netlify": {
        "suffix": ".netlify.app",
        "body_markers": ["Not Found - Default Page", "netlify"],
    },
    "Vercel": {
        "suffix": ".vercel.app",
        "body_markers": ["The deployment could not be found", "vercel"],
    },
    "Fly.dev": {
        "suffix": ".fly.dev",
        "body_markers": ["404", "fly.io"],
    },
    "Render": {
        "suffix": ".onrender.com",
        "body_markers": ["There isn't a site here", "render"],
    },
    "Bitbucket Pages": {
        "suffix": ".bitbucket.io",
        "body_markers": ["404", "bitbucket"],
    },
    "Cloudfront": {
        "suffix": ".cloudfront.net",
        "body_markers": ["Bad request", "cloudfront"],
    },
    "Google Cloud Storage": {
        "suffix": "storage.googleapis.com",
        "body_markers": ["The specified bucket does not exist", "NoSuchBucket"],
    },
    "Webflow": {
        "suffix": ".webflow.io",
        "body_markers": ["The page you are looking for doesn't exist", "webflow"],
    },
    "Tilda": {
        "suffix": ".tilda.ws",
        "body_markers": ["Please enter a valid domain", "tilda"],
    },
    "Smartling": {
        "suffix": ".smartling.com",
        "body_markers": ["Domain not found", "smartling"],
    },
    "S3 Website": {
        "suffix": ".s3-website",
        "body_markers": ["The specified bucket does not exist", "NoSuchBucket"],
    },
    "Fastmail": {
        "suffix": ".fastmail.net",
        "body_markers": ["Domain not found", "fastmail"],
    },
    "Zendesk": {
        "suffix": ".zendesk.com",
        "body_markers": ["Help Center Closed", "zendesk"],
    },
    "Readme.io": {
        "suffix": ".readme.io",
        "body_markers": ["Project not found", "readme"],
    },
    "Unbounce": {
        "suffix": ".unbouncepages.com",
        "body_markers": ["The requested URL was not found", "unbounce"],
    },
}


def _stdlib_fetch(
    url: str,
    *,
    timeout: int = 15,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    max_bytes: int = 4000,
) -> tuple[int, dict[str, str], str]:
    """HTTP GET/POST via urllib. Returns (status, headers, body). Never raises.

    ``max_bytes`` caps the response body read (default 4000 -- fine for most
    probe responses). Callers fetching large JSON payloads (e.g. crt.sh CT
    logs, which can exceed 100KB for popular domains) must pass a larger cap
    or the body is truncated mid-stream and JSON parsing silently fails.
    """
    try:
        hdrs = {"User-Agent": "BreachPilot-DomainRecon/1.0"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, headers=hdrs, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - passive recon
            body = resp.read(max_bytes).decode(errors="replace")
            return resp.status, dict(resp.headers.items()), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(min(2000, max_bytes)).decode(errors="replace")
        except Exception:  # ponytail: bare except intentional
            body = ""
        return e.code, dict(e.headers.items()) if e.headers else {}, body
    except Exception:  # ponytail: bare except intentional
        return 0, {}, ""


def _dns_resolve_all(domain: str, *, resolver_fn=None) -> dict[str, list[str]]:
    """Resolve all common record types for a domain.

    Uses ``socket.getaddrinfo`` for A/AAAA (no external dep) and an optional
    ``resolver_fn(domain, rtype) -> list[str]`` for the richer record types
    (MX/NS/TXT/CNAME/SOA/CAA). When ``resolver_fn`` is None, only A/AAAA are
    resolved via the system resolver; the other types return empty lists with
    a note. Never raises.
    """
    result: dict[str, list[str]] = {rt: [] for rt in _RESOLVE_TYPES}
    if not domain:
        return result
    # A / AAAA via socket
    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM):
            try:
                ip = info[4][0].split("%")[0]
                if ip and ip not in result["A"]:
                    result["A"].append(ip)
            except (IndexError, TypeError):
                continue
    except (OSError, socket.gaierror):
        pass
    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM):
            try:
                ip = info[4][0].split("%")[0]
                if ip and ip not in result["AAAA"]:
                    result["AAAA"].append(ip)
            except (IndexError, TypeError):
                continue
    except (OSError, socket.gaierror):
        pass
    # Richer record types via the optional resolver_fn (e.g. dnspython-backed)
    if resolver_fn is not None:
        for rt in ("MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
            try:
                vals = resolver_fn(domain, rt)
                if isinstance(vals, list):
                    result[rt] = [str(v) for v in vals if v]
            except _EXC_GROUP_CATCH as exc:
                _log_nested_exceptions(exc)
                continue
    return result


def register_domain_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    require_allowlist = ctx.require_allowlist

    # ------------------------------------------------------------------
    # 1. resolve_domain -- the bridge primitive
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("domain")
    def resolve_domain(
        domain: str,
        record_types: str = "A,AAAA,MX,NS,TXT,CNAME,SOA,CAA",
    ) -> str:
        """Resolve DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA).

        The bridge primitive for domain targeting -- every other domain tool
        builds on the A/AAAA records this returns. ``record_types`` is a
        comma-separated list; omit for all types. A/AAAA use the system
        resolver; the richer types (MX/NS/TXT/CNAME/SOA/CAA) require
        ``dnspython`` (optional) -- when absent, only A/AAAA are returned
        with a note. PASSIVE: queries public DNS only, no active scanning.

        Args:
            domain: The domain to resolve (e.g. ``example.com``).
            record_types: Comma-separated DNS record types to query.

        Returns:
            A ``DNS_RESULT:`` block with resolved records per type.
        """
        if not domain or not domain.strip():
            return "ERROR: domain is required."
        dom = domain.strip().lower()
        if not is_fqdn(dom):
            return f"ERROR: {dom!r} is not a valid domain."
        requested = [r.strip().upper() for r in (record_types or "").split(",") if r.strip()]
        if not requested:
            requested = list(_RESOLVE_TYPES)

        # Try dnspython for the richer types; fall back to socket for A/AAAA.
        resolver_fn = None
        try:
            import dns.resolver  # type: ignore

            def _dnspython_resolver(d: str, rt: str) -> list[str]:
                try:
                    answers = dns.resolver.resolve(d, rt)
                    return [str(r.to_text()) for r in answers]
                except Exception:  # ponytail: bare except intentional
                    return []

            resolver_fn = _dnspython_resolver
        except ImportError:
            pass

        all_records = _dns_resolve_all(dom, resolver_fn=resolver_fn)
        lines = [
            "DNS_RESULT: completed",
            f"DOMAIN: {dom}",
        ]
        if resolver_fn is None:
            lines.append("NOTE: dnspython not installed -- only A/AAAA resolved. Install with: pip install dnspython")
        for rt in requested:
            vals = all_records.get(rt, [])
            if vals:
                for v in vals:
                    lines.append(f"  {rt}: {v}")
            else:
                lines.append(f"  {rt}: (none)")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 2. enumerate_subdomains -- attack-surface expansion
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("domain")
    def enumerate_subdomains(
        domain: str,
        sources: str = "crt_sh,dns_bruteforce",
        max_results: int = 500,
    ) -> str:
        """Enumerate subdomains of a domain via passive + active sources.

        Sources (comma-separated):
          - ``crt_sh``        -- Certificate Transparency logs via crt.sh (passive)
          - ``dns_bruteforce`` -- DNS resolution of a ~200-word built-in wordlist (active)
          - ``subfinder``     -- ProjectDiscovery subfinder (if installed; passive)
          - ``amass``         -- OWASP Amass (if installed; passive + active)

        Each discovered subdomain is auto-authorized (added to
        ``EXPLOIT_DISCOVERED_TARGETS``) so the agent can attack it without a
        per-host config edit -- the target-IP lock is preserved (each host is
        still gated through ``is_target_in_allowlist``). Returns ``(subdomain,
        resolved_ip)`` pairs capped at ``max_results``. Also flags potential
        dangling-CNAME takeover targets when the resolved CNAME points to a
        known deprovisioned service (GitHub Pages, Heroku, S3, Azure, etc.).

        Args:
            domain: The parent domain (e.g. ``example.com``).
            sources: Comma-separated discovery sources.
            max_results: Cap on returned subdomains (default 500).

        Returns:
            A ``SUBDOMAIN_RESULT:`` block with discovered hosts, IPs, and
            takeover candidates.
        """
        if not domain or not domain.strip():
            return "ERROR: domain is required."
        dom = domain.strip().lower()
        if not is_fqdn(dom):
            return f"ERROR: {dom!r} is not a valid domain."
        srcs = [s.strip().lower() for s in (sources or "").split(",") if s.strip()]
        if not srcs:
            srcs = ["crt_sh", "dns_bruteforce"]

        subs: dict[str, str | None] = {}  # subdomain -> resolved IP (or None)

        # crt.sh Certificate Transparency
        if "crt_sh" in srcs:
            # CT log responses for popular domains can exceed 100KB; the default
            # 4000-byte cap would truncate the JSON mid-stream and silently
            # lose all subdomains (the json.loads fails and the except: pass
            # swallows it). Pass a 5MB cap so the full response is parsed.
            status, _hdr, body = _stdlib_fetch(
                f"https://crt.sh/?q=%25.{dom}&output=json",
                timeout=20,
                max_bytes=5_000_000,
            )
            if status == 200 and body:
                try:
                    for row in json.loads(body):
                        for nv in str(row.get("name_value", "")).splitlines():
                            for s in nv.split(","):
                                s = s.strip().lstrip("*.").strip().lower()
                                if s and is_subdomain_of(s, dom) and s != dom and s not in subs:
                                    subs[s] = None
                except Exception:  # ponytail: bare except intentional
                    pass

        # DNS bruteforce with the built-in wordlist. Resolutions run on a
        # bounded worker pool with a 5s per-query timeout (socket.getaddrinfo
        # has no timeout of its own -- an unbounded resolve stalled callers
        # for minutes on a dead resolver). The halved fan-out rate-limits the
        # query burst against the system resolver.
        if "dns_bruteforce" in srcs:
            from concurrent.futures import ThreadPoolExecutor

            candidates = [f"{prefix}.{dom}" for prefix in _SUBDOMAIN_WORDLIST if f"{prefix}.{dom}" not in subs]

            def _resolve_one(cand: str) -> tuple[str, str | None]:
                try:
                    ip, _domain = resolve_target_bounded(cand, timeout_seconds=5.0)
                except (TimeoutError, OSError):
                    return cand, None
                return cand, ip

            with ThreadPoolExecutor(max_workers=16) as pool:
                for cand, ip in pool.map(_resolve_one, candidates):
                    if ip:
                        subs[cand] = ip

        # subfinder (passive, if installed)
        if "subfinder" in srcs and shutil.which("subfinder"):
            try:
                argv = ["subfinder", "-d", dom, "-silent", "-nc"]
                rc, out, _err = _run_with_pgrp_timeout(
                    argv,
                    120,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if rc == 0 and out:
                    for line in out.splitlines():
                        s = line.strip().lower()
                        if s and is_subdomain_of(s, dom) and s != dom and s not in subs:
                            subs[s] = None
            except Exception:  # ponytail: bare except intentional
                pass

        # amass (passive+active, if installed)
        if "amass" in srcs and shutil.which("amass"):
            try:
                argv = ["amass", "enum", "-passive", "-d", dom]
                rc, out, _err = _run_with_pgrp_timeout(
                    argv,
                    120,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if rc == 0 and out:
                    for line in out.splitlines():
                        s = line.strip().lower()
                        if s and is_subdomain_of(s, dom) and s != dom and s not in subs:
                            subs[s] = None
            except Exception:  # ponytail: bare except intentional
                pass

        # Resolve any subdomains found passively that don't have an IP yet,
        # and auto-authorize each discovered host via add_discovered_target.
        takeover_candidates: list[dict[str, str]] = []
        resolved_pairs: list[tuple[str, str]] = []
        for sub in sorted(subs.keys())[:max_results]:
            ip = subs[sub]
            if ip is None:
                try:
                    ip, _domain = resolve_target_bounded(sub, timeout_seconds=5.0)
                except (TimeoutError, OSError):
                    ip = None
            if ip:
                resolved_pairs.append((sub, ip))
                add_discovered_target(sub, ip)
            else:
                # Unresolvable subdomain -- potential dangling CNAME / takeover.
                add_discovered_target(sub)
                # Check for a CNAME pointing at a known deprovisioned service.
                cname_target = ""
                try:
                    import dns.resolver  # type: ignore

                    answers = dns.resolver.resolve(sub, "CNAME")
                    for r in answers:
                        cname_target = str(r.to_text()).rstrip(".")
                        break
                except Exception:  # ponytail: bare except intentional
                    pass
                if cname_target:
                    for svc, fp in _TAKEOVER_FINGERPRINTS.items():
                        if cname_target.endswith(fp["suffix"]):
                            # CNAME-suffix match -- a "likely" signal. Try to
                            # CONFIRM by fetching the subdomain's HTTP response
                            # and matching the service's body_markers (e.g.
                            # Heroku's "No such app"). A deprovisioned service
                            # that still resolves would fail this check.
                            status = "unresolvable -- likely dangling CNAME"
                            markers = fp.get("body_markers") or []
                            if markers:
                                for probe_scheme in ("https", "http"):
                                    _status, _hdr, body = _stdlib_fetch(
                                        f"{probe_scheme}://{sub}/",
                                        timeout=8,
                                    )
                                    if _status and body:
                                        body_lower = body.lower()
                                        if any(m.lower() in body_lower for m in markers):
                                            status = f"CONFIRMED takeover -- body matches {svc} (HTTP {_status})"
                                            break
                            takeover_candidates.append(
                                {
                                    "subdomain": sub,
                                    "cname": cname_target,
                                    "service": svc,
                                    "status": status,
                                }
                            )
                            break
                    else:
                        takeover_candidates.append(
                            {
                                "subdomain": sub,
                                "cname": cname_target,
                                "service": "unknown",
                                "status": "unresolvable -- investigate",
                            }
                        )

        lines = [
            "SUBDOMAIN_RESULT: completed",
            f"DOMAIN: {dom}",
            f"SOURCES: {', '.join(srcs)}",
            f"DISCOVERED: {len(resolved_pairs)} resolvable subdomains",
            f"TAKEOVER_CANDIDATES: {len(takeover_candidates)}",
            "",
            "SUBDOMAINS:",
        ]
        for sub, ip in resolved_pairs:
            lines.append(f"  {sub} -> {ip}")
        if takeover_candidates:
            lines.append("")
            lines.append("TAKEOVER_CANDIDATES:")
            for tc in takeover_candidates:
                lines.append(f"  {tc['subdomain']} (CNAME -> {tc['cname']}, {tc['service']}): {tc['status']}")
        lines.append("")
        lines.append(
            "AUTO_AUTHORIZED: each discovered host added to EXPLOIT_DISCOVERED_TARGETS; "
            "the target-IP lock now accepts them."
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 3. dns_recon -- full DNS intelligence
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("domain")
    def dns_recon(domain: str, zone_transfer: bool = False) -> str:
        """Full DNS reconnaissance against a domain.

        Queries all common record types (A, AAAA, MX, NS, TXT, CNAME, SOA,
        CAA, SPF, DMARC), attempts a DNS zone transfer (AXFR) when
        ``zone_transfer=True`` (opt-in, gated by ``recon.dns_zone_transfer``
        config), checks DNSSEC status, and fingerprints the nameserver
        version. Uses ``dnspython`` when installed; falls back to
        ``socket.getaddrinfo`` for A/AAAA when absent. PASSIVE except for the
        opt-in AXFR attempt.

        Args:
            domain: The domain to recon (e.g. ``example.com``).
            zone_transfer: Attempt an AXFR zone transfer (default False;
                            opt-in via ``recon.dns_zone_transfer`` config).

        Returns:
            A ``DNS_RECON_RESULT:`` block with all records, AXFR results,
            DNSSEC status, and NS version info.
        """
        if not domain or not domain.strip():
            return "ERROR: domain is required."
        dom = domain.strip().lower()
        if not is_fqdn(dom):
            return f"ERROR: {dom!r} is not a valid domain."

        # Respect the config gate for zone transfers even when the caller
        # passes zone_transfer=True (defense-in-depth).
        recon_cfg = (config or {}).get("recon", {}) or {}
        allow_axfr = bool(zone_transfer and recon_cfg.get("dns_zone_transfer", False))

        lines = [
            "DNS_RECON_RESULT: completed",
            f"DOMAIN: {dom}",
        ]
        records: dict[str, list[str]] = {}
        axfr_result = ""
        dnssec_status = "unknown"
        ns_version = ""

        try:
            import dns.exception  # type: ignore
            import dns.name  # type: ignore
            import dns.query  # type: ignore
            import dns.rdataclass  # type: ignore
            import dns.rdatatype  # type: ignore
            import dns.resolver  # type: ignore
            import dns.zone  # type: ignore

            try:
                import dns.xfr  # type: ignore  # dnspython 2.x (TransferError lives here)
            except ImportError:
                pass

            resolver = dns.resolver.Resolver()
            for rt in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"):
                try:
                    answers = resolver.resolve(dom, rt)
                    records[rt] = [str(r.to_text()) for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    records[rt] = []
                except dns.exception.DNSException:
                    records[rt] = []

            # SPF / DMARC (TXT records)
            try:
                spf_answers = resolver.resolve(dom, "TXT")
                spf = [str(r.to_text()) for r in spf_answers if "spf" in str(r.to_text()).lower()]
                records["SPF"] = spf
            except Exception:  # ponytail: bare except intentional
                records["SPF"] = []
            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{dom}", "TXT")
                records["DMARC"] = [str(r.to_text()) for r in dmarc_answers]
            except Exception:  # ponytail: bare except intentional
                records["DMARC"] = []

            # DNSSEC: presence of a DS record at the parent zone indicates a
            # signed zone. The previous AD-flag heuristic measured the resolving
            # resolver's validation config, not the target domain's DNSSEC.
            try:
                resolver.resolve(dom, "DS", lifetime=5)
                dnssec_status = "signed (DS record present)"
            except dns.resolver.NoAnswer:
                dnssec_status = "unsigned (no DS record)"
            except (dns.resolver.NXDOMAIN, dns.exception.DNSException):
                dnssec_status = "unsigned"
            except Exception:  # ponytail: bare except intentional
                dnssec_status = "unknown"

            # NS version fingerprinting -- query version.bind in the CHAOS
            # (CH) class, not a subdomain of the NS host. The old code queried
            # ``version.bind.{ns_name}`` as a normal TXT record, which returned
            # NXDOMAIN.
            ns_hosts = records.get("NS", [])
            if ns_hosts:
                try:
                    version_answers = resolver.resolve(
                        dns.name.from_text("version.bind"),
                        rdtype=dns.rdatatype.TXT,
                        rdclass=dns.rdataclass.CH,
                        lifetime=5,
                    )
                    ns_version = " ".join(str(r.to_text()) for r in version_answers)
                except Exception:  # ponytail: bare except intentional
                    ns_version = "(version.bind query failed / refused)"

            # AXFR zone transfer (opt-in)
            if allow_axfr and ns_hosts:
                ns_name = ns_hosts[0].rstrip(".")
                try:
                    ns_a = resolver.resolve(ns_name, "A")
                    ns_ip = str(ns_a[0].to_text())
                    # dnspython 2.x moved xfr() to dns.xfr.xfr(); 1.x had it on
                    # dns.query.xfr. Resolve the callable defensively.
                    xfr_fn = getattr(dns.xfr, "xfr", None) or dns.query.xfr
                    zone = dns.zone.from_xfr(xfr_fn(ns_ip, dom, timeout=10))
                    zone_records = []
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            rdtype = dns.rdatatype.to_text(rdataset.rdtype)
                            for rdata in rdataset:
                                zone_records.append(f"{name}.{dom} {rdtype} {rdata.to_text()}")
                    axfr_result = f"AXFR_SUCCESS: {len(zone_records)} records from {ns_ip}"
                    records["AXFR"] = zone_records[:200]  # cap for display
                except dns.exception.FormError:
                    axfr_result = "AXFR_REFUSED: server refused zone transfer"
                except Exception as e:  # ponytail: bare except intentional
                    # dns.xfr.TransferError (when importable) is a subclass of
                    # Exception, so this branch covers both transfer-refused
                    # and generic AXFR failures without needing to name the
                    # class at the except-clause (which would AttributeError
                    # if dns.xfr failed to import above).
                    if "TransferError" in type(e).__name__:
                        axfr_result = f"AXFR_REFUSED: {e}"
                    else:
                        axfr_result = f"AXFR_FAILED: {e}"
            elif allow_axfr:
                axfr_result = "AXFR_SKIPPED: no NS records found"
            else:
                axfr_result = "AXFR_NOT_REQUESTED (set zone_transfer=True and recon.dns_zone_transfer=true)"

        except ImportError:
            # Fall back to socket-based A/AAAA only.
            records = _dns_resolve_all(dom)
            lines.append(
                "NOTE: dnspython not installed -- only A/AAAA resolved. "
                "Install with: pip install dnspython for full DNS recon."
            )
            axfr_result = "AXFR_UNAVAILABLE: requires dnspython"
            dnssec_status = "unknown (requires dnspython)"
            ns_version = "unknown (requires dnspython)"

        # Render records
        for rt in ("A", "AAAA", "MX", "NS", "TXT", "SPF", "DMARC", "SOA", "CAA"):
            vals = records.get(rt, [])
            if vals:
                lines.append(f"{rt}:")
                for v in vals:
                    lines.append(f"  {v}")
            else:
                lines.append(f"{rt}: (none)")

        lines.append(f"DNSSEC: {dnssec_status}")
        lines.append(f"NS_VERSION: {ns_version}")
        lines.append(f"AXFR: {axfr_result}")
        if "AXFR" in records and records["AXFR"]:
            lines.append("AXFR_RECORDS (first 200):")
            for r in records["AXFR"][:200]:
                lines.append(f"  {r}")

        # Persist the full result for the audit trail.
        attempt_dir, attempt_id = _attempt_dir(workspace)
        try:
            (attempt_dir / "dns_recon.json").write_text(json.dumps(records, indent=2, default=str), encoding="utf-8")
        except OSError:
            pass

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 4. vhost_enum -- virtual host enumeration
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist()
    def vhost_enum(
        target_ip: str,
        port: int = 80,
        domain: str = "",
        wordlist: str = "",
        timeout: int = 300,
    ) -> str:
        """Enumerate virtual hosts on a web server via Host-header rotation.

        Sends HTTP requests to ``http(s)://<target_ip>:<port>/`` with rotated
        ``Host: <word>.<domain>`` headers and compares the response body
        length / status to the baseline (the default Host). A different
        response indicates another virtual host served on the same IP:port.
        Distinct from the recon_pipeline IP-first vhost enumerator (which
        derives the domain from reverse DNS); this one takes the domain
        directly so it works with domain targets.

        Args:
            target_ip: The web server to probe (IP or domain).
            port: TCP port (default 80).
            domain: The parent domain to build vhost candidates from
                      (e.g. ``example.com`` -> ``www.example.com``). Required.
            wordlist: Comma-separated extra vhost prefixes (appended to the
                        built-in wordlist).
            timeout: Overall budget in seconds (default 300). Each probe
                      gets 10s; the wordlist is capped at ``timeout // 10``
                      probes so the total stays within budget.

        Returns:
            A ``VHOST_RESULT:`` block with discovered virtual hosts.

        Note:
            For HTTPS (443/8443), this tool rotates the ``Host:`` header but
            does NOT rotate TLS SNI (urllib has no SNI override). TLS-based
            vhost servers that key off SNI rather than Host may be missed;
            the output flags this when it applies.
        """
        if not target_ip or not target_ip.strip():
            return "ERROR: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."
        if isinstance(port, str) and port.strip().isdigit():
            port = int(port.strip())
        if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
            return "ERROR: port must be an integer between 1 and 65535."
        if not domain or not domain.strip():
            return "ERROR: domain is required."
        dom = domain.strip().lower()
        if not is_fqdn(dom):
            return f"ERROR: {dom!r} is not a valid domain."

        scheme = "https" if port in (443, 8443) else "http"
        base_url = f"{scheme}://{target_ip}:{port}/"

        words = [
            "www",
            "mail",
            "admin",
            "api",
            "dev",
            "staging",
            "test",
            "vpn",
            "portal",
            "git",
            "jenkins",
            "jira",
            "internal",
            "blog",
            "shop",
            "app",
            "secure",
            "remote",
            "support",
            "help",
            "docs",
            "wiki",
            "status",
            "monitor",
            "dashboard",
            "cdn",
            "static",
            "assets",
        ]
        if wordlist and wordlist.strip():
            # Attacker-controlled: keep only DNS-label-safe tokens (a raw
            # "\r\n" here would inject headers via the Host: value) and cap
            # the extras so the probe loop stays bounded.
            extras = [w.strip().lower() for w in wordlist.split(",") if w.strip()]
            extras = [w for w in extras if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", w)]
            words.extend(extras[:100])

        # Attacker-controlled budget: clamp so a huge timeout cannot inflate
        # the probe loop (each probe gets a 10s per-request timeout).
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            timeout = 300
        timeout = max(10, min(timeout, 300))

        # Cap the wordlist so the total probe time stays within the budget
        # (each probe gets a 10s per-request timeout). At least one probe.
        max_probes = max(1, timeout // 10)
        if len(words) > max_probes:
            words = words[:max_probes]

        per_probe = 10

        # Baseline request with the default Host (the target_ip itself).
        _b_status, _b_hdr, base_body = _stdlib_fetch(base_url, timeout=per_probe)
        base_len = len(base_body)
        base_hash = hashlib.sha256(base_body.encode(errors="replace")).hexdigest()[:12]

        found: list[dict[str, Any]] = []
        for w in words:
            host = f"{w}.{dom}"
            s, _h, body = _stdlib_fetch(base_url, timeout=per_probe, headers={"Host": host})
            if s and s not in (404,):
                body_hash = hashlib.sha256(body.encode(errors="replace")).hexdigest()[:12]
                # Flag a vhost if the body differs from baseline by length OR
                # status OR content hash. The hash catches same-length
                # different-content responses the old length-only check missed.
                if len(body) != base_len or s != _b_status or body_hash != base_hash:
                    found.append(
                        {
                            "vhost": host,
                            "status": s,
                            "length": len(body),
                            "baseline_length": base_len,
                            "hash": body_hash,
                            "baseline_hash": base_hash,
                        }
                    )

        lines = [
            "VHOST_RESULT: completed",
            f"TARGET: {target_ip}:{port}",
            f"DOMAIN: {dom}",
            f"BASELINE_LENGTH: {base_len}",
            f"BASELINE_HASH: {base_hash}",
            f"VHOSTS_FOUND: {len(found)}",
            "",
            "VHOSTS:",
        ]
        for v in found:
            lines.append(
                f"  {v['vhost']} (status={v['status']}, len={v['length']} vs baseline {v['baseline_length']}, hash={v['hash']} vs {v['baseline_hash']})"
            )
        if not found:
            lines.append("  (none -- the server returns the same response for all Host headers)")
        if scheme == "https":
            lines.append(
                "NOTE: HTTPS vhost enum uses the Host header only; SNI is not "
                "rotated (urllib has no SNI override). TLS-vhost servers that "
                "key off SNI may be missed."
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 5. domain_whois -- WHOIS + DNS provider profiling
    # ------------------------------------------------------------------
    @mcp.tool()
    @require_allowlist("domain")
    def domain_whois(domain: str) -> str:
        """WHOIS lookup + DNS-provider profiling for a domain.

        Returns registrar, creation/expiry dates, nameservers, registrant
        organization, and a best-guess DNS provider (Cloudflare / AWS
        Route53 / Google / Azure / etc. derived from NS names). Uses the
        ``python-whois`` library when installed, else shells to the ``whois``
        binary when available, else returns a "not installed" message.
        PASSIVE: queries public WHOIS/DNS only.

        Args:
            domain: The domain to look up (e.g. ``example.com``).

        Returns:
            A ``WHOIS_RESULT:`` block with registrar, dates, nameservers,
            registrant, and DNS provider.
        """
        if not domain or not domain.strip():
            return "ERROR: domain is required."
        dom = domain.strip().lower()
        if not is_fqdn(dom):
            return f"ERROR: {dom!r} is not a valid domain."

        registrar = ""
        creation_date = ""
        expiry_date = ""
        registrant_org = ""
        nameservers: list[str] = []
        dns_provider = "unknown"

        # Try python-whois first (structured fields — preferred over binary parsing)
        try:
            import whois  # type: ignore

            w = whois.whois(dom)
            registrar = str(getattr(w, "registrar", "") or "")
            # python-whois returns dates as a list for some TLDs (e.g. .com) —
            # take the first; format datetimes to ISO.
            _cd = getattr(w, "creation_date", None)
            if isinstance(_cd, list):
                _cd = _cd[0] if _cd else None
            creation_date = str(_cd or "")
            _ed = getattr(w, "expiration_date", None)
            if isinstance(_ed, list):
                _ed = _ed[0] if _ed else None
            expiry_date = str(_ed or "")
            registrant_org = str(getattr(w, "org", "") or getattr(w, "organization", "") or "")
            ns = getattr(w, "name_servers", []) or []
            if isinstance(ns, list):
                nameservers = [str(n).rstrip(".").lower() for n in ns]
            else:
                nameservers = [str(ns).rstrip(".").lower()]
        except ImportError:
            pass
        except Exception:  # ponytail: bare except intentional
            pass

        # Fallback: shell to the whois binary
        if not registrar and shutil.which("whois"):
            try:
                argv = ["whois", dom]
                rc, out, _err = _run_with_pgrp_timeout(
                    argv,
                    30,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if rc == 0 and out:
                    # Parse common WHOIS fields heuristically. Different
                    # registrars format differently (Verisign vs. .io vs.
                    # ccTLDs), so match case-insensitively on the line prefix.
                    for line in out.splitlines():
                        ll = line.strip().lower()
                        if "registrar:" in ll and not registrar:
                            registrar = line.split(":", 1)[1].strip()
                        elif "creation date" in ll and not creation_date:
                            creation_date = line.split(":", 1)[1].strip()
                        elif "registry expiry" in ll and not expiry_date:
                            expiry_date = line.split(":", 1)[1].strip()
                        elif "registrant org" in ll and not registrant_org:
                            registrant_org = line.split(":", 1)[1].strip()
                        elif ll.startswith("name server:"):
                            # Bug fix: the old `and not nameservers` guard
                            # stopped after the first NS line, so only one
                            # nameserver was captured. Collect ALL of them.
                            ns_val = line.split(":", 1)[1].strip().rstrip(".").lower()
                            if ns_val and ns_val not in nameservers:
                                nameservers.append(ns_val)
            except Exception:  # ponytail: bare except intentional
                pass

        if not registrar and not shutil.which("whois"):
            return (
                "WHOIS_RESULT: unavailable\n"
                f"DOMAIN: {dom}\n"
                "Install python-whois (pip install python-whois) or the whois "
                "binary (apt install whois) to enable WHOIS lookups."
            )

        # DNS provider profiling from NS names
        ns_joined = " ".join(nameservers).lower()
        if "cloudflare" in ns_joined:
            dns_provider = "Cloudflare"
        elif "awsdns" in ns_joined or "route53" in ns_joined or "aws" in ns_joined:
            dns_provider = "AWS Route53"
        elif "googledomains" in ns_joined or "google" in ns_joined or "gcp" in ns_joined:
            dns_provider = "Google Cloud DNS"
        elif "azure" in ns_joined or "windows" in ns_joined or "microsoft" in ns_joined:
            dns_provider = "Azure DNS"
        elif "dnsimple" in ns_joined:
            dns_provider = "DNSimple"
        elif "dnsmadeeasy" in ns_joined:
            dns_provider = "DNS Made Easy"
        elif "namecheaphosting" in ns_joined or "namecheap" in ns_joined:
            dns_provider = "Namecheap"
        elif "godaddy" in ns_joined:
            dns_provider = "GoDaddy"
        elif nameservers:
            dns_provider = f"unknown (NS: {nameservers[0]})"

        lines = [
            "WHOIS_RESULT: completed",
            f"DOMAIN: {dom}",
            f"REGISTRAR: {registrar or '(not found)'}",
            f"CREATION_DATE: {creation_date or '(not found)'}",
            f"EXPIRY_DATE: {expiry_date or '(not found)'}",
            f"REGISTRANT_ORG: {registrant_org or '(not found)'}",
            f"DNS_PROVIDER: {dns_provider}",
            "NAMESERVERS:",
        ]
        for ns in nameservers[:10]:
            lines.append(f"  {ns}")
        if not nameservers:
            lines.append("  (none found)")
        return "\n".join(lines)
