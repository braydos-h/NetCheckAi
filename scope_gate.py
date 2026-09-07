"""Scope Gate for authorized security research.

Must return `allowed=True` before any executor action can proceed.

Supports:
- Exact domain matching
- Wildcard domain matching (*.example.com)
- IP address matching
- CIDR range matching
- Out-of-scope exclusion rules
- Forbidden action types
- Rate limit enforcement
- Third-party asset detection
- Risk level gating

Every executor action passes through `check_scope()` before execution.
"""
# BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot

from __future__ import annotations

import ipaddress
import re
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from db import DatabaseManager

# ── Default forbidden actions (hard-blocked, always enforced) ───────────────

_HARD_FORBIDDEN_ACTIONS = frozenset(
    {
        "denial_of_service",
        "destructive_exploit",
        "social_engineering",
        "physical_attack",
        "malware",
        "credential_theft",
    }
)

# ── Third-party detection patterns ─────────────────────────────────────────

_THIRD_PARTY_DOMAINS = frozenset(
    {
        "akamai",
        "cloudflare",
        "fastly",
        "azure",
        "aws",
        "cloudfront",
        "googleapis",
        "google-analytics",
        "facebook",
        "twitter",
        "linkedin",
        "cdn",
        "assets",
        "static",
        "img",
        "media",
    }
)

_THIRD_PARTY_PATTERN = re.compile(
    r"^(https?://)?(?:[a-zA-Z0-9-]+\.)*(?:" + "|".join(re.escape(d) for d in _THIRD_PARTY_DOMAINS) + r")\.\w+",
    re.IGNORECASE,
)


# ── Result type ────────────────────────────────────────────────────────────


@dataclass
class ScopeCheckResult:
    """Returned by `check_scope()` for every action evaluation."""

    allowed: bool
    reason: str = ""
    matched_scope_rule: str = ""
    risk_level: str = "low"
    requires_human_approval: bool = False
    is_third_party: bool = False
    rate_limit_remaining: int | None = None


# ── Rate limiter ───────────────────────────────────────────────────────────


@dataclass
class _RateBucket:
    # Sliding-window timestamps of accepted requests in the last 1.0s.
    # A fixed start-of-window counter allows a 2x burst at the boundary
    # (a fresh window opens the instant the old one ends, so N requests at
    # t=0.999 and N more at t=1.001 both pass). A sliding window of accepted
    # timestamps closes that gap.
    timestamps: deque = field(default_factory=deque)
    max_per_second: float = 2.0


# ── Scope Gate class ───────────────────────────────────────────────────────


class ScopeGate:
    """Enforces authorization scope for all agent actions.

    Usage::

        gate = ScopeGate(db_manager, mission)
        result = gate.check_scope("example.com", "recon", "run_nmap_scan", "low")
        if not result.allowed:
            print(f"BLOCKED: {result.reason}")
    """

    def __init__(
        self,
        db: DatabaseManager,
        mission_id: str,
        *,
        allowed_assets: list[str] | None = None,
        disallowed_assets: list[str] | None = None,
        forbidden_actions: list[str] | None = None,
        rate_limits: dict[str, Any] | None = None,
        risk_profile: str = "low_noise_non_destructive",
        default_rps: float | None = None,
    ) -> None:
        self._db = db
        self._mission_id = mission_id

        # Scope rules — loaded once and cached
        self._allow_rules: list[dict[str, Any]] = []
        self._deny_rules: list[dict[str, Any]] = []
        self._forbidden_action_strs: set[str] = set(_HARD_FORBIDDEN_ACTIONS)

        # Rate buckets: keyed by (asset, action_type)
        self._rate_buckets: dict[str, _RateBucket] = {}
        # Rate limit RPS precedence: per-call rate_limits dict > constructor
        # ``default_rps`` kwarg (typically Mission.default_rate_limit_rps) >
        # built-in 2.0 default. The Mission default is honored by callers
        # (e.g. agent_loop.py) passing ``default_rps=self._mission.default_rate_limit_rps``.
        rps = rate_limits.get("default_requests_per_second") if rate_limits else None
        self._default_rps = float(rps if rps is not None else (default_rps if default_rps is not None else 2.0))
        self._risk_profile = risk_profile

        # Build internal rules from arguments
        if allowed_assets:
            for a in allowed_assets:
                self._allow_rules.append({"pattern": a.strip(), "target_type": _classify_target_type(a.strip())})
        if disallowed_assets:
            for a in disallowed_assets:
                self._deny_rules.append({"pattern": a.strip(), "target_type": _classify_target_type(a.strip())})

        if forbidden_actions:
            for fa in forbidden_actions:
                if fa and isinstance(fa, str):
                    self._forbidden_action_strs.add(fa.strip())

    # ------------------------------------------------------------------
    def load_from_db(self) -> None:
        """Reload scope rules from the DB (useful after dynamic `add-scope`)."""
        with self._db.connection() as conn:
            rows = self._db.get_scope_rules(conn, self._mission_id)
        self._allow_rules.clear()
        self._deny_rules.clear()
        for r in rows:
            rule_type = r.get("rule_type", "")
            target_type = r.get("target_type", "")
            pattern = r.get("pattern", "")
            if rule_type == "allow" and target_type != "action":
                self._allow_rules.append({"pattern": pattern, "target_type": target_type})
            elif rule_type == "deny":
                if target_type == "action":
                    self._forbidden_action_strs.add(pattern)
                else:
                    self._deny_rules.append({"pattern": pattern, "target_type": target_type})

    # ------------------------------------------------------------------
    def check_scope(
        self,
        asset: str,
        action_type: str,
        tool_name: str = "",
        risk_level: str = "low",
        *,
        enforce_rate_limit: bool = True,
    ) -> ScopeCheckResult:
        """The primary API: returns ScopeCheckResult indicating whether the action is allowed.

        Args:
            asset: The target asset (domain, IP, URL, etc.)
            action_type: Phase or action category (recon, test, exploit, etc.)
            tool_name: Specific tool being invoked (optional, for logging)
            risk_level: low, medium, or high

        Returns:
            ScopeCheckResult with `allowed` and detailed reason.

        IMPORTANT (caller contract): a result with ``allowed=True`` AND
        ``requires_human_approval=True`` is *not* a green light to execute.
        High-risk actions under a non-``high_authorized_testing`` profile are
        returned as ``allowed=True`` so the caller can render the approval
        prompt -- callers (``tool_router`` C2 / ``cli`` H16 /
        ``autonomous_orchestrator``) MUST check ``requires_human_approval`` and
        gate execution on an explicit human ALLOW. Do not call
        ``check_scope`` for a bare in-scope query (use ``is_asset_in_scope``
        instead) -- ``check_scope`` always applies risk gating and may flag
        approval even for in-scope assets.
        """
        # ``asset_clean`` is the host-normalized form for domain/IP/CIDR
        # matching. ``asset_raw`` keeps scheme/path so ``url_prefix`` rules
        # can match at path level (normalization would strip them).
        asset_raw = asset.strip()
        asset_clean = _clean_asset(asset)

        # ── 1. Forbidden action type check (hard-block) ──
        if action_type and action_type.lower() in self._forbidden_action_strs:
            return ScopeCheckResult(
                allowed=False,
                reason=f"Action type '{action_type}' is explicitly forbidden.",
                risk_level=risk_level,
            )

        # Substrings that mark an action_type as inherently dangerous and thus
        # hard-blocked regardless of scope. CRITICAL: ``action_type`` is always a
        # planner phase string (recon / test / exploit / report / ...), NEVER
        # free-form LLM input, so this set MUST NOT contain legitimate phase
        # names. Earlier versions included "exploit"/"attack"/"kill"/"fuzz",
        # which silently disabled Flow B's exploit phase -- ``planner.py`` emits
        # ``phase="exploit"`` and ``mission.py`` lists "exploit" as a valid
        # testing_mode, so those substrings blocked the planner's own legitimate
        # output. The hard-forbidden *actions* (denial_of_service,
        # destructive_exploit, social_engineering, ...) are already exact-matched
        # against ``self._forbidden_action_strs`` above, so retaining their
        # substrings here is belt-and-braces defense, not the primary gate.
        _HARD_FORBIDDEN_SUBSTRINGS = frozenset(
            {
                "denial_of_service",
                "destructive_exploit",
                "social_engineering",
                "physical_attack",
                "malware",
                "credential_theft",
                "brute_force",
                "dos",
                "overload",
                "crash",
                "saturate",
            }
        )
        lower_action = action_type.lower()
        for hard in _HARD_FORBIDDEN_SUBSTRINGS:
            if hard in lower_action:
                return ScopeCheckResult(
                    allowed=False,
                    reason=f"Action classified as dangerous ('{action_type}'). Verify authorization.",
                    risk_level=risk_level,
                )

        # ── 2. Third-party asset detection ──
        third_party = False
        if _is_third_party_asset(asset_clean):
            third_party = True
            # Third-party assets MUST have an explicit allow rule; auto-reject otherwise.
            if not _matches_allow_rules(asset_clean, self._allow_rules, asset_raw):
                return ScopeCheckResult(
                    allowed=False,
                    reason=f"'{asset_clean}' appears to be a third-party/infrastructure asset. Not in explicit scope.",
                    is_third_party=True,
                    risk_level=risk_level,
                )

        # ── 3. Check deny rules first ──
        for rule in self._deny_rules:
            if _rule_matches(rule, asset_clean, asset_raw):
                return ScopeCheckResult(
                    allowed=False,
                    reason=f"Asset '{asset_clean}' is explicitly out of scope (rule: {rule['pattern']}).",
                    matched_scope_rule=rule["pattern"],
                    risk_level=risk_level,
                )

        # ── 4. Check allow rules ──
        matched_allow = None
        for rule in self._allow_rules:
            if _rule_matches(rule, asset_clean, asset_raw):
                matched_allow = rule
                break

        if not matched_allow:
            return ScopeCheckResult(
                allowed=False,
                reason=(f"Asset '{asset_clean}' is not in the authorized scope. No allow rule matches this asset."),
                risk_level=risk_level,
            )

        # ── 5. Rate limit check ──
        if enforce_rate_limit:
            rl_result = self._check_rate_limit(asset_clean, action_type)
            if not rl_result.allowed:
                return rl_result

        # ── 6. Risk level gating ──
        requires_human = False
        if risk_level == "high" and self._risk_profile != "high_authorized_testing":
            requires_human = True

        return ScopeCheckResult(
            allowed=True,
            reason=f"In scope: matched rule '{matched_allow['pattern']}'.",
            matched_scope_rule=matched_allow["pattern"],
            risk_level=risk_level,
            requires_human_approval=requires_human,
            is_third_party=third_party,
            rate_limit_remaining=None,
        )

    # ── Internal helpers ──────────────────────────────────────────────

    def _check_rate_limit(self, asset: str, action_type: str) -> ScopeCheckResult:
        bucket_key = f"{asset}:{action_type[:20]}"
        now = time.monotonic()
        window = 1.0

        bucket = self._rate_buckets.get(bucket_key)
        if bucket is None:
            bucket = _RateBucket(max_per_second=self._default_rps)
            self._rate_buckets[bucket_key] = bucket

        # Evict timestamps that have aged out of the sliding window.
        while bucket.timestamps and (now - bucket.timestamps[0]) >= window:
            bucket.timestamps.popleft()

        # Clamp fractional RPS to 1 (sliding window is 1s, can't do <1 req/s)
        max_rps = max(1, int(bucket.max_per_second))
        if len(bucket.timestamps) >= max_rps:
            return ScopeCheckResult(
                allowed=False,
                reason=f"Rate limit exceeded for '{asset}' ({action_type}). Max {bucket.max_per_second} req/s.",
                risk_level="low",
                rate_limit_remaining=0,
            )

        bucket.timestamps.append(now)
        remaining = max(0, int(bucket.max_per_second) - len(bucket.timestamps))
        return ScopeCheckResult(
            allowed=True,
            reason="Rate limit check passed.",
            rate_limit_remaining=remaining,
        )

    # ── Utility methods ──────────────────────────────────────────────

    def list_scope(self) -> dict[str, list[str]]:
        return {
            "allow": [r["pattern"] for r in self._allow_rules],
            "deny": [r["pattern"] for r in self._deny_rules],
            "forbidden_actions": sorted(self._forbidden_action_strs),
        }

    def list_forbidden_actions(self) -> list[str]:
        return sorted(self._forbidden_action_strs)

    def is_asset_in_scope(self, asset: str) -> bool:
        result = self.check_scope(asset, "recon", "scope_query", "low", enforce_rate_limit=False)
        return result.allowed


# ── Rule matching engine ───────────────────────────────────────────────────


def _rule_matches(rule: dict[str, Any], asset: str, raw_asset: str | None = None) -> bool:
    """Test whether a scope rule matches an asset string.

    ``asset`` is the host-normalized form (see :func:`_clean_asset`) used by
    the host/domain/IP/CIDR matchers. ``raw_asset`` is the original,
    unstripped asset string; ``url_prefix`` rules are matched against it via
    :func:`_url_prefix_matches` because normalization strips the scheme/path
    that path-level rules depend on. When ``raw_asset`` is omitted it
    defaults to ``asset``.
    """
    target_type = rule.get("target_type", "domain")
    pattern = rule.get("pattern", "").strip()

    if not pattern or not asset:
        return False

    if target_type == "url_prefix":
        return _url_prefix_matches(pattern, raw_asset if raw_asset is not None else asset)

    asset_lower = asset.lower()
    pattern_lower = pattern.lower()

    if target_type == "domain":
        return asset_lower == pattern_lower

    if target_type == "wildcard_domain":
        # "*.example.com" matches "sub.example.com" but not "example.com"
        wild = pattern_lower  # e.g. "*.example.com"
        if wild.startswith("*."):
            suffix = wild[1:]  # ".example.com"
            return asset_lower.endswith(suffix)
        return asset_lower == wild

    if target_type == "ip":
        try:
            return str(ipaddress.ip_address(asset)) == str(ipaddress.ip_address(pattern))
        except ValueError:
            return asset_lower == pattern_lower

    if target_type == "cidr":
        try:
            network = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
        # Asset may be a bare host IP ("10.0.0.5") or a subnet CIDR
        # ("10.0.0.0/16"). A CIDR asset is in-scope iff it is contained
        # within the allowed network — a /16 must NOT match a /24 allow
        # (that was the prefix-strip scope escape). subnet_of covers
        # equality too, but it raises TypeError across IP versions.
        try:
            addr = ipaddress.ip_address(asset)
            return addr in network
        except ValueError:
            try:
                asset_net = ipaddress.ip_network(asset, strict=False)
            except ValueError:
                return False
            if asset_net.version != network.version:
                return False
            return asset_net.subnet_of(network)

    # Fallback: exact match
    return asset_lower == pattern_lower


# ── URL-prefix matching ────────────────────────────────────────────────────

# Schemes whose default port is normalized away during comparison, so
# ``https://host/admin`` and ``https://host:443/admin`` are the same scope.
_URL_DEFAULT_PORTS = {"http": 80, "https": 443}


def _canonicalize_url(value: str) -> tuple[str, str, int | None, str] | None:
    """Parse *value* into ``(scheme, host, port, path)`` or return None.

    Uses :func:`urllib.parse.urlsplit` (never string splitting). Hostnames
    are compared case-insensitively (lowercased here); default ports are
    normalized to None; an empty path becomes ``"/"``. Query strings and
    fragments do not affect resource scope and are dropped.

    Returns None (fail closed) for malformed URLs: missing scheme or host,
    invalid port, whitespace/control characters, or an unparseable value.
    """
    s = value.strip()
    if not s or any(c.isspace() or ord(c) < 32 for c in s):
        return None
    try:
        parts = urllib.parse.urlsplit(s)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return None
    # Percent-escapes in the host are never valid DNS/IP literals — reject
    # so an encoded host can't compare equal to (or confusingly near) a
    # real rule hostname.
    if "%" in host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is not None and _URL_DEFAULT_PORTS.get(scheme) == port:
        port = None
    # ``urlsplit`` never raises for the path; unquote %XX only for the
    # boundary comparison so ``/admin`` and ``/%61dmin`` compare equal.
    # A malformed escape is left as-is rather than failing the whole rule.
    try:
        path = urllib.parse.unquote(parts.path) or "/"
    except Exception:
        path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return (scheme, host, port, path)


def _url_prefix_matches(pattern: str, asset: str) -> bool:
    """Boundary-safe URL-prefix scope check.

    The asset must share the rule's scheme, hostname (case-insensitive),
    and normalized port, and its path must equal the rule path or live
    *under* it (``/admin`` matches ``/admin`` and ``/admin/users`` but NOT
    ``/administrator``). Query strings and fragments are ignored.
    """
    rule = _canonicalize_url(pattern)
    candidate = _canonicalize_url(asset)
    if rule is None or candidate is None:
        return False
    if rule[:3] != candidate[:3]:
        return False
    rule_path, asset_path = rule[3], candidate[3]
    if asset_path == rule_path:
        return True
    # Directory-boundary prefix: "/admin" authorizes "/admin/..." only.
    prefix = rule_path if rule_path.endswith("/") else rule_path + "/"
    return asset_path.startswith(prefix)


def _matches_allow_rules(asset: str, allow_rules: list[dict[str, Any]], raw_asset: str | None = None) -> bool:
    """Return True if asset matches at least one allow rule.

    Supports exact match, wildcard domain (*.example.com), CIDR, and
    ``url_prefix`` (matched against ``raw_asset`` — the unstripped asset —
    so path-level rules keep their scheme/path).
    """
    if not allow_rules:
        return False
    for rule in allow_rules:
        if _rule_matches(rule, asset, raw_asset if raw_asset is not None else asset):
            return True
    return False


def _classify_target_type(asset: str) -> str:
    assert isinstance(asset, str)
    asset = asset.strip()
    if asset.startswith("*."):
        return "wildcard_domain"
    lowered = asset.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return "url_prefix"
    try:
        ipaddress.ip_address(asset)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(asset, strict=False)
        if "/" in asset:
            return "cidr"
        return "ip"
    except ValueError:
        pass
    return "domain"


def _is_third_party_asset(asset: str) -> bool:
    """Heuristic check for CDN/infra/third-party asset patterns.

    Uses the anchored ``_THIRD_PARTY_PATTERN`` (which requires a known
    third-party label as a DNS label immediately followed by ``.\\w+``) so
    that innocent domains sharing a substring (e.g. ``laws.com`` contains
    ``"aws"``) are NOT flagged. The explicit ``cdn.`` / ``.cloudfront.`` /
    ``.googleapis.`` label checks are retained as belt-and-braces.
    """
    asset_clean = asset.strip()
    if _THIRD_PARTY_PATTERN.match(asset_clean):
        return True
    # Explicit CDN/third-party label patterns
    lower = asset_clean.lower()
    if "cdn." in lower or ".cloudfront." in lower or ".googleapis." in lower:
        return True
    return False


def _clean_asset(asset: str) -> str:
    """Strip protocol, trailing slashes, ports from a URL if present.

    IPv6-safe: bare IPv6 literals (``2001:db8::1``) are returned unchanged, and
    bracketed IPv6 literals (``[2001:db8::1]:443``) are un-bracketed with any
    trailing ``:port`` stripped. The legacy ``rsplit(":port")`` port-strip is
    guarded by ``s.count(":") <= 1`` so multi-colon IPv6 strings are never
    mangled.
    """
    s = asset.strip()
    # Strip protocol
    for proto in ("https://", "http://"):
        if s.lower().startswith(proto):
            s = s[len(proto) :]
            break
    # CIDR subnet literal (e.g. "10.0.0.0/16") — preserve the prefix.
    # Stripping the "/16" collapses the asset to its base IP, which then
    # matches a narrower /24 allow rule and lets an over-broad subnet
    # escape scope (e.g. an allow of 10.0.0.0/24 approving 10.0.0.0/16).
    # ``ip_network`` rejects strings with trailing path/query (e.g.
    # "example.com/path", "10.0.0.0/16/foo"), so a single-slash parse
    # success unambiguously identifies a CIDR. Return the normalized form
    # (host bits cleared) so the matcher sees the real network.
    if s.count("/") == 1:
        try:
            net = ipaddress.ip_network(s, strict=False)
            return str(net)
        except ValueError:
            pass
    # Strip path/query/fragment
    if "/" in s:
        s = s.split("/", 1)[0]
    # Bare IP literal (IPv4 or IPv6) — no port suffix to strip, return as-is.
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass
    # Bracketed IPv6 literal: [2001:db8::1] or [2001:db8::1]:443
    if s.startswith("[") and "]" in s:
        host = s[1 : s.index("]")]
        # Strip any trailing ":port" after the closing bracket.
        return host
    # Strip trailing :port — but only for single-colon (IPv4 / host:port)
    # strings. IPv6 contains multiple colons and is handled above.
    if s.count(":") <= 1 and ":" in s:
        maybe_ip = s.rsplit(":", 1)
        if len(maybe_ip) == 2 and maybe_ip[1].isdigit():
            s = maybe_ip[0]
    return s
