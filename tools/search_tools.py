"""Restricted vulnerability-intelligence search via SerpAPI DuckDuckGo."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any


PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:"
    r"10(?:\.\d{1,3}){3}|"
    r"127(?:\.\d{1,3}){3}|"
    r"192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}"
    r")\b"
)
BLOCKED_QUERY_TERMS = {
    "payload",
    "reverse shell",
    "weaponized",
    "metasploit",
    "msfconsole",
    "hydra",
    "bruteforce",
    "brute force",
    "exploit db",
    "exploit-db",
    "pastebin",
}


@dataclass(frozen=True)
class SearchSettings:
    enabled: bool = True
    endpoint: str = "https://serpapi.com/search.json"
    engine: str = "duckduckgo"
    region: str = "us-en"
    api_key_env: str = "SERPAPI_API_KEY"
    timeout_seconds: int = 20
    max_results: int = 5


class VulnerabilitySearch:
    """Small, defensive wrapper around the SerpAPI DuckDuckGo endpoint.

    Includes a lightweight in-memory TTL cache and an async-safe entry point
    so the event loop is never blocked by synchronous urllib calls.
    """

    def __init__(self, settings: SearchSettings) -> None:
        self.settings = settings
        self._cache: OrderedDict[str, tuple[float, str]] = OrderedDict()
        self._cache_ttl = 3600.0
        self._cache_max = 20

    def search_vulnerability_intel(self, query: str) -> str:
        """Synchronous search (for MCP tool handlers)."""
        if not self.settings.enabled:
            return "BLOCKED: vulnerability-intelligence search is disabled in config.yaml."

        try:
            clean_query = sanitize_query(query)
        except ValueError as exc:
            return f"BLOCKED: {exc}"

        cached = self._get_cached(clean_query)
        if cached is not None:
            return cached

        result = self._do_search(clean_query)
        self._store_cache(clean_query, result)
        return result

    async def search_vulnerability_intel_async(self, query: str) -> str:
        """Async-safe search that runs the blocking IO in a threadpool."""
        if not self.settings.enabled:
            return "BLOCKED: vulnerability-intelligence search is disabled in config.yaml."

        try:
            clean_query = sanitize_query(query)
        except ValueError as exc:
            return f"BLOCKED: {exc}"

        cached = self._get_cached(clean_query)
        if cached is not None:
            return cached

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self._do_search, clean_query)
        self._store_cache(clean_query, result)
        return result

    def _get_cached(self, query: str) -> str | None:
        if query in self._cache:
            cached_at, result = self._cache[query]
            if time.monotonic() - cached_at < self._cache_ttl:
                self._cache.move_to_end(query)
                return result
            del self._cache[query]
        return None

    def _store_cache(self, query: str, result: str) -> None:
        self._cache[query] = (time.monotonic(), result)
        if len(self._cache) > self._cache_max:
            self._cache.popitem(last=False)

    def _do_search(self, clean_query: str) -> str:
        defensive_query = f"{clean_query} vulnerability CVE advisory remediation"
        params = {
            "engine": self.settings.engine,
            "q": defensive_query,
            "kl": self.settings.region,
        }

        api_key = os.environ.get(self.settings.api_key_env, "").strip()
        if api_key:
            params["api_key"] = api_key

        url = self.settings.endpoint + "?" + urllib.parse.urlencode(params)
        try:
            with urllib.request.urlopen(url, timeout=self.settings.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:800]
            return (
                f"ERROR: SerpAPI returned HTTP {exc.code}. "
                f"Set {self.settings.api_key_env} if your account requires an API key.\n{body}"
            )
        except urllib.error.URLError as exc:
            return f"ERROR: search request failed: {exc}"
        except json.JSONDecodeError:
            return "ERROR: search response was not valid JSON."

        return format_search_results(payload, url, self.settings.max_results)


def sanitize_query(query: str) -> str:
    text = " ".join(str(query).strip().split())
    if not text:
        raise ValueError("empty search queries are not allowed.")
    if len(text) > 180:
        raise ValueError("search query is too long.")
    if PRIVATE_IP_PATTERN.search(text):
        raise ValueError("do not send private IP addresses or local hostnames to web search.")

    lowered = text.lower()
    for term in BLOCKED_QUERY_TERMS:
        if term in lowered:
            raise ValueError(f"blocked search term {term!r} is not allowed.")

    if re.search(r"[;&|<>`$\\\n\r]", text):
        raise ValueError("shell metacharacters are not allowed in search queries.")
    if not re.fullmatch(r"[A-Za-z0-9 ._:/()+,\-#]{1,180}", text):
        raise ValueError("query contains unsupported characters.")
    return text


def format_search_results(payload: dict[str, Any], url: str, max_results: int) -> str:
    if "error" in payload:
        return f"ERROR: SerpAPI error: {payload['error']}"

    organic_results = payload.get("organic_results") or payload.get("results") or []
    rows: list[str] = [
        "SEARCH_URL:",
        redact_api_key(url),
        "",
        "RESULTS:",
    ]
    if not organic_results:
        rows.append("No organic results returned.")
        return "\n".join(rows)

    for index, item in enumerate(organic_results[:max_results], start=1):
        title = str(item.get("title") or "Untitled").strip()
        link = str(item.get("link") or item.get("url") or "").strip()
        snippet = str(item.get("snippet") or item.get("description") or "").strip()
        rows.extend(
            [
                f"{index}. {title}",
                f"   URL: {link}",
                f"   Summary: {snippet[:500]}",
            ]
        )
    return "\n".join(rows)


def redact_api_key(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    redacted = [
        (key, "***" if key == "api_key" else value)
        for key, value in query
    ]
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(redacted), parsed.fragment)
    )
