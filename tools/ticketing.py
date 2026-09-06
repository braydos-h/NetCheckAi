"""Remediation ticket generation — outbound-only Jira/GitHub ticket creation.

Generates a ticket payload from a confirmed finding (``TechnicalFinding``-
shaped dict) and POSTs it to a Jira or GitHub Issues endpoint. Outbound-only:
no target touch, no inbound surface. The token is read from the named env var
(``ticketing.token_env``) — NEVER copied into config or logs.

Failure modes:
- ticket API down → retry with exponential backoff, then drop (do not block).
- auth missing (env var unset) → no-op, log once.
- field mapping missing → skip the field, don't crash.
- rate limit (HTTP 429) → back off using ``Retry-After`` when present.

The provider is selected by ``ticketing.provider`` (``"jira"`` or
``"github"``). Each provider has a small field-mapping table; missing fields
are skipped (not crashed on). The ticket payload is built from
``build_ticket_payload(finding)`` which is pure + testable without network.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger("tools.ticketing")

_DEFAULTS = {
    "enabled": False,
    "provider": "",
    "base_url": "",
    "token_env": "TICKETING_TOKEN",
    "project_key": "",
    "max_retries": 3,
    "backoff_seconds": 2.0,
}

_logged_missing_token = False


def _load_ticketing_config(config: dict[str, Any] | None) -> dict[str, Any]:
    cfg = (config or {}).get("ticketing", {}) or {}
    if not isinstance(cfg, dict):
        return dict(_DEFAULTS)
    merged = dict(_DEFAULTS)
    merged.update(cfg)
    return merged


def build_ticket_payload(
    finding: dict[str, Any],
    *,
    provider: str,
    project_key: str = "",
) -> dict[str, Any]:
    """Build a provider-specific ticket payload from a confirmed finding.

    Pure + side-effect-free: no network, no config read. The finding dict is
    the shape ``TechnicalFinding.to_dict()`` returns. Missing fields are
    skipped (not crashed on). Returns ``{}`` for an unknown provider.
    """
    title = str(finding.get("title") or finding.get("finding_id") or "Untitled finding")
    severity = str(finding.get("severity") or "unknown")
    asset = str(finding.get("affected_asset") or "")
    vuln_class = str(finding.get("vuln_class") or "")
    summary = str(finding.get("summary") or "")
    remediation = str(finding.get("remediation") or "")
    repro = finding.get("reproduction_steps") or []
    if not isinstance(repro, list):
        repro = []
    refs = finding.get("references") or []
    if not isinstance(refs, list):
        refs = []
    cvss = finding.get("cvss") or {}
    cvss_score = cvss.get("base_score") if isinstance(cvss, dict) else None

    body_lines = [
        f"**Severity:** {severity}",
        f"**Affected asset:** {asset}",
        f"**Vulnerability class:** {vuln_class}",
    ]
    if cvss_score is not None:
        body_lines.append(f"**CVSS:** {cvss_score}")
    if summary:
        body_lines.append(f"\n**Summary**\n{summary}")
    if repro:
        body_lines.append("\n**Reproduction steps**")
        body_lines.extend(f"1. {step}" for step in repro)
    if remediation:
        body_lines.append(f"\n**Remediation**\n{remediation}")
    if refs:
        body_lines.append("\n**References**")
        body_lines.extend(f"- {r}" for r in refs)
    body = "\n".join(body_lines)

    provider = (provider or "").strip().lower()
    if provider == "jira":
        return {
            "fields": {
                "project": {"key": project_key or "SEC"},
                "summary": title[:200],
                "description": body,
                "issuetype": {"name": "Bug"},
                "labels": ["security", f"severity-{severity.lower()}"],
            }
        }
    if provider == "github":
        return {
            "title": title[:200],
            "body": body,
            "labels": ["security", f"severity:{severity.lower()}"],
        }
    return {}


def _post_ticket(
    url: str,
    payload: bytes,
    headers: dict[str, str],
    timeout: int,
) -> tuple[bool, str, dict[str, str]]:
    """POST ``payload`` to ``url``. Returns (ok, status, response_headers)."""
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (200 <= resp.status < 300), f"HTTP {resp.status}", dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}", dict(exc.headers or {})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"{type(exc).__name__}: {exc}", {}


def create_ticket(
    finding: dict[str, Any],
    config: dict[str, Any] | None = None,
    *,
    timeout_seconds: int = 10,
    require_signoff: bool = False,
) -> dict[str, Any]:
    """Create a remediation ticket from a confirmed finding.

    Returns ``{"created": bool, "url": str, "status": str}``. On failure
    (API down, auth missing, rate limit) returns ``{"created": False, ...}``
    and never raises — ticketing is best-effort and must not block the run.
    With ``require_signoff=True``, findings whose ``verify_status`` is not
    ``VERIFIED`` (verify-or-it-didn't-happen) are held and never ticketed.
    """
    global _logged_missing_token
    cfg = _load_ticketing_config(config)
    if require_signoff and str(finding.get("verify_status") or "") != "VERIFIED":
        return {
            "created": False,
            "status": f"held: finding not VERIFIED (verify_status={finding.get('verify_status') or 'HOLDING'})",
            "url": "",
        }
    if not cfg.get("enabled"):
        return {"created": False, "status": "disabled", "url": ""}
    provider = str(cfg.get("provider") or "").strip().lower()
    if provider not in ("jira", "github"):
        return {"created": False, "status": f"unknown provider: {provider!r}", "url": ""}
    base_url = str(cfg.get("base_url") or "").strip()
    if not base_url:
        return {"created": False, "status": "base_url not configured", "url": ""}
    token = os.environ.get(str(cfg.get("token_env") or "TICKETING_TOKEN"), "").strip()
    if not token:
        if not _logged_missing_token:
            log.info("ticketing: token env var %s not set; no-op", cfg.get("token_env"))
            _logged_missing_token = True
        return {"created": False, "status": "auth missing (token env var unset)", "url": ""}

    project_key = str(cfg.get("project_key") or "")
    payload_dict = build_ticket_payload(finding, provider=provider, project_key=project_key)
    if not payload_dict:
        return {"created": False, "status": "field mapping missing", "url": ""}
    payload = json.dumps(payload_dict).encode("utf-8")

    # Resolve the provider endpoint URL.
    if provider == "jira":
        url = base_url.rstrip("/") + "/rest/api/2/issue"
    else:  # github
        url = base_url.rstrip("/") + "/issues"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "BreachPilot-ticketing/0.1",
    }
    if provider == "jira":
        headers["Authorization"] = f"Bearer {token}"
    else:  # github
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"

    max_retries = int(cfg.get("max_retries", 3))
    backoff = float(cfg.get("backoff_seconds", 2.0))
    import time as _time

    last_status = ""
    for attempt in range(max_retries):
        ok, status, resp_headers = _post_ticket(url, payload, headers, timeout_seconds)
        if ok:
            # Best-effort: extract the ticket URL from the response.
            ticket_url = resp_headers.get("Location", "") or resp_headers.get("location", "")
            return {"created": True, "status": status, "url": ticket_url}
        last_status = status
        # Rate limit: honor Retry-After if present.
        retry_after = resp_headers.get("Retry-After") or resp_headers.get("retry-after")
        if retry_after:
            try:
                _time.sleep(min(float(retry_after), 60.0))
                continue
            except (TypeError, ValueError):
                pass
        if attempt + 1 < max_retries:
            _time.sleep(backoff * (2**attempt))
    log.warning(
        "ticketing: dropped finding %s after %d attempts: %s", finding.get("finding_id", "?"), max_retries, last_status
    )
    return {"created": False, "status": last_status, "url": ""}


__all__ = ["build_ticket_payload", "create_ticket"]
