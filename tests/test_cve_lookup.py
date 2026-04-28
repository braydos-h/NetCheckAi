"""Tests for tools/cve_lookup.py NVD API wrapper."""

from __future__ import annotations

import json
from unittest.mock import patch
import pytest

from tools.cve_lookup import (
    CVESearchSettings,
    CVEEntry,
    NVDClient,
    format_cve_results,
)


SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "description": [
                            {"lang": "en", "value": "CWE-502"}
                        ]
                    }
                ],
                "published": "2021-12-10T00:00:00.000",
                "references": [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
                ]
            }
        }
    ]
}


def test_parse_cve_entry():
    client = NVDClient(CVESearchSettings())
    entries = client._parse(SAMPLE_NVD_RESPONSE)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.cve_id == "CVE-2021-44228"
    assert entry.cvss_score == 10.0
    assert entry.severity == "CRITICAL"
    assert entry.cwe == "CWE-502"
    assert entry.published == "2021-12-10"
    assert "JNDI" in entry.description


def test_format_cve_results():
    entry = CVEEntry(
        cve_id="CVE-2021-44228",
        description="Log4j RCE",
        cvss_score=10.0,
        severity="CRITICAL",
        cwe="CWE-502",
        published="2021-12-10",
        references=["https://example.com"],
    )
    text = format_cve_results([entry], "log4j 2.14")
    assert "CVE-2021-44228" in text
    assert "10.0" in text
    assert "CWE-502" in text


def test_format_empty_results():
    text = format_cve_results([], "unknown thing")
    assert "No CVEs found" in text


@pytest.mark.asyncio
async def test_search_rate_limit_and_cache():
    client = NVDClient(CVESearchSettings(rate_limit_seconds=0.1))
    with patch.object(client, "_fetch_sync", return_value=[]) as mock_fetch:
        await client.search("test")
        await client.search("test")  # should be cached
        mock_fetch.assert_called_once()


@pytest.mark.asyncio
async def test_disabled_client_returns_empty():
    client = NVDClient(CVESearchSettings(enabled=False))
    result = await client.search("anything")
    assert result == []
