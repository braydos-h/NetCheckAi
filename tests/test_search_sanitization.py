"""Tests for search query sanitization."""

import pytest

from tools.search_tools import sanitize_query


def test_simple_query_allowed():
    assert sanitize_query("apache httpd 2.4") == "apache httpd 2.4"


def test_empty_query_rejected():
    with pytest.raises(ValueError, match="empty"):
        sanitize_query("")


def test_private_ip_rejected():
    with pytest.raises(ValueError, match="private IP"):
        sanitize_query("192.168.1.1 vulnerability")


def test_blocked_term_rejected():
    with pytest.raises(ValueError, match="blocked search term"):
        sanitize_query("metasploit exploit")


def test_shell_metacharacters_rejected():
    with pytest.raises(ValueError, match="shell metacharacters"):
        sanitize_query("apache; rm -rf /")


def test_too_long_rejected():
    with pytest.raises(ValueError, match="too long"):
        sanitize_query("a" * 200)
