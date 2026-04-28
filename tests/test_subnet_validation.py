"""Tests for subnet validation."""

import ipaddress

import pytest

from tools.nmap_tools import validate_subnet


def test_valid_rfc1918_subnet():
    network = validate_subnet("192.168.1.0/24")
    assert network == ipaddress.ip_network("192.168.1.0/24")


def test_valid_10_subnet():
    network = validate_subnet("10.0.0.0/8")
    assert network == ipaddress.ip_network("10.0.0.0/8")


def test_invalid_public_subnet():
    with pytest.raises(ValueError, match="outside RFC1918"):
        validate_subnet("8.8.8.0/24")


def test_loopback_rejected():
    with pytest.raises(ValueError, match="not an allowed local LAN range"):
        validate_subnet("127.0.0.0/24")


def test_multicast_rejected():
    with pytest.raises(ValueError, match="not an allowed local LAN range"):
        validate_subnet("224.0.0.0/24")


def test_overly_broad_rejected():
    with pytest.raises(ValueError, match="above the configured max_subnet_addresses"):
        validate_subnet("10.0.0.0/8", max_subnet_addresses=1000)
