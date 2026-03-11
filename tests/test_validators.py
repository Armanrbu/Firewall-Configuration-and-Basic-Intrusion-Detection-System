"""
Tests for IP address and port validation helpers.
"""

import pytest
from utils.validators import (
    is_valid_ip,
    is_valid_ipv4,
    is_valid_cidr,
    is_valid_port,
    is_private_ip,
    normalise_ip,
)


class TestIsValidIp:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("0.0.0.0")
        assert is_valid_ip("255.255.255.255")

    def test_valid_ipv6(self):
        assert is_valid_ip("::1")
        assert is_valid_ip("2001:db8::1")

    def test_invalid_ip(self):
        assert not is_valid_ip("999.999.999.999")
        assert not is_valid_ip("not-an-ip")
        assert not is_valid_ip("")
        assert not is_valid_ip("192.168.1")
        assert not is_valid_ip("abc.def.ghi.jkl")


class TestIsValidIpv4:
    def test_ipv4(self):
        assert is_valid_ipv4("10.0.0.1")

    def test_ipv6_returns_false(self):
        assert not is_valid_ipv4("::1")

    def test_garbage(self):
        assert not is_valid_ipv4("not-an-ip")


class TestIsValidCidr:
    def test_valid_cidr(self):
        assert is_valid_cidr("192.168.0.0/24")
        assert is_valid_cidr("10.0.0.0/8")
        assert is_valid_cidr("0.0.0.0/0")

    def test_invalid_cidr(self):
        assert not is_valid_cidr("not-a-cidr")
        assert not is_valid_cidr("192.168.1.1/33")


class TestIsValidPort:
    def test_valid_ports(self):
        assert is_valid_port(1)
        assert is_valid_port(80)
        assert is_valid_port(65535)
        assert is_valid_port("443")

    def test_invalid_ports(self):
        assert not is_valid_port(0)
        assert not is_valid_port(65536)
        assert not is_valid_port(-1)
        assert not is_valid_port("abc")
        assert not is_valid_port(None)


class TestIsPrivateIp:
    def test_private(self):
        assert is_private_ip("192.168.1.1")
        assert is_private_ip("10.0.0.1")
        assert is_private_ip("127.0.0.1")
        assert is_private_ip("172.16.0.1")

    def test_public(self):
        assert not is_private_ip("8.8.8.8")
        assert not is_private_ip("1.1.1.1")


class TestNormaliseIp:
    def test_normalise(self):
        # IPv6 normalisation
        assert normalise_ip("::0001") == "::1"
        # Valid IPv4 round-trips unchanged
        assert normalise_ip("192.168.1.1") == "192.168.1.1"

    def test_invalid_passthrough(self):
        assert normalise_ip("invalid") == "invalid"
