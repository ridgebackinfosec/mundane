"""Tests for mundane_pkg.parsing module."""

import pytest

from mundane_pkg.parsing import (
    split_host_port,
    is_ipv4,
    is_ipv6,
    is_hostname,
    is_valid_token,
    parse_hosts_ports,
    build_item_set,
    normalize_combos,
)


class TestSplitHostPort:
    """Tests for split_host_port function."""

    def test_ipv4_with_port(self):
        """Test IPv4 address with port."""
        host, port = split_host_port("192.168.1.1:80")
        assert host == "192.168.1.1"
        assert port == "80"

    def test_ipv4_without_port(self):
        """Test IPv4 address without port."""
        host, port = split_host_port("192.168.1.1")
        assert host == "192.168.1.1"
        assert port is None

    def test_ipv6_bracketed_with_port(self):
        """Test bracketed IPv6 address with port."""
        host, port = split_host_port("[2001:db8::1]:8080")
        assert host == "2001:db8::1"
        assert port == "8080"

    def test_ipv6_bare(self):
        """Test bare IPv6 address without port."""
        host, port = split_host_port("2001:db8::1")
        assert host == "2001:db8::1"
        assert port is None

    def test_ipv6_with_colons_no_brackets(self):
        """Test IPv6 with multiple colons (no port)."""
        host, port = split_host_port("fe80::1")
        assert host == "fe80::1"
        assert port is None

    def test_hostname_with_port(self):
        """Test hostname with port."""
        host, port = split_host_port("example.com:443")
        assert host == "example.com"
        assert port == "443"

    def test_hostname_without_port(self):
        """Test hostname without port."""
        host, port = split_host_port("example.com")
        assert host == "example.com"
        assert port is None

    def test_localhost_with_port(self):
        """Test localhost with port."""
        host, port = split_host_port("localhost:8080")
        assert host == "localhost"
        assert port == "8080"

    def test_empty_string(self):
        """Test empty string input."""
        host, port = split_host_port("")
        assert host is None
        assert port is None

    def test_port_only(self):
        """Test string with only port number."""
        host, port = split_host_port(":80")
        assert host == ""
        assert port == "80"

    def test_invalid_port(self):
        """Test invalid port number."""
        host, port = split_host_port("192.168.1.1:abc")
        assert host == "192.168.1.1:abc"
        assert port is None

    def test_port_zero(self):
        """Test port 0."""
        host, port = split_host_port("192.168.1.1:0")
        assert host == "192.168.1.1"
        assert port == "0"


class TestIPValidation:
    """Tests for IP address validation functions."""

    def test_is_ipv4_valid(self):
        """Test valid IPv4 addresses."""
        assert is_ipv4("192.168.1.1") is True
        assert is_ipv4("10.0.0.1") is True
        assert is_ipv4("172.16.0.1") is True
        assert is_ipv4("255.255.255.255") is True
        assert is_ipv4("0.0.0.0") is True

    def test_is_ipv4_invalid(self):
        """Test invalid IPv4 addresses."""
        assert is_ipv4("256.1.1.1") is False
        assert is_ipv4("192.168.1") is False
        assert is_ipv4("192.168.1.1.1") is False
        assert is_ipv4("example.com") is False
        assert is_ipv4("2001:db8::1") is False
        assert is_ipv4("") is False

    def test_is_ipv6_valid(self):
        """Test valid IPv6 addresses."""
        assert is_ipv6("2001:db8::1") is True
        assert is_ipv6("fe80::1") is True
        assert is_ipv6("::1") is True
        assert is_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001") is True
        assert is_ipv6("::ffff:192.0.2.1") is True  # IPv4-mapped IPv6

    def test_is_ipv6_invalid(self):
        """Test invalid IPv6 addresses."""
        assert is_ipv6("192.168.1.1") is False
        assert is_ipv6("example.com") is False
        assert is_ipv6("gggg::1") is False
        assert is_ipv6("") is False

    def test_is_hostname_valid(self):
        """Test valid hostnames."""
        assert is_hostname("example.com") is True
        assert is_hostname("sub.example.com") is True
        assert is_hostname("localhost") is True
        assert is_hostname("server01") is True
        assert is_hostname("test-server.local") is True

    def test_is_hostname_invalid(self):
        """Test invalid hostnames."""
        assert is_hostname("192.168.1.1") is False
        assert is_hostname("2001:db8::1") is False
        assert is_hostname("") is False
        assert is_hostname("-invalid") is False
        assert is_hostname("invalid-") is False


class TestIsValidToken:
    """Tests for is_valid_token function."""

    def test_valid_single_port(self):
        """Test valid single port number."""
        assert is_valid_token("80") is True
        assert is_valid_token("443") is True
        assert is_valid_token("8080") is True

    def test_valid_port_range(self):
        """Test valid port range."""
        assert is_valid_token("80-443") is True
        assert is_valid_token("1-65535") is True
        assert is_valid_token("8000-9000") is True

    def test_valid_ip_address(self):
        """Test valid IP address."""
        assert is_valid_token("192.168.1.1") is True
        assert is_valid_token("10.0.0.1") is True

    def test_valid_cidr(self):
        """Test valid CIDR notation."""
        assert is_valid_token("192.168.1.0/24") is True
        assert is_valid_token("10.0.0.0/8") is True

    def test_valid_hostname(self):
        """Test valid hostname."""
        assert is_valid_token("example.com") is True
        assert is_valid_token("localhost") is True

    def test_invalid_empty(self):
        """Test empty string."""
        assert is_valid_token("") is False

    def test_invalid_characters(self):
        """Test invalid characters."""
        assert is_valid_token("192.168.1.1;rm -rf") is False
        assert is_valid_token("test@example") is False

    def test_invalid_port_range(self):
        """Test invalid port ranges."""
        assert is_valid_token("80-") is False
        assert is_valid_token("-443") is False
        assert is_valid_token("443-80") is False  # Reversed range


class TestParseHostsPorts:
    """Tests for parse_hosts_ports function."""

    def test_basic_parsing(self, sample_hosts_list):
        """Test basic parsing of mixed host entries."""
        result = parse_hosts_ports(sample_hosts_list)

        assert "192.168.1.1" in result
        assert 80 in result["192.168.1.1"]
        assert "192.168.1.2" in result
        assert 443 in result["192.168.1.2"]

    def test_duplicate_removal(self):
        """Test that duplicates are removed."""
        hosts = ["192.168.1.1:80", "192.168.1.1:80", "192.168.1.1:443"]
        result = parse_hosts_ports(hosts)

        assert len(result["192.168.1.1"]) == 2
        assert 80 in result["192.168.1.1"]
        assert 443 in result["192.168.1.1"]

    def test_empty_list(self):
        """Test parsing empty list."""
        result = parse_hosts_ports([])
        assert result == {}

    def test_host_without_port(self):
        """Test host without port (should still be included)."""
        hosts = ["192.168.1.1", "192.168.1.1:80"]
        result = parse_hosts_ports(hosts)

        assert "192.168.1.1" in result
        assert None in result["192.168.1.1"]
        assert 80 in result["192.168.1.1"]

    def test_ipv6_parsing(self):
        """Test IPv6 address parsing."""
        hosts = ["[2001:db8::1]:8080", "2001:db8::2"]
        result = parse_hosts_ports(hosts)

        assert "2001:db8::1" in result
        assert 8080 in result["2001:db8::1"]
        assert "2001:db8::2" in result
        assert None in result["2001:db8::2"]


class TestBuildItemSet:
    """Tests for build_item_set function."""

    def test_single_items(self):
        """Test parsing single items."""
        result = build_item_set(["80", "443", "8080"])
        assert result == {80, 443, 8080}

    def test_port_ranges(self):
        """Test parsing port ranges."""
        result = build_item_set(["80-82"])
        assert result == {80, 81, 82}

    def test_mixed_items_and_ranges(self):
        """Test mixing single items and ranges."""
        result = build_item_set(["80", "443-445", "8080"])
        assert result == {80, 443, 444, 445, 8080}

    def test_overlapping_ranges(self):
        """Test overlapping ranges are deduplicated."""
        result = build_item_set(["80-85", "83-88"])
        assert result == {80, 81, 82, 83, 84, 85, 86, 87, 88}

    def test_empty_input(self):
        """Test empty input."""
        result = build_item_set([])
        assert result == set()

    def test_invalid_range(self):
        """Test invalid range (should be skipped or handled)."""
        result = build_item_set(["80", "invalid", "443"])
        # Should skip 'invalid' and continue
        assert 80 in result
        assert 443 in result


class TestNormalizeCombos:
    """Tests for normalize_combos function."""

    def test_basic_normalization(self):
        """Test basic host:port normalization."""
        items = ["192.168.1.1:80", "192.168.1.2:443"]
        result = normalize_combos(items)

        assert "192.168.1.1:80" in result
        assert "192.168.1.2:443" in result

    def test_ipv6_bracketing(self):
        """Test IPv6 addresses are properly bracketed."""
        items = ["[2001:db8::1]:8080", "2001:db8::2:9090"]
        result = normalize_combos(items)

        # Should normalize to bracketed format
        assert any("2001:db8::1" in item for item in result)

    def test_duplicate_removal(self):
        """Test duplicates are removed."""
        items = ["192.168.1.1:80", "192.168.1.1:80", "192.168.1.2:443"]
        result = normalize_combos(items)

        assert len(result) == 2

    def test_empty_input(self):
        """Test empty input."""
        result = normalize_combos([])
        assert result == []


@pytest.mark.parametrize(
    "input_str,expected_host,expected_port",
    [
        ("192.168.1.1:80", "192.168.1.1", "80"),
        ("10.0.0.1", "10.0.0.1", None),
        ("[::1]:8080", "::1", "8080"),
        ("example.com:443", "example.com", "443"),
        ("localhost", "localhost", None),
        ("", None, None),
    ],
)
def test_split_host_port_parametrized(input_str, expected_host, expected_port):
    """Parametrized test for split_host_port."""
    host, port = split_host_port(input_str)
    assert host == expected_host
    assert port == expected_port


@pytest.mark.parametrize(
    "ip,is_v4,is_v6",
    [
        ("192.168.1.1", True, False),
        ("10.0.0.1", True, False),
        ("2001:db8::1", False, True),
        ("::1", False, True),
        ("example.com", False, False),
        ("", False, False),
    ],
)
def test_ip_type_detection(ip, is_v4, is_v6):
    """Parametrized test for IP type detection."""
    assert is_ipv4(ip) == is_v4
    assert is_ipv6(ip) == is_v6
