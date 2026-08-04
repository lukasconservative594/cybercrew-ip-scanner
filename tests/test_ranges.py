"""Range, feeder and port parsing."""

from __future__ import annotations

import ipaddress

import pytest

from ipscanner.core.ranges import (
    RandomFeeder, RangeError, RangeFeeder, format_ports, is_broadcastish,
    netmask_to_prefix, parse_ports, parse_range_text, range_of_network,
)


class TestParseRangeText:
    @pytest.mark.parametrize("text,start,end", [
        ("192.168.1.1", "192.168.1.1", "192.168.1.1"),
        ("192.168.1.1-192.168.1.50", "192.168.1.1", "192.168.1.50"),
        ("192.168.1.1-50", "192.168.1.1", "192.168.1.50"),
        ("192.168.1.0/24", "192.168.1.0", "192.168.1.255"),
        ("10.0.0.0/8", "10.0.0.0", "10.255.255.255"),
        ("192.168.1.0/255.255.255.0", "192.168.1.0", "192.168.1.255"),
        ("192.168.1.*", "192.168.1.0", "192.168.1.255"),
        ("10.0.*.*", "10.0.0.0", "10.0.255.255"),
    ])
    def test_shapes(self, text, start, end):
        got_start, got_end = parse_range_text(text)
        assert str(got_start) == start
        assert str(got_end) == end

    def test_ipv6_cidr(self):
        start, end = parse_range_text("2001:db8::/126")
        assert str(start) == "2001:db8::"
        assert str(end) == "2001:db8::3"

    @pytest.mark.parametrize("bad", ["", "not-an-address", "999.999.999.999"])
    def test_rejects_nonsense(self, bad):
        with pytest.raises(RangeError):
            parse_range_text(bad)


class TestNetmask:
    @pytest.mark.parametrize("value,expected", [
        ("255.255.255.0", 24), ("255.255.0.0", 16), ("/24", 24), ("24", 24),
        ("255.255.255.252", 30),
    ])
    def test_accepts_forms(self, value, expected):
        assert netmask_to_prefix(value) == expected

    def test_rejects_bad_mask(self):
        with pytest.raises(RangeError):
            netmask_to_prefix("255.0.255.0")

    def test_range_of_network(self):
        start, end = range_of_network(ipaddress.ip_address("192.168.1.77"), 24)
        assert (str(start), str(end)) == ("192.168.1.0", "192.168.1.255")


class TestRangeFeeder:
    def test_counts_and_iterates(self):
        feeder = RangeFeeder("192.168.1.10", "192.168.1.20")
        addresses = list(feeder)
        assert len(feeder) == 11
        assert len(addresses) == 11
        assert str(addresses[0]) == "192.168.1.10"
        assert str(addresses[-1]) == "192.168.1.20"

    def test_reversed_endpoints_are_normalised(self):
        feeder = RangeFeeder("192.168.1.50", "192.168.1.10")
        assert str(feeder.start) == "192.168.1.10"
        assert len(feeder) == 41

    def test_len_matches_iteration_when_skipping_broadcast(self):
        # The fast count must agree with what iteration actually yields.
        feeder = RangeFeeder("192.168.0.0", "192.168.3.255", skip_broadcast=True)
        assert len(feeder) == len(list(feeder)) == 1024 - 8

    def test_skip_broadcast_removes_edges(self):
        feeder = RangeFeeder("192.168.1.0", "192.168.1.255", skip_broadcast=True)
        addresses = {str(a) for a in feeder}
        assert "192.168.1.0" not in addresses
        assert "192.168.1.255" not in addresses
        assert len(addresses) == 254

    def test_partial_range_skip_count(self):
        feeder = RangeFeeder("192.168.1.250", "192.168.2.5", skip_broadcast=True)
        assert len(feeder) == len(list(feeder))

    def test_mixed_families_rejected(self):
        with pytest.raises(RangeError):
            RangeFeeder("192.168.1.1", "2001:db8::1")

    def test_from_text(self):
        feeder = RangeFeeder.from_text("10.0.0.0/30")
        assert len(feeder) == 4
        assert feeder.info == "10.0.0.0 - 10.0.0.3"


class TestRandomFeeder:
    def test_yields_requested_count_inside_network(self):
        feeder = RandomFeeder("10.1.2.3", 24, 25, seed=7)
        addresses = list(feeder)
        assert len(addresses) == len(feeder) == 25
        network = ipaddress.ip_network("10.1.2.0/24")
        assert all(a in network for a in addresses)

    def test_seed_is_reproducible(self):
        a = list(RandomFeeder("10.1.2.3", 24, 10, seed=99))
        b = list(RandomFeeder("10.1.2.3", 24, 10, seed=99))
        assert a == b


class TestPorts:
    @pytest.mark.parametrize("text,expected", [
        ("80", [80]),
        ("80,443", [80, 443]),
        ("1-5", [1, 2, 3, 4, 5]),
        ("443,80,443", [80, 443]),
        ("80, 443 ; 8080", [80, 443, 8080]),
        ("5-1", [1, 2, 3, 4, 5]),
    ])
    def test_parse(self, text, expected):
        assert parse_ports(text) == expected

    @pytest.mark.parametrize("bad", ["0", "65536", "abc", "1-70000"])
    def test_rejects_out_of_range(self, bad):
        with pytest.raises(RangeError):
            parse_ports(bad)

    def test_empty_is_empty(self):
        assert parse_ports("") == []

    @pytest.mark.parametrize("ports,expected", [
        ([80], "80"),
        ([80, 443], "80,443"),
        ([1, 2, 3], "1-3"),
        ([1, 2, 3, 80, 443, 444, 445], "1-3,80,443-445"),
        ([], ""),
    ])
    def test_format(self, ports, expected):
        assert format_ports(ports) == expected

    def test_round_trip(self):
        text = "22,80,443,8000-8010"
        assert format_ports(parse_ports(text)) == text


def test_is_broadcastish():
    assert is_broadcastish(ipaddress.ip_address("192.168.1.0"))
    assert is_broadcastish(ipaddress.ip_address("192.168.1.255"))
    assert not is_broadcastish(ipaddress.ip_address("192.168.1.1"))
    assert not is_broadcastish(ipaddress.ip_address("2001:db8::"))
