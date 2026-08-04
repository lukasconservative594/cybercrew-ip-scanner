"""Config, subject state, OUI lookup, NetBIOS encoding and the engine."""

from __future__ import annotations

import ipaddress
import struct

import pytest

from ipscanner.core import oui, portscan
from ipscanner.core.config import Config
from ipscanner.core.pingers import PingResult
from ipscanner.core.scanner import ScanStats, Scanner
from ipscanner.core.ranges import ListFeeder
from ipscanner.core.subject import HostState, ScanningSubject, ScanResult
from ipscanner.fetchers.base import Fetcher
from ipscanner.fetchers.netbios import _encode_name, _parse_reply


@pytest.fixture
def config(tmp_path):
    return Config(path=tmp_path / "config.json")


class TestConfig:
    def test_defaults_available(self, config):
        assert config.int_of("max_threads") > 0
        assert config.get("ping_method") == "combined"

    def test_round_trip(self, config, tmp_path):
        config.set("max_threads", 42)
        assert config.save()
        assert Config(path=tmp_path / "config.json").int_of("max_threads") == 42

    def test_int_clamping(self, config):
        config.set("max_threads", 99999)
        assert config.int_of("max_threads", 1, 1024) == 1024
        config.set("max_threads", "nonsense")
        assert config.int_of("max_threads") > 0

    def test_unknown_keys_ignored_on_load(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text('{"max_threads": 7, "bogus_key": 1}', encoding="utf-8")
        loaded = Config(path=path)
        assert loaded.int_of("max_threads") == 7
        assert "bogus_key" not in loaded.as_dict()

    def test_corrupt_file_falls_back_to_defaults(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text("{not json at all", encoding="utf-8")
        assert Config(path=path).int_of("max_threads") > 0


class TestSubjectState:
    def test_promote_never_downgrades(self, config):
        subject = ScanningSubject(ipaddress.ip_address("10.0.0.1"), config)
        subject.promote(HostState.WITH_PORTS)
        subject.promote(HostState.ALIVE)
        assert subject.state is HostState.WITH_PORTS

    def test_set_state_can_downgrade(self, config):
        subject = ScanningSubject(ipaddress.ip_address("10.0.0.1"), config)
        subject.promote(HostState.ALIVE)
        subject.set_state(HostState.DEAD)
        assert subject.state is HostState.DEAD

    def test_scratchpad(self, config):
        subject = ScanningSubject(ipaddress.ip_address("10.0.0.1"), config)
        assert not subject.has("mac")
        subject.set("mac", "AA:BB:CC:DD:EE:FF")
        assert subject.get("mac") == "AA:BB:CC:DD:EE:FF"


class TestScanResultDisplay:
    def _result(self, values):
        return ScanResult(ipaddress.ip_address("10.0.0.1"), HostState.ALIVE, values)

    def test_missing_key_is_not_scanned(self):
        assert self._result({}).display("ports", "[n/a]", "[n/s]") == "[n/s]"

    def test_none_value_is_not_available(self):
        assert self._result({"ports": None}).display("ports", "[n/a]", "[n/s]") == "[n/a]"

    def test_empty_list_is_not_available(self):
        assert self._result({"ports": []}).display("ports", "[n/a]", "[n/s]") == "[n/a]"

    def test_list_is_joined(self):
        assert self._result({"ports": [80, 443]}).display("ports") == "80, 443"


class TestPingResult:
    def test_loss_and_averages(self):
        result = PingResult(sent=4, received=2, times=[10.0, 30.0])
        assert result.alive
        assert result.average == 20.0
        assert result.best == 10.0
        assert result.worst == 30.0
        assert result.packet_loss == 50

    def test_no_replies(self):
        result = PingResult(sent=3, received=0)
        assert not result.alive
        assert result.packet_loss == 100
        assert result.average == 0.0

    def test_merge_keeps_first_method_that_answered(self):
        icmp = PingResult(sent=2, received=0, method="")
        tcp = PingResult(sent=1, received=1, times=[5.0], method="TCP", open_port=443)
        merged = icmp.merge(tcp)
        assert merged.received == 1
        assert merged.method == "TCP"
        assert merged.open_port == 443


class TestOUI:
    @pytest.mark.parametrize("mac,expected", [
        ("00:0C:29:11:22:33", "vmware"),
        ("08:00:27:AA:BB:CC", "virtualbox"),
        ("00:15:5D:01:02:03", "hyper-v"),
        ("52:54:00:AA:BB:CC", "qemu"),
        ("B8:27:EB:01:02:03", "raspberry pi"),
    ])
    def test_platform_is_identifiable(self, mac, expected):
        # The IEEE registrant alone is often unhelpful ("PCS Systemtechnik
        # GmbH"), so the hypervisor/SBC hint must survive into the result.
        vendor = oui.lookup(mac)
        assert vendor and expected in vendor.lower()

    def test_hint_annotates_rather_than_replaces_the_registrant(self):
        assert oui.lookup("08:00:27:AA:BB:CC") == "PCS Systemtechnik GmbH (VirtualBox)"

    def test_hint_not_duplicated_when_registrant_already_says_it(self):
        assert oui.lookup("00:0C:29:11:22:33") == "VMware, Inc."

    def test_platform_hint_lookup(self):
        assert oui.platform_hint("00:15:5D:01:02:03") == "Hyper-V"
        assert oui.platform_hint("BC:F1:05:89:57:F6") is None

    def test_separator_insensitive(self):
        assert oui.lookup("000C29112233") == oui.lookup("00-0C-29-11-22-33")

    def test_randomised_address_flagged(self):
        assert oui.is_randomised("62:4C:FA:66:6A:2A")
        assert not oui.is_randomised("00:0C:29:11:22:33")

    def test_unknown_returns_none_or_randomised(self):
        assert oui.lookup("") is None
        assert oui.lookup("ZZ") is None


class TestNetBIOS:
    def test_name_encoding_length(self):
        encoded = _encode_name("*")
        assert len(encoded) == 32
        assert encoded.startswith(b"CK")  # '*' is 0x2A -> 'C','K'

    def test_parse_reply_extracts_names_and_mac(self):
        header = struct.pack("!HHHHHH", 0x1234, 0x8400, 0, 1, 0, 0)
        answer = b"\x20" + _encode_name("*") + b"\x00"
        answer += struct.pack("!HHIH", 0x0021, 0x0001, 0, 0)

        names = b""
        names += b"WORKSTATION-1  " + bytes([0x00]) + struct.pack("!H", 0x0400)
        names += b"WORKGROUP      " + bytes([0x00]) + struct.pack("!H", 0x8400)
        names += b"ALICE          " + bytes([0x03]) + struct.pack("!H", 0x0400)
        payload = header + answer + bytes([3]) + names
        payload += bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])

        info = _parse_reply(payload)
        assert info is not None
        assert info.computer == "WORKSTATION-1"
        assert info.workgroup == "WORKGROUP"
        assert info.user == "ALICE"
        assert info.mac == "DE:AD:BE:EF:00:01"

    def test_messenger_entry_matching_computer_is_not_a_user(self):
        header = struct.pack("!HHHHHH", 0x1234, 0x8400, 0, 1, 0, 0)
        answer = b"\x20" + _encode_name("*") + b"\x00"
        answer += struct.pack("!HHIH", 0x0021, 0x0001, 0, 0)
        names = b"PC01           " + bytes([0x00]) + struct.pack("!H", 0x0400)
        names += b"PC01           " + bytes([0x03]) + struct.pack("!H", 0x0400)
        payload = header + answer + bytes([2]) + names + b"\x00" * 6
        info = _parse_reply(payload)
        assert info.computer == "PC01"
        assert info.user == ""

    def test_truncated_reply_is_safe(self):
        assert _parse_reply(b"\x00" * 10) is None


class TestPortScanHelpers:
    def test_service_names(self):
        assert portscan.service_name(22) == "ssh"
        assert portscan.service_name(3389) == "rdp"
        assert portscan.service_name(64999) == ""

    def test_http_summary_pulls_server_header(self):
        raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nDate: x\r\n\r\n"
        assert portscan._http_summary(raw) == "HTTP/1.1 200 OK (nginx/1.24.0)"

    def test_clean_strips_control_characters(self):
        assert portscan._clean(b"SSH-2.0-OpenSSH_9.2\r\n") == "SSH-2.0-OpenSSH_9.2"

    def test_empty_port_list_returns_nothing(self):
        result = portscan.scan_ports("127.0.0.1", 2, [], timeout=0.1)
        assert result.open_ports == [] and not result.has_open


class _StubFetcher(Fetcher):
    """Marks every host alive so the engine has something to count."""

    id = "stub"
    name = "Stub"
    requires_alive = False
    order = 1

    def scan(self, subject):
        subject.promote(HostState.ALIVE)
        return "ok"


class _DeadFetcher(Fetcher):
    id = "dead_only"
    name = "Dead only"
    requires_alive = True
    order = 2

    def scan(self, subject):
        return "ran"


class TestScannerEngine:
    def test_runs_every_address(self, config):
        config.set("max_threads", 4)
        feeder = ListFeeder([f"10.9.9.{i}" for i in range(1, 21)])
        results = []
        scanner = Scanner(feeder, [_StubFetcher()], config,
                          on_result=results.append, display="all")
        stats = scanner.run()
        assert stats.scanned == 20
        assert stats.alive == 20
        assert len(results) == 20
        assert {r.ip for r in results} == {f"10.9.9.{i}" for i in range(1, 21)}

    def test_display_filter_limits_emitted_rows(self, config):
        config.set("max_threads", 2)
        feeder = ListFeeder(["10.9.9.1", "10.9.9.2"])
        emitted = []
        Scanner(feeder, [_StubFetcher()], config,
                on_result=emitted.append, display="ports").run()
        assert emitted == []  # alive, but no open ports

    def test_dead_hosts_skip_alive_only_fetchers(self, config):
        config.set("max_threads", 2)
        config.set("scan_dead_hosts", False)
        feeder = ListFeeder(["10.9.9.1"])
        results = []
        Scanner(feeder, [_DeadFetcher()], config,
                on_result=results.append, display="all").run()
        assert len(results) == 1
        # The key must be absent, which renders as "not scanned".
        assert "dead_only" not in results[0].values

    def test_broken_fetcher_does_not_stop_the_scan(self, config):
        class Exploding(Fetcher):
            id = "boom"
            name = "Boom"
            requires_alive = False
            order = 5

            def scan(self, subject):
                raise RuntimeError("deliberate")

        config.set("max_threads", 2)
        errors = []
        results = []
        stats = Scanner(ListFeeder(["10.9.9.1", "10.9.9.2"]),
                        [_StubFetcher(), Exploding()], config,
                        on_result=results.append,
                        on_error=lambda where, exc: errors.append(where),
                        display="all").run()
        assert stats.scanned == 2
        assert len(results) == 2
        assert len(errors) == 2
        assert all(r.values["boom"] is None for r in results)


class TestScanStats:
    def test_percentages_and_summary(self):
        stats = ScanStats(total=200, scanned=50, alive=10, with_ports=3, open_ports=7)
        assert stats.percent == 25
        assert stats.dead == 40
        assert "10 alive" in stats.summary()

    def test_zero_total_is_safe(self):
        assert ScanStats(total=0, scanned=0).percent == 0
