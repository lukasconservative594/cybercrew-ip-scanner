"""Export formats."""

from __future__ import annotations

import csv
import ipaddress
import json
import xml.etree.ElementTree as ET

import pytest

from ipscanner import fetchers as fetchers_pkg
from ipscanner.core.subject import HostState, ScanResult
from ipscanner.exporters import ExportError, export, format_for


@pytest.fixture
def results():
    return [
        ScanResult(ipaddress.ip_address("192.168.1.1"), HostState.WITH_PORTS, {
            "ip": "192.168.1.1", "ping": 2, "hostname": "gateway.lan",
            "ports": "80,443",
        }, 1),
        ScanResult(ipaddress.ip_address("192.168.1.9"), HostState.ALIVE, {
            "ip": "192.168.1.9", "ping": 11, "hostname": None, "ports": None,
        }, 2),
        ScanResult(ipaddress.ip_address("192.168.1.20"), HostState.DEAD, {
            "ip": "192.168.1.20", "ping": None,
        }, 3),
    ]


@pytest.fixture
def columns():
    return fetchers_pkg.create(["ip", "ping", "hostname", "ports"])


def test_format_inferred_from_extension():
    assert format_for("out.csv") == "csv"
    assert format_for("out.HTML") == "html"
    assert format_for("out.unknown") == "csv"


def test_unknown_format_rejected(tmp_path, results, columns):
    with pytest.raises(ExportError):
        export(results, tmp_path / "x.dat", columns, fmt="pdf")


class TestCSV:
    def test_headers_and_rows(self, tmp_path, results, columns):
        path = tmp_path / "out.csv"
        assert export(results, path, columns) == 3

        with open(path, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        assert rows[0] == ["Status", "IP", "Ping", "Hostname", "Open Ports"]
        assert rows[1][:3] == ["Open ports", "192.168.1.1", "2"]
        assert rows[3][0] == "Dead"

    def test_not_scanned_vs_not_available(self, tmp_path, results, columns):
        path = tmp_path / "out.csv"
        export(results, path, columns, not_available="NA", not_scanned="NS")
        with open(path, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        # Row 2 was pinged but had no hostname -> NA. Row 3 was dead, so the
        # hostname fetcher never ran -> NS.
        assert rows[2][3] == "NA"
        assert rows[3][3] == "NS"


class TestJSON:
    def test_structure(self, tmp_path, results, columns):
        path = tmp_path / "out.json"
        export(results, path, columns, feeder_info="192.168.1.0/24")
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["range"] == "192.168.1.0/24"
        assert [c["id"] for c in payload["columns"]] == ["ip", "ping", "hostname", "ports"]
        assert len(payload["hosts"]) == 3
        assert payload["hosts"][0]["ip"] == "192.168.1.1"
        assert payload["hosts"][0]["status"] == "Open ports"


class TestXML:
    def test_well_formed(self, tmp_path, results, columns):
        path = tmp_path / "out.xml"
        export(results, path, columns, feeder_info="test-range")
        root = ET.parse(path).getroot()
        assert root.tag == "scan"
        assert root.get("range") == "test-range"
        hosts = root.findall("host")
        assert len(hosts) == 3
        assert hosts[0].get("ip") == "192.168.1.1"
        fields = {f.get("id"): f.text for f in hosts[0].findall("field")}
        assert fields["ports"] == "80,443"


class TestIPPortList:
    def test_expands_every_open_port(self, tmp_path, results, columns):
        path = tmp_path / "out.txt"
        written = export(results, path, columns, fmt="lst")
        lines = path.read_text(encoding="utf-8").split()
        assert written == 2
        assert lines == ["192.168.1.1:80", "192.168.1.1:443"]

    def test_expands_port_ranges(self, tmp_path, columns):
        result = ScanResult(ipaddress.ip_address("10.0.0.1"), HostState.WITH_PORTS,
                            {"ip": "10.0.0.1", "ports": "80-82"})
        path = tmp_path / "out.txt"
        assert export([result], path, columns, fmt="lst") == 3
        assert path.read_text(encoding="utf-8").split() == [
            "10.0.0.1:80", "10.0.0.1:81", "10.0.0.1:82",
        ]

    def test_accepts_list_values(self, tmp_path, columns):
        result = ScanResult(ipaddress.ip_address("10.0.0.1"), HostState.WITH_PORTS,
                            {"ip": "10.0.0.1", "ports": [22, 443]})
        path = tmp_path / "out.txt"
        assert export([result], path, columns, fmt="lst") == 2


class TestText:
    def test_columns_are_aligned(self, tmp_path, results, columns):
        path = tmp_path / "out.txt"
        export(results, path, columns, fmt="txt")
        body = path.read_text(encoding="utf-8")
        assert "CyberCrew IP Scanner" in body
        assert "192.168.1.1" in body
        data_lines = [l for l in body.splitlines() if l.startswith(("Open ports", "Alive", "Dead"))]
        # Every data row should place the IP at the same offset.
        offsets = {line.index("192.168.1") for line in data_lines}
        assert len(offsets) == 1


class TestHTML:
    def test_self_contained_report(self, tmp_path, results, columns):
        path = tmp_path / "out.html"
        export(results, path, columns, feeder_info="192.168.1.0/24")
        body = path.read_text(encoding="utf-8")
        assert body.lstrip().startswith("<!doctype html>")
        assert "192.168.1.0/24" in body
        assert "gateway.lan" in body
        # No external requests: the report must work offline.
        assert "http://" not in body.replace("http://www.w3.org", "")
        assert "<script" not in body.lower()

    def test_escapes_markup_in_values(self, tmp_path, columns):
        nasty = ScanResult(ipaddress.ip_address("10.0.0.1"), HostState.ALIVE,
                           {"ip": "10.0.0.1", "hostname": "<img src=x onerror=alert(1)>"})
        path = tmp_path / "out.html"
        export([nasty], path, columns)
        body = path.read_text(encoding="utf-8")
        assert "<img src=x" not in body
        assert "&lt;img" in body


def test_empty_result_set(tmp_path, columns):
    for fmt in ("csv", "txt", "xml", "json", "lst", "html"):
        path = tmp_path / f"empty.{fmt}"
        assert export([], path, columns, fmt=fmt) == 0
        assert path.exists()
