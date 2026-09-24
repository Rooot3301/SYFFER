"""Tests de syffer.reports.formatters."""

from __future__ import annotations

import json
from pathlib import Path

from syffer.core.models import (
    CaptureResult,
    GeoInfo,
    Host,
    Interface,
    NetworkInfo,
    PacketSummary,
    ScanResult,
)
from syffer.reports.formatters import to_csv, to_json, to_txt


def _sample_scan() -> ScanResult:
    return ScanResult(
        cidr="192.168.1.0/24",
        started_at=1700000000.0,
        duration_s=1.23,
        hosts=(
            Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", vendor="TestCo"),
            Host(ip="192.168.1.20", mac="11:22:33:44:55:66", vendor=None),
        ),
    )


def _sample_capture() -> CaptureResult:
    return CaptureResult(
        pcap_path=Path("/tmp/x.pcap"),
        packets=(
            PacketSummary(index=0, timestamp=1.0, summary="TCP", src="1.1.1.1", dst="2.2.2.2", protocol="TCP", length=64),
        ),
        bpf_filter="tcp",
        iface="eth0",
    )


def _sample_info() -> NetworkInfo:
    return NetworkInfo(
        hostname="host",
        local_ip="10.0.0.5",
        default_gateway=None,
        interfaces=(Interface(name="lo", mac=None, is_up=True, mtu=65536, addresses=()),),
    )


def _sample_geo() -> GeoInfo:
    return GeoInfo(
        ip="8.8.8.8", country="US", city="Mountain View", region="CA",
        lat=37.4, lon=-122.0, isp="Google", status="success",
    )


class TestToTxt:
    def test_scan(self):
        text = to_txt(_sample_scan())
        assert "192.168.1.0/24" in text
        assert "192.168.1.10" in text
        assert "aa:bb:cc:dd:ee:ff" in text
        assert "TestCo" in text

    def test_capture(self):
        text = to_txt(_sample_capture())
        assert "tcp" in text
        assert "TCP" in text

    def test_info(self):
        text = to_txt(_sample_info())
        assert "host" in text
        assert "10.0.0.5" in text
        assert "lo" in text

    def test_geo(self):
        text = to_txt(_sample_geo())
        assert "8.8.8.8" in text
        assert "US" in text


class TestToJson:
    def test_scan_roundtrip(self):
        payload = json.loads(to_json(_sample_scan()))
        assert payload["cidr"] == "192.168.1.0/24"
        assert len(payload["hosts"]) == 2

    def test_geo_roundtrip(self):
        payload = json.loads(to_json(_sample_geo()))
        assert payload["country"] == "US"


class TestToCsv:
    def test_scan_has_header_and_rows(self):
        csv_text = to_csv(_sample_scan())
        lines = csv_text.strip().splitlines()
        assert lines[0] == "ip,mac,vendor"
        assert len(lines) == 3

    def test_capture_has_header(self):
        csv_text = to_csv(_sample_capture())
        assert csv_text.splitlines()[0] == "index,timestamp,summary,src,dst,protocol,length"

    def test_info_has_header(self):
        csv_text = to_csv(_sample_info())
        assert csv_text.splitlines()[0] == "interface,mac,is_up,mtu,addresses"

    def test_geo_single_row(self):
        csv_text = to_csv(_sample_geo())
        lines = csv_text.strip().splitlines()
        assert lines[0] == "ip,country,city,region,lat,lon,isp,status"
        assert len(lines) == 2


from syffer.core.models import NmapHost, NmapPort, NmapScan, NmapScript


def _sample_nmap() -> NmapScan:
    return NmapScan(
        target="scanme.nmap.org",
        profile="Aggressive",
        started_at=0.0,
        duration_s=12.5,
        nmap_version="7.94",
        xml_path=None,
        hosts=(
            NmapHost(
                ip="45.33.32.156",
                hostname="scanme.nmap.org",
                state="up",
                os_guess="Linux 3.11 - 4.1",
                os_accuracy=95,
                ports=(
                    NmapPort(port=22, proto="tcp", state="open", service="ssh",
                             product="OpenSSH", version="6.6.1", banner="SSH-2.0"),
                    NmapPort(port=80, proto="tcp", state="open", service="http",
                             product="Apache", version="2.4.7", banner=None),
                ),
                scripts=(NmapScript(id="http-server-header", output="Apache/2.4.7"),),
            ),
        ),
    )


class TestNmapScanFormatters:
    def test_txt_contains_target_and_ports(self):
        text = to_txt(_sample_nmap())
        assert "scanme.nmap.org" in text
        assert "45.33.32.156" in text
        assert "22" in text
        assert "ssh" in text
        assert "OpenSSH" in text
        assert "Linux" in text

    def test_json_roundtrip(self):
        payload = json.loads(to_json(_sample_nmap()))
        assert payload["target"] == "scanme.nmap.org"
        assert payload["hosts"][0]["ports"][0]["service"] == "ssh"

    def test_csv_flattens_ports(self):
        csv_text = to_csv(_sample_nmap())
        lines = csv_text.strip().splitlines()
        assert lines[0].startswith("host_ip,hostname,os_guess,os_accuracy,port")
        assert len(lines) == 3
        assert "45.33.32.156" in csv_text
        assert "OpenSSH" in csv_text
