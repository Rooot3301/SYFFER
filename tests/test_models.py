"""Tests des dataclasses de syffer.core.models."""

from __future__ import annotations

from pathlib import Path

import pytest

from syffer.core.models import (
    CaptureResult,
    GeoInfo,
    Host,
    Interface,
    InterfaceAddress,
    NetworkInfo,
    PacketSummary,
    ScanResult,
)


def test_interface_is_frozen():
    iface = Interface(name="eth0", mac="aa:bb:cc:dd:ee:ff", is_up=True, mtu=1500, addresses=())
    with pytest.raises(Exception):
        iface.name = "eth1"  # type: ignore[misc]


def test_host_equality():
    h1 = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", vendor="Foo")
    h2 = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", vendor="Foo")
    assert h1 == h2


def test_scan_result_hosts_is_tuple():
    result = ScanResult(cidr="192.168.1.0/24", started_at=0.0, duration_s=1.5, hosts=())
    assert isinstance(result.hosts, tuple)


def test_capture_result_carries_bpf():
    result = CaptureResult(
        pcap_path=Path("/tmp/x.pcap"),
        packets=(),
        bpf_filter="tcp port 443",
        iface=None,
    )
    assert result.bpf_filter == "tcp port 443"


def test_geo_info_status_field():
    g = GeoInfo(ip="1.1.1.1", country="AU", city=None, region=None, lat=-33.0, lon=151.0, isp=None, status="success")
    assert g.status == "success"


def test_network_info_composition():
    addr = InterfaceAddress(family="AF_INET", address="192.168.1.10", netmask="255.255.255.0", broadcast="192.168.1.255")
    iface = Interface(name="eth0", mac=None, is_up=True, mtu=1500, addresses=(addr,))
    info = NetworkInfo(hostname="test", local_ip="192.168.1.10", default_gateway="192.168.1.1", interfaces=(iface,))
    assert info.interfaces[0].addresses[0].address == "192.168.1.10"


def test_packet_summary_fields():
    p = PacketSummary(index=0, timestamp=1234.5, summary="TCP ...", src="1.1.1.1", dst="2.2.2.2", protocol="TCP", length=64)
    assert p.protocol == "TCP"


from syffer.core.models import NmapHost, NmapPort, NmapScan, NmapScript


def test_nmap_port_is_frozen():
    p = NmapPort(port=80, proto="tcp", state="open", service="http",
                 product=None, version=None, banner=None)
    with pytest.raises(Exception):
        p.port = 443  # type: ignore[misc]


def test_nmap_host_carries_scripts():
    scripts = (NmapScript(id="http-title", output="Welcome"),)
    ports = (NmapPort(port=80, proto="tcp", state="open", service="http",
                     product=None, version=None, banner=None),)
    host = NmapHost(ip="1.2.3.4", hostname=None, state="up",
                    os_guess=None, os_accuracy=None, ports=ports, scripts=scripts)
    assert host.scripts[0].id == "http-title"
    assert host.ports[0].port == 80


def test_nmap_scan_composition():
    scan = NmapScan(target="1.2.3.4", profile="quick", started_at=0.0,
                    duration_s=1.0, hosts=(), nmap_version="7.94",
                    xml_path=None)
    assert scan.hosts == ()
    assert scan.nmap_version == "7.94"
