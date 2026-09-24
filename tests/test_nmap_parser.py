"""Tests de syffer.core.nmap_parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from syffer.core.nmap_parser import parse_xml

_FIXTURE = Path(__file__).parent / "fixtures" / "nmap-sample.xml"


def _sample_xml() -> bytes:
    return _FIXTURE.read_bytes()


def test_parse_valid_xml_has_one_host():
    scan = parse_xml(_sample_xml())
    assert len(scan.hosts) == 1


def test_parse_extracts_version():
    scan = parse_xml(_sample_xml())
    assert scan.nmap_version == "7.94"


def test_parse_extracts_ports():
    scan = parse_xml(_sample_xml())
    ports = scan.hosts[0].ports
    assert len(ports) == 3
    port_numbers = sorted(p.port for p in ports)
    assert port_numbers == [22, 80, 9929]


def test_parse_extracts_service_and_version():
    scan = parse_xml(_sample_xml())
    ssh = next(p for p in scan.hosts[0].ports if p.port == 22)
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version and ssh.version.startswith("6.6.1")


def test_parse_extracts_os_guess():
    scan = parse_xml(_sample_xml())
    host = scan.hosts[0]
    assert host.os_guess == "Linux 3.11 - 4.1"
    assert host.os_accuracy == 95


def test_parse_extracts_hostscripts():
    scan = parse_xml(_sample_xml())
    assert any(s.id == "http-server-header" for s in scan.hosts[0].scripts)


def test_parse_extracts_hostname():
    scan = parse_xml(_sample_xml())
    assert scan.hosts[0].hostname == "scanme.nmap.org"


def test_parse_extracts_state():
    scan = parse_xml(_sample_xml())
    assert scan.hosts[0].state == "up"


def test_parse_target_profile_pass_through():
    scan = parse_xml(_sample_xml(), target="scanme.nmap.org", profile="Aggressive")
    assert scan.target == "scanme.nmap.org"
    assert scan.profile == "Aggressive"


def test_parse_empty_bytes_raises():
    with pytest.raises(ValueError):
        parse_xml(b"")


def test_parse_malformed_raises():
    with pytest.raises(ValueError):
        parse_xml(b"<not-nmap/>")
