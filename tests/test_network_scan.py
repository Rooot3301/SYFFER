"""Tests de syffer.core.network_scan."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from syffer.core.network_scan import arp_scan, lookup_vendor


def test_arp_scan_validates_cidr(mocker):
    mocker.patch("syffer.core.network_scan.srp", return_value=([], []))
    with pytest.raises(ValueError):
        arp_scan("not-a-cidr")


def test_arp_scan_returns_hosts(mocker):
    fake_reply = MagicMock()
    fake_reply.psrc = "192.168.1.10"
    fake_reply.hwsrc = "aa:bb:cc:dd:ee:ff"
    mocker.patch(
        "syffer.core.network_scan.srp",
        return_value=([(MagicMock(), fake_reply)], []),
    )
    mocker.patch("syffer.core.network_scan.lookup_vendor", return_value="TestVendor")

    result = arp_scan("192.168.1.0/24", timeout=1)
    assert result.cidr == "192.168.1.0/24"
    assert len(result.hosts) == 1
    assert result.hosts[0].ip == "192.168.1.10"
    assert result.hosts[0].mac == "aa:bb:cc:dd:ee:ff"
    assert result.hosts[0].vendor == "TestVendor"
    assert result.duration_s >= 0


def test_arp_scan_normalizes_cidr(mocker):
    mocker.patch("syffer.core.network_scan.srp", return_value=([], []))
    result = arp_scan("192.168.1.5/24", timeout=1)
    assert result.cidr == "192.168.1.0/24"


def test_lookup_vendor_returns_none_when_manuf_missing(mocker):
    mocker.patch("syffer.core.network_scan._MANUF", None)
    assert lookup_vendor("aa:bb:cc:dd:ee:ff") is None
