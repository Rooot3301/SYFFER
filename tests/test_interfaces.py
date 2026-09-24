"""Tests de syffer.core.interfaces."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

import psutil

from syffer.core.interfaces import list_interfaces


def test_list_interfaces_maps_psutil(mocker):
    fake_addr = MagicMock()
    fake_addr.family = socket.AF_INET
    fake_addr.address = "192.168.1.10"
    fake_addr.netmask = "255.255.255.0"
    fake_addr.broadcast = "192.168.1.255"

    fake_mac = MagicMock()
    fake_mac.family = psutil.AF_LINK if hasattr(psutil, "AF_LINK") else -1
    fake_mac.address = "aa:bb:cc:dd:ee:ff"
    fake_mac.netmask = None
    fake_mac.broadcast = None

    fake_stats = MagicMock()
    fake_stats.isup = True
    fake_stats.mtu = 1500

    mocker.patch("psutil.net_if_addrs", return_value={"eth0": [fake_addr, fake_mac]})
    mocker.patch("psutil.net_if_stats", return_value={"eth0": fake_stats})

    result = list_interfaces()
    assert len(result) == 1
    iface = result[0]
    assert iface.name == "eth0"
    assert iface.is_up is True
    assert iface.mtu == 1500
    assert iface.mac == "aa:bb:cc:dd:ee:ff"
    assert len(iface.addresses) == 1
    assert iface.addresses[0].address == "192.168.1.10"


def test_list_interfaces_handles_missing_stats(mocker):
    fake_addr = MagicMock()
    fake_addr.family = socket.AF_INET
    fake_addr.address = "10.0.0.1"
    fake_addr.netmask = None
    fake_addr.broadcast = None

    mocker.patch("psutil.net_if_addrs", return_value={"lo": [fake_addr]})
    mocker.patch("psutil.net_if_stats", return_value={})

    result = list_interfaces()
    assert len(result) == 1
    assert result[0].name == "lo"
    assert result[0].is_up is False
    assert result[0].mtu is None
    assert result[0].mac is None


def test_list_interfaces_returns_tuple(mocker):
    mocker.patch("psutil.net_if_addrs", return_value={})
    mocker.patch("psutil.net_if_stats", return_value={})
    result = list_interfaces()
    assert isinstance(result, tuple)
    assert result == ()
