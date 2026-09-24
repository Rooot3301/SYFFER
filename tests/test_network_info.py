"""Tests de syffer.core.network_info."""

from __future__ import annotations

from unittest.mock import MagicMock

from syffer.core.network_info import get_local_ip, get_network_info
from syffer.core.models import Interface


def test_get_local_ip_returns_string(mocker):
    fake_sock = MagicMock()
    fake_sock.getsockname.return_value = ("192.168.1.42", 12345)
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.socket", return_value=fake_sock)

    assert get_local_ip() == "192.168.1.42"


def test_get_local_ip_returns_none_on_error(mocker):
    fake_sock = MagicMock()
    fake_sock.connect.side_effect = OSError("no route")
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.socket", return_value=fake_sock)

    assert get_local_ip() is None


def test_get_network_info_composes(mocker):
    mocker.patch("syffer.core.network_info.get_local_ip", return_value="10.0.0.5")
    mocker.patch("syffer.core.network_info.get_default_gateway", return_value="10.0.0.1")
    mocker.patch("syffer.core.network_info.socket.gethostname", return_value="testhost")
    mocker.patch(
        "syffer.core.network_info.list_interfaces",
        return_value=(Interface(name="lo", mac=None, is_up=True, mtu=65536, addresses=()),),
    )
    info = get_network_info()
    assert info.hostname == "testhost"
    assert info.local_ip == "10.0.0.5"
    assert info.default_gateway == "10.0.0.1"
    assert info.interfaces[0].name == "lo"
