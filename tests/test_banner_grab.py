"""Tests de syffer.core.banner_grab."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

from syffer.core.banner_grab import grab_banner


def test_grab_banner_returns_stripped_string(mocker):
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.create_connection", return_value=fake_sock)

    assert grab_banner("1.2.3.4", 22) == "SSH-2.0-OpenSSH_8.9"


def test_grab_banner_returns_none_on_timeout(mocker):
    mocker.patch("socket.create_connection", side_effect=socket.timeout())
    assert grab_banner("1.2.3.4", 22) is None


def test_grab_banner_returns_none_on_refused(mocker):
    mocker.patch("socket.create_connection", side_effect=ConnectionRefusedError())
    assert grab_banner("1.2.3.4", 22) is None


def test_grab_banner_returns_none_on_empty(mocker):
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b""
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.create_connection", return_value=fake_sock)

    assert grab_banner("1.2.3.4", 22) is None


def test_grab_banner_decodes_latin1(mocker):
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b"\xff\xfe hello"
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.create_connection", return_value=fake_sock)

    result = grab_banner("1.2.3.4", 22)
    assert result is not None
    assert "hello" in result
