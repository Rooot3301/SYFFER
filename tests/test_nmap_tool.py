"""Tests de syffer.core.nmap_tool."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from syffer.core.nmap_tool import (
    AGGRESSIVE,
    OS_DETECTION,
    QUICK,
    SERVICE_VERSION,
    NmapTool,
)


def test_available_false(mocker):
    mocker.patch("shutil.which", return_value=None)
    assert NmapTool().available() is False


def test_run_scan_refuses_when_missing(mocker):
    mocker.patch("shutil.which", return_value=None)
    with pytest.raises(FileNotFoundError):
        NmapTool().run_scan(target="1.2.3.4", profile=QUICK)


def test_run_scan_builds_command_with_quick_profile(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    completed = MagicMock()
    completed.returncode = 0
    completed.stdout = b"<nmaprun/>"
    completed.stderr = b""
    mock_run = mocker.patch("subprocess.run", return_value=completed)

    result = NmapTool().run_scan(target="1.2.3.4", profile=QUICK)

    assert result == b"<nmaprun/>"
    called_args = mock_run.call_args.args[0]
    assert called_args[0] == "/usr/bin/nmap"
    assert "-T4" in called_args
    assert "-F" in called_args
    assert "-oX" in called_args
    assert "-" in called_args
    assert "1.2.3.4" in called_args


def test_run_scan_appends_ports(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    completed = MagicMock(returncode=0, stdout=b"<nmaprun/>", stderr=b"")
    mock_run = mocker.patch("subprocess.run", return_value=completed)

    NmapTool().run_scan(target="1.2.3.4", profile=SERVICE_VERSION, ports="22,80")
    called_args = mock_run.call_args.args[0]
    assert "-p" in called_args
    p_index = called_args.index("-p")
    assert called_args[p_index + 1] == "22,80"


def test_run_scan_rejects_unsafe_target(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    mocker.patch("subprocess.run")
    with pytest.raises(AssertionError):
        NmapTool().run_scan(target="1.2.3.4; rm -rf /", profile=QUICK)


def test_run_scan_raises_on_nonzero_exit(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    mocker.patch(
        "subprocess.run",
        return_value=MagicMock(returncode=1, stdout=b"", stderr=b"boom"),
    )
    with pytest.raises(RuntimeError):
        NmapTool().run_scan(target="1.2.3.4", profile=QUICK)


def test_version_parses_output(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    mocker.patch(
        "subprocess.run",
        return_value=MagicMock(
            returncode=0,
            stdout=b"Nmap version 7.94 ( https://nmap.org )\n",
            stderr=b"",
        ),
    )
    assert NmapTool().version() == "7.94"


def test_version_none_when_missing(mocker):
    mocker.patch("shutil.which", return_value=None)
    assert NmapTool().version() is None


def test_aggressive_profile_contains_A_flag():
    assert "-A" in AGGRESSIVE


def test_os_detection_profile_contains_O_and_Pn():
    assert "-O" in OS_DETECTION
    assert "-Pn" in OS_DETECTION
