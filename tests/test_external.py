"""Tests de syffer.core.external."""

from __future__ import annotations

import subprocess

import pytest

from syffer.core.external import ExternalTool


def test_available_true(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    tool = ExternalTool("nmap")
    assert tool.available() is True


def test_available_false(mocker):
    mocker.patch("shutil.which", return_value=None)
    tool = ExternalTool("nmap")
    assert tool.available() is False


def test_run_calls_subprocess(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    mock_run = mocker.patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess(args=["nmap", "-v"], returncode=0, stdout=b"ok", stderr=b""),
    )
    tool = ExternalTool("nmap")
    result = tool.run(["-v"])
    mock_run.assert_called_once()
    assert result.returncode == 0


def test_run_raises_when_missing(mocker):
    mocker.patch("shutil.which", return_value=None)
    tool = ExternalTool("nmap")
    with pytest.raises(FileNotFoundError):
        tool.run(["-v"])
