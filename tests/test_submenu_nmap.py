"""Tests du sous-menu nmap."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from syffer.cli import submenu_nmap
from syffer.cli.session import Session
from syffer.core.models import NmapScan


def test_run_refuses_when_nmap_missing(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = False
    mocker.patch("syffer.cli.submenu_nmap.nt.NmapTool", return_value=fake_tool)
    mock_error = mocker.patch("syffer.cli.display.error")

    submenu_nmap.run(Session())
    mock_error.assert_called_once()


def test_run_returns_on_retour(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    mocker.patch("syffer.cli.submenu_nmap.nt.NmapTool", return_value=fake_tool)
    mocker.patch("questionary.select", return_value=MagicMock(ask=lambda: "Retour"))
    mock_port_scan = mocker.patch("syffer.cli.submenu_nmap.port_scan")

    submenu_nmap.run(Session())
    mock_port_scan.assert_not_called()


def test_run_dispatches_to_port_scan(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    mocker.patch("syffer.cli.submenu_nmap.nt.NmapTool", return_value=fake_tool)
    mocker.patch(
        "questionary.select",
        return_value=MagicMock(ask=lambda: "Quick (top 100 ports)"),
    )
    mocker.patch("syffer.cli.prompts.ask_target", return_value="1.2.3.4")
    mocker.patch(
        "questionary.confirm",
        return_value=MagicMock(ask=lambda: True),
    )
    fake_scan = NmapScan(
        target="1.2.3.4", profile="Quick", started_at=0.0, duration_s=1.0,
        hosts=(), nmap_version="7.94", xml_path=None,
    )
    mock_port_scan = mocker.patch(
        "syffer.cli.submenu_nmap.port_scan", return_value=fake_scan
    )
    mocker.patch("syffer.cli.display.render_nmap_scan")
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)

    submenu_nmap.run(Session())
    mock_port_scan.assert_called_once()
    kwargs = mock_port_scan.call_args.kwargs
    assert kwargs["target"] == "1.2.3.4"
    assert kwargs["profile_name"] == "Quick"


def test_build_custom_profile_all_toggles():
    profile = submenu_nmap._build_custom_profile(True, True, True, True)
    assert "-sV" in profile
    assert "-sC" in profile
    assert "-O" in profile
    assert "-Pn" in profile


def test_build_custom_profile_none():
    profile = submenu_nmap._build_custom_profile(False, False, False, False)
    assert "-sV" not in profile
    assert "-sC" not in profile
    assert "-O" not in profile
    assert "-Pn" not in profile
