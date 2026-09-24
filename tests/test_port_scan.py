"""Tests de syffer.core.port_scan."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from syffer.core.nmap_tool import QUICK
from syffer.core.port_scan import port_scan

_XML = b"""<?xml version="1.0"?>
<nmaprun version="7.94" start="0">
  <host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
    </ports>
  </host>
  <runstats><finished elapsed="1.0"/></runstats>
</nmaprun>"""


def test_port_scan_validates_target(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.core.port_scan.NmapTool")
    with pytest.raises(ValueError):
        port_scan("bad target!!!", QUICK, profile_name="Quick")


def test_port_scan_refuses_when_nmap_missing(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = False
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)

    with pytest.raises(FileNotFoundError):
        port_scan("1.2.3.4", QUICK, profile_name="Quick")


def test_port_scan_writes_xml_and_returns_scan(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    fake_tool.run_scan.return_value = _XML
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)

    scan = port_scan("1.2.3.4", QUICK, profile_name="Quick")

    assert scan.target == "1.2.3.4"
    assert scan.profile == "Quick"
    assert scan.xml_path is not None
    assert scan.xml_path.exists()
    assert scan.xml_path.parent == tmp_extract_dir
    assert scan.hosts[0].ports[0].service == "ssh"


def test_port_scan_enriches_only_open_ports_with_banner(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    fake_tool.run_scan.return_value = _XML
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)
    mock_banner = mocker.patch(
        "syffer.core.port_scan.grab_banner", return_value="SSH-2.0-OpenSSH"
    )

    scan = port_scan("1.2.3.4", QUICK, profile_name="Quick", banner=True)

    assert mock_banner.call_count == 1
    mock_banner.assert_called_once_with("1.2.3.4", 22)

    port_22 = next(p for p in scan.hosts[0].ports if p.port == 22)
    port_80 = next(p for p in scan.hosts[0].ports if p.port == 80)
    assert port_22.banner == "SSH-2.0-OpenSSH"
    assert port_80.banner is None


def test_port_scan_skips_banner_when_disabled(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    fake_tool.run_scan.return_value = _XML
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)
    mock_banner = mocker.patch("syffer.core.port_scan.grab_banner")

    port_scan("1.2.3.4", QUICK, profile_name="Quick", banner=False)
    mock_banner.assert_not_called()


def test_port_scan_validates_ports(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    fake_tool.run_scan.return_value = _XML
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)

    with pytest.raises(ValueError):
        port_scan("1.2.3.4", QUICK, profile_name="Quick", ports="99999")
