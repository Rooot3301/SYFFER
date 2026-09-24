"""Tests des handlers du menu (via mocks, pas d'I/O reelle)."""

from __future__ import annotations

from pathlib import Path

from syffer.cli import handlers
from syffer.cli.session import Session
from syffer.core.models import (
    CaptureResult,
    GeoInfo,
    NetworkInfo,
    ScanResult,
)


def test_handle_scan_calls_core(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_cidr", return_value="192.168.1.0/24")
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)
    mock_scan = mocker.patch(
        "syffer.core.network_scan.arp_scan",
        return_value=ScanResult(cidr="192.168.1.0/24", started_at=0.0, duration_s=0.1, hosts=()),
    )
    mocker.patch("syffer.cli.display.render_scan")

    handlers.handle_scan(Session())
    mock_scan.assert_called_once()


def test_handle_scan_handles_permission_error(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_cidr", return_value="192.168.1.0/24")
    mocker.patch("syffer.core.network_scan.arp_scan", side_effect=PermissionError())
    mock_error = mocker.patch("syffer.cli.display.error")

    handlers.handle_scan(Session())
    mock_error.assert_called_once()


def test_handle_capture_updates_session(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_int", return_value=5)
    mocker.patch("syffer.cli.prompts.ask_bpf", return_value=None)
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)
    fake_result = CaptureResult(
        pcap_path=tmp_extract_dir / "x.pcap", packets=(), bpf_filter=None, iface=None
    )
    mocker.patch("syffer.core.packet_capture.capture", return_value=(fake_result, ["raw1"]))
    mocker.patch("syffer.cli.display.render_capture")

    session = Session()
    handlers.handle_capture(session)
    assert session.last_capture is fake_result
    assert session.captured_packets == ["raw1"]


def test_handle_packet_details_no_capture(mocker):
    mock_error = mocker.patch("syffer.cli.display.error")
    handlers.handle_packet_details(Session())
    mock_error.assert_called_once()


def test_handle_geo_success(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_ip", return_value="8.8.8.8")
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)
    fake_geo = GeoInfo(
        ip="8.8.8.8", country="US", city="MV", region="CA",
        lat=37.4, lon=-122.0, isp="Google", status="success",
    )
    mocker.patch("syffer.core.geolocation.lookup", return_value=fake_geo)
    mock_render = mocker.patch("syffer.cli.display.render_geo")

    handlers.handle_geo(Session())
    mock_render.assert_called_once_with(fake_geo)


def test_handle_info_calls_render(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)
    fake_info = NetworkInfo(hostname="h", local_ip="1.2.3.4", default_gateway=None, interfaces=())
    mocker.patch("syffer.core.network_info.get_network_info", return_value=fake_info)
    mock_render = mocker.patch("syffer.cli.display.render_info")

    handlers.handle_info(Session())
    mock_render.assert_called_once_with(fake_info)


def test_handle_local_ip_success(mocker):
    mocker.patch("syffer.core.network_info.get_local_ip", return_value="10.0.0.5")
    mock_success = mocker.patch("syffer.cli.display.success")
    handlers.handle_local_ip(Session())
    mock_success.assert_called_once()


def test_handle_local_ip_failure(mocker):
    mocker.patch("syffer.core.network_info.get_local_ip", return_value=None)
    mock_error = mocker.patch("syffer.cli.display.error")
    handlers.handle_local_ip(Session())
    mock_error.assert_called_once()
