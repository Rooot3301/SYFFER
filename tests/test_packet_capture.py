"""Tests de syffer.core.packet_capture."""

from __future__ import annotations

from pathlib import Path

import pytest

from syffer.core.packet_capture import capture, summarize_packet


class _FakePacket:
    def __init__(self, summary: str = "TCP 1.1.1.1 > 2.2.2.2", src: str = "1.1.1.1", dst: str = "2.2.2.2", length: int = 64):
        self._summary = summary
        self._src = src
        self._dst = dst
        self._length = length
        self.time = 12345.6
        self.src = src
        self.dst = dst

    def summary(self) -> str:
        return self._summary

    def __len__(self) -> int:
        return self._length


def test_capture_calls_sniff_and_writes_pcap(mocker, tmp_extract_dir: Path):
    fake_packets = [_FakePacket() for _ in range(3)]
    mock_sniff = mocker.patch("syffer.core.packet_capture.sniff", return_value=fake_packets)
    mock_wrpcap = mocker.patch("syffer.core.packet_capture.wrpcap")

    result, raw = capture(count=3, bpf_filter=None, iface=None, timeout=None)

    mock_sniff.assert_called_once_with(count=3, filter=None, iface=None, timeout=None)
    mock_wrpcap.assert_called_once()
    assert len(result.packets) == 3
    assert result.pcap_path.parent == tmp_extract_dir
    assert result.pcap_path.suffix == ".pcap"
    assert raw == fake_packets


def test_capture_validates_bpf(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.core.packet_capture.sniff", return_value=[])
    mocker.patch("syffer.core.packet_capture.wrpcap")

    with pytest.raises(ValueError):
        capture(count=1, bpf_filter="tcp; rm -rf /", iface=None, timeout=None)


def test_capture_passes_valid_bpf(mocker, tmp_extract_dir: Path):
    mock_sniff = mocker.patch("syffer.core.packet_capture.sniff", return_value=[])
    mocker.patch("syffer.core.packet_capture.wrpcap")

    capture(count=1, bpf_filter="tcp port 443", iface=None, timeout=None)
    kwargs = mock_sniff.call_args.kwargs
    assert kwargs["filter"] == "tcp port 443"


def test_summarize_packet_extracts_fields():
    packet = _FakePacket(summary="ICMP echo", src="10.0.0.1", dst="10.0.0.2", length=98)
    summary = summarize_packet(index=0, packet=packet)
    assert summary.index == 0
    assert summary.summary == "ICMP echo"
    assert summary.length == 98
    assert summary.timestamp == 12345.6
