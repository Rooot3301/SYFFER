"""Capture de paquets reseau avec filtres BPF."""

from __future__ import annotations

import logging
from typing import Any

from scapy.all import sniff, wrpcap  # type: ignore[import-untyped]

from syffer.core.models import CaptureResult, PacketSummary
from syffer.utils.paths import resolve_extract_dir, timestamped_name
from syffer.utils.validation import validate_bpf

logger = logging.getLogger(__name__)


def summarize_packet(index: int, packet: Any) -> PacketSummary:
    """Convertit un paquet scapy en PacketSummary serialisable."""
    try:
        summary = packet.summary()
    except Exception:
        summary = repr(packet)
    src = getattr(packet, "src", None)
    dst = getattr(packet, "dst", None)
    protocol = packet.__class__.__name__ if hasattr(packet, "__class__") else None
    try:
        length = len(packet)
    except Exception:
        length = 0
    timestamp = float(getattr(packet, "time", 0.0))
    return PacketSummary(
        index=index,
        timestamp=timestamp,
        summary=summary,
        src=src,
        dst=dst,
        protocol=protocol,
        length=length,
    )


def capture(
    count: int,
    bpf_filter: str | None = None,
    iface: str | None = None,
    timeout: int | None = None,
) -> tuple[CaptureResult, list[Any]]:
    """Capture `count` paquets (ou jusqu'a `timeout`s) avec filtre BPF optionnel.

    Retourne (CaptureResult, packets_raw). CaptureResult est serialisable
    (utilise par les exporters), packets_raw contient les objets scapy
    bruts (utilises pour l'affichage detaille en session).
    """
    if bpf_filter is not None:
        bpf_filter = validate_bpf(bpf_filter)
    logger.debug("capture: count=%d filter=%s iface=%s timeout=%s", count, bpf_filter, iface, timeout)
    packets = sniff(count=count, filter=bpf_filter, iface=iface, timeout=timeout)

    extract = resolve_extract_dir()
    pcap_path = extract / timestamped_name("capture", "pcap")
    wrpcap(str(pcap_path), packets)
    logger.info("pcap ecrit : %s", pcap_path)

    summaries = tuple(summarize_packet(i, p) for i, p in enumerate(packets))
    result = CaptureResult(
        pcap_path=pcap_path,
        packets=summaries,
        bpf_filter=bpf_filter,
        iface=iface,
    )
    return result, list(packets)
