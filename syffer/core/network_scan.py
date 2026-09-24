"""Scan ARP du reseau local via scapy."""

from __future__ import annotations

import logging
import time

from scapy.all import ARP, Ether, srp  # type: ignore[import-untyped]

from syffer.core.models import Host, ScanResult
from syffer.utils.validation import validate_cidr

logger = logging.getLogger(__name__)

try:
    from scapy.data import MANUFDB as _MANUF  # type: ignore[import-untyped]
except Exception:
    _MANUF = None  # type: ignore[assignment]


def lookup_vendor(mac: str) -> str | None:
    """Lookup local du vendor via scapy.data.MANUFDB. None si indisponible."""
    if _MANUF is None:
        return None
    try:
        return _MANUF._get_manuf(mac)  # type: ignore[attr-defined]
    except Exception:
        return None


def arp_scan(cidr: str, timeout: int = 3) -> ScanResult:
    """Envoie un ARP broadcast sur le CIDR et collecte les reponses."""
    normalized = validate_cidr(cidr)
    logger.debug("arp_scan: cidr=%s timeout=%d", normalized, timeout)

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=normalized)
    started = time.time()
    answered, _ = srp(request, timeout=timeout, verbose=0)
    duration = time.time() - started

    hosts = tuple(
        Host(ip=reply.psrc, mac=reply.hwsrc, vendor=lookup_vendor(reply.hwsrc))
        for _sent, reply in answered
    )
    logger.info("scan ARP termine : %d hosts en %.2fs", len(hosts), duration)

    return ScanResult(
        cidr=normalized,
        started_at=started,
        duration_s=duration,
        hosts=hosts,
    )
