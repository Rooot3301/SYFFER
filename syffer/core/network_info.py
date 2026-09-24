"""Informations reseau de la machine (hostname, IP locale, gateway)."""

from __future__ import annotations

import socket

import psutil

from syffer.core.interfaces import list_interfaces
from syffer.core.models import NetworkInfo


def get_local_ip(timeout: float = 1.0) -> str | None:
    """Renvoie l'IP locale sortante (aucun paquet reellement envoye)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def get_default_gateway() -> str | None:
    """Renvoie la passerelle par defaut, ou None si non determinable.

    psutil ne l'expose pas de facon cross-platform ; on renvoie None
    par defaut (limitation documentee en Phase 0).
    """
    try:
        # Reference psutil pour eviter un import inutilise; extension
        # possible en Phase suivante via parsing plateforme.
        _ = getattr(psutil, "net_if_stats", None)
        return None
    except Exception:
        return None


def get_network_info() -> NetworkInfo:
    """Compose une NetworkInfo complete (hostname, IP, gateway, interfaces)."""
    return NetworkInfo(
        hostname=socket.gethostname(),
        local_ip=get_local_ip(),
        default_gateway=get_default_gateway(),
        interfaces=list_interfaces(),
    )
