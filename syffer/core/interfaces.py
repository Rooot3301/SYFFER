"""Enumeration des interfaces reseau (via psutil, cross-platform)."""

from __future__ import annotations

import socket

import psutil

from syffer.core.models import Interface, InterfaceAddress

_LINK_FAMILIES: set[int] = set()
if hasattr(psutil, "AF_LINK"):
    _LINK_FAMILIES.add(int(psutil.AF_LINK))
if hasattr(socket, "AF_PACKET"):
    _LINK_FAMILIES.add(int(socket.AF_PACKET))


def _family_name(family: int) -> str:
    if family in _LINK_FAMILIES:
        return "AF_LINK"
    try:
        return socket.AddressFamily(family).name  # type: ignore[arg-type]
    except (ValueError, AttributeError):
        return str(family)


def list_interfaces() -> tuple[Interface, ...]:
    """Enumere les interfaces reseau de la machine.

    Retourne un tuple d'Interface avec adresses, MAC, etat up/down et MTU.
    Ne fait aucune I/O reseau.
    """
    addrs_map = psutil.net_if_addrs()
    stats_map = psutil.net_if_stats()

    interfaces: list[Interface] = []
    for name, addrs in addrs_map.items():
        mac: str | None = None
        addresses: list[InterfaceAddress] = []
        for a in addrs:
            family_int = int(a.family)
            if family_int in _LINK_FAMILIES:
                mac = a.address
                continue
            addresses.append(
                InterfaceAddress(
                    family=_family_name(family_int),
                    address=a.address,
                    netmask=a.netmask,
                    broadcast=a.broadcast,
                )
            )
        stats = stats_map.get(name)
        interfaces.append(
            Interface(
                name=name,
                mac=mac,
                is_up=bool(stats.isup) if stats else False,
                mtu=int(stats.mtu) if stats else None,
                addresses=tuple(addresses),
            )
        )
    return tuple(interfaces)
