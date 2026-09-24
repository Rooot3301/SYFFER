"""Validation et sanitisation des entrees utilisateur."""

from __future__ import annotations

import ipaddress
import re

_SAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")
_MAX_FILENAME_LEN = 100
_MAX_BPF_LEN = 200
_BPF_FORBIDDEN = ("`", ";", "|", "&", "$", "\n", "\r")


def safe_filename(name: str) -> str:
    """Renvoie un nom de fichier sanitize, ou leve ValueError.

    Rejette les noms vides/blancs, contenant `..`, un separateur de chemin,
    ou depassant 100 caracteres. Filtre les caracteres non
    [A-Za-z0-9._-] du nom retourne.
    """
    if not name or not name.strip():
        raise ValueError("nom de fichier vide")
    if len(name) > _MAX_FILENAME_LEN:
        raise ValueError(f"nom de fichier trop long (max {_MAX_FILENAME_LEN})")
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError("nom de fichier contient un separateur ou '..'")
    cleaned = _SAFE_FILENAME_CHARS.sub("", name)
    if not cleaned:
        raise ValueError("nom de fichier vide apres sanitisation")
    return cleaned


def validate_cidr(cidr: str) -> str:
    """Valide un CIDR IPv4/IPv6 et renvoie sa forme normalisee."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"CIDR invalide : {cidr}") from exc
    return str(network)


def validate_ip(ip: str) -> str:
    """Valide une adresse IP (v4 ou v6) et renvoie sa forme canonique."""
    if not ip:
        raise ValueError("adresse IP vide")
    try:
        address = ipaddress.ip_address(ip)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"adresse IP invalide : {ip}") from exc
    return str(address)


def validate_bpf(expr: str) -> str:
    """Valide une expression BPF (defense minimale contre injection)."""
    if not expr:
        raise ValueError("filtre BPF vide")
    if len(expr) > _MAX_BPF_LEN:
        raise ValueError(f"filtre BPF trop long (max {_MAX_BPF_LEN})")
    for forbidden in _BPF_FORBIDDEN:
        if forbidden in expr:
            raise ValueError(f"filtre BPF contient un caractere interdit : {forbidden!r}")
    return expr
