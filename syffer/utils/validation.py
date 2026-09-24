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


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-.]*[A-Za-z0-9])?$")
_MAX_HOSTNAME_LEN = 253
_PORTS_RE = re.compile(r"^[0-9,\-]+$")


def validate_hostname(name: str) -> str:
    if not name:
        raise ValueError("hostname vide")
    if len(name) > _MAX_HOSTNAME_LEN:
        raise ValueError(f"hostname trop long (max {_MAX_HOSTNAME_LEN})")
    if ".." in name:
        raise ValueError("hostname contient '..'")
    if not _HOSTNAME_RE.match(name):
        raise ValueError(f"hostname invalide : {name}")
    return name


def validate_target(target: str) -> str:
    """Cible d'un scan : IP, CIDR ou hostname."""
    for candidate in (validate_ip, validate_cidr, validate_hostname):
        try:
            return candidate(target)
        except ValueError:
            continue
    raise ValueError(f"cible invalide : {target}")


def validate_ports(spec: str) -> str:
    if not spec:
        raise ValueError("spec de ports vide")
    if not _PORTS_RE.match(spec):
        raise ValueError(f"spec de ports invalide : {spec}")
    for chunk in spec.split(","):
        if "-" in chunk:
            parts = chunk.split("-")
            if len(parts) != 2:
                raise ValueError(f"plage invalide : {chunk}")
            try:
                lo, hi = int(parts[0]), int(parts[1])
            except ValueError as exc:
                raise ValueError(f"plage non numerique : {chunk}") from exc
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"plage hors bornes : {chunk}")
        else:
            try:
                n = int(chunk)
            except ValueError as exc:
                raise ValueError(f"port non numerique : {chunk}") from exc
            if not (1 <= n <= 65535):
                raise ValueError(f"port hors bornes : {n}")
    return spec
