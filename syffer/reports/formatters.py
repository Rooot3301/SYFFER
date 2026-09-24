"""Serialisation des resultats vers txt / json / csv."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from typing import Union

from syffer.core.models import (
    CaptureResult,
    GeoInfo,
    NetworkInfo,
    NmapScan,
    ScanResult,
)

Result = Union[CaptureResult, ScanResult, NetworkInfo, GeoInfo, NmapScan]


def to_json(result: Result) -> str:
    return json.dumps(asdict(result), default=str, indent=2, ensure_ascii=False)


def to_txt(result: Result) -> str:
    if isinstance(result, ScanResult):
        lines = [
            f"Scan ARP : {result.cidr}",
            f"Duree : {result.duration_s:.2f}s",
            f"Hosts detectes : {len(result.hosts)}",
            "-" * 60,
        ]
        for host in result.hosts:
            vendor = host.vendor or "?"
            lines.append(f"{host.ip:<18} {host.mac:<20} {vendor}")
        return "\n".join(lines) + "\n"

    if isinstance(result, CaptureResult):
        lines = [
            f"Capture : {len(result.packets)} paquets",
            f"Interface : {result.iface or 'defaut'}",
            f"Filtre BPF : {result.bpf_filter or 'aucun'}",
            f"PCAP : {result.pcap_path}",
            "-" * 60,
        ]
        for p in result.packets:
            lines.append(f"[{p.index}] {p.summary} ({p.length} octets)")
        return "\n".join(lines) + "\n"

    if isinstance(result, NetworkInfo):
        lines = [
            f"Hostname : {result.hostname}",
            f"IP locale : {result.local_ip or 'inconnue'}",
            f"Gateway : {result.default_gateway or 'inconnue'}",
            "-" * 60,
        ]
        for iface in result.interfaces:
            state = "UP" if iface.is_up else "DOWN"
            lines.append(f"{iface.name} [{state}] MAC={iface.mac or '?'} MTU={iface.mtu or '?'}")
            for a in iface.addresses:
                lines.append(f"    {a.family}: {a.address}")
        return "\n".join(lines) + "\n"

    if isinstance(result, GeoInfo):
        lines = [
            f"IP : {result.ip}",
            f"Pays : {result.country or '?'}",
            f"Ville : {result.city or '?'}",
            f"Region : {result.region or '?'}",
            f"Coordonnees : {result.lat}, {result.lon}",
            f"ISP : {result.isp or '?'}",
        ]
        return "\n".join(lines) + "\n"

    if isinstance(result, NmapScan):
        lines = [
            f"Scan nmap : {result.target}",
            f"Profil : {result.profile}",
            f"Version nmap : {result.nmap_version or '?'}",
            f"Duree : {result.duration_s:.2f}s",
            f"XML : {result.xml_path or '-'}",
            "-" * 60,
        ]
        for host in result.hosts:
            hn = f" ({host.hostname})" if host.hostname else ""
            lines.append(f"Host {host.ip}{hn} [{host.state}]")
            if host.os_guess:
                acc = f" {host.os_accuracy}%" if host.os_accuracy is not None else ""
                lines.append(f"  OS : {host.os_guess}{acc}")
            for p in host.ports:
                service = p.service or "?"
                version = f" {p.product or ''} {p.version or ''}".strip()
                banner = f" | {p.banner}" if p.banner else ""
                lines.append(f"  {p.port}/{p.proto} {p.state:<8} {service} {version}{banner}")
            for s in host.scripts:
                lines.append(f"  [script:{s.id}] {s.output}")
        return "\n".join(lines) + "\n"

    raise TypeError(f"type de resultat non supporte : {type(result).__name__}")


def to_csv(result: Result) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")

    if isinstance(result, ScanResult):
        writer.writerow(["ip", "mac", "vendor"])
        for host in result.hosts:
            writer.writerow([host.ip, host.mac, host.vendor or ""])
    elif isinstance(result, CaptureResult):
        writer.writerow(["index", "timestamp", "summary", "src", "dst", "protocol", "length"])
        for p in result.packets:
            writer.writerow([p.index, p.timestamp, p.summary, p.src or "", p.dst or "", p.protocol or "", p.length])
    elif isinstance(result, NetworkInfo):
        writer.writerow(["interface", "mac", "is_up", "mtu", "addresses"])
        for iface in result.interfaces:
            addrs = ";".join(f"{a.family}:{a.address}" for a in iface.addresses)
            writer.writerow([iface.name, iface.mac or "", iface.is_up, iface.mtu or "", addrs])
    elif isinstance(result, GeoInfo):
        writer.writerow(["ip", "country", "city", "region", "lat", "lon", "isp", "status"])
        writer.writerow([
            result.ip, result.country or "", result.city or "", result.region or "",
            result.lat if result.lat is not None else "",
            result.lon if result.lon is not None else "",
            result.isp or "", result.status,
        ])
    elif isinstance(result, NmapScan):
        writer.writerow([
            "host_ip", "hostname", "os_guess", "os_accuracy",
            "port", "proto", "state", "service", "product", "version", "banner",
        ])
        for host in result.hosts:
            for p in host.ports:
                writer.writerow([
                    host.ip, host.hostname or "",
                    host.os_guess or "", host.os_accuracy if host.os_accuracy is not None else "",
                    p.port, p.proto, p.state,
                    p.service or "", p.product or "", p.version or "", p.banner or "",
                ])
    else:
        raise TypeError(f"type de resultat non supporte : {type(result).__name__}")

    return buffer.getvalue()
