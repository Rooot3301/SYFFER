"""Dataclasses partagees entre core, reports et cli."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class InterfaceAddress:
    family: str
    address: str
    netmask: str | None
    broadcast: str | None


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    mac: str | None
    is_up: bool
    mtu: int | None
    addresses: tuple[InterfaceAddress, ...]


@dataclass(frozen=True, slots=True)
class NetworkInfo:
    hostname: str
    local_ip: str | None
    default_gateway: str | None
    interfaces: tuple[Interface, ...]


@dataclass(frozen=True, slots=True)
class PacketSummary:
    index: int
    timestamp: float
    summary: str
    src: str | None
    dst: str | None
    protocol: str | None
    length: int


@dataclass(frozen=True, slots=True)
class CaptureResult:
    pcap_path: Path
    packets: tuple[PacketSummary, ...]
    bpf_filter: str | None
    iface: str | None


@dataclass(frozen=True, slots=True)
class Host:
    ip: str
    mac: str
    vendor: str | None


@dataclass(frozen=True, slots=True)
class ScanResult:
    cidr: str
    started_at: float
    duration_s: float
    hosts: tuple[Host, ...]


@dataclass(frozen=True, slots=True)
class GeoInfo:
    ip: str
    country: str | None
    city: str | None
    region: str | None
    lat: float | None
    lon: float | None
    isp: str | None
    status: str


@dataclass(frozen=True, slots=True)
class NmapScript:
    id: str
    output: str


@dataclass(frozen=True, slots=True)
class NmapPort:
    port: int
    proto: str
    state: str
    service: str | None
    product: str | None
    version: str | None
    banner: str | None


@dataclass(frozen=True, slots=True)
class NmapHost:
    ip: str
    hostname: str | None
    state: str
    os_guess: str | None
    os_accuracy: int | None
    ports: tuple[NmapPort, ...]
    scripts: tuple[NmapScript, ...]


@dataclass(frozen=True, slots=True)
class NmapScan:
    target: str
    profile: str
    started_at: float
    duration_s: float
    hosts: tuple[NmapHost, ...]
    nmap_version: str | None
    xml_path: Path | None
