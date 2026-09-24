"""Parser de la sortie XML de nmap (-oX -)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from syffer.core.models import NmapHost, NmapPort, NmapScan, NmapScript


def _parse_port(elem: ET.Element) -> NmapPort:
    state_elem = elem.find("state")
    service_elem = elem.find("service")
    return NmapPort(
        port=int(elem.get("portid", "0")),
        proto=elem.get("protocol", "tcp"),
        state=state_elem.get("state", "unknown") if state_elem is not None else "unknown",
        service=service_elem.get("name") if service_elem is not None else None,
        product=service_elem.get("product") if service_elem is not None else None,
        version=service_elem.get("version") if service_elem is not None else None,
        banner=None,
    )


def _parse_scripts(elem: ET.Element) -> tuple[NmapScript, ...]:
    scripts = []
    for s in elem.findall("script"):
        script_id = s.get("id")
        output = s.get("output", "")
        if script_id:
            scripts.append(NmapScript(id=script_id, output=output))
    return tuple(scripts)


def _parse_host(elem: ET.Element) -> NmapHost:
    status_elem = elem.find("status")
    state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

    ip = ""
    for addr in elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            ip = addr.get("addr", "")
            break
        if not ip:
            ip = addr.get("addr", "")

    hostname_elem = elem.find("hostnames/hostname")
    hostname = hostname_elem.get("name") if hostname_elem is not None else None

    ports_container = elem.find("ports")
    ports: tuple[NmapPort, ...] = ()
    if ports_container is not None:
        ports = tuple(_parse_port(p) for p in ports_container.findall("port"))

    os_guess: str | None = None
    os_accuracy: int | None = None
    osmatch = elem.find("os/osmatch")
    if osmatch is not None:
        os_guess = osmatch.get("name")
        try:
            os_accuracy = int(osmatch.get("accuracy", "0"))
        except ValueError:
            os_accuracy = None

    scripts: tuple[NmapScript, ...] = ()
    hostscript = elem.find("hostscript")
    if hostscript is not None:
        scripts = _parse_scripts(hostscript)

    return NmapHost(
        ip=ip,
        hostname=hostname,
        state=state,
        os_guess=os_guess,
        os_accuracy=os_accuracy,
        ports=ports,
        scripts=scripts,
    )


def parse_xml(xml_bytes: bytes, target: str = "", profile: str = "") -> NmapScan:
    if not xml_bytes:
        raise ValueError("XML nmap vide")
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"XML nmap malforme : {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError(f"racine XML inattendue : <{root.tag}>")

    version = root.get("version")
    try:
        started_at = float(root.get("start", "0"))
    except ValueError:
        started_at = 0.0

    duration = 0.0
    finished = root.find("runstats/finished")
    if finished is not None:
        try:
            duration = float(finished.get("elapsed", "0"))
        except ValueError:
            duration = 0.0

    hosts = tuple(_parse_host(h) for h in root.findall("host"))

    return NmapScan(
        target=target,
        profile=profile,
        started_at=started_at,
        duration_s=duration,
        hosts=hosts,
        nmap_version=version,
        xml_path=None,
    )
