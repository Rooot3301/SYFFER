"""Orchestrateur : nmap + banner grabbing optionnel."""

from __future__ import annotations

import logging
import time
from dataclasses import replace

from syffer.core.banner_grab import grab_banner
from syffer.core.models import NmapHost, NmapScan
from syffer.core.nmap_parser import parse_xml
from syffer.core.nmap_tool import NmapProfile, NmapTool
from syffer.utils.paths import resolve_extract_dir, timestamped_name
from syffer.utils.validation import (
    safe_filename,
    validate_ports,
    validate_target,
)

logger = logging.getLogger(__name__)


def _enrich_with_banners(host: NmapHost) -> NmapHost:
    new_ports = []
    for p in host.ports:
        if p.state == "open":
            banner = grab_banner(host.ip, p.port)
            new_ports.append(replace(p, banner=banner))
        else:
            new_ports.append(p)
    return replace(host, ports=tuple(new_ports))


def port_scan(
    target: str,
    profile: NmapProfile,
    profile_name: str,
    ports: str | None = None,
    banner: bool = False,
    timeout: int = 300,
) -> NmapScan:
    validated_target = validate_target(target)
    validated_ports = validate_ports(ports) if ports is not None else None

    tool = NmapTool()
    if not tool.available():
        raise FileNotFoundError("nmap requis : https://nmap.org/download.html")

    logger.info("nmap scan : target=%s profil=%s", validated_target, profile_name)
    started = time.time()
    xml_bytes = tool.run_scan(
        target=validated_target,
        profile=profile,
        ports=validated_ports,
        timeout=timeout,
    )
    duration = time.time() - started
    logger.info("nmap termine en %.2fs", duration)

    slug = safe_filename(validated_target.replace("/", "-").replace(":", "-"))
    xml_path = resolve_extract_dir() / timestamped_name(f"nmap-{slug}", "xml")
    xml_path.write_bytes(xml_bytes)

    scan = parse_xml(xml_bytes, target=validated_target, profile=profile_name)

    if banner:
        hosts = tuple(_enrich_with_banners(h) for h in scan.hosts)
    else:
        hosts = scan.hosts

    return NmapScan(
        target=scan.target,
        profile=scan.profile,
        started_at=scan.started_at,
        duration_s=scan.duration_s,
        hosts=hosts,
        nmap_version=scan.nmap_version,
        xml_path=xml_path,
    )
