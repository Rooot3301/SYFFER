"""Rendu rich des resultats et messages."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from syffer.core.models import CaptureResult, GeoInfo, NetworkInfo, ScanResult

_console = Console()

_BANNER = r"""
 ▄▄▄▄▄  ▄     ▄  ▄▄▄▄▄▄  ▄▄▄▄▄▄  ▄▄▄▄▄▄  ▄▄▄▄▄
 █      █     █  █       █       █       █    █
 █▄▄▄▄  █▄▄▄▄▄█  █▄▄▄▄▄  █▄▄▄▄▄  █▄▄▄▄▄  █▄▄▄▄█
      █  █   █   █       █       █       █   █
 ▄▄▄▄▄█  █   █   █       █       █▄▄▄▄▄  █    █
"""


def banner() -> None:
    _console.print(Panel.fit(_BANNER, style="bold cyan", subtitle="recon toolkit"))


def error(msg: str) -> None:
    _console.print(f"[bold red]![/bold red] {msg}")


def success(msg: str) -> None:
    _console.print(f"[bold green]OK[/bold green] {msg}")


def render_scan(result: ScanResult) -> None:
    table = Table(title=f"Scan ARP {result.cidr} ({result.duration_s:.2f}s)")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Vendor")
    for host in result.hosts:
        table.add_row(host.ip, host.mac, host.vendor or "-")
    _console.print(table)


def render_capture(result: CaptureResult) -> None:
    _console.print(f"[bold]Capture[/bold] : {len(result.packets)} paquets, filtre='{result.bpf_filter or 'aucun'}'")
    _console.print(f"PCAP : [green]{result.pcap_path}[/green]")
    table = Table()
    table.add_column("#", justify="right")
    table.add_column("Resume")
    table.add_column("Taille", justify="right")
    for p in result.packets:
        table.add_row(str(p.index), p.summary, str(p.length))
    _console.print(table)


def render_info(info: NetworkInfo) -> None:
    _console.print(f"[bold]Hostname[/bold] : {info.hostname}")
    _console.print(f"[bold]IP locale[/bold] : {info.local_ip or '?'}")
    _console.print(f"[bold]Gateway[/bold] : {info.default_gateway or '?'}")
    table = Table(title="Interfaces")
    table.add_column("Nom")
    table.add_column("Etat")
    table.add_column("MAC")
    table.add_column("MTU")
    table.add_column("Adresses")
    for iface in info.interfaces:
        state = "[green]UP[/green]" if iface.is_up else "[red]DOWN[/red]"
        addrs = "\n".join(f"{a.family}: {a.address}" for a in iface.addresses)
        table.add_row(iface.name, state, iface.mac or "-", str(iface.mtu or "-"), addrs or "-")
    _console.print(table)


def render_geo(info: GeoInfo) -> None:
    table = Table(title=f"Geolocalisation {info.ip}")
    table.add_column("Champ")
    table.add_column("Valeur")
    for field_name, value in [
        ("Pays", info.country),
        ("Ville", info.city),
        ("Region", info.region),
        ("Latitude", info.lat),
        ("Longitude", info.lon),
        ("ISP", info.isp),
    ]:
        table.add_row(field_name, str(value) if value is not None else "-")
    _console.print(table)


def render_packet_details(packet: Any) -> None:
    try:
        details = packet.show(dump=True)
        _console.print(Panel(details, title="Details paquet", border_style="cyan"))
    except Exception as exc:
        error(f"impossible d'afficher le paquet : {exc}")


def render_nmap_scan(scan: Any) -> None:
    from syffer.core.models import NmapScan
    assert isinstance(scan, NmapScan)

    header_lines = [
        f"Cible : [bold cyan]{scan.target}[/bold cyan]",
        f"Profil : {scan.profile}",
        f"Version nmap : {scan.nmap_version or '?'}",
        f"Duree : {scan.duration_s:.2f}s",
        f"XML : [dim]{scan.xml_path or '-'}[/dim]",
    ]
    _console.print(Panel("\n".join(header_lines), title="Scan nmap", border_style="cyan"))

    for host in scan.hosts:
        hn = f" ({host.hostname})" if host.hostname else ""
        state_color = "green" if host.state == "up" else "red"
        title = f"[{state_color}]{host.ip}[/{state_color}]{hn}"
        if host.os_guess:
            acc = f" [{host.os_accuracy}%]" if host.os_accuracy is not None else ""
            title += f" - OS: {host.os_guess}{acc}"

        table = Table(title=title)
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("Proto")
        table.add_column("Etat")
        table.add_column("Service")
        table.add_column("Version")
        table.add_column("Banner")
        for p in host.ports:
            state_style = "green" if p.state == "open" else "dim"
            version = " ".join(filter(None, [p.product, p.version]))
            banner_display = (p.banner or "")[:40]
            table.add_row(
                str(p.port), p.proto,
                f"[{state_style}]{p.state}[/{state_style}]",
                p.service or "-", version or "-", banner_display or "-",
            )
        _console.print(table)

        for s in host.scripts:
            _console.print(Panel(s.output, title=f"script: {s.id}", border_style="magenta"))
