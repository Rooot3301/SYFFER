"""Handlers du menu interactif."""

from __future__ import annotations

import logging

from syffer import config
from syffer.cli import display, prompts
from syffer.cli.session import Session
from syffer.core import geolocation, network_info, network_scan, packet_capture
from syffer.core.geolocation import GeolocationError
from syffer.reports.exporter import export
from syffer.utils import logging_setup

logger = logging.getLogger(__name__)


def _maybe_export(result) -> None:
    choice = prompts.ask_export()
    if choice is None:
        return
    fmt, name = choice
    path = export(result, fmt=fmt, name=name)  # type: ignore[arg-type]
    display.success(f"rapport ecrit : {path}")


def handle_capture(session: Session) -> None:
    count = prompts.ask_int("Nombre de paquets a capturer", default=config.DEFAULT_CAPTURE_COUNT)
    bpf = prompts.ask_bpf()
    try:
        result, raw = packet_capture.capture(count=count, bpf_filter=bpf, iface=None, timeout=None)
    except PermissionError:
        display.error("permissions insuffisantes (essayez en root/admin)")
        return
    except OSError as exc:
        display.error(f"erreur reseau : {exc}")
        return
    except ValueError as exc:
        display.error(str(exc))
        return

    session.captured_packets = raw
    session.last_capture = result
    display.render_capture(result)
    _maybe_export(result)


def handle_scan(session: Session) -> None:
    cidr = prompts.ask_cidr()
    try:
        result = network_scan.arp_scan(cidr, timeout=config.DEFAULT_ARP_TIMEOUT)
    except PermissionError:
        display.error("permissions insuffisantes (essayez en root/admin)")
        return
    except OSError as exc:
        display.error(f"erreur reseau : {exc}")
        return
    except ValueError as exc:
        display.error(str(exc))
        return

    display.render_scan(result)
    _maybe_export(result)


def handle_info(session: Session) -> None:
    info = network_info.get_network_info()
    display.render_info(info)
    _maybe_export(info)


def handle_local_ip(session: Session) -> None:
    ip = network_info.get_local_ip()
    if ip is None:
        display.error("IP locale non determinable")
    else:
        display.success(f"IP locale : {ip}")


def handle_geo(session: Session) -> None:
    ip = prompts.ask_ip()
    try:
        info = geolocation.lookup(ip)
    except GeolocationError as exc:
        display.error(f"echec geolocation : {exc}")
        return
    except ValueError as exc:
        display.error(str(exc))
        return
    display.render_geo(info)
    _maybe_export(info)


def handle_packet_details(session: Session) -> None:
    if not session.captured_packets:
        display.error("aucun paquet capture dans cette session (option 1 d'abord)")
        return
    index = prompts.ask_int("Index du paquet a afficher (0-base)", default=0)
    if index >= len(session.captured_packets):
        display.error(f"index hors limites (0..{len(session.captured_packets) - 1})")
        return
    display.render_packet_details(session.captured_packets[index])


def handle_settings(session: Session) -> None:
    import questionary
    new_verbose = questionary.confirm("Activer les logs verbeux ?", default=session.verbose).ask()
    if new_verbose is None:
        return
    session.verbose = bool(new_verbose)
    logging_setup.configure(verbose=session.verbose)
    display.success(f"mode verbeux : {'ON' if session.verbose else 'OFF'}")
