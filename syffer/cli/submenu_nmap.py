"""Sous-menu Scan avance (nmap)."""

from __future__ import annotations

import logging
import subprocess

import questionary

from syffer.cli import display, prompts
from syffer.cli.session import Session
from syffer.core import nmap_tool as nt
from syffer.core.port_scan import port_scan

logger = logging.getLogger(__name__)

_PROFILE_LABELS: dict[str, tuple[str, nt.NmapProfile | None, bool]] = {
    "Quick (top 100 ports)": ("Quick", nt.QUICK, False),
    "Full TCP (65535 ports)": ("Full TCP", nt.FULL_TCP, False),
    "Service + version (-sV)": ("Service+Version", nt.SERVICE_VERSION, False),
    "OS detection (-O, requiert admin)": ("OS Detection", nt.OS_DETECTION, False),
    "Aggressive (-A : -sV -O -sC --traceroute)": ("Aggressive", nt.AGGRESSIVE, False),
    "Custom": ("Custom", None, True),
}


def _build_custom_profile(sv: bool, sc: bool, o: bool, pn: bool) -> nt.NmapProfile:
    flags = list(nt.CUSTOM_BASE)
    if sv:
        flags.append("-sV")
    if sc:
        flags.append("-sC")
    if o:
        flags.append("-O")
    if pn:
        flags.append("-Pn")
    return tuple(flags)


def run(session: Session) -> None:
    tool = nt.NmapTool()
    if not tool.available():
        display.error("nmap requis. Installe-le : https://nmap.org/download.html")
        return

    label = questionary.select(
        "Profil de scan",
        choices=[*_PROFILE_LABELS.keys(), "Retour"],
    ).ask()
    if label in (None, "Retour"):
        return

    profile_name, profile_flags, is_custom = _PROFILE_LABELS[label]

    try:
        target = prompts.ask_target()
    except KeyboardInterrupt:
        return

    ports: str | None = None
    if is_custom:
        try:
            ports = prompts.ask_ports()
            sv, sc, o, pn = prompts.ask_custom_toggles()
        except KeyboardInterrupt:
            return
        profile_flags = _build_custom_profile(sv, sc, o, pn)

    try:
        do_banner = questionary.confirm("Banner grabbing en complement ?", default=True).ask()
    except KeyboardInterrupt:
        return
    if do_banner is None:
        return

    assert profile_flags is not None
    try:
        result = port_scan(
            target=target,
            profile=profile_flags,
            profile_name=profile_name,
            ports=ports,
            banner=bool(do_banner),
        )
    except FileNotFoundError as exc:
        display.error(str(exc))
        return
    except subprocess.TimeoutExpired:
        display.error("timeout nmap (>300s), essayez le profil Quick")
        return
    except ValueError as exc:
        display.error(str(exc))
        return
    except RuntimeError as exc:
        display.error(f"echec nmap : {exc}")
        return

    display.render_nmap_scan(result)

    from syffer.cli.handlers import _maybe_export
    _maybe_export(result)
