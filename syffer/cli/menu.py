"""Boucle principale du menu interactif."""

from __future__ import annotations

import logging

import questionary

from syffer.cli import display, handlers
from syffer.cli.session import Session

logger = logging.getLogger(__name__)

_CHOICES = [
    ("Capture de paquets", handlers.handle_capture),
    ("Scan du reseau (ARP)", handlers.handle_scan),
    ("Scan avance (nmap)", handlers.handle_nmap_scan),
    ("Informations reseau de la machine", handlers.handle_info),
    ("Adresse IP locale", handlers.handle_local_ip),
    ("Geolocaliser une IP publique", handlers.handle_geo),
    ("Details d'un paquet capture", handlers.handle_packet_details),
    ("Parametres", handlers.handle_settings),
    ("Quitter", None),
]


def run(session: Session | None = None) -> int:
    session = session or Session()
    display.banner()
    while True:
        try:
            choice = questionary.select(
                "Menu principal",
                choices=[label for label, _ in _CHOICES],
            ).ask()
        except KeyboardInterrupt:
            return 130
        if choice is None or choice == "Quitter":
            return 0
        handler = dict(_CHOICES)[choice]
        if handler is None:
            return 0
        try:
            handler(session)
        except KeyboardInterrupt:
            display.error("interrompu")
        except Exception as exc:
            logger.exception("erreur inattendue dans %s", choice)
            display.error(f"erreur inattendue : {exc}")
