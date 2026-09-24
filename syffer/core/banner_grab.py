"""Banner grabbing TCP passif (recv sans envoi de payload)."""

from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)

_BUF_SIZE = 1024


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Ouvre une connexion TCP, lit jusqu'a 1024 octets, ferme, retourne
    la chaine strippee ou None sur erreur/timeout/vide.

    N'envoie AUCUN payload : c'est passif. Certains services (SSH, SMTP,
    FTP) envoient une banner spontanement, d'autres non (HTTP attend une
    requete). C'est acceptable pour du recon simple.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(_BUF_SIZE)
    except (OSError, socket.timeout) as exc:
        logger.debug("banner %s:%d echec : %s", ip, port, exc)
        return None
    if not data:
        return None
    return data.decode("latin-1", errors="replace").strip()
