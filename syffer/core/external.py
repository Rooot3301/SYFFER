"""Wrapper generique pour outils CLI externes (prepare Phase 1)."""

from __future__ import annotations

import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)


class ExternalTool:
    """Represente un binaire externe (nmap, tcpdump, ...).

    Phase 0 : structure en place, aucun outil consomme.
    Phase 1 : sous-classes concretes (NmapTool) branchees dessus.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def available(self) -> bool:
        return shutil.which(self.name) is not None

    def run(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
        binary = shutil.which(self.name)
        if binary is None:
            raise FileNotFoundError(f"binaire introuvable : {self.name}")
        logger.debug("execution externe : %s %s", binary, args)
        return subprocess.run(
            [binary, *args],
            check=False,
            capture_output=True,
            timeout=timeout,
        )
