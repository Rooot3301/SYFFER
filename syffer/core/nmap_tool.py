"""Wrapper subprocess autour du binaire nmap."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

from syffer.core.external import ExternalTool

logger = logging.getLogger(__name__)

NmapProfile = tuple[str, ...]

QUICK: NmapProfile = ("-T4", "-F")
FULL_TCP: NmapProfile = ("-T4", "-p-")
SERVICE_VERSION: NmapProfile = ("-T4", "-sV")
OS_DETECTION: NmapProfile = ("-T4", "-O", "-Pn")
AGGRESSIVE: NmapProfile = ("-T4", "-A")
CUSTOM_BASE: NmapProfile = ("-T4",)

_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9.:/-]+$")
_VERSION_RE = re.compile(r"Nmap version ([0-9.]+)")


class NmapTool(ExternalTool):
    def __init__(self) -> None:
        super().__init__("nmap")

    def version(self) -> str | None:
        if not self.available():
            return None
        try:
            result = self.run(["--version"], timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        match = _VERSION_RE.search(result.stdout.decode("utf-8", errors="replace"))
        return match.group(1) if match else None

    def run_scan(
        self,
        target: str,
        profile: NmapProfile,
        ports: str | None = None,
        timeout: int = 300,
    ) -> bytes:
        binary = shutil.which(self.name)
        if binary is None:
            raise FileNotFoundError("nmap requis : https://nmap.org/download.html")
        assert _SAFE_TARGET_RE.match(target), f"cible non sanitize (bug amont) : {target!r}"

        args = [binary, *profile, "-oX", "-", "--stats-every", "2s"]
        if ports is not None:
            args.extend(["-p", ports])
        args.append(target)

        logger.debug("nmap : %s", args)
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"nmap exit {completed.returncode} : {stderr}")
        return completed.stdout
