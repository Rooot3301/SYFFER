"""Constantes runtime de Syffer."""

from __future__ import annotations

from pathlib import Path

EXTRACT_DIR: Path = Path("extract").resolve()

DEFAULT_ARP_TIMEOUT: int = 3
DEFAULT_CAPTURE_COUNT: int = 10
DEFAULT_HTTP_TIMEOUT: int = 5

IP_API_URL: str = "http://ip-api.com/json/{ip}"

APP_NAME: str = "Syffer"
