"""Configuration du logging avec RichHandler."""

from __future__ import annotations

import logging

from rich.logging import RichHandler

_CONFIGURED_MARKER = "_syffer_configured"


def configure(verbose: bool = False) -> None:
    """Configure le root logger avec RichHandler. Idempotent."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers = [h for h in root.handlers if not getattr(h, _CONFIGURED_MARKER, False)]
    handler = RichHandler(rich_tracebacks=True, show_path=False, show_time=True)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    setattr(handler, _CONFIGURED_MARKER, True)
    root.addHandler(handler)
