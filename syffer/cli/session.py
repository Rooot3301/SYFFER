"""Etat de session du menu interactif."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from syffer import config
from syffer.core.models import CaptureResult


@dataclass
class Session:
    captured_packets: list[Any] = field(default_factory=list)
    last_capture: CaptureResult | None = None
    verbose: bool = False
    extract_dir: Path = field(default_factory=lambda: config.EXTRACT_DIR)
