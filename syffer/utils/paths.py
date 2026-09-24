"""Resolution et sanitisation des chemins de sortie."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from syffer import config
from syffer.utils.validation import safe_filename


def resolve_extract_dir() -> Path:
    """Renvoie le dossier de sortie, le cree si necessaire."""
    directory = config.EXTRACT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def safe_output_path(name: str, extension: str) -> Path:
    """Construit un chemin de sortie sous EXTRACT_DIR, sanitize et verifie."""
    clean = safe_filename(name)
    ext = extension.lstrip(".")
    base = resolve_extract_dir()
    candidate = (base / f"{clean}.{ext}").resolve()
    if not str(candidate).startswith(str(base.resolve())):
        raise ValueError("chemin de sortie hors du dossier extract")
    return candidate


def timestamped_name(prefix: str, extension: str) -> str:
    """Renvoie un nom horodate au format prefix-YYYYMMDD-HHMMSS.ext."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    ext = extension.lstrip(".")
    return f"{prefix}-{ts}.{ext}"
