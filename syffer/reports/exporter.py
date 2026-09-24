"""Dispatcher d'export : txt / json / csv sous EXTRACT_DIR."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from syffer.reports.formatters import Result, to_csv, to_json, to_txt
from syffer.utils.paths import safe_output_path

Format = Literal["txt", "json", "csv"]


def export(result: Result, fmt: Format, name: str) -> Path:
    if fmt == "txt":
        content = to_txt(result)
    elif fmt == "json":
        content = to_json(result)
    elif fmt == "csv":
        content = to_csv(result)
    else:
        raise ValueError(f"format inconnu : {fmt}")

    path = safe_output_path(name, fmt)
    path.write_text(content, encoding="utf-8")
    return path
