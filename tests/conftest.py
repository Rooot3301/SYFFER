"""Fixtures pytest partagees."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def tmp_extract_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirige EXTRACT_DIR vers un tmp_path isole pour le test."""
    extract = tmp_path / "extract"
    extract.mkdir()
    monkeypatch.setattr("syffer.config.EXTRACT_DIR", extract)
    return extract
