"""Tests de syffer.reports.exporter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from syffer.core.models import Host, ScanResult
from syffer.reports.exporter import export


def _sample() -> ScanResult:
    return ScanResult(
        cidr="192.168.1.0/24", started_at=0.0, duration_s=0.1,
        hosts=(Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", vendor=None),),
    )


def test_export_txt_writes_under_extract(tmp_extract_dir: Path):
    path = export(_sample(), fmt="txt", name="rapport")
    assert path.exists()
    assert path.parent == tmp_extract_dir
    assert path.suffix == ".txt"
    assert "192.168.1.1" in path.read_text(encoding="utf-8")


def test_export_json_valid(tmp_extract_dir: Path):
    path = export(_sample(), fmt="json", name="rapport")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["cidr"] == "192.168.1.0/24"


def test_export_csv_valid(tmp_extract_dir: Path):
    path = export(_sample(), fmt="csv", name="rapport")
    content = path.read_text(encoding="utf-8")
    assert "ip,mac,vendor" in content
    assert "192.168.1.1" in content


def test_export_rejects_traversal(tmp_extract_dir: Path):
    with pytest.raises(ValueError):
        export(_sample(), fmt="txt", name="../evil")


def test_export_rejects_unknown_format(tmp_extract_dir: Path):
    with pytest.raises(ValueError):
        export(_sample(), fmt="xml", name="rapport")  # type: ignore[arg-type]
