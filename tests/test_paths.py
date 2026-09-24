"""Tests de syffer.utils.paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from syffer.utils.paths import (
    resolve_extract_dir,
    safe_output_path,
    timestamped_name,
)


def test_resolve_extract_dir_creates(tmp_extract_dir: Path):
    resolve_extract_dir().rmdir()
    result = resolve_extract_dir()
    assert result.exists()
    assert result.is_dir()


def test_safe_output_path_returns_under_extract(tmp_extract_dir: Path):
    p = safe_output_path("rapport", "txt")
    assert p == tmp_extract_dir / "rapport.txt"


def test_safe_output_path_strips_leading_dot(tmp_extract_dir: Path):
    p = safe_output_path("rapport", ".json")
    assert p.name == "rapport.json"


def test_safe_output_path_rejects_traversal(tmp_extract_dir: Path):
    with pytest.raises(ValueError):
        safe_output_path("../evil", "txt")


def test_safe_output_path_rejects_empty(tmp_extract_dir: Path):
    with pytest.raises(ValueError):
        safe_output_path("", "txt")


def test_timestamped_name_format():
    name = timestamped_name("capture", "pcap")
    assert name.startswith("capture-")
    assert name.endswith(".pcap")
    assert len(name) == len("capture-20260924-123456.pcap")
