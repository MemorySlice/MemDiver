"""Tests for harvester.sidecar module - SidecarParser metadata parsing."""
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from harvester.sidecar import SidecarParser


def test_find_sidecar_empty_dir():
    """An empty directory should have no sidecar file."""
    tmp_dir = tempfile.mkdtemp()
    try:
        result = SidecarParser.find_sidecar(Path(tmp_dir))
        assert result is None
    finally:
        shutil.rmtree(tmp_dir)


def test_find_sidecar_json():
    """A directory with metadata.json should be found as a sidecar."""
    tmp_dir = tempfile.mkdtemp()
    try:
        sidecar_path = Path(tmp_dir) / "metadata.json"
        sidecar_path.write_text('{"version": "1.0"}')
        result = SidecarParser.find_sidecar(Path(tmp_dir))
        assert result is not None
        assert result.name == "metadata.json"
    finally:
        shutil.rmtree(tmp_dir)


def test_find_sidecar_meta():
    """A directory with info.meta should be found as a sidecar."""
    tmp_dir = tempfile.mkdtemp()
    try:
        sidecar_path = Path(tmp_dir) / "info.meta"
        sidecar_path.write_text("version=1.0\n")
        result = SidecarParser.find_sidecar(Path(tmp_dir))
        assert result is not None
        assert result.name == "info.meta"
    finally:
        shutil.rmtree(tmp_dir)


def test_parse_json_valid():
    """Parsing a valid JSON sidecar should return a dict with the expected keys."""
    tmp_dir = tempfile.mkdtemp()
    try:
        sidecar_path = Path(tmp_dir) / "metadata.json"
        sidecar_path.write_text(json.dumps({"version": "1.0", "library": "openssl"}))
        result = SidecarParser.parse(sidecar_path)
        assert result["version"] == "1.0"
        assert result["library"] == "openssl"
    finally:
        shutil.rmtree(tmp_dir)


def test_parse_meta_valid():
    """Parsing a valid .meta sidecar should return a dict with both key-value pairs."""
    tmp_dir = tempfile.mkdtemp()
    try:
        sidecar_path = Path(tmp_dir) / "info.meta"
        sidecar_path.write_text("version=1.0\nlibrary=openssl\n")
        result = SidecarParser.parse(sidecar_path)
        assert result["version"] == "1.0"
        assert result["library"] == "openssl"
    finally:
        shutil.rmtree(tmp_dir)


def test_parse_nonexistent():
    """Parsing a nonexistent path should return an empty dict."""
    result = SidecarParser.parse(Path("/tmp/nonexistent_sidecar_file_xyz.json"))
    assert result == {}
