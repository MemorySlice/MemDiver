"""Tests for the path info and browse API endpoints."""

import tempfile
from pathlib import Path

import pytest

from api.routers.path import browse_directory, path_info


class TestPathInfo:
    def test_nonexistent_path(self):
        result = path_info("/nonexistent/path/to/nowhere")
        assert result["exists"] is False
        assert result["detected_mode"] == "unknown"

    def test_single_file(self, tmp_path):
        f = tmp_path / "test.dump"
        f.write_bytes(b"\x00" * 100)
        result = path_info(str(f))
        assert result["exists"] is True
        assert result["is_file"] is True
        assert result["is_directory"] is False
        assert result["extension"] == ".dump"
        assert result["detected_mode"] == "single_file"
        assert result["file_size"] == 100

    def test_directory_with_run_dirs(self, tmp_path):
        run_dir = tmp_path / "openssl_run_12_1"
        run_dir.mkdir()
        (run_dir / "pre_handshake.dump").write_bytes(b"\x00" * 50)
        (run_dir / "keylog.csv").write_text("CLIENT_RANDOM,abc,def")
        result = path_info(str(tmp_path))
        assert result["exists"] is True
        assert result["is_directory"] is True
        assert result["detected_mode"] == "run_directory"
        assert result["has_keylog"] is True
        assert result["dump_count"] >= 1

    def test_empty_directory(self, tmp_path):
        result = path_info(str(tmp_path))
        assert result["exists"] is True
        assert result["is_directory"] is True


class TestBrowseDirectory:
    def test_browse_nonexistent(self):
        result = browse_directory("/nonexistent/path/xyz")
        assert result["error"] == "Path does not exist"
        assert result["entries"] == []

    def test_browse_file_not_dir(self, tmp_path):
        f = tmp_path / "test.dump"
        f.write_bytes(b"\x00")
        result = browse_directory(str(f))
        assert result["error"] == "Path is not a directory"

    def test_browse_lists_dirs_and_dumps(self, tmp_path):
        (tmp_path / "subdir").mkdir()
        (tmp_path / "test.dump").write_bytes(b"\x00" * 64)
        (tmp_path / "test.msl").write_bytes(b"\x00" * 128)
        (tmp_path / "readme.txt").write_text("ignored")
        result = browse_directory(str(tmp_path))
        assert "error" not in result
        assert result["current"] == str(tmp_path.resolve())
        names = [e["name"] for e in result["entries"]]
        assert "subdir" in names
        assert "test.dump" in names
        assert "test.msl" in names
        assert "readme.txt" not in names

    def test_browse_dirs_first(self, tmp_path):
        (tmp_path / "zzz_dir").mkdir()
        (tmp_path / "aaa.dump").write_bytes(b"\x00")
        result = browse_directory(str(tmp_path))
        entries = result["entries"]
        assert entries[0]["name"] == "zzz_dir"
        assert entries[0]["is_dir"] is True
        assert entries[1]["name"] == "aaa.dump"
        assert entries[1]["is_dir"] is False

    def test_browse_default_home(self):
        result = browse_directory()
        assert "current" in result
        assert result["current"] == str(Path.home())

    def test_browse_has_parent(self, tmp_path):
        child = tmp_path / "sub"
        child.mkdir()
        result = browse_directory(str(child))
        assert result["parent"] == str(tmp_path.resolve())
