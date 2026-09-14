"""Tests for the shared user preferences file.

``memdiver_home()/config.json`` is written by three unrelated features — the
upload directory, the setup wizard's ``skip_duckdb_setup`` flag and the file
browser's favourites. That sharing is the whole risk: a write that replaced the
file instead of merging into it would silently delete another feature's
settings, and a write that was not atomic could truncate the file for all of
them at once. These tests pin both properties, plus the tolerance that keeps a
corrupt file from breaking every request that reads it.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from memdiver.api import user_prefs


@pytest.fixture
def prefs_home(tmp_path: Path, monkeypatch) -> Path:
    """Redirect ``memdiver_home()`` so the developer's real prefs are untouched."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    return tmp_path


def test_path_lives_under_memdiver_home(prefs_home):
    assert user_prefs.user_config_path() == prefs_home / "xdg" / "memdiver" / "config.json"


def test_missing_file_reads_as_empty(prefs_home):
    assert user_prefs.read_prefs() == {}
    assert user_prefs.read_pref("anything") is None
    assert user_prefs.read_pref("anything", "fallback") == "fallback"


def test_write_then_read_round_trips(prefs_home):
    user_prefs.write_pref("favourite_dirs", [{"path": "/tmp", "label": "tmp"}])

    assert user_prefs.read_pref("favourite_dirs") == [{"path": "/tmp", "label": "tmp"}]


def test_write_preserves_other_features_keys(prefs_home):
    """THE property this module exists for: one setting may not evict another."""
    user_prefs.write_pref("upload_dir", "/data/uploads")
    user_prefs.write_pref("skip_duckdb_setup", True)

    user_prefs.write_pref("favourite_dirs", [{"path": "/data"}])

    stored = json.loads(user_prefs.user_config_path().read_text())
    assert stored["upload_dir"] == "/data/uploads"
    assert stored["skip_duckdb_setup"] is True
    assert stored["favourite_dirs"] == [{"path": "/data"}]


def test_write_is_owner_only_and_leaves_no_temp_file(prefs_home):
    """0o600, and the sibling ``.json.tmp`` is renamed rather than left behind."""
    user_prefs.write_pref("upload_dir", "/data/uploads")

    target = user_prefs.user_config_path()
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert not target.with_suffix(".json.tmp").exists()


def test_corrupt_file_degrades_to_empty(prefs_home):
    """A hand-edited, broken prefs file must not raise into every caller."""
    target = user_prefs.user_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{not json")

    assert user_prefs.read_prefs() == {}


def test_non_object_file_degrades_to_empty(prefs_home):
    """Valid JSON that is not an object is just as unusable, and just as survivable."""
    target = user_prefs.user_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("[1, 2, 3]")

    assert user_prefs.read_prefs() == {}


def test_write_over_a_corrupt_file_recovers(prefs_home):
    """Unreadable prior content is replaced rather than propagated."""
    target = user_prefs.user_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{not json")

    user_prefs.write_pref("upload_dir", "/data/uploads")

    assert json.loads(target.read_text()) == {"upload_dir": "/data/uploads"}


def test_upload_dir_module_still_reads_and_writes_through_this_file(prefs_home):
    """The delegation in ``api/upload_dir.py`` keeps its own public behaviour."""
    from memdiver.api import upload_dir as upload_dir_mod

    upload_dir_mod.write_user_upload_dir(Path("/data/uploads"))

    assert upload_dir_mod.read_user_upload_dir() == Path("/data/uploads")
    assert upload_dir_mod.user_config_path() == user_prefs.user_config_path()
    assert json.loads(user_prefs.user_config_path().read_text()) == {
        "upload_dir": "/data/uploads"
    }
