"""Tests for setup wizard and project_db dependency helpers."""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from engine.project_db import check_deps, default_db_path, install_hint, HAS_DUCKDB


# ---------------------------------------------------------------------------
# engine/project_db helpers
# ---------------------------------------------------------------------------


def test_check_deps_returns_dict():
    result = check_deps()
    assert isinstance(result, dict)
    assert "duckdb" in result
    assert "ibis" in result
    assert "ready" in result


@pytest.mark.skipif(not HAS_DUCKDB, reason="duckdb not installed")
def test_check_deps_ready_when_installed():
    result = check_deps()
    assert result["ready"] is True
    assert result["duckdb"] is True
    assert result["ibis"] is True
    assert "duckdb_version" in result


def test_default_db_path_returns_path():
    p = default_db_path()
    assert isinstance(p, Path)
    assert p.name == "project.duckdb"


def test_default_db_path_creates_parent(tmp_path, monkeypatch):
    target = tmp_path / "custom_memdiver"
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    # Patch the function to use tmp_path-based home
    from engine import project_db
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    with patch.object(Path, "home", return_value=tmp_path):
        p = default_db_path()
    assert p.parent.exists()
    assert "memdiver" in str(p.parent).lower() or ".memdiver" in str(p.parent)


def test_default_db_path_xdg_override(tmp_path, monkeypatch):
    xdg_dir = tmp_path / "xdg_data"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_dir))
    p = default_db_path()
    assert str(xdg_dir) in str(p)
    assert p.name == "project.duckdb"
    assert (xdg_dir / "memdiver").exists()


def test_install_hint_returns_string():
    hint = install_hint()
    assert "pip install" in hint
    assert "memdiver" in hint


# ---------------------------------------------------------------------------
# setup_wizard
# ---------------------------------------------------------------------------


def test_should_show_wizard_not_when_duckdb_installed():
    """When DuckDB is installed, wizard should not show."""
    from ui.components.setup_wizard import should_show_wizard
    if HAS_DUCKDB:
        assert should_show_wizard() is False


def test_should_show_wizard_always_false(tmp_path, monkeypatch):
    """DuckDB is now a core dep, wizard never shows."""
    import ui.components.setup_wizard as wiz
    monkeypatch.setattr(wiz, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr("engine.project_db.check_deps", lambda: {"ready": True})
    assert wiz.should_show_wizard() is False


def test_should_show_wizard_respects_skip_pref(tmp_path, monkeypatch):
    """When user has skipped, wizard should not show even without DuckDB."""
    import ui.components.setup_wizard as wiz
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"skip_duckdb_setup": True}))
    monkeypatch.setattr(wiz, "_config_path", lambda: config)
    with patch("engine.project_db.HAS_DUCKDB", False):
        assert wiz.should_show_wizard() is False


def test_load_prefs_missing_file(tmp_path, monkeypatch):
    """Missing config file returns empty dict."""
    import ui.components.setup_wizard as wiz
    monkeypatch.setattr(wiz, "_config_path", lambda: tmp_path / "nonexistent.json")
    assert wiz._load_prefs() == {}


def test_save_and_load_prefs_roundtrip(tmp_path, monkeypatch):
    """Save then load should round-trip."""
    import ui.components.setup_wizard as wiz
    config = tmp_path / "subdir" / "config.json"
    monkeypatch.setattr(wiz, "_config_path", lambda: config)
    wiz._save_prefs({"skip_duckdb_setup": True, "theme": "dark"})
    loaded = wiz._load_prefs()
    assert loaded["skip_duckdb_setup"] is True
    assert loaded["theme"] == "dark"


def test_create_wizard_buttons():
    """create_wizard_buttons returns a 2-tuple using mo.ui.button."""
    mo = MagicMock()
    btn_mock = MagicMock()
    mo.ui.button.return_value = btn_mock
    from ui.components.setup_wizard import create_wizard_buttons
    install_btn, skip_btn = create_wizard_buttons(mo)
    assert mo.ui.button.call_count == 2
    assert install_btn is btn_mock
    assert skip_btn is btn_mock
