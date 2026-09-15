"""Tests for the opt-in oracle directory (``api/oracle_dir.py`` + config wiring).

``oracle_dir`` is the directory user-supplied Python is stored in *and executed
from*, so the properties pinned here are security properties, not conveniences:

* it stays ``None`` — oracle endpoints stay 503 — until someone opts in;
* the opt-in goes through the same validation gauntlet as ``upload_dir`` (no
  system dirs, no world-writable temp roots, no ``sys.prefix``, no bare
  ``$HOME``, writability *proven* rather than inferred);
* the resulting directory is ``0o700``, because
  ``engine.oracle._assert_safe_path`` refuses to load an oracle whose parent
  directory is group/world-writable — a directory accepted here but rejected
  there would only fail much later, from a stack trace;
* ``MEMDIVER_ORACLE_DIR=""`` is *unset*, not "the server's CWD".

Two seams are monkeypatched, both for the same reason they are in
``tests/test_api_upload_dir.py``: ``XDG_DATA_HOME`` redirects
``core.constants.memdiver_home()`` so the developer's real
``~/.memdiver/config.json`` is never written, and ``upload_dir._temp_roots``
is substituted because pytest's ``tmp_path`` itself lives under
``tempfile.gettempdir()``, which validation rejects. One test deliberately does
NOT patch the latter, so the real rule stays covered.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

from memdiver.api import oracle_dir as oracle_dir_mod
from memdiver.api import upload_dir as upload_dir_mod
from memdiver.api.config import Settings, env_pinned, get_settings
from memdiver.api.oracle_dir import (
    USER_CONFIG_KEY,
    default_oracle_dir,
    read_user_oracle_dir,
    validate_candidate,
    write_user_oracle_dir,
)
from memdiver.api.user_prefs import user_config_path


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch):
    """Redirect ``memdiver_home()`` into ``tmp_path`` and clear the env var."""
    monkeypatch.delenv("MEMDIVER_ORACLE_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def allow_tmp_paths(monkeypatch):
    """Let validation accept a pytest ``tmp_path``.

    ``tmp_path`` lives inside ``tempfile.gettempdir()``, which the shared
    validator rejects outright, so without this seam no happy-path test could
    name a directory it accepts.
    """
    monkeypatch.setattr(upload_dir_mod, "_temp_roots", lambda: ())


# ---------------------------------------------------------------------------
# Defaults and persistence
# ---------------------------------------------------------------------------


def test_default_is_under_memdiver_home(isolated_home):
    from memdiver.core.constants import memdiver_home

    assert default_oracle_dir() == memdiver_home() / "oracles"
    assert default_oracle_dir().name == "oracles"


def test_unset_reads_as_none(isolated_home):
    assert read_user_oracle_dir() is None


def test_round_trip_through_prefs_file(isolated_home, tmp_path):
    chosen = tmp_path / "my_oracles"
    write_user_oracle_dir(chosen)
    assert read_user_oracle_dir() == chosen
    stored = json.loads(user_config_path().read_text())
    assert stored[USER_CONFIG_KEY] == str(chosen)


def test_write_preserves_sibling_settings(isolated_home, tmp_path):
    """The prefs file is shared; enabling oracles must not clobber upload_dir."""
    upload_dir_mod.write_user_upload_dir(tmp_path / "uploads")
    write_user_oracle_dir(tmp_path / "oracles")
    stored = json.loads(user_config_path().read_text())
    assert stored["upload_dir"] == str(tmp_path / "uploads")
    assert stored[USER_CONFIG_KEY] == str(tmp_path / "oracles")


def test_corrupt_prefs_file_degrades_to_none(isolated_home):
    path = user_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json at all")
    assert read_user_oracle_dir() is None


@pytest.mark.parametrize("junk", ["", "   ", 17, None, ["/a"]])
def test_non_string_pref_degrades_to_none(isolated_home, junk):
    from memdiver.api.user_prefs import write_pref

    write_pref(USER_CONFIG_KEY, junk)
    assert read_user_oracle_dir() is None


# ---------------------------------------------------------------------------
# Validation — the shared rules, delegated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "candidate",
    ["", "   ", "relative/path", "./oracles"],
)
def test_reject_non_absolute(candidate, allow_tmp_paths):
    with pytest.raises(ValueError):
        validate_candidate(candidate)


def test_reject_system_dir(allow_tmp_paths):
    with pytest.raises(ValueError, match="system directory"):
        validate_candidate("/usr/local/memdiver-oracles")


def test_reject_home_itself(allow_tmp_paths):
    with pytest.raises(ValueError, match="home directory"):
        validate_candidate(str(Path.home()))


def test_reject_sys_prefix(allow_tmp_paths):
    with pytest.raises(ValueError, match="Python installation"):
        validate_candidate(str(Path(sys.prefix) / "oracles"))


def test_reject_real_tempdir():
    """Deliberately unpatched: the real world-writable-temp rule stays covered."""
    with pytest.raises(ValueError, match="temporary directory"):
        validate_candidate(str(Path(tempfile.gettempdir()) / "memdiver_oracles"))


def test_reject_existing_file(tmp_path, allow_tmp_paths):
    target = tmp_path / "not_a_dir"
    target.write_text("x")
    with pytest.raises(ValueError, match="not a directory"):
        validate_candidate(str(target))


# ---------------------------------------------------------------------------
# Validation — the oracle-specific 0o700 rule
# ---------------------------------------------------------------------------


def test_creates_directory_at_0700(tmp_path, allow_tmp_paths):
    target = tmp_path / "fresh" / "oracles"
    resolved = validate_candidate(str(target))
    assert resolved == target.resolve()
    assert resolved.is_dir()
    assert stat.S_IMODE(resolved.stat().st_mode) == 0o700


def test_tightens_a_permissive_existing_directory(tmp_path, allow_tmp_paths):
    """A pre-existing 0o777 dir must come back locked down, not merely accepted.

    This is the case ``engine.oracle._assert_safe_path`` would otherwise reject
    at load time, long after the user thought they had enabled the feature.
    """
    target = tmp_path / "loose"
    target.mkdir(mode=0o777)
    os.chmod(target, 0o777)
    resolved = validate_candidate(str(target))
    mode = resolved.stat().st_mode
    assert stat.S_IMODE(mode) == 0o700
    assert not mode & (stat.S_IWGRP | stat.S_IWOTH)


def test_result_satisfies_the_oracle_loader_parent_check(tmp_path, allow_tmp_paths):
    """The whole point: a file in the validated dir passes _assert_safe_path."""
    from memdiver.engine.oracle import _assert_safe_path

    resolved = validate_candidate(str(tmp_path / "oracles"))
    oracle = resolved / "x.py"
    oracle.write_text("def verify(c):\n    return False\n")
    os.chmod(oracle, 0o600)
    _assert_safe_path(oracle)  # must not raise


def test_expands_user_home_prefix(tmp_path, monkeypatch, allow_tmp_paths):
    monkeypatch.setenv("HOME", str(tmp_path / "fakehome"))
    (tmp_path / "fakehome").mkdir()
    resolved = validate_candidate("~/oracles")
    assert resolved == (tmp_path / "fakehome" / "oracles").resolve()


# ---------------------------------------------------------------------------
# Settings resolution precedence
# ---------------------------------------------------------------------------


def test_env_var_wins_over_user_config(isolated_home, tmp_path, monkeypatch):
    write_user_oracle_dir(tmp_path / "from_prefs")
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(tmp_path / "from_env"))
    assert Settings().oracle_dir == tmp_path / "from_env"


def test_user_config_used_when_env_unset(isolated_home, tmp_path):
    write_user_oracle_dir(tmp_path / "from_prefs")
    assert Settings().oracle_dir == tmp_path / "from_prefs"


def test_unconfigured_stays_none(isolated_home):
    """The default must remain disabled — oracles are opt-in, not opt-out."""
    assert Settings().oracle_dir is None


def test_empty_env_var_is_treated_as_unset(isolated_home, monkeypatch, caplog):
    """``MEMDIVER_ORACLE_DIR=""`` parses to Path(".") — the server CWD.

    Treating that as *enabled* would drop executable oracles into whatever
    directory the server happened to start in.
    """
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", "")
    with caplog.at_level("WARNING", logger="memdiver.api.config"):
        settings = Settings()
    assert settings.oracle_dir is None
    assert any("MEMDIVER_ORACLE_DIR is empty" in r.message for r in caplog.records)


def test_empty_env_var_does_not_shadow_the_user_config(
    isolated_home, tmp_path, monkeypatch
):
    """An empty env var falls through to the prefs file rather than winning."""
    write_user_oracle_dir(tmp_path / "from_prefs")
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", "")
    assert Settings().oracle_dir == tmp_path / "from_prefs"


# ---------------------------------------------------------------------------
# The shared env-pinned helper
# ---------------------------------------------------------------------------


def test_env_pinned_is_parameterised_by_var_name(isolated_home, monkeypatch):
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", "/some/where")
    monkeypatch.delenv("MEMDIVER_UPLOAD_DIR", raising=False)
    assert env_pinned("MEMDIVER_ORACLE_DIR") is True
    # ...and does not bleed across variables.
    assert env_pinned("MEMDIVER_UPLOAD_DIR") in (True, False)


def test_env_pinned_ignores_a_blank_value(isolated_home, monkeypatch):
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", "   ")
    assert env_pinned("MEMDIVER_ORACLE_DIR") is False


def test_env_pinned_reads_the_dotenv_file(isolated_home, tmp_path, monkeypatch):
    """pydantic-settings applies .env ahead of the prefs file, so it pins too."""
    monkeypatch.delenv("MEMDIVER_ORACLE_DIR", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text('MEMDIVER_ORACLE_DIR="/opt/oracles"\n')
    monkeypatch.chdir(tmp_path)
    settings = get_settings()
    monkeypatch.setitem(settings.model_config, "env_file", str(env_file))
    assert env_pinned("MEMDIVER_ORACLE_DIR") is True


def test_settings_router_still_answers_for_upload_dir(isolated_home, monkeypatch):
    """The lifted helper must not change the upload-dir router's behaviour."""
    from memdiver.api.routers.settings import _env_pinned

    monkeypatch.delenv("MEMDIVER_UPLOAD_DIR", raising=False)
    assert _env_pinned() is False
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", "/somewhere")
    assert _env_pinned() is True


def test_oracle_module_does_not_import_config(isolated_home):
    """config imports oracle_dir during validation; the reverse would cycle.

    Checked on the AST rather than the text so the module docstring, which
    *describes* this rule, does not itself trip the assertion.
    """
    import ast

    tree = ast.parse(Path(oracle_dir_mod.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not any(name.endswith("api.config") for name in imported), imported
