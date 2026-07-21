"""Tests for the co-located user-structure cache-sync helpers.

Covers :func:`add_user_structure` and :func:`remove_user_structure`, which
bundle the persist/register and delete/unregister steps so callers cannot
leave the cached singleton out of sync with disk. Built-ins-win collision
policy and best-effort (no-raise) behaviour are asserted here too.
"""

import pytest

from memdiver.core import structure_library
from memdiver.core.structure_library import (
    add_user_structure,
    get_structure_library,
    remove_user_structure,
)
from memdiver.core.structure_defs import FieldDef, FieldType, StructureDef


def _make_struct(name: str, size: int = 16) -> StructureDef:
    return StructureDef(
        name=name,
        total_size=size,
        fields=(FieldDef("blob", FieldType.BYTES, 0, size),),
        protocol="test",
        description="synthetic",
        tags=("test",),
    )


@pytest.fixture
def user_dir(tmp_path, monkeypatch):
    """Redirect the user dir at call time and reset the cached singleton."""
    d = tmp_path / "structures"
    d.mkdir()
    monkeypatch.setattr(
        "memdiver.core.structure_loader.DEFAULT_USER_DIR", d, raising=True
    )
    # save_user_structure binds its default dir at def-time; patch that too.
    monkeypatch.setattr(
        "memdiver.core.structure_loader.save_user_structure.__defaults__",
        (d,),
        raising=True,
    )
    monkeypatch.setattr(structure_library, "_library", None, raising=True)
    yield d
    monkeypatch.setattr(structure_library, "_library", None, raising=True)


def test_add_persists_file_and_registers(user_dir):
    path = add_user_structure(_make_struct("helper_demo"))
    # File written under the redirected user dir.
    assert path == user_dir / "helper_demo.json"
    assert path.is_file()
    # Immediately visible in the live singleton, no rebuild needed.
    assert get_structure_library().get("helper_demo") is not None


def test_remove_deletes_file_and_unregisters(user_dir):
    add_user_structure(_make_struct("removable"))
    assert (user_dir / "removable.json").is_file()

    deleted = remove_user_structure("removable")
    assert deleted is True
    assert not (user_dir / "removable.json").exists()
    assert get_structure_library().get("removable") is None


def test_remove_missing_file_is_no_raise(user_dir):
    # Nothing on disk; must not raise and reports nothing deleted.
    assert remove_user_structure("never_existed") is False


def test_add_collision_with_builtin_does_not_override(user_dir, caplog):
    # aes128_key is a built-in with total_size 16; user tries size 99.
    import logging

    with caplog.at_level(logging.WARNING):
        add_user_structure(_make_struct("aes128_key", size=99))

    kept = get_structure_library().get("aes128_key")
    assert kept is not None
    # Built-in wins in the live registry: total_size stays 16, not 99.
    assert kept.total_size == 16
    # File is still persisted to disk (prior behaviour preserved).
    assert (user_dir / "aes128_key.json").is_file()
    assert any("built-in" in r.getMessage() for r in caplog.records)


def test_remove_never_unregisters_builtin(user_dir):
    # Even if a caller aims a delete at a built-in name, the built-in survives.
    remove_user_structure("aes128_key")
    assert get_structure_library().get("aes128_key") is not None


def test_remove_contained_to_user_dir(user_dir, tmp_path):
    # A traversal-style name must not delete files outside the user dir.
    outside = tmp_path / "outside.json"
    outside.write_text("keep me", encoding="utf-8")
    deleted = remove_user_structure("../outside")
    assert deleted is False
    assert outside.exists()
