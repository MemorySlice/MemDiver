"""Tests for auto-merging user-defined structures into the shared library.

Verifies that :func:`get_structure_library` (default ``include_user=True``)
merges user JSON structures from the user directory alongside the built-ins,
while keeping built-ins authoritative and containing all load failures.
"""

import json
import logging

import pytest

from memdiver.core import structure_library
from memdiver.core.structure_library import get_structure_library


def _write(directory, name, payload):
    """Write ``payload`` (str or dict) to ``<directory>/<name>.json``."""
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (directory / f"{name}.json").write_text(text, encoding="utf-8")


@pytest.fixture
def user_dir(tmp_path, monkeypatch):
    """Point the loader at a temp user dir and reset the cached singleton."""
    d = tmp_path / "structures"
    d.mkdir()
    # get_structure_library reads structure_loader.DEFAULT_USER_DIR at call
    # time, so monkeypatching the module attribute redirects the load.
    monkeypatch.setattr(
        "memdiver.core.structure_loader.DEFAULT_USER_DIR", d, raising=True
    )
    monkeypatch.setattr(structure_library, "_library", None, raising=True)
    yield d
    # Ensure the polluted singleton does not leak into other tests.
    monkeypatch.setattr(structure_library, "_library", None, raising=True)


def test_builtins_still_present(user_dir):
    lib = get_structure_library()
    assert lib.get("aes128_key") is not None
    assert lib.get("aes256_key") is not None


def test_valid_user_structure_is_merged(user_dir):
    _write(
        user_dir,
        "my_user_struct",
        {
            "name": "my_user_struct",
            "total_size": 16,
            "fields": [
                {"name": "blob", "field_type": "bytes", "offset": 0, "size": 16}
            ],
        },
    )
    lib = get_structure_library()
    merged = lib.get("my_user_struct")
    assert merged is not None
    assert merged.total_size == 16
    # Built-ins remain available alongside the user structure.
    assert lib.get("aes128_key") is not None


def test_invalid_json_is_skipped_without_raising(user_dir):
    _write(user_dir, "broken", "{ this is not valid json ")
    # Also drop a schema-invalid (but parseable) file to exercise validation.
    _write(user_dir, "bad_schema", {"name": "x", "fields": "not-a-list"})
    lib = get_structure_library()  # must not raise
    assert lib.get("broken") is None
    assert lib.get("bad_schema") is None
    assert lib.get("aes128_key") is not None


def test_user_structure_cannot_override_builtin(user_dir):
    # Built-in aes128_key has total_size 16; user file tries to redefine it.
    _write(
        user_dir,
        "aes128_key",
        {
            "name": "aes128_key",
            "total_size": 99,
            "fields": [
                {"name": "blob", "field_type": "bytes", "offset": 0, "size": 99}
            ],
        },
    )
    lib = get_structure_library()
    kept = lib.get("aes128_key")
    assert kept is not None
    # Built-in wins: total_size stays 16, not the user's 99.
    assert kept.total_size == 16


def test_include_user_false_returns_builtins_only(user_dir):
    _write(
        user_dir,
        "my_user_struct",
        {
            "name": "my_user_struct",
            "total_size": 8,
            "fields": [
                {"name": "blob", "field_type": "bytes", "offset": 0, "size": 8}
            ],
        },
    )
    lib = get_structure_library(include_user=False)
    assert lib.get("aes128_key") is not None
    assert lib.get("my_user_struct") is None


# --------------------------------------------------------------------------- #
# (a) A name collision emits a warning (built-in still wins).
# --------------------------------------------------------------------------- #
def test_collision_emits_warning(user_dir, caplog):
    _write(
        user_dir,
        "aes128_key",
        {
            "name": "aes128_key",
            "total_size": 99,
            "fields": [
                {"name": "blob", "field_type": "bytes", "offset": 0, "size": 99}
            ],
        },
    )
    with caplog.at_level(logging.WARNING):
        lib = get_structure_library()

    # Built-in remains authoritative.
    assert lib.get("aes128_key").total_size == 16
    # And the clash was surfaced, not swallowed silently.
    assert any(
        "collides" in r.getMessage() and "aes128_key" in r.getMessage()
        for r in caplog.records
    )


# --------------------------------------------------------------------------- #
# (b) A missing / non-directory user dir degrades gracefully.
# --------------------------------------------------------------------------- #
def test_missing_user_dir_degrades_gracefully(tmp_path, monkeypatch):
    missing = tmp_path / "nope" / "structures"  # never created
    monkeypatch.setattr(
        "memdiver.core.structure_loader.DEFAULT_USER_DIR", missing, raising=True
    )
    monkeypatch.setattr(structure_library, "_library", None, raising=True)

    lib = get_structure_library()  # must not raise
    assert lib.get("aes128_key") is not None
    assert lib.get("aes256_key") is not None

    monkeypatch.setattr(structure_library, "_library", None, raising=True)


def test_non_directory_user_dir_degrades_gracefully(tmp_path, monkeypatch):
    # Point the loader at a regular file rather than a directory.
    not_a_dir = tmp_path / "a_file"
    not_a_dir.write_text("i am not a directory", encoding="utf-8")
    monkeypatch.setattr(
        "memdiver.core.structure_loader.DEFAULT_USER_DIR", not_a_dir, raising=True
    )
    monkeypatch.setattr(structure_library, "_library", None, raising=True)

    lib = get_structure_library()  # must not raise
    assert lib.get("aes128_key") is not None

    monkeypatch.setattr(structure_library, "_library", None, raising=True)


# --------------------------------------------------------------------------- #
# (c) Interleaved include_user True/False/True calls don't cross-contaminate.
# --------------------------------------------------------------------------- #
def test_interleaved_include_user_calls_no_cross_contamination(user_dir):
    _write(
        user_dir,
        "my_user_struct",
        {
            "name": "my_user_struct",
            "total_size": 16,
            "fields": [
                {"name": "blob", "field_type": "bytes", "offset": 0, "size": 16}
            ],
        },
    )

    # True: builds + caches the singleton (user structure merged in).
    lib_true = get_structure_library(include_user=True)
    assert lib_true.get("my_user_struct") is not None

    # False: a fresh built-ins-only library, must NOT see the user structure
    # and must NOT be the cached singleton.
    lib_false = get_structure_library(include_user=False)
    assert lib_false.get("my_user_struct") is None
    assert lib_false.get("aes128_key") is not None
    assert lib_false is not lib_true

    # True again: returns the same cached singleton, still uncontaminated by the
    # intervening include_user=False call.
    lib_true_again = get_structure_library(include_user=True)
    assert lib_true_again is lib_true
    assert lib_true_again.get("my_user_struct") is not None
