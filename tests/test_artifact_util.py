"""Tests for :mod:`memdiver.core.artifact_util`.

Focused on :func:`atomic_write_text`, the shared ``tmp + os.replace``
primitive extracted from ``TaskManager._persist`` (plan item 2.5g) so the
``app/`` sweep ledger can reuse it without importing ``api/``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from memdiver.core.artifact_util import atomic_write_text


def _stray_tmps(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.tmp"))


def test_atomic_write_text_writes_content(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"

    atomic_write_text(target, '{"a": 1}')

    assert target.read_text(encoding="utf-8") == '{"a": 1}'


def test_atomic_write_text_leaves_no_temp_file(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"

    atomic_write_text(target, "payload")

    assert _stray_tmps(tmp_path) == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["manifest.json"]


def test_atomic_write_text_overwrites_existing(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"
    target.write_text("old", encoding="utf-8")

    atomic_write_text(target, "new")

    assert target.read_text(encoding="utf-8") == "new"
    assert _stray_tmps(tmp_path) == []


def test_atomic_write_text_honours_encoding(tmp_path: Path) -> None:
    target = tmp_path / "note.txt"

    atomic_write_text(target, "grüße", encoding="utf-8")

    assert target.read_bytes() == "grüße".encode("utf-8")


def test_atomic_write_text_cleans_up_and_keeps_original_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mid-write failure must remove the tmp and leave the old file intact."""
    target = tmp_path / "manifest.json"
    target.write_text("original", encoding="utf-8")

    def boom(src: object, dst: object) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", boom)

    with pytest.raises(OSError, match="replace failed"):
        atomic_write_text(target, "replacement")

    assert target.read_text(encoding="utf-8") == "original"
    assert _stray_tmps(tmp_path) == []


def test_atomic_write_text_cleans_up_on_base_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cleanup is registered on ``BaseException``, not just ``Exception``.

    A ``KeyboardInterrupt`` (or a worker cancellation, which is also a
    ``BaseException``) mid-write must not strand a tmp file on disk.
    """
    target = tmp_path / "manifest.json"

    def interrupt(src: object, dst: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "replace", interrupt)

    with pytest.raises(KeyboardInterrupt):
        atomic_write_text(target, "replacement")

    assert not target.exists()
    assert _stray_tmps(tmp_path) == []


def test_atomic_write_text_temp_names_do_not_collide(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two writes to the same path must use distinct tmp names.

    A shared ``<name>.tmp`` was the original bug: concurrent writers tore
    each other's output, or the second ``os.replace`` raised
    ``FileNotFoundError`` because the tmp had already been moved.
    """
    target = tmp_path / "manifest.json"
    seen: list[str] = []

    real_replace = os.replace

    def record_then_replace(src: object, dst: object) -> None:
        seen.append(Path(str(src)).name)
        real_replace(src, dst)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "replace", record_then_replace)

    atomic_write_text(target, "first")
    atomic_write_text(target, "second")

    assert len(seen) == 2
    assert seen[0] != seen[1]
    assert all(name.startswith("manifest.json.") for name in seen)
    assert all(name.endswith(".tmp") for name in seen)
    assert target.read_text(encoding="utf-8") == "second"


def test_atomic_write_text_interleaved_writers_do_not_collide(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second writer starting mid-first-write must not break either one.

    Reproduces the original two-thread race deterministically: the inner
    write completes while the outer one is between ``write_text`` and
    ``os.replace``. With a per-write tmp both succeed (last-writer-wins);
    with a shared tmp the outer ``os.replace`` would raise.
    """
    target = tmp_path / "manifest.json"
    real_replace = os.replace
    reentered = False

    def replace_with_nested_write(src: object, dst: object) -> None:
        nonlocal reentered
        if not reentered:
            reentered = True
            monkeypatch.setattr(os, "replace", real_replace)
            atomic_write_text(target, "inner")
            monkeypatch.setattr(os, "replace", replace_with_nested_write)
        real_replace(src, dst)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "replace", replace_with_nested_write)

    atomic_write_text(target, "outer")

    assert target.read_text(encoding="utf-8") == "outer"
    assert _stray_tmps(tmp_path) == []
