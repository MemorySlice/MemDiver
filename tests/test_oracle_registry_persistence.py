"""Tests for the ``<uuid>.json`` sidecar that makes the oracle registry survive.

Without it the registry is memory-only: a restart drops every config and arm
state, orphans the ``.py`` files on disk, and makes the pipeline's stored
``oracleId`` 404 mid-run -- with the wizard's Next button silently going dead
because its entry vanished.

The restore is deliberately *partial*, and each refusal is pinned below:

* ``armed`` never survives a restart (it is an authorization act bound to a
  sha the user saw, not cached state), but ``previously_armed`` tells the UI
  to say "re-arm to run" instead of "your work is gone".
* a ``.py`` whose bytes changed while the server was down is NOT adopted --
  handing a tampered file an id the UI already trusts is the one thing the
  stored sha exists to prevent.
* rehydration must never IMPORT the oracle, which would execute every stored
  user module at server boot with no user present and no sandbox probe.

Fixture and naming style follows ``tests/test_api_oracles.py``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

import pytest

from memdiver.api.services.oracle_registry import (
    OracleNotFound,
    OracleRegistry,
    reset_oracle_registry,
)

LOGGER_NAME = "memdiver.api.services.oracle_registry"

ORACLE_SRC = """\
def verify(candidate):
    return candidate == b"sentinel"
"""


@pytest.fixture
def examples_dir() -> Path:
    return Path(__file__).parent.parent / "docs" / "oracle" / "examples"


@pytest.fixture
def oracle_dir(tmp_path: Path) -> Path:
    return tmp_path / "oracles"


@pytest.fixture
def registry(oracle_dir: Path, examples_dir: Path):
    reg = OracleRegistry(oracle_dir=oracle_dir, examples_dir=examples_dir)
    yield reg
    reset_oracle_registry()


def _sidecar_of(py: Path) -> Path:
    return py.with_suffix(".json")


def _seed_oracle(
    oracle_dir: Path,
    oracle_id: str = "a" * 32,
    *,
    source: str = ORACLE_SRC,
    **overrides,
) -> Path:
    """Write a ``<id>.py`` + a valid ``<id>.json`` directly, bypassing upload.

    Writing the pair by hand is what lets a test describe the *disk state* a
    restart finds -- a tampered file, a corrupt sidecar, a dangling one --
    without having to simulate the process that produced it.
    """
    oracle_dir.mkdir(parents=True, exist_ok=True)
    py = oracle_dir / f"{oracle_id}.py"
    py.write_text(source)
    payload = {
        "schema": 1,
        "oracle_id": oracle_id,
        "filename": "seeded.py",
        "description": "a seeded oracle",
        "sha256": hashlib.sha256(source.encode()).hexdigest(),
        "size": len(source.encode()),
        "shape": 1,
        "uploaded_at": 1000.0,
        "config": {"tag": "value"},
        "armed_at": None,
    }
    payload.update(overrides)
    _sidecar_of(py).write_text(json.dumps(payload))
    return py


def _fresh(oracle_dir: Path, examples_dir: Path) -> OracleRegistry:
    """A second registry over the same directory -- i.e. "the server restarted"."""
    return OracleRegistry(oracle_dir=oracle_dir, examples_dir=examples_dir)


# -- Writing the sidecar -------------------------------------------------------


def test_upload_writes_a_locked_down_sidecar(registry, oracle_dir):
    """Upload must leave enough on disk to rebuild the entry, at ``0o600``.

    The sidecar carries ``config``, which may name absolute filesystem paths
    or a third-party oracle's passphrase, so it gets the same mode as the
    ``.py`` itself.
    """
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())
    sidecar = _sidecar_of(entry.path)

    assert sidecar.is_file()
    assert sidecar.stat().st_mode & 0o777 == 0o600

    payload = json.loads(sidecar.read_text())
    assert payload["schema"] == 1
    assert payload["oracle_id"] == entry.oracle_id
    assert payload["sha256"] == entry.sha256
    assert payload["shape"] == entry.shape
    assert payload["filename"] == "s.py"
    assert payload["config"] == {}
    assert payload["armed_at"] is None
    # head_lines are deliberately NOT stored: cheap to recompute, and a stored
    # copy could disagree with the bytes on disk.
    assert "head_lines" not in payload


def test_set_config_rewrites_the_sidecar(registry):
    """A config filled in after upload must outlive the process that took it.

    The UI's order of operations is "drop the file, THEN fill in the form", so
    persisting only at upload would lose every value the user typed.
    """
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())

    registry.set_config(entry.oracle_id, {"sample_ciphertext": "/vault/x"})

    payload = json.loads(_sidecar_of(entry.path).read_text())
    assert payload["config"] == {"sample_ciphertext": "/vault/x"}


def test_arm_records_armed_at_in_the_sidecar(registry):
    """``armed_at`` is what lets a restart say "armed earlier -- re-arm to run".

    Arming itself is not restored, so without this timestamp the UI could only
    present a restored oracle as if it had never been armed at all.
    """
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())
    assert json.loads(_sidecar_of(entry.path).read_text())["armed_at"] is None
    before = time.time()

    registry.arm(entry.oracle_id, entry.sha256)

    payload = json.loads(_sidecar_of(entry.path).read_text())
    assert payload["armed_at"] is not None
    assert payload["armed_at"] >= before
    assert entry.armed is True
    assert entry.armed_at == payload["armed_at"]


def test_delete_removes_both_files(registry):
    """A deleted oracle must not come back at the next restart.

    Leaving the sidecar behind would resurrect a 404-ing entry whose ``.py``
    is gone; leaving the ``.py`` behind would strand an unreferenced user
    module in a directory the server executes from.
    """
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())
    sidecar = _sidecar_of(entry.path)
    assert entry.path.is_file() and sidecar.is_file()

    registry.delete(entry.oracle_id)

    assert not entry.path.exists()
    assert not sidecar.exists()
    with pytest.raises(OracleNotFound):
        registry.get(entry.oracle_id)


# -- Restoring from it ---------------------------------------------------------


def test_restart_restores_the_entry_unarmed(registry, oracle_dir, examples_dir):
    """The 404 fix: the id keeps resolving, but arming does not carry over.

    Arming is bound to a sha the user echoed back, it is the one place the
    real config is replayed through the strict sandbox, and it is the gate
    between "a .py sits in a directory" and "this process will exec it". A
    restart invalidates all three; re-arming costs one click.
    """
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())
    registry.set_config(entry.oracle_id, {"tag": "magic"})
    registry.arm(entry.oracle_id, entry.sha256)

    restored = _fresh(oracle_dir, examples_dir).get(entry.oracle_id)

    assert restored.oracle_id == entry.oracle_id
    assert restored.filename == "s.py"
    assert restored.sha256 == entry.sha256
    assert restored.shape == entry.shape
    assert restored.config == {"tag": "magic"}
    assert restored.armed is False
    assert restored.previously_armed is True
    assert restored.armed_at == entry.armed_at


def test_restored_entry_recomputes_head_lines_from_disk(
    registry, oracle_dir, examples_dir
):
    """``head_lines`` come from the file, so they can never disagree with it."""
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())

    restored = _fresh(oracle_dir, examples_dir).get(entry.oracle_id)

    assert restored.head_lines == entry.head_lines
    assert any("verify" in line for line in restored.head_lines)


def test_never_armed_entry_restores_without_previously_armed(
    registry, oracle_dir, examples_dir
):
    """Non-vacuity for ``previously_armed``: it is not simply always true."""
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())

    restored = _fresh(oracle_dir, examples_dir).get(entry.oracle_id)

    assert restored.armed is False
    assert restored.previously_armed is False
    assert restored.armed_at is None


def test_modified_py_is_not_restored_and_is_logged(
    registry, oracle_dir, examples_dir, caplog
):
    """A file changed while the server was down must lose its trusted id.

    The stored sha exists to give ``arm``'s display-vs-disk check something
    truthful to compare against; adopting a tampered file would hand it an id
    the UI already trusts.
    """
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())
    entry.path.write_text("def verify(candidate):\n    return True\n")

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        rebuilt = _fresh(oracle_dir, examples_dir)

    with pytest.raises(OracleNotFound):
        rebuilt.get(entry.oracle_id)
    assert any(
        "refusing to restore" in rec.getMessage() for rec in caplog.records
    ), caplog.text


@pytest.mark.parametrize(
    "description, writer",
    [
        ("corrupt json", lambda p: p.write_text("{not json")),
        ("unknown schema", lambda p: p.write_text(json.dumps({"schema": 99}))),
        ("not an object", lambda p: p.write_text(json.dumps(["nope"]))),
        ("unsafe id", lambda p: p.write_text(json.dumps(
            {"schema": 1, "oracle_id": "../escape", "sha256": "x"}
        ))),
    ],
)
def test_unusable_sidecar_is_skipped_and_others_still_restore(
    oracle_dir, examples_dir, caplog, description, writer
):
    """One bad sidecar must not take the whole catalog down with it.

    Boot-time restore walks a directory of user-owned files; a single corrupt
    or hand-edited one is an ordinary state, not a reason to start with an
    empty registry.
    """
    good = _seed_oracle(oracle_dir, "b" * 32)
    bad = oracle_dir / "bad.json"
    (oracle_dir / "bad.py").write_text(ORACLE_SRC)
    writer(bad)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        rebuilt = _fresh(oracle_dir, examples_dir)

    ids = {e.oracle_id for e in rebuilt.list_entries()}
    assert ids == {"b" * 32}, description
    assert good.is_file()
    assert any("ignoring" in rec.getMessage() for rec in caplog.records), caplog.text


def test_dangling_sidecar_without_its_py_is_skipped(
    oracle_dir, examples_dir, caplog
):
    """Metadata for a file that is gone must not resurrect a broken entry.

    Restoring it would produce an id the UI shows and every run then fails on
    with a bare ``FileNotFoundError``.
    """
    _seed_oracle(oracle_dir, "c" * 32)
    (oracle_dir / f"{'c' * 32}.py").unlink()

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        rebuilt = _fresh(oracle_dir, examples_dir)

    assert rebuilt.list_entries() == []
    assert any("is gone" in rec.getMessage() for rec in caplog.records), caplog.text


def test_rehydrate_does_not_import_the_oracle_module(oracle_dir, examples_dir):
    """The G10 guard: restoring metadata must never EXECUTE user code.

    ``shape`` is stored precisely so rehydration does not have to call
    ``_detect_shape``, which imports the module -- that would run every stored
    oracle's top level at server boot, with no user present, no sandbox probe
    and no one to see the result. A stored shape can only ever mislabel a
    badge; ``load_oracle`` re-derives the real one every time the oracle is
    actually run.
    """
    marker = oracle_dir.parent / "IMPORTED"
    source = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('imported at module level')\n"
        "\n"
        "def verify(candidate):\n"
        "    return False\n"
    )
    _seed_oracle(oracle_dir, "d" * 32, source=source)
    assert not marker.exists()

    rebuilt = _fresh(oracle_dir, examples_dir)

    # The entry IS restored -- this is not passing because nothing happened.
    assert rebuilt.get("d" * 32).shape == 1
    assert not marker.exists(), "rehydrate imported the oracle module"


def test_enable_rehydrates_a_directory_that_already_has_sidecars(
    examples_dir, oracle_dir
):
    """Turning the oracle dir on at runtime must adopt what is already there.

    ``POST /api/oracles/enable`` is the one-click path, and a user pointing it
    at the directory they used last week expects their oracles back, not an
    empty catalog beside a folder full of files.
    """
    _seed_oracle(oracle_dir, "e" * 32, armed_at=1234.0)
    registry = OracleRegistry(oracle_dir=None, examples_dir=examples_dir)
    try:
        assert registry.list_entries() == []

        registry.enable(oracle_dir)

        restored = registry.get("e" * 32)
        assert restored.config == {"tag": "value"}
        assert restored.armed is False
        assert restored.previously_armed is True
    finally:
        reset_oracle_registry()


# -- Orphans -------------------------------------------------------------------


def test_orphan_files_lists_only_unbacked_py_files(registry, oracle_dir):
    """A ``.py`` with no metadata is dead weight the user should be told about.

    It is never deleted automatically: a boot-time process must not remove a
    user's file because a schema check failed.
    """
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())
    stray = oracle_dir / "leftover.py"
    stray.write_text(ORACLE_SRC)

    assert registry.orphan_files() == ["leftover.py"]
    assert entry.path.name not in registry.orphan_files()


def test_orphan_files_ignores_a_py_that_still_has_a_sidecar(
    oracle_dir, examples_dir
):
    """Non-vacuity: having metadata is what keeps a file off the orphan list."""
    _seed_oracle(oracle_dir, "f" * 32)

    rebuilt = _fresh(oracle_dir, examples_dir)

    assert rebuilt.orphan_files() == []


def test_prune_orphans_removes_only_the_orphans(registry, oracle_dir):
    """The user-initiated cleanup must not touch a live, sidecar-backed oracle."""
    entry = registry.upload(filename="s.py", content=ORACLE_SRC.encode())
    stray = oracle_dir / "leftover.py"
    stray.write_text(ORACLE_SRC)

    removed = registry.prune_orphans()

    assert removed == ["leftover.py"]
    assert not stray.exists()
    assert entry.path.is_file()
    assert _sidecar_of(entry.path).is_file()
    assert registry.get(entry.oracle_id).oracle_id == entry.oracle_id
    assert registry.orphan_files() == []
