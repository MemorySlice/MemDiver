"""Pagination + wasted-I/O regression tests for ``GET /api/dataset/runs``.

These exercise the endpoint helpers in ``api.routers.dataset`` directly (no
FastAPI app wiring) to verify the performance work:

* ``list_runs`` paginates via ``limit``/``offset`` and reports ``total``.
* Dump sizes are sourced from ``meta.json`` rather than a per-file ``stat()``
  (proven by serving a size for a dump whose file does not exist on disk).
* The ``/runs`` path never triggers ``_extract_msl_secrets`` (secrets are not
  returned by this endpoint, so the expensive extraction is skipped).

A companion regression confirms the default ``load_run_directory`` path still
parses secrets so unrelated callers keep working.
"""

from __future__ import annotations

import json
from pathlib import Path

from memdiver.api.routers.dataset import (
    _dump_to_dict,
    _load_run_entry,
    list_runs,
)
from memdiver.core.discovery import RunDiscovery
from memdiver.core.models import DumpFile

MASTER_KEY_HEX = "0011223344556677"


# ---------------------------------------------------------------------------
# Helpers — build dataset-style run directories on disk
# ---------------------------------------------------------------------------


def _make_run_dir(run_dir: Path, *, msl_size: int = 48, meta_size: int | None = None) -> Path:
    """Create ``run_dir`` with a ``meta.json`` + an ``.msl`` dump file.

    ``msl_size`` is the actual on-disk byte count of the ``.msl`` file;
    ``meta_size`` (defaults to ``msl_size``) is what ``meta.json`` declares,
    letting a test prove the declared size wins over the on-disk one.
    """
    run_dir.mkdir(parents=True)
    msl_path = run_dir / "test_capture.msl"
    msl_path.write_bytes(b"MSL0" + b"\x00" * (msl_size - 4))

    meta = {
        "run_id": run_dir.name,
        "cipher": "AES-256-GCM",
        "password": "hunter2",
        "master_key_hex": MASTER_KEY_HEX,
        "aslr_base": "0x400000",
        "pid": 4321,
        "dumps": {
            "memslicer": {
                "path": f"{run_dir.name}/{msl_path.name}",
                "size": meta_size if meta_size is not None else msl_size,
            },
        },
    }
    (run_dir / "meta.json").write_text(json.dumps(meta))
    return msl_path


def _make_dataset(root: Path, n: int) -> None:
    """Create ``root`` holding ``n`` sequentially-named dataset run dirs."""
    root.mkdir(parents=True)
    for i in range(1, n + 1):
        _make_run_dir(root / f"run_{i:04d}")


# ---------------------------------------------------------------------------
# B2 — pagination
# ---------------------------------------------------------------------------


def test_list_runs_reports_total_and_returns_all_by_default(tmp_path: Path) -> None:
    """``limit=None`` returns every run yet still reports ``total``."""
    root = tmp_path / "dataset_root"
    _make_dataset(root, 5)

    result = list_runs(root=str(root), session=None)

    assert result["total"] == 5
    assert result["offset"] == 0
    assert result["limit"] is None
    assert len(result["runs"]) == 5


def test_list_runs_paginates_with_limit_and_offset(tmp_path: Path) -> None:
    """A ``limit``/``offset`` window slices the sorted candidate list."""
    root = tmp_path / "dataset_root"
    _make_dataset(root, 5)

    all_paths = [r["path"] for r in list_runs(root=str(root), session=None)["runs"]]

    page = list_runs(root=str(root), limit=2, offset=1, session=None)
    assert page["total"] == 5
    assert page["offset"] == 1
    assert page["limit"] == 2
    assert [r["path"] for r in page["runs"]] == all_paths[1:3]


def test_list_runs_offset_past_end_yields_empty_page(tmp_path: Path) -> None:
    """An offset beyond the candidate count returns no rows but the total."""
    root = tmp_path / "dataset_root"
    _make_dataset(root, 3)

    result = list_runs(root=str(root), limit=10, offset=10, session=None)
    assert result["total"] == 3
    assert result["runs"] == []


def test_list_runs_clamps_negative_offset_and_limit(tmp_path: Path) -> None:
    """Negative offset clamps to 0; a non-positive limit yields no rows."""
    root = tmp_path / "dataset_root"
    _make_dataset(root, 4)

    neg_offset = list_runs(root=str(root), offset=-5, session=None)
    assert neg_offset["offset"] == 0
    assert len(neg_offset["runs"]) == 4

    neg_limit = list_runs(root=str(root), limit=-1, offset=0, session=None)
    assert neg_limit["total"] == 4
    assert neg_limit["runs"] == []


# ---------------------------------------------------------------------------
# B1 — size from meta.json, no wasted stat()
# ---------------------------------------------------------------------------


def test_dump_size_comes_from_meta_even_when_file_absent(tmp_path: Path) -> None:
    """``_dump_to_dict`` prefers the meta.json size over a ``stat()`` fallback.

    The dump path does not exist on disk, so the ``stat()`` fallback would
    yield ``0``; the declared meta size must be returned instead.
    """
    missing = tmp_path / "nope" / "gcore.core"
    assert not missing.exists()
    dump = DumpFile(
        path=missing,
        timestamp="",
        phase_prefix="full",
        phase_name="gcore",
        kind="gcore",
    )

    result = _dump_to_dict(dump, {"gcore": 123456})
    assert result["size"] == 123456
    assert result["kind"] == "gcore"


def test_dump_size_falls_back_to_stat_without_meta(tmp_path: Path) -> None:
    """With no usable meta size, a real file's on-disk size is used."""
    dump_path = tmp_path / "some.core"
    dump_path.write_bytes(b"\x00" * 42)
    dump = DumpFile(
        path=dump_path,
        timestamp="",
        phase_prefix="full",
        phase_name="gcore",
        kind="gcore",
    )

    # No mapping, and a 0/absent meta size, both fall through to stat().
    assert _dump_to_dict(dump, None)["size"] == 42
    assert _dump_to_dict(dump, {"gcore": 0})["size"] == 42


def test_meta_size_wins_over_on_disk_size(tmp_path: Path) -> None:
    """Endpoint reports the meta.json size, not the (differing) on-disk one."""
    root = tmp_path / "dataset_root"
    root.mkdir()
    run_dir = root / "run_0001"
    _make_run_dir(run_dir, msl_size=48, meta_size=999)

    entry = _load_run_entry(run_dir)
    assert entry is not None
    sizes = {d["kind"]: d["size"] for d in entry["dumps"]}
    assert sizes["msl"] == 999  # from meta.json, not the 48-byte file


def test_runs_path_never_extracts_msl_secrets(tmp_path: Path, monkeypatch) -> None:
    """The browsing path must not invoke the expensive MSL key extraction."""
    def _boom(*args, **kwargs):
        raise AssertionError("_extract_msl_secrets must not run for /runs")

    monkeypatch.setattr(
        "memdiver.core.discovery._extract_msl_secrets", _boom
    )

    root = tmp_path / "dataset_root"
    _make_dataset(root, 2)

    # Neither the low-level entry loader nor the endpoint may trigger it.
    for name in ("run_0001", "run_0002"):
        assert _load_run_entry(root / name) is not None
    result = list_runs(root=str(root), session=None)
    assert len(result["runs"]) == 2


# ---------------------------------------------------------------------------
# Regression — default load_run_directory still extracts secrets
# ---------------------------------------------------------------------------


def test_default_load_run_directory_still_parses_keylog(tmp_path: Path) -> None:
    """With ``extract_secrets`` defaulting True, keylog.csv secrets are parsed."""
    run_dir = tmp_path / "testlib_run_13_1"
    run_dir.mkdir()
    (run_dir / "test_capture.msl").write_bytes(b"MSL0" + b"\x00" * 44)
    (run_dir / "keylog.csv").write_text(
        "line\nCLIENT_RANDOM " + "aa" * 32 + " " + "bb" * 48 + "\n"
    )

    run = RunDiscovery.load_run_directory(run_dir)
    assert run is not None
    assert run.secret_source == "keylog"
    assert any(s.secret_type == "CLIENT_RANDOM" for s in run.secrets)


def test_extract_secrets_false_skips_secret_parsing(tmp_path: Path) -> None:
    """``extract_secrets=False`` leaves secrets empty even with a keylog."""
    run_dir = tmp_path / "testlib_run_13_1"
    run_dir.mkdir()
    (run_dir / "keylog.csv").write_text(
        "line\nCLIENT_RANDOM " + "aa" * 32 + " " + "bb" * 48 + "\n"
    )

    run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    assert run is not None
    assert run.secrets == []
    assert run.secret_source == "none"
