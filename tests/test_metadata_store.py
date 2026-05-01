"""Tests for harvester.metadata_store.MetadataStore.

The store aggregates RunDirectory records (optionally enriched with a
sidecar dict) and exposes filtering + summary queries over them. Polars
is used internally for the populated-summary path and is gated by
``HAS_POLARS`` -- when polars is unavailable the populated-summary test
falls back to a smaller contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.models import RunDirectory
from harvester.metadata_store import HAS_POLARS, MetadataStore


def _make_run(library: str, version: str, run_number: int,
              num_dumps: int = 0, num_secrets: int = 0,
              path: Path | None = None) -> RunDirectory:
    """Construct a minimal RunDirectory with placeholder dumps/secrets lists.

    MetadataStore.add_run only calls ``len(run.dumps)`` / ``len(run.secrets)``
    on these collections, so any iterable of the right length suffices.
    """
    run = RunDirectory(
        path=path or Path(f"/fake/{library}/{version}/run{run_number}"),
        library=library,
        protocol_version=version,
        run_number=run_number,
    )
    # Pad with truthy stand-ins -- the store only takes the length.
    run.dumps = [object()] * num_dumps
    run.secrets = [object()] * num_secrets
    return run


# ---------------------------------------------------------------------------


def test_add_run_minimal():
    """add_run with no sidecar registers a record discoverable by library."""
    store = MetadataStore()
    run = _make_run("openssl", "1.3", 0, num_dumps=2, num_secrets=1)
    store.add_run(run)

    # Canonical query for "is the run there?" is get_runs_for_library.
    matches = store.get_runs_for_library("openssl")
    assert len(matches) == 1
    record = matches[0]
    assert record["library"] == "openssl"
    assert record["tls_version"] == "1.3"
    assert record["run_number"] == 0
    assert record["num_dumps"] == 2
    assert record["num_secrets"] == 1
    # No sidecar -> no meta_* keys present.
    assert not any(k.startswith("meta_") for k in record)


def test_add_run_with_sidecar():
    """Sidecar scalar values propagate as ``meta_<key>`` columns."""
    store = MetadataStore()
    run = _make_run("boringssl", "1.2", 7)
    sidecar = {
        "compiler": "clang",
        "version_major": 14,
        "is_release": True,
        "build_time": 1234.5,
        # Non-scalar values must be silently ignored per the contract.
        "compile_flags": ["-O2", "-fPIC"],
    }
    store.add_run(run, sidecar=sidecar)

    record = store.get_runs_for_library("boringssl")[0]
    assert record["meta_compiler"] == "clang"
    assert record["meta_version_major"] == 14
    assert record["meta_is_release"] is True
    assert record["meta_build_time"] == 1234.5
    # The list value should NOT propagate as a meta_ field.
    assert "meta_compile_flags" not in record


def test_get_runs_for_library_filtering():
    """Adds 3 runs across 2 libraries; query returns only the matching subset."""
    store = MetadataStore()
    store.add_run(_make_run("openssl", "1.2", 0))
    store.add_run(_make_run("boringssl", "1.3", 0))
    store.add_run(_make_run("openssl", "1.3", 1))

    openssl_runs = store.get_runs_for_library("openssl")
    boringssl_runs = store.get_runs_for_library("boringssl")
    assert len(openssl_runs) == 2
    assert len(boringssl_runs) == 1
    # Insertion order is preserved (records list is a plain Python list).
    assert openssl_runs[0]["run_number"] == 0
    assert openssl_runs[1]["run_number"] == 1


def test_summary_empty():
    """An empty store reports total_runs == 0 with no other guarantees."""
    store = MetadataStore()
    summary = store.summary()
    assert summary == {"total_runs": 0}


def test_summary_populated():
    """Populated summary reports total_runs and includes library info.

    With polars: returns total_dumps, total_secrets, and a unique library
    count (an int via ``n_unique()``).
    Without polars: returns the list of library names.
    """
    store = MetadataStore()
    store.add_run(_make_run("openssl", "1.2", 0, num_dumps=2, num_secrets=1))
    store.add_run(_make_run("openssl", "1.3", 1, num_dumps=3, num_secrets=2))
    store.add_run(_make_run("boringssl", "1.3", 0, num_dumps=1, num_secrets=1))

    summary = store.summary()
    assert summary["total_runs"] == 3
    if HAS_POLARS:
        assert summary["libraries"] == 2  # n_unique -> int
        assert summary["total_dumps"] == 6
        assert summary["total_secrets"] == 4
    else:
        assert set(summary["libraries"]) == {"openssl", "boringssl"}


def test_filter_by_multikey():
    """filter_by accepts multiple keyword pairs and AND-combines them."""
    store = MetadataStore()
    store.add_run(_make_run("openssl", "1.2", 0))
    store.add_run(_make_run("openssl", "1.3", 1))
    store.add_run(_make_run("openssl", "1.3", 2))
    store.add_run(_make_run("boringssl", "1.3", 0))

    # library + tls_version: openssl@1.3 has 2 runs.
    matches = store.filter_by(library="openssl", tls_version="1.3")
    assert len(matches) == 2
    assert {m["run_number"] for m in matches} == {1, 2}

    # No matches case.
    none_match = store.filter_by(library="boringssl", tls_version="1.2")
    assert none_match == []
